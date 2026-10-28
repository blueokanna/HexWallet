#!/usr/bin/env python3
"""Generate fork profiles from the compatibility registry.

Address metadata alone cannot enable signing. A signing row needs official
chainparams, a reviewed legacy or fork-id sighash source, and explicit
transaction-review and signing capabilities.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools" / "fork_registry.json"
PROFILES_OUT = ROOT / "src/generated/WalletForkProfiles.inc"
CATALOG_OUT = ROOT / "src/generated/WalletForkCatalog.inc"
POLICIES_OUT = ROOT / "src/generated/WalletForkSigningPolicies.inc"
VECTORS_OUT = ROOT / "tests/fixtures/WalletForkAddressVectorsTest.inc"

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TEST_PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


def cpp_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def base58check(payload: bytes) -> str:
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + digest
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = BASE58[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + encoded


def p2pkh_address(version: int) -> str:
    public = hashlib.sha256(TEST_PUBKEY).digest()
    ripemd = hashlib.new("ripemd160", public).digest()
    return base58check(bytes([version]) + ripemd)


def main() -> int:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows = data["profiles"]
    graveyard = json.loads((ROOT / "tools/miningpoolstats_graveyard.json").read_text())
    blocked = {k: v for k, v in graveyard["coins"].items()
               if k not in graveyard.get("exceptions", [])}
    identities = {(v["n"].strip().casefold(), v["s"].upper()) for v in blocked.values()}
    for row in rows:
        if row["network"] in blocked or (row["name"].strip().casefold(), row["symbol"].upper()) in identities:
            raise SystemExit("GRAVEYARD profile forbidden: " + row["network"])
    for row in rows:
        if row.get("signing") and not row.get("source_verified"):
            raise SystemExit("signing profile lacks source verification: " + row["network"])
        if row.get("signing") and not row.get("source"):
            raise SystemExit("signing profile lacks source URL: " + row["network"])
        if row.get("signing") and not row.get("sighash_source"):
            raise SystemExit("signing profile lacks sighash evidence: " + row["network"])
        if row.get("signing") and row.get("sighash") not in ("legacy", "forkid"):
            raise SystemExit("signing profile has unclassified sighash: " + row["network"])
        if row.get("signing") and row.get("sighash") == "forkid" and not row.get(
            "forkid_vectors"
        ):
            raise SystemExit("fork-id profile lacks consensus vectors: " + row["network"])
        row.setdefault("fork_id", 0)
    rows.sort(key=lambda r: (r["name"].lower(), r["symbol"]))

    seen_ids: set[str] = set()
    seen_symbols: set[str] = set()
    profiles: list[str] = []
    catalog: list[str] = []
    policies: list[str] = []
    vectors: list[str] = []

    for row in rows:
        network = "fork_" + row["network"]
        symbol = row["symbol"]
        name = row["name"]
        slip44 = int(row["slip44"])
        p2pkh = int(row["p2pkh"])
        p2sh = int(row["p2sh"])
        sighash = row["sighash"]
        fork_id = int(row["fork_id"])
        bech32 = row.get("bech32") or ""
        segwit = str(row.get("segwit") or "")
        if not network or not symbol or not name:
            raise SystemExit("empty identity in registry")
        if network in seen_ids:
            raise SystemExit("duplicate network id: " + network)
        if symbol.upper() in seen_symbols:
            raise SystemExit("duplicate symbol: " + symbol)
        if not 0 <= slip44 < 0x80000000:
            raise SystemExit("invalid slip44: " + symbol)
        if not 0 <= p2pkh <= 0xFFFF or not 0 <= p2sh <= 0xFFFF:
            raise SystemExit("invalid address version: " + symbol)
        if sighash not in ("legacy", "forkid", "timestamp", "type", "unknown", "unverified"):
            raise SystemExit("invalid sighash: " + network)
        if sighash == "forkid" and p2pkh > 0xFF:
            raise SystemExit("fork-id profile must use a 1-byte version: " + network)
        if p2pkh <= 0xFF:
            encoding = "AddressEncoding::P2pkh"
            if p2sh > 0xFF:
                raise SystemExit("mixed-width address versions unsupported: " + network)
            utxo = f"{{0x{p2pkh:02x}, 0x{p2sh:02x}, nullptr, false}}"
            alt_p2pkh = 0
            alt_p2sh = 0
        else:
            encoding = "AddressEncoding::ZcashTransparent"
            utxo = "{0, 0, nullptr, false}"
            alt_p2pkh = p2pkh
            alt_p2sh = p2sh
        if bech32 and p2pkh > 0xFF:
            raise SystemExit("bech32 profile needs 1-byte base58 versions: " + network)
        if bech32 and not bech32.islower():
            raise SystemExit("bech32 HRP must be lowercase: " + network)
        seen_ids.add(network)
        seen_symbols.add(symbol.upper())
        profiles.append(
            f'  {{"{network}", {cpp_string(symbol)}, {cpp_string(name)}, '
            f"{slip44}, {slip44}, 44, DerivationStyle::Bip44, {encoding}, "
            f"{utxo}, 0, 0, 0x{alt_p2pkh:04x}, 0x{alt_p2sh:04x}, nullptr}},"
        )
        signing = bool(row.get("signing"))
        family = (
            "SighashFamily::Bitcoin"
            if sighash == "legacy"
            else "SighashFamily::ForkId"
            if sighash == "forkid"
            else ""
        )
        if signing and not family:
            raise SystemExit("signing profile has no consensus family: " + network)
        status = (
            f"source-verified chainparams and {sighash} sighash; signing enabled"
            if signing
            else "internal address profile; not exposed as a wallet"
        )
        capabilities = "WalletCapabilityAddress"
        if signing:
            capabilities += " | WalletCapabilityTransactionReview | WalletCapabilitySigning"
            catalog.append(
                f'  {{"{network}", {cpp_string(symbol)}, {cpp_string(name)}, {slip44}, '
                f'{capabilities}, "{network}", {cpp_string(status)}}},'
            )
            policies.append(f'  {{"{network}", {family}, {fork_id}}},')
        if p2pkh <= 0xFF:
            vectors.append(f'  {{"{network}", {cpp_string(p2pkh_address(p2pkh))}}},')

        # Native SegWit profiles are emitted only for rows whose chainparams
        # were read from the official repository and declare a bech32 HRP.
        if bech32 and "native" in segwit:
            native_id = network + "84"
            if native_id in seen_ids:
                raise SystemExit("duplicate network id: " + native_id)
            seen_ids.add(native_id)
            native_utxo = (
                f"{{0x{p2pkh:02x}, 0x{p2sh:02x}, {cpp_string(bech32)}, false}}"
            )
            profiles.append(
                f'  {{"{native_id}", {cpp_string(symbol)}, '
                f'{cpp_string(name + " Native SegWit")}, '
                f"{slip44}, {slip44}, 84, DerivationStyle::Bip44, "
                f"AddressEncoding::P2wpkh, {native_utxo}, 0, 0, 0, 0, nullptr}},"
            )
            if signing:
                catalog.append(
                    f'  {{"{native_id}", {cpp_string(symbol)}, '
                    f'{cpp_string(name + " Native SegWit")}, {slip44}, '
                    f'{capabilities}, "{native_id}", {cpp_string(status)}}},'
                )
                policies.append(f'  {{"{native_id}", {family}, {fork_id}}},')
        if "nested" in segwit:
            nested_id = network + "49"
            if nested_id in seen_ids:
                raise SystemExit("duplicate network id: " + nested_id)
            seen_ids.add(nested_id)
            nested_utxo = f"{{0x{p2pkh:02x}, 0x{p2sh:02x}, nullptr, false}}"
            profiles.append(
                f'  {{"{nested_id}", {cpp_string(symbol)}, '
                f'{cpp_string(name + " Nested SegWit")}, '
                f"{slip44}, {slip44}, 49, DerivationStyle::Bip44, "
                f"AddressEncoding::P2shP2wpkh, {nested_utxo}, 0, 0, 0, 0, nullptr}},"
            )
            if signing:
                catalog.append(
                    f'  {{"{nested_id}", {cpp_string(symbol)}, '
                    f'{cpp_string(name + " Nested SegWit")}, {slip44}, '
                    f'{capabilities}, "{nested_id}", {cpp_string(status)}}},'
                )
                policies.append(f'  {{"{nested_id}", {family}, {fork_id}}},')

    header = (
        "// Generated by tools/generate_fork_profiles.py from tools/fork_registry.json.\n"
        "// WalletForkCatalog.inc exposes only explicitly signable profiles.\n"
        "// Address-only profiles remain internal and are not user-facing wallets.\n"
    )
    PROFILES_OUT.write_text(header + "\n".join(profiles) + "\n", encoding="utf-8")
    CATALOG_OUT.write_text(header + "\n".join(catalog) + "\n", encoding="utf-8")
    POLICIES_OUT.write_text(header + "\n".join(policies) + "\n", encoding="utf-8")
    VECTORS_OUT.write_text('// TEST FIXTURES ONLY. Public secp256k1 private key = 1. NEVER RECEIVE FUNDS HERE.\n// Generated encoding expectations, not wallet-derived receiving addresses.\n#ifndef HEXWALLET_HOST_TEST\n#error "Address fixtures are restricted to host tests"\n#endif\n' + header + "\n".join(vectors) + "\n", encoding="utf-8")
    print(f"generated {len(profiles)} profiles and {len(policies)} signing policies "
          f"from {len(rows)} registry rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
