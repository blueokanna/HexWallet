#!/usr/bin/env python3
"""Generate address-only fork profiles from the compatibility registry.

Imported metadata cannot enable transaction signing. Each signing policy needs
an explicit implementation and independent consensus fixtures.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tools" / "fork_registry.json"
PROFILES_OUT = ROOT / "WalletForkProfiles.inc"
CATALOG_OUT = ROOT / "WalletForkCatalog.inc"

def cpp_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def classify(row: dict) -> str:
    # Address metadata and repository ancestry are not transaction evidence.
    # Audited signing policies belong in WalletNetworks.cpp with independent
    # consensus fixtures; imported registry rows cannot enable signing.
    return "unverified"


def main() -> int:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows = data["profiles"]
    for row in rows:
        row["sighash"] = classify(row)
        row.setdefault("fork_id", 0)
    rows.sort(key=lambda r: (r["name"].lower(), r["symbol"]))

    seen_ids: set[str] = set()
    seen_symbols: set[str] = set()
    profiles: list[str] = []
    catalog: list[str] = []

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
        if sighash not in ("legacy", "forkid", "unverified"):
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
        status = (
            "official chainparams address parameters; signing policy is separate"
            if row.get("source_verified")
            else "imported address metadata; no official chainparams review; signing unavailable"
        )
        capabilities = "WalletCapabilityAddress"
        catalog.append(
            f'  {{"{network}", {cpp_string(symbol)}, {cpp_string(name)}, {slip44}, '
            f'{capabilities}, "{network}", {cpp_string(status)}}},'
        )

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
            catalog.append(
                f'  {{"{native_id}", {cpp_string(symbol)}, '
                f'{cpp_string(name + " Native SegWit")}, {slip44}, '
                f'{capabilities}, "{native_id}", {cpp_string(status)}}},'
            )
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
            catalog.append(
                f'  {{"{nested_id}", {cpp_string(symbol)}, '
                f'{cpp_string(name + " Nested SegWit")}, {slip44}, '
                f'{capabilities}, "{nested_id}", {cpp_string(status)}}},'
            )

    header = (
        "// Generated by tools/generate_fork_profiles.py from tools/fork_registry.json.\n"
        "// Base parameters imported from iancoleman/bip39; rows carrying a source\n"
        "// field were cross-checked against the official chainparams.cpp. Native\n"
        "// SegWit requires an official bech32 HRP; nested SegWit requires explicit\n"
        "// segwit metadata from the same source.\n"
        "// Sorted by chain name A-Z.\n"
    )
    PROFILES_OUT.write_text(header + "\n".join(profiles) + "\n", encoding="utf-8")
    CATALOG_OUT.write_text(header + "\n".join(catalog) + "\n", encoding="utf-8")
    signable = sum(1 for row in rows if row["sighash"] != "unverified")
    print(f"generated {len(profiles)} profiles from {len(rows)} registry rows "
          f"({signable} imported signing claims)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
