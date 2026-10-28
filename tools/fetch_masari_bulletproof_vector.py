#!/usr/bin/env python3
"""Pin a real Masari RCT type-3 transaction as a firmware regression vector.

Masari's standard-Bulletproof path stays disabled until a transaction that a
Masari node accepted has been validated. This tool produces that vector from a
node or from a blob you already have; it never invents one.

Usage:
    # exact transaction
    python tools/fetch_masari_bulletproof_vector.py --url <daemon> --hash <txid>
    # find the first type-3 transaction in a block range (inclusive)
    python tools/fetch_masari_bulletproof_vector.py --url <daemon> --scan 1000000:1000200
    # offline: blob from get_transactions (as_hex)
    python tools/fetch_masari_bulletproof_vector.py --hex-file blob.hex --hash <txid>

Outputs:
    tests/fixtures/masari/tx3.bin      raw wire transaction
    tests/fixtures/masari/tx3.json     provenance: txid, source, sha256, size

`run_masari_self_tests()` then has to parse the blob, verify every Bulletproof
and reject single-byte edits. Only after that may shipping firmware be built
with -DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests/fixtures/masari"
BIN_PATH = FIXTURE_DIR / "tx3.bin"
JSON_PATH = FIXTURE_DIR / "tx3.json"

MAX_TX_BYTES = 16384
RCT_TYPE_BULLETPROOF = 3


def rpc(daemon: str, method: str, params: dict | None = None) -> dict:
    body = json.dumps({"method": method, "params": params or {}}).encode()
    request = urllib.request.Request(
        daemon.rstrip("/") + "/json_rpc",
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "HexWallet"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read())
    if "error" in payload:
        raise SystemExit(f"{method}: {payload['error']}")
    return payload.get("result", {})


def transactions(daemon: str, hashes: list[str]) -> list[dict]:
    result = rpc(
        daemon,
        "get_transactions",
        {"txs_hashes": hashes, "decode_as_json": True, "prune": False},
    )
    return result.get("txs", [])


def rct_type(tx: dict):
    raw = tx.get("as_json")
    if not raw:
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return decoded.get("rct_signatures", {}).get("type")


def find_type3(daemon: str, start: int, end: int):
    for height in range(start, end + 1):
        block = rpc(daemon, "get_block", {"height": height})
        hashes = block.get("json", {}).get("tx_hashes", [])
        for offset in range(0, len(hashes), 8):
            for tx in transactions(daemon, hashes[offset : offset + 8]):
                if rct_type(tx) == RCT_TYPE_BULLETPROOF:
                    blob = tx.get("as_hex") or tx.get("hex")
                    if blob:
                        print(f"found type-3 transaction in block {height}")
                        return tx["tx_hash"], blob
        print(f"block {height}: no type-3 transaction", file=sys.stderr)
    raise SystemExit(f"no RCT type-3 transaction in blocks {start}..{end}")


def main(argv: list[str]) -> int:
    args = dict(zip(argv[1::2], argv[2::2]))
    daemon = args.get("--url")
    txid = args.get("--hash")
    hex_file = args.get("--hex-file")
    scan = args.get("--scan")

    if hex_file is not None:
        blob_hex = pathlib.Path(hex_file).read_text(encoding="utf8").strip()
        source = f"file:{hex_file}"
        if txid is None:
            raise SystemExit("--hex-file requires --hash for provenance")
    elif scan is not None:
        if daemon is None:
            raise SystemExit("--scan requires --url")
        try:
            start_text, end_text = scan.split(":", 1)
            start, end = int(start_text), int(end_text)
        except ValueError:
            raise SystemExit("--scan expects <start>:<end>") from None
        if end < start:
            raise SystemExit("--scan end must not be below start")
        txid, blob_hex = find_type3(daemon, start, end)
        source = f"{daemon} (scan {start}:{end})"
    elif txid is not None and daemon is not None:
        result = transactions(daemon, [txid])
        if len(result) != 1:
            raise SystemExit(f"daemon returned {len(result)} transactions for {txid}")
        tx = result[0]
        if tx.get("tx_hash", "").lower() != txid.lower():
            raise SystemExit("daemon returned a different transaction hash")
        kind = rct_type(tx)
        if kind != RCT_TYPE_BULLETPROOF:
            raise SystemExit(f"transaction is RCT type {kind}, not {RCT_TYPE_BULLETPROOF}")
        blob_hex = tx.get("as_hex") or tx.get("hex")
        if not blob_hex:
            raise SystemExit("daemon reply has no transaction hex")
        source = daemon
    else:
        sys.stderr.write(__doc__)
        return 2

    try:
        blob = bytes.fromhex(blob_hex.strip())
    except ValueError as error:
        raise SystemExit(f"transaction hex is not valid hex: {error}") from error
    if not blob:
        raise SystemExit("empty transaction")
    if len(blob) > MAX_TX_BYTES:
        raise SystemExit(
            f"{len(blob)} bytes exceeds the firmware limit of {MAX_TX_BYTES}; "
            "the device would reject this transaction anyway"
        )

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    BIN_PATH.write_bytes(blob)
    manifest = {
        "txid": txid,
        "source": source,
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "note": (
            "Public test material. run_masari_self_tests() must parse this "
            "blob, verify every Bulletproof and reject single-byte edits "
            "before HEXWALLET_MSR_ENABLE_RCT_TYPE3 can be enabled."
        ),
    }
    JSON_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    print(f"wrote {BIN_PATH.relative_to(ROOT)} ({len(blob)} bytes)")
    print(f"txid  {txid}")
    print(f"sha256 {manifest['sha256']}")
    print("next: powershell -File tests/host/build.ps1 (expect 'masari=pass')")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
