#!/usr/bin/env python3
"""Pin a real Monero mainnet transaction as a firmware regression vector.

Reconstruct the wire blob from cached explorer JSON and require both its full
v2 transaction ID and size to match the external record. Monero's v2 ID is
Keccak(Keccak(prefix) || Keccak(RCT base) || Keccak(RCT prunable)); it is not
the prefix hash and its bytes are not reversed. Matching size alone proves
nothing about field order. This tool runs on the development PC, never firmware.

Usage:
    python tools/fetch_monero_vector.py --fetch     # download and cache JSON
    python tools/fetch_monero_vector.py --check     # re-verify the cached JSON
    python tools/fetch_monero_vector.py --write     # regenerate the .inc

The cached JSON lives in tools/monero_tx_vectors.json so the build works
offline and the vector can be audited by hand.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / "tools/monero_tx_vectors.json"
OUTPUT = ROOT / "src/generated/MoneroTxVectorsTest.inc"

# Mainnet transactions spanning different shapes. Each must be a v2 / RCT type
# 6 spend (not coinbase) to exercise the code path this firmware implements.
HASHES = [
    "05357a30c183be26e3b683fd83d8dc0c1c50b1ec01154bbeadd6d1ab027b5676",
]
EXPLORERS = [
    ("https://moneroexplorer.org/api/rawtransaction/{hash}",
     "https://moneroexplorer.org/api/transaction/{hash}"),
]


# --------------------------------------------------------------------------
# Keccak-256 (Monero uses the pre-standard padding byte 0x01)
# --------------------------------------------------------------------------
def keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak

    digest = keccak.new(digest_bits=256)
    digest.update(data)
    return digest.digest()


def write_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def parse_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7


def key(value: str) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(raw)}")
    return raw


def serialize(tx: dict) -> tuple[bytes, bytes, bytes]:
    prefix = bytearray()
    prefix += write_varint(int(tx["version"]))
    prefix += write_varint(int(tx["unlock_time"]))

    vin = tx["vin"]
    prefix += write_varint(len(vin))
    for item in vin:
        # Only txin_to_key spends appear in a RingCT transaction.
        if "key" not in item:
            raise ValueError(f"unsupported input kind: {sorted(item)}")
        entry = item["key"]
        prefix += write_varint(2)  # txin_to_key
        prefix += write_varint(int(entry["amount"]))
        offsets = [int(value) for value in entry["key_offsets"]]
        prefix += write_varint(len(offsets))
        for value in offsets:
            prefix += write_varint(value)
        prefix += key(entry["k_image"])

    vout = tx["vout"]
    prefix += write_varint(len(vout))
    for item in vout:
        target = item["target"]
        prefix += write_varint(int(item["amount"]))
        if "tagged_key" in target:
            prefix += write_varint(3)  # txout_to_tagged_key
            prefix += key(target["tagged_key"]["key"])
            tag = target["tagged_key"]["view_tag"]
            prefix += bytes([int(str(tag), 16)] if isinstance(tag, str) else [int(tag)])
        elif "key" in target:
            prefix += write_varint(2)  # txout_to_key
            prefix += key(target["key"])
        else:
            raise ValueError(f"unsupported output target: {sorted(target)}")

    extra = bytes(tx["extra"])
    prefix += write_varint(len(extra))
    prefix += extra

    # ---- rctSigBase -------------------------------------------------------
    rct = tx["rct_signatures"]
    rct_type = int(rct["type"])
    if rct_type != 6:
        raise ValueError(f"only RCT type 6 is covered, got {rct_type}")
    body = bytearray(prefix)
    body.append(rct_type)
    body += write_varint(int(rct["txnFee"]))
    for item in rct["ecdhInfo"]:
        body += bytes.fromhex(item["amount"])  # 8-byte truncated amount
    for item in rct["outPk"]:
        body += key(item)

    base_end = len(body)
    # ---- rctSigPrunable ---------------------------------------------------
    prunable = tx["rctsig_prunable"]
    proofs = prunable["bpp"]
    body += write_varint(len(proofs))
    for proof in proofs:
        # V is reconstructed from outPk and is NEVER serialized here.
        body += key(proof["A"])
        body += key(proof["A1"])
        body += key(proof["B"])
        body += key(proof["r1"])
        body += key(proof["s1"])
        body += key(proof["d1"])
        for name in ("L", "R"):
            items = proof[name]
            body += write_varint(len(items))
            for item in items:
                body += key(item)

    clsags = prunable["CLSAGs"]
    for sig in clsags:
        # s[] has NO length prefix: the ring size comes from key_offsets and
        # the reference serializer writes the elements directly. Then c1 and D.
        # The key image lives in txin_to_key, not here.
        for item in sig["s"]:
            body += key(item)
        body += key(sig["c1"])
        body += key(sig["D"])

    for item in prunable["pseudoOuts"]:
        body += key(item)

    return bytes(prefix), bytes(body[len(prefix):base_end]), bytes(body[base_end:])


def load(hashes: list[str]) -> dict[str, dict]:
    cached: dict[str, dict] = {}
    if CACHE.exists():
        cached = json.loads(CACHE.read_text(encoding="utf-8"))
    return cached


def fetch(hashes: list[str]) -> dict[str, dict]:
    cached = load(hashes)
    for tx_hash in hashes:
        if tx_hash in cached:
            continue
        record = None
        for raw_template, meta_template in EXPLORERS:
            try:
                def get(url: str) -> dict:
                    request = urllib.request.Request(
                        url, headers={"User-Agent": "HexWallet-vector-pinner/1.0"})
                    with urllib.request.urlopen(request, timeout=30) as response:
                        return json.loads(response.read().decode("utf-8"))["data"]

                # The raw endpoint carries the full structure; the transaction
                # endpoint carries the authoritative size and txid.
                raw = get(raw_template.format(hash=tx_hash))
                meta = get(meta_template.format(hash=tx_hash))
                raw["tx_size"] = int(meta["tx_size"])
                raw["tx_hash"] = meta["tx_hash"]
                raw["tx_version"] = int(meta["tx_version"])
                raw["_source"] = raw_template.format(hash=tx_hash)
                record = raw
                break
            except Exception as error:  # noqa: BLE001 - report and try the next
                sys.stderr.write(f"{raw_template}: {error}\n")
        if record is None:
            raise SystemExit(f"could not fetch {tx_hash}")
        cached[tx_hash] = record
        sys.stderr.write(f"cached {tx_hash}\n")
    CACHE.write_text(json.dumps(cached, indent=2, sort_keys=True), encoding="utf-8")
    return cached


def verify(record: dict, tx_hash: str) -> dict:
    prefix, base, prunable = serialize(record)
    blob = prefix + base + prunable
    computed_id = keccak256(keccak256(prefix) + keccak256(base) + keccak256(prunable)).hex()
    size_matches = len(blob) == int(record["tx_size"])
    id_matches = computed_id == tx_hash
    return {
        "hash": tx_hash,
        "size": len(blob),
        "expected_size": int(record["tx_size"]),
        "computed_id": computed_id,
        "id_matches": id_matches,
        "size_matches": size_matches,
        "blob": blob,
    }


def main() -> int:
    if "--fetch" in sys.argv:
        fetch(HASHES)
    records = load(HASHES)
    missing = [h for h in HASHES if h not in records]
    if missing:
        raise SystemExit(f"missing cached vectors {missing}; run --fetch")

    results = []
    ok = True
    for tx_hash in HASHES:
        result = verify(records[tx_hash], tx_hash)
        results.append(result)
        # Both checks are mandatory. Size alone cannot authenticate a blob.
        if not result["size_matches"] or not result["id_matches"]:
            ok = False
        if not result["id_matches"]:
            sys.stderr.write(
                f"ERROR: {tx_hash} txid mismatch (computed {result['computed_id']}).\n")
        sys.stderr.write(
            f"{tx_hash[:16]}… bytes={result['size']}/{result['expected_size']} "
            f"txid={'match' if result['id_matches'] else 'PENDING'}\n"
        )
    if not ok:
        raise SystemExit("vector verification failed: transaction ID or byte length differs")

    if "--write" in sys.argv:
        header = (
            "// Monero mainnet transactions, pinned by tools/fetch_monero_vector.py.\n"
            "// Generated. Do not edit by hand.\n"
            "//\n"
            "// Reconstructed from cached explorer JSON; full v2 transaction ID\n"
            "// and byte length match the external record. This establishes byte\n"
            "// provenance, not validation of a newly constructed transaction.\n"
            "//\n"
            "// {txid, byte length, raw transaction hex, computed full txid}\n"
        )
        rows = []
        for result in results:
            rows.append(
                "  {\n"
                f'    "{result["hash"]}",\n'
                f"    {result['size']},\n"
                f'    "{result["blob"].hex()}",\n'
                f'    "{result["computed_id"]}",\n'
                "  },"
            )
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(header + "\n".join(rows) + "\n", encoding="utf-8")
        sys.stderr.write(f"wrote {OUTPUT.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
