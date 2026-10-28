"""Independent XRPL Payment fixtures for the firmware review/serializer.

Uses xrpl-py for the binary codec and the published BIP44 path
m/44'/144'/0'/0/0. TEST ONLY seed 00..3f; never use for value.
"""
from __future__ import annotations
import hashlib
import hmac
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from xrpl.core import binarycodec
from xrpl.core.addresscodec import encode_classic_address

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/fixtures/xrp-sdk.json"
SEED = bytes(range(64))
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(k, p=G):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r


def compressed(p):
    return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, "big")


def derive(path):
    node = hmac.new(b"Bitcoin seed", SEED, hashlib.sha512).digest()
    key, chain = int.from_bytes(node[:32], "big"), node[32:]
    for part in path.split("/")[1:]:
        hardened = part.endswith("'")
        index = int(part[:-1] if hardened else part)
        index |= 0x80000000 if hardened else 0
        data = (b"\x00" + key.to_bytes(32, "big") if hardened else compressed(mul(key))) + index.to_bytes(4, "big")
        node = hmac.new(chain, data, hashlib.sha512).digest()
        key = (int.from_bytes(node[:32], "big") + key) % N
        chain = node[32:]
    return key


def amount_bytes(drops):
    return (0x4000000000000000 | drops).to_bytes(8, "big")


def payload(amount, fee, sequence, last, tag, destination):
    return (bytes([1, 1 if tag is not None else 0]) + amount.to_bytes(8, "big")
            + fee.to_bytes(8, "big") + sequence.to_bytes(4, "big")
            + last.to_bytes(4, "big") + (tag or 0).to_bytes(4, "big") + destination)


def main():
    path = "m/44'/144'/0'/0/0"
    key = derive(path)
    pub = compressed(mul(key))
    account = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    source = encode_classic_address(account)
    destination = encode_classic_address(bytes([0x11]) * 20)
    cases = []
    for name, amount, fee, seq, last, tag in (
        ("payment", 1_000_000, 10, 1, 100, None),
        ("payment-tag", 25_000_000, 12, 42, 500, 12345),
        ("payment-zero-tag", 7, 10, 4294967295, 4294967295, 0),
    ):
        body = payload(amount, fee, seq, last, tag, bytes([0x11]) * 20)
        tx = {"TransactionType": "Payment", "Flags": 0x80000000,
              "Sequence": seq, "LastLedgerSequence": last, "Amount": str(amount),
              "Fee": str(fee), "SigningPubKey": pub.hex().upper(),
              "Account": source, "Destination": destination}
        if tag is not None:
            tx["DestinationTag"] = tag
        signed_hex = binarycodec.encode_for_signing(tx)
        unsigned = bytes.fromhex(signed_hex)[4:]
        digest = hashlib.sha512(b"\x53\x54\x58\x00" + unsigned).digest()[:32]
        cases.append({"name": name, "payload": body.hex(), "public_key": pub.hex(),
                      "source": source, "destination": destination,
                      "unsigned": unsigned.hex(), "hash": digest.hex(),
                      "amount": str(amount), "fee": str(fee), "sequence": seq,
                      "last": last, "tag": tag})
    rejected = []
    base = payload(1_000_000, 10, 1, 100, None, bytes([0x11]) * 20)
    for name, body in (
        ("zero-amount", payload(0, 10, 1, 100, None, bytes([0x11]) * 20)),
        ("fee-too-low", payload(1, 9, 1, 100, None, bytes([0x11]) * 20)),
        ("fee-too-high", payload(1, 2_000_001, 1, 100, None, bytes([0x11]) * 20)),
        ("zero-sequence", payload(1, 10, 0, 100, None, bytes([0x11]) * 20)),
        ("zero-last", payload(1, 10, 1, 0, None, bytes([0x11]) * 20)),
        ("zero-destination", payload(1, 10, 1, 100, None, bytes(20))),
        ("self-destination", payload(1, 10, 1, 100, None, account)),
        ("bad-version", bytes([2]) + base[1:]),
        ("bad-tag-flag", bytes([1, 2]) + base[2:]),
        ("truncated", base[:-1]),
    ):
        rejected.append({"name": name, "payload": body.hex()})
    payload_out = {"sdk": "xrpl-py", "verification": "xrpl binary codec + hashlib",
                   "seed": SEED.hex(), "path": path, "public_key": pub.hex(),
                   "source": source, "destination": destination, "cases": cases,
                   "rejected": rejected}
    text = json.dumps(payload_out, indent=2) + "\n"
    if "--check" in sys.argv:
        if OUT.read_text(encoding="utf8") != text:
            print("XRP vectors are stale", file=sys.stderr)
            return 1
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf8", newline="\n")
        print(f"generated {len(cases)} accepted and {len(rejected)} rejected XRP cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
