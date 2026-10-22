"""Cross-check generated P2PKH vectors with an independent base58check encoder."""
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TEST_PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
VECTOR = re.compile(r'\{"(fork_[^"]+)", "([^"]+)"\}')


def base58check(payload: bytes) -> str:
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + digest
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = ALPHABET[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + encoded


def p2pkh(version: int) -> str:
    sha = hashlib.sha256(TEST_PUBKEY).digest()
    payload = bytes([version]) + hashlib.new("ripemd160", sha).digest()
    return base58check(payload)


class ForkAddressVectorTests(unittest.TestCase):
    def test_vectors_match_independent_encoder(self):
        registry = json.loads(
            (ROOT / "tools" / "fork_registry.json").read_text(encoding="utf-8"))
        lines = (ROOT / "tests/fixtures/WalletForkAddressVectors.inc").read_text(
            encoding="utf-8").splitlines()
        vectors = {match.group(1): match.group(2)
                   for line in lines for match in [VECTOR.search(line)] if match}
        expected = {}
        for row in registry["profiles"]:
            if row["p2pkh"] <= 0xFF:
                expected["fork_" + row["network"]] = p2pkh(row["p2pkh"])
        self.assertEqual(vectors, expected)


if __name__ == "__main__":
    unittest.main()
