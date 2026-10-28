"""C++ NEAR review/sign versus near-api-js fixtures."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_NEAR_PROBE",
                            ROOT / "tests/host/near_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/near-sdk.json").read_text(encoding="utf8"))
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def slip10(path):
    seed = bytes.fromhex(VECTORS["seed"])
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in path:
        data = b"\x00" + key + (index | 0x80000000).to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


def probe(transaction, index):
    assert PROBE.exists(), "Build the real C++ NEAR probe first"
    result = subprocess.run([str(PROBE), transaction.hex(), VECTORS["seed"], str(index)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode in (0, 1, 2), result.stdout + result.stderr
    return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())


class NearTests(unittest.TestCase):
    def test_fixture_provenance(self):
        self.assertEqual(VECTORS["sdk"], "near-api-js")
        self.assertEqual(VECTORS["version"], "5.1.1")
        self.assertIn("TEST ONLY", VECTORS["parameters"])
        check = subprocess.run(
            [sys.executable, str(ROOT / "tools/generate_near_selftest.py"), "--check"],
            capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_fixture_signatures_verify_with_derived_ed25519_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                key = Ed25519PrivateKey.from_private_bytes(slip10([44, 397, case["index"]]))
                signed = bytes.fromhex(case["signed"])
                transaction = bytes.fromhex(case["transaction"])
                self.assertEqual(signed[:len(transaction)], transaction)
                self.assertEqual(signed[len(transaction)], 0)  # Signature::ED25519
                key.public_key().verify(
                    signed[len(transaction) + 1:],
                    hashlib.sha256(transaction).digest())

    def test_probe_matches_every_sdk_field(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = probe(bytes.fromhex(case["transaction"]), case["index"])
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["signed"], case["signed"])
                self.assertEqual(actual["hash"], case["hash"])
                self.assertEqual(actual["signer"], case["signer"])
                self.assertEqual(actual["receiver"], case["receiver"])
                self.assertEqual(actual["public_key"], case["public_key"])
                self.assertEqual(actual["block_hash"], case["block_hash"])
                self.assertEqual(actual["nonce"], str(case["nonce"]))
                self.assertEqual(actual["actions"], str(len(case["amounts"])))
                self.assertEqual(actual["total_text"], case["formatted"])

    def test_every_rejected_transaction_is_refused(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["transaction"]), case["index"])[0], 1)

    def test_sampled_truncations_are_refused(self):
        for case in VECTORS["cases"]:
            raw = bytes.fromhex(case["transaction"])
            for end in list(range(1, min(len(raw), 30))) + list(range(30, len(raw), 17)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(probe(raw[:end], case["index"])[0], 1)

    def test_foreign_index_is_refused(self):
        case = VECTORS["cases"][0]
        self.assertEqual(probe(bytes.fromhex(case["transaction"]), case["index"] + 1)[0], 1)


if __name__ == "__main__":
    unittest.main()
