"""C++ Algorand review/sign versus py-algorand-sdk fixtures."""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_ALGORAND_PROBE",
                            ROOT / "tests/host/algorand_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/algorand-sdk.json").read_text(encoding="utf8"))


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
    assert PROBE.exists(), "Build the real C++ Algorand probe first"
    result = subprocess.run([str(PROBE), transaction.hex(), VECTORS["seed"], str(index)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode in (0, 1, 2), result.stdout + result.stderr
    return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())


class AlgorandTests(unittest.TestCase):
    def test_independent_provenance(self):
        generator = ROOT / "tests/reference/generate_algorand_vectors.py"
        self.assertTrue(generator.exists())
        self.assertEqual(hashlib.sha256(generator.read_bytes()).hexdigest(),
                         VECTORS["generator_sha256"])
        self.assertEqual(VECTORS["sdk"], "py-algorand-sdk")
        self.assertIn("TEST ONLY", VECTORS["parameters"])
        check = subprocess.run(
            [sys.executable, str(ROOT / "tools/generate_algorand_selftest.py"), "--check"],
            capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_fixture_signatures_verify_with_derived_ed25519_key(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                key = Ed25519PrivateKey.from_private_bytes(
                    slip10([44, 283, 0, 0, case["index"]]))
                signed = bytes.fromhex(case["signed"])
                self.assertEqual(signed[:7], b"\x82\xa3sig\xc4\x40")
                self.assertEqual(signed[71:75], b"\xa3txn")
                key.public_key().verify(signed[7:71], b"TX" + signed[75:])

    def test_probe_matches_every_sdk_field(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = probe(bytes.fromhex(case["transaction"]), case["index"])
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["signed"], case["signed"])
                text = case["txid"]
                self.assertEqual(actual["txid"],
                                 base64.b32decode(text + "=" * (-len(text) % 8)).hex())
                self.assertEqual(actual["sender"], case["sender"])
                self.assertEqual(actual["recipient"], case["recipient"])
                self.assertEqual(actual["kind"], str(case["kind"]))
                self.assertEqual(actual["amount"], str(case["amount"]))
                self.assertEqual(actual["asset_id"], str(case["asset_id"]))
                self.assertEqual(actual["fee"], str(case["fee"]))
                self.assertEqual(actual["note"], case["note"])
                self.assertEqual(actual["lease"], case["lease"])

    def test_every_rejected_transaction_is_refused(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["transaction"]), case["index"])[0], 1)

    def test_sampled_truncations_are_refused(self):
        for case in VECTORS["cases"]:
            raw = bytes.fromhex(case["transaction"])
            for end in list(range(1, min(len(raw), 30))) + list(range(30, len(raw), 13)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(probe(raw[:end], case["index"])[0], 1)

    def test_foreign_index_is_refused(self):
        case = VECTORS["cases"][0]
        self.assertEqual(probe(bytes.fromhex(case["transaction"]), case["index"] + 1)[0], 1)


if __name__ == "__main__":
    unittest.main()
