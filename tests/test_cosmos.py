"""C++ Cosmos MsgSend builder versus independent Python/OpenSSL fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_COSMOS_PROBE",
                            ROOT / "tests/host/cosmos_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/cosmos-vectors.json").read_text(encoding="utf8"))


def probe(payload, network, from_address, public_key):
    assert PROBE.exists(), "Build the real C++ Cosmos probe first"
    result = subprocess.run([str(PROBE), payload.hex(), network, from_address,
                             public_key], capture_output=True, text=True, timeout=20)
    assert result.returncode in (0, 1, 2), result.stdout + result.stderr
    return result.returncode, dict(line.split("=", 1)
                                   for line in result.stdout.splitlines())


class CosmosTests(unittest.TestCase):
    def test_independent_provenance(self):
        source = ROOT / "tools/generate_cosmos_vectors.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         VECTORS["generator_sha256"])
        self.assertIn("OpenSSL", VECTORS["source"])
        self.assertIn("TEST ONLY", VECTORS["parameters"])

    @unittest.skipUnless(importlib.util.find_spec("cryptography") is not None
                         and importlib.util.find_spec("Crypto") is not None,
                         "vector regeneration needs cryptography and pycryptodome")
    def test_vectors_are_current(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/generate_cosmos_vectors.py"),
                                 "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fixture_signatures_are_valid_and_low_s(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), bytes.fromhex(VECTORS["public_key"]))
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                signature = bytes.fromhex(case["signature"])
                self.assertEqual(len(signature), 64)
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                self.assertGreaterEqual(s, 1)
                self.assertLessEqual(s, order // 2)
                key.verify(utils.encode_dss_signature(r, s),
                           bytes.fromhex(case["digest"]),
                           ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def test_reviewed_bytes_match_the_independent_builder(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = probe(bytes.fromhex(case["payload"]),
                                     case["network"], case["from_address"],
                                     VECTORS["public_key"])
                self.assertEqual(code, 0, actual)
                expected = {
                    "from": case["from_address"], "to": case["to_address"],
                    "chain_id": case["chain_id"], "account": case["account"],
                    "sequence": case["sequence"], "amount": case["amount"],
                    "fee": case["fee"], "gas": case["gas"],
                    "amount_text": case["amount_text"],
                    "fee_text": case["fee_text"], "body": case["body"],
                    "auth_info": case["auth_info"], "digest": case["digest"],
                }
                for field, value in expected.items():
                    self.assertEqual(actual[field], value, field)

    def test_every_rejected_payload_is_refused(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["payload"]), case["network"],
                                       VECTORS["cases"][0]["from_address"],
                                       VECTORS["public_key"])[0], 1)

    def test_every_sampled_truncation_is_refused(self):
        for case in VECTORS["cases"]:
            raw = bytes.fromhex(case["payload"])
            for end in list(range(1, min(len(raw), 30))) + list(range(30, len(raw), 11)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(probe(raw[:end], case["network"],
                                           case["from_address"],
                                           VECTORS["public_key"])[0], 1)

    def test_foreign_owner_is_refused(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["payload"]),
                                       case["network"], case["to_address"],
                                       VECTORS["public_key"])[0], 1)

    def test_foreign_public_key_is_refused(self):
        foreign = "02" + "11" * 32
        case = VECTORS["cases"][0]
        self.assertEqual(probe(bytes.fromhex(case["payload"]), case["network"],
                               case["from_address"], foreign)[0], 1)


if __name__ == "__main__":
    unittest.main()
