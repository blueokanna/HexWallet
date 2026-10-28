"""C++ TRON review versus independent Python/OpenSSL fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_TRON_PROBE", ROOT / "tests/host/tron_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/tron-vectors.json").read_text(encoding="utf8"))
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = B58[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + encoded


def probe(raw, address):
    assert PROBE.exists(), "Build the real C++ TRON probe first"
    result = subprocess.run([str(PROBE), raw.hex(), address],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode in (0, 1, 2), result.stdout + result.stderr
    return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())


class TronTests(unittest.TestCase):
    def test_signer_revalidates_all_review_fields_and_bounds(self):
        for case in VECTORS['cases']:
            for field in ('oversize', 'raw', 'kind', 'decimals', 'fee', 'expiration',
                          'timestamp', 'id_flag', 'owner', 'recipient', 'contract',
                          'amount', 'id', 'block', 'txid', 'owner_text',
                          'recipient_text', 'contract_text', 'symbol', 'amount_text', 'id_text'):
                with self.subTest(case=case['name'], field=field):
                    result = subprocess.run([str(PROBE), case['raw'], VECTORS['address'], field],
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('tamper_rejected=1', result.stdout)

    def test_fractional_amount_boundaries(self):
        for amount in (1, 99999, 100000, 500000, 999999, 1000000, 1000001):
            result = subprocess.run([str(PROBE), 'format', str(amount)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             f'amount={amount // 1000000}.{amount % 1000000:06d} TRX')

    def test_independent_provenance(self):
        source = ROOT / "tools/generate_tron_vectors.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         VECTORS["generator_sha256"])
        self.assertIn("OpenSSL", VECTORS["source"])
        self.assertIn("TEST ONLY", VECTORS["parameters"])

    @unittest.skipUnless(importlib.util.find_spec("cryptography") is not None
                         and importlib.util.find_spec("Crypto") is not None,
                         "vector regeneration needs cryptography and pycryptodome")
    def test_vectors_are_current(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/generate_tron_vectors.py"),
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
                raw = bytes.fromhex(case["raw"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), case["txid"])
                signature = bytes.fromhex(case["signature"])
                self.assertEqual(len(signature), 65)
                self.assertIn(signature[64], (27, 28))
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:64], "big")
                self.assertGreaterEqual(s, 1)
                self.assertLessEqual(s, order // 2)
                der = utils.encode_dss_signature(r, s)
                key.verify(der, bytes.fromhex(case["txid"]),
                           ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def test_signed_cases_are_reviewed_exactly(self):
        kinds = {"native": ("0", "TRX"), "trc20": ("1", "USDT"),
                 "trc721": ("2", "TRC-721"), "trc1155": ("3", "TRC-1155")}
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = probe(bytes.fromhex(case["raw"]), VECTORS["address"])
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["txid"], case["txid"])
                self.assertEqual(actual["recipient"], case["recipient"])
                expected_kind, expected_token = kinds[case["kind"]]
                self.assertEqual(actual["kind"], expected_kind)
                self.assertEqual(actual["token"], expected_token)
                if case["kind"] == "trc20":
                    self.assertEqual(actual["contract"], VECTORS["trc20_usdt_contract"])
                    self.assertEqual(actual["amount"], "25.000000 USDT")
                elif case["kind"] == "trc721":
                    self.assertEqual(actual["amount"], "1 NFT")
                    self.assertEqual(actual["token_id"], "4242")
                elif case["kind"] == "trc1155":
                    self.assertEqual(actual["amount"], "3 TRC-1155")
                    self.assertEqual(actual["token_id"], "7")
                else:
                    self.assertEqual(actual["amount"], "1.500000 TRX")

    def test_every_rejected_vector_is_refused(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["raw"]), VECTORS["address"])[0], 1)

    def test_every_sampled_truncation_is_refused(self):
        for case in VECTORS["cases"]:
            raw = bytes.fromhex(case["raw"])
            for end in list(range(1, min(len(raw), 40))) + list(range(40, len(raw), 7)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(probe(raw[:end], VECTORS["address"])[0], 1)

    def test_foreign_owner_is_refused(self):
        foreign = b"\x41" + bytes([0x33]) * 20
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["raw"]), base58check(foreign))[0], 1)


if __name__ == "__main__":
    unittest.main()
