"""Firmware XDR/signature bytes checked against independent Stellar SDK output."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_STELLAR_PROBE", ROOT / "tests/host/stellar_probe.exe"))
FIXTURE = json.loads((ROOT / "tests/fixtures/stellar-sdk.json").read_text(encoding="utf8"))

class StellarTests(unittest.TestCase):
    def probe(self, raw, index=0, mode=None, seed=None):
        self.assertTrue(PROBE.exists(), "Build the Stellar C++ probe first")
        args = [str(PROBE), raw.hex(), seed or FIXTURE["seed"], str(index)]
        if mode: args.append(mode)
        result = subprocess.run(args, capture_output=True, text=True, timeout=25)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_provenance(self):
        self.assertEqual(FIXTURE["version"], "13.1.0")
        self.assertEqual(FIXTURE["generator_sha256"], hashlib.sha256(
            (ROOT/"tests/reference/generate_stellar_vectors.py").read_bytes()).hexdigest())
        self.assertIn("TEST ONLY", FIXTURE["parameters"])

    def test_device_vector_matches_sdk_fixture(self):
        import sys
        result = subprocess.run([sys.executable, str(ROOT / "tools/generate_stellar_selftest.py"), "--check"],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_envelope_hash_and_review(self):
        for case in FIXTURE["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = self.probe(bytes.fromhex(case["request"]), case["index"])
                self.assertEqual(code, 0, actual)
                for field in ("transaction", "source", "hash"):
                    self.assertEqual(actual[field], case[field])
                for field in ("fee", "memo_type", "memo"):
                    self.assertEqual(actual[field], str(case[field]))
                self.assertEqual(actual["path"], f"m/44'/148'/{case['index']}'")
                self.assertEqual(int(actual["count"]), len(case["operations"]))
                self.assertEqual(actual["sequence"], "123456790")
                self.assertEqual(actual["min_time"], "1700000000")
                self.assertEqual(actual["max_time"], "1800000000")
                for i, op in enumerate(case["operations"]):
                    for field, value in op.items(): self.assertEqual(actual[f"{field}_{i}"], str(value))

    def test_sdk_rejection_cases(self):
        for case in FIXTURE["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.probe(bytes.fromhex(case["request"]), case["index"])[0], 1)

    def test_all_truncations_and_trailing_bytes(self):
        # Exercise the shortest native and longest issued/memo/dynamic layouts.
        for case in (FIXTURE["cases"][0], FIXTURE["cases"][1], FIXTURE["cases"][6]):
            raw = bytes.fromhex(case["request"])
            for n in range(len(raw)):
                with self.subTest(case=case["name"], length=n):
                    self.assertEqual(self.probe(raw[:n])[0], 1)
            self.assertEqual(self.probe(raw + b"\0")[0], 1)

    def test_review_tampering_and_key_binding(self):
        raw = bytes.fromhex(FIXTURE["cases"][0]["request"])
        for mode in ("amount", "destination", "issuer", "asset", "formatted", "type", "source",
                     "fee", "sequence", "min_time", "max_time", "memo_type", "memo", "count",
                     "hash", "raw", "index", "size", "small"):
            with self.subTest(mode=mode): self.assertEqual(self.probe(raw, mode=mode)[0], 1)
        self.assertEqual(self.probe(raw, seed="01"*64)[0], 1)
        self.assertEqual(self.probe(raw, index=2**31)[0], 1)

    def test_malformed_xdr_and_unsupported_unions(self):
        raw = bytes.fromhex(FIXTURE["cases"][0]["request"])
        # Network(32), envelope(4), source(36), fee(4), sequence(8), time(20),
        # memo(4), op count(4), source pointer(4), type(4), destination(36),
        # asset(4), amount(8), extension(4), signatures(4).
        mutations = [(32, 0), (32, 5), (36, 256), (84, 2), (104, 5),
                     (108, 0), (108, 9), (112, 2), (116, 8), (120, 256),
                     (156, 3), (168, 1), (172, 1)]
        for offset, value in mutations:
            bad = bytearray(raw); bad[offset:offset+4] = value.to_bytes(4, "big")
            with self.subTest(offset=offset, value=value): self.assertEqual(self.probe(bad)[0], 1)
        for amount in (0, 2**63, 2**64-1):
            bad = bytearray(raw); bad[160:168] = amount.to_bytes(8, "big")
            self.assertEqual(self.probe(bad)[0], 1)
        # Nonzero XDR string padding must not be silently normalized.
        bad = bytearray.fromhex(FIXTURE["cases"][1]["request"])
        bad[123] = 1
        self.assertEqual(self.probe(bad)[0], 1)

if __name__ == "__main__": unittest.main()
