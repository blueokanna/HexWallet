"""Real firmware parser/signer versus independent solders SDK transaction bytes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_SOLANA_PROBE", ROOT / "tests/host/solana_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/solana-sdk.json").read_text(encoding="utf8"))

class SolanaTests(unittest.TestCase):
    def run_probe(self, raw, seed=None, mode=None):
        self.assertTrue(PROBE.exists(), "Build the Solana host harness first")
        args = [str(PROBE), raw.hex(), seed or VECTORS["seed"]]
        if mode: args.append(mode)
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_reference_provenance(self):
        self.assertEqual(VECTORS["version"], "0.26.0")
        self.assertIn("TEST ONLY", VECTORS["parameters"])
        source = ROOT / "tests/reference/generate_solana_vectors.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), VECTORS["generator_sha256"])

    def test_complete_signed_bytes_and_display_fields(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = self.run_probe(bytes.fromhex(case["message"]))
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["transaction"], case["transaction"])
                self.assertEqual(actual["payer"], case["payer"])
                self.assertEqual(int(actual["fee"]), 5000 + case["priority_fee"])
                self.assertEqual(int(actual["total"]), sum(o["lamports"] for o in case["transfers"]))
                for i, output in enumerate(case["transfers"]):
                    self.assertEqual(actual[f"recipient_{i}"], output["recipient"])
                    self.assertEqual(int(actual[f"amount_{i}"]), output["lamports"])

    def test_every_truncation_and_trailing_bytes(self):
        raw = bytes.fromhex(VECTORS["cases"][0]["message"])
        for n in range(len(raw)):
            with self.subTest(length=n):
                self.assertEqual(self.run_probe(raw[:n])[0], 1)
        self.assertEqual(self.run_probe(raw+b"\0")[0], 1)

    def test_wrong_owner_changed_review_and_short_output(self):
        raw = bytes.fromhex(VECTORS["cases"][0]["message"])
        self.assertEqual(self.run_probe(raw, seed="01"*64)[0], 1)
        self.assertEqual(self.run_probe(raw, mode="tamper")[0], 1)
        self.assertEqual(self.run_probe(raw, mode="small")[0], 1)

    def test_malformed_or_unreviewable_messages(self):
        raw = bytearray.fromhex(VECTORS["cases"][0]["message"])
        mutations = {}
        def replace(name, offset, value):
            candidate = raw.copy(); candidate[offset:offset+len(value)] = value
            mutations[name] = candidate
        replace("additional-signer", 0, b"\x02")
        replace("readonly-payer", 1, b"\x01")
        replace("writable-program", 2, b"\0")
        replace("readonly-destination", 2, b"\x02")
        replace("duplicate-account", 36, raw[4:36])
        replace("unknown-program", 68, bytes([7])*32)
        replace("zero-blockhash", 100, bytes(32))
        replace("invalid-program-index", 133, b"\xff")
        replace("wrong-source", 135, b"\x01")
        replace("self-transfer", 136, b"\0")
        replace("out-of-range-destination", 136, b"\xff")
        replace("unsupported-instruction", 138, b"\0\0\0\0")
        replace("zero-amount", 142, bytes(8))
        replace("total-overflow", 142, bytes([255])*8)
        mutations["noncanonical-shortvec"] = raw[:3]+b"\x83\0"+raw[4:]
        mutations["invalid-shortvec"] = raw[:3]+b"\xff\xff\x04"+raw[4:]
        mutations["unknown-version"] = b"\x81"+raw
        v0 = bytearray.fromhex(VECTORS["cases"][2]["message"])
        v0[-1] = 1; mutations["unresolved-address-table"] = v0
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                self.assertEqual(self.run_probe(candidate)[0], 1)

    def test_priority_fee_limits_and_canonical_budget(self):
        raw = bytearray.fromhex(VECTORS["cases"][1]["message"])
        # Locate the SDK's instruction data, not a wallet encoder.
        limit = raw.index(bytes.fromhex("02400d0300"))
        price = raw.index(bytes.fromhex("03e903000000000000"))
        cases=[]
        for value in (0, 1400001):
            copy=raw.copy(); copy[limit+1:limit+5]=value.to_bytes(4,"little"); cases.append(copy)
        for value in (2**64-1, 1000000000):
            copy=raw.copy(); copy[price+1:price+9]=value.to_bytes(8,"little"); cases.append(copy)
        copy=raw.copy(); copy[price]=2; cases.append(copy) # duplicate/invalid limit
        for candidate in cases: self.assertEqual(self.run_probe(candidate)[0],1)

if __name__ == "__main__": unittest.main()
