"""C++ classic SPL signer versus independent SDK fixtures (no SDK needed in CI)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_SOLANA_PROBE", ROOT / "tests/host/solana_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/spl-sdk.json").read_text(encoding="utf8"))


class SplTests(unittest.TestCase):
    def probe(self, raw, mode=None):
        self.assertTrue(PROBE.exists(), "Build the real C++ Solana probe first")
        args = [str(PROBE), raw.hex(), VECTORS["seed"]]
        if mode: args.append(mode)
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_independent_provenance(self):
        source = ROOT / "tests/reference/generate_spl_vectors.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), VECTORS["generator_sha256"])
        self.assertEqual(VECTORS["source"], "solana-py 0.36.6 + solders 0.26.0")
        self.assertIn("TEST ONLY", VECTORS["parameters"])

    def test_signed_bytes_and_every_review_field(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = self.probe(bytes.fromhex(case["message"]))
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["transaction"], case["transaction"])
                native_total = sum(o["amount"] for o in case["transfers"] if o["kind"] == 0)
                self.assertEqual(int(actual["total"]), native_total)
                self.assertEqual(int(actual["fee"]), 5201 if "priority" in case["name"] else 5000)
                for index, output in enumerate(case["transfers"]):
                    for field in ("source", "mint", "recipient", "amount", "decimals", "kind", "formatted"):
                        self.assertEqual(actual[f"{field}_{index}"], str(output[field]), field)

    def test_unsupported_and_contradictory_instructions(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.probe(bytes.fromhex(case["message"]))[0], 1)

    def test_all_truncations_legacy_and_v0(self):
        for case in (VECTORS["cases"][0], VECTORS["cases"][7]):
            raw = bytes.fromhex(case["message"])
            for end in range(len(raw)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(self.probe(raw[:end])[0], 1)
            self.assertEqual(self.probe(raw+b"\0")[0], 1)

    def test_approval_binds_token_identity_precision_and_accounts(self):
        raw = bytes.fromhex(VECTORS["cases"][1]["message"])
        for mode in ("tamper", "mint", "source", "destination", "decimals", "kind", "small"):
            with self.subTest(mode=mode):
                self.assertEqual(self.probe(raw, mode)[0], 1)


if __name__ == "__main__": unittest.main()
