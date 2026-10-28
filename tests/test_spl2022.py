"""C++ Token-2022 signer versus independent solders fixtures (no SDK in CI)."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "build" / "spl-svm-reference"
if (VENDORED / "solders").is_dir():
    sys.path.insert(0, str(VENDORED))
PROBE = Path(os.environ.get("HEXWALLET_SOLANA_PROBE", ROOT / "tests/host/solana_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/spl-2022-sdk.json").read_text(encoding="utf8"))


class Token2022Tests(unittest.TestCase):
    def probe(self, raw, mode=None):
        self.assertTrue(PROBE.exists(), "Build the real C++ Solana probe first")
        args = [str(PROBE), raw.hex(), VECTORS["seed"]]
        if mode:
            args.append(mode)
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        self.assertIn(result.returncode, (0, 1), result.stdout + result.stderr)
        return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())

    def test_independent_provenance(self):
        source = ROOT / "tools/generate_spl2022_vectors.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         VECTORS["generator_sha256"])
        self.assertIn("solders 0.28.0", VECTORS["source"])
        self.assertIn("TEST ONLY", VECTORS["parameters"])

    @unittest.skipUnless(importlib.util.find_spec("solders") is not None,
                         "vector regeneration needs solders 0.28.0")
    def test_vectors_are_current(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/generate_spl2022_vectors.py"),
                                 "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_signed_bytes_and_every_review_field(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                code, actual = self.probe(bytes.fromhex(case["message"]))
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["transaction"], case["transaction"])
                self.assertEqual(int(actual["total"]),
                                 sum(t["amount"] for t in case["transfers"] if t["kind"] == 0))
                self.assertEqual(int(actual["fee"]), case["fee"])
                for index, output in enumerate(case["transfers"]):
                    for field in ("source", "mint", "recipient", "amount",
                                  "decimals", "kind", "formatted"):
                        self.assertEqual(actual[f"{field}_{index}"], str(output[field]), field)

    def test_2022_transfers_are_labelled_as_such(self):
        kinds = {case["name"]: [t["kind"] for t in case["transfers"]]
                 for case in VECTORS["cases"]}
        self.assertEqual(kinds["t22-legacy-decimals-6"], [2])
        self.assertEqual(kinds["t22-decimals-18"], [2])
        self.assertEqual(kinds["t22-mixed-with-classic-and-sol"], [1, 2, 0])

    def test_unsupported_token_2022_instructions(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.probe(bytes.fromhex(case["message"]))[0], 1)

    def test_all_truncations(self):
        for case in (VECTORS["cases"][0], VECTORS["cases"][1]):
            raw = bytes.fromhex(case["message"])
            for end in range(len(raw)):
                with self.subTest(case=case["name"], length=end):
                    self.assertEqual(self.probe(raw[:end])[0], 1)
            self.assertEqual(self.probe(raw + b"\0")[0], 1)

    def test_approval_binds_token_program_identity_and_precision(self):
        raw = bytes.fromhex(VECTORS["cases"][0]["message"])
        for mode in ("tamper", "mint", "source", "destination", "decimals", "kind", "small"):
            with self.subTest(mode=mode):
                self.assertEqual(self.probe(raw, mode)[0], 1)


if __name__ == "__main__":
    unittest.main()
