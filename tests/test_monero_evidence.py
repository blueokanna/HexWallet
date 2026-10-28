"""Offline verification of pinned independent Monero evidence and rejection cases."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/monero-bp-plus"
PROBE = ROOT / "tests/host/bp_plus_probe.exe"


class MoneroEvidence(unittest.TestCase):
    def test_fixture_integrity(self):
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        for entry in manifest["cases"]:
            for suffix, field in (("txt", "proof_sha256"), ("json", "trace_sha256")):
                raw = (FIXTURES / f"{entry['name']}.{suffix}").read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(), entry[field])
            data = json.loads((FIXTURES / f"{entry['name']}.json").read_text())
            self.assertEqual(data["accepted"], "1")
            self.assertEqual(data["multiexp"], "01" + "00" * 31)
        self.assertEqual(hashlib.sha256((FIXTURES / "generators.json").read_bytes()).hexdigest(),
                         manifest["generators_sha256"])
        for path, digest in manifest["reference_sources_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)

    def test_review_proof_provenance(self):
        raw = (FIXTURES / "review.json").read_bytes()
        data = json.loads(raw)
        self.assertEqual(data["accepted"], "1")
        include = (ROOT / "src/generated/MoneroReviewProofTest.inc").read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(), include)
        self.assertIn("TEST ONLY", data["parameters"])

    @unittest.skipUnless(PROBE.exists(), "build tests/host/build.ps1 first")
    def test_all_generators(self):
        result = subprocess.run([str(PROBE), "--generators"], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(actual, json.loads((FIXTURES / "generators.json").read_text()))

    @unittest.skipUnless(PROBE.exists(), "build tests/host/build.ps1 first")
    def test_independently_rejected_mutations(self):
        cases = json.loads((FIXTURES / "negative-cases.json").read_text())
        base = (FIXTURES / "outputs-1.txt").read_text().splitlines()
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "candidate.txt"
            for case in cases:
                with self.subTest(case=case["name"]):
                    self.assertIn(case["reference_returncode"], (1, 2))
                    lines = base.copy()
                    if "truncate_lines" in case:
                        lines = lines[:case["truncate_lines"]]
                    else:
                        lines[case["line"]] = case["replacement"]
                    target.write_text("\n".join(lines) + "\n")
                    result = subprocess.run([str(PROBE), str(target)], capture_output=True,
                                            text=True, timeout=120)
                    self.assertIn(result.returncode, (1, 2), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
