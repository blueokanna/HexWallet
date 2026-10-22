"""Imported metadata must never authorize transaction signing."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "fork_generator", ROOT / "tools" / "generate_fork_profiles.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class ForkRegistryTests(unittest.TestCase):
    def test_claimed_sighash_cannot_enable_signing(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            generator.REGISTRY = directory / "registry.json"
            generator.PROFILES_OUT = directory / "profiles.inc"
            generator.CATALOG_OUT = directory / "catalog.inc"
            generator.POLICIES_OUT = directory / "policies.inc"
            generator.VECTORS_OUT = directory / "vectors.inc"
            source = json.dumps({"profiles": [
                {"network": "test" + str(i), "symbol": "T" + str(i),
                 "name": "Test " + str(i), "slip44": i,
                 "p2pkh": 0, "p2sh": 5, "sighash": claim}
                for i, claim in enumerate(("legacy", "forkid", "unverified"))
            ]})
            generator.REGISTRY.write_text(source, encoding="utf-8")
            self.assertEqual(generator.main(), 0)
            catalog = generator.CATALOG_OUT.read_text(encoding="utf-8")
            self.assertFalse(
                any(line.lstrip().startswith("{") for line in catalog.splitlines()))
            self.assertEqual(generator.REGISTRY.read_text(encoding="utf-8"), source)


class SigningEvidenceTests(unittest.TestCase):
    def test_signing_rows_have_consensus_evidence(self):
        registry = json.loads(
            (ROOT / "tools" / "fork_registry.json").read_text(encoding="utf-8"))
        for row in registry["profiles"]:
            if not row.get("signing"):
                continue
            with self.subTest(network=row["network"]):
                self.assertIn(row.get("sighash"), ("legacy", "forkid"))
                self.assertTrue(row.get("source"))
                self.assertTrue(row.get("source_verified"))
                self.assertTrue(
                    row.get("sighash_source", "").startswith(
                        "https://raw.githubusercontent.com/"))

    def test_audit_covers_every_signing_row(self):
        registry = json.loads(
            (ROOT / "tools" / "fork_registry.json").read_text(encoding="utf-8"))
        audit = json.loads(
            (ROOT / "tools" / "utxo_sighash_audit.json").read_text(encoding="utf-8"))
        audited = {row["network"]: row["verdict"] for row in audit["rows"]}
        for row in registry["profiles"]:
            if row.get("signing"):
                with self.subTest(network=row["network"]):
                    self.assertEqual(row["sighash"], audited[row["network"]])

    def test_unsupported_verdicts_cannot_sign(self):
        registry = json.loads(
            (ROOT / "tools" / "fork_registry.json").read_text(encoding="utf-8"))
        for row in registry["profiles"]:
            if row.get("sighash") in ("timestamp", "unknown"):
                with self.subTest(network=row["network"]):
                    self.assertFalse(row.get("signing"))

    def test_fork_id_signing_requires_vectors(self):
        registry = json.loads(
            (ROOT / "tools" / "fork_registry.json").read_text(encoding="utf-8"))
        for row in registry["profiles"]:
            if row.get("signing") and row.get("sighash") == "forkid":
                with self.subTest(network=row["network"]):
                    self.assertTrue(row.get("forkid_vectors"))


class SegwitProfileTests(unittest.TestCase):
    def test_segwit_rows_are_explicit_and_source_scoped(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            generator.REGISTRY = directory / "registry.json"
            generator.PROFILES_OUT = directory / "profiles.inc"
            generator.CATALOG_OUT = directory / "catalog.inc"
            generator.POLICIES_OUT = directory / "policies.inc"
            generator.VECTORS_OUT = directory / "vectors.inc"
            source = json.dumps({"profiles": [
                {"network": "sugar", "symbol": "SUGAR", "name": "Sugar",
                 "slip44": 408, "p2pkh": 63, "p2sh": 125,
                 "bech32": "sugar", "segwit": "native+nested",
                 "source_verified": True, "sighash": "unverified"},
                {"network": "plain", "symbol": "PLAIN", "name": "Plain",
                 "slip44": 409, "p2pkh": 64, "p2sh": 126,
                 "sighash": "unverified"},
            ]})
            generator.REGISTRY.write_text(source, encoding="utf-8")
            self.assertEqual(generator.main(), 0)
            profiles = generator.PROFILES_OUT.read_text(encoding="utf-8")
            self.assertIn('"fork_sugar84"', profiles)
            self.assertIn('"fork_sugar49"', profiles)
            self.assertIn('"sugar", false', profiles)
            self.assertNotIn('"fork_plain84"', profiles)
            self.assertNotIn('"fork_plain49"', profiles)


if __name__ == "__main__":
    unittest.main()
