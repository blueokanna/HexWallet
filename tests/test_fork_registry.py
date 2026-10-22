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
            source = json.dumps({"profiles": [
                {"network": "test" + str(i), "symbol": "T" + str(i),
                 "name": "Test " + str(i), "slip44": i,
                 "p2pkh": 0, "p2sh": 5, "sighash": claim}
                for i, claim in enumerate(("legacy", "forkid", "unverified"))
            ]})
            generator.REGISTRY.write_text(source, encoding="utf-8")
            self.assertEqual(generator.main(), 0)
            catalog = generator.CATALOG_OUT.read_text(encoding="utf-8")
            self.assertNotIn("WalletCapabilitySigning", catalog)
            self.assertNotIn("WalletCapabilityTransactionReview", catalog)
            self.assertEqual(catalog.count("WalletCapabilityAddress"), 3)
            self.assertEqual(generator.REGISTRY.read_text(encoding="utf-8"), source)


class SegwitProfileTests(unittest.TestCase):
    def test_segwit_rows_are_explicit_and_source_scoped(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            generator.REGISTRY = directory / "registry.json"
            generator.PROFILES_OUT = directory / "profiles.inc"
            generator.CATALOG_OUT = directory / "catalog.inc"
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
