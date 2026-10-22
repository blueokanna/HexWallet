"""The mining table ships only chains with an exposed signing catalog entry."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "mining_generator", ROOT / "tools" / "generate_mining_catalog.py")
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class MiningCatalogTests(unittest.TestCase):
    def test_known_coin_maps_and_unknown_stays_null(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / "src/generated").mkdir(parents=True)
            (directory / "WalletCatalog.cpp").write_text(
                '{ "btc", "BTC", "Bitcoin", 0, WalletCapabilityAddress, "btc", "x" },',
                encoding="utf-8")
            (directory / "src/generated/WalletForkCatalog.inc").write_text("", encoding="utf-8")
            generator.ROOT = directory
            generator.OUT = directory / "src/generated/WalletMiningCatalog.inc"
            generator.fetch_coins = lambda: [
                {"symbol": "BTC", "name": "Bitcoin", "algo": "SHA-256",
                 "typ": "ASIC", "mc": 1},
                {"symbol": "NOPE", "name": "No Coin", "algo": "RandomX",
                 "typ": "CPU", "mc": 2},
            ]
            self.assertEqual(generator.main(), 0)
            output = generator.OUT.read_text(encoding="utf-8")
            self.assertIn('"BTC", "Bitcoin", "SHA-256", MiningCoinType::Asic, "btc"',
                          output)
            self.assertNotIn("NOPE", output)


if __name__ == "__main__":
    unittest.main()
