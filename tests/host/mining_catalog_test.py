"""Adversarial identity/admission checks for the actual catalog generator."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("mining", ROOT / "tools/generate_mining_catalog.py")
mining = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mining)


class MiningIdentityTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {"ASIC - Ethash": {"bitnetmoney": {"s": "BTN", "n": "Bitnet Money"}},
                         "CPU - Various Algo": {"bitnet": {"s": "BIT", "n": "BitNet"}},
                         "GRAVEYARD": {"retired": {"s": "OLD", "n": "Retired"}}, "time": 1}
        self.catalog = mining.catalog_rows("btn|BTN|Bitnet|15|btn|evm:210|Native and token signing\n")
        self.mapping = {"bitnetmoney": {"symbol": "BTN", "name": "Bitnet Money", "catalog_id": "btn"}}

    def test_explicit_native_identity(self):
        active = mining.active_rows(self.snapshot)
        self.assertEqual(set(mining.resolve(active, self.mapping, self.catalog)), {"bitnetmoney"})
        bad = {"bitnet": {"symbol": "BIT", "name": "BitNet", "catalog_id": "btn"}}
        with self.assertRaisesRegex(ValueError, "native asset mismatch"):
            mining.resolve(active, bad, self.catalog)

    def test_changed_identity_and_retired_mapping(self):
        active = mining.active_rows(self.snapshot)
        self.mapping["bitnetmoney"]["name"] = "Another coin"
        with self.assertRaisesRegex(ValueError, "identity changed"):
            mining.resolve(active, self.mapping, self.catalog)
        with self.assertRaisesRegex(ValueError, "no longer active"):
            mining.resolve(active, {"retired": {}}, self.catalog)

    def test_duplicate_and_graveyard_source_ids(self):
        duplicate = copy.deepcopy(self.snapshot)
        duplicate["CPU - Various Algo"]["bitnetmoney"] = {"s": "OTHER", "n": "Other"}
        with self.assertRaises(ValueError):
            mining.active_rows(duplicate)
        duplicate = copy.deepcopy(self.snapshot)
        duplicate["GRAVEYARD"]["bitnetmoney"] = {"s": "BTN", "n": "Bitnet Money"}
        with self.assertRaises(ValueError):
            mining.active_rows(duplicate)

    def test_no_guess_for_shared_ticker(self):
        self.snapshot["CPU - Various Algo"]["bitnet"]["s"] = "BTN"
        active = mining.active_rows(self.snapshot)
        resolved = mining.resolve(active, self.mapping, self.catalog)
        self.assertNotIn("bitnet", resolved)
        _, report, ambiguous = mining.render(active, resolved, {"checked_date": "test", "source": "test"})
        self.assertIn("bitnet | BTN / BitNet | — | UNMAPPED", report)
        self.assertIn('"btn"', ambiguous)

    def test_duplicate_json_keys_fail(self):
        path = Mock()
        path.read_text.return_value = '{"a":1,"a":2}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            mining.read_json(path)

    def test_digest_ignores_newlines_but_binds_values(self):
        path = Mock()
        path.read_text.return_value = '{\r\n"n":"Bitcoin",\r\n"s":"BTC"\r\n}'
        digest = mining.snapshot_digest(mining.read_json(path))
        self.assertEqual(digest, mining.snapshot_digest({"s": "BTC", "n": "Bitcoin"}))
        self.assertNotEqual(digest, mining.snapshot_digest({"s": "OTHER", "n": "Bitcoin"}))

    def test_invalid_capabilities(self):
        with self.assertRaises(ValueError):
            mining.catalog_rows("btc|BTC|Bitcoin|5|btc|utxo|Signing without review\n")
        with self.assertRaises(ValueError):
            mining.catalog_rows("btn|BTN|Bitnet|15|btn|evm:210|ok\n" * 2)

    def test_repository_snapshot_regressions(self):
        active = mining.active_rows(mining.read_json(ROOT / "tools/miningpoolstats_coin_list.json"))
        mapping = mining.read_json(ROOT / "tools/miningpoolstats_mapping.json")
        self.assertNotIn("callisto", active)
        self.assertNotIn("etica_eti", mapping)
        self.assertNotIn("bitnet", mapping)
        self.assertNotIn("conflux", mapping)  # Core Space is not eSpace.
        self.assertEqual(mapping["monero"]["catalog_id"], "xmr")
        self.assertEqual(mapping["chia"]["catalog_id"], "xch")


if __name__ == "__main__":
    unittest.main()
