"""Guards for asset identity and the offline firmware boundary."""
from pathlib import Path
import importlib.util
import unittest
import re
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('coverage_report', ROOT/'tools/coin_coverage_report.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)
class CoverageTests(unittest.TestCase):
    def test_chain_admission_is_explicit(self):
        rows = {row['id']: row for row in report.load_catalog()[0]}
        for network in ('sui', 'fil', 'ada'):
            self.assertTrue(rows[network]['sign'])
            self.assertTrue(rows[network]['review'])
            self.assertTrue(rows[network]['address'])
        for network in ('dot', 'ksm'):
            self.assertFalse(rows[network]['sign'])
            self.assertFalse(rows[network]['review'])
            self.assertTrue(rows[network]['address'])
        # ERG's review is now bound to the signed preimage (single external
        # output, every token listed, otherwise refused); XCH signing stays
        # closed until the BLS secret-scalar path is constant time.
        for network in ('erg',):
            self.assertTrue(rows[network]['sign'])
            self.assertTrue(rows[network]['review'])
            self.assertTrue(rows[network]['address'])
        self.assertTrue(rows['xch']['address'])
        self.assertFalse(rows['xch']['sign'])
        self.assertFalse(rows['hive']['address'])
        self.assertTrue(rows['hive']['sign'])

    def test_disabled_row_does_not_claim_an_address(self):
        rows = [dict(id='xch', symbol='XCH', sign=False, review=False, address=False)]
        self.assertEqual(report.classify('XCH', rows, {})[0], 'ABSENT')
    def test_priority_native_chains_are_not_omitted(self):
        priority = 'DASH ZEC XEC XMR ETH BTC BCH BSV RVN XCH DOGE FLUX FIL FIRO DCR KAS SOL ADA DOT'.split()
        self.assertTrue(set(priority).issubset(report.REQUESTED))
        self.assertEqual(len(report.REQUESTED), len(set(report.REQUESTED)))
        self.assertNotIn('MSR', report.REQUESTED)
    def test_removed_masari_is_not_exposed(self):
        rows, _ = report.load_catalog()
        self.assertFalse(any(row['id'] == 'msr' for row in rows))
    def test_arbitrum_network_does_not_claim_governance_token(self):
        rows=[dict(id='arb1',symbol='ARB1',name='Arbitrum',sign=True,review=True,address=True,network='arb1')]
        self.assertEqual(report.classify('ARB',rows,{})[0], 'ABSENT')
    def test_all_token_networks_are_reported(self):
        tokens=report.load_tokens()
        self.assertIn('eth:eth-usdc',tokens['USDC'])
        self.assertIn('opt:opt-usdc-native',tokens['USDC'])
        self.assertNotIn('opt:opt-usdc,',tokens['USDC'])
        self.assertIn('opt:opt-usdc',tokens['USDC.E'])
        self.assertIn('matic:matic-usdc-e',tokens['USDC.E'])
    def test_gold_and_mana_tokens_are_registered(self):
        tokens = report.load_tokens()
        self.assertIn('eth:eth-xaut', tokens['XAUT'])
        self.assertIn('eth:eth-paxg', tokens['PAXG'])
        self.assertIn('eth:eth-mana', tokens['MANA'])
        self.assertIn('matic:matic-mana', tokens['MANA'])

    def test_token_ids_are_unique(self):
        text = (ROOT / 'WalletTokens.cpp').read_text(encoding='utf8')
        ids = re.findall(r'\{\s*"([^"]+)"\s*,\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*"[^"]+"\s*,\s*TokenStandard::', text)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreater(len(ids), 20)

    def test_firmware_does_not_import_network_clients(self):
        # Dependency guard, not a claim that all possible networking APIs are caught.
        forbidden=re.compile(r'^\s*#\s*include\s*[<\"](?:WiFi|HTTPClient|Ethernet|WebServer|NetworkClient|esp_http_client|lwip/)',re.M)
        for pattern in ('*.cpp','*.h','*.ino'):
            for path in ROOT.glob(pattern):
                self.assertIsNone(forbidden.search(path.read_text(encoding='utf8')),str(path))
