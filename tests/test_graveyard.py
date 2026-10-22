"""Production registries must exclude the reviewed GRAVEYARD identities."""
import json
from pathlib import Path
import re
import unittest
ROOT = Path(__file__).resolve().parents[1]
class GraveyardTests(unittest.TestCase):
    def test_catalogs_exclude_graveyard_except_masari(self):
        snapshot = json.loads((ROOT / 'tools/miningpoolstats_graveyard.json').read_text())
        self.assertEqual(snapshot['exceptions'], ['masari'])
        identities = {(v['n'].strip().casefold(), v['s'].upper())
                      for k,v in snapshot['coins'].items() if k != 'masari'}
        rows = json.loads((ROOT / 'tools/fork_registry.json').read_text())['profiles']
        for row in rows:
            self.assertNotIn((row['name'].strip().casefold(),row['symbol'].upper()), identities)
        for name in ['WalletNetworks.cpp','WalletCatalog.cpp','src/generated/WalletForkCatalog.inc']:
            for line in (ROOT / name).read_text().splitlines():
                fields = re.findall(r'"([^"]*)"',line)
                if line.strip().startswith('{') and len(fields) >= 3:
                    self.assertNotIn((fields[2].strip().casefold(),fields[1].upper()),identities)
        self.assertIn('"msr", "MSR", "Masari"', (ROOT / 'WalletNetworks.cpp').read_text())
