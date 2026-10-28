"""Production registries must exclude the reviewed GRAVEYARD identities.

The snapshot comes from MiningPoolStats and carries the date it was taken.
Every registry that can reach a user is checked here, so a graveyard coin
cannot re-enter through a generated file or through the mining table.
"""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

# Catalog rows are {id, symbol, name, ...}; mining rows are
# {symbol, name, algorithm, type, catalog_id}. Indexes point at the symbol and
# display name of each layout.
NAME_INDEX = {
    'WalletNetworks.cpp': (2, 1),
    'WalletCatalog.cpp': (2, 1),
    'src/generated/WalletForkCatalog.inc': (2, 1),
    'src/generated/WalletForkProfiles.inc': (2, 1),
    'src/generated/WalletMiningCatalog.inc': (1, 0),
}


class GraveyardTests(unittest.TestCase):
    def load_snapshot(self):
        snapshot = json.loads((ROOT / 'tools/miningpoolstats_graveyard.json').read_text())
        self.assertEqual(snapshot['exceptions'], [],
                         'the graveyard policy has no per-coin exceptions')
        # An empty or unparsed file would make every other assertion vacuous.
        self.assertGreater(len(snapshot['coins']), 100, snapshot.get('checked_date'))
        identities = {(value['n'].strip().casefold(), value['s'].upper())
                      for value in snapshot['coins'].values()}
        self.assertIn(('flux', 'FLUX'), identities)
        return identities

    def test_catalogs_exclude_graveyard_without_exceptions(self):
        identities = self.load_snapshot()
        rows = json.loads((ROOT / 'tools/fork_registry.json').read_text())['profiles']
        for row in rows:
            self.assertNotIn((row['name'].strip().casefold(), row['symbol'].upper()),
                             identities, row['network'])
        for name, (name_index, symbol_index) in NAME_INDEX.items():
            for line in (ROOT / name).read_text().splitlines():
                if not line.strip().startswith('{'):
                    continue
                fields = re.findall(r'"([^"]*)"', line)
                if len(fields) <= max(name_index, symbol_index):
                    continue
                identity = (fields[name_index].strip().casefold(),
                            fields[symbol_index].upper())
                self.assertNotIn(identity, identities,
                                 '%s: %s' % (name, line.strip()))

    def test_withdrawn_chains_stay_withdrawn(self):
        """Pins the specific withdrawals so they cannot drift back in silently."""
        networks = (ROOT / 'WalletNetworks.cpp').read_text()
        self.assertNotIn('"msr", "MSR", "Masari"', networks)
        self.assertNotIn('{"flux",', networks)
        self.assertNotIn('{"qubic",', networks)
        self.assertNotIn('"flux", SighashFamily', networks)
        self.assertNotIn('0x76b809bb', networks)
        catalog = (ROOT / 'WalletCatalog.cpp').read_text()
        self.assertNotIn('"flux", "FLUX"', catalog)
        mining = (ROOT / 'src/generated/WalletMiningCatalog.inc').read_text()
        self.assertNotIn('"FLUX"', mining)
        self.assertNotIn('"MSR"', mining)

    def test_mining_table_only_lists_existing_catalog_ids(self):
        """A mining row may only point at a wallet the catalog actually ships."""
        catalog_ids = {m.group(1) for m in re.finditer(
            r'\{\s*"([^"]+)",\s*"[^"]+",\s*"[^"]+"', (ROOT / 'WalletCatalog.cpp').read_text())}
        catalog_ids |= {m.group(1) for m in re.finditer(
            r'\{\s*"([^"]+)",\s*"[^"]+",\s*"[^"]+"',
            (ROOT / 'src/generated/WalletForkCatalog.inc').read_text())}
        for line in (ROOT / 'src/generated/WalletMiningCatalog.inc').read_text().splitlines():
            if not line.strip().startswith('{'):
                continue
            catalog_id = re.findall(r'"([^"]*)"', line)[-1]
            self.assertIn(catalog_id, catalog_ids, line.strip())


if __name__ == '__main__':
    unittest.main()
