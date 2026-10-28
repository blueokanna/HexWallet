"""Guards every shipped test-vector artifact and its generator.

Each .inc under src/generated that carries reference vectors is produced by a
script in tools/ and consumed by exactly one firmware source file. Deleting a
generator would make the artifact unreproducible and its provenance unauditable,
so this test fails if the chain is broken.
"""
import os
import re
import unittest
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# artifact under src/generated -> generator in tools/
ARTIFACTS = {
    'TezosVectorsTest.inc': 'generate_tezos_selftest.py',
    'MoneroTxVectorsTest.inc': 'fetch_monero_vector.py',
    'ClsagReferenceVectorTest.inc': 'generate_clsag_reference_vector.py',
    'RingCtAmountVectorsTest.inc': 'generate_ringct_amount_vectors.py',
    'ZcashZip243VectorsTest.inc': 'generate_zcash_zip243_vectors.py',
    'BulletproofPlusReferenceTest.inc': 'generate_bp_plus_fixtures.py',
    'TronVectorsTest.inc': 'generate_tron_vectors.py',
    'CosmosVectorsTest.inc': 'generate_cosmos_vectors.py',
    'StellarVectorsTest.inc': 'generate_stellar_selftest.py',
}

PRODUCTION = (
    'WalletForkCatalog.inc',
    'WalletForkProfiles.inc',
    'WalletForkSigningPolicies.inc',
    'WalletMiningCatalog.inc',
)


def source_files():
    for name in os.listdir(ROOT):
        if name.endswith(('.cpp', '.h')):
            yield os.path.join(ROOT, name)


class GeneratedArtifacts(unittest.TestCase):
    def test_test_vectors_are_named_as_tests(self):
        """Anything only tests consume has to say so in its file name."""
        for name in ARTIFACTS:
            self.assertTrue(name.endswith('Test.inc'),
                            '%s is a test artifact but is not named ...Test.inc' % name)

    def test_production_data_is_not_named_as_test(self):
        for name in PRODUCTION:
            self.assertFalse(name.endswith('Test.inc'),
                             '%s ships to the device and must not be a test name' % name)

    def test_every_artifact_exists_and_is_included(self):
        includes = ''
        for path in source_files():
            with open(path, encoding='utf-8', errors='ignore') as handle:
                includes += handle.read()
        for name in ARTIFACTS:
            path = os.path.join(ROOT, 'src', 'generated', name)
            self.assertTrue(os.path.exists(path), 'missing artifact %s' % name)
            self.assertIn(name, includes, '%s is not included by any source file' % name)

    def test_every_artifact_has_a_generator(self):
        for name, generator in ARTIFACTS.items():
            path = os.path.join(ROOT, 'tools', generator)
            self.assertTrue(os.path.exists(path), 'missing generator %s' % generator)
            with open(path, encoding='utf-8') as handle:
                body = handle.read()
            self.assertIn(name, body,
                          '%s does not mention %s, so it cannot reproduce it' % (generator, name))

    def test_generated_includes_are_not_compiled_directly(self):
        """The include directory must contain data only, never translation units."""
        directory = os.path.join(ROOT, 'src', 'generated')
        for name in os.listdir(directory):
            self.assertTrue(name.endswith('.inc'),
                            'src/generated must hold only .inc data, found %s' % name)


class ReferenceBaseline(unittest.TestCase):
    def test_bulletproof_plus_fixtures_are_current(self):
        """The pinned include must match what the fixtures describe."""
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, 'tools', 'generate_bp_plus_fixtures.py'), '--check'],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manifest_pins_a_monero_commit(self):
        import json
        path = os.path.join(ROOT, 'tests', 'fixtures', 'monero-bp-plus', 'manifest.json')
        with open(path, encoding='utf-8') as handle:
            manifest = json.load(handle)
        self.assertEqual(manifest['source'], 'monero-project/monero')
        self.assertRegex(manifest['commit'], r'^[0-9a-f]{40}$')
        self.assertIn('TEST ONLY', manifest['randomness'])
        names = [case['name'] for case in manifest['cases']]
        self.assertEqual(len(names), len(set(names)), 'duplicate case names')
        counts = sorted(case['count'] for case in manifest['cases'])
        self.assertEqual(counts, [1, 2, 3, 4, 5, 8, 9, 16],
                         'the baseline must cover every output count up to 16 '
                         'that changes the round count')


if __name__ == '__main__':
    unittest.main()
