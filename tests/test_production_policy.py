"""Run the real policy build without host-only legacy-chain exceptions."""
import subprocess
import unittest
from test_cardano_hedera import ROOT


class ProductionPolicyTests(unittest.TestCase):
    def test_fail_closed(self):
        result = subprocess.run(
            [str(ROOT / 'build/chain-native/Release/production_policy.exe')],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('production_policy=pass', result.stdout)
