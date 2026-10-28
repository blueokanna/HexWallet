"""Legacy XMSS public-address oracle; no test exports private material."""
import json
import subprocess
import unittest
from test_cardano_hedera import ROOT, PROBE

V = json.loads((ROOT / 'tests/fixtures/qrl-sdk.json').read_text())


def run(case, height=None, cancel=False):
    mode = 'qrl-vector' if case['index'] is None else 'qrl-mapped-vector'
    args = [str(PROBE), mode, case['input'], str(case['index'] or 0), str(case['height'] if height is None else height)]
    if cancel:
        args.append('cancel')
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    return result.returncode, dict(line.split('=', 1) for line in result.stdout.splitlines())


class QrlTests(unittest.TestCase):
    def test_upstream_public_keys_and_addresses(self):
        for case in V['cases']:
            with self.subTest(case=case['name']):
                code, actual = run(case)
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual['public'], case['public'])
                self.assertEqual(actual['address'], case['address'])

    def test_cancel_and_invalid_height_clear_output(self):
        case = V['cases'][0]
        for height in (0, 3, 5, 13, 14, 255):
            code, actual = run(case, height=height)
            self.assertEqual(code, 1, actual)
            self.assertEqual(actual['zero'], '1')
        code, actual = run(case, cancel=True)
        self.assertEqual(code, 1, actual)
        self.assertEqual(actual['zero'], '1')
