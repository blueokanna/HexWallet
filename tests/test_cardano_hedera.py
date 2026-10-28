"""Real firmware against independently generated Cardano/Hedera SDK fixtures."""
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get('HEXWALLET_CHAIN_PROBE', ROOT / 'build/chain-native/Release/chain_probe.exe'))
FIXTURES = [json.loads((ROOT / 'tests/fixtures' / name).read_text())
            for name in ('cardano-sdk.json', 'hedera-sdk.json')]


def probe(case, payload=None, mode=None):
    args = [str(PROBE), case['network'], case['seed'],
            case['payload'] if payload is None else payload, str(case['index'])]
    if mode is not None:
        args.append(str(mode))
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode not in (0, 1):
        raise AssertionError(result.stdout + result.stderr)
    return result.returncode, dict(line.split('=', 1) for line in result.stdout.splitlines())


class CardanoHederaTests(unittest.TestCase):
    def test_official_sdk_signed_bytes(self):
        for fixture in FIXTURES:
            for case in fixture['cases']:
                with self.subTest(network=case['network'], case=case['name']):
                    code, actual = probe(case)
                    self.assertEqual(code, 0, actual)
                    for key in ('address', 'recipient', 'amount', 'fee', 'hash', 'signed'):
                        self.assertEqual(actual[key], case[key], key)
                    self.assertEqual(actual['guard'], '1')

    def test_unsupported_sdk_transactions(self):
        for fixture in FIXTURES:
            for case in fixture['rejected']:
                with self.subTest(network=case['network'], case=case['name']):
                    self.assertEqual(probe(case)[0], 1)

    def test_review_binding_and_output_guards(self):
        for fixture in FIXTURES:
            case = fixture['cases'][0]
            for mode in ('review', 'hash', 'payload', 'index', 0, 1,
                         len(bytes.fromhex(case['signed'])) - 1):
                with self.subTest(network=case['network'], mode=mode):
                    code, actual = probe(case, mode=mode)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')

    def test_all_truncations_and_trailing_bytes(self):
        for fixture in FIXTURES:
            case = fixture['cases'][0]
            raw = bytes.fromhex(case['payload'])
            for length in range(1, len(raw)):
                with self.subTest(network=case['network'], length=length):
                    self.assertEqual(probe(case, raw[:length].hex())[0], 1)
            self.assertEqual(probe(case, (raw + b'\x00').hex())[0], 1)
