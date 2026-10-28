"""Protocol fixtures plus fail-closed behavior for NEM/Hive/Sia native transfers."""
import json
from pathlib import Path
import unittest
from test_cardano_hedera import probe

V = json.loads((Path(__file__).parent / 'fixtures/native-remaining-sdk.json').read_text())

class NativeRemainingTests(unittest.TestCase):
    def test_sdk_vectors(self):
        for case in V['cases']:
            with self.subTest(case=case['name']):
                code, actual = probe(case)
                self.assertEqual(code, 0, actual)
                for key in ('address', 'recipient', 'amount', 'fee', 'hash', 'signed'):
                    if key in case:
                        self.assertEqual(actual[key], case[key], key)
                self.assertEqual(actual['guard'], '1')

    def test_invalid_requests(self):
        for case in V['rejected']:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(case)[0], 1)

    def test_tampering_and_guards(self):
        for network in ('xem', 'hive', 'sc'):
            case = next(c for c in V['cases'] if c['network'] == network)
            for mode in ('review', 'hash', 'payload', 'index', 0, 1, 63):
                with self.subTest(network=network, mode=mode):
                    code, actual = probe(case, mode=mode)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')

    def test_all_truncations_and_trailing_data(self):
        for network in ('xem', 'hive', 'sc'):
            case = next(c for c in V['cases'] if c['network'] == network)
            raw = bytes.fromhex(case['payload'])
            for n in range(1, len(raw)):
                with self.subTest(network=network, size=n):
                    self.assertEqual(probe(case, raw[:n].hex())[0], 1)
            self.assertEqual(probe(case, (raw + b'\x00').hex())[0], 1)
