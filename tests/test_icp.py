"""ICP SDK request IDs, envelope signatures, rejection and review binding."""
import json
from pathlib import Path
import unittest
from test_cardano_hedera import probe

V = json.loads((Path(__file__).parent / 'fixtures/icp-sdk.json').read_text())


class IcpTests(unittest.TestCase):
    def test_sdk_fields_and_signature(self):
        for case in V['cases']:
            with self.subTest(case=case['name']):
                code, actual = probe(case)
                self.assertEqual(code, 0, actual)
                for key in ('address', 'recipient', 'amount', 'fee', 'hash'):
                    self.assertEqual(actual[key], case[key], key)
                # Full envelope decoding/request hashing lives in the independent
                # SDK check. Here pin both CBOR byte strings and the IDL argument.
                raw = bytes.fromhex(actual['signed'])
                for key in ('signature', 'public_der', 'arg'):
                    self.assertIn(bytes.fromhex(case[key]), raw)
                self.assertEqual(actual['guard'], '1')

    def test_invalid_requests(self):
        for case in V['rejected']:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(case)[0], 1)

    def test_tamper_and_capacity(self):
        case = V['cases'][0]
        for mode in ('review', 'hash', 'payload', 'index', 0, 1, 63, 300):
            with self.subTest(mode=mode):
                code, actual = probe(case, mode=mode)
                self.assertEqual(code, 1, actual)
                self.assertEqual(actual['size'], '0')
                self.assertEqual(actual['zero'], '1')
                self.assertEqual(actual['guard'], '1')

    def test_truncation_and_trailing_data(self):
        case = V['cases'][0]
        raw = bytes.fromhex(case['payload'])
        for n in range(1, len(raw)):
            self.assertEqual(probe(case, raw[:n].hex())[0], 1)
        self.assertEqual(probe(case, (raw + b'\x00').hex())[0], 1)
