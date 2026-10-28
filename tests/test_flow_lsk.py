"""Flow EVM and Ethereum LSK use separate, explicitly pinned networks."""
import json
from pathlib import Path
import unittest
from test_cardano_hedera import probe

V = json.loads((Path(__file__).parent / 'fixtures/flow-lsk-sdk.json').read_text())


class FlowLskTests(unittest.TestCase):
    def test_sdk_vectors(self):
        for case in V['cases']:
            with self.subTest(case=case['name']):
                code, actual = probe(case)
                self.assertEqual(code, 0, actual)
                for key in ('address', 'recipient', 'amount', 'fee', 'hash', 'asset', 'fee_asset'):
                    self.assertEqual(actual[key], case[key])
                self.assertEqual(actual['guard'], '1')

    def test_network_binding(self):
        for case in V['rejected']:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(case)[0], 1)

    def test_review_binding(self):
        for case in V['cases'][:2]:
            for mode in ('review', 'hash', 'payload', 'index', 0, 1, 63):
                with self.subTest(case=case['name'], mode=mode):
                    code, actual = probe(case, mode=mode)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')
