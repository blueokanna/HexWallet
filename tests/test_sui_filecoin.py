"""SUI/FIL acceptance suite, isolated from other concurrently edited adapters."""
import unittest
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get('HEXWALLET_CHAIN_PROBE', ROOT / 'build/chain-native/Release/chain_probe.exe'))
V = json.loads((ROOT / 'tests/fixtures/sui-filecoin-sdk.json').read_text(encoding='utf8'))

def probe(case, payload=None, mode=None, index=None):
    if not PROBE.exists():
        raise AssertionError('Build tests/host/chain with real WalletSecurity.cpp first')
    args = [str(PROBE), case['network'], V['seed'], case['payload'] if payload is None else payload,
            str(case['index'] if index is None else index)]
    if mode is not None:
        args.append(str(mode))
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert result.returncode in (0, 1), result.stdout + result.stderr
    return result.returncode, dict(line.split('=', 1) for line in result.stdout.splitlines())

CASES = [c for c in V['cases'] if c['network'] in ('sui', 'fil')]
REJECTED = [c for c in V['rejected'] if c['network'] in ('sui', 'fil')]

class SuiFilecoinTests(unittest.TestCase):
    def test_sdk_addresses_review_and_signed_bytes(self):
        self.assertEqual(len(CASES), 12)
        for case in CASES:
            with self.subTest(case=case['name']):
                code, actual = probe(case)
                self.assertEqual(code, 0, actual)
                for key in ('address', 'recipient', 'amount', 'fee', 'hash', 'signed'):
                    self.assertEqual(actual[key], case[key], key)
                self.assertEqual(actual['sender'], case['address'])
                self.assertEqual(actual['guard'], '1')

    def test_unsupported_sdk_transactions(self):
        self.assertEqual(len(REJECTED), 75)
        for case in REJECTED:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(case)[0], 1)

    def test_all_truncations_and_trailing_bytes(self):
        for network in ('sui', 'fil'):
            case = next(c for c in CASES if c['network'] == network)
            raw = bytes.fromhex(case['payload'])
            for n in range(1, len(raw)):
                with self.subTest(network=network, length=n):
                    self.assertEqual(probe(case, raw[:n].hex())[0], 1)
            self.assertEqual(probe(case, (raw + b'\0').hex())[0], 1)

    def test_approval_binding_and_foreign_wallet(self):
        for case in CASES:
            self.assertEqual(probe(case, index=case['index'] + 1)[0], 1)
            for mode in ('review', 'hash', 'payload', 'index'):
                with self.subTest(case=case['name'], mode=mode):
                    code, actual = probe(case, mode=mode)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')

    def test_exact_and_short_buffers(self):
        for case in CASES:
            size = len(bytes.fromhex(case['signed']))
            for n in (0, 1, size - 1, size):
                with self.subTest(case=case['name'], capacity=n):
                    code, actual = probe(case, mode=n)
                    self.assertEqual(actual['guard'], '1')
                    if n < size:
                        self.assertEqual(code, 1, actual)
                        self.assertEqual(actual['size'], '0')
                        self.assertEqual(actual['zero'], '1')
                    else:
                        self.assertEqual(code, 0, actual)
                        self.assertEqual(actual['signed'], case['signed'])

    def test_nonminimal_lengths_and_wrong_envelopes(self):
        for network in ('sui', 'fil'):
            case = next(c for c in CASES if c['network'] == network)
            raw = bytes.fromhex(case['payload'])
            if network == 'sui':
                malformed = [b'\x80\0' + raw[1:], b'\1' + raw[1:], b'\0\0\0' + raw]
            else:
                malformed = [raw[:1] + b'\x18\0' + raw[2:], raw[:1] + b'\x20' + raw[2:],
                             b'\x9f' + raw[1:] + b'\xff',
                             raw.replace(bytes.fromhex('4900112210f47de98115'), bytes.fromhex('4901112210f47de98115'))]
            for value in malformed:
                self.assertNotEqual(value, raw)
                self.assertEqual(probe(case, value.hex())[0], 1)

if __name__ == '__main__':
    unittest.main()
