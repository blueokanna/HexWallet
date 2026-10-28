"""End-to-end firmware derivation/review/sign against independent chain SDKs.

Uses the real WalletSecurity.cpp + Mbed TLS, never host_security.cpp stubs.
DOT/KSM cases test a historical codec behind a host-only flag; production
signing remains disabled until authenticated runtime metadata is implemented.
"""
from pathlib import Path
import json
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get('HEXWALLET_CHAIN_PROBE', ROOT / 'build/chain-native/Release/chain_probe.exe'))
V = json.loads((ROOT / 'tests/fixtures/chain-sdk.json').read_text(encoding='utf8'))

def probe(case, payload=None, mode=None, index=None):
    if not PROBE.exists():
        raise AssertionError('Build tests/host/chain with real WalletSecurity.cpp first')
    args = [str(PROBE), case['network'], V['seed'], case['payload'] if payload is None else payload,
            str(case['index'] if index is None else index)]
    if mode is not None:
        args.append(str(mode))
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert p.returncode in (0, 1), p.stdout + p.stderr
    return p.returncode, dict(line.split('=', 1) for line in p.stdout.splitlines())

class ChainTests(unittest.TestCase):
    def test_sdk_bytes_addresses_and_signatures(self):
        for case in V['cases']:
            with self.subTest(case=case['name']):
                code, actual = probe(case)
                self.assertEqual(code, 0, actual)
                for key in ('address', 'recipient', 'hash', 'signed', 'amount', 'fee'):
                    if key in case:
                        self.assertEqual(actual[key], case[key], key)
                self.assertEqual(actual['sender'], case['address'])
                self.assertEqual(actual['guard'], '1')

    def test_unsupported_and_unsafe_transactions(self):
        for case in V['rejected']:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(case)[0], 1)

    def test_truncation_and_trailing_data(self):
        for network in ('sui', 'fil', 'vet', 'icx', 'dot', 'ksm', 'ton', 'dcr', 'ckb', 'ada', 'hive', 'erg', 'xch'):
            case = next(c for c in V['cases'] if c['network'] == network)
            raw = bytes.fromhex(case['payload'])
            for n in sorted(set([1, 2, 3, len(raw)-1] + list(range(7, len(raw), 19)))):
                with self.subTest(network=network, length=n):
                    self.assertEqual(probe(case, raw[:n].hex())[0], 1)
            self.assertEqual(probe(case, (raw+b'\0').hex())[0], 1)

    def test_review_hash_and_payload_substitution_zero_output(self):
        for network in ('sui', 'fil', 'vet', 'icx', 'dot', 'ksm', 'ton', 'dcr', 'ckb', 'ada', 'hive', 'erg', 'xch'):
            case = next(c for c in V['cases'] if c['network'] == network)
            for mode in ('review', 'hash', 'payload', 'index'):
                with self.subTest(network=network, mode=mode):
                    code, actual = probe(case, mode=mode)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')

    def test_short_output_buffers_preserve_guard_bytes(self):
        for network in ('sui', 'fil', 'vet', 'icx', 'dot', 'ksm', 'ton', 'dcr', 'ckb', 'ada', 'hive', 'erg', 'xch'):
            case = next(c for c in V['cases'] if c['network'] == network)
            size = len(bytes.fromhex(case['signed']))
            for capacity in (0, 1, size-1):
                with self.subTest(network=network, capacity=capacity):
                    code, actual = probe(case, mode=capacity)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')
            code, actual = probe(case, mode=size)
            self.assertEqual(code, 0, actual)
            self.assertEqual(actual['signed'], case['signed'])
            self.assertEqual(actual['guard'], '1')

    def test_cardano_ledger_transfer(self):
        case = {
            'network': 'ada',
            'index': 0,
            'payload': (
                'a400818258201111111111111111111111111111111111111111111111111111111111111111'
                '0001828258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f1124'
                '1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a004c4b40'
                '825839019aee797640d85cfc3844ef243a6ebebd5bf9e6dfe3fc909777d58053c4b6'
                '99d0f78a1e845112ee82ef9839b658a023ae2b18f56fb59dc8551a00493e0002'
                '1a00030d40031a000f4240'
            ),
        }
        code, actual = probe(case)
        self.assertEqual(code, 0, actual)
        self.assertEqual(
            actual['address'],
            'addr1qxdwu7tkgrv9elpcgnhjgwnwh674h70xml3leyyhwl2cq57yk6vapau2r6z9zyhwstheswdktzsz8t3trr6kldvaep2stzrjmv',
        )
        self.assertEqual(
            actual['recipient'],
            'addr1qy2vzmtlgvjrhkq50rngh8d482zj3l20kyrc6kx4ffl3zfqayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqf7zhh2',
        )
        self.assertEqual(actual['amount'], '5.0 ADA')
        self.assertEqual(actual['fee'], '0.2 ADA')
        self.assertEqual(
            actual['hash'],
            'e7ace5feb926365ca5ba7b95ef65e39d0254bd06eba1870ec55ad89806072a9f',
        )
        self.assertEqual(actual['size'], '290')

    def test_flux_zip243_transfer(self):
        case = {
            'network': 'flux',
            'index': 0,
            'payload': (
                '5a454334bb09b8768a0000000400008085202f8901'
                '1111111111111111111111111111111111111111111111111111111111111111'
                '0000000000ffffffff0280d1f008000000001976a914'
                '222222222222222222222222222222222222222288ac'
                '408fe108000000001976a9149d7794a456cdf8eb21a1fc0fb771e7ab'
                '297f418888ac0000000000000000000000000000000000000001'
                '00a3e111000000001976a9149d7794a456cdf8eb21a1fc0fb771e7ab'
                '297f418888ac000000000000000000'
            ),
        }
        code, actual = probe(case)
        self.assertEqual(code, 0, actual)
        self.assertEqual(actual['address'],
                         't1YEDM4VMCkUMnjRRZeTScifJcJrGyXKBuG')
        self.assertEqual(actual['fee'], '1000000')
        self.assertEqual(
            actual['digest'],
            '07d7853e06f51fe8c3f83ab09995ba80dee24da3f078cc7de39115892f9a8369',
        )
        self.assertEqual(actual['size'], '244')

    def test_filecoin_nonminimal_cbor_and_negative_bigint(self):
        c = next(c for c in V['cases'] if c['network'] == 'fil')
        raw = bytes.fromhex(c['payload'])
        for value in (raw[:1] + b'\x18\0' + raw[2:], raw[:1] + b'\x20' + raw[2:],
                      b'\x9f' + raw[1:] + b'\xff', raw.replace(bytes.fromhex('4900112210f47de98115'), bytes.fromhex('4901112210f47de98115'))):
            self.assertNotEqual(value, raw)
            self.assertEqual(probe(c, value.hex())[0], 1)

if __name__ == '__main__':
    unittest.main()

