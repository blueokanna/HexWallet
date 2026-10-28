"""Firmware XTZ signatures and reviews against Taquito, verified by OpenSSL."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/fixtures/tezos-sdk.json').read_text(encoding='utf8'))
PROBE = Path(os.environ.get('HEXWALLET_TEZOS_PROBE', ROOT / 'tests/host/tezos_probe.exe'))

def probe(raw, index=0, tamper=None, seed=None):
    args = [str(PROBE), raw.hex(), seed or FIXTURE['seed'], str(index)]
    if tamper: args.append(tamper)
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode not in (0, 1):
        raise AssertionError(result.stdout + result.stderr)
    return result.returncode, dict(line.split('=', 1) for line in result.stdout.splitlines())

class TezosTests(unittest.TestCase):
    def test_independent_provenance(self):
        self.assertEqual(FIXTURE['version'], '25.0.0')
        self.assertEqual(hashlib.sha256((ROOT / 'tests/reference/generate_tezos_vectors.cjs').read_bytes()).hexdigest(), FIXTURE['generator_sha256'])
        result = subprocess.run([sys.executable, str(ROOT / 'tools/generate_tezos_selftest.py'), '--check'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exact_reviews_and_complete_signed_operations(self):
        for case in FIXTURE['cases']:
            with self.subTest(case=case['name']):
                raw = bytes.fromhex(case['transaction'])
                code, actual = probe(raw, case['index'])
                self.assertEqual(code, 0, actual)
                for field in ('signer', 'public_key', 'branch', 'hash', 'signed'):
                    self.assertEqual(actual[field], case[field])
                self.assertEqual(actual['path'], f"m/44'/1729'/0'/0'/{case['index']}'")
                self.assertEqual(int(actual['count']), len(case['contents']))
                self.assertEqual(int(actual['total']), sum(int(op.get('amount', 0)) for op in case['contents']))
                self.assertEqual(int(actual['fee']), sum(int(op['fee']) for op in case['contents']))
                self.assertEqual(int(actual['storage']), sum(int(op['storage_limit']) for op in case['contents']))
                for i, op in enumerate(case['contents']):
                    self.assertEqual(actual[f'op{i}'], ','.join(map(str, [int(op['kind'] == 'reveal'), op['fee'], op['counter'], op['gas_limit'], op['storage_limit'], op.get('amount', 0), op.get('destination', op['source'])])))
                digest = hashlib.blake2b(b'\x03' + raw, digest_size=32).digest()
                self.assertEqual(actual['hash'], digest.hex())
                signed = bytes.fromhex(actual['signed'])
                self.assertEqual(signed[:-64], raw)
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(case['public_raw'])).verify(signed[-64:], digest)

    def test_rejected_sdk_operations(self):
        for case in FIXTURE['rejected']:
            with self.subTest(case=case['name']):
                self.assertEqual(probe(bytes.fromhex(case['transaction']), case['index'])[0], 1)

    def test_truncation_except_complete_operation_boundaries(self):
        for case in FIXTURE['cases']:
            raw = bytes.fromhex(case['transaction'])
            for end in range(len(raw)):
                with self.subTest(case=case['name'], end=end):
                    self.assertEqual(probe(raw[:end], case['index'])[0], 0 if end in case['operation_ends'] else 1)

    def test_noncanonical_zarith_and_unsupported_tags(self):
        raw = bytes.fromhex(FIXTURE['cases'][0]['transaction'])
        end = 54
        while raw[end] & 128: end += 1
        malformed = [bytes(32) + raw[32:], raw[:32] + b'\x00' + raw[33:],
                     raw[:end] + bytes([raw[end] | 128, 0]) + raw[end+1:],
                     raw[:54] + b'\xff' * 9 + b'\x01' + raw[end+1:],
                     raw + b'\x00', raw + bytes(64)]
        for value in malformed: self.assertEqual(probe(value)[0], 1)

    def test_approval_summary_is_bound_to_signature(self):
        for case in (FIXTURE['cases'][0], FIXTURE['cases'][5]):
            for field in ('size','index','raw','hash','source','public_key','branch','count',
                          'total','fee','storage','reveal','op_fee','counter','gas','op_storage',
                          'amount','recipient','small'):
                with self.subTest(case=case['name'], field=field):
                    code, actual = probe(bytes.fromhex(case['transaction']), case['index'], field)
                    self.assertEqual(code, 0, actual)
                    self.assertEqual(actual['tamper_rejected'], '1')

    def test_foreign_wallet_is_rejected(self):
        for case in FIXTURE['cases']:
            self.assertEqual(probe(bytes.fromhex(case['transaction']), case['index'], seed='11'*64)[0], 1)

if __name__ == '__main__': unittest.main()
