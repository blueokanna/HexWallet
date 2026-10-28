"""End-to-end firmware derivation/review/sign against independent chain SDKs.

Uses the real WalletSecurity.cpp + Mbed TLS, never host_security.cpp stubs.
DOT/KSM cases test a historical codec behind a host-only flag; production
signing remains disabled until authenticated runtime metadata is implemented.
"""
from pathlib import Path
import hashlib
import hmac
import json
import os
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get('HEXWALLET_CHAIN_PROBE', ROOT / 'build/chain-native/Release/chain_probe.exe'))
V = json.loads((ROOT / 'tests/fixtures/chain-sdk.json').read_text(encoding='utf8'))

# secp256k1 parameters for the independent Hive signature recovery check below.
_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
_BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % _SECP256K1_P == 0:
        return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], -1, _SECP256K1_P) % _SECP256K1_P
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], -1, _SECP256K1_P) % _SECP256K1_P
    x = (slope * slope - left[0] - right[0]) % _SECP256K1_P
    return x, (slope * (left[0] - x) - left[1]) % _SECP256K1_P


def _point_mul(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _recover_public_key(compact, digest):
    """Recover the compressed secp256k1 key from a graphene compact signature."""
    header = compact[0]
    assert 31 <= header <= 34, header
    recovery = header - 27 - 4
    r = int.from_bytes(compact[1:33], 'big')
    s = int.from_bytes(compact[33:65], 'big')
    assert r < _SECP256K1_N and s <= _SECP256K1_N // 2, 'non-canonical (r, s)'
    assert r < 2**255 and s < 2**255, 'non-canonical DER integers'
    x = r + (_SECP256K1_N if recovery & 2 else 0)
    y = pow((x * x * x + 7) % _SECP256K1_P, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    if y & 1 != recovery & 1:
        y = _SECP256K1_P - y
    inverse = pow(r, -1, _SECP256K1_N)
    z = int.from_bytes(digest, 'big')
    point = _point_add(_point_mul(s * inverse % _SECP256K1_N, (x, y)),
                       _point_mul(-z * inverse % _SECP256K1_N, _SECP256K1_G))
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def _base58_decode(text):
    value = 0
    for character in text:
        value = value * 58 + _BASE58_ALPHABET.index(character)
    body = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return b'\0' * (len(text) - len(text.lstrip('1'))) + body


def _base58check_encode(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(data, 'big')
    text = ''
    while value:
        value, remainder = divmod(value, 58)
        text = _BASE58_ALPHABET[remainder] + text
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + text


def _compressed_public_key(private_key):
    point = _point_mul(private_key, _SECP256K1_G)
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def _bip44_private_key(seed, coin_type):
    """BIP32 m/44'/coin'/0'/0/0; hardened and non-hardened steps per spec."""
    digest = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain = int.from_bytes(digest[:32], 'big'), digest[32:]
    for index in (44 | 0x80000000, coin_type | 0x80000000, 0x80000000, 0, 0):
        if index & 0x80000000:
            data = b'\0' + key.to_bytes(32, 'big') + index.to_bytes(4, 'big')
        else:
            data = _compressed_public_key(key) + index.to_bytes(4, 'big')
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key = (int.from_bytes(digest[:32], 'big') + key) % _SECP256K1_N
        chain = digest[32:]
    return key


def _t1_address(seed, coin_type):
    public_key = _compressed_public_key(_bip44_private_key(seed, coin_type))
    script_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).digest()
    return _base58check_encode(bytes.fromhex('1cb8') + script_hash)


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
            # The Hive vector pins a length only: graphene canonicalisation picks
            # a different (still valid) nonce than dhive, so the bytes are
            # checked by signature recovery in test_hive_signature_recovers_sender.
            size = len(bytes.fromhex(case['signed'])) if 'signed' in case else case['signed_size']
            for capacity in (0, 1, size-1):
                with self.subTest(network=network, capacity=capacity):
                    code, actual = probe(case, mode=capacity)
                    self.assertEqual(code, 1, actual)
                    self.assertEqual(actual['size'], '0')
                    self.assertEqual(actual['zero'], '1')
                    self.assertEqual(actual['guard'], '1')
            code, actual = probe(case, mode=size)
            self.assertEqual(code, 0, actual)
            self.assertEqual(actual['size'], str(size))
            if 'signed' in case:
                self.assertEqual(actual['signed'], case['signed'])
            self.assertEqual(actual['guard'], '1')

    def test_hive_signature_recovers_sender(self):
        """A Hive node accepts a signature only if it recovers the sender key.

        The payload and digest come from @hiveio/dhive 1.3.6
        (tests/reference/generate_native_remaining.cjs, hive-0-HIVE). dhive
        re-hashes the message with a counter when a signature is not canonical,
        so its exact (r, s) differs from the firmware's RFC6979 retry; recovery
        is the consensus-relevant check.
        """
        case = next(c for c in V['cases'] if c['network'] == 'hive')
        code, actual = probe(case)
        self.assertEqual(code, 0, actual)
        signature = bytes.fromhex(actual['signed'])
        self.assertEqual(len(signature), case['signed_size'])
        recovered = _recover_public_key(signature, bytes.fromhex(actual['hash']))
        # "STM" + base58(compressed key || RIPEMD-160(key)[:4]).
        payload = _base58_decode(case['address'][3:])
        self.assertEqual(len(payload), 37)
        self.assertEqual(hashlib.new('ripemd160', payload[:33]).digest()[:4],
                         payload[33:], 'STM address checksum')
        self.assertEqual(payload[:33], recovered, 'signature does not recover the sender key')

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

    def test_zcash_zip243_transfer(self):
        case = {
            'network': 'zec',
            'index': 0,
            'payload': (
                '5a45433430f337548a0000000400008085202f8901'
                '1111111111111111111111111111111111111111111111111111111111111111'
                '0000000000ffffffff0280d1f008000000001976a914'
                '222222222222222222222222222222222222222288ac'
                '4051cd14000000001976a914c8526260f90ddca458f53f5077'
                '1480a51ee4174c88ac00000000000000000000000000000000'
                '00000001'
                '0065cd1d000000001976a914c8526260f90ddca458f53f50771480a5'
                '1ee4174c88ac000000000000000000'
            ),
        }
        code, actual = probe(case)
        self.assertEqual(code, 0, actual)
        # The payload spends m/44'/133'/0'/0/0; derive it independently here.
        self.assertEqual(actual['address'], _t1_address(bytes(range(64)), 133))
        self.assertEqual(actual['address'], 't1c8oqrzA1kYPdgVhfDNUZn3buAbk6rXxiX')
        self.assertEqual(actual['recipient'],
                         't1Lz5sUzNoMBWmq8qk1zS4q5A54RgF5e4Ua')
        self.assertEqual(actual['fee'], '1000000')
        # ZIP-243 SIGHASH_ALL digest from tools/build_zcash_review_payload.py.
        self.assertEqual(
            actual['digest'],
            'e3a688194c0d8ccdfafa8b3034e5a3e59fa2b493af879ce7b5b1e8c1bd48e0d1',
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

