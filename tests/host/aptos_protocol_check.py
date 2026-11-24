"""Check the phone request, device review and returned authenticator using aptos-sdk 0.11.0."""

import hashlib
import hmac
import struct
import subprocess
import sys

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Deserializer, Serializer
from aptos_sdk.ed25519 import PrivateKey
from aptos_sdk.transactions import EntryFunction, RawTransaction, SignedTransaction, TransactionArgument, TransactionPayload


def fixture_key():
    words = ('abandon ' * 11 + 'about').encode()
    seed = hashlib.pbkdf2_hmac('sha512', words, b'mnemonic', 2048)
    node = hmac.digest(b'ed25519 seed', seed, 'sha512')
    for index in (44, 637, 0, 0, 3):
        node = hmac.digest(node[32:], b'\0' + node[:32] + struct.pack('>I', 0x80000000 | index), 'sha512')
    return PrivateKey.from_hex(node[:32], strict=False)


def payment(probe, key, destination, amount, chain, sequence, price, expiry, max_gas=2000):
    sender = AccountAddress.from_key(key.public_key())
    entry = EntryFunction.natural('0x1::aptos_account', 'transfer', [], [
        TransactionArgument(destination, Serializer.struct), TransactionArgument(amount, Serializer.u64)])
    unsigned = RawTransaction(sender, sequence, TransactionPayload(entry), max_gas, price, expiry, chain)
    wire = b'APT1' + struct.pack('>BBQQQI', chain, 0, max_gas, price, expiry, sequence) + destination.address + struct.pack('>Q', amount)
    args = [probe, 'phone-review', 'apt', wire.hex()]
    review = subprocess.check_output(args + ['approve'], text=True).splitlines()
    def amount_text(octas):
        whole, frac = divmod(octas, 10**8)
        return f"{whole}.{f'{frac:08}'.rstrip('0') or '0'} APT"
    for field in [f'address={sender}', "path=m/44'/637'/0'/0'/3'", str(destination), amount_text(amount),
                  amount_text(max_gas * price), f'SEQUENCE {sequence}', f'GAS {max_gas} x {price}', f'CHAIN {chain}', f'EXPIRY {expiry}']:
        assert field in review, (field, review)
    raw = Serializer()
    raw.struct(unsigned)
    signed = raw.output() + bytes.fromhex(next(line[7:] for line in review if line.startswith('signed=')))
    parser = Deserializer(signed)
    decoded = SignedTransaction.deserialize(parser)
    assert parser.remaining() == 0 and decoded.verify()
    assert signed == SignedTransaction(unsigned, unsigned.sign(key)).bytes()
    assert 'signed=' not in subprocess.check_output(args + ['stale-page'], text=True)
    return signed


def check(probe):
    key = fixture_key()
    for chain, price in [(1, 100), (2, 0)]:
        payment(probe, key, AccountAddress(bytes([0x44]) * 32), 12345678, chain, 7, price, 1799999999)
    print('Aptos phone review, HD address, SDK transaction bytes and signature verification passed (mainnet/testnet IDs)')


if __name__ == '__main__':
    check(sys.argv[1])
