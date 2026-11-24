"""Compare approved transparent transactions with zcash-test-vectors and ethers.

PYTHONPATH points to zcash/zcash-test-vectors at the revision pinned in CI.
NODE_PATH points to tests/host/protocol-oracles/node_modules.
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from zcash_test_vectors import zip_0243, zip_0244
from zcash_test_vectors.rand import Rand
from zcash_test_vectors.transaction import LegacyTransaction, OutPoint, Script, TransactionV5, TxIn, TxOut


def fixture_key(coin, index, digest=None):
    js = """
        const { HDNodeWallet, Mnemonic } = require('ethers');
        const [coin, index, digest] = process.argv.slice(1);
        const seed = Mnemonic.fromPhrase('abandon '.repeat(11) + 'about').computeSeed();
        const key = HDNodeWallet.fromSeed(seed).derivePath(`m/44'/${coin}'/0'/0/${index}`).signingKey;
        console.log(JSON.stringify(digest ? key.sign('0x' + digest).toJSON() : key.compressedPublicKey));
    """
    args = ['node', '-e', js, str(coin), str(index)]
    if digest is not None:
        args.append(digest.hex())
    return json.loads(subprocess.check_output(args, text=True))


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def push(data):
    assert len(data) <= 75
    return bytes([len(data)]) + data


def der_integer(value):
    raw = bytes.fromhex(value[2:]).lstrip(b'\0')
    return b'\x02' + push((b'\0' if raw[0] & 128 else b'') + raw)


def check_historical_signatures(probe):
    # Public master key and chain code from run_zcash_transaction_self_test at 06597624.
    js = """
        const { HDNodeWallet, encodeBase58, getBytes, sha256 } = require('ethers');
        const key = Buffer.from(Array.from({length: 32}, (_, i) => i + 1));
        const code = Buffer.from(Array.from({length: 32}, (_, i) => 128 + i));
        const payload = Buffer.concat([Buffer.from('0488ade4', 'hex'), Buffer.alloc(9), code, Buffer.alloc(1), key]);
        const sum = getBytes(sha256(sha256(payload))).slice(0, 4);
        const signer = HDNodeWallet.fromExtendedKey(encodeBase58(Buffer.concat([payload, sum])))
          .derivePath("m/44'/133'/0'/0/0").signingKey;
        const digest = process.argv[1];
        console.log(JSON.stringify(digest ? signer.sign('0x' + digest).toJSON() : signer.compressedPublicKey));
    """
    def key(*args):
        return json.loads(subprocess.check_output(['node', '-e', js, *args], text=True))

    outputs = json.loads(Path(__file__).with_name('protocol-oracles').joinpath('zcash-nu62.json').read_text())
    pub = bytes.fromhex(key()[2:])
    payment = b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'
    redeem = push(pub) + b'\xac'
    for kind, script_code, tail in [('p2pkh', payment, pub), ('p2sh', redeem, redeem)]:
        tx = LegacyTransaction(Rand(bytes), 4)
        tx.nExpiryHeight = 1_000_000
        tx.vin = [TxIn.from_components(OutPoint.from_components(bytes(32), 0), Script.from_bytes(b''), 0xfffffffe)]
        tx.vout = [TxOut(Rand(bytes)), TxOut(Rand(bytes))]
        tx.vout[0].nValue, tx.vout[0].scriptPubKey = 40_000_000, Script.from_bytes(payment)
        tx.vout[1].nValue, tx.vout[1].scriptPubKey = 59_999_000, Script.from_bytes(bytes.fromhex(
            '76a9145453e4698f02a38abdaa521cd1ff2dee6fac187188ac'))
        branch = 0x5437f330
        unsigned = bytes(tx)
        digest = zip_0243.signature_hash(Script.from_bytes(script_code), tx, 0, 1, 100_000_000, branch)
        sig = key(digest.hex())
        der = b'\x30' + push(der_integer(sig['r']) + der_integer(sig['s']))
        tx.vin[0].scriptSig = Script.from_bytes(push(der + b'\x01') + push(tail))
        assert bytes(tx).hex() == outputs[kind]
        script = b'\xa9\x14' + hash160(redeem) + b'\x87' if kind == 'p2sh' else payment
        meta = b'\x01' + struct.pack('<Q', 100_000_000) + push(script) + bytes(9) + push(redeem if kind == 'p2sh' else b'')
        envelope = b'ZEC5' + struct.pack('<II', branch, len(unsigned)) + unsigned + meta
        refused = subprocess.run([probe, 'phone-review', 'zec', envelope.hex(), 'approve'], capture_output=True, text=True)
        assert refused.returncode == 1 and 'signed=' not in refused.stdout
        print(f'Archived NU6.2 {kind}: independent signed bytes match ({len(bytes(tx))} bytes), NU7 request refused')


def check(probe, network, coin, branch):
    v5 = network == 'zec'
    # Selection bits 0 and 1 in the reference constructor request only transparent fields.
    rand = Rand(lambda size: b'\x03' * size)
    tx = TransactionV5(rand, branch) if v5 else LegacyTransaction(Rand(bytes), 4)
    tx.nLockTime = 12
    tx.nExpiryHeight = 4_000_000 if v5 else 4_500_000
    tx.vin = []
    prevouts = []
    metadata = bytearray()
    pushes = []
    for i, value in enumerate([100_000, 120_000]):
        pub = bytes.fromhex(fixture_key(coin, 3 + i)[2:])
        redeem = push(pub) + b'\xac' if i else b''
        script = b'\xa9\x14' + hash160(redeem) + b'\x87' if i else b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'
        pushes.append(redeem or pub)
        prevouts.append(SimpleNamespace(nIn=i, amount=value, scriptPubKey=Script.from_bytes(script)))
        tx.vin.append(TxIn.from_components(OutPoint.from_components(bytes(range(i, i + 32)), 2 + i),
                                           Script.from_bytes(b''), 0xfffffffe - i))
        metadata.extend(struct.pack('<Q', value) + push(script) + struct.pack('<IBI', 0, 0, 3 + i) + push(redeem))
    recipient = TxOut(rand)
    recipient.nValue = 200_000
    recipient.scriptPubKey = prevouts[0].scriptPubKey
    tx.vout = [recipient]
    unsigned = bytes(tx)

    def envelope(wire, branch_id=branch):
        return b'ZEC5' + struct.pack('<II', branch_id, len(wire)) + wire + bytes([len(prevouts)]) + metadata

    payload = envelope(unsigned)
    for i, prev in enumerate(prevouts):
        code = Script.from_bytes(pushes[i]) if i else prev.scriptPubKey
        digest = (zip_0244.signature_digest(tx, prevouts, 1, prev) if v5 else
                  zip_0243.signature_hash(code, tx, i, 1, prev.amount, branch))
        sig = fixture_key(coin, 3 + i, digest)
        der = b'\x30' + push(der_integer(sig['r']) + der_integer(sig['s']))
        tx.vin[i].scriptSig = Script.from_bytes(push(der + b'\x01') + push(pushes[i]))

    args = [probe, 'phone-review', network]
    result = subprocess.check_output(args + [payload.hex(), 'approve'], text=True).splitlines()
    assert f'signed={bytes(tx).hex()}' in result
    assert 'P2SH INPUT' in result and f'0.00200000 {network.upper()}' in result
    assert f'0.00120000 {network.upper()}' in result and f'0.00020000 {network.upper()}' in result
    assert ('Zcash (transparent)' if v5 else 'ZERO (transparent)') in result
    assert 'signed=' not in subprocess.check_output(args + [payload.hex(), 'reject'], text=True)
    invalid = [envelope(bytes(tx)), envelope(unsigned, branch ^ 1)]
    if v5:
        txid = zip_0244.txid_digest(tx)[::-1].hex()
        for wire in [unsigned, bytes(tx)]:
            assert subprocess.check_output([probe, 'zec-v5-txid', wire.hex()], text=True).strip() == txid
        invalid += [envelope(unsigned[:8] + struct.pack('<I', 0x5437f330) + unsigned[12:]),
                    envelope(unsigned[:-1] + b'\x01'), envelope(unsigned + b'\x00')]
        # A well-formed transparent v4 transaction is prohibited even with the NU7 envelope.
        v4 = bytes.fromhex('0400008085202f89') + unsigned[20:-3] + unsigned[12:20] + bytes(11)
        invalid += [envelope(v4), envelope(v4, 0x5437f330)]
    for data in invalid:
        refused = subprocess.run(args + [data.hex(), 'approve'], capture_output=True, text=True)
        assert refused.returncode == 1 and 'signed=' not in refused.stdout
    print(f'{network}: official serialization and both input signatures match ({len(bytes(tx))} bytes)')
    if v5:
        print(f'ZIP-244 txid={txid}')

    # The t3 input takes one of the sixteen review rows. Verify the last
    # destination is included at the limit and the next output refuses approval.
    for txin in tx.vin:
        txin.scriptSig = Script.from_bytes(b'')
    tx.vout = []
    expected_amounts = []
    for i in range(16):
        payment = TxOut(rand)
        payment.nValue = 10_000 + i
        payment.scriptPubKey = prevouts[i % 2].scriptPubKey
        tx.vout.append(payment)
        expected_amounts.append(f'0.{payment.nValue:08d} {network.upper()}')
        if len(tx.vout) == 15:
            lines = subprocess.check_output(args + [envelope(bytes(tx)).hex(), 'approve'], text=True).splitlines()
            assert lines.count('EXTERNAL') == 15 and lines.count('P2SH INPUT') == 1
            assert all(amount in lines for amount in expected_amounts)
    refused = subprocess.run(args + [envelope(bytes(tx)).hex(), 'approve'], capture_output=True, text=True)
    assert refused.returncode == 1 and 'signed=' not in refused.stdout


if __name__ == '__main__':
    # Mined in Zcash mainnet block 3,599,999. Preserve the explorer's wire
    # bytes to exercise the RPC byte order with inputs unrelated to the test wallet.
    # https://api.blockchair.com/zcash/raw/transaction/a9ea32f8c7d3b60b06621133b5af8c9f108e44198035e8e7cdc4017c74cc02f2
    confirmed_txid = 'a9ea32f8c7d3b60b06621133b5af8c9f108e44198035e8e7cdc4017c74cc02f2'
    confirmed_wire = (
        '050000800a27a726d90a1977000000000000000001002d172b23eac96e3959c2fe'
        'f23ab4deb2da68c0a2bd0484c76df6824e129ec3000000006b483045022100ca8e'
        'f20a20dd4f1bfb54676fd2d4bab5546004c9daeab4289757b3e2ef534de1022054'
        '2818ab1f9e24d630460612ddbf9d26c2b2de320ab8d2482d8e43e65966f8a701'
        '2102ca835793e826901bc82038759608c9de10b0af0b1d7f5b71b9b6a27af833'
        '006bffffffff0240420f000000000017a914341f30aad1726b2837eceb485a217e17'
        '27fb43178734637e03000000001976a9145c2d3b1b77e352045d8e0beee89e37e7'
        'c4e9d31e88ac000000')
    assert subprocess.check_output([sys.argv[1], 'zec-v5-txid', confirmed_wire], text=True).strip() == confirmed_txid
    print(f'Zcash mainnet block 3599999 txid={confirmed_txid}')
    check_historical_signatures(sys.argv[1])
    check(sys.argv[1], 'zec', 133, 0x77190ad9)
    check(sys.argv[1], 'zer', 323, 0x7361707a)
