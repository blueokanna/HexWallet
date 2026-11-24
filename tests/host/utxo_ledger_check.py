"""Spend mined outputs through the phone callback on each network's private Core regtest."""

import hashlib
import struct
import subprocess
import sys

from regtest_rpc import regtest


def varbytes(data):
    if len(data) >= 253:
        return b'\xfd' + struct.pack('<H', len(data)) + data
    return bytes([len(data)]) + data


def field(key, value):
    return varbytes(key) + varbytes(value)


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def public_keys(purpose, coin):
    js = """
      const { HDNodeWallet, Mnemonic } = require('ethers');
      const root = HDNodeWallet.fromSeed(Mnemonic.fromPhrase('abandon '.repeat(11) + 'about').computeSeed());
      const path = `m/${process.argv[1]}'/${process.argv[2]}'/0'/0/`;
      console.log([root.fingerprint, ...[3, 4].map(i => root.derivePath(path+i).publicKey)].join(' '));
    """
    line = subprocess.check_output(['node', '-e', js, str(purpose), str(coin)], text=True)
    return tuple(bytes.fromhex(word[2:]) for word in line.split())


def psbt(version, txid, vout, script, redeem, fingerprint, pub, purpose, coin, amount, fee, destination, flag, previous):
    prev = bytes.fromhex(txid)[::-1]
    index = struct.pack('<I', vout)
    sequence = b'\xff' * 4
    value = struct.pack('<Q', amount - fee)
    script_out = value + varbytes(destination)
    tx = b'\x02\0\0\0\x01' + prev + index + b'\0' + sequence + b'\x01' + script_out + bytes(4)
    global_map = field(b'\0', tx) if version == 0 else (
        field(b'\xfb', struct.pack('<I', 2)) + field(b'\x02', tx[:4]) + field(b'\x04', b'\x01') + field(b'\x05', b'\x01'))
    path = struct.pack('<5I', purpose | 0x80000000, coin | 0x80000000, 0x80000000, 0, 3)
    inputs = field(b'\x00', previous) if previous else field(b'\x01', struct.pack('<Q', amount) + varbytes(script))
    if purpose == 86:
        inputs += field(b'\x16' + pub[1:], b'\0' + fingerprint + path) + field(b'\x17', pub[1:])
    else:
        inputs += field(b'\x06' + pub, fingerprint + path)
    if redeem:
        inputs += field(b'\x04', redeem)
    if flag is not None:
        inputs += field(b'\x03', struct.pack('<I', flag))
    outputs = b''
    if version == 2:
        inputs += field(b'\x0e', prev) + field(b'\x0f', index) + field(b'\x10', sequence)
        outputs = field(b'\x03', value) + field(b'\x04', destination)
    return b'psbt\xff' + global_map + b'\0' + inputs + b'\0' + outputs + b'\0'


def check(probe, network, rpc, catalog=None):
    coin, profiles = {
        'btc': (0, [('btc44', 44), ('btc49', 49), ('btc', 84), ('btc86', 86)]),
        'ltc': (2, [('ltc', 44), ('ltc49', 49), ('ltc84', 84)]),
        'doge': (3, [('doge', 44)]),
        'grs': (17, [('grs', 44), ('grs49', 49), ('grs84', 84)]),
        'bch': (145, [('bch', 44)]),
        'btg': (156, [('btg', 44), ('btg49', 49), ('btg84', 84)]),
        'xec': (899, [('xec', 44)]),
    }[network]
    fork_id = network in ('bch', 'btg', 'xec')
    # Bitcoin ABC RPC expresses one XEC as 100 base units.
    scale = 100 if network == 'xec' else 10**8
    profiles = [(profile, purpose, coin) for profile, purpose in profiles]
    if catalog:
        family, fork = {'btc': ('bitcoin', '0'), 'bch': ('forkid', '0'),
                        'grs': ('groestl', '0'), 'btg': ('forkid', '79')}[network]
        rows = subprocess.check_output([catalog, '--psbt'], text=True).splitlines()
        profiles = [(profile, int(purpose), int(coin)) for profile, purpose, coin, algorithm, number
                    in (row.split('|') for row in rows) if (algorithm, number) == (family, fork)]
        assert profiles and len({profile for profile, _, _ in profiles}) == len(profiles)
    funded = []
    for profile, purpose, coin in profiles:
        fingerprint, pub, recipient = public_keys(purpose, coin)
        witness = b'\0\x14' + hash160(pub)
        if purpose == 86:
            descriptor = rpc('getdescriptorinfo', f'tr({pub[1:].hex()})')['descriptor']
            address, = rpc('deriveaddresses', descriptor)
            script = bytes.fromhex(rpc('validateaddress', address)['scriptPubKey'])
        else:
            script = {44: b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac',
                      49: b'\xa9\x14' + hash160(witness) + b'\x87', 84: witness}[purpose]
            decoded = rpc('decodescript', script.hex())
            address = decoded['address'] if 'address' in decoded else decoded['addresses'][0]
        destination = b'\x76\xa9\x14' + hash160(recipient) + b'\x88\xac'
        if profile == 'prl':
            desc = rpc('getdescriptorinfo', f'tr({recipient[1:].hex()})')['descriptor']
            target, = rpc('deriveaddresses', desc)
            destination = bytes.fromhex(rpc('validateaddress', target)['scriptPubKey'])
        block, = rpc('generatetoaddress', 1, address)
        txid = rpc('getblock', block)['tx'][0]
        coinbase = rpc('getrawtransaction', txid, 1)
        output, = [out for out in coinbase['vout'] if out['scriptPubKey']['hex'] == script.hex()]
        previous = bytes.fromhex(coinbase['hex']) if purpose == 44 and not fork_id else None
        funded.append((profile, purpose, coin, fingerprint, pub, script, witness, destination, txid, output, previous))
    # Bitcoin Gold activates ForkID at 2000. Litecoin regtest activates SegWit at genesis.
    height = max({'btg': 2001, 'grs': 125}.get(network, 110), len(funded) + 100)
    rpc('generatetoaddress', height - rpc('getblockcount'), address)
    assert rpc('getblockcount') == height
    submitted = []
    for profile, purpose, coin, fingerprint, pub, script, witness, destination, txid, output, previous in funded:
        valid_flag = 0x41 if fork_id else 1
        invalid_flag = 1 if fork_id else 0x41
        variants = {}
        amount = int(output['value'] * scale)
        # Dogecoin Core recommends 1000 koinu per byte; the single-input payment estimates 193 bytes.
        fee = 193000 if profile == 'doge' else 1000
        for version in (0, 2):
            for flag in (None, valid_flag, invalid_flag):
                wire = psbt(version, txid, output['n'], script, witness if purpose == 49 else b'',
                            fingerprint, pub, purpose, coin, amount, fee, destination, flag, previous)
                result = subprocess.run([probe, 'phone-review', profile, wire.hex(), 'approve'], capture_output=True, text=True)
                if flag == invalid_flag:
                    assert result.returncode == 1 and 'signed=' not in result.stdout
                else:
                    result.check_returncode()
                    lines = result.stdout.splitlines()
                    assert profile in lines and 'EXTERNAL' in lines and f"path=m/{purpose}'/{coin}'/0'/0/3" in lines
                    if profile in ('doge', 'prl'):
                        symbol = 'DOGE' if profile == 'doge' else 'PRL'
                        if profile == 'doge':
                            assert '0.00193 DOGE | 1000 koinu/vB (floor)' in lines
                        else:
                            assert any(line.startswith('0.00001 PRL | ') and line.endswith(' grain/vB (floor)') for line in lines)
                        whole, fraction = divmod(amount - fee, 10**8)
                        assert f'{whole}.{fraction:08d}'.rstrip('0') + ' ' + symbol in lines
                    else:
                        assert f'fee={fee} sat' in lines and f'amount={amount - fee} sat' in lines
                    signed, = [line[7:] for line in lines if line.startswith('signed=')]
                    variants[version, flag] = signed
            if profile in ('btc44', 'doge'):
                limit = 193 * (1000 if profile == 'doge' else 500)
                excessive = psbt(version, txid, output['n'], script, b'', fingerprint, pub, purpose, coin,
                                 amount, limit + 1, destination, None, previous)
                result = subprocess.run([probe, 'phone-review', profile, excessive.hex(), 'approve'], capture_output=True, text=True)
                assert result.returncode == 1 and 'signed=' not in result.stdout
        for flag in (None, valid_flag):
            assert variants[0, flag] == variants[2, flag]
        raw = variants[0, None]
        if purpose == 86:
            for flag, size in ((None, 64), (1, 65)):
                candidate = variants[0, flag]
                signature, = rpc('decoderawtransaction', candidate)['vin'][0]['txinwitness']
                assert len(bytes.fromhex(signature)) == size and (flag is None or signature.endswith('01'))
                assert rpc('testmempoolaccept', [candidate])[0]['allowed']
        else:
            assert raw == variants[0, valid_flag]
        expected = rpc('decoderawtransaction', raw)
        assert expected['vout'][0]['scriptPubKey']['hex'] == destination.hex()
        assert int(expected['vout'][0]['value'] * scale) == amount - fee
        txid = rpc('sendrawtransaction', raw)
        assert txid == expected['txid']
        submitted.append(txid)
        print(f'{profile} PSBT v0/v2 signed and accepted {txid}', flush=True)
    block, = rpc('generatetoaddress', 1, address)
    assert set(submitted) <= set(rpc('getblock', block)['tx'])
    print(f'{network} Core regtest height {rpc("getblockcount")} confirmed {len(submitted)} in {block}')


if __name__ == '__main__':
    probe, network, daemon, *options = sys.argv[1:]
    if options and (len(options) != 2 or options[0] != '--catalog'):
        sys.exit('Expected optional --catalog <catalog_dump>')
    with regtest(daemon, ['-disablewallet', '-txindex=1']) as call:
        check(probe, network, call, options[1] if options else None)
