"""Confirm transparent P2PKH and P2SH-P2PK spends on private ZEC and ZERO regtest nodes."""

import hashlib
import struct
import subprocess
import sys

from regtest_rpc import regtest, running_regtest
from zcash_protocol_check import fixture_key, hash160, push


def regtest_address(key_hash):
    data = bytes.fromhex('1d25') + key_hash
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    number = int.from_bytes(data + checksum, 'big')
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    text = ''
    while number:
        number, digit = divmod(number, 58)
        text = alphabet[digit] + text
    return text


def zebra_regtest(daemon, address):
    def prepare(datadir, port, password):
        config = datadir / 'zebrad.toml'
        config.write_text(f'''[network]
network = "Regtest"
listen_addr = "127.0.0.1:0"
initial_testnet_peers = []
[network.testnet_parameters]
should_allow_unshielded_coinbase_spends = true
[network.testnet_parameters.activation_heights]
Canopy = 1
NU5 = 2
NU6 = 4
"NU6.1" = 5
"NU6.2" = 6
"NU6.3" = 7
NU7 = 105
[rpc]
listen_addr = "127.0.0.1:{port}"
enable_cookie_auth = false
[state]
ephemeral = true
[mempool]
debug_enable_at_height = 0
[mining]
miner_address = "{address}"
''', encoding='utf-8')
        return [daemon, '-c', str(config), 'start']
    return running_regtest(prepare, chain_name='test')


def check(probe, network, daemon):
    if network not in ('zer', 'zec'):
        raise ValueError('Expected zer or zec')
    v5 = network == 'zec'
    branch = 0x77190ad9 if v5 else 0x7361707a
    keys = [bytes.fromhex(fixture_key(133 if v5 else 323, i)[2:]) for i in (3, 4)]
    key_hash = hash160(keys[0])
    p2pkh = b'\x76\xa9\x14' + key_hash + b'\x88\xac'
    redeem = push(keys[1]) + b'\xac'
    p2sh = b'\xa9\x14' + hash160(redeem) + b'\x87'
    args = ['-nuparams=6f76727a:1', '-nuparams=7361707a:1', '-txindex=1',
            '-mineraddress=' + regtest_address(key_hash), '-minetolocalwallet=0']
    node = zebra_regtest(daemon, regtest_address(key_hash)) if v5 else regtest(daemon, args)
    with node as rpc:
        if v5:
            assert rpc('getblockhash', 0) == '029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327'
        # ZERO v4.0.0 enforces 720-block coinbase maturity on regtest as well.
        blocks = rpc('generate', 105 if v5 else 720)
        assert rpc('getblockchaininfo')['consensus']['nextblock'] == f'{branch:08x}'
        coinbase = rpc('getblock', blocks[0])['tx'][0]
        outputs = rpc('getrawtransaction', coinbase, 1)['vout']
        out, = [o for o in outputs if o['scriptPubKey']['hex'] == p2pkh.hex()]
        value = int(out['value'] * 10**8)

        def submit(inputs, outputs):
            expiry = struct.pack('<II', 0, rpc('getblockcount') + 20)
            wire = bytearray.fromhex('050000800a27a726' if v5 else '0400008085202f89')
            if v5:
                wire.extend(struct.pack('<I', branch) + expiry)
            wire.append(len(inputs))
            metadata = bytearray([len(inputs)])
            for txid, vout, amount, script, index, redeem_script in inputs:
                wire.extend(bytes.fromhex(txid)[::-1] + struct.pack('<I', vout) + b'\0\xff\xff\xff\xff')
                metadata.extend(struct.pack('<Q', amount) + push(script) + struct.pack('<IBI', 0, 0, index) + push(redeem_script))
            wire.append(len(outputs))
            for amount, script in outputs:
                wire.extend(struct.pack('<Q', amount) + push(script))
            wire.extend(bytes(3) if v5 else expiry + bytes(11))
            payload = b'ZEC5' + struct.pack('<II', branch, len(wire)) + wire + metadata
            lines = subprocess.check_output([probe, 'phone-review', network, payload.hex(), 'approve'], text=True).splitlines()
            signed, = [line[7:] for line in lines if line.startswith('signed=')]
            txid = rpc('sendrawtransaction', signed)
            block, = rpc('generate', 1)
            assert txid in rpc('getblock', block)['tx']
            decoded = rpc('getrawtransaction', txid, 1)
            assert decoded['confirmations'] >= 1 and [(int(o['value'] * 10**8), o['scriptPubKey']['hex'])
                   for o in decoded['vout']] == [(amount, script.hex()) for amount, script in outputs]
            print(f'{network} regtest height {rpc("getblockcount")} confirmed {txid} in {block}', flush=True)
            return txid

        fee = 10000
        change = value - 100000 - fee
        funding = submit([(coinbase, out['n'], value, p2pkh, 3, b'')], [(change, p2pkh), (100000, p2sh)])
        submit([(funding, 0, change, p2pkh, 3, b''), (funding, 1, 100000, p2sh, 4, redeem)], [(value - 2 * fee, p2pkh)])


if __name__ == '__main__':
    check(*sys.argv[1:])
