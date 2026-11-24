"""Mine a private fork with stock ryod and check approved Ryo payments against its UTXO set."""
import argparse
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time

from native_rpc_check import offline_node, post
from payment_interop import L, Oracle, ROOT, scalar, varint


def rpc(port, method, params):
    response = post(port, 'json_rpc', dict(jsonrpc='2.0', id=1, method=method, params=params))
    if 'error' in response or response['result']['status'] != 'OK':
        raise RuntimeError(f'{method}: {response}')
    return response['result']


def address(oracle, prefix, spend, view):
    body = varint(prefix) + oracle.mul(oracle.G, spend) + oracle.mul(oracle.G, view)
    data = body + oracle.hash(body)[:4]
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    result = ''
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        n, digits = int.from_bytes(block, 'big'), ''
        while n:
            n, remainder = divmod(n, 58)
            digits = alphabet[remainder] + digits
        result += digits.rjust([0,2,3,5,6,7,9,10,11][len(block)], '1')
    return result


def mine(port, receiver, height, epoch):
    template = rpc(port, 'getblocktemplate', dict(wallet_address=receiver, reserve_size=0))
    assert template['height'] == height and template['difficulty'] == 1, template
    wire = bytes.fromhex(template['blocktemplate_blob'])
    pos = 2  # major and minor versions here both fit one byte
    while wire[pos] & 128:
        pos += 1
    wire = wire[:2] + varint(epoch + height*240) + wire[pos+1:]
    rpc(port, 'submitblock', [wire.hex()])


def transaction(port, txid):
    response = post(port, 'gettransactions', dict(txs_hashes=[txid], decode_as_json=True, prune=False))
    assert response['status'] == 'OK' and not response.get('missed_tx'), response
    entry, = response['txs']
    assert entry['tx_hash'] == txid and not entry['in_pool']
    return entry, json.loads(entry['as_json'])


def check_view_wallet(binary, root, daemon_port, receiver, expected):
    # The private fork descends from testnet genesis. Give the wallet its
    # testnet encoding of the same two public keys used on the phone.
    description = root/'watch.json'
    description.write_text(json.dumps(dict(version=1, filename='watch', password='', address=receiver,
                                            viewkey=scalar(11).hex(), scan_from_height=47)))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        wallet_port = str(sock.getsockname()[1])
    cmd = [str(binary.resolve()), '--testnet', '--daemon-address', '127.0.0.1:'+daemon_port,
           '--generate-from-json', str(description), '--rpc-bind-ip', '127.0.0.1', '--rpc-bind-port', wallet_port,
           '--disable-rpc-login', '--trusted-daemon', '--log-file', str(root/'watch.log')]
    with tempfile.TemporaryFile() as log, subprocess.Popen(cmd, cwd=root, stdin=subprocess.DEVNULL,
                                                            stdout=log, stderr=log) as wallet:
        try:
            deadline = time.monotonic() + 90
            while wallet.poll() is None and time.monotonic() < deadline:
                try:
                    reply = post(wallet_port, 'json_rpc', dict(jsonrpc='2.0', id=1, method='get_transfers',
                                                              params={'in': True, 'account_index': 0}))
                except OSError:
                    time.sleep(.25)
                    continue
                assert 'error' not in reply, reply
                incoming = reply['result'].get('in', [])
                if len(incoming) >= len(expected):
                    assert {t['txid']: (t['height'], t['amount'], t['payment_id'], t['address']) for t in incoming} == expected
                    print(f'Stock Ryo view-only wallet received {len(expected)} payments with exact amounts and payment IDs', flush=True)
                    return
                time.sleep(.5)
            log.seek(0)
            raise RuntimeError(f'Ryo wallet scan failed: {log.read()[-2500:]!r}')
        finally:
            if wallet.poll() is None:
                try:
                    post(wallet_port, 'json_rpc', dict(jsonrpc='2.0', id=2, method='stop_wallet', params={}))
                    wallet.wait(timeout=8)
                except (OSError, subprocess.TimeoutExpired):
                    wallet.kill()
                    wallet.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('probe', 'ryod', 'oracle'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--wallet-rpc', type=Path, help='independently scan both payments with stock ryo-wallet-rpc')
    args = parser.parse_args()
    if not __debug__:
        parser.error('Checks require Python assertions')
    o = Oracle(args.oracle)
    spend = o.hs(bytes.fromhex('069b4a88474010274fa4f911c93ce869a3af8f253f172c96eb73e23be3dd4863'))
    view = o.hs(scalar(spend))
    epoch = int(time.time()) - 2*86400
    with tempfile.TemporaryDirectory(prefix='hexwallet-ryo-ledger-') as folder:
        root = Path(folder)
        # The stage difficulty algorithm needs 46 previous timestamps. Seed the
        # fork with an offline testnet prefix mined and validated by this same
        # binary. All spendable outputs used below are mined after the fork.
        with offline_node(args.ryod, True, directory=root, network='testnet') as port:
            miner = address(o, 0x306192, 31, 37)
            for h in range(1, 47):
                mine(port, miner, h, epoch)
            parent = rpc(port, 'getblockheaderbyheight', dict(height=46))['block_header']['hash']
            genesis = rpc(port, 'getblockheaderbyheight', dict(height=0))['block_header']['hash']
        (root/'stagenet').mkdir()
        shutil.copytree(root/'testnet'/'lmdb02', root/'stagenet'/'lmdb02')
        with offline_node(args.ryod, True, directory=root, network='stagenet', height=47) as port:
            info = post(port, 'getinfo', {})
            assert info['offline'] and info['stagenet'] and not info['mainnet']
            assert rpc(port, 'getblockheaderbyheight', dict(height=46))['block_header']['hash'] == parent
            payer = address(o, 0xd1c2192, spend, view)
            miner = address(o, 0xd1c2192, 31, 37)
            for h in range(47, 133):
                mine(port, payer if h in (47, 48, 49) else miner, h, epoch)
            entries = []
            for h in range(47, 72):
                txid = rpc(port, 'getblock', dict(height=h))['miner_tx_hash']
                entry, tx = transaction(port, txid)
                entries.append((entry['output_indices'][0], txid, tx))
            ring_reply = post(port, 'get_outs', dict(outputs=[dict(amount=0, index=i) for i, _, _ in entries]))
            assert ring_reply['status'] == 'OK' and len(ring_reply['outs']) == 25
            ring = []
            for (idx, txid, tx), member in zip(entries, ring_reply['outs'], strict=True):
                assert member['unlocked'] and member['txid'] == txid and member['key'] == tx['vout'][0]['target']['key']
                ring.append(dict(index=str(idx), destination='0x'+member['key'], commitment='0x'+member['mask']))
            sources = []
            for i, (_, _, tx) in enumerate(entries[:3]):
                amount = tx['vout'][0]['amount']
                extra = bytes(tx['extra'])
                assert extra[0] == 1
                key = o.hs(o.mul(extra[1:33], view*8) + varint(0))
                secret = (key + spend) % L
                dest = o.mul(o.G, secret)
                assert dest.hex() == ring[i]['destination'][2:]
                hp = o.hp(dest)
                img = o.mul(hp, secret)
                nonce = secrets.randbelow(L-1) + 1
                c = o.hs(img + o.mul(o.G, nonce) + o.mul(hp, nonce))
                sources.append(dict(ring=ring, realIndex=i, outputIndex='0', fundingPublic='0x'+extra[1:33].hex(),
                                    coinbaseAmount=str(amount), keyImage='0x'+img.hex(),
                                    keyImageSignature='0x'+(scalar(c)+scalar(nonce-c*secret)).hex()))
            expected = {}
            receiver = address(o, 0x306192, 7, 11)
            for n, selected in enumerate((sources[:1], sources[1:]), 1):
                intent = dict(payer=address(o, 0x2ce192, spend, view), recipient=address(o, 0x2ce192, 7, 11),
                              viewSecret='0x'+scalar(view).hex(), paymentId='0x'+'ae'*32, inputs=selected, amount=str(12345678*n))
                if n == 1:
                    intent['fee'] = '100000000'
                path = root/'intent.json'
                path.write_text(json.dumps(intent))
                script = Path(__file__).with_name('ryo_ledger_phone.cjs')
                def phone(*arguments):
                    return subprocess.check_output(['node', str(script), str(path), *arguments], text=True, timeout=90).strip()
                signed = json.loads(phone(str(args.probe.resolve())))
                # The release phone pins mainnet. Native acceptance here uses
                # the separately identified local fork and its real RPC pool.
                heights = dict(height=0)
                assert rpc(port, 'getblockheaderbyheight', heights)['block_header']['hash'] == genesis
                result = post(port, 'sendrawtransaction', dict(tx_as_hex=signed['wire'], do_not_relay=False))
                assert result['status'] == 'OK' and not result.get('not_relayed'), result
                assert post(port, 'getinfo', {})['tx_pool_size'] == 1
                pending = post(port, 'gettransactions', dict(txs_hashes=[signed['id']], decode_as_json=False, prune=False))
                pooled, = pending['txs']
                assert pooled['in_pool'] and pooled['tx_hash'] == signed['id'] and pooled['as_hex'] == signed['wire']
                h = 132 + n
                mine(port, miner, h, epoch)
                block = rpc(port, 'getblock', dict(height=h))
                assert signed['id'] in block['tx_hashes']
                entry, _ = transaction(port, signed['id'])
                assert entry['block_height'] == h and entry['as_hex'] == signed['wire']
                scanned = json.loads(phone('--scan', entry['as_hex']))
                assert scanned == [intent['amount'], intent['paymentId'][2:]]
                expected[signed['id']] = (h, int(intent['amount']), scanned[1], receiver)
                assert not post(port, 'get_transaction_pool', {}).get('transactions')
                print(f'{n} input(s), {signed["id"]}, height {h}, block {block["block_header"]["hash"]}, received {scanned[0]} atomic', flush=True)
            print(f'Offline testnet fork at 46 ({parent}), genesis {genesis}, stock daemon in stagenet mode')
            if args.wallet_rpc:
                check_view_wallet(args.wallet_rpc, root, port, receiver, expected)


if __name__ == '__main__':
    main()
