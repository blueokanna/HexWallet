"""Spend mature Zarcanum outputs on the accelerated-HF6 private testnet daemon."""
import argparse
import base64
from decimal import Decimal
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from native_rpc_check import offline_node, post
from payment_interop import varint


def rpc(port, method, params):
    reply = post(port, 'json_rpc', dict(jsonrpc='2.0', id=1, method=method, params=params))
    if 'error' in reply or reply['result']['status'] != 'OK':
        raise RuntimeError(f'{method}: {reply}')
    return reply['result']


def mine(port, height, address, epoch):
    template = rpc(port, 'getblocktemplate', dict(wallet_address=address))
    assert template['height'] == height and int(template['difficulty']) == 1, (height, template['difficulty'])
    wire = bytes.fromhex(template['blocktemplate_blob'])
    # major, u64 nonce, previous hash, single-byte minor, timestamp varint.
    assert wire[41] < 128
    end = 42
    while wire[end] & 128:
        end += 1
    wire = wire[:42] + varint(epoch + height * 240) + wire[end+1:]
    rpc(port, 'submitblock', [wire.hex()])
    return rpc(port, 'get_blocks_details', dict(height_start=height, count=1))['blocks'][0]


def wallet_command(binary, folder, port, *args, expected_exit=0):
    command = [str(binary.resolve()), '--daemon-address', f'127.0.0.1:{port}', '--password', 'LedgerTest123',
               '--log-file', str(Path(folder)/'wallet.log'), *args]
    run = subprocess.run(command, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, timeout=90, text=True, errors='replace')
    assert run.returncode == expected_exit, f'upstream wallet exited {run.returncode}'
    return run.stdout


def create_recipient(binary, folder, port):
    # Export an empty watch-only wallet before the payments exist. The full
    # wallet never sees either transaction. Both files live in the temp dir.
    # This pinned simplewallet exits with EXIT_FAILURE immediately after a
    # successful --generate-new-wallet. Reopen it for the export command.
    output = wallet_command(binary, folder, port, '--generate-new-wallet', 'recipient', '--no-set-creation-date', expected_exit=1)
    wallet_command(binary, folder, port, '--wallet-file', 'recipient', 'save_watch_only', 'observer', 'LedgerTest123')
    assert (Path(folder)/'observer').is_file(), 'upstream watch-only export failed'
    address = re.search(r'Generated new\s+wallet: (Zx\w+)', output)
    view = re.search(r'view key: ([0-9a-f]{64})', output)
    assert address and view, 'missing generated address or view key'
    return {'recipient': address[1], 'recipientView': '0x'+view[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('probe','release-probe','zanod','simplewallet'):
        parser.add_argument('--'+arg, type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('Python assertions must be enabled')
    phone = ['node',str(Path(__file__).with_name('zano_phone_check.cjs').resolve())]
    address = json.loads(subprocess.check_output(phone+['--addresses']))
    with tempfile.TemporaryDirectory() as folder, offline_node(args.zanod, False) as port:
        genesis = rpc(port,'getblockheaderbyheight',{'height':0})['block_header']['hash']
        assert genesis == '610f3b7d7bd87df12c4c56d7a48c111aa389700a49979d246c6366bf0243e5ed'
        recipient = create_recipient(args.simplewallet, folder, port)
        epoch = int(time.time())-86400
        outputs, owned = [], []
        for height in range(1,39):
            is_payer = height in (6,7,8)
            block = mine(port,height,address['payer' if is_payer else 'recipient'],epoch)
            if not 5 <= height <= 27:
                continue
            miner = block['transactions_details'][0]['id']
            entry = rpc(port,'get_tx_details',{'tx_hash':miner})['tx_info']
            tx = json.loads(base64.b64decode(entry['object_in_json']))
            assert tx['version'] == 4
            for i,(out,detail) in enumerate(zip(tx['vout'],entry['outs'],strict=True)):
                o = out['tx_out_zarcanum']
                member = dict(index=detail['global_index'],destination=o['stealth_address'],asset=o['blinded_asset_id'],commitment=o['amount_commitment'])
                outputs.append(member)
                if is_payer and i == 0:
                    owned.append(dict(**member,publicKey=entry['pub_key'],outputIndex=i,concealing=o['concealing_point'],
                                      encryptedAmount=str(o['encrypted_amount']),encryptedPaymentId=str(o['encrypted_payment_id'])))
        assert len(owned) == 3
        for f in owned:
            ring = [m for m in outputs if m['index'] != f['index']][:15] + [f.copy()]
            f['ring'] = sorted(ring,key=lambda m:m['index'])
        cases = Path(folder)/'inputs.json'
        result = Path(folder)/'payments.json'
        cases.write_text(json.dumps([dict(funds=owned[:1],amount='12345678',**recipient),dict(funds=owned[1:],amount='24691356',**recipient)]))
        subprocess.run(phone+[str(args.probe.resolve()),str(args.release_probe.resolve()),str(cases),str(result)],check=True,timeout=300)
        payments = json.loads(result.read_text())
        for height,tx in enumerate(payments,39):
            sent = post(port,'sendrawtransaction',{'tx_as_hex':tx['wire']})
            assert sent['status'] == 'OK', sent
            pool = rpc(port,'get_pool_txs_details',{})
            assert any(t['id']==tx['id'] for t in pool['txs']), pool
            block = mine(port,height,address['recipient'],epoch)
            assert tx['id'] in [t['id'] for t in block['transactions_details']]
            detail = rpc(port,'get_tx_details',{'tx_hash':tx['id']})['tx_info']
            assert detail['keeper_block']==height and detail['fee']==10000000000
            assert base64.b64decode(detail['blob']) == bytes.fromhex(tx['wire'])
            print(f"Private Zano block {height} {block['id']}, tx {tx['id']}, {tx['amount']} atomic units, fee {detail['fee']}",flush=True)
        payment_id = '0807060504030201'
        wallet_command(args.simplewallet, folder, port, '--wallet-file', 'observer', 'refresh')
        output = wallet_command(args.simplewallet, folder, port, '--wallet-file', 'observer', 'payments', payment_id)
        rows = re.findall(rf'{payment_id}\s+<?([a-f0-9]{{64}})>?\s+(\d+)\s+([\d.]+)\s+\d+', output)
        actual = sorted((int(height), txid, Decimal(amount)*10**12) for txid,height,amount in rows)
        assert actual == [(h,tx['id'],int(tx['amount'])) for h,tx in enumerate(payments,39)], (actual,output[-1600:])
        print(f'Upstream watch-only wallet scanned both receipts for {recipient["recipient"]}, payment ID {payment_id}')


if __name__ == '__main__':
    main()
