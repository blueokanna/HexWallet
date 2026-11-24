"""Execute a reviewed transfer on a fresh private Aptos ledger using testnet chain ID 2."""

import asyncio
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

from aptos_sdk.account import Account
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import RestClient
from aptos_sdk.bcs import Deserializer
from aptos_sdk.ed25519 import PrivateKey
from aptos_sdk.transactions import SignedTransaction

from aptos_protocol_check import fixture_key, payment


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


async def check(probe, endpoint, root_key):
    client = RestClient(endpoint)
    try:
        assert await client.chain_id() == 2
        key = fixture_key()
        sender = AccountAddress.from_key(key.public_key())
        recipient = AccountAddress(bytes([0x44]) * 32)
        root = Account(AccountAddress.from_str_relaxed('0xa550c18'), root_key)
        funding = await client.bcs_transfer(root, sender, 100000000)
        await client.wait_for_transaction(funding)
        assert await client.account_balance(sender) == 100000000
        price, amount = 100, 12345678
        signed = payment(probe, key, recipient, amount, 2, 0, price, int(time.time()) + 120, max_gas=200000)
        transaction = SignedTransaction.deserialize(Deserializer(signed))
        txid = await client.submit_bcs_transaction(transaction)
        await client.wait_for_transaction(txid)
        receipt = await client.transaction_by_hash(txid)
        assert receipt['success'] and receipt['sender'] == str(sender) and receipt['hash'] == txid
        assert receipt['payload']['function'] == '0x1::aptos_account::transfer'
        assert receipt['payload']['arguments'] == [str(recipient), str(amount)]
        assert await client.account_balance(recipient) == amount
        assert await client.account_balance(sender) == 100000000 - amount - price * int(receipt['gas_used'])
        block = await client.blocks_by_version(int(receipt['version']), True)
        assert any(tx['hash'] == txid for tx in block['transactions'])
        print(f"Aptos local chain 2, version {receipt['version']}, block {block['block_height']} {block['block_hash']}, "
              f"txid {txid}, gas {receipt['gas_used']}, recipient received {amount} octas")
    finally:
        await client.close()


def run(probe, cli, framework):
    # aptos-core tag aptos-cli-v9.6.0, aptos-move/framework/cached-packages/src/head.mrb.
    assert hashlib.sha256(framework.read_bytes()).hexdigest() == '0411fed6090f3f4f3638ad542ed9f6a50a5ebd01767dc19d8c38a1cda6657bc0'
    root_key = PrivateKey.from_hex(bytes([17]) * 32, strict=False)
    with tempfile.TemporaryDirectory(prefix='aptos-wallet-') as temp:
        data = Path(temp)
        node_dir = data / '0'
        node_dir.mkdir()
        repo = data / 'genesis'
        repo.mkdir()
        def genesis(*args):
            subprocess.run([cli, 'genesis', *args], check=True, stdout=subprocess.DEVNULL)
        api, consensus, fullnode, ready = free_port(), free_port(), free_port(), free_port()
        genesis('generate-keys', '--output-dir', node_dir, '--random-seed', '22' * 32)
        genesis('generate-layout-template', '--output-file', repo / 'layout.yaml')
        layout = (repo / 'layout.yaml').read_text()
        for old, new in [('root_key: ~', f'root_key: "{root_key.public_key()}"'), ('users: []', 'users: [validator]'),
                         ('chain_id: 4', 'chain_id: 2')]:
            assert layout.count(old) == 1
            layout = layout.replace(old, new)
        (repo / 'layout.yaml').write_text(layout)
        shutil.copyfile(framework, repo / 'framework.mrb')
        genesis('set-validator-configuration', '--local-repository-dir', repo, '--username', 'validator',
                '--owner-public-identity-file', node_dir / 'public-keys.yaml', '--stake-amount', '100000000000000',
                '--validator-host', f'127.0.0.1:{consensus}', '--join-during-genesis')
        genesis('generate-genesis', '--local-repository-dir', repo, '--output-dir', node_dir)
        waypoint = {'from_file': str(node_dir / 'waypoint.txt')}
        identity = str(node_dir / 'validator-identity.yaml')
        config = {'base': {'role': 'validator', 'data_dir': str(data), 'waypoint': waypoint},
                  'execution': {'genesis_file_location': str(node_dir / 'genesis.blob')},
                  'state_sync': {'state_sync_driver': {'bootstrapping_mode': 'ExecuteTransactionsFromGenesis',
                      'enable_auto_bootstrapping': True, 'max_connection_deadline_secs': 1}},
                  'full_node_networks': [{'network_id': {'private': 'vfn'}, 'listen_address': f'/ip4/127.0.0.1/tcp/{fullnode}'}],
                  'validator_network': {'discovery_method': 'onchain', 'mutual_authentication': True,
                                        'listen_address': f'/ip4/127.0.0.1/tcp/{consensus}',
                                        'network_id': 'validator', 'identity': {'type': 'from_file', 'path': identity}},
                  'consensus': {'safety_rules': {'service': {'type': 'local'},
                      'initial_safety_rules_config': {'from_file': {'waypoint': waypoint, 'identity_blob_path': identity}}}},
                  'api': {'enabled': True, 'address': f'127.0.0.1:{api}'}}
        (node_dir / 'node.yaml').write_text(json.dumps(config))
        endpoint = f'http://127.0.0.1:{api}/v1'
        with tempfile.TemporaryFile() as log, subprocess.Popen([cli, 'node', 'run-localnet', '--test-dir', data,
                '--no-faucet', '--no-txn-stream', '--bind-to', '127.0.0.1', '--ready-server-listen-port', str(ready)],
                stdout=log, stderr=log) as process:
            try:
                deadline = time.monotonic() + 60
                while process.poll() is None and time.monotonic() < deadline:
                    try:
                        with urlopen(endpoint, timeout=2) as response:
                            if int(json.load(response)['block_height']) > 0:
                                break
                    except OSError:
                        pass
                    time.sleep(0.25)
                else:
                    log.seek(0)
                    validator_log = data / 'validator.log'
                    details = validator_log.read_text(errors='replace')[-6000:] if validator_log.exists() else ''
                    raise RuntimeError(log.read().decode(errors='replace')[-1800:] + details)
                asyncio.run(check(probe, endpoint, root_key))
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2], Path(sys.argv[3]))
