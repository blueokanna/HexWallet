"""Run with solders==0.29.0: solana_ledger_check.py chain_probe [spl_swap.so [orca_v2.so]].

Use `solana program dump --url devnet SwapsVeCiPHMUAtzQWZw7RjsKjgCjhwU55QGu4U1Szw spl_swap.so`
and `solana program dump --url mainnet-beta 9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP orca_v2.so`.
Pass --deployed-swaps after chain_probe to read both program images from RPC.
Both modes check the same executable hashes and execute transactions locally.
"""

import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from solders.account import Account
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.token import ID as TOKEN_PROGRAM
from solders.token.state import Mint, TokenAccount, TokenAccountState
from solders.sysvar import CLOCK, RENT, STAKE_HISTORY
from solders.transaction import Transaction, VersionedTransaction
from solders.transaction_metadata import TransactionMetadata


def public_fixture_payer():
    words = ('abandon ' * 11 + 'about').encode()
    seed = hashlib.pbkdf2_hmac('sha512', words, b'mnemonic', 2048)
    node = hmac.digest(b'ed25519 seed', seed, 'sha512')
    for index in (44, 501, 0, 0, 3):
        child = b'\0' + node[:32] + (index | 0x80000000).to_bytes(4, 'big')
        node = hmac.digest(node[32:], child, 'sha512')
    return Keypair.from_seed(node[:32]).pubkey()


def deployed_program(rpc, program_data):
    payload = dict(jsonrpc='2.0', id=1, method='getAccountInfo',
                   params=[program_data, dict(encoding='base64', commitment='finalized')])
    req = Request(rpc, data=json.dumps(payload).encode(), headers={'Content-Type': 'application/json',
                                                                   'User-Agent': 'HexWallet-ledger-test/1'})
    with urlopen(req, timeout=30) as response:
        account = json.load(response)['result']['value']
    assert account['owner'] == 'BPFLoaderUpgradeab1e11111111111111111111111'
    raw = base64.b64decode(account['data'][0], validate=True)
    assert raw[:4] == struct.pack('<I', 3)  # UpgradeableLoaderState::ProgramData
    return raw[45:]


def run(probe, swap_image=None, orca_image=None):
    svm = LiteSVM().with_sigverify(True).with_blockhash_check(True)
    payer = public_fixture_payer()
    recipient, mint, source, destination = [Keypair.from_seed(bytes([i]) * 32).pubkey() for i in range(1, 5)]
    initial = 100_000_000
    assert isinstance(svm.airdrop(payer, initial), TransactionMetadata)
    receipts = []

    def execute(message, kind):
        unsigned = to_bytes_versioned(message)
        output = subprocess.check_output([probe, 'phone-review', 'sol', unsigned.hex(), 'approve'], text=True)
        signed = next(line[7:] for line in output.splitlines() if line.startswith('signed='))
        tx = VersionedTransaction.from_bytes(bytes.fromhex(signed))
        assert to_bytes_versioned(tx.message) == unsigned
        tx.verify_and_hash_message()
        result = svm.send_transaction(tx)
        assert isinstance(result, TransactionMetadata), result
        assert result.signature() == tx.signatures[0]
        assert svm.get_transaction(tx.signatures[0]).signature() == result.signature()
        receipts.append(dict(program=kind, signature=str(result.signature()), fee=result.fee()))
        return result.fee()

    amount = 2_000_000
    ix = transfer(TransferParams(from_pubkey=payer, to_pubkey=recipient, lamports=amount))
    fee = execute(Message.new_with_blockhash([ix], payer, svm.latest_blockhash()), 'System transfer (legacy)')
    assert svm.get_balance(recipient) == amount
    assert svm.get_balance(payer) == initial - amount - fee

    def install(key, state):
        data = bytes(state)
        svm.set_account(key, Account(svm.minimum_balance_for_rent_exemption(len(data)), data, TOKEN_PROGRAM))

    install(mint, Mint(None, 1, 0, True, None))
    for key, owner, balance in ((source, payer, 1), (destination, recipient, 0)):
        install(key, TokenAccount(mint, owner, balance, None, TokenAccountState.Initialized, None, 0, None))
    accounts = [AccountMeta(source, False, True), AccountMeta(mint, False, False),
                AccountMeta(destination, False, True), AccountMeta(payer, True, False)]
    checked = Instruction(TOKEN_PROGRAM, bytes([12]) + (1).to_bytes(8, 'little') + bytes([0]), accounts)
    second_fee = execute(MessageV0.try_compile(payer, [checked], [], svm.latest_blockhash()), 'SPL TransferChecked (v0)')
    assert TokenAccount.from_bytes(svm.get_account(source).data).amount == 0
    received = TokenAccount.from_bytes(svm.get_account(destination).data)
    assert (received.owner, received.mint, received.amount) == (recipient, mint, 1)
    nft_mint = Mint.from_bytes(svm.get_account(mint).data)
    assert (nft_mint.supply, nft_mint.decimals, nft_mint.mint_authority) == (1, 0, None)
    assert svm.get_balance(payer) == initial - amount - fee - second_fee

    # Initialize a local validator using the runtime's Vote program.
    node = Keypair.from_seed(bytes([8]) * 32)
    vote = Keypair.from_seed(bytes([9]) * 32).pubkey()
    vote_program = Pubkey.from_string('Vote111111111111111111111111111111111111111')
    assert isinstance(svm.airdrop(node.pubkey(), 1_000_000), TransactionMetadata)
    svm.set_account(vote, Account(svm.minimum_balance_for_rent_exemption(3762), bytes(3762), vote_program))
    vote_init = Instruction(vote_program, struct.pack('<I', 0) + bytes(node.pubkey()) * 3 + bytes([1]),
                            [AccountMeta(vote, False, True), AccountMeta(RENT, False, False),
                             AccountMeta(CLOCK, False, False), AccountMeta(node.pubkey(), True, False)])
    setup = Transaction.new_signed_with_payer([vote_init], node.pubkey(), [node], svm.latest_blockhash())
    assert isinstance(svm.send_transaction(setup), TransactionMetadata)
    stake_program = Pubkey.from_string('Stake11111111111111111111111111111111111111')
    stake_config = Pubkey.from_string('StakeConfig11111111111111111111111111111111')
    reserve = svm.minimum_balance_for_rent_exemption(200)
    delegated = 1_000_000_000
    meta = struct.pack('<Q', reserve) + bytes(payer) * 2 + bytes(48)
    state = (struct.pack('<I', 1) + meta).ljust(200, b'\0')
    for legacy in (False, True):
        stake_key = Keypair.from_seed(bytes([6 if legacy else 5]) * 32).pubkey()
        svm.set_account(stake_key, Account(reserve + delegated, state, stake_program))
        delegate_accounts = [AccountMeta(stake_key, False, True), AccountMeta(vote, False, False)]
        if legacy:
            delegate_accounts += [AccountMeta(key, False, False) for key in (CLOCK, STAKE_HISTORY, stake_config)]
        delegate_accounts.append(AccountMeta(payer, True, False))
        ix = Instruction(stake_program, struct.pack('<I', 2), delegate_accounts)
        execute(Message.new_with_blockhash([ix], payer, svm.latest_blockhash()),
                'Stake delegate (' + ('legacy accounts' if legacy else 'compact accounts') + ')')
        after_delegation = svm.get_account(stake_key).data
        assert struct.unpack_from('<I', after_delegation)[0] == 2
        assert after_delegation[124:156] == bytes(vote)
        assert struct.unpack_from('<QQQ', after_delegation, 156) == (delegated, svm.get_clock().epoch, (1 << 64) - 1)
        accounts = [AccountMeta(stake_key, False, True)]
        if legacy:
            accounts.append(AccountMeta(CLOCK, False, False))
        accounts.append(AccountMeta(payer, True, False))
        ix = Instruction(stake_program, struct.pack('<I', 5), accounts)
        execute(Message.new_with_blockhash([ix], payer, svm.latest_blockhash()),
                'Stake deactivate (' + ('legacy accounts' if legacy else 'compact accounts') + ')')
        account = svm.get_account(stake_key)
        assert account.lamports == reserve + delegated
        assert account.data[124:172] == after_delegation[124:172]
        assert struct.unpack_from('<Q', account.data, 172)[0] == svm.get_clock().epoch
    if swap_image is not None:
        program = Pubkey.from_string('SwapsVeCiPHMUAtzQWZw7RjsKjgCjhwU55QGu4U1Szw')
        assert hashlib.sha256(swap_image).hexdigest() == 'a86de91ddb85c87207bb887ebcf4e0ca2d2554d3862924a84ac634d232bc813c'
        svm.add_program(program, swap_image)
        swap = Keypair.from_seed(bytes([10]) * 32)
        authority = Pubkey.find_program_address([bytes(swap.pubkey())], program)[0]
        mint_a, mint_b, pool_mint, vault_a, vault_b, pool_fee, lp, user_a, user_b = [
            Keypair.from_seed(bytes([i]) * 32).pubkey() for i in range(11, 20)]
        for key, supply in ((mint_a, 1_001_000), (mint_b, 2_000_000)):
            install(key, Mint(None, supply, 6, True, None))
        install(pool_mint, Mint(authority, 0, 2, True, None))
        for key, token, owner, units in ((vault_a, mint_a, authority, 1_000_000), (vault_b, mint_b, authority, 2_000_000),
                (pool_fee, pool_mint, node.pubkey(), 0), (lp, pool_mint, node.pubkey(), 0),
                (user_a, mint_a, payer, 1000), (user_b, mint_b, payer, 0)):
            install(key, TokenAccount(token, owner, units, None, TokenAccountState.Initialized, None, 0, None))
        svm.set_account(swap.pubkey(), Account(svm.minimum_balance_for_rent_exemption(324), bytes(324), program))
        keys = [swap.pubkey(), authority, vault_a, vault_b, pool_mint, pool_fee, lp, TOKEN_PROGRAM]
        setup_accounts = [AccountMeta(key, i == 0, i in (0, 4, 6)) for i, key in enumerate(keys)]
        setup_ix = Instruction(program, bytes(1 + 64 + 33), setup_accounts)  # Zero fees, constant product curve.
        setup_tx = Transaction.new_signed_with_payer([setup_ix], node.pubkey(), [node, swap], svm.latest_blockhash())
        setup_result = svm.send_transaction(setup_tx)
        assert isinstance(setup_result, TransactionMetadata), setup_result
        keys = [swap.pubkey(), authority, payer, user_a, vault_a, vault_b, user_b, pool_mint, pool_fee, TOKEN_PROGRAM]
        metas = [AccountMeta(key, i == 2, 3 <= i <= 8) for i, key in enumerate(keys)]
        ix = Instruction(program, struct.pack('<BQQ', 1, 1000, 1998), metas)
        execute(Message.new_with_blockhash([ix], payer, svm.latest_blockhash()), 'SPL Token Swap (devnet program)')
        for key, units in ((user_a, 0), (vault_a, 1_001_000), (vault_b, 1_998_002), (user_b, 1998)):
            assert TokenAccount.from_bytes(svm.get_account(key).data).amount == units
    if orca_image is not None:
        orca = Pubkey.from_string('9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP')
        assert hashlib.sha256(orca_image).hexdigest() == '930a47e23fe7f8185557c1b5acabf658f97ca0f4c6cdd1f0d0510a897a9322e6'
        svm.add_program(orca, orca_image)
        snapshot = json.loads(Path(__file__).with_name('protocol-oracles').joinpath('orca-sol-usdc.json').read_text())
        pool, vault_sol, vault_usdc, pool_mint, fee_account = [Pubkey.from_string(row['address']) for row in snapshot['accounts']]
        for row in snapshot['accounts']:
            svm.set_account(Pubkey.from_string(row['address']), Account(row['lamports'], base64.b64decode(row['data']),
                                                                        Pubkey.from_string(row['owner'])))
        authority = Pubkey.find_program_address([bytes(pool)], orca)[0]
        sol = TokenAccount.from_bytes(svm.get_account(vault_sol).data)
        usdc = TokenAccount.from_bytes(svm.get_account(vault_usdc).data)
        assert sol.owner == usdc.owner == authority
        user_usdc, user_sol = [Keypair.from_seed(bytes([i]) * 32).pubkey() for i in (20, 21)]
        native_reserve = svm.minimum_balance_for_rent_exemption(165)
        units = 1_000_000  # One USDC; pool charges 25 bp trading and 5 bp owner fees.
        net = units - units * 25 // 10000 - units * 5 // 10000
        expected = sol.amount * net // (usdc.amount + net)
        install(user_usdc, TokenAccount(usdc.mint, payer, units, None, TokenAccountState.Initialized, None, 0, None))
        install(user_sol, TokenAccount(sol.mint, payer, 0, None, TokenAccountState.Initialized, native_reserve, 0, None))
        keys = [pool, authority, payer, user_usdc, vault_usdc, vault_sol, user_sol, pool_mint, fee_account, TOKEN_PROGRAM]
        metas = [AccountMeta(key, i == 2, 3 <= i <= 8) for i, key in enumerate(keys)]
        ix = Instruction(orca, struct.pack('<BQQ', 1, units, expected), metas)
        execute(Message.new_with_blockhash([ix], payer, svm.latest_blockhash()), 'Orca classic USDC to wrapped SOL (mainnet program)')
        for key, balance in ((user_usdc, 0), (vault_usdc, usdc.amount + units), (vault_sol, sol.amount - expected), (user_sol, expected)):
            assert TokenAccount.from_bytes(svm.get_account(key).data).amount == balance
        assert svm.get_balance(user_sol) == native_reserve + expected
        receipts[-1].update(inputUsdcRaw=units, outputLamports=expected, poolSnapshotSlot=snapshot['slot'])
    assert svm.get_balance(payer) == initial - amount - sum(tx['fee'] for tx in receipts)
    print(json.dumps(receipts, indent=2))


if __name__ == '__main__':
    if sys.argv[2:] == ['--deployed-swaps']:
        run(sys.argv[1],
            deployed_program('https://solana-devnet.api.onfinality.io/public', '44Kn5tKxjrBHCwkTbvtvZVSUDYRLCTNnBJja2V1pmbXE'),
            deployed_program('https://solana-rpc.publicnode.com', 'DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8'))
    else:
        run(sys.argv[1], *(Path(name).read_bytes() for name in sys.argv[2:]))
