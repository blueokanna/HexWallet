"""Independent classic SPL fixtures; public TEST ONLY seed, no wallet imports.

Pin solana-py for instruction encoding and solders for message compilation,
ATA derivation and Ed25519 signing. Synthetic blockhash is NOT node evidence.
Run on the development PC, never on firmware.
"""
import hashlib
import hmac
import importlib.metadata
import json
from pathlib import Path
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction, AccountMeta
from solders.keypair import Keypair
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import transfer_checked, TransferCheckedParams, get_associated_token_address

ROOT = Path(__file__).resolve().parents[2]
assert importlib.metadata.version("solana") == "0.36.6"
assert importlib.metadata.version("solders") == "0.26.0"
seed = bytes(range(64))
digest = hmac.digest(b"ed25519 seed", seed, "sha512")
for index in [44, 501, 0, 0, 0]:
    digest = hmac.digest(digest[32:], b"\0" + digest[:32] + (index | 0x80000000).to_bytes(4, "big"), "sha512")
payer = Keypair.from_seed(digest[:32])
owner = Keypair.from_seed(bytes([71])*32).pubkey()
mint = Keypair.from_seed(bytes([72])*32).pubkey()
mint2 = Keypair.from_seed(bytes([73])*32).pubkey()
blockhash = Hash(bytes([42])*32)


def token_instruction(token_mint=mint, amount=123456789, decimals=6):
    return transfer_checked(TransferCheckedParams(
        program_id=TOKEN_PROGRAM_ID,
        source=get_associated_token_address(payer.pubkey(), token_mint),
        mint=token_mint, dest=get_associated_token_address(owner, token_mint),
        owner=payer.pubkey(), amount=amount, decimals=decimals))


def compile_message(instructions, v0=False):
    return (MessageV0.try_compile(payer.pubkey(), instructions, [], blockhash) if v0 else
            Message.new_with_blockhash(instructions, payer.pubkey(), blockhash))


def formatted(amount, decimals):
    if decimals > 19:
        return f"{amount} x 10^-{decimals} token"
    if decimals == 0:
        return f"{amount} token"
    return f"{amount // 10**decimals}.{amount % 10**decimals:0{decimals}d} token"


cases = []
def add_case(name, instructions, v0=False):
    msg = compile_message(instructions, v0)
    tx = VersionedTransaction(msg, [payer])
    tx.verify_and_hash_message()
    assert len(bytes(tx)) <= 1232
    transfers = []
    for ix in instructions:
        if ix.program_id == TOKEN_PROGRAM_ID:
            amount, decimals = int.from_bytes(ix.data[1:9], "little"), ix.data[9]
            transfers.append(dict(source=bytes(ix.accounts[0].pubkey).hex(),
                                  mint=bytes(ix.accounts[1].pubkey).hex(),
                                  recipient=bytes(ix.accounts[2].pubkey).hex(),
                                  amount=amount, decimals=decimals, kind=1,
                                  formatted=formatted(amount, decimals)))
        elif ix.program_id == Pubkey.default():
            amount = int.from_bytes(ix.data[4:], "little")
            transfers.append(dict(source=bytes(payer.pubkey()).hex(), mint="00"*32,
                                  recipient=bytes(ix.accounts[1].pubkey).hex(),
                                  amount=amount, decimals=9, kind=0,
                                  formatted=f"{amount // 10**9}.{amount % 10**9:09d} SOL"))
    cases.append(dict(name=name, message=to_bytes_versioned(msg).hex(),
                      transaction=bytes(tx).hex(), transfers=transfers))


for v0 in [False, True]:
    for decimals in [0, 6, 9, 18, 19, 20, 255]:
        add_case(f"{'v0' if v0 else 'legacy'}-decimals-{decimals}",
                 [token_instruction(amount=2**64-1 if decimals >= 19 else 123456789, decimals=decimals)], v0)
add_case("two-mints-and-sol-priority", [set_compute_unit_limit(200000), set_compute_unit_price(1001),
    token_instruction(), token_instruction(mint2, 9000000000, 9),
    transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=owner, lamports=1000000))], True)
add_case("sixteen-token-transfers", [token_instruction(amount=i+1) for i in range(16)])

base = token_instruction()
rejected = []
def reject(name, instructions):
    rejected.append(dict(name=name, message=to_bytes_versioned(compile_message(instructions)).hex()))

# Token-2022 TransferChecked is covered by tools/generate_spl2022_vectors.py;
# this classic fixture no longer asserts that the programme id is rejected.
reject("unchecked-transfer", [Instruction(TOKEN_PROGRAM_ID, b"\x03"+base.data[1:9],
    [base.accounts[i] for i in (0, 2, 3)])])
for opcode in [4, 5, 6, 7, 8, 9, 13, 14, 15, 255]:
    reject(f"unsupported-opcode-{opcode}", [Instruction(TOKEN_PROGRAM_ID, bytes([opcode])+base.data[1:], base.accounts)])
reject("zero-amount", [token_instruction(amount=0)])
reject("same-mint-conflicting-decimals", [base, token_instruction(decimals=9)])
reject("token-account-conflicting-mint", [base, Instruction(TOKEN_PROGRAM_ID, base.data,
    [base.accounts[0], AccountMeta(mint2, False, False), *base.accounts[2:]])])
reject("seventeen-transfers", [token_instruction(amount=i+1) for i in range(17)])
for name, index, meta in [
    ("readonly-source", 0, AccountMeta(base.accounts[0].pubkey, False, False)),
    ("readonly-destination", 2, AccountMeta(base.accounts[2].pubkey, False, False)),
    ("writable-mint", 1, AccountMeta(mint, False, True)),
    ("wrong-authority", 3, AccountMeta(owner, False, False)),
    ("self-transfer", 2, base.accounts[0]),
    ("payer-as-source", 0, AccountMeta(payer.pubkey(), True, True)),
    ("payer-as-destination", 2, AccountMeta(payer.pubkey(), True, True)),
]:
    accounts = list(base.accounts); accounts[index] = meta
    reject(name, [Instruction(TOKEN_PROGRAM_ID, base.data, accounts)])
reject("extra-account", [Instruction(TOKEN_PROGRAM_ID, base.data,
    [*base.accounts, AccountMeta(owner, False, False)])])
reject("extra-data", [Instruction(TOKEN_PROGRAM_ID, base.data+b"\0", base.accounts)])
reject("compute-budget-after-transfer", [base, set_compute_unit_limit(200000), set_compute_unit_price(1)])

payload = dict(source="solana-py 0.36.6 + solders 0.26.0",
    source_urls=["https://github.com/michaelhly/solana-py/tree/v0.36.6",
                 "https://github.com/kevinheavey/solders/tree/0.26.0"],
    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    parameters="TEST ONLY public seed 00..3f, synthetic mints/accounts and blockhash 2a*32; not node acceptance",
    seed=seed.hex(), derivation_path="m/44'/501'/0'/0'/0'",
    program=bytes(TOKEN_PROGRAM_ID).hex(), cases=cases, rejected=rejected)
target = ROOT / "tests/fixtures/spl-sdk.json"
target.write_text(json.dumps(payload, indent=2)+"\n", encoding="utf8")
print(f"generated {len(cases)} accepted and {len(rejected)} rejected SPL cases")
