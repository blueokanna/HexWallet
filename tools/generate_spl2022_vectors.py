"""Independent Token-2022 fixtures for the Solana review/sign path.

Only solders is used: message compilation and Ed25519 signing come from the
pinned SDK build in build/spl-svm-reference (0.28.0), so expected bytes are not
produced by the firmware under test. Associated token accounts are derived with
`solders.pubkey.Pubkey.find_program_address`, not with wallet code.

TEST ONLY: public seed 00..3f, synthetic mints/accounts, synthetic blockhash.
Outputs tests/fixtures/spl-2022-sdk.json.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build" / "spl-svm-reference"))

from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price  # noqa: E402
from solders.hash import Hash  # noqa: E402
from solders.instruction import AccountMeta, Instruction  # noqa: E402
from solders.keypair import Keypair  # noqa: E402
from solders.message import Message, MessageV0, to_bytes_versioned  # noqa: E402
from solders.pubkey import Pubkey  # noqa: E402
from solders.system_program import TransferParams, transfer  # noqa: E402
from solders.transaction import VersionedTransaction  # noqa: E402

TOKEN_PROGRAM = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN_2022_PROGRAM = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
ATA_PROGRAM = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")


def slip10_seed() -> bytes:
    seed = bytes(range(64))
    digest = hmac.digest(b"ed25519 seed", seed, "sha512")
    for index in [44, 501, 0, 0, 0]:
        digest = hmac.digest(digest[32:], b"\0" + digest[:32]
                             + (index | 0x80000000).to_bytes(4, "big"), "sha512")
    return digest[:32]


payer = Keypair.from_seed(slip10_seed())
owner = Keypair.from_seed(bytes([71]) * 32).pubkey()
classic_mint = Keypair.from_seed(bytes([72]) * 32).pubkey()
mint_2022 = Keypair.from_seed(bytes([73]) * 32).pubkey()
mint_2022_zero = Keypair.from_seed(bytes([74]) * 32).pubkey()
blockhash = Hash(bytes([42]) * 32)


def ata(wallet: Pubkey, mint: Pubkey, program: Pubkey) -> Pubkey:
    return Pubkey.find_program_address(
        [bytes(wallet), bytes(program), bytes(mint)], ATA_PROGRAM)[0]


def token_instruction(program, mint, amount, decimals, source=None, dest=None,
                      authority=None):
    source = source or ata(payer.pubkey(), mint, program)
    dest = dest or ata(owner, mint, program)
    data = bytes([12]) + amount.to_bytes(8, "little") + bytes([decimals])
    return Instruction(program, data, [
        AccountMeta(source, False, True),
        AccountMeta(mint, False, False),
        AccountMeta(dest, False, True),
        AccountMeta(authority or payer.pubkey(), True, False),
    ])


def compile_message(instructions, v0=False):
    return (MessageV0.try_compile(payer.pubkey(), instructions, [], blockhash) if v0
            else Message.new_with_blockhash(instructions, payer.pubkey(), blockhash))


def formatted(amount, decimals):
    if decimals > 19:
        return f"{amount} x 10^-{decimals} token"
    if decimals == 0:
        return f"{amount} token"
    return f"{amount // 10**decimals}.{amount % 10**decimals:0{decimals}d} token"


cases = []
rejected = []


def add_case(name, instructions, v0=False):
    message = compile_message(instructions, v0)
    transaction = VersionedTransaction(message, [payer])
    transaction.verify_and_hash_message()
    assert len(bytes(transaction)) <= 1232
    transfers = []
    unit_limit = micro_price = 0
    for instruction in instructions:
        if instruction.program_id == Pubkey.from_string(
                "ComputeBudget111111111111111111111111111111"):
            if instruction.data[0] == 2:
                unit_limit = int.from_bytes(instruction.data[1:5], "little")
            elif instruction.data[0] == 3:
                micro_price = int.from_bytes(instruction.data[1:9], "little")
        if instruction.program_id in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
            amount = int.from_bytes(instruction.data[1:9], "little")
            decimals = instruction.data[9]
            transfers.append(dict(
                source=bytes(instruction.accounts[0].pubkey).hex(),
                mint=bytes(instruction.accounts[1].pubkey).hex(),
                recipient=bytes(instruction.accounts[2].pubkey).hex(),
                amount=amount, decimals=decimals,
                kind=1 if instruction.program_id == TOKEN_PROGRAM else 2,
                formatted=formatted(amount, decimals)))
        elif instruction.program_id == Pubkey.default():
            amount = int.from_bytes(instruction.data[4:], "little")
            transfers.append(dict(
                source=bytes(payer.pubkey()).hex(), mint="00" * 32,
                recipient=bytes(instruction.accounts[1].pubkey).hex(),
                amount=amount, decimals=9, kind=0,
                formatted=f"{amount // 10**9}.{amount % 10**9:09d} SOL"))
    priority = (unit_limit * micro_price + 999999) // 1000000 if micro_price else 0
    cases.append(dict(name=name, message=to_bytes_versioned(message).hex(),
                      transaction=bytes(transaction).hex(), transfers=transfers,
                      fee=5000 + priority))


def reject(name, instructions, v0=False):
    rejected.append(dict(name=name,
                         message=to_bytes_versioned(compile_message(instructions, v0)).hex()))


add_case("t22-legacy-decimals-6",
         [token_instruction(TOKEN_2022_PROGRAM, mint_2022, 123456789, 6)])
add_case("t22-v0-decimals-6-priority",
         [set_compute_unit_limit(200000), set_compute_unit_price(1001),
          token_instruction(TOKEN_2022_PROGRAM, mint_2022, 2500000000, 6)], True)
add_case("t22-decimals-0",
         [token_instruction(TOKEN_2022_PROGRAM, mint_2022_zero, 42, 0)])
add_case("t22-decimals-18",
         [token_instruction(TOKEN_2022_PROGRAM, mint_2022, 10**18, 18)])
add_case("t22-mixed-with-classic-and-sol", [
    set_compute_unit_limit(300000), set_compute_unit_price(2),
    token_instruction(TOKEN_PROGRAM, classic_mint, 5000000, 6),
    token_instruction(TOKEN_2022_PROGRAM, mint_2022, 7000000000, 9),
    transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=owner,
                            lamports=1000000))], True)

base = token_instruction(TOKEN_2022_PROGRAM, mint_2022, 1000000, 6)
# Unchecked Transfer (opcode 3) omits decimals and is refused for both programs.
reject("t22-unchecked-transfer",
       [Instruction(TOKEN_2022_PROGRAM, b"\x03" + base.data[1:9],
                    [base.accounts[i] for i in (0, 2, 3)])])
# TransferCheckedWithFee (opcode 26) would hide a fee the review cannot verify.
reject("t22-transfer-checked-with-fee",
       [Instruction(TOKEN_2022_PROGRAM,
                    bytes([26]) + base.data[1:9] + b"\x00" * 8 + bytes([6]),
                    base.accounts)])
# A transfer hook needs extra accounts; refuse instead of blind-signing them.
reject("t22-hook-extra-account",
       [Instruction(TOKEN_2022_PROGRAM, base.data,
                    [*base.accounts, AccountMeta(owner, False, False)])])
reject("t22-readonly-source", [Instruction(TOKEN_2022_PROGRAM, base.data, [
    AccountMeta(base.accounts[0].pubkey, False, False), *base.accounts[1:]])])
reject("t22-zero-amount",
       [token_instruction(TOKEN_2022_PROGRAM, mint_2022, 0, 6)])
reject("t22-conflicting-decimals", [
    token_instruction(TOKEN_2022_PROGRAM, mint_2022, 1, 6),
    token_instruction(TOKEN_2022_PROGRAM, mint_2022, 2, 9)])
reject("t22-payer-as-source",
       [token_instruction(TOKEN_2022_PROGRAM, mint_2022, 1, 6,
                          source=payer.pubkey())])

payload = dict(
    source="solders 0.28.0 (build/spl-svm-reference)",
    source_urls=["https://github.com/kevinheavey/solders/tree/0.28.0"],
    generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    parameters="TEST ONLY seed 00..3f, synthetic mints/accounts and blockhash 2a*32; not node acceptance",
    seed=bytes(range(64)).hex(),
    derivation_path="m/44'/501'/0'/0'/0'",
    programs={"classic": bytes(TOKEN_PROGRAM).hex(),
              "token2022": bytes(TOKEN_2022_PROGRAM).hex()},
    cases=cases, rejected=rejected)

target = ROOT / "tests/fixtures/spl-2022-sdk.json"
text = json.dumps(payload, indent=2) + "\n"
if "--check" in sys.argv:
    current = target.read_text(encoding="utf8") if target.exists() else ""
    if current != text:
        print("Token-2022 vectors are stale; rerun tools/generate_spl2022_vectors.py",
              file=sys.stderr)
        raise SystemExit(1)
    print("Token-2022 vectors are current")
    raise SystemExit(0)

target.write_text(text, encoding="utf8")
print(f"generated {len(cases)} accepted and {len(rejected)} rejected Token-2022 cases")
