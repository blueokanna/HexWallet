"""Execute firmware-signed SPL transactions in solders' independent LiteSVM.

This is local VM execution, NOT RPC/node acceptance or physical-device testing.
Test accounts are explicitly injected; signature and blockhash checks stay ON.
Dependencies: solders==0.28.0 (Windows LiteSVM wheels start at 0.28).
Message instructions come from the independent 0.26.0/solana-py fixtures.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import struct
from solders.account import Account
from solders.litesvm import LiteSVM
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction
from solders.transaction_metadata import FailedTransactionMetadata

ROOT = Path(__file__).resolve().parents[2]
assert importlib.metadata.version("solders") == "0.28.0"
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
fixtures = json.loads((ROOT / "tests/fixtures/spl-sdk.json").read_text())
case = fixtures["cases"][1]
output = case["transfers"][0]
reference_message = Message.from_bytes(bytes.fromhex(case["message"]))
payer = reference_message.account_keys[0]
source, mint, dest = (Pubkey(bytes.fromhex(output[name])) for name in ("source", "mint", "recipient"))
recipient_owner = Pubkey(bytes([77])*32)
probe = Path(os.environ.get("HEXWALLET_SOLANA_PROBE", ROOT / "tests/host/solana_probe.exe"))
assert probe.exists(), "Build the C++ firmware harness first"
zero = bytes(32)
initial = 500000000


def account_data(token_mint, owner, amount, frozen=False):
    # Canonical 165-byte classic Token Account state, not firmware parser data.
    return struct.pack("<32s32sQI32sBIQQI32s", bytes(token_mint), bytes(owner), amount,
                       0, zero, 2 if frozen else 1, 0, 0, 0, 0, zero)


results = []
for name, v0 in [("legacy-valid", False), ("v0-valid", True),
                 ("wrong-mint-decimals", False), ("wrong-source-owner", False),
                 ("destination-mint-mismatch", False), ("frozen-source", False),
                 ("frozen-destination", False), ("insufficient-balance", False),
                 ("corrupted-signature", False)]:
    svm = LiteSVM().with_sigverify(True).with_blockhash_check(True)
    assert not isinstance(svm.airdrop(payer, 1000000000), FailedTransactionMetadata)
    program = svm.get_account(TOKEN_PROGRAM_ID)
    assert program is not None and program.executable
    token_program_sha256 = hashlib.sha256(bytes(program.data)).hexdigest()
    mint_data = struct.pack("<I32sQBBI32s", 0, zero, initial,
                           9 if name == "wrong-mint-decimals" else 6, 1, 0, zero)
    for key, data in [
        (mint, mint_data),
        (source, account_data(mint, recipient_owner if name == "wrong-source-owner" else payer,
                             1 if name == "insufficient-balance" else initial, name == "frozen-source")),
        (dest, account_data(source if name == "destination-mint-mismatch" else mint,
                           recipient_owner, 0, name == "frozen-destination")),
    ]:
        svm.set_account(key, Account(svm.minimum_balance_for_rent_exemption(len(data)), data, TOKEN_PROGRAM_ID))
    header = reference_message.header
    msg = (MessageV0(header, reference_message.account_keys, svm.latest_blockhash(),
                    reference_message.instructions, []) if v0 else
           Message.new_with_compiled_instructions(header.num_required_signatures,
               header.num_readonly_signed_accounts, header.num_readonly_unsigned_accounts,
               reference_message.account_keys, svm.latest_blockhash(), reference_message.instructions))
    signed = subprocess.run([str(probe), to_bytes_versioned(msg).hex(), fixtures["seed"]],
        capture_output=True, text=True, check=True, timeout=30)
    parsed = dict(line.split("=", 1) for line in signed.stdout.splitlines())
    wire = bytearray.fromhex(parsed["transaction"])
    if name == "corrupted-signature": wire[1] ^= 1
    tx = VersionedTransaction.from_bytes(bytes(wire))
    before_source = bytes(svm.get_account(source).data)
    before_dest = bytes(svm.get_account(dest).data)
    payer_before = svm.get_balance(payer)
    result = svm.send_transaction(tx)
    succeeded = not isinstance(result, FailedTransactionMetadata)
    assert succeeded == name.endswith("-valid"), (name, result)
    if succeeded:
        source_after = struct.unpack_from("<Q", svm.get_account(source).data, 64)[0]
        dest_after = struct.unpack_from("<Q", svm.get_account(dest).data, 64)[0]
        assert source_after == initial-output["amount"] and dest_after == output["amount"]
        assert payer_before-svm.get_balance(payer) == int(parsed["fee"]) == 5000
    else:
        assert bytes(svm.get_account(source).data) == before_source
        assert bytes(svm.get_account(dest).data) == before_dest
    results.append(dict(name=name, accepted=succeeded, message=to_bytes_versioned(msg).hex(),
                        transaction=bytes(wire).hex(), result=str(result)))

record = dict(source="solders 0.28.0 bundled LiteSVM; solana-py 0.36.6/solders 0.26.0 input fixture", test_only=True,
    scope="Injected local account state; actual firmware signatures; signature/blockhash checks enabled. Not node or board acceptance.",
    token_program_sha256=token_program_sha256,
    verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), results=results)
target = ROOT / "build/spl-svm-execution.json"
target.parent.mkdir(exist_ok=True)
target.write_text(json.dumps(record, indent=2)+"\n", encoding="utf8")
print(f"PASS: {len(results)} independent LiteSVM execution cases; {target}")
