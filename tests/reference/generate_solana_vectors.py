"""Generate public TEST ONLY fixtures using solders 0.26.0, never wallet code.

PC-only development dependency; normal CI consumes the checked-in JSON.
The resulting blockhash is synthetic: these are SDK regression vectors, not
evidence that a node accepted or executed a transaction.
"""
import hashlib
import hmac
import json
from pathlib import Path
import solders
from solders.keypair import Keypair
from solders.hash import Hash
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.transaction import VersionedTransaction
from solders.system_program import transfer, TransferParams
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price

assert solders.__version__ == "0.26.0", solders.__version__
ROOT = Path(__file__).resolve().parents[2]
seed = bytes(range(64))
path = [0x8000002c, 0x800001f5, 0x80000000, 0x80000000, 0x80000000]
digest = hmac.digest(b"ed25519 seed", seed, "sha512")
for index in path:
    digest = hmac.digest(digest[32:], b"\0" + digest[:32] + index.to_bytes(4, "big"), "sha512")
payer = Keypair.from_seed(digest[:32])
blockhash = Hash(bytes([42]) * 32)
cases = []
for name, count, version, price in [
    ("legacy-transfer", 1, False, None),
    ("legacy-priority", 2, False, 1001),
    ("v0-transfer", 1, True, None),
    ("v0-priority", 2, True, 1001),
    ("legacy-16-transfers", 16, False, None),
    ("v0-zero-priority", 1, True, 0),
]:
    outputs = [(Keypair.from_seed(bytes([10+i])*32).pubkey(), 123456789+i) for i in range(count)]
    instructions = [] if price is None else [set_compute_unit_limit(200000), set_compute_unit_price(price)]
    instructions += [transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=key, lamports=amount))
                     for key, amount in outputs]
    msg = MessageV0.try_compile(payer.pubkey(), instructions, [], blockhash) if version else \
        Message.new_with_blockhash(instructions, payer.pubkey(), blockhash)
    tx = VersionedTransaction(msg, [payer])
    tx.verify_and_hash_message()
    cases.append(dict(name=name, message=to_bytes_versioned(msg).hex(), transaction=bytes(tx).hex(),
                      payer=bytes(payer.pubkey()).hex(), payer_address=str(payer.pubkey()),
                      priority_fee=0 if price is None else (price*200000+999999)//1000000,
                      transfers=[dict(recipient=bytes(key).hex(), address=str(key), lamports=amount)
                                 for key, amount in outputs]))
payload = dict(source="solders", version=solders.__version__,
               source_url="https://github.com/kevinheavey/solders/tree/0.26.0",
               generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               parameters="TEST ONLY public BIP39 seed bytes 00..3f; synthetic blockhash 2a*32; no chain acceptance claimed",
               seed=seed.hex(), derivation_path="m/44'/501'/0'/0'/0'", cases=cases)
target = ROOT / "tests/fixtures/solana-sdk.json"
target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf8")
print(f"generated {len(cases)} independent SDK vectors: {target}")
