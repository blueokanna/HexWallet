"""Independent, offline Stellar SDK oracle. Public test keys; never use for funds.

Install stellar-sdk==13.1.0 in a desktop-only environment to regenerate.
No wallet source is imported and no RPC or Horizon requests are made.
"""
import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

import stellar_sdk
from mnemonic import Mnemonic
from stellar_sdk import Account, Asset, Keypair, MuxedAccount, Network, TransactionBuilder

ROOT = Path(__file__).resolve().parents[2]
PHRASE = "illness spike retreat truth genius clock brain pass fit cave bargain toe"
SEED = Mnemonic.to_seed(PHRASE)
DEST = Keypair.from_raw_ed25519_seed(bytes(range(32))).public_key
ISSUER = Keypair.from_raw_ed25519_seed(bytes(range(1, 33))).public_key

def make(name, *, index=0, memo=None, operations=None, **options):
    key = Keypair.from_mnemonic_phrase(PHRASE, index=index)
    network = options.get("network", Network.PUBLIC_NETWORK_PASSPHRASE)
    builder = TransactionBuilder(Account(key.public_key, 123456789), network, base_fee=options.get("fee", 100))
    if not options.get("no_time"):
        builder.add_time_bounds(1700000000, options.get("max_time", 1800000000))
    if options.get("v2"): builder.set_min_sequence_age(1)
    if memo:
        getattr(builder, "add_" + memo[0] + "_memo")(memo[1])
    ops = operations or [("payment", "XLM", "12.3456789")]
    expected = []
    for kind, code, amount in ops:
        if kind == "create": builder.append_create_account_op(DEST, amount)
        elif kind == "manage": builder.append_manage_data_op("test", b"data")
        else:
            asset = Asset.native() if code == "XLM" else Asset(code, ISSUER)
            dest = MuxedAccount(DEST, 42) if options.get("muxed") else DEST
            source = ISSUER if options.get("foreign_source") else key.public_key if options.get("source") else None
            builder.append_payment_op(dest, asset, amount, source=source)
        raw_amount = int(Decimal(amount)*10000000)
        expected.append(dict(destination=DEST, issuer="" if code == "XLM" else ISSUER,
                             asset=code, amount=raw_amount,
                             formatted=f"{raw_amount//10000000}.{raw_amount%10000000:07d} {code}",
                             type=0 if kind == "create" else 1))
    tx = builder.build()
    request = hashlib.sha256(network.encode()).digest() + tx.to_xdr_object().to_xdr_bytes()
    tx_hash = tx.hash()
    tx.sign(key)
    key.verify(tx_hash, tx.signatures[0].signature)
    memo_type = 0 if not memo else dict(text=1, id=2, hash=3, return_hash=4)[memo[0]]
    memo_text = "NONE" if not memo else memo[1].hex() if isinstance(memo[1], bytes) else str(memo[1])
    return dict(name=name, index=index, source=key.public_key, request=request.hex(),
                fee=tx.transaction.fee, memo_type=memo_type, memo=memo_text,
                hash=tx_hash.hex(), transaction=tx.to_xdr_object().to_xdr_bytes().hex(), operations=expected)

def main():
    assert stellar_sdk.__version__ == "13.1.0"
    cases = [make("native"), make("text", memo=("text", "exchange 42")),
             make("id", memo=("id", 2**64-1)), make("hash", memo=("hash", bytes(range(32)))),
             make("return", memo=("return_hash", bytes(range(32)))),
             make("issued", operations=[("payment", "USD", "0.0000001")]),
             make("long-asset", operations=[("payment", "ABCDEFGHIJKL", "922337203685.4775807")]),
             make("create", operations=[("create", "XLM", "2")]),
             make("multi", index=1, source=True, operations=[("create", "XLM", "2"), ("payment", "USD", "1.2")]),
             make("max-ops", operations=[("payment", "XLM", "1")]*8),
             make("text-max", memo=("text", "A"*28)), make("fee-cap", fee=10000000)]
    rejected = [make("testnet", network=Network.TESTNET_NETWORK_PASSPHRASE),
                make("unbounded", max_time=0), make("no-time", no_time=True),
                make("fee-excess", fee=10000001), make("fee-low", fee=99),
                make("control-memo", memo=("text", "a\nb")), make("nul-memo", memo=("text", "a\0b")),
                make("unicode-memo", memo=("text", "\u202eXLM")),
                make("too-many", operations=[("payment", "XLM", "1")]*9),
                make("manage-data", operations=[("manage", "XLM", "1")]),
                make("foreign-source", foreign_source=True), make("muxed-destination", muxed=True),
                make("preconditions-v2", v2=True)]
    document = dict(sdk="stellar-sdk", version=stellar_sdk.__version__,
                    parameters="TEST ONLY: SEP-0005 public mnemonic; synthetic ledger state, no broadcast",
                    generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    seed=SEED.hex(), cases=cases, rejected=rejected)
    path = ROOT/"tests/fixtures/stellar-sdk.json"
    content = json.dumps(document, indent=2)+"\n"
    if "--check" in sys.argv:
        if path.read_text(encoding="utf8") != content: raise SystemExit("Stellar SDK fixture is stale")
        print("Stellar SDK fixture matches independent regeneration")
    else:
        path.write_text(content, encoding="utf8")

if __name__ == "__main__": main()
