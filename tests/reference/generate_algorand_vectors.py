"""Offline oracle: py-algorand-sdk==2.11.1 and PyNaCl, public test seed only."""
import base64
import hashlib
import hmac
import importlib.metadata
import json
from pathlib import Path
import sys
from algosdk import account, encoding, transaction
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
SEED = bytes(range(64))
GENESIS = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
DEST = encoding.encode_address(bytes(SigningKey(bytes(range(32))).verify_key))

def derive(index):
    node = hmac.new(b"ed25519 seed", SEED, hashlib.sha512).digest()
    for value in (44, 283, 0, 0, index):
        node = hmac.new(node[32:], b"\0"+node[:32]+(value | 0x80000000).to_bytes(4,"big"), hashlib.sha512).digest()
    key = SigningKey(node[:32])
    return base64.b64encode(node[:32]+bytes(key.verify_key)).decode()

def make(name, *, kind="pay", index=0, amount=1234567, asset=12345678, **kw):
    key = derive(index)
    sender = account.address_from_private_key(key)
    sp = transaction.SuggestedParams(kw.get("fee",1000), 40000000, kw.get("last",40001000),
                                    kw.get("genesis",GENESIS), kw.get("gen_id","mainnet-v1.0"), flat_fee=True)
    options = {k:kw[k] for k in ("note","lease","rekey_to") if k in kw}
    recipient = sender if kind == "opt-in" else DEST
    if kind == "pay":
        tx = transaction.PaymentTxn(sender,sp,recipient,amount,close_remainder_to=kw.get("close"),**options)
    else:
        tx = transaction.AssetTransferTxn(sender,sp,recipient,0 if kind == "opt-in" else amount,asset,
                                         close_assets_to=kw.get("close"),revocation_target=kw.get("clawback"),**options)
    if kw.get("group"): tx.group = bytes(range(32))
    raw = base64.b64decode(encoding.msgpack_encode(tx))
    signed = tx.sign(key)
    signature = base64.b64decode(signed.signature)
    SigningKey(base64.b64decode(key)[:32]).verify_key.verify(b"TX"+raw,signature)
    return dict(name=name,index=index,transaction=raw.hex(),signed=base64.b64decode(encoding.msgpack_encode(signed)).hex(),
                txid=tx.get_txid(),sender=sender,recipient=recipient,kind=0 if kind=="pay" else 2 if kind=="opt-in" else 1,
                amount=0 if kind=="opt-in" else amount, asset_id=0 if kind=="pay" else asset, fee=sp.fee,
                note=kw.get("note",b"").hex(),lease=kw.get("lease",b"").hex())

def main():
    assert importlib.metadata.version("py-algorand-sdk") == "2.11.1"
    cases=[make("payment"),make("one-microalgo",amount=1),make("max-amount",amount=2**64-1),
           make("asa",kind="asa",amount=12345),make("nft-unit",kind="asa",amount=1),
           make("opt-in",kind="opt-in"),make("different-key",index=7),make("no-gen-id",gen_id=None),
           make("note-and-lease",note=b"binary\0note\xff",lease=bytes(range(32))),
           make("max-note",note=bytes(range(256))*4),make("fee-cap",fee=1000000)]
    rejected=[make("testnet",genesis=base64.b64encode(bytes(32)).decode()),make("wrong-id",gen_id="testnet-v1.0"),
              make("fee-low",fee=999),make("fee-high",fee=1000001),make("too-many-rounds",last=40001001),
              make("reverse-rounds",last=39999999),make("zero-payment",amount=0),
              make("rekey",rekey_to=DEST),make("close",close=DEST),make("group",group=True),
              make("asset-close",kind="asa",close=DEST),make("clawback",kind="asa",clawback=DEST)]
    result=dict(sdk="py-algorand-sdk",version="2.11.1",seed=SEED.hex(),
                parameters="TEST ONLY: public synthetic seed and ledger rounds; no broadcast or funds",
                generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases,rejected=rejected)
    text=json.dumps(result,indent=2)+"\n"
    path=ROOT/"tests/fixtures/algorand-sdk.json"
    if "--check" in sys.argv:
        if path.read_text(encoding="utf8") != text: raise SystemExit("Algorand SDK fixture is stale")
    else: path.write_text(text,encoding="utf8",newline="\n")
if __name__ == "__main__": main()
