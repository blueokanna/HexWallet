"""Independent TRON fixtures for the firmware's raw_data review/sign path.

Everything here is written from the published TRON protocol definitions and
plain Python: protobuf wire encoding, BIP32/SLIP-0010-free BIP32 derivation,
RFC 6979 deterministic ECDSA over secp256k1, and Base58Check.  The signatures
produced here are cross-checked with OpenSSL (through `cryptography`) before
they are written, so a bug in the local curve code cannot silently bless a
firmware bug.

TEST ONLY: public seed 00..3f, synthetic recipient/ref-block data.  These
vectors are not mainnet acceptance evidence and must never be used to receive
or send value.

Outputs:
  tests/fixtures/tron-vectors.json
  src/generated/TronVectorsTest.inc
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# --- secp256k1 ---------------------------------------------------------------
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def serialize_point(point):
    return bytes([0x04]) + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def rfc6979_nonce(private_key: int, digest: bytes) -> int:
    x = private_key.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(private_key: int, digest: bytes) -> bytes:
    """TRON signature: r || s || v, low-S, v = 27 + recovery id."""
    z = int.from_bytes(digest, "big") % N
    nonce = rfc6979_nonce(private_key, digest)
    point = point_mul(nonce)
    r = point[0] % N
    s = (pow(nonce, N - 2, N) * (z + r * private_key)) % N
    recovery = point[1] & 1
    if s > N // 2:
        s = N - s
        recovery ^= 1
    assert 1 <= r < N and 1 <= s < N
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recovery])


def verify_with_openssl(public_point, digest: bytes, signature: bytes) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    der = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"))
    key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), serialize_point(public_point))
    key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)  # keep import used


# --- BIP32 -------------------------------------------------------------------
def bip32_master(seed: bytes) -> tuple[int, bytes]:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(digest[:32], "big"), digest[32:]


def compressed(point) -> bytes:
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def bip32_child(key: int, chain: bytes, index: int) -> tuple[int, bytes]:
    if index >= 0x80000000:
        data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = compressed(point_mul(key)) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    return (int.from_bytes(digest[:32], "big") + key) % N, digest[32:]


def derive_path(seed: bytes, path: str) -> int:
    key, chain = bip32_master(seed)
    for part in path.split("/")[1:]:
        hardened = part.endswith("'")
        index = int(part[:-1] if hardened else part)
        key, chain = bip32_child(key, chain, index | (0x80000000 if hardened else 0))
    return key


# --- Base58Check -------------------------------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = B58[digit] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + encoded


def base58check_decode(text: str) -> bytes:
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum
    return payload


# --- protobuf ----------------------------------------------------------------
def varint(value: int) -> bytes:
    assert value >= 0
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field_bytes(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def field_varint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def any_message(type_name: str, value: bytes) -> bytes:
    return (field_bytes(1, f"type.googleapis.com/protocol.{type_name}".encode())
            + field_bytes(2, value))


def contract(contract_type: int, type_name: str, body: bytes) -> bytes:
    return field_varint(1, contract_type) + field_bytes(2, any_message(type_name, body))


def transfer_contract(owner: bytes, recipient: bytes, amount: int) -> bytes:
    return field_bytes(1, owner) + field_bytes(2, recipient) + field_varint(3, amount)


def trigger_contract(owner: bytes, token: bytes, data: bytes, call_value=0,
                     fee_limit=0) -> bytes:
    body = field_bytes(1, owner) + field_bytes(2, token)
    if call_value:
        body += field_varint(3, call_value)
    body += field_bytes(4, data)
    return body


def raw_data(contract_body: bytes, fee_limit: int = 0,
             ref_block_bytes=b"\x12\x34", ref_block_hash=bytes(range(1, 9)),
             expiration=1735689600000, timestamp=1735686000000) -> bytes:
    out = field_bytes(1, ref_block_bytes)
    out += field_bytes(4, ref_block_hash)
    out += field_varint(8, expiration)
    out += field_bytes(11, contract_body)
    out += field_varint(14, timestamp)
    if fee_limit:
        out += field_varint(18, fee_limit)
    return out


def trc20_transfer_data(recipient_evm: bytes, amount: int) -> bytes:
    assert len(recipient_evm) == 20
    return (bytes.fromhex("a9059cbb") + b"\x00" * 12 + recipient_evm
            + amount.to_bytes(32, "big"))


def erc721_safe_transfer_data(from_evm: bytes, to_evm: bytes, token_id: int) -> bytes:
    assert len(from_evm) == 20 and len(to_evm) == 20
    return (bytes.fromhex("42842e0e") + b"\x00" * 12 + from_evm
            + b"\x00" * 12 + to_evm + token_id.to_bytes(32, "big"))


def erc1155_safe_transfer_data(from_evm: bytes, to_evm: bytes, token_id: int,
                               value: int, tail: bytes = b"") -> bytes:
    assert len(from_evm) == 20 and len(to_evm) == 20
    head = (bytes.fromhex("f242432a") + b"\x00" * 12 + from_evm
            + b"\x00" * 12 + to_evm + token_id.to_bytes(32, "big")
            + value.to_bytes(32, "big") + (0xA0).to_bytes(32, "big"))
    if not tail:
        return head + (0).to_bytes(32, "big")
    # Deliberately non-canonical: the ABI length word is not zero.
    padded = tail + b"\x00" * ((32 - len(tail) % 32) % 32)
    return head + len(tail).to_bytes(32, "big") + padded


# --- cases -------------------------------------------------------------------
def main() -> int:
    seed = bytes(range(64))
    path = "m/44'/195'/0'/0/0"
    private_key = derive_path(seed, path)
    public_point = point_mul(private_key)
    public_key = serialize_point(public_point)
    from Crypto.Hash import keccak
    digest = keccak.new(digest_bits=256, data=public_key[1:]).digest()
    owner = b"\x41" + digest[-20:]
    owner_text = base58check(owner)
    recipient = b"\x41" + bytes([0x11]) * 20
    recipient_text = base58check(recipient)
    token_contract = base58check_decode("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
    assert len(token_contract) == 21 and token_contract[0] == 0x41

    cases = []
    rejected = []

    def add(name, raw, kind, amount, token=None, fee_limit=0):
        txid = hashlib.sha256(raw).digest()
        signature = sign_digest(private_key, txid)
        verify_with_openssl(public_point, txid, signature)
        cases.append(dict(
            name=name, raw=raw.hex(), txid=txid.hex(), signature=signature.hex(),
            kind=kind, amount=str(amount),
            recipient=recipient_text if kind != "native" else recipient_text,
            token=base58check(token) if token else None,
            fee_limit=str(fee_limit)))

    native_raw = raw_data(contract(1, "TransferContract",
                                   transfer_contract(owner, recipient, 1_500_000)))
    add("trx-transfer", native_raw, "native", 1_500_000)

    usdt_data = trc20_transfer_data(recipient[1:], 25_000_000)
    usdt_raw = raw_data(contract(31, "TriggerSmartContract",
                                 trigger_contract(owner, token_contract, usdt_data)),
                        fee_limit=30_000_000)
    add("trc20-usdt-transfer", usdt_raw, "trc20", 25_000_000, token_contract, 30_000_000)

    nft_contract = b"\x41" + b"\x33" * 20
    nft721_raw = raw_data(contract(31, "TriggerSmartContract",
                                   trigger_contract(owner, nft_contract,
                                                    erc721_safe_transfer_data(
                                                        owner[1:], recipient[1:], 4242))),
                          fee_limit=30_000_000)
    nft1155_raw = raw_data(contract(31, "TriggerSmartContract",
                                    trigger_contract(owner, nft_contract,
                                                     erc1155_safe_transfer_data(
                                                         owner[1:], recipient[1:], 7, 3))),
                           fee_limit=30_000_000)

    # Rejections: every mutation below must be refused before signing.
    def reject(name, raw):
        rejected.append(dict(name=name, raw=raw.hex()))

    reject("unregistered-trc721-contract", nft721_raw)
    reject("unregistered-trc1155-contract", nft1155_raw)
    for field in (3, 5, 6):
        body = trigger_contract(owner, token_contract, usdt_data)
        reject(f"duplicate-optional-field-{field}", raw_data(
            contract(31, "TriggerSmartContract", body + field_varint(field, 1)
                     + field_varint(field, 0)), fee_limit=30_000_000))
    reject("deprecated-ref-block-num", native_raw + field_varint(3, 1))

    reject("unknown-field-memo",
           raw_data(contract(1, "TransferContract",
                             transfer_contract(owner, recipient, 1_000_000))) + field_bytes(10, b"hi"))
    reject("wrong-type-url", raw_data(contract(1, "TriggerSmartContract",
                                              transfer_contract(owner, recipient, 1_000_000))))
    reject("type-url-mismatch", raw_data(contract(31, "TransferContract",
                                                  transfer_contract(owner, recipient, 1_000_000))))
    reject("zero-native-amount", raw_data(contract(1, "TransferContract",
                                                   transfer_contract(owner, recipient, 0))))
    reject("native-call-value", raw_data(contract(31, "TriggerSmartContract",
                                                  trigger_contract(owner, token_contract,
                                                                   usdt_data, call_value=1)),
                                         fee_limit=30_000_000))
    reject("unknown-token", raw_data(contract(31, "TriggerSmartContract",
                                              trigger_contract(owner, b"\x41" + b"\x22" * 20,
                                                               usdt_data)),
                                     fee_limit=30_000_000))
    reject("wrong-selector", raw_data(contract(31, "TriggerSmartContract",
                                               trigger_contract(owner, token_contract,
                                                                b"\xde\xad\xbe\xef" + usdt_data[4:])),
                                      fee_limit=30_000_000))
    reject("fee-limit-too-high", raw_data(contract(31, "TriggerSmartContract",
                                                   trigger_contract(owner, token_contract, usdt_data)),
                                          fee_limit=101_000_000))
    reject("fee-limit-zero", raw_data(contract(31, "TriggerSmartContract",
                                               trigger_contract(owner, token_contract, usdt_data))))
    foreign = b"\x41" + b"\x44" * 20
    reject("trc721-wrong-from",
           raw_data(contract(31, "TriggerSmartContract",
                             trigger_contract(owner, nft_contract,
                                              erc721_safe_transfer_data(
                                                  foreign[1:], recipient[1:], 4242))),
                    fee_limit=30_000_000))
    reject("trc721-ambiguous-transfer-from",
           raw_data(contract(31, "TriggerSmartContract",
                             trigger_contract(owner, nft_contract,
                                              b"\x23\xb8\x72\xdd" + b"\x00" * 12 + owner[1:]
                                              + b"\x00" * 12 + recipient[1:]
                                              + (4242).to_bytes(32, "big"))),
                    fee_limit=30_000_000))
    reject("trc1155-nonempty-tail",
           raw_data(contract(31, "TriggerSmartContract",
                             trigger_contract(owner, nft_contract,
                                              erc1155_safe_transfer_data(
                                                  owner[1:], recipient[1:], 7, 3, b"\x01"))),
                    fee_limit=30_000_000))
    reject("trc1155-zero-value",
           raw_data(contract(31, "TriggerSmartContract",
                             trigger_contract(owner, nft_contract,
                                              erc1155_safe_transfer_data(
                                                  owner[1:], recipient[1:], 7, 0))),
                    fee_limit=30_000_000))
    reject("trc1155-batch",
           raw_data(contract(31, "TriggerSmartContract",
                             trigger_contract(owner, nft_contract,
                                              b"\x2e\xb2\xc2\xd6" + b"\x00" * 4)),
                    fee_limit=30_000_000))
    reject("two-contracts", raw_data(contract(1, "TransferContract",
                                              transfer_contract(owner, recipient, 1_000_000))
                                     + field_bytes(11, contract(1, "TransferContract",
                                                                transfer_contract(owner, recipient, 2_000_000)))))
    reject("trailing-byte", native_raw + b"\x00")
    # Field numbers above 2^29 must not be truncated into a known field.
    reject("oversized-field-number",
           native_raw + varint((0x20000000 << 3) | 2) + varint(1) + b"\x00")
    reject("duplicate-field", native_raw + field_bytes(1, b"\x56\x78"))
    reject("permission-id", field_bytes(1, b"\x12\x34") + field_bytes(4, bytes(8))
           + field_varint(8, 1735689600000)
           + field_bytes(11, field_varint(1, 1) + field_bytes(2, any_message(
               "TransferContract", transfer_contract(owner, recipient, 1_000_000)))
               + field_varint(5, 2))
           + field_varint(14, 1735686000000))

    payload = dict(
        source="independent Python secp256k1/protobuf implementation, "
               "signatures cross-checked with OpenSSL (cryptography 50.0.2)",
        generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        parameters="TEST ONLY seed 00..3f, synthetic recipient/ref block; not node acceptance",
        seed=seed.hex(), path=path,
        private_key=f"{private_key:064x}", public_key=public_key.hex(),
        address=owner_text,
        trc20_usdt_contract=base58check(token_contract),
        cases=cases, rejected=rejected)

    fixtures = ROOT / "tests/fixtures/tron-vectors.json"
    fixtures.parent.mkdir(parents=True, exist_ok=True)
    fixtures_text = json.dumps(payload, indent=2) + "\n"

    generated = ROOT / "src/generated/TronVectorsTest.inc"
    lines = [
        "// Generated by tools/generate_tron_vectors.py; TEST ONLY.",
        "// Independent Python/OpenSSL fixtures; never used to receive or send value.",
        f'static const char kTronVectorSeedHex[] = "{seed.hex()}";',
        f'static const char kTronVectorPath[] = "{path}";',
        f'static const char kTronVectorPrivateKeyHex[] = "{private_key:064x}";',
        f'static const char kTronVectorAddress[] = "{owner_text}";',
        f'static const char kTronVectorTrc20Usdt[] = "{base58check(token_contract)}";',
        "struct TronVectorCase { const char *name; const char *raw_hex; const char *txid_hex; const char *signature_hex; };",
        "static const TronVectorCase kTronVectorCases[] = {",
    ]
    for case in cases:
        lines.append('  {"%s", "%s", "%s", "%s"},'
                     % (case["name"], case["raw"], case["txid"], case["signature"]))
    lines += ["};", "struct TronRejectedCase { const char *name; const char *raw_hex; };",
              "static const TronRejectedCase kTronRejectedCases[] = {"]
    for case in rejected:
        lines.append('  {"%s", "%s"},' % (case["name"], case["raw"]))
    lines += ["};"]
    generated_text = "\n".join(lines) + "\n"

    if "--check" in sys.argv:
        current_fixture = fixtures.read_text(encoding="utf8") if fixtures.exists() else ""
        current_generated = (generated.read_text(encoding="utf8")
                             if generated.exists() else "")
        if current_fixture != fixtures_text or current_generated != generated_text:
            print("TRON vectors are stale; rerun tools/generate_tron_vectors.py",
                  file=sys.stderr)
            return 1
        print("TRON vectors are current")
        return 0

    fixtures.write_text(fixtures_text, encoding="utf8")
    generated.write_text(generated_text, encoding="utf8")
    print(f"generated {len(cases)} accepted and {len(rejected)} rejected TRON cases")
    print(f"address {owner_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
