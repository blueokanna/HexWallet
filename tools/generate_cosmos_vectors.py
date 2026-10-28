"""Independent Cosmos SDK MsgSend fixtures (ATOM / OSMO / TIA).

The protobuf writer, BIP32 derivation, bech32 encoding and RFC 6979 ECDSA are
implemented here from the public specifications, not taken from the firmware.
Every signature is verified with OpenSSL before it is written out.

TEST ONLY: public seed 00..3f, synthetic account/sequence. Not node evidence.

Outputs:
  tests/fixtures/cosmos-vectors.json
  src/generated/CosmosVectorsTest.inc
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


def compressed(point) -> bytes:
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


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
    """Cosmos signature: 64-byte r || s, low-S."""
    z = int.from_bytes(digest, "big") % N
    nonce = rfc6979_nonce(private_key, digest)
    point = point_mul(nonce)
    r = point[0] % N
    s = (pow(nonce, N - 2, N) * (z + r * private_key)) % N
    if s > N // 2:
        s = N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_with_openssl(public_point, digest: bytes, signature: bytes) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    der = utils.encode_dss_signature(
        int.from_bytes(signature[:32], "big"),
        int.from_bytes(signature[32:], "big"))
    key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), compressed(public_point))
    key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


# --- BIP32 -------------------------------------------------------------------
def bip32_master(seed: bytes):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return int.from_bytes(digest[:32], "big"), digest[32:]


def bip32_child(key: int, chain: bytes, index: int):
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


# --- bech32 (BIP-173, BECH32 checksum) ---------------------------------------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for index in range(5):
            chk ^= generators[index] if ((top >> index) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    result = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            result.append((acc >> bits) & maxv)
    if pad and bits:
        result.append((acc << (tobits - bits)) & maxv)
    return result


def bech32_encode(hrp: str, payload: bytes) -> str:
    data = convertbits(payload, 8, 5)
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def address(hrp: str, pubkey: bytes) -> str:
    return bech32_encode(hrp, hash160(pubkey))


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


def field_string(number: int, value: str) -> bytes:
    return field_bytes(number, value.encode())


def field_varint(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


# --- cases -------------------------------------------------------------------
CHAINS = {
    "atom": dict(hrp="cosmos", prefix="cosmoshub-", denom="uatom", symbol="ATOM"),
    "osmo": dict(hrp="osmo", prefix="osmosis-", denom="uosmo", symbol="OSMO"),
    "tia": dict(hrp="celestia", prefix="celestia", denom="utia", symbol="TIA"),
}

seed = bytes(range(64))
path = "m/44'/118'/0'/0/0"
private_key = derive_path(seed, path)
public_point = point_mul(private_key)
public_key = compressed(public_point)
addresses = {network: address(chain["hrp"], public_key)
             for network, chain in CHAINS.items()}
# A distinct synthetic recipient; reusing the wallet's own address would make
# every accepted case a self-transfer.
recipient_key = int.from_bytes(bytes([0x47]) * 32, "big")
recipient_public = compressed(point_mul(recipient_key))
recipient_addresses = {network: address(chain["hrp"], recipient_public)
                       for network, chain in CHAINS.items()}


def build_payload(network, chain_id, account, sequence, amount, fee, gas,
                  to_address, memo=b"", version=1):
    out = bytearray([version])
    out += bytes([len(chain_id)]) + chain_id.encode()
    for value in (account, sequence, amount, fee, gas):
        out += value.to_bytes(8, "big")
    out += bytes([len(to_address)]) + to_address.encode()
    out += bytes([len(memo)]) + memo
    return bytes(out)


def build_transaction(network, chain_id, account, sequence, amount, fee, gas,
                      to_address):
    chain = CHAINS[network]
    from_address = addresses[network]
    denom = chain["denom"]
    coin = field_string(1, denom) + field_string(2, str(amount))
    msg_send = (field_string(1, from_address) + field_string(2, to_address)
                + field_bytes(3, coin))
    any_message = (field_string(1, "/cosmos.bank.v1beta1.MsgSend")
                   + field_bytes(2, msg_send))
    body = field_bytes(1, any_message)

    pubkey_message = field_bytes(1, public_key)
    pubkey_any = (field_string(1, "/cosmos.crypto.secp256k1.PubKey")
                  + field_bytes(2, pubkey_message))
    mode_info = field_bytes(1, field_varint(1, 1))  # SIGN_MODE_DIRECT
    signer_info = (field_bytes(1, pubkey_any) + field_bytes(2, mode_info)
                   + field_varint(3, sequence))
    fee_coin = field_string(1, denom) + field_string(2, str(fee))
    fee_message = field_bytes(1, fee_coin) + field_varint(2, gas)
    auth_info = field_bytes(1, signer_info) + field_bytes(2, fee_message)

    sign_doc = (field_bytes(1, body) + field_bytes(2, auth_info)
                + field_string(3, chain_id) + field_varint(4, account))
    digest = hashlib.sha256(sign_doc).digest()
    signature = sign_digest(private_key, digest)
    verify_with_openssl(public_point, digest, signature)
    tx_raw = (field_bytes(1, body) + field_bytes(2, auth_info)
              + field_bytes(3, signature))
    return dict(body=body.hex(), auth_info=auth_info.hex(),
                digest=digest.hex(), signature=signature.hex(),
                tx_raw=tx_raw.hex())


def display(amount: int) -> str:
    return f"{amount // 10**6}.{amount % 10**6:06d}"


cases = []
rejected = []


def add(name, network, chain_id, account, sequence, amount, fee, gas,
        to_network=None, memo=b""):
    recipient_network = to_network or network
    to_address = recipient_addresses[recipient_network]
    payload = build_payload(network, chain_id, account, sequence, amount, fee,
                            gas, to_address, memo)
    expected = build_transaction(network, chain_id, account, sequence, amount,
                                 fee, gas, to_address)
    cases.append(dict(
        name=name, network=network, payload=payload.hex(),
        from_address=addresses[network], to_address=to_address,
        chain_id=chain_id, account=str(account), sequence=str(sequence),
        amount=str(amount), fee=str(fee), gas=str(gas),
        amount_text=f"{display(amount)} {CHAINS[network]['symbol']}",
        fee_text=f"{display(fee)} {CHAINS[network]['symbol']}",
        **expected))


add("atom-msg-send", "atom", "cosmoshub-4", 12345, 7, 1_500_000, 5000, 200000)
add("osmo-msg-send", "osmo", "osmosis-1", 0, 0, 250_000_000, 2500, 150000)
add("tia-msg-send", "tia", "celestia", 42, 1, 100_000_000, 4000, 120000)


def reject(name, payload):
    rejected.append(dict(name=name, network="atom", payload=payload.hex()))


base_to = recipient_addresses["atom"]
reject("version-2", build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000,
                                  base_to, version=2))
reject("wrong-chain-prefix",
       build_payload("atom", "osmosis-1", 1, 1, 1, 1, 100000, base_to))
reject("wrong-hrp",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000,
                     recipient_addresses["osmo"]))
bad_checksum = base_to[:-1] + ("q" if base_to[-1] != "q" else "p")
reject("bad-checksum",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000, bad_checksum))
reject("uppercase-address",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000, base_to.upper()))
reject("self-transfer",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000, addresses["atom"]))
reject("zero-amount", build_payload("atom", "cosmoshub-4", 1, 1, 0, 1, 100000,
                                    base_to))
reject("fee-too-high",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 10_000_001, 100000, base_to))
reject("gas-zero", build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 0, base_to))
reject("gas-too-high",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 2_000_001, base_to))
reject("memo-present",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000, base_to, memo=b"x"))
reject("trailing-byte",
       build_payload("atom", "cosmoshub-4", 1, 1, 1, 1, 100000, base_to) + b"\x00")

payload = dict(
    source="independent Python protobuf/bech32/BIP32/RFC 6979 implementation; "
           "signatures cross-checked with OpenSSL (cryptography)",
    generator_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    parameters="TEST ONLY seed 00..3f, synthetic account/sequence; not node acceptance",
    seed=seed.hex(), path=path,
    private_key=f"{private_key:064x}", public_key=public_key.hex(),
    addresses=addresses,
    cases=cases, rejected=rejected)

fixtures = ROOT / "tests/fixtures/cosmos-vectors.json"
fixtures.parent.mkdir(parents=True, exist_ok=True)
fixtures_text = json.dumps(payload, indent=2) + "\n"

lines = [
    "// Generated by tools/generate_cosmos_vectors.py; TEST ONLY.",
    "// Independent Python/OpenSSL fixtures; never used to receive or send value.",
    f'static const char kCosmosVectorPrivateKeyHex[] = "{private_key:064x}";',
    f'static const char kCosmosVectorPublicKeyHex[] = "{public_key.hex()}";',
    "struct CosmosVectorCase { const char *name; const char *network; const char *payload_hex;",
    "  const char *from_address; const char *to_address; const char *chain_id;",
    "  const char *account; const char *sequence; const char *amount; const char *fee;",
    "  const char *gas; const char *amount_text; const char *fee_text;",
    "  const char *body_hex; const char *auth_info_hex;",
    "  const char *digest_hex; const char *signature_hex; const char *tx_raw_hex; };",
    "static const CosmosVectorCase kCosmosVectorCases[] = {",
]
for case in cases:
    lines.append(
        '  {"%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", '
        '"%s", "%s", "%s", "%s", "%s", "%s", "%s"},'
        % (case["name"], case["network"], case["payload"], case["from_address"],
           case["to_address"], case["chain_id"], case["account"], case["sequence"],
           case["amount"], case["fee"], case["gas"], case["amount_text"],
           case["fee_text"], case["body"], case["auth_info"],
           case["digest"], case["signature"], case["tx_raw"]))
lines += ["};", "struct CosmosRejectedCase { const char *name; const char *network; const char *payload_hex; };",
          "static const CosmosRejectedCase kCosmosRejectedCases[] = {"]
for case in rejected:
    lines.append('  {"%s", "atom", "%s"},' % (case["name"], case["payload"]))
lines += ["};"]
generated_text = "\n".join(lines) + "\n"
generated = ROOT / "src/generated/CosmosVectorsTest.inc"

if "--check" in sys.argv:
    current_fixture = fixtures.read_text(encoding="utf8") if fixtures.exists() else ""
    current_generated = generated.read_text(encoding="utf8") if generated.exists() else ""
    if current_fixture != fixtures_text or current_generated != generated_text:
        print("Cosmos vectors are stale; rerun tools/generate_cosmos_vectors.py",
              file=sys.stderr)
        raise SystemExit(1)
    print("Cosmos vectors are current")
    raise SystemExit(0)

fixtures.write_text(fixtures_text, encoding="utf8")
generated.write_text(generated_text, encoding="utf8")
print(f"generated {len(cases)} accepted and {len(rejected)} rejected Cosmos cases")
for network, value in addresses.items():
    print(f"{network}: {value}")
