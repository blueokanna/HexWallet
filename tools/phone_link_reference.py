"""Reference implementation of the HexWallet phone link protocol (version 1).

This is the phone side of the protocol implemented by the firmware
(WalletLink.cpp / WalletLinkCrypto.cpp). It exists so an Android application
can be written against a tested reference instead of reverse-engineering the
device. It uses only the Python standard library so it can run anywhere.

Wire format (all integers little-endian):

    frame  = "HWLK" | version(1) | type(1) | 0 | 0
             session_id(4) | sequence(4) | payload_length(2) | payload
             [ tag(32) for Request/Response ]

Message types:
    0x01 PairRequest    -> phone identity key, phone nonce, Ed25519 signature
    0x02 PairResponse   -> device identity key, phone nonce, device nonce, sig
    0x03 HelloRequest   -> phone identity key, phone ephemeral key, nonce, sig
    0x04 HelloResponse  -> device identity key, device ephemeral key, nonce, sig
    0x10 Request        -> encrypted application request
    0x11 Response       -> encrypted application reply
    0x7f Error

Signatures cover a domain string followed by the fields listed in the
protocol document (docs/phone-link-protocol.md).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

PROTOCOL_VERSION = 1
MAGIC = b"HWLK"
HEADER_SIZE = 18

TYPE_PAIR_REQUEST = 0x01
TYPE_PAIR_RESPONSE = 0x02
TYPE_HELLO_REQUEST = 0x03
TYPE_HELLO_RESPONSE = 0x04
TYPE_REQUEST = 0x10
TYPE_RESPONSE = 0x11
TYPE_ERROR = 0x7F

SECURE_TYPES = {TYPE_REQUEST, TYPE_RESPONSE}
TAG_SIZE = 32
DIRECTION_DEVICE_TO_PHONE = 1
DIRECTION_PHONE_TO_DEVICE = 2

# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032) - pure Python, extended coordinates, a = -1.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _sqrt_pow(x: int) -> int:
    return pow(x, (_P + 3) // 8, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = _sqrt_pow(x2)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = (_P - x) % _P
    return x


def _point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


_IDENTITY = (0, 1, 1, 0)


def _scalarmult(point, scalar: int):
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _encode(point) -> bytes:
    x, y, z, _ = point
    zinv = _inv(z)
    x = x * zinv % _P
    y = y * zinv % _P
    value = y | ((x & 1) << 255)
    return value.to_bytes(32, "little")


def _decode(data: bytes):
    if len(data) != 32:
        raise ValueError("point must be 32 bytes")
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        raise ValueError("invalid point")
    return (x, y, 1, x * y % _P)


_BASE_Y = 4 * _inv(5) % _P
_BASE_X = _recover_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def _clamp(h: bytes) -> int:
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")


def ed25519_public_key(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    return _encode(_scalarmult(_BASE, _clamp(h)))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = _clamp(h)
    public = _encode(_scalarmult(_BASE, a))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _L
    r_encoded = _encode(_scalarmult(_BASE, r))
    k = int.from_bytes(
        hashlib.sha512(r_encoded + public + message).digest(), "little"
    ) % _L
    s = (r + k * a) % _L
    return r_encoded + s.to_bytes(32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    try:
        a_point = _decode(public)
        r_point = _decode(signature[:32])
    except ValueError:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _L
    left = _scalarmult(_BASE, s)
    right = _point_add(r_point, _scalarmult(a_point, k))
    return hmac.compare_digest(_encode(left), _encode(right))


def ed25519_ecdh(seed: bytes, peer_public: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    shared = _scalarmult(_decode(peer_public), _clamp(h))
    encoded = _encode(shared)
    if encoded == b"\x01" + b"\x00" * 31:
        raise ValueError("degenerate shared secret")
    return encoded


# ---------------------------------------------------------------------------
# ChaCha20 (RFC 8439) and HKDF-SHA256 (RFC 5869).
# ---------------------------------------------------------------------------


def _rotl(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce))
    working = list(state)
    for _ in range(10):
        _quarter(working, 0, 4, 8, 12)
        _quarter(working, 1, 5, 9, 13)
        _quarter(working, 2, 6, 10, 14)
        _quarter(working, 3, 7, 11, 15)
        _quarter(working, 0, 5, 10, 15)
        _quarter(working, 1, 6, 11, 12)
        _quarter(working, 2, 7, 8, 13)
        _quarter(working, 3, 4, 9, 14)
    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray(len(data))
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, nonce, counter)
        chunk = data[offset : offset + 64]
        for index, value in enumerate(chunk):
            out[offset + index] = value ^ block[index]
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(out)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length > 96:
        raise ValueError("hkdf length too large")
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += previous
        counter += 1
    return output[:length]


# ---------------------------------------------------------------------------
# Link frames and session.
# ---------------------------------------------------------------------------


def _mac_key(key: bytes) -> bytes:
    return hmac.new(key, b"HexWallet Link authentication", hashlib.sha256).digest()


def _enc_key(key: bytes) -> bytes:
    return hmac.new(key, b"HexWallet Link encryption", hashlib.sha256).digest()


def _tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(
        _mac_key(key), aad + nonce + ciphertext, hashlib.sha256
    ).digest()


def seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    ciphertext = chacha20_xor(_enc_key(key), nonce, 0, plaintext)
    return ciphertext, _tag(key, nonce, aad, ciphertext)


def open_(
    key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    if not hmac.compare_digest(_tag(key, nonce, aad, ciphertext), tag):
        raise ValueError("authentication failed")
    return chacha20_xor(_enc_key(key), nonce, 0, ciphertext)


def encode_frame(
    frame_type: int,
    session_id: int,
    sequence: int,
    payload: bytes,
    tag: bytes = b"",
) -> bytes:
    header = (
        MAGIC
        + bytes([PROTOCOL_VERSION, frame_type, 0, 0])
        + struct.pack("<II", session_id, sequence)
        + struct.pack("<H", len(payload))
    )
    return header + payload + tag


def decode_frame(frame: bytes) -> dict:
    if len(frame) < HEADER_SIZE or frame[:4] != MAGIC:
        raise ValueError("bad frame")
    version, frame_type = frame[4], frame[5]
    if version != PROTOCOL_VERSION or frame[6] != 0 or frame[7] != 0:
        raise ValueError("bad frame version")
    session_id, sequence = struct.unpack("<II", frame[8:16])
    (length,) = struct.unpack("<H", frame[16:18])
    tag_size = TAG_SIZE if frame_type in SECURE_TYPES else 0
    if len(frame) != HEADER_SIZE + length + tag_size:
        raise ValueError("bad frame length")
    return {
        "type": frame_type,
        "session_id": session_id,
        "sequence": sequence,
        "payload": frame[HEADER_SIZE : HEADER_SIZE + length],
        "tag": frame[HEADER_SIZE + length :],
        "header": frame[:HEADER_SIZE],
    }


def session_nonce(session_id: int, direction: int, sequence: int) -> bytes:
    return struct.pack("<IBI", session_id, direction, sequence) + b"\x00\x00\x00"


@dataclass
class PhoneLink:
    """Phone side of the pairing + session protocol."""

    identity_seed: bytes
    identity_public: bytes = field(init=False)
    ephemeral_seed: bytes | None = None
    ephemeral_public: bytes | None = None
    nonce: bytes | None = None
    device_public: bytes | None = None
    device_ephemeral: bytes | None = None
    device_nonce: bytes | None = None
    session_id: int = 0
    key_c2d: bytes | None = None
    key_d2c: bytes | None = None
    tx_sequence: int = 0
    rx_sequence: int = 0

    def __post_init__(self) -> None:
        self.identity_public = ed25519_public_key(self.identity_seed)

    # -- pairing -----------------------------------------------------------
    def pair_request(self, nonce: bytes) -> bytes:
        self.nonce = nonce
        fields = self.identity_public + nonce
        signature = ed25519_sign(self.identity_seed, b"HWLK1-PAIR" + fields)
        return encode_frame(
            TYPE_PAIR_REQUEST, 0, 0, fields + signature
        )

    def accept_pair_response(self, frame: bytes) -> None:
        parsed = decode_frame(frame)
        if parsed["type"] != TYPE_PAIR_RESPONSE:
            raise ValueError("unexpected frame type")
        payload = parsed["payload"]
        if len(payload) != 160:
            raise ValueError("bad pair response length")
        device_public = payload[:32]
        echoed_nonce = payload[32:64]
        device_nonce = payload[64:96]
        signature = payload[96:]
        if echoed_nonce != self.nonce:
            raise ValueError("nonce mismatch")
        signed = (
            b"HWLK1-PAIR-RESP"
            + self.identity_public
            + device_public
            + self.nonce
            + device_nonce
        )
        if not ed25519_verify(device_public, signed, signature):
            raise ValueError("bad device signature")
        self.device_public = device_public
        self.device_nonce = device_nonce

    # -- handshake ---------------------------------------------------------
    def hello_request(self, ephemeral_seed: bytes, nonce: bytes) -> bytes:
        self.ephemeral_seed = ephemeral_seed
        self.ephemeral_public = ed25519_public_key(ephemeral_seed)
        fields = self.identity_public + self.ephemeral_public + nonce
        signature = ed25519_sign(self.identity_seed, b"HWLK1-HELLO" + fields)
        return encode_frame(TYPE_HELLO_REQUEST, 0, 0, fields + signature)

    def accept_hello_response(self, frame: bytes) -> None:
        parsed = decode_frame(frame)
        if parsed["type"] != TYPE_HELLO_RESPONSE:
            raise ValueError("unexpected frame type")
        payload = parsed["payload"]
        if len(payload) != 160:
            raise ValueError("bad hello response length")
        device_public = payload[:32]
        device_ephemeral = payload[32:64]
        device_nonce = payload[64:96]
        signature = payload[96:]
        if self.device_public is not None and device_public != self.device_public:
            raise ValueError("device identity changed")
        signed = (
            b"HWLK1-RESP"
            + self.identity_public
            + self.ephemeral_public
            + self.nonce
            + device_public
            + device_ephemeral
            + device_nonce
        )
        if not ed25519_verify(device_public, signed, signature):
            raise ValueError("bad device signature")

        transcript = (
            b"HWLK1-SESSION"
            + self.identity_public
            + self.ephemeral_public
            + self.nonce
            + device_public
            + device_ephemeral
            + device_nonce
        )
        transcript_hash = hashlib.sha256(transcript).digest()
        shared = ed25519_ecdh(self.ephemeral_seed, device_ephemeral)
        keys = hkdf_sha256(shared, transcript_hash, b"HWLK1-KEYS", 64)
        self.key_c2d = keys[:32]
        self.key_d2c = keys[32:]
        self.session_id = struct.unpack("<I", transcript_hash[:4])[0]
        self.device_ephemeral = device_ephemeral
        self.device_nonce = device_nonce
        self.tx_sequence = 0
        self.rx_sequence = 0

    # -- encrypted requests ------------------------------------------------
    def secure_request(self, payload: bytes) -> bytes:
        if self.key_c2d is None:
            raise ValueError("session not established")
        nonce = session_nonce(self.session_id, DIRECTION_PHONE_TO_DEVICE, self.tx_sequence)
        header = (
            MAGIC
            + bytes([PROTOCOL_VERSION, TYPE_REQUEST, 0, 0])
            + struct.pack("<II", self.session_id, self.tx_sequence)
            + struct.pack("<H", len(payload))
        )
        ciphertext, tag = seal(self.key_c2d, nonce, header, payload)
        self.tx_sequence += 1
        return header + ciphertext + tag

    def accept_response(self, frame: bytes) -> bytes:
        parsed = decode_frame(frame)
        if parsed["type"] != TYPE_RESPONSE:
            raise ValueError("unexpected frame type")
        if parsed["session_id"] != self.session_id:
            raise ValueError("wrong session")
        if parsed["sequence"] != self.rx_sequence:
            raise ValueError("unexpected sequence")
        nonce = session_nonce(
            self.session_id, DIRECTION_DEVICE_TO_PHONE, parsed["sequence"]
        )
        plaintext = open_(
            self.key_d2c,
            nonce,
            parsed["header"],
            parsed["payload"],
            parsed["tag"],
        )
        self.rx_sequence += 1
        return plaintext
