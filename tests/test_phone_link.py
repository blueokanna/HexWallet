"""End-to-end test of the phone link protocol against the real device code.

`tests/host/link_pipe.exe` runs the firmware's WalletLinkDevice with an
in-memory pairing store. This test drives it with the reference phone client
in tools/phone_link_reference.py: pairing, handshake, encrypted request,
replay rejection and tamper rejection.

Run from the repository root:

    python tests/test_phone_link.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import phone_link_reference as link  # noqa: E402

PIPE = os.path.join(ROOT, "tests", "host", "link_pipe.exe")
PHONE_SEED = bytes(range(0x40, 0x60))
PHONE_NONCE = bytes(range(0x80, 0xA0))
EPHEMERAL_SEED = bytes(range(0xC0, 0xE0))


class DeviceProcess:
    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [PIPE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        line = self.process.stdout.readline().strip()
        if not line.startswith("READY "):
            raise RuntimeError(f"device did not start: {line!r}")
        self.device_public = bytes.fromhex(line.split()[1])
        self.pending: list[str] = []

    def send(self, command: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def read_result(self) -> dict:
        """Reads until a terminal line, buffering any CODE lines."""
        assert self.process.stdout is not None
        while True:
            line = self.process.stdout.readline()
            if line == "":
                raise RuntimeError("device closed the pipe")
            line = line.strip()
            if line.startswith("CODE "):
                self.pending.append(line)
                continue
            if line.startswith("RESP "):
                return {"kind": "resp", "frame": bytes.fromhex(line.split()[1])}
            if line.startswith("STATUS "):
                return {"kind": "status", "status": line.split()[1]}
            if line.startswith("PAIR "):
                return {"kind": "pair", "value": line.split()[1]}
            if line.startswith("SESSION "):
                return {"kind": "session", "value": line}
            raise RuntimeError(f"unexpected line: {line!r}")

    def close(self) -> None:
        try:
            self.send("QUIT")
            self.process.wait(timeout=5)
        except Exception:
            self.process.kill()
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass


@unittest.skipUnless(os.path.exists(PIPE), "build tests/host/build.ps1 first")
class PhoneLinkTest(unittest.TestCase):
    def setUp(self) -> None:
        self.device = DeviceProcess()
        self.phone = link.PhoneLink(PHONE_SEED)

    def tearDown(self) -> None:
        self.device.close()

    def pair(self) -> None:
        request = self.phone.pair_request(PHONE_NONCE)
        self.device.send("FRAME " + request.hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "status")
        self.assertEqual(result["status"], "pending-pairing")
        self.assertTrue(self.device.pending, "pairing code was not shown")
        self.device.pending.clear()
        self.device.send("APPROVE")
        self.assertEqual(self.device.read_result()["value"], "ok")

        self.device.send("FRAME " + request.hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "resp", result)
        self.phone.accept_pair_response(result["frame"])
        self.assertEqual(self.phone.device_public, self.device.device_public)

    def handshake(self) -> None:
        hello = self.phone.hello_request(EPHEMERAL_SEED, PHONE_NONCE)
        self.device.send("FRAME " + hello.hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "resp", result)
        self.phone.accept_hello_response(result["frame"])
        self.assertNotEqual(self.phone.session_id, 0)
        self.device.send("SESSION")
        session = self.device.read_result()["value"]
        self.assertIn("active=1", session)
        self.assertIn(f"{self.phone.session_id:08x}", session)

    def test_pairing_requires_confirmation(self) -> None:
        request = self.phone.pair_request(PHONE_NONCE)
        self.device.send("FRAME " + request.hex())
        first = self.device.read_result()
        self.assertEqual(first["status"], "pending-pairing")
        # The same request must not produce a response until the user approves.
        self.device.send("FRAME " + request.hex())
        second = self.device.read_result()
        self.assertEqual(second["kind"], "status")
        self.assertEqual(second["status"], "pending-pairing")
        # A different phone is rejected outright.
        other = link.PhoneLink(bytes(range(0x10, 0x30)))
        self.device.send("FRAME " + other.pair_request(bytes(32)).hex())
        third = self.device.read_result()
        self.assertEqual(third["kind"], "status")
        self.assertIn(third["status"], {"rejected", "invalid-argument"})

    def test_full_session_and_secure_request(self) -> None:
        self.pair()
        self.handshake()

        payload = bytes([0x01, 0x02, 0x03, 0x04])
        response = self.phone.secure_request(payload)
        self.device.send("FRAME " + response.hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "resp", result)
        plaintext = self.phone.accept_response(result["frame"])
        self.assertEqual(plaintext, bytes(value ^ 0xA5 for value in payload))

        # A replayed frame is refused and does not produce a reply.
        self.device.send("FRAME " + response.hex())
        replay = self.device.read_result()
        self.assertEqual(replay["kind"], "status")
        self.assertEqual(replay["status"], "replay")

    def test_tampered_frame_tears_down_session(self) -> None:
        self.pair()
        self.handshake()

        frame = bytearray(self.phone.secure_request(b"\x10\x20\x30"))
        frame[link.HEADER_SIZE] ^= 0x01
        self.device.send("FRAME " + bytes(frame).hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "status")
        self.assertEqual(result["status"], "authentication-failed")
        self.device.send("SESSION")
        self.assertIn("active=0", self.device.read_result()["value"])

    def test_unsigned_hello_is_rejected(self) -> None:
        hello = bytearray(self.phone.hello_request(EPHEMERAL_SEED, PHONE_NONCE))
        hello[link.HEADER_SIZE + 96] ^= 0x01
        self.device.send("FRAME " + bytes(hello).hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "status")
        self.assertIn(result["status"], {"rejected", "authentication-failed"})

    def test_truncated_frame_is_rejected(self) -> None:
        request = self.phone.pair_request(PHONE_NONCE)
        self.device.send("FRAME " + request[:-1].hex())
        result = self.device.read_result()
        self.assertEqual(result["kind"], "status")
        self.assertEqual(result["status"], "invalid-argument")


class ProtocolVectorTest(unittest.TestCase):
    """Pins the primitives the firmware and the phone must agree on."""

    def test_chacha20_rfc8439_block(self) -> None:
        key = bytes(range(32))
        nonce = bytes.fromhex("000000090000004a00000000")
        block = link.chacha20_block(key, nonce, 1)
        self.assertEqual(
            block.hex(),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c0680304"
            "22aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129"
            "cd1de164eb9cbd083e8a2503c4e",
        )

    def test_hkdf_rfc5869_case1(self) -> None:
        ikm = b"\x0b" * 22
        salt = bytes(range(13))
        info = bytes(range(0xF0, 0xFA))
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5d"
            "b02d56ecc4c5bf34007208d5b887185865"
        )
        self.assertEqual(link.hkdf_sha256(ikm, salt, info, 42), expected)

    def test_ed25519_rfc8032_vector1(self) -> None:
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        public = link.ed25519_public_key(seed)
        self.assertEqual(
            public.hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        signature = link.ed25519_sign(seed, b"")
        self.assertEqual(
            signature.hex(),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        self.assertTrue(link.ed25519_verify(public, b"", signature))
        self.assertFalse(link.ed25519_verify(public, b"x", signature))

    def test_frames_are_canonical(self) -> None:
        frame = link.encode_frame(link.TYPE_REQUEST, 7, 9, b"abc", b"\x00" * 32)
        parsed = link.decode_frame(frame)
        self.assertEqual(parsed["session_id"], 7)
        self.assertEqual(parsed["sequence"], 9)
        self.assertEqual(parsed["payload"], b"abc")
        with self.assertRaises(ValueError):
            link.decode_frame(frame[:-1])
        with self.assertRaises(ValueError):
            link.decode_frame(b"XWLK" + frame[4:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
