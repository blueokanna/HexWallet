"""Firmware TOTP versus independent hashlib/hmac calculations."""
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_TOTP_PROBE",
                            ROOT / "tests/host/totp_probe.exe"))

RFC_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
RFC_SECRETS = {
    "sha1": b"12345678901234567890",
    "sha256": b"12345678901234567890123456789012",
    "sha512": (b"1234567890123456789012345678901234567890"
               b"123456789012345678901234"),
}
RFC_CODES = {
    "sha1": [94287082, 7081804, 14050471, 89005924, 69279037, 65353130],
    "sha256": [46119246, 68084774, 67062674, 91819424, 90698825, 77737706],
    "sha512": [90693936, 25091201, 99943326, 93441116, 38618901, 47863826],
}


def probe(*args):
    assert PROBE.exists(), "Build the real C++ TOTP probe first"
    result = subprocess.run([str(PROBE), *args], capture_output=True, text=True,
                            timeout=20)
    return result.returncode, result.stdout.strip()


def independent(algorithm, secret, unix_seconds, period=30, digits=8):
    counter = (unix_seconds // period).to_bytes(8, "big")
    digest = hmac.new(secret, counter, getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return binary % (10 ** digits)


class TotpTests(unittest.TestCase):
    def test_clock_runs_beyond_multiple_arduino_wraps(self):
        times = [1000, 4294967295, 4294967296, 8589934592, 31536000000]
        code, output = probe('clock', '1700000000', '1000', *map(str, times))
        self.assertEqual(code, 0, output)
        self.assertEqual(output.splitlines(),
                         [f'1:{1700000000 + (t - 1000) // 1000}' for t in times])

    def test_clock_rejects_rollback_after_successful_read(self):
        code, output = probe('clock', '1700000000', '1000', '31000', '30000', '32000')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.splitlines(), ['1:1700000030', '0:0', '0:0'])

    def test_clock_rejects_unix_overflow(self):
        code, output = probe('clock', str(2**64 - 1), '0', '1000', '2000')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.splitlines(), ['0:0', '0:0'])

    def test_rfc6238_vectors_match_independent_hmac(self):
        for algorithm in ("sha1", "sha256", "sha512"):
            secret = RFC_SECRETS[algorithm]
            for unix_seconds, expected in zip(RFC_TIMES, RFC_CODES[algorithm]):
                with self.subTest(algorithm=algorithm, time=unix_seconds):
                    self.assertEqual(independent(algorithm, secret, unix_seconds),
                                     expected)
                    code, output = probe("code", algorithm, secret.hex(),
                                         str(unix_seconds), "30", "8")
                    self.assertEqual(code, 0, output)
                    self.assertEqual(output, f"code={expected:08d}")

    def test_default_six_digit_output(self):
        secret = RFC_SECRETS["sha1"]
        code, output = probe("code", "sha1", secret.hex(), "1234567890", "30", "6")
        self.assertEqual(code, 0, output)
        self.assertEqual(output, f"code={independent('sha1', secret, 1234567890, digits=6):06d}")

    def test_base32_rfc4648(self):
        expectations = {
            "MZXW6===": "666f6f",
            "JBSWY3DPEHPK3PXP": "48656c6c6f21deadbeef",
            "jbswy3dp ehpk3pxp": "48656c6c6f21deadbeef",
        }
        for text, expected in expectations.items():
            with self.subTest(text=text):
                code, output = probe("b32", text)
                self.assertEqual(code, 0, output)
                self.assertEqual(output, expected)

    def test_base32_rejects_malformed_input(self):
        for text in ("", "JBSWY3DPEHPK3PX!", "MZXW6===" + "A", "MZXW6=",
                     "JBSWY3DPEHPK3PXP=", "MZ", "A"):
            with self.subTest(text=text):
                code, _ = probe("b32", text)
                self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
