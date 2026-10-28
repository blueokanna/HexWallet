"""XRPL Payment review versus the independent xrpl-py binary codec."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest

try:
    from xrpl.core import binarycodec
    HAVE_XRPL = True
except ImportError:  # the fixture still lets the C++ probe run without the SDK
    binarycodec = None
    HAVE_XRPL = False

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(os.environ.get("HEXWALLET_XRP_PROBE", ROOT / "tests/host/xrp_probe.exe"))
VECTORS = json.loads((ROOT / "tests/fixtures/xrp-sdk.json").read_text(encoding="utf8"))


def probe(payload, public_key):
    assert PROBE.exists(), "Build the real C++ XRP probe first"
    result = subprocess.run([str(PROBE), payload.hex(), public_key.hex()],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode in (0, 1, 2), result.stdout + result.stderr
    return result.returncode, dict(line.split("=", 1) for line in result.stdout.splitlines())


class XrpTests(unittest.TestCase):
    def test_independent_provenance(self):
        self.assertEqual(VECTORS["sdk"], "xrpl-py")
        source = ROOT / "tools/generate_xrp_vectors.py"
        self.assertIn("xrpl", source.read_text(encoding="utf8"))
        self.assertIn("TEST ONLY", source.read_text(encoding="utf8"))

    @unittest.skipUnless(HAVE_XRPL, "xrpl-py not installed")
    def test_unsigned_and_hash_match_xrpl_py(self):
        for case in VECTORS["cases"]:
            with self.subTest(case=case["name"]):
                tx = {
                    "TransactionType": "Payment",
                    "Flags": 0x80000000,
                    "Sequence": case["sequence"],
                    "LastLedgerSequence": case["last"],
                    "Amount": case["amount"],
                    "Fee": case["fee"],
                    "SigningPubKey": case["public_key"].upper(),
                    "Account": case["source"],
                    "Destination": case["destination"],
                }
                if case["tag"] is not None:
                    tx["DestinationTag"] = case["tag"]
                encoded = bytes.fromhex(binarycodec.encode_for_signing(tx))
                unsigned = encoded[4:]
                digest = hashlib.sha512(encoded).digest()[:32]
                self.assertEqual(unsigned.hex(), case["unsigned"])
                self.assertEqual(digest.hex(), case["hash"])
                code, actual = probe(bytes.fromhex(case["payload"]),
                                     bytes.fromhex(case["public_key"]))
                self.assertEqual(code, 0, actual)
                self.assertEqual(actual["source"], case["source"])
                self.assertEqual(actual["destination"], case["destination"])
                self.assertEqual(actual["amount"], f"{int(case['amount'])/1e6:.6f} XRP")
                self.assertEqual(actual["fee"], f"{int(case['fee'])/1e6:.6f} XRP")
                self.assertEqual(actual["sequence"], str(case["sequence"]))
                self.assertEqual(actual["last"], str(case["last"]))
                self.assertEqual(actual["has_tag"], "1" if case["tag"] is not None else "0")
                if case["tag"] is not None:
                    self.assertEqual(actual["tag"], str(case["tag"]))
                self.assertEqual(actual["hash"], case["hash"])
                self.assertEqual(actual["unsigned"], case["unsigned"])

    def test_every_rejected_payload_is_refused(self):
        for case in VECTORS["rejected"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(probe(bytes.fromhex(case["payload"]),
                                       bytes.fromhex(VECTORS["public_key"]))[0], 1)


if __name__ == "__main__":
    unittest.main()
