"""Embed one independent SDK vector for the Algorand startup known-answer test.

This script only transcodes tests/fixtures/algorand-sdk.json; it does not build
transactions or signatures. Regenerate the SDK fixture separately first.
"""
import base64
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/algorand-sdk.json"
OUTPUT = ROOT / "src/generated/AlgorandVectorsTest.inc"


def array(name, data):
    lines = [f"static const uint8_t {name}[] = {{"]
    for index in range(0, len(data), 16):
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in data[index:index + 16]) + ",")
    return "\n".join(lines + ["};"])


def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf8"))
    case = fixture["cases"][0]
    txid = base64.b32decode(case["txid"] + "=" * (-len(case["txid"]) % 8))
    content = (f"// Generated from {fixture['sdk']}=={fixture['version']}; "
               "public TEST ONLY seed.\n")
    content += array("kAlgorandTestSeed", bytes.fromhex(fixture["seed"])) + "\n"
    content += array("kAlgorandTestRequest", bytes.fromhex(case["transaction"])) + "\n"
    content += array("kAlgorandTestSigned", bytes.fromhex(case["signed"])) + "\n"
    content += array("kAlgorandTestTxid", txid) + "\n"
    content += f'static const char kAlgorandTestSender[] = "{case["sender"]}";\n'
    if "--check" in sys.argv:
        if OUTPUT.read_text(encoding="utf8") != content:
            raise SystemExit("AlgorandVectorsTest.inc is stale")
    else:
        OUTPUT.write_text(content, encoding="utf8", newline="\n")


if __name__ == "__main__":
    main()
