"""Embed one independent SDK vector for the Tezos startup known-answer test.

This script only transcodes tests/fixtures/tezos-sdk.json; it does not build
transactions or signatures. Regenerate the SDK fixture separately first.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/tezos-sdk.json"
OUTPUT = ROOT / "src/generated/TezosVectorsTest.inc"


def array(name, data):
    lines = [f"static const uint8_t {name}[] = {{"]
    for index in range(0, len(data), 16):
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in data[index:index + 16]) + ",")
    return "\n".join(lines + ["};"])


def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf8"))
    case = fixture["cases"][0]
    content = (f"// Generated from {fixture['sdk']}=={fixture['version']}; "
               "public TEST ONLY seed.\n")
    content += array("kTezosTestSeed", bytes.fromhex(fixture["seed"])) + "\n"
    content += array("kTezosTestRequest", bytes.fromhex(case["transaction"])) + "\n"
    content += array("kTezosTestSigned", bytes.fromhex(case["signed"])) + "\n"
    content += array("kTezosTestHash", bytes.fromhex(case["hash"])) + "\n"
    content += f'static const char kTezosTestSigner[] = "{case["signer"]}";\n'
    if "--check" in sys.argv:
        if OUTPUT.read_text(encoding="utf8") != content:
            raise SystemExit("TezosVectorsTest.inc is stale")
    else:
        OUTPUT.write_text(content, encoding="utf8", newline="\n")


if __name__ == "__main__":
    main()
