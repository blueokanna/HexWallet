"""Embed one independent SDK envelope for the device startup known-answer test.

This script only transcodes tests/fixtures/stellar-sdk.json; it does not compute
transaction bytes or signatures. Regenerate the SDK fixture separately first.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/stellar-sdk.json"
OUTPUT = ROOT / "src/generated/StellarVectorsTest.inc"

def array(name, value):
    data = bytes.fromhex(value)
    lines = [f"static const uint8_t {name}[] = {{"]
    for i in range(0, len(data), 16):
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in data[i:i+16]) + ",")
    return "\n".join(lines + ["};"])

def main():
    fixture = json.loads(FIXTURE.read_text(encoding="utf8"))
    case = fixture["cases"][0]
    content = "// Generated from stellar-sdk==13.1.0; public TEST ONLY key.\n"
    content += array("kStellarTestRequest", case["request"]) + "\n"
    content += array("kStellarTestEnvelope", case["transaction"]) + "\n"
    if "--check" in sys.argv:
        if OUTPUT.read_text(encoding="utf8") != content: raise SystemExit("StellarVectorsTest.inc is stale")
    else:
        OUTPUT.write_text(content, encoding="utf8", newline="\n")

if __name__ == "__main__": main()
