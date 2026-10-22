#!/usr/bin/env python3
"""Audit generated UTXO signing profiles against their upstream sources.

Address metadata alone never enables signing.  A profile is eligible only when
the upstream chainparams confirm the base58 versions and the upstream script
interpreter confirms a Bitcoin legacy sighash for P2PKH inputs.

Usage:
    python tools/verify_utxo_sighash.py           # report only
    python tools/verify_utxo_sighash.py --apply   # write evidence to registry
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "tools" / "fork_registry.json"
AUDIT = ROOT / "tools" / "utxo_sighash_audit.json"
UA = "HexWallet-consensus-audit/1.0"
FORK_MARKERS = re.compile(r"SIGHASH_FORKID|SIGHASH_FORK_ID|nForkId|forkId|fork_id")
SIGHASH = re.compile(r"\bSignatureHash\b")
PREFIX = re.compile(
    r"base58Prefixes\[(PUBKEY_ADDRESS|SCRIPT_ADDRESS)\]\s*=\s*"
    r"(?:\{\s*|std::vector<unsigned char>\(1,\s*)?(0x[0-9a-fA-F]+|\d+)"
)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def github_parts(url: str) -> tuple[str, str, str, str] | None:
    match = re.match(
        r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url.strip()
    )
    return match.groups() if match else None


def raw_url(owner: str, repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


def fetch(url: str) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": UA})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                return None
            time.sleep(1 + attempt)
    return None


def main_section(text: str) -> str:
    start = text.find("class CMainParams")
    if start < 0:
        start = text.find("CMainParams")
    if start < 0:
        return text
    end = text.find("class CTestNetParams", start)
    if end < 0:
        end = text.find("CTestNetParams", start)
    return text[start : end if end > 0 else len(text)]


def parse_prefixes(text: str) -> dict[str, int]:
    section = main_section(strip_comments(text))
    found: dict[str, int] = {}
    for name, value in PREFIX.findall(section):
        found.setdefault(name, int(value, 0))
    return found


def first_source(row: dict) -> tuple[str, str, str, str] | None:
    source = row.get("source") or ""
    return github_parts(source)


def serializer_body(code: str, name: str) -> str:
    declaration = re.search(
        r"(?:class|struct)\s+" + re.escape(name) + r"\s*(?::[^{;]+)?\{", code
    )
    if declaration is None:
        return ""
    brace = code.find("{", declaration.start())
    if brace < 0:
        return ""
    depth = 0
    for index in range(brace, len(code)):
        if code[index] == "{":
            depth += 1
        elif code[index] == "}":
            depth -= 1
            if depth == 0:
                return code[brace : index + 1]
    return code[brace:]


def audit_row(row: dict) -> dict:
    network = row["network"]
    result = {
        "network": network,
        "symbol": row.get("symbol"),
        "p2pkh": row.get("p2pkh"),
        "p2sh": row.get("p2sh"),
        "source": row.get("source"),
        "chainparams": False,
        "prefix_match": False,
        "interpreter": None,
        "legacy_active": False,
        "fork_markers": [],
        "timestamp_hint": False,
        "transaction_header": None,
        "tx_time": False,
        "tx_type_wide": False,
        "verdict": "unknown",
    }
    parts = first_source(row)
    if not parts:
        return result
    owner, repo, ref, path = parts

    chain_text = fetch(raw_url(owner, repo, ref, path))
    if chain_text is None and path != "src/chainparams.cpp":
        chain_text = fetch(raw_url(owner, repo, ref, "src/chainparams.cpp"))
    if chain_text is not None:
        result["chainparams"] = True
        prefixes = parse_prefixes(chain_text)
        result["prefixes"] = prefixes
        result["prefix_match"] = (
            prefixes.get("PUBKEY_ADDRESS") == row.get("p2pkh")
            and prefixes.get("SCRIPT_ADDRESS") == row.get("p2sh")
        )

    tx_text = fetch(raw_url(owner, repo, ref, "src/primitives/transaction.h"))
    if tx_text is not None:
        tx_code = strip_comments(tx_text)
        result["transaction_header"] = raw_url(
            owner, repo, ref, "src/primitives/transaction.h"
        )
        result["tx_time"] = bool(
            re.search(
                r"(?:READWRITE|Serialize)\s*\([^;]{0,500}\bnTime\b", tx_code, re.S
            )
        )
        result["tx_type_wide"] = bool(
            re.search(r"(?:int32_t|uint32_t)\s+nType\b", tx_code)
        )

    for candidate in (
        "src/script/interpreter.cpp",
        "src/script/interpreter.h",
        "src/interpreter.cpp",
        "src/script.cpp",
    ):
        text = fetch(raw_url(owner, repo, ref, candidate))
        if text is None:
            continue
        code = strip_comments(text)
        if not SIGHASH.search(code):
            continue
        result["interpreter"] = raw_url(owner, repo, ref, candidate)
        markers = sorted(set(FORK_MARKERS.findall(code)))
        result["fork_markers"] = markers
        marker = code.find("static const uint256 one")
        legacy = code[marker:] if marker >= 0 else code
        match = re.search(r"([A-Za-z_]\w*)\s+txTmp\s*\(", legacy)
        serializer = (
            match.group(1) if match else "CTransactionSignatureSerializer"
        )
        result["serializer"] = serializer
        result["timestamp_hint"] = "nTime" in serializer_body(code, serializer)
        result["legacy_active"] = not markers
        break

    if not result["prefix_match"] or result["interpreter"] is None:
        result["verdict"] = "unknown"
    elif result["fork_markers"]:
        result["verdict"] = "forkid"
    elif result["timestamp_hint"] or result["tx_time"]:
        result["verdict"] = "timestamp"
    elif result["tx_type_wide"]:
        result["verdict"] = "type"
    else:
        result["verdict"] = "legacy"
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    rows = [row for row in data["profiles"] if row.get("signing")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(audit_row, rows))

    AUDIT.write_text(
        json.dumps({"generated_by": "tools/verify_utxo_sighash.py", "rows": results},
                   indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    counts: dict[str, int] = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        print(
            f"{result['network']:28} {result['verdict']:8} "
            f"prefix={'ok' if result['prefix_match'] else 'no':2} "
            f"fork={','.join(result['fork_markers']) or '-':20} "
            f"{result['interpreter'] or result['source']}"
        )
    print("summary:", counts)

    if not args.apply:
        return 0

    by_network = {result["network"]: result for result in results}
    for row in data["profiles"]:
        result = by_network.get(row["network"])
        if result is None:
            continue
        row["sighash"] = result["verdict"]
        row["sighash_source"] = result["interpreter"]
        row["source_verified"] = bool(result["prefix_match"])
        if result["verdict"] != "legacy":
            row["signing"] = False
    REGISTRY.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print("registry updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
