#!/usr/bin/env python3
"""Build a reviewable UTXO candidate registry from MiningPoolStats and chainparams."""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from miningpool_coverage import fetch_coins

OUT = ROOT / "tools" / "utxo_candidates.json"
SLIP44 = ROOT / "slip-0044.md"
PATHS = ("src/chainparams.cpp", "src/kernel/chainparams.cpp")


def curl(url: str) -> bytes:
    try:
        return subprocess.run(
            ["curl", "-L", "--max-time", "30", "-sS",
             "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
             url],
            capture_output=True, check=True).stdout
    except subprocess.CalledProcessError:
        return b""


def supported_rows() -> set[tuple[str, str, str]]:
    text = (ROOT / "src/generated/WalletMiningCatalog.inc").read_text(encoding="utf-8")
    return {
        (match.group(1).upper(), match.group(3).lower(), match.group(4).upper())
        for match in re.finditer(
            r'\{"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*MiningCoinType::(\w+),', text)
    }


def slip44_map() -> tuple[dict[str, int], dict[str, int]]:
    by_symbol: dict[str, list[int]] = {}
    by_name: dict[str, list[int]] = {}
    text = SLIP44.read_text(encoding="utf-8")
    for match in re.finditer(r'^\|\s*(\d+)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|$',
                             text, re.M):
        number = int(match.group(1))
        symbol = match.group(2).strip().upper()
        name = match.group(3).strip().lower()
        if symbol:
            by_symbol.setdefault(symbol, []).append(number)
        if name:
            by_name.setdefault(name, []).append(number)
    return ({key: values[0] for key, values in by_symbol.items() if len(values) == 1},
            {key: values[0] for key, values in by_name.items() if len(values) == 1})


def normalize_name(value: str) -> str:
    name = value.strip().lower()
    for suffix in (" native segwit", " nested segwit", " legacy"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def parse_number(group: str | None) -> int | None:
    if group is None:
        return None
    return int(group, 0)


def parse_chainparams(text: str) -> dict | None:
    main = re.search(r'strNetworkID\s*=\s*(?:"main"|CBaseChainParams::MAIN)', text)
    if main is None:
        return None
    next_id = re.search(r'strNetworkID\s*=', text[main.end():])
    section = text[main.start():main.end() + next_id.start()] if next_id else text[main.start():]

    def vector(name: str) -> int | None:
        match = re.search(
            rf'base58Prefixes\[{name}\]\s*=\s*(?:std::vector<(?:unsigned char|uint8_t)>'
            rf'\(1,\s*(0x[0-9a-fA-F]+|\d+)\)|\{{([^}}]+)\}})', section)
        if match is None:
            return None
        if match.group(1):
            return parse_number(match.group(1))
        values = [parse_number(value.strip()) for value in match.group(2).split(",")]
        if len(values) != 1:
            return None
        return values[0]

    p2pkh = vector("PUBKEY_ADDRESS")
    p2sh = vector("SCRIPT_ADDRESS")
    if p2pkh is None or p2sh is None or p2pkh > 0xFF or p2sh > 0xFF:
        return None
    if re.search(r'cashaddrPrefix|SIGHASH_FORKID|nForkId|consensus\.nForkId|'
                 r'Overwinter|ZIP243', section + text):
        return None
    hrp_match = re.search(r'bech32_hrp\s*=\s*"([^"]+)"', section)
    hrp = hrp_match.group(1) if hrp_match else None
    return {"p2pkh": p2pkh, "p2sh": p2sh, "bech32": hrp,
            "sighash": "bitcoin"}


def github_repo(page: str) -> str | None:
    html = curl(f"https://miningpoolstats.stream/{page}").decode("utf-8", "replace")
    match = re.search(r'href="https://github\.com/([^"/]+)/([^"/]+)"', html)
    return f"{match.group(1)}/{match.group(2)}" if match else None


def main() -> int:
    coins = [coin for coin in fetch_coins() if coin.get("typ") in ("ASIC", "GPU", "CPU", "HDD")]
    supported = supported_rows()
    by_listing = {
        ((coin.get("symbol") or "").upper(), (coin.get("algo") or "").lower(),
         coin["typ"].upper()): coin
        for coin in coins
    }
    by_symbol, by_name = slip44_map()
    rows = []
    seen = set()
    limit = int(os.environ.get("UTXO_LIMIT", "0"))
    for key, coin in by_listing.items():
        if key in supported:
            continue
        if limit and len(seen) >= limit:
            break
        symbol = (coin.get("symbol") or "").upper()
        name = coin.get("name") or ""
        algorithm = coin.get("algo") or ""
        kind = coin["typ"]
        dedupe = (symbol, name.lower())
        if dedupe in seen:
            continue
        seen.add(dedupe)
        slip44 = by_symbol.get(symbol.upper()) or by_name.get(normalize_name(name))
        if slip44 is None:
            continue
        page = coin.get("page")
        if not page:
            continue
        repo = github_repo(page)
        if repo is None:
            continue
        parsed = None
        source = None
        for path in PATHS:
            raw = curl(f"https://raw.githubusercontent.com/{repo}/HEAD/{path}")
            if raw.startswith(b"404") or len(raw) < 1000:
                continue
            parsed = parse_chainparams(raw.decode("utf-8", "replace"))
            if parsed is not None:
                source = f"https://github.com/{repo}/blob/HEAD/{path}"
                break
        if parsed is None:
            continue
        rows.append({
            "network": "utxo_" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-"),
            "symbol": symbol.upper(),
            "name": name,
            "algorithm": algorithm,
            "mining_type": kind,
            "slip44": slip44,
            "p2pkh": parsed["p2pkh"],
            "p2sh": parsed["p2sh"],
            "bech32": parsed["bech32"],
            "sighash": parsed["sighash"],
            "source": source,
        })
    OUT.write_text(json.dumps({"source": "MiningPoolStats + official chainparams",
                               "candidates": rows}, indent=1) + "\n",
                   encoding="utf-8")
    print(f"candidates={len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
