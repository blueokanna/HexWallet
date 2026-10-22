#!/usr/bin/env python3
"""Compare MiningPoolStats' active coin list with the wallet catalog."""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
URL = "https://data.miningpoolstats.stream/data/coins_data.js"
TYPES = ("ASIC", "GPU", "CPU", "HDD")


def fetch_coins() -> list[dict]:
    # Cloudflare rejects Python's TLS fingerprint; curl is the supported path.
    # The data URL carries the cache token published by the home page.
    command = [
        "curl", "-L", "--max-time", "60", "-sS",
        "-H", "Referer: https://miningpoolstats.stream/",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    ]
    home = subprocess.run(command + ["https://miningpoolstats.stream/"],
                          capture_output=True, check=True).stdout
    token = re.search(rb"coins_data\.js\?t=(\d+)", home)
    data_url = f"{URL}?t={token.group(1).decode()}" if token else URL
    text = subprocess.run(command + [data_url], capture_output=True,
                          check=True).stdout.decode("utf-8")
    return json.loads(text[text.index("{"):])["data"]


def mining_rows() -> list[tuple[str, str, str, str, str]]:
    text = (ROOT / "src/generated/WalletMiningCatalog.inc").read_text(encoding="utf-8")
    rows: list[tuple[str, str, str, str, str]] = []
    for match in re.finditer(
            r'\{"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*MiningCoinType::(\w+),\s*'
            r'"([^"]+)"\},', text):
        rows.append((match.group(1), match.group(2), match.group(3),
                     match.group(4), match.group(5)))
    return rows


def main() -> int:
    try:
        coins = fetch_coins()
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"ERR miningpool-fetch: {error}", file=sys.stderr)
        return 1
    rows = mining_rows()
    live = [coin for coin in coins if coin.get("typ") in TYPES]
    supported = {(row[0].upper(), row[2].lower(), row[3].upper()) for row in rows}
    active = {
        ((coin.get("symbol") or "").upper(), (coin.get("algo") or "").lower(),
         coin["typ"].upper())
        for coin in live if coin.get("symbol") and coin.get("algo")
    }
    covered = supported & active
    print(f"MiningPoolStats active listings: {len(active)}")
    print(f"firmware supported rows: {len(supported)}")
    print(f"matched active listings: {len(covered)}")
    for kind in TYPES:
        total = sum(1 for item in active if item[2] == kind)
        hit = sum(1 for item in covered if item[2] == kind)
        print(f"{kind:4} {hit:3}/{total:3} active listings supported")
    missing = sorted(active - covered)
    if missing:
        print(f"not supported ({len(missing)}):")
        for symbol, algorithm, kind in missing[:100]:
            print(f"  {kind:4} {symbol:10} {algorithm}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
