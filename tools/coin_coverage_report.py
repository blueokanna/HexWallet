#!/usr/bin/env python3
"""Evidence-based coverage report for a requested ticker list.

Sources of truth, in order:

  1. tests/host/catalog_dump.exe -- the *resolved* catalog printed by the real
     WalletCatalog code. WalletCatalog::resolved_entry() grants review/signing
     to every network that has a signing policy or is EVM, so parsing the
     source text alone under-reports what the firmware can actually do.
  2. Source text fallback (WalletCatalog.cpp + generated fork catalog) when the
     harness has not been built.

A ticker is SIGN only when the resolved mask really carries
WalletCapabilitySigning. Anything else is reported as ADDRESS / TOKEN / ABSENT,
because advertising support the firmware refuses at runtime is the one failure
mode this project must never ship.

Usage:
    python tools/coin_coverage_report.py            # markdown to stdout
    python tools/coin_coverage_report.py --write    # also write docs/coin-coverage.md
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/coin-coverage.md"

# Every ticker the project has been asked to support. This is the question, not
# the answer.
REQUESTED = """
XMR XCH ZEC DASH RVN BTC BCH ADA AVAX ATOM CKB XEC CRO XAUT ARB DCR ALGO ETH SOL
FLR DOGE LTC FIRO FLUX BTG AION USDT USDC BNB ETC DOT FIL FTM KAS KSM MNT NEAR
POL SFP SUI TON TRX VET XLM XPL XRP LINK DAI PYUSD AAVE PAXG MANA ASTER ONE BSV ERG
DGB KDA XTZ CFX KAIA FLOW BERA TIA OSMO AXL ZETA GLMR HBAR SEI IOTA XDC LUNA
LUNC XRD TEL ROSE ZEN SCRT DERO TAO THETA POKT ICP SC ICX QTUM HIVE LSK XEM
""".split()

# Tickers whose catalog symbol differs from the common exchange ticker.
ALIASES = {
    "AVAX": "AVAXC",
    "BNB": "BSC",
    "POL": "MATIC",
    "LINK": "LINK",
}

# Chains for which this tree has no transaction adapter. These are statements
# about the code, not about the chains.
MISSING_ADAPTER = {
    "XCH": "disabled: unbound signing data and variable-time BLS secret operations",
    "DOT": "SS58 address; signing disabled until authenticated runtime metadata is admitted",
    "KSM": "SS58 address; signing disabled until authenticated runtime metadata is admitted",
    "ALGO": "address primitive only; no transaction adapter",
    "XRP": "no XRPL binary codec",
    "ICP": "no IC candid adapter",
    "NEAR": "no NEAR borsh adapter",
    "SEI": "no Cosmos SDK protobuf signer",
    "AXL": "no Cosmos SDK protobuf signer",
    "ZETA": "no Cosmos SDK protobuf signer",
    "FLOW": "no Cadence adapter",
    "IOTA": "no IOTA adapter",
    "LUNA": "no Terra adapter",
    "LUNC": "no Terra adapter",
    "XRD": "no Radix adapter",
    "TEL": "no Telos EVM profile registered",
    "ROSE": "no Oasis adapter",
    "ZEN": "no Horizen fork profile admitted",
    "SCRT": "no Secret Network adapter",
    "DERO": "no Dero adapter",
    "TAO": "no Bittensor adapter",
    "THETA": "no Theta adapter",
    "POKT": "no Pocket adapter",
    "SC": "no Siacoin adapter",
    "HIVE": "no Hive adapter",
    "LSK": "no Lisk adapter",
    "XEM": "no NEM adapter",
    "ERG": "address only; no Ergo adapter",
    "KDA": "no Kadena adapter",
    "ONE": "no Harmony adapter",
    "AION": "no Aion adapter",
    "XDC": "no XinFin adapter",
    "MNT": "no EVM profile for this chain id",
    "SFP": "no EVM profile for this chain id",
    "XPL": "no EVM profile for this chain id",
    "BERA": "no EVM profile for this chain id",
    "XAUT": "token contract not registered",
}

ROW = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*[0-9]+\s*,\s*([^,]+),'
)
TOKEN_ROW = re.compile(
    r'\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,'
)

CAP_ADDRESS = "WalletCapabilityAddress"
CAP_REVIEW = "WalletCapabilityTransactionReview"
CAP_SIGN = "WalletCapabilitySigning"
CAP_TOKEN = "WalletCapabilityTokenAccount"


def load_catalog() -> tuple[list[dict], str]:
    dump = ROOT / "tests/host/catalog_dump.exe"
    rows: list[dict] = []
    if dump.exists():
        out = subprocess.run([str(dump)], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) != 5:
                continue
            entry_id, symbol, human, caps, network = parts
            caps = int(caps)
            rows.append({
                "id": entry_id, "symbol": symbol.upper(), "name": human,
                "address": bool(caps & 1), "review": bool(caps & 2),
                "sign": bool(caps & 4), "token": bool(caps & 8),
                "network": network,
            })
        return rows, "tests/host/catalog_dump.exe (resolved catalog)"

    for name in ("WalletCatalog.cpp", "src/generated/WalletForkCatalog.inc"):
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for match in ROW.finditer(text):
            entry_id, symbol, human, caps = match.groups()
            rows.append({
                "id": entry_id, "symbol": symbol.upper(), "name": human,
                "address": CAP_ADDRESS in caps, "review": CAP_REVIEW in caps,
                "sign": CAP_SIGN in caps, "token": CAP_TOKEN in caps,
                "network": entry_id,
            })
    return rows, "source text (run tests/host/build.ps1 for resolved data)"


def load_tokens() -> dict[str, str]:
    path = ROOT / "WalletTokens.cpp"
    if not path.exists():
        return {}
    tokens: dict[str, str] = {}
    for token_id, network, symbol, _name in TOKEN_ROW.findall(path.read_text(encoding="utf-8")):
        key = symbol.upper()
        entry = f"{network}:{token_id}"
        tokens[key] = tokens[key] + ", " + entry if key in tokens else entry
    return tokens


def classify(ticker: str, rows: list[dict], tokens: dict[str, str]) -> tuple[str, str]:
    lookup = ALIASES.get(ticker, ticker)
    owned = [row for row in rows if row["symbol"] == lookup]
    if any(row["sign"] for row in owned):
        ids = ", ".join(sorted({row["id"] for row in owned if row["sign"]}))
        return "SIGN", ids
    if any(row["review"] for row in owned):
        ids = ", ".join(sorted({row["id"] for row in owned if row["review"]}))
        return "REVIEW", ids
    if any(row["address"] for row in owned):
        return "ADDRESS", ", ".join(sorted({row["id"] for row in owned if row["address"]}))
    if lookup in tokens:
        return "TOKEN", tokens[lookup]
    return "ABSENT", MISSING_ADAPTER.get(ticker, "no profile in this tree")


def requested_pairs(rows: list[dict]) -> list[str]:
    requested = json.loads((ROOT / "tools/requested_asset_networks.json").read_text())
    networks = {"Ethereum":"eth", "Arbitrum One":"arb1", "BNB Smart Chain":"bsc",
                "Avalanche C-Chain":"avaxc", "Optimism":"opt", "Polygon":"matic",
                "Base":"base", "Linea":"linea", "Bitcoin":"btc",
                "Unichain":"unichain", "Monad":"monad", "Plasma":"plasma",
                "Berachain":"bera", "Arc":"arc", "TRON":"trx", "Solana":"sol",
                "X Layer":"xlayer", "zkSync Era":"zksync", "OKT Chain":"okt"}
    native_eth = {"eth", "arb1", "opt", "base", "linea", "unichain", "zksync"}
    signable = {row["network"] for row in rows if row["sign"]}
    tokens = TOKEN_ROW.findall((ROOT / "WalletTokens.cpp").read_text())
    result = ["", "## 本次要求的资产与网络组合", "",
              "REGISTERED 表示已登记并连接现有签名路径；不是主网验收结果。MISSING 不可作为完整收发功能使用。",
              "原生 ETH 不是 ERC-20；Lightning 需要独立通道状态协议，不能视为 Bitcoin 普通转账。",
              "", "| 资产 | 网络 | 状态 | 对应代码条目 |", "| --- | --- | --- | --- |"]
    for asset, chains in requested.items():
        for chain in chains:
            network = networks.get(chain)
            matches = [tid for tid, net, symbol, _ in tokens
                       if net == network and symbol.upper() == asset.upper() and net in signable]
            if network in signable and ((asset == "ETH" and network in native_eth) or
                                        (asset == "BTC" and network == "btc") or
                                        (asset == "USDC" and network == "arc")):
                matches.append(network + " (native)")
            result.append(f"| {asset} | {chain} | {'REGISTERED' if matches else 'MISSING'} | {', '.join(matches) or '未完成/未核实具体资产部署'} |")
    return result


def main() -> int:
    rows, source = load_catalog()
    tokens = load_tokens()
    counts = {"SIGN": 0, "REVIEW": 0, "ADDRESS": 0, "TOKEN": 0, "ABSENT": 0}
    lines = [
        "# 币种覆盖（由 `tools/coin_coverage_report.py` 生成）",
        "",
        f"数据来源：`{source}`。",
        "",
        "`SIGN` 表示代码目录声明签名能力，不等同于节点验收、全部交易类型或生产安全认证。",
        "`TOKEN` 是已登记的 EVM/TRC-20 代币合约，前提是所属网络本身可签名。",
        "`ADDRESS` 只能派生地址；`ABSENT` 表示这棵树里没有对应适配器。",
        "原链清单来自本脚本的 `REQUESTED`；资产与网络组合来自 `tools/requested_asset_networks.json`。",
        "MSR 已按用户要求移除；SOL 支持原生转账、SPL Token 与 Token-2022 TransferChecked（Token-2022 显示扩展风险警告，拒绝 ATA 创建）；TRX 支持原生 TRX 与已登记 TRC-20（仅 owner 权限、无 memo）；ATOM/OSMO/TIA 支持 Cosmos SDK 原生 MsgSend（无 IBC/memo/多消息）；ZEC 仅透明地址 v4。SIGN 不代表该链全部交易类型。",
        "Starknet 使用 Cairo 而非 EVM，Aptos/Sui/TON/NEAR 也不是 EVM；它们需要各自独立的交易适配器，不应以 EVM profile 冒充。",
        "XLM 已接入主网 XDR Payment/CreateAccount、SEP-0005 地址和 memo/发行者审阅；范围见 stellar-signing.md。NFT ABI 解析器不等于已准入 NFT 合约，实际缺口见 adapter-status.md。",
        "",
        "| Ticker | 状态 | 目录条目 / 说明 |",
        "| --- | --- | --- |",
    ]
    sign_rows = []
    for ticker in REQUESTED:
        status, detail = classify(ticker, rows, tokens)
        counts[status] += 1
        if status == "SIGN":
            sign_rows.append(ticker)
        lines.append(f"| {ticker} | {status} | {detail} |")
    lines += [
        "",
        f"合计：SIGN {counts['SIGN']} / REVIEW {counts['REVIEW']} / "
        f"ADDRESS {counts['ADDRESS']} / TOKEN {counts['TOKEN']} / "
        f"ABSENT {counts['ABSENT']}（共 {len(REQUESTED)} 个）",
        "",
        f"目录声明签名入口：{', '.join(sign_rows) if sign_rows else '（无）'}",
        "",
    ]
    lines += requested_pairs(rows)
    text = "\n".join(lines)
    sys.stdout.write(text)
    if "--write" in sys.argv:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        sys.stderr.write(f"wrote {OUT.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
