#!/usr/bin/env python3
"""Audit the firmware against the hardware architecture it is claimed to have.

Each row searches uncommented source for a capability-related symbol. A match
may be a declaration or test and is not proof of a working implementation.
The report provides navigation hints for manual audits, not a readiness verdict.

Usage:
    python tools/hardware_readiness.py            # markdown to stdout
    python tools/hardware_readiness.py --write    # also write docs/hardware-readiness.md
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/hardware-readiness.md"

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")

# (module, claim, regex). The regex must match real code after comment removal.
CLAIMS: list[tuple] = [
    ("SE051", "I2C presence probe at 0x48", r"beginTransmission\(\s*0x48\s*\)"),
    ("SE051", "SCP03 authenticated session", r"scp03_[a-z_]+\s*\("),
    ("SE051", "APDU exchange with the applet", r"se05[01]_[a-z_]*apdu|apdu_[a-z_]*se05[01]"),
    ("SE051", "monotonic counter read/increment", r"(se05[01]|se)_monotonic[a-z_]*\s*\("),
    ("SE051", "PIN verification performed by the element", r"se05[01]_verify_pin\s*\("),
    ("SE051", "key object import / non-exportable handle", r"se05[01]_import_key\s*\("),
    ("SE051", "state sealed by an element-held key", r"se05[01]_(seal|unseal)[a-z_]*\s*\("),

    ("XMSS", "XMSS/WOTS+ signing", r"\bqrl_[a-z0-9_]*_sign(?:_[a-z0-9]+)*\("),
    ("XMSS", "Merkle/BDS state held in RAM", r"QrlXmssState|BdsState|bds_state"),
    ("XMSS", "BDS state persisted across power loss", r"(Preferences|nvs)[a-z_]*.*(xmss|bds)|(xmss|bds)[a-z_]*.*(Preferences|nvs)"),
    ("XMSS", "anti-rollback leaf index gate (arithmetic only)", r"(leaf_index|leafIndex)[a-z_]*.*(persist|commit|nvs)|anti_?rollback|qrl_ots_index_usable\s*\("),
  ("XMSS", "signature layout pinned to upstream sizes", r"qrl_xmss_signature_size\s*\("),

    ("XMR", "address + view/spend key derivation", r"cryptonote_address_from_seed\s*\("),
    ("XMR", "on-device output scan with the view secret", r"cryptonote_scan_output\s*\("),
    ("XMR", "RCT type-6 parser", r"cryptonote_parse_transaction\s*\("),
    ("XMR", "byte-exact transaction rewrite", r"cryptonote_serialize_transaction\s*\("),
    ("XMR", "commitment balance check", r"cryptonote_transaction_balance_ok\s*\("),
    ("XMR", "CLSAG signing wired into the tx", r"cryptonote_sign_input\s*\("),
    ("XMR", "Bulletproofs+ verification", r"bulletproof[_a-z]*verify\s*\("),
    ("XMR", "host-proposed tx review with amount binding", r"cryptonote_review_transaction\s*\("),
    ("XMR", "one-time secret derived per spent output", r"cryptonote_derive_secret_key\s*\(", "CryptoNoteReview.cpp"),
    ("XMR", "view-key export command", r"view_key[a-z_]*export|export_view_key"),
    ("XMR", "spend key zeroized after signing", r"secure_zero\(\s*&?master", "WalletSigning.cpp"),

    ("Platform", "second core task pinned", r"xTaskCreatePinnedToCore\s*\("),
    ("Platform", "PSRAM allocator available", r"(ps_malloc|heap_caps_malloc)\s*\("),
    ("Platform", "decoy matrix / tx context placed in PSRAM", r"(ps_malloc|heap_caps_malloc)[^;]*(decoy|tx_context)|(decoy|tx_context)[^;]*(ps_malloc|heap_caps_malloc)"),
    ("Platform", "P4 low-power core image", r"ulp_riscv_[a-z_]+\s*\("),
    ("Platform", "blocking wait / task yield (not a watchdog guarantee)", r"vTaskDelay\s*\(|portMAX_DELAY"),
]


def strip_comments(text: str) -> str:
    # Preserve original line numbers for navigable evidence locations.
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub(lambda m: "\n" * m[0].count("\n"), text))


def main() -> int:
    corpus: list[tuple[str, str]] = []
    for path in (sorted(ROOT.glob("*.cpp")) + sorted(ROOT.glob("*.h"))
                 + sorted(ROOT.glob("*.ino"))):
        try:
            corpus.append((path.name, strip_comments(path.read_text(encoding="utf-8", errors="ignore"))))
        except OSError:
            continue

    rows: list[tuple[str, str, str]] = []
    present = 0
    for module, claim, pattern, *scope in CLAIMS:
        evidence = ""
        wanted = scope[0] if scope else ""
        for name, text in corpus:
            if wanted and wanted not in name:
                continue
            match = re.search(pattern, text)
            if match:
                line = text[: match.start()].count("\n") + 1
                evidence = f"{name}:{line}"
                break
        status = "SOURCE_MATCH" if evidence else "NOT_FOUND"
        present += 1 if evidence else 0
        rows.append((module, claim, f"{status}|{evidence or '—'}"))

    lines = [
        "# 硬件能力就绪度（由 `tools/hardware_readiness.py` 生成）",
        "",
        "本表仅搜索去除注释后的源码，提供人工审计入口，不判定硬件能力已经就绪。",
        "`SOURCE_MATCH` 可能是声明、调用或测试；不证明功能、调用链、保密性或实机行为正确。",
        "`NOT_FOUND` 表示当前搜索规则未找到匹配，不能单靠正则表达式证明功能不存在。",
        "",
        "| 模块 | 声明 | 状态 | 证据 |",
        "| --- | --- | --- | --- |",
    ]
    for module, claim, packed in rows:
        status, evidence = packed.split("|", 1)
        lines.append(f"| {module} | {claim} | {status} | {evidence} |")
    lines += [
        "",
        f"合计：SOURCE_MATCH {present} / {len(CLAIMS)}。",
        "",
        "SE051、可信显示、断电恢复和看门狗等行为仍须核对真实调用链并进行实机验收。",
    ]
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if "--write" in sys.argv:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        sys.stderr.write(f"wrote {OUT.relative_to(ROOT)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
