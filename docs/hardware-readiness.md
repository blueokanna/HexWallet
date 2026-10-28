# 硬件能力就绪度（由 `tools/hardware_readiness.py` 生成）

本表仅搜索去除注释后的源码，提供人工审计入口，不判定硬件能力已经就绪。
`SOURCE_MATCH` 可能是声明、调用或测试；不证明功能、调用链、保密性或实机行为正确。
`NOT_FOUND` 表示当前搜索规则未找到匹配，不能单靠正则表达式证明功能不存在。

| 模块 | 声明 | 状态 | 证据 |
| --- | --- | --- | --- |
| SE051 | I2C presence probe at 0x48 | SOURCE_MATCH | WalletBoardPort.cpp:618 |
| SE051 | SCP03 authenticated session | NOT_FOUND | — |
| SE051 | APDU exchange with the applet | NOT_FOUND | — |
| SE051 | monotonic counter read/increment | NOT_FOUND | — |
| SE051 | PIN verification performed by the element | NOT_FOUND | — |
| SE051 | key object import / non-exportable handle | NOT_FOUND | — |
| SE051 | state sealed by an element-held key | NOT_FOUND | — |
| XMSS | XMSS/WOTS+ signing | NOT_FOUND | — |
| XMSS | Merkle/BDS state held in RAM | NOT_FOUND | — |
| XMSS | BDS state persisted across power loss | NOT_FOUND | — |
| XMSS | anti-rollback leaf index gate (arithmetic only) | SOURCE_MATCH | QrlXmss.cpp:420 |
| XMSS | signature layout pinned to upstream sizes | SOURCE_MATCH | QrlXmss.cpp:410 |
| XMR | address + view/spend key derivation | SOURCE_MATCH | CryptoNoteAddress.cpp:481 |
| XMR | on-device output scan with the view secret | SOURCE_MATCH | CryptoNoteOutputScan.cpp:10 |
| XMR | RCT type-6 parser | SOURCE_MATCH | CryptoNoteBulletproofPlus.cpp:674 |
| XMR | byte-exact transaction rewrite | SOURCE_MATCH | CryptoNoteSigning.cpp:621 |
| XMR | commitment balance check | SOURCE_MATCH | CryptoNoteReview.cpp:342 |
| XMR | CLSAG signing wired into the tx | SOURCE_MATCH | CryptoNoteSigning.cpp:610 |
| XMR | Bulletproofs+ verification | SOURCE_MATCH | CryptoNoteBulletproofPlus.cpp:276 |
| XMR | host-proposed tx review with amount binding | SOURCE_MATCH | CryptoNoteReview.cpp:540 |
| XMR | one-time secret derived per spent output | SOURCE_MATCH | CryptoNoteReview.cpp:467 |
| XMR | view-key export command | NOT_FOUND | — |
| XMR | spend key zeroized after signing | SOURCE_MATCH | WalletSigning.cpp:1061 |
| Platform | second core task pinned | SOURCE_MATCH | WalletWorker.cpp:140 |
| Platform | PSRAM allocator available | SOURCE_MATCH | WalletBoardPort.cpp:45 |
| Platform | decoy matrix / tx context placed in PSRAM | NOT_FOUND | — |
| Platform | P4 low-power core image | NOT_FOUND | — |
| Platform | blocking wait / task yield (not a watchdog guarantee) | SOURCE_MATCH | WalletWorker.cpp:90 |

合计：SOURCE_MATCH 16 / 28。

SE051、可信显示、断电恢复和看门狗等行为仍须核对真实调用链并进行实机验收。
