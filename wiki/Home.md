# HexWallet documentation

[中文](Home-zh)

HexWallet parses transactions offline and presents recipients, amounts and fees for local approval. The catalog exposes 214 entries across the supported network families. The production device session currently reports `CustodyUnavailable`. Hardware acceptance requires a provisioned SE051C2HQ1, non-exportable derivation and signing handles, a trusted boot configuration and a physical review-to-broadcast test. [Secure element](Secure-Element) · [Security model](Security-Model)

| Task | Guide |
| --- | --- |
| Select a board, check the rev A UART wiring or inspect the 296 × 128 landscape display | [Boards and display](Boards-and-Display) |
| Build an image or migrate a device with credentials | [Build and flash](Build-and-Flash) |
| Determine which operations a network can review | [Supported chains](Supported-Chains) · [Registries](Registries) · [Admission policy](Admission-Policy) |
| Implement a host integration | [Phone link](Phone-Link) · [Chain payloads](Chain-Payloads) |
| Compare an SDK result with a native-node receipt | [Validation records](validation) · [Testing](Testing) |
| Check a limitation from the four original screenshots | [Capability review](Capability-Review) |
| Review the design and assumptions | [Architecture](Architecture) · [Threat model](Threat-Model) · [Audit records](Audit-Records) |

The current validation record includes a 172-check PSBT audit, upstream Ryo/Zano verifier comparisons and three firmware-rendered review frames. Earlier records identify the native nodes, transactions and execution environments used for ledger acceptance. [Validation records](validation)
