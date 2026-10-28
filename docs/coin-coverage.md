# 币种覆盖（由 `tools/coin_coverage_report.py` 生成）

数据来源：`tests/host/catalog_dump.exe (resolved catalog)`。

`SIGN` 表示代码目录声明签名能力，不等同于节点验收、全部交易类型或生产安全认证。
`TOKEN` 是已登记的 EVM/TRC-20 代币合约，前提是所属网络本身可签名。
`ADDRESS` 只能派生地址；`ABSENT` 表示这棵树里没有对应适配器。
原链清单来自本脚本的 `REQUESTED`；资产与网络组合来自 `tools/requested_asset_networks.json`。
MSR 已按用户要求移除；SOL 支持原生转账、SPL Token 与 Token-2022 TransferChecked（Token-2022 显示扩展风险警告，拒绝 ATA 创建）；TRX 支持原生 TRX 与已登记 TRC-20（仅 owner 权限、无 memo）；ATOM/OSMO/TIA 支持 Cosmos SDK 原生 MsgSend（无 IBC/memo/多消息）；ZEC 仅透明地址 v4。SIGN 不代表该链全部交易类型。
Starknet 使用 Cairo 而非 EVM，Aptos/Sui/TON/NEAR 也不是 EVM；它们需要各自独立的交易适配器，不应以 EVM profile 冒充。
XLM 已接入主网 XDR Payment/CreateAccount、SEP-0005 地址和 memo/发行者审阅；范围见 stellar-signing.md。NFT ABI 解析器不等于已准入 NFT 合约，实际缺口见 adapter-status.md。

| Ticker | 状态 | 目录条目 / 说明 |
| --- | --- | --- |
| XMR | SIGN | xmr |
| XCH | ADDRESS | xch |
| ZEC | SIGN | zec |
| DASH | SIGN | dash |
| RVN | SIGN | rvn |
| BTC | SIGN | btc, btc44, btc49 |
| BCH | SIGN | bch |
| ADA | SIGN | ada |
| AVAX | SIGN | avaxc |
| ATOM | SIGN | atom |
| CKB | SIGN | ckb |
| XEC | SIGN | xec |
| CRO | SIGN | cro |
| XAUT | TOKEN | eth:eth-xaut |
| ARB | ABSENT | no profile in this tree |
| DCR | SIGN | dcr |
| ALGO | SIGN | algo |
| ETH | SIGN | aurora, blast, eth, linea, scroll, unichain, zkevm, zksync |
| SOL | SIGN | sol |
| FLR | ABSENT | no profile in this tree |
| DOGE | SIGN | doge, dogechain |
| LTC | SIGN | ltc, ltc49, ltc84 |
| FIRO | SIGN | firo |
| FLUX | ABSENT | no profile in this tree |
| BTG | SIGN | btg, btg49, btg84 |
| AION | ABSENT | no Aion adapter |
| USDT | TOKEN | eth:eth-usdt, bsc:bsc-usdt, arb1:arb-usdt, avaxc:avaxc-usdt, opt:opt-usdt, kaia:kaia-usdt, celo:celo-usdt, trx:trx-usdt |
| USDC | SIGN | arc |
| BNB | SIGN | bsc |
| ETC | SIGN | etc |
| DOT | ADDRESS | dot |
| FIL | SIGN | fil |
| FTM | SIGN | ftm |
| KAS | SIGN | kas |
| KSM | ADDRESS | ksm |
| MNT | SIGN | mantle |
| NEAR | SIGN | near |
| POL | SIGN | matic |
| SFP | ABSENT | no EVM profile for this chain id |
| SUI | SIGN | sui |
| TON | SIGN | ton |
| TRX | SIGN | trx |
| VET | SIGN | vet |
| XLM | SIGN | xlm |
| XPL | SIGN | plasma |
| XRP | SIGN | xrp |
| LINK | ABSENT | no profile in this tree |
| DAI | TOKEN | eth:eth-dai, matic:matic-dai, bsc:bsc-dai, arb1:arb-dai |
| PYUSD | ABSENT | no profile in this tree |
| AAVE | ABSENT | no profile in this tree |
| PAXG | TOKEN | eth:eth-paxg |
| MANA | TOKEN | eth:eth-mana, matic:matic-mana |
| ASTER | ABSENT | no profile in this tree |
| ONE | SIGN | harmony |
| BSV | SIGN | bsv |
| ERG | SIGN | erg |
| DGB | SIGN | dgb, dgb49, dgb84 |
| KDA | ABSENT | no Kadena adapter |
| XTZ | SIGN | xtz |
| CFX | SIGN | cfx |
| KAIA | SIGN | kaia |
| FLOW | SIGN | flow-evm |
| BERA | SIGN | bera |
| TIA | SIGN | tia |
| OSMO | SIGN | osmo |
| AXL | ABSENT | no Cosmos SDK protobuf signer |
| ZETA | ABSENT | no Cosmos SDK protobuf signer |
| GLMR | SIGN | glmr |
| HBAR | SIGN | hbar |
| SEI | SIGN | seievm |
| IOTA | ABSENT | no IOTA adapter |
| XDC | ABSENT | no XinFin adapter |
| LUNA | ABSENT | no Terra adapter |
| LUNC | ABSENT | no Terra adapter |
| XRD | ABSENT | no Radix adapter |
| TEL | ABSENT | no Telos EVM profile registered |
| ROSE | ABSENT | no Oasis adapter |
| ZEN | ABSENT | no Horizen fork profile admitted |
| SCRT | ABSENT | no Secret Network adapter |
| DERO | ABSENT | no Dero adapter |
| TAO | ABSENT | no Bittensor adapter |
| THETA | ABSENT | no Theta adapter |
| POKT | ABSENT | no Pocket adapter |
| ICP | SIGN | icp |
| SC | SIGN | sc |
| ICX | SIGN | icx |
| QTUM | SIGN | qtum |
| HIVE | SIGN | hive |
| LSK | TOKEN | eth:eth-lsk |
| XEM | SIGN | xem |

合计：SIGN 56 / REVIEW 0 / ADDRESS 3 / TOKEN 6 / ABSENT 25（共 90 个）

目录声明签名入口：XMR, ZEC, DASH, RVN, BTC, BCH, ADA, AVAX, ATOM, CKB, XEC, CRO, DCR, ALGO, ETH, SOL, DOGE, LTC, FIRO, BTG, USDC, BNB, ETC, FIL, FTM, KAS, MNT, NEAR, POL, SUI, TON, TRX, VET, XLM, XPL, XRP, ONE, BSV, ERG, DGB, XTZ, CFX, KAIA, FLOW, BERA, TIA, OSMO, GLMR, HBAR, SEI, ICP, SC, ICX, QTUM, HIVE, XEM


## 本次要求的资产与网络组合

REGISTERED 表示已登记并连接现有签名路径；不是主网验收结果。MISSING 不可作为完整收发功能使用。
原生 ETH 不是 ERC-20；Lightning 需要独立通道状态协议，不能视为 Bitcoin 普通转账。

| 资产 | 网络 | 状态 | 对应代码条目 |
| --- | --- | --- | --- |
| USDT | X Layer | MISSING | 未完成/未核实具体资产部署 |
| USDT | Ethereum | REGISTERED | eth-usdt |
| USDT | TRON | REGISTERED | trx-usdt |
| USDT | Aptos | MISSING | 未完成/未核实具体资产部署 |
| USDT | Arbitrum One | REGISTERED | arb-usdt |
| USDT | BNB Smart Chain | REGISTERED | bsc-usdt |
| USDT | Avalanche C-Chain | REGISTERED | avaxc-usdt |
| USDT | Berachain | MISSING | 未完成/未核实具体资产部署 |
| USDT | Monad | MISSING | 未完成/未核实具体资产部署 |
| USDT | Optimism | REGISTERED | opt-usdt |
| USDT | Plasma | MISSING | 未完成/未核实具体资产部署 |
| USDT | Polygon | MISSING | 未完成/未核实具体资产部署 |
| USDT | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDT | Tempo | MISSING | 未完成/未核实具体资产部署 |
| USDT | TON | MISSING | 未完成/未核实具体资产部署 |
| USDT | Unichain | MISSING | 未完成/未核实具体资产部署 |
| USDT | OKT Chain | MISSING | 未完成/未核实具体资产部署 |
| USDC | X Layer | REGISTERED | xlayer-usdc |
| USDC | Ethereum | REGISTERED | eth-usdc |
| USDC | TRON | MISSING | 未完成/未核实具体资产部署 |
| USDC | Aptos | MISSING | 未完成/未核实具体资产部署 |
| USDC | Arbitrum One | REGISTERED | arb-usdc |
| USDC | Arc | REGISTERED | arc (native) |
| USDC | Avalanche C-Chain | REGISTERED | avaxc-usdc |
| USDC | Base | REGISTERED | base-usdc |
| USDC | Monad | REGISTERED | monad-usdc |
| USDC | Optimism | REGISTERED | opt-usdc-native |
| USDC | Polygon | REGISTERED | matic-usdc |
| USDC | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDC | Sui | MISSING | 未完成/未核实具体资产部署 |
| USDC | Unichain | REGISTERED | unichain-usdc |
| USDC | OKT Chain | MISSING | 未完成/未核实具体资产部署 |
| USDC | BNB Smart Chain | REGISTERED | bsc-usdc |
| USDC.e | Polygon | REGISTERED | matic-usdc-e |
| DAI | Ethereum | REGISTERED | eth-dai |
| DAI | Polygon | REGISTERED | matic-dai |
| DAI | Arbitrum One | REGISTERED | arb-dai |
| XAUT | Ethereum | REGISTERED | eth-xaut |
| USDG | X Layer | MISSING | 未完成/未核实具体资产部署 |
| USDG | Ethereum | MISSING | 未完成/未核实具体资产部署 |
| USDG | Solana | MISSING | 未完成/未核实具体资产部署 |
| USDG | Robinhood Chain | MISSING | 未完成/未核实具体资产部署 |
| BTC | X Layer | MISSING | 未完成/未核实具体资产部署 |
| BTC | Bitcoin | REGISTERED | btc (native) |
| BTC | Lightning | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Aptos | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Sui | MISSING | 未完成/未核实具体资产部署 |
| xBTC | Solana | MISSING | 未完成/未核实具体资产部署 |
| ETH | X Layer | MISSING | 未完成/未核实具体资产部署 |
| ETH | Ethereum | REGISTERED | eth (native) |
| ETH | Arbitrum One | REGISTERED | arb1 (native) |
| ETH | Base | REGISTERED | base (native) |
| ETH | Linea | REGISTERED | linea (native) |
| ETH | Optimism | REGISTERED | opt (native) |
| ETH | Robinhood Chain | MISSING | 未完成/未核实具体资产部署 |
| ETH | Starknet | MISSING | 未完成/未核实具体资产部署 |
| ETH | Unichain | REGISTERED | unichain (native) |
| ETH | zkSync Era | REGISTERED | zksync (native) |
| ETH | OKT Chain | MISSING | 未完成/未核实具体资产部署 |