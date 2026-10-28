# EVM 网络与代币证据表

本文件记录 `WalletNetworks.cpp` / `WalletTokens.cpp` 中 EVM 行的数据来源。原则：
**链 ID 与代币合约必须能指回公开来源**；无法指回的行不应当作生产支持宣传。代币精度以发行方
合约表或链上 token API 为准，不能凭常见值猜测。

## 链 ID

| Network | chain id | 来源 |
| --- | --- | --- |
| Ethereum | 1 | EIP-155 / 链规范 |
| Ethereum Classic | 61 | 链规范 |
| Unichain | 130 | Uniswap Unichain 官方文档（network information） |
| Monad | 143 | Monad 官方文档（network information） |
| Plasma | 9745 | Plasma 官方文档（connect-to-plasma） |
| Berachain | 80094 | Berachain 官方文档（connect-to-berachain） |
| Arc | 5042 | Circle Arc 官方文档（connect-to-arc） |
| X Layer | 196 | chainid.network（链上 EIP-155 注册表）；OKX 官方文档当前不可达 |
| zkSync Era | 324 | chainid.network（EIP-155 注册表）；官方文档未提供稳定直链 |
| OKT Chain | 66 | chainid.network（EIP-155 注册表） |

其余历史 EVM profile（BSC 56、Polygon 137、Avalanche 43114、Arbitrum 42161、Optimism 10、
Base 8453、Linea 59144、Scroll 534352、Blast 81457、Mantle 5000、opBNB 204、Polygon zkEVM 1101、
Aurora 1313161554、Metis 1088、Kaia 8217、Astar 592、Canto 7700、Dogechain 2000、Fuse 122、
Evmos 9001、Harmony 1666600000、Telos 40、Sei EVM 1329、EthereumPoW 10001、Callisto 820、
Etho 1313114、OctaSpace 800001、Etica 61803、Aves 33333、Canxium 3003、Bitnet 210、
Larissa 9898、VirBiCoin 329、Cronos 25、Kava 2222、Gnosis 100、Fantom 250、Core 1116、
Conflux eSpace 1030、Moonbeam 1284、Moonriver 1285、Rootstock 30、Celo 42220）来自各自上线时
核对过的官方网络文档。

## 代币

| Token | Network | 合约 | 精度 | 来源 |
| --- | --- | --- | --- | --- |
| USDC | Unichain | `0x078D782b760474a361dDA0AF3839290b0EF57AD6` | 6 | Circle USDC contract table |
| USDC | Monad | `0x754704Bc059F8C67012fEd69BC8A327a5aafb603` | 6 | Circle USDC contract table |
| USDC | Plasma | `0x2d661C89D812261039AF9764eceaAee884f5F67F` | 6 | Circle USDC contract table |
| USDC | X Layer | `0xB6CEceAB302E2E4948951eE7843FC24E92933061` | 6 | Circle USDC contract table |
| USDC | zkSync Era | `0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4` | 6 | Circle USDC contract table |
| XAUT | Ethereum | `0x68749665FF8D2d112Fa859AA293F07A622782F38` | 6 | Tether supported protocols + Blockscout token API; 2026-10-24 `symbol()`/`decimals()` RPC check |
| PAXG | Ethereum | `0x45804880De22913dAFE09f4980848ECE6EcbAf78` | 18 | Paxos PAX Gold contract; 2026-10-24 `symbol()`/`decimals()` RPC check |
| MANA | Ethereum | `0x0F5D2fB29fb7d3CFeE444a200298f468908cC942` | 18 | Decentraland contract; 2026-10-24 `symbol()`/`decimals()` RPC check |
| MANA | Polygon | `0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4` | 18 | Decentraland Polygon deployment; 2026-10-24 `symbol()`/`decimals()` RPC check |
| USDT | Ethereum / BSC / Arbitrum | 见表内注释 | 6 / 18 / 6 | Tether 官方 supported-protocols 表；BSC 为 Binance-Peg |
| USDC | Ethereum / Base / Arbitrum / Optimism / Polygon / Avalanche | 见表内注释 | 6 | Circle USDC contract table（含 Polygon `USDC.e`） |
| DAI / BTCB / ETH | BSC / Polygon / Arbitrum | 见表内注释 | 18 | 2026-10-24 公开 RPC `symbol()`/`decimals()` 复核 |

`USDT0` 行（`xlayer` / `monad` / `plasma` / `bera` / `opt`）按部署地址登记；本文件**未**独立
核实其发行方公告，因此在正式资金路径启用前必须由部署方公告或链上合约再次确认。未确认前
不应把它们称为“USDT”。

## 非 EVM（不要伪装成 EVM）

Starknet 使用 Cairo VM 与 Cairo 交易；Aptos、Sui、TON、NEAR 也不是 EVM。它们需要独立的
交易序列化、签名与审阅适配器，不能通过增加 chain id 来“支持”。同理，TRON 使用 protobuf
与 65 字节 recoverable 签名，已经由 `TronTransaction.cpp` 单独实现。
