# 链支持

[English](Supported-Chains) · [首页](Home-zh)

目录里有 215 个钱包条目，覆盖 247 个编译进来的网络配置。一个条目 = 一条派生路径 + 一套审查/签名策略。
它不代表节点接受过交易。

能力位是字面意思：`address` 能派生并显示地址，`review` 能把载荷解析成可审查字段，`sign` 能产出签名，
`token-account` 表示该网络有 token 登记表。只有四个条目没有 `sign`，也只有一个条目没有 `address`。

## UTXO 及同类

| 条目 | 路径 | 范围 |
| --- | --- | --- |
| `btc` | BIP84 `m/84'/0'/0'/0/i` | PSBT v0/v2、P2WPKH、BIP143 |
| `btc49` | BIP49 | P2SH-P2WPKH、BIP143 |
| `btc44` | BIP44 | P2PKH、legacy sighash，legacy 输入需要 `non_witness_utxo` |
| `btc86` | BIP86 | P2TR key-path、`SIGHASH_DEFAULT`/`ALL`、无脚本树 |
| `prl` | BIP86 | Pearl 主网，只支持 Taproot key-path；不做 P2MR、XMSS 或脚本路径 |
| `zec` | BIP44 | v4 透明交易、ZIP-243、t1 P2PKH 与 t3 P2SH-P2PK、NU6.2 |
| `dash` | BIP44 | 专用适配器：type-0 普通支付、legacy 摘要、P2PKH/P2SH 输出；每个输入带资助交易，手续费是算出来的而不是主机给的；InstantSend 意图会显示，锁离线不可验证 |
| `kas` | BIP44 | BIP340 Schnorr、v0 交易、`SIGHASH_ALL`、KIP-0009 mass |
| `ltc`、`ltc49`、`ltc84`、`doge`、`rvn`、`vtc*`、`btg*`、`dgb*`、`grs*`、`axe` 等 | 各自配置 | 核对过 sighash 家族的 UTXO 分叉：legacy、BIP143、`SIGHASH_FORKID`、Groestl-512 |

105 个分叉配置由 `tools/fork_registry.json` 生成。准入条件是上游 `chainparams` 里 base58 版本对应
legacy P2PKH sighash，且交易头没有 `nTime`、没有宽 `nType`。带时间戳 sighash 或宽交易头的链一律不进：
Bitcoin legacy 签名器绝不用来猜。

## EVM

62 条网络共用一个签名器：EIP-155，需要访问列表的链走 EIP-2930，支持的链走 EIP-1559。原生转账、
已登记 token 调用、任意 calldata、合约创建都可以签；不是已登记 token 调用的 calldata 会以原始字节
加 keccak-256 显示，绝不解码成转账。

```text
Acala EVM, Arbitrum One, Arc, Astar, Aurora, Avalanche C-Chain, Aves, Base, Berachain,
Binance Smart Chain, Bitlayer, Bitnet, Blast, Canto, Canxium, Celo, Conflux eSpace, Core,
Cronos, Dogechain EVM, Ethereum, Ethereum Classic, EthereumPoW, Etho Protocol, Etica,
Evmos EVM, Fantom, Flare, Flow EVM, Fuse, Gnosis Chain, Harmony EVM, Kaia,
Kava EVM, Larissa Chain, Linea, Mantle, Merlin Chain, Metis Andromeda, Monad, Moonbeam,
Moonriver, Oasis Sapphire, OctaSpace, OKT Chain, opBNB, Optimism, Plasma, Polygon,
Polygon zkEVM, Robinhood Chain, Ronin, Rootstock, Scroll, Sei EVM, Telos EVM, Theta,
Unichain, VirBiCoin, X Layer, XinFin Network, zkSync Era
```

Theta 是唯一有两条路径的网络：TFUEL 转账走 EVM 适配器，原生 `SendTx` 走 Theta 适配器，载荷格式决定走哪条。

18 条网络上固定了 78 条 token 记录（`WalletTokens.cpp`）。用户可以在设备上自加 token；审查界面会标注
"自加"，而且它们永远不改变被签名的字节。

## 原生适配器

这些链通过 `chain begin <network> <index> <payload-hex>` 接收各自格式的载荷。具体封装见
[载荷格式](Chain-Payloads-zh)。

| 条目 | 范围说明 |
| --- | --- |
| `xmr` | RCT type 6、CLSAG、Bulletproofs+、16 成员环、子地址花费；诱饵由手机提供 |
| `alph` | P2PKH 原生 ALPH 转账。检查每个输入的公钥或复用前一解锁脚本，审阅一个外部收款方、可选本机找零及 gas 费用。测试与 Alephium 官方 SDK 3.0.5 的交易哈希和签名字节一致。 |
| `quantus` | 主网 runtime 153/6。透明账户使用 ML-DSA-87 和 SS58 前缀 189，支持普通余额转账。设备审阅收款方、金额、小费、nonce 和有效期，生成完整 v4 extrinsic。 |
| `zeph` | ZPH 原生普通转账，v3 前缀、RingCT type 6、16 成员 CLSAG 环。按既定策略与 XMR 共用派生密钥，审阅按 Zephyr 的地址前缀和资产字段执行。 |
| `trx` | owner 权限转账、TRC-10、已登记 TRC-20、可打印 memo ≤ 64 字节；不做 NFT、批量、多合约 |
| `xlm` | SEP-0005、主网 XDR Payment/CreateAccount、发行资产与 memo 审查；最多 8 个操作 |
| `sol` | Legacy/v0、System Transfer、SPL 与 Token-2022 `TransferChecked`、精确 mint/账户审查；不做 ALT、不建 ATA |
| `xrp` | 原生 Payment、规范 XRPL 二进制、SHA-512Half；不做发行货币、path、memo、部分支付、多签 |
| `atom`、`osmo`、`tia`、`kava`、`terra`、`terraclassic` | 1–4 条 `MsgSend`、`SIGN_MODE_DIRECT`、可选 memo；不做 IBC、authz、wasm、amino 签名 |
| `ada` | Conway body 审查与 Ed25519-BIP32 签名；body 不带输入金额/所有者，余额需要节点 |
| `algo` | 规范 MessagePack `pay`/`axfer`、genesis/手续费/轮次校验、ASA opt-in；仅主网 |
| `apt` | Aptos 转账载荷，Ed25519 认证密钥派生 |
| `ckb` | secp256k1 sighash 与 Molecule 序列化 |
| `dcr` | BLAKE-256、legacy prefix/witness sighash、P2PKH |
| `erg` | P2PK ProveDlog：设备自己重建 tx-id 原像并返回完整证明交易 |
| `fil` | CBOR `Send`、CID 摘要、f1 发送方 |
| `hbar` | Hedera 转账 body 签名 |
| `hive` | 只能审查 + 签名：STM 公钥不是收款地址，所以这个条目没有地址能力 |
| `icp` | Ed25519 请求签名与 IC principal 派生 |
| `vet` | 紧凑载荷、规范 RLP、BLAKE2b-256、可恢复签名；只支持单 clause VET |
| `icx` | `icx_sendTransaction` 规范文本、SHA3-256；只支持原生 ICX |
| `dot`、`ksm` | `DOT2` 载荷、钉死的 runtime `spec_version`/`transaction_version`、短命期 era + tip；历史 DOT1 布局只在 host 测试里存在 |
| `qrl` | XMSS/SHAKE-256，树高 10；签名前先把叶子写进持久存储，设备在释放签名前验证自己的签名 |
| `qrl2` | ML-DSA-87 账户、SHAKE-256 校验和的 `Q` 地址、keccak-256 信封；只支持主网 chain id 1 |
| `stark` | Stark 曲线密钥、Cairo v3 `deploy_account` 与一次 ERC-20 `transfer`（走 `execute`）；只支持 `SN_MAIN` |
| `theta` | 原生 46 字节 `SendTx` 载荷；TFUEL 的 EVM 转账走 EVM 条目 |
| `ton` | Wallet v4R2 cell/BoC 序列化、user-friendly 地址、空 body |
| `sui` | BCS 分离 gas 的原生转账、Ed25519；不做 Move 调用、赞助或 token |
| `xch` | 只支持 Chia `CREATE_COIN`；BLS12-381 G1 密钥 |
| `xem` | NEM 的 Keccak-Ed25519 变体，不是 RFC 8032 Ed25519 |

## 仅地址

| 条目 | 原因 |
| --- | --- |
| `ryo` | CryptoNote 长地址，前缀 `0x2ce192` |
| `zano` | CryptoNote `Zx` 地址，前缀 `0xc5` |

## 拒绝清单

拒绝清单是契约的一部分，不是免责声明：屏蔽式 Zcash、Peercoin 签名、TRON NFT 与批量调用、
Cosmos IBC/authz/amino、Dash 特殊交易、EVM 盲解码、Lightning、Stacks、把 Mimblewimble 链当钱包用，
以及所有没有上游 SLIP-0044 编号的链。准入流程见 [准入策略](Admission-Policy-zh)。

## 机器生成的矩阵

- `wiki/native-chain-capabilities.md` —— 每个编译进来的配置一行，由 `tools/native_coverage.ps1`
  从编译产物生成。
- `wiki/miningpoolstats-coverage.md` —— MiningPoolStats 每条列表及其解析状态，由
  `tools/generate_mining_catalog.py` 生成。
- `wiki/chain-support.md` 与 `wiki/chain-protocols.md` —— 详细的实现记录。

如果某一页和生成的矩阵冲突，以矩阵为准，那一页就是 bug。
