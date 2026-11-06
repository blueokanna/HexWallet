# 载荷格式

[English](Chain-Payloads) · [首页](Home-zh)

主机怎么把交易交给设备，设备又还回什么。CLI 上一律是十六进制，手机链路上是带长度前缀的二进制；
两边跑的是同一份解析代码。

## Zephyr、Alephium 和 Quantus

**Zephyr** 使用手机链路 `kind=5` 和 `coin_id=zeph`。设备要求普通 ZPH 输入和带 view tag 的 ZPH 输出，换币相关的报价高度、销毁量和铸造量必须为零。设备重建前缀并验证 BP+、输入归属、找零及 CLSAG。诱饵和未花费状态仍需节点确认。[主网测试交易](https://explorer.zephyrprotocol.com/tx/7e2f3d9d1b5deaf3db873d5fe5d6c54272d127a84aa04ddc18bd46e66a9a7c12)

**Alephium** 的 `chain begin alph <index> <payload-hex>` 接收官方 SDK 的主网 UnsignedTx 字节。支持 1 至 16 个同一 P2PKH 密钥的输入、一个外部收款方及可选找零。拒绝脚本调用、代币、锁定输出、附加数据和重复输入。设备显示 ALPH 金额和 gas 费，签署 BLAKE2b-256 交易 ID，返回 64 字节低 S 签名。节点负责确认每个输出引用有效且未花费。[上游编码](https://github.com/alephium/alephium-web3/tree/c457e9f3959423b22ffa3e18dd0e14b1e26dcf20/packages/web3/src/codec)

**Quantus** 的 `chain begin quantus <index> <payload-hex>` 接收官方顺序的 `call || extra || implicit`，固定主网创世哈希、spec 153 和 transaction 6。支持 balances 普通转账与保活转账，审阅小费与有效期。基础费用由 runtime 计算。签名携带 `QUANTUS_EXTRINSIC` 上下文，返回完整 v4 extrinsic。升级后的 runtime 需要重新核验。[官方签名实现](https://github.com/Quantus-Network/quantus-wasm/blob/04174ffca2e385ca64d45ee0c9523cc1dd36707d/src/ext.rs)

## 通用规则

- 长度必须精确匹配。多余字节算错误，不当填充。
- 解析器无法完整校验的载荷一律拒绝，绝不截断后"尽力而为"。
- 上限：PSBT 4096 字节（`HEXWALLET_MAX_PSBT_BYTES`），原生适配器载荷 2048 字节（`kChainMaxPayload`），
  手机 `BEGIN_SIGN` 载荷 16384 字节。
- 设备返回的是已签名交易，不是裸签名；只有明确这样定义的适配器例外（HIVE 返回 65 字节 graphene 签名，
  XRP 返回签名后的二进制）。
- 金额、手续费、nonce 全部由主机提供。设备只校验内部一致性和钱包归属，不校验链上是否存在。

## Beam

Beam 的设备端证明格式、双端命令及最终交易序列化见[原生交互转账](Beam-zh)。

## Xelis 原生账户

Xelis 的 24 个词直接编码 32 字节私钥，可附第 25 个校验词。当前恢复器支持英文和简体中文词表，检查校验词与标量范围。账户公钥为 `sk⁻¹·H`，普通主网地址前缀为 `xel:`。设备命令 `xelis check-address <address>` 检查校验和及压缩点，返回该外部地址的公钥。原生 Schnorr 签名通过独立向量验证。生产恢复入口、密文余额同步和机密转账证明仍待接入。[上游恢复格式](https://github.com/xelis-project/xelis-blockchain/blob/db59b5c246ab0e40386d6c241dcd77f0aea84b10/xelis_wallet/src/mnemonics/mod.rs)

## Ethereum 代币授权

授权审阅按链和合约区分同名 ABI。ERC-20 显示 spender 与额度，并区分无限额度和撤销。ERC-721 显示被授权的 token ID，ERC-721 和 ERC-1155 的整组授权明确区分授予与撤销。ENS Base Registrar 和 Name Wrapper 已按官方部署地址注册，并在同一以太坊主网区块 `0x1922794` 用 ERC-165 核对接口。[ENS 部署记录](https://docs.ens.domains/learn/deployments/)

## Quai 账户转账

`quai` 接受主网 Cyprus-1 的 type 0 转账。地址索引使用 quais.js 为该分片选中的实际子索引。设备按 `m/44'/994'/0'/0/index` 派生，并检查发送方和接收方均属于本区的 Quai 账户账本。

主机提交 go-quai 的 `ProtoEncodeTxSigningData` 字节。按字段号顺序编码 type、to、nonce、value、gas、data、chain_id、gas_price、access_list。type 为 0，chain_id 为 9，data 和 access_list 显式编码为空。value 和 gas_price 为最短大端正整数。审阅显示转账额、nonce、gas 上限、单价和最高费用。确认后返回 65 字节 `r || s || yParity`，由主机组装交易。

[go-quai](https://github.com/dominant-strategies/go-quai/blob/5917bf5e2ced1d3f1cafdde6bc6fa3345fb71c3e/core/types/transaction.go) · [Cyprus-1 type 0](https://quaiscan.io/tx/0x00060019fdf877647e4a9bab684b0c51732b590cb0ffebc058fb29702fe87f97)

## Bitcoin PSBT

`tx inspect [<coin>] <psbt-hex>` 接受 PSBT v0（BIP174）和 v2（BIP370）。全局、输入、输出三张 map
都按键规则解析；未知的 proprietary key 忽略，但"声称是已知类型、长度却不对"的 key 直接报错。
输入必须通过 `witness_utxo` 或 `non_witness_utxo` 指向本钱包的 UTXO，且派生出的 script 必须与钱包一致。

`tx sign <code>` 返回合并了签名的 PSBT，协调方可以继续加签名。支持的签名类型：legacy、BIP143、
Taproot key-path；sighash 为 `ALL`，P2TR 另支持 `SIGHASH_DEFAULT`。

## EVM

`evm inspect <network> <index> <unsigned-rlp-hex>` 接受未签名 RLP 信封：legacy
（`nonce, gasPrice, gas, to, value, data, chainId, 0, 0`）、EIP-2930（type `0x01`）或
EIP-1559（type `0x02`）。`chainId` 必须与该网络配置一致，否则在签名之前就拒绝。

审查界面显示 `to`、`value`、`gas`、手续费上限，以及"解码后的已登记 token 调用"或"完整 calldata + keccak-256"。
合约创建会显示将要生成的地址。`evm sign <code>` 返回已签名 RLP 和 `tx-hash`。

不存在"主机端可信 token 列表"这条路：只有固件里登记过、或者用户在设备上亲自加过的合约才会被解码。

## Kaspa

`kaspa inspect <payload-hex>` 接受紧凑审查结构，整数小端：

```text
u16 version
u64 lock_time
u8  payload_size + payload
u8  input_count
input_count * {
      txid[32], u32 index, u64 sequence, u64 value,
      u16 script_version, u8 script_size + script,
      u32 account_index, u8 change, u32 address_index,
      u8 sigop_count }
u8  output_count
output_count * { u64 value, u16 script_version, u8 script_size + script }
```

每个输入都带着它花费的 prevout 的金额和 script，所以设备不连节点也能算出金额和 KIP-0009 mass。
`kaspa sign <code>` 返回已签名的 v0 交易。

## Zcash

`zec inspect <payload-hex>` 支持两种 magic：`ZEC4` 和 `ZEC5`，整数小端：

```text
"ZEC4" | "ZEC5"
u32 branch_id
u32 unsigned_transaction_size
未签名 v4 交易字节          （每个 scriptSig 必须为空）
u8  input_count             （必须等于交易的 vin 数量）
input_count * {
      u64 value, u8 script_size + scriptPubKey,
      u32 account, u8 change, u32 address_index,
      [u8 redeem_size + redeem script]     // 仅 ZEC5，P2PKH 时必须为 0
    }
```

`ZEC4` 不能携带 P2SH prevout。`ZEC5` 给每个输入恰好加一条 redeem 记录；设备会用 t3 地址重新哈希它，
并且只接受单钥 `CHECKSIG` 脚本。载荷必须在最后一个输入记录之后结束。`zec sign <code>` 返回已签名 v4 交易。

## CryptoNote（Monero）

手机链路上是 `kind=5`，或者走 `BEGIN_SIGN` 背后的 CryptoNote 路径：

```text
u8  version = 1、2 或 3
u16 tx_len
u8[] tx                      已序列化未签名交易（RCT type 6）
u8[32] tx_secret             标准地址为 R = rG，单一子地址为 R = rD
if version >= 3:
  u8   additional_tx_key_count
  u8[32] additional_tx_secret[count]
u8 input_count
u8 output_count
u8 flags                     保留字段，必须为 0
input[input_count]
output[output_count]
```

每个输入：

```text
u64 amount, u16 real_index, u16 ring_size, u8[32] original_tx_public,
u64 output_index, u8[32] pseudo_out_mask, u32 subaddress_major,
u32 subaddress_minor,
ring_size * u64 ring_offsets,
ring_size * { u8[32] dest, u8[32] mask }
```

每个输出：

```text
u8 out_flags（bit0 找零，bit1 子地址）, u8[32] spend_public,
u8[32] view_public, u64 amount, u32 subaddress_major, u32 subaddress_minor,
[u8[32] mask]                // 仅当头部 flags bit0 为 1
if version >= 3: u8 tx_key_index
```

`tx_key_index` 属于当前输出记录，必须紧跟该记录的 `mask`；主交易密钥为 0，第 i 个 additional key 为 `i+1`。
设备上限：XMR 8 输入 / 16 输出、ring 固定 16、序列化交易 6144 字节；超限返回 `unsupported`，绝不截断。

## 原生适配器（`chain begin`）

```text
chain begin <network> <index> <payload-hex>
chain sign <code>
chain reject
```

封装格式由各适配器定义，解析器旁边的头文件就是规范：

| 家族 | 载荷约定 |
| --- | --- |
| SUI | 原始 BCS `TransactionData`；返回 97 字节：flag、签名、公钥 |
| FIL | 原始 CBOR `Message`；返回完整已签名 CBOR |
| ADA | 原始 Conway body CBOR；返回 `[body, witness_set, true, null]` |
| DOT / KSM | `DOT2` 载荷，带短命期 era 和 tip；返回 v4 已签名 extrinsic |
| XRP | 50 字节 Payment 审查结构；返回已签名二进制 |
| THETA | 46 字节原生 `SendTx`；同一网络 id 也承载 EVM 转账 |
| DASH | `DAS2`/`DAS3` 审查载荷，见下文 |
| VET / ICX / TON / DCR / CKB / HIVE / SOL / TRX / XLM / ATOM 等 | 各家族自己的紧凑结构，带 magic 的写在 `<Name>Transaction.h` |

签名前 `chain_sign_transaction()` 会重新跑一遍审查并逐字段比对。载荷和审查结果对不上，就不签。

## Dash

`DAS2` 和 `DAS3` 只差最后一个字节；两者都带每个输入的资助交易，这是"屏上的输入金额是真的"而不是主机文本的唯一依据。

```text
"DAS2" | "DAS3"
u32 lock_time
u8  input_count
input_count * { u8[32] previous_txid, u32 previous_index, u32 sequence,
                u64 value, u8 script_size + script,
                u32 account, u8 change, u32 address_index }
u8  output_count
output_count * { u64 value, u8 script_size + script }
input_count * { u16 funding_size, funding_transaction }
u8  flags                     // 仅 DAS3；DAS2 视为 0
```

`flags` bit0 表示 InstantSend 意图。其它任何位都返回 `unsupported`：主机要求固件没实现的行为，
必须在审查之前知道，而不是签完之后。

每个资助交易必须是 type-0 Dash 交易，其 double-SHA256 等于 `previous_txid`，且 `previous_index`
指向的输出金额等于 `value`、脚本等于 `script`。任何不匹配都是 `WrongWallet`。随后设备用被证明的值
重算手续费，主机无法靠抬高输入金额把手续费藏起来。

旧 `DASH` 载荷没有资助证明。它仍然可以解析，让旧主机收到明确的 `missing-field`，但永远不能签名。

### InstantSend

InstantSend 不给交易加任何字节：LLMQ 是在已签名字节存在之后锁输入的。设备没有可签的字段，也没有
可校验的东西。所以这个声明就按"声明"处理：

- bit0 置位时，可信屏幕显示"主机会求 InstantSend"，并说明锁是广播后由 quorum 决定的，未上锁的交易
  不算确认；
- 标志在被哈希的载荷里，手机无法在设备渲染审查之后加上或去掉它；
- 带标志和不带标志签出的字节完全相同，这一点有测试断言。审查标志绝不能改变实际广播的内容。

固件永远不会把 Dash 交易报告为已锁、已确认或已终局。

## 链路状态码

`0` ok · `1` pending · `2` rejected · `3` unknown-coin · `4` invalid · `5` expired ·
`6` unsupported · `8` not-approved · `9` locked · `10` fee-policy。

`7` 已废弃，不再返回。拒绝时绝不返回部分输出。
