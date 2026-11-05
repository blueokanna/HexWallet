# 载荷格式

[English](Chain-Payloads) · [首页](Home-zh)

主机怎么把交易交给设备，设备又还回什么。CLI 上一律是十六进制，手机链路上是带长度前缀的二进制；
两边跑的是同一份解析代码。

## 通用规则

- 长度必须精确匹配。多余字节算错误，不当填充。
- 解析器无法完整校验的载荷一律拒绝，绝不截断后"尽力而为"。
- 上限：PSBT 4096 字节（`HEXWALLET_MAX_PSBT_BYTES`），原生适配器载荷 2048 字节（`kChainMaxPayload`），
  手机 `BEGIN_SIGN` 载荷 16384 字节。
- 设备返回的是已签名交易，不是裸签名；只有明确这样定义的适配器例外（HIVE 返回 65 字节 graphene 签名，
  XRP 返回签名后的二进制）。
- 金额、手续费、nonce 全部由主机提供。设备只校验内部一致性和钱包归属，不校验链上是否存在。

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
u8 flags                     bit0：每个输出带 mask（仅 MSR）；其余位必须为 0
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
| VET / ICX / TON / DCR / CKB / HIVE / SOL / TRX / XLM / ATOM 等 | 各家族自己的紧凑结构，带 magic 的写在 `<Name>Transaction.h` |

签名前 `chain_sign_transaction()` 会重新跑一遍审查并逐字段比对。载荷和审查结果对不上，就不签。

## 链路状态码

`0` ok · `1` pending · `2` rejected · `3` unknown-coin · `4` invalid · `5` expired ·
`6` unsupported · `8` not-approved · `9` locked · `10` fee-policy。

`7` 已废弃，不再返回。拒绝时绝不返回部分输出。
