# SUI / FIL 原生转账适配器

本轮按用户后续指示集中处理 SUI/FIL；其他适配器由另一会话继续。
这里的完成范围是固件地址派生、原生交易解析、审阅、批准后重新校验和签名，
以及独立 SDK 对照。尚未完成真机 NFC/屏幕操作及节点接收验收，不代表所有硬件钱包的全部功能。

## 设备与手机接口

地址请求沿用手机协议的 `ADDRESS`，`coin_id=sui` 或 `fil`。
签名使用 `BEGIN_SIGN kind=14`，`address_index` 选择设备地址，账户和 change 均为 0。
payload 是下面定义的原始 BCS/CBOR 字节，不是哈希，也不带 `SUI1`/`FIL1` 自定义前缀。
最多 2048 字节。手机负责查询链状态、构建未签名交易、收集签名、组装 RPC 请求及广播；
私钥和种子在设备中派生，不通过手机协议输出。

设备从 payload 中解析收款人、金额和费用，校验发送人与本机派生地址一致，
显示发送地址、地址索引及交易明细。用户在设备批准后，签名器重新派生并重解析
相同 payload，对比审阅字段和摘要。篡改审阅、摘要、payload 或索引都会被拒绝。
签名失败时返回长度为 0，并清除调用者提供范围内的输出缓冲区。

## SUI

路径为 `m/44'/784'/0'/0'/index'`，SLIP-0010 Ed25519。
地址为 `0x || hex(BLAKE2b-256(0x00 || public_key))`。

支持的原生 BCS `TransactionData::V1`：

1. `ProgrammableTransaction`，恰好两个 Pure input：input 0 为 8 字节 LE 的 MIST 数额，input 1 为 32 字节目的地址。
2. 恰好两个 command：`SplitCoins(GasCoin, [Input(0)])`，然后 `TransferObjects([NestedResult(0,0)], Input(1))`。
3. 发送人与 gas owner 必须为本机地址；gas payment 为 1–8 个不重复的 ObjectRef，每个 digest 恰好 32 字节。
4. 正 gas price、正 gas budget；设备当前将 budget 上限限制为 100 SUI。显示签入交易的最大费用。
5. expiration 为 None 或 Epoch；所有其他 envelope、参数顺序、命令、额外字节均拒绝。

签名摘要为 `BLAKE2b-256(0x00 0x00 0x00 || TransactionData)`，
使用纯 Ed25519 签该摘要。返回 97 字节 `0x00 || signature[64] || public_key[32]`；
手机将其 Base64 编码，连同原始交易 bytes 提交 Sui RPC。

不支持任意 Move 调用、SPL/ERC 代币、Sui token/NFT、赞助 gas、多接收人、
整枚 gas coin 转移、其他签名方案或其他 PTB 结构。BCS 中没有可供本适配器验证的 chain ID；
网络选择、对象存在性/余额和 gas price 必须由手机与目标节点核实。

实现依据：[Sui 密钥和签名说明](https://docs.sui.io/develop/transactions/transaction-auth/auth-overview)、
[官方 BCS 定义](https://github.com/MystenLabs/ts-sdks/blob/main/packages/sui/src/bcs/bcs.ts)。
测试使用 `@mysten/sui 1.45.2` 独立构建交易及签名。

## FIL

路径为 `m/44'/461'/0'/0/index`，BIP32 secp256k1。
修正了旧编码器使用压缩公钥、缺失前缀/校验和的问题：

```
payload = BLAKE2b-160(uncompressed_SEC1_public_key[65])
checksum = BLAKE2b-32(0x01 || payload)
address = "f1" || base32_lower_no_padding(payload || checksum)
```

旧版本产生的 `ae...`/`ah...` 字符串不是合法 Filecoin f1 地址。派生路径和私钥保持不变，
修复的是公钥序列化和地址编码；新结果已与 Zondax SDK 在多个索引逐字节对照。

输入为 canonical CBOR 10 项 Message：

```
[0, To, From, Nonce, Value, GasLimit, GasFeeCap, GasPremium, 0, h'']
```

发送方仅支持 f1；接收方支持 f1、f3，以及 actor ID >=100 的 f0。
只支持 Send(method 0)、空 params、正 value。金额与 fee cap/premium 最多 128 位，
使用 Filecoin 符号字节加最短大端整数的 bigint 编码。拒绝负数、前导零、
非最短 CBOR 整数、无限长容器、尾随字节、gas premium 高于 fee cap 及总额溢出。
gas limit 为 1..10,000,000,000。设备显示 `GasLimit × GasFeeCap` 的最大 FIL 费用。

摘要与输出：

```
CID = 01 71 a0 e4 02 20 || BLAKE2b-256(MessageCBOR)
signing_digest = BLAKE2b-256(CID)
signature = secp256k1_recoverable_low_S(signing_digest)
SignedMessageCBOR = [Message, bytes(0x01 || r[32] || s[32] || recovery_id)]
```

返回完整 SignedMessage CBOR。使用 Lotus JSON RPC 的手机端必须将其解码为 Message
和 `Signature { Type: 1, Data: base64(r||s||recovery_id) }` 后提交 `MpoolPush`；
不能把整段 CBOR 当作 JSON 的 Signature.Data。

不支持 actor 调用、f2/f4 收款地址、BLS 发送方、FEVM、multisig actor 或其他方法。
消息字节不含 `f`/`t` 网络前缀或 chain ID；前缀不能提供密码学上的主测试网隔离。
nonce、余额、base fee 和目标链仍需节点验证。

实现依据：[Lotus Message 编码](https://github.com/filecoin-project/lotus/blob/master/chain/types/cbor_gen.go)、
[Lotus secp 签名](https://github.com/filecoin-project/lotus/blob/master/lib/sigs/secp/init.go)。
独立签名测试使用 `@zondax/filecoin-signing-tools 2.4.3`。

## 可重复验证

`tests/host/chain` 将真实 `WalletSecurity.cpp` 与 Mbed TLS 3.6.5 链接；
只替换 Arduino Serial 和平台随机数入口，主机随机数使用 Windows BCrypt。
它不链接 `host_security.cpp` 中的 BIP32/secp256k1 失败桩。

```powershell
git clone --depth 1 --branch mbedtls-3.6.5 --recurse-submodules --shallow-submodules https://github.com/Mbed-TLS/mbedtls.git build/chain-mbedtls
powershell -ExecutionPolicy Bypass -File tests/host/build_chain_native.ps1
python -m unittest discover -s tests -p test_sui_filecoin.py
python tools/generate_chain_selftest.py --check
```

构建脚本验证 Mbed TLS commit 为 `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`。
SUI/FIL 专用 SDK fixture 和生成器位于 `tests/fixtures/sui-filecoin-sdk.json`、
`tests/reference/generate_chain_vectors.mjs`；只使用明确标注 TEST ONLY 的公开种子。
共享的 `chain-sdk.json` 中其他链向量由其他适配器测试使用，不扩大本次验收范围。

生成器也构建其他链的参考值，因此需将共享 `chain-sdk.json` 中 `sdk` 列出的全部
精确依赖版本安装到 `build/chain-sdk`，再运行以下只比较 SUI/FIL 的命令：

```powershell
node tests/reference/generate_chain_vectors.mjs --sui-filecoin --check
```

独立的 SUI/FIL 回归包含 12 组正向 SDK 向量、75 组拒绝向量、完整截断遍历、
尾随字节、非规范编码、异账户/异索引、审阅替换，以及短缓冲/精确长度缓冲保护。

## 尚需真机验收

仍需在实际板卡验证恢复同一测试种子后的地址、NFC 分包、完整地址显示、批准/拒绝、
超时/锁定/断电，以及将设备输出提交目标链节点后确认接收/执行。
源码和主机回归不能证明 SE050 非导出密钥托管、可信启动或物理攻击防护。
