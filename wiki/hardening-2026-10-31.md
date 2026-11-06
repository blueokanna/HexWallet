> Dated hardening record (2026-10-31). Kept as the evidence trail.

# 固件修复记录 · 2026-10-31

本轮把三条"只登记地址"的链路补成可签名，并新增 Aptos。所有"通过"都指仓库里的主机测试或
交叉编译；没有连接实体钱包，也没有广播交易。

## 本轮变化

| 范围 | 变化 |
| --- | --- |
| QRL（v1 XMSS） | 新增 `QrlTransaction`：解析 `QRL1` 负载、设备自建 QRL 转账预映像（`master_addr ‖ fee ‖ message ‖ (addr ‖ amount)*`）、`sha256` 摘要、XMSS 签名。新增 `QrlOtsStore`：把 `QrlOtsJournal` 的双槽记录适配成 `qrl_xmss_sign_digest()` 需要的 `read/reserve` 端口，并为 ESP32 提供 NVS 实现（`nvs_set_blob` + `nvs_commit` 后才算成功）。租户标签是 `SHA-256(公钥)` 的前 128 位，所以同一钱包的两个 QRL 账户不共享计数器。 |
| QRL 端口命名 | `QrlXmss.h` 的 `struct QrlOtsStorage` 与 `QrlOtsJournal.h` 的 `class QrlOtsStorage` 同名，两个头文件同时包含时无法编译。端口改名为 `QrlOtsPort`，持久化协议仍叫 `QrlOtsStorage`。 |
| Chia | 目录从 ADDRESS 改为 SIGN。BLS12-381 的私密标量运算已迁到固定基线 blst（`third_party/blst`，`HEXWALLET_BLST_FORCE_32BIT` 强制 32-bit limb，宿主机与 MCU 编译同一份代码），签名为 `AGG_SIG_ME` 增广方案。 |
| DOT / KSM | 目录从 ADDRESS 改为 SIGN。`DOT2` 载荷的 signed extensions 与 `spec_version`/`transaction_version` 钉死在构建期（DOT 2005002/26、KSM 2005001/26），genesis 固定；`CheckMetadataHash` 以 mode 0 进入签名载荷。不符者以 `RuntimeMismatch` 拒绝。历史 `DOT1` 布局只在宿主测试构建可见。 |
| Aptos | 新增 `AptosTransaction`：`sha3-256(pk ‖ 0x00)` 地址、`0x1::aptos_account::transfer` 的 BCS `RawTransaction`、`sha3-256("APTOS::RawTransaction" ‖ BCS)` 签名消息、`0x00 ‖ sig ‖ pk` authenticator。 |
| EVM | 任意 calldata 与合约创建原本已在 `evm_parse_for_review()` 里实现（未知选择器走 opaque 审阅、创建交易设备自算 `keccak256(rlp([sender, nonce]))[12..]` 作为“预期创建地址”），但目录文案仍写着“拒绝”。文案改为陈述实际行为。 |
| 构建 | `build.ps1` 用 clang-cl 编译 blst 这一个 C99 单元（MSVC 没有 VLA），并把它加进所有链接行；`device_compile_check.ps1` 用目标 C 编译器单独编译 `src/BlstBackend.c`，并要求 `QrlOtsStore.cpp` 以 `-DARDUINO` 的真实包含集编译一次，确保 NVS 分支不是“只在宿主编译过”。 |

## 可重复验证

| 命令 | 本轮结果 / 验证边界 |
| --- | --- |
| `tests/host/build.ps1` | 退出码 0；`chain`/`catalog`/`networks` 全通过，含新增 `chain.qrl`、`chain.aptos` |
| `tests/host/qrl_oracle_check.ps1` | 与 qrllib `xmss_Signmsg` 逐字节一致（h=4/6/10，索引 0/1/末叶） |
| `tests/host/policy_check.ps1` | 143 个 已撤回资产 身份、五张注册表、无界字符串拷贝基线通过 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 全部固件源 + blst C 单元 + NVS 分支编译通过；不是整包链接 |
| `tests/host/p4_runtime_compile_check.ps1` | WalletSigning / LinkService / CLI / 草图对真实 P4 头文件编译通过 |
| `tools/native_coverage.ps1` | 重新生成 `native-chain-capabilities.md` |

## 仍未完成

- **QRL v2（Zond，ML-DSA-87）**：`ledger-app-qrl-v2` 签的是 v2，本固件实现的是 v1（XMSS）。
  v2 需要 FIPS 204 与约 63 KB 暂存方案，见 [chain-gates.md](chain-gates.md)。
- **QRL 跨恢复防复用**：空 journal 与"被抹掉的 journal"无法区分。当前策略是"首次签名时绑定索引 0"，
  托管层必须把"已入金的账户 + 空 journal"当作恢复事件处理。BDS 遍历状态没有持久化，
  每次签名重算整棵树（设备上约数秒）。
- **THETA**：治理币不在 EVM 上（EVM 交易只能搬 TFUEL），需要 Theta 原生 `SendTx` 的 RLP 与
  `SignBytes` 前缀；详见 chain-gates.md。
- **BEAM / PRL**：交互式 Mimblewimble 与 Pearl 专有方案，均未接入。
- 安全托管、量产 secure boot/eFuse、面板波形、按键/NFC、断电恢复、侧信道与真实节点验收。

## 后续状态

同日晚些时候，`third_party/blst` 已整体删除：BLS12-381 的 Fp/Fp2、G1/G2、压缩编码与 RFC 9380 hash-to-curve 现由仓内 [Bls12381.cpp](../Bls12381.cpp) 实现，blspy 与 RFC 9380 J.10.1 向量继续作为验收门槛。本文其余内容记录的是当时的状态。
