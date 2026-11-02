# 独立签名与网络审计 · 2026-11-02

本轮按用户确认，只新增独立测试与审计文件，不改并行聊天正在实现的业务代码。
验收结论：**不通过**。真实 Mbed TLS、BIP32 和 ECDSA 路径执行 32 项检查，25 项通过、7 项失败。没有连接真实钱包、导入用户密钥或广播交易。

首次受测 `BitcoinTransaction.cpp` SHA-256：
`B7E3381D7DE70CB3C464E3CDE73506EAD557C20F4ED36D50B4CF404CC1E62EC4`。
最后复测 SHA-256：`F79AD250D31448B9477377EDBFBE7F1ED18DFE2EC9BB5B22589E7AC0308F5436`，仍为 32 项检查、7 项失败。两次运行之间实现聊天有更新；每次运行内部的源码一致性检查均通过，后续版本另需重跑。测试使用公开、固定种子。

## 必须修复

### P1：v2 输出 map 提前返回，末尾校验不可达

`parse_output_map_v2()` 在读到 map terminator 时立即返回 `Ok`，使函数末尾的 `has_amount`、`has_script` 与输出派生所有权验证不可达。

复现：`reject missing amount`、`reject missing script`、`output ownership checked`、`reject false output ownership` 四项失败。带错误 master fingerprint 的输出派生没有被拒绝；合法钱包输出也没有被正确标记为钱包所有。

应将成功读到 terminator 的路径改为结束循环，再校验必需字段并处理派生。错误读取仍立即返回错误。这里报告的是解析和审阅边界缺陷；未证明缺失脚本可以穿过后续签名器，不能把它夸大为已验证的盗币路径。

### P2：PSBT_GLOBAL_TX_MODIFIABLE 宽度错误

`read_psbt_global()` 使用四字节 `psbt_read_u32_value()` 读取此字段，但 BIP370 指定一字节 bitfield。测试确认合法的一字节零值被拒绝，非法的四字节零值却被接受。

应严格检查 `value_size == 1`，读取 `value[0]`，随后执行钱包自身的修改标志策略。拒绝仍允许修改的请求可以是本钱包的产品限制，但不能改变协议编码。

### P2：required locktime 可被全 final sequence 架空

测试构造 `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME=100` 且唯一输入 `nSequence=0xffffffff`。解析成功并产生 `nLockTime=100`，但全 final sequence 不会强制该锁定时间。

这是一项签名策略缺口：不能向用户声称 required locktime 已生效。应在签名前拒绝这种组合，或采用有明确协议依据、可重新审阅的处理。不能暗中修改已审阅交易的 sequence。本测试不将普通、无 required 字段的 final sequence 交易一律禁止。

## 已执行检查

| 检查 | 结果 | 证明范围 |
| --- | --- | --- |
| PSBT v0、显式 version=0、v2 | 通过 | 固定 BIP84 单输入/单输出样本解析 |
| v0/v2 签名一致性 | 通过 | 同一交易最终签名字节完全一致 |
| 重复金额、重复 outpoint、未定义 v1、v2 混入 unsigned tx、尾随数据 | 通过 | 对应恶意输入被拒绝 |
| 普通 required height、失败不修改调用者输出 | 通过 | 指定样本行为 |
| 12 个 EVM profile 的 chain ID 与自定义 ERC-20 登记 | 通过 | BSC、Polygon、Flare、Arbitrum One、AVAX C、Arc、Aurora、Fantom、Bitlayer、Base、X Layer、Rootstock |
| 自定义 token 存储、token calldata 自检 | 通过 | 现有回归用例；不是完整 NFT 或全节点验收 |
| `se051_port_check.ps1` | 通过 | 主机端口测试 |
| `se051_port_check.ps1 -Device` | 通过 | 真实 P4 工具链编译，未连接实卡 |
| `policy_check.ps1` | 通过 | 脚本定义的目录/生产策略检查，不是全固件认证 |

P4 首次执行因沙箱路径、随后 DLL 重定位失败；指定已安装工具链路径并在沙箱外运行后通过。测试没有绕过固件内的托管门。

## 原请求中仍未得到完整验收的能力

- **PSBT v1**：BIP370 明确跳过版本 1；应该支持 v0/v2 并拒绝线上的 version=1。Taproot 的 BIP371 字段可以用于两者，PSBT v2 通过不等于 BIP86 或 Taproot 签名通过。
- **BTC BIP86、Lightning、Stacks、ZER**：受审的网络表/签名入口中未找到完整实现。本轮没有为这些功能背书。ZER 必须对照其自己的节点源码、升级规则和交易向量，不能因与 Zcash 有渊源便套用 ZEC 参数。
- **Rootstock、X Layer**：已验证 EVM profile 和自定义 ERC-20 登记，不等于验证 BTC 跨链桥、托管赎回或 Lightning 通道。资产不能因为界面显示 BTC 就被视作同一种链上资产。
- **NFT**：现有 `CustomTokenStandard` 仅有 EVM ERC-20、TRC-20、SPL、Stellar asset、Starknet ERC-20，自定义 NFT 登记尚未具备。已有 ERC-721/1155 解码分支也不等于任意 NFT 完整支持；EVM 审阅明确拒绝批量转移、非空回调数据等路径。
- **Kaspa/Zcash/Monero**：存在专用实现，不能说只有地址；但本次没有重新验证全部密码学、当前升级兼容性或全节点接收。仓库已明确 Kaspa v1、Zcash shielded/v5 等仍受限。
- **SE051/NFC/摄像头/USB**：主机测试与端口编译不能证明安全芯片非导出托管、实卡 SCP03、可信屏幕和物理确认成立。需要实板、配钥流程、故障注入与传输通道验收。没有可据此承诺“零漏洞”的证据。

## 复现

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/psbt_audit/run.ps1
```

需要 Visual Studio 2022、CMake 和仓库现有的固定 Mbed TLS 3.6.5 checkout。输出位于 `build/psbt-audit/`：`results.txt`、`source-hashes.json` 和可执行文件。脚本遇到失败返回非零；检测到审计期间源码变化时拒绝给出稳定快照结论。这里保留失败断言，供实现聊天修复后复测，不能通过删除断言使验收变绿。

## 规范来源

- [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)：PSBT v0 与字段唯一性。
- [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)：v2、版本 1 被跳过、modifiable 字段、required locktime。
- [BIP371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki)：Taproot PSBT 字段。
- [Arc 官方连接参数](https://docs.arc.io/arc/references/connect-to-arc)：本轮核实主网 chain ID 5042，原生 gas USDC 按 18 位小数处理；勿套用 ERC-20 USDC 的显示精度。
- [ZERO 节点仓库](https://github.com/zerocurrencycoin/Zero)：后续 ZER 适配的源码入口；本轮未完成协议审计。
