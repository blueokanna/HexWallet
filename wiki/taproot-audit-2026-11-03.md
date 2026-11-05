> Dated audit record (2026-11-03). Kept as the evidence trail.

# Taproot 签名审计与修复

这次工作补齐并验证 BIP86 单密钥花费路径，同时审查并发接入的 BIP341/BIP371 实现。没有把单密钥签名扩展解释为脚本树、多签或 Lightning 通道支持。

## 已修复

- BIP341 `SIGHASH_NONE` 不再提交输出集合。
- `ANYONECANPAY` 提交当前输入的 outpoint、金额、scriptPubKey 和 sequence。
- annex 按 CompactSize 长度前缀参与 SHA256；接受仅含 `0x50` 的 annex，覆盖 252/253 字节编码边界，并修复最长 SigMsg 缓冲容量。
- 拒绝规范未定义的 `0x80` sighash；普通非 Taproot 输入拒绝 `SIGHASH_DEFAULT`，防止解析时接受、签名时改成 ALL。
- v0/v2 输出 map 接入 BIP371 内部公钥和派生字段。派生、fingerprint、tweaked scriptPubKey 一致后才显示为本钱包找零；重复或不匹配字段拒绝。
- Taproot 准入限定于 Bitcoin profile，其他使用 Bitcoin 风格签名器的链不能自动继承该能力。
- 托管分类新增 BIP86/TapTweak/Schnorr，避免将 Taproot 当作 SE051 ECDSA 能力。没有经过验证的卡内实现时仍要求 MCU 私钥，生产托管门保持关闭。

## 验证

2026-11-03 的稳定快照结果：PSBT/NFT/Taproot 回归 **90/90**；BIP341 独立回归 **13/13**。两个 runner 均通过前后源码哈希一致性检查。BitcoinTransaction.cpp 的 SHA-256 为 `110832F4BF02ADFA37F30B0E3338F10BBA22EB6CFF393DFD8559995C333B6447`；后续任何源码变化都需要重新验证，不能沿用本次结论。P4 runtime 编译通过，覆盖 CLI、签名调度、NFC、草图与三个显示 profile。主机编译仍有体积估算的 size_t 转 uint32_t 警告，未把通过编译写成零告警。

`tests/host/taproot_audit/` 保存 Bitcoin 官方未修改向量、固定 SHA-256、独立加载器及复现脚本。验证全部七组官方 key-path 摘要，另有三组独立构造的 annex 边界向量和非法参数检查。

`tests/host/psbt_audit/` 增加 BIP86 v0/v2、默认/显式 ALL、真实 Schnorr 签名验证、找零归属、内部公钥错配、重复字段、错误网络及不支持脚本路径的拒绝测试。它使用公开固定种子与真实密码学代码，不连接用户钱包、不广播交易。

## 仍未实现或未验收

Taproot script-path、登记的多签策略、MuSig2、Lightning 通道状态与撤销机制未接入。不能通过接受任意 leaf 或任意摘要签名来补齐这些能力；必须先有设备可验证的策略登记、每次签名状态和恢复流程。

Stacks、ZER、BEAM、PRL 的完整协议接入，以及 SC/XEM/ICP/Flow/Lisk/DOT/KSM/XCH/QRL/APT/THETA 的全部交易类型，本次没有完成。Kaspa、Zcash、Monero 仍需逐项完成当前网络规则、节点接受及设备性能验证。本次没有用扩大注册表或能力位代替它们的实现。

用户确认已有开发板但 SE051 尚未接入，因此卡内密钥托管和真实 NFC、摄像头、USB 物理确认不能在本次判定通过。另纠正 SE051 文档中直接拆分 seed 为主节点的错误：BIP32 要先执行主节点 HMAC；卡内 HMAC 也不等于卡内标量加法、完整 CKDpriv 或非导出对象派生。

规范依据：[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)、[BIP86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)、[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)、[BIP371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki)。
