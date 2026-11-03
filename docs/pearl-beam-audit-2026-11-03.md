# Pearl 与 BEAM 接入审计

项目身份由用户确认：PRL 是 pearlresearch.ai 的 Pearl，BEAM 是 beam.mw 的隐私链。

## Pearl

协议基线固定为官方仓库提交 [`d7c517d267f10f5bcbbdc366f3e603942f9a5ab5`](https://github.com/pearl-research-labs/pearl/tree/d7c517d267f10f5bcbbdc366f3e603942f9a5ab5)。主要依据：

- `node/chaincfg/params.go`：主网 HRP `prl`、项目使用的 coin type `808276`。这里不额外声称该值已获 SLIP-44 登记。
- `wallet/waddrmgr/scoped_manager.go`：BIP86 作用域及 P2TR 地址构造。
- `node/txscript/sign.go`、`sighash.go`、`taproot.go`：单密钥 TapTweak、BIP341 和 BIP340。
- `node/btcutil/const.go`：每 PRL 为 `10^8` grains，最大金额 `21 × 10^9 × 10^8` grains。
- `node/wire/msgtx.go`：交易和 witness 序列化。

本次路径为主网 BIP86 单密钥花费。PSBT v0/v2 的输入和找零都使用注册表中的 coin type，校验设备派生公钥、内部公钥、tweaked 输出公钥及输出脚本。只签 DEFAULT/ALL，只接受 P2TR 收款脚本。网络 id、地址参数、摘要算法和 fork id 必须与注册表一致；不能把 Pearl 请求改标签后交给 BTC 签名。

修复的共性问题是原 PSBT 校验将所有网络的 coin type 固定为 `0'`。这会拒绝其他链的正常派生路径，并让错误路径与网络标签混用。现在解析输入、校验找零和最终签名使用同一网络参数，摘要计算的独立测试接口不受此策略限制。

验证程序见 [pearl_audit](../tests/host/pearl_audit/README.md)。预期地址、摘要和完整交易来自官方 Go 实现；固件使用自己的 C++/Mbed TLS 实现比对。P2MR、XMSS、脚本树、多签没有通过本次测试获得准入。官方 XMSS 接口是有状态签名，不能因为现有 QRL 模块也叫 XMSS 就直接复用参数、状态或密钥。

## BEAM

协议基线为 [`BeamMW/beam@6994a67059b38144c43b76f140955f3632b9bffa`](https://github.com/BeamMW/beam/tree/6994a67059b38144c43b76f140955f3632b9bffa)。[官方硬件钱包说明](https://www.beam.mw/docs/hardware-wallet)与 [`hw_crypto/keykeeper.h`](https://github.com/BeamMW/beam/blob/6994a67059b38144c43b76f140955f3632b9bffa/hw_crypto/keykeeper.h)说明它有可用的硬件协议，不能再以“没有地址、无法审阅”为由判定不可实现。

该版本的硬件协议是 `BeamHW` version 6，包含 `DisplayEndpoint`、`TxAddCoins`、`TxReceive`、`TxSend1/2`、`TxSendShielded`、`SignOfflineAddr` 和 shielded vouchers。平台须实现 `KeyKeeper_ConfirmTransaction`、安全清零、nonce slot 读写/更新和辅助缓存。交易状态保存各资产净额与费用，确认回调提供对端、内核及阶段信息。

移植时必须把第一阶段用户同意、第二阶段内核/付款证明、资产净额和设备显示绑定为同一会话。nonce slot 更新还必须经过断电和恢复测试，不能允许重放或回滚导致 nonce 重用。离线交易有独立路径，不应假设所有交易都需要接收方在线。

本仓库尚未实现这些 BEAM 状态机和密码学操作，因此没有添加可签名 profile，也没有把上游能力当作本机验收结果。

## 实机边界

开发板已有，SE051 尚未接入。上述软件验证不改变芯片托管状态，也不替代 USB、NFC、摄像头 AIRGAP 的整机确认测试。Kaspa、Zcash、Monero 与其他链仍按各自已有的交易范围和验收记录表述，不推导为全面生产可用。
