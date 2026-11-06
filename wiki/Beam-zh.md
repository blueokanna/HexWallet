# Beam 原生交互转账

HexWallet 在固件内派生 Beam 密钥、生成完整 Bulletproof、恢复自己的输出，并完成普通转账的双方内核签名。联网主机传递公开的协商数据和最终交易。密钥派生和签名流程不调用 Beam Desktop、wallet-api 或远程签名服务。

当前实现覆盖 **主网第六次分叉后的原生 BEAM、一个已拥有的输入、一个收款输出和可选找零**。两端使用 HexWallet 交互帧。最终交易按 Beam 节点格式序列化。官方钱包的 SBBS 协商、带资产证明的输出、屏蔽池、多个输入以及自动扫描、广播、确认和重组处理仍待接入。端点公钥用于核对对手方。向其他钱包提供收款 token 还需要对应的消息收发协议。

## 双方怎样完成一笔转账

以下命令通过已认证的串口执行。金额和费用均为十进制 groth，1 BEAM 等于 100,000,000 groth。节点高度、输入的存在性、成熟度与未花费状态由联网端检查。

1. 收款方在支持私钥托管的会话中使用 `beam address <id>`，在设备屏幕核对普通地址，再交给付款方。地址包含 SBBS 公钥、频道和独立付款端点。测试使用上游 KDF、YAS 和钱包 Base58 独立生成相同地址。两端的 `id` 均为非零本地编号。
2. 付款方执行 `beam offer <id> <regular-address-or-endpoint> <groth> <fee> <min-height> <max-height> <owned-output-hex>`。设备接受未指定金额的普通原生币地址，也兼容原有的 32 字节端点。设备验证输入证明、恢复金额、核对承诺并计算找零，再将返回的 `beam-offer` 交给收款方。
3. 收款方执行 `beam receive <id> <offer-hex>`。设备检查要约是否指向自己的端点。核对屏幕上的金额和对方声明的端点，然后执行 `beam approve <屏幕确认码>`。设备生成收款输出、内核签名份额、偏移量和收款方签署的付款证明。将 `beam-receiver-reply` 交还付款方。
4. 付款方执行 `beam finalize <reply-hex>`。设备将回复与本机会话中的原始要约比对，验证收款方端点签名、内核签名份额、范围证明以及输出与约定金额之间的群等式。屏幕显示收款端点、金额、矿工费、找零和有效高度。确认后执行 `beam approve <屏幕确认码>`，取得 `beam-transaction`。

协商帧以明文传输，转发者可以看到双方端点、金额和费用。付款方的内核 nonce 只保存在易失内存中。一轮会话只能完成一次；拒绝、锁定、过期或断电后须重新协商。每一轮的等待时限为 120 秒。`beam reject` 取消当前会话。请在节点确认入块后再记账。

## 输出与协商帧

- `beam verify <output-hex>` 验证 707 字节节点输出。首字节为 4 或 5，其后是承诺横坐标与 674 字节的完整机密范围证明。
- `beam recover <output-hex>` 额外检查钱包归属。设备恢复金额和 CoinID，再派生一次承诺；只有两者吻合才返回记录。
- `beam prove <regular|change> <index> <subkey> <groth>` 构造指定 CoinID 的输出证明。生成证明本身不会产生链上余额。正常交易会在设备内生成新的收款或找零索引。
- `beam check-peer <offer-hex> <receiver-reply-hex>` 单独验证收款方贡献。此命令核对参数中的接收端点。付款流程在 `finalize` 时使用本机最初保存的要约。

要约为 162 字节。金额、费用、最低和最高高度各占 8 字节，使用大端序。随后依次为双方各 32 字节的端点、付款方的公开内核承诺和公开 nonce。后两项均为 32 字节横坐标加一字节奇偶位。回复为 902 字节，依次包含收款输出、合并后的内核承诺和 nonce、32 字节部分签名、32 字节偏移量及 65 字节付款证明签名。

## 验证和上线条件

原生测试 `chain_probe beam-output-selftest` 使用公开测试种子走完两方协商，分别恢复收款与找零，检查篡改与重复完成同一会话。加上输出文件参数可导出测试输入以及后缀为 `.tx` 的最终交易。`tests/host/beam` 中的独立验证器直接链接固定版本的 Beam 上游代码，验证每个范围证明、标准内核签名和包含费用及偏移量的平衡等式。

在 Windows 主机上先运行 `tests/host/build_chain_native.ps1`。将下方的 `$beam` 指向文末链接对应版本的上游工作树，其中应包含该版本固定的 `3rdparty/secp256k1` 子模块。然后在仓库根目录执行以下命令。输出文件仅包含本次测试的承诺、范围证明和交易。

```powershell
cmake -S tests/host/beam -B build/beam-reference-test -A x64 "-DBEAM_REFERENCE=$beam"
cmake --build build/beam-reference-test --config Release
& build/chain-native/Release/chain_probe.exe beam-output-selftest build/beam-reference-test/output.bin
& build/beam-reference-test/Release/beam_reference.exe build/beam-reference-test/output.bin build/beam-reference-test/output.bin.tx
```

生产固件的安全托管策略目前拒绝加载软件种子。公开证明可单独验证；真实资产收付还需要可工作的安全托管后端、两台设备的屏幕确认与断电测试，以及节点接收、确认和恢复验证。通用收款目录在这些条件完成前保持关闭。

[Beam 上游输出与内核实现](https://github.com/BeamMW/beam/blob/90a8be3ba2bed3e3adac748867658e9381b3f462/core/block_crypt.cpp) · [交互式签名参考](https://github.com/BeamMW/beam/blob/90a8be3ba2bed3e3adac748867658e9381b3f462/keykeeper/local_private_key_keeper.cpp)
