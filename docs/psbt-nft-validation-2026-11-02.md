# PSBT 与自定义 NFT 修复记录

本记录只描述本次修改和可复现验证，不代表整机生产认证。

## PSBT

修复 v2 输出 map 结束时提前返回的问题。金额、脚本必需字段与输出派生所有权校验现在都会执行；输出脚本字段禁止携带 key data。

`PSBT_GLOBAL_TX_MODIFIABLE` 按 BIP370 读取一个字节。当前签名策略仍拒绝非零标志。required height 必须大于零且小于 500000000；请求 required locktime 但全部输入 sequence 为 final 时拒绝签名，不擅自修改 sequence。

保留 v0/v2 支持，拒绝 version=1。BIP370 明确跳过该版本号。PSBT v2 支持不等于 Taproot、BIP86、多签或 Lightning 支持。当前输出是已签交易，并非任意多方 PSBT 合并器。

## 自定义 NFT

新增 ERC-721 与 ERC-1155 collection 登记，沿用现有固定容量存储、网络与合约绑定、失败回滚及删除接口。序列化布局不变，增加两个标准枚举值；旧固件不认识这些值，会拒绝包含它们的表，降级前应备份自定义资产记录。

CLI：

```text
token custom-add-nft <network> <contract-hex> <erc721|erc1155> <symbol> <name>
token custom-list <network>
token custom-remove <network> <contract-hex>
```

网络使用内部 ID，例如 `bsc`、`matic`、`flare`、`arb1`、`avaxc`、`arc`、`aurora`、`ftm`、`bitlayer`、`base`、`xlayer`、`rsk`。记录是集合级标签，不能证明链上合约身份、余额或所有权。同一网络/合约只有一个声明标准，再次登记替换原记录。

EVM 审阅根据登记的标准解码，而不是把所有自定义合约当成 ERC-20。NFT 的 token ID 和数量取自交易 calldata，以整数显示；设备继续显示合约地址和 `UNVERIFIED CUSTOM TOKEN`。只支持现有解码器允许的调用；批量 ERC-1155、非空回调数据、未实现的授权操作不会因此放行。没有加入 NFT 图片下载、余额索引或市场功能。

## 验证与剩余工作

本次最终独立回归为 **64 项通过、0 项失败**，包括 NFT 插入、更新、删除的存储失败回滚。另通过多链原生测试（钱包派生、chain、Zcash、Cosmos、Dash、Bitcoin、EVM、Starknet）、生产托管拒绝策略、SE051 主机端口测试，以及 P4 runtime 编译脚本。P4 检查包含 CLI、NVS 存储、签名调度、NFC APDU、Arduino 草图及三个显示 profile；它不是整机链接或实板测试。MSVC 仍报告 Bitcoin 体积估算中的 size_t 到 uint32_t 转换警告，未据此声称零告警。

独立回归入口：`tests/host/psbt_audit/run.ps1`。链接固定 Mbed TLS 3.6.5 与实际 BIP32/ECDSA 实现，使用公开固定种子。结果和源文件哈希写入 `build/psbt-audit/`。覆盖 PSBT 必需字段、规范编码、重复输入、所有权、锁定时间、v0/v2 签名字节一致性，12 个 EVM profile 的 ERC-20 登记，以及 NFT 持久化、真实签名、审阅标记、错误链、错误所有者和错误标准拒绝。

本次没有实现 Lightning 通道状态机、Stacks 签名、ZER 交易协议、BIP86/Taproot 花费，也没有完成 Kaspa/Zcash/Monero 的全部升级兼容验收。Rootstock/X Layer 的 EVM 签名不能证明跨链桥操作正确。SE051 主机端口检查通过，但安全芯片内非导出派生与签名、实卡 SCP03、恢复流程和物理确认仍须按照 `docs/se051-integration.md` 验收。生产托管门保持关闭，不能把主机测试通过当成可保管真实资产的结论。

规范：[BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)、[ERC-721](https://eips.ethereum.org/EIPS/eip-721)、[ERC-1155](https://eips.ethereum.org/EIPS/eip-1155)。ZER 官网本次无法通过浏览工具读取，未据此添加未经验证的链参数。
