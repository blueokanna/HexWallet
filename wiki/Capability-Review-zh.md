# 四张原图的功能与安全核对

[English](Capability-Review) · [首页](Home-zh) · [逐链验证记录](validation)

截至 2026-11-24，7 号板构建仍为诊断固件。生产会话返回 `CustodyUnavailable`。下表逐条说明原图中的说法与当前源码、公开夹具和本地节点回执的关系。主机签名使用公开测试密钥。

当前工作区缺少四张需求原图。下文保留既有记录中的尺寸及逐项分析。当前图库收录 132 张主机渲染的固件画面。[逐格图库](UI-Gallery) · [配对、收款准入及硬件核查](Wallet-Hardening-2026-11-24)

## 图一　哪些交易可以签

原图一，1034 × 407；待恢复文件：`Review-Chain-Scope.png`。

| 项目 | 已有证据与可用范围 |
| --- | --- |
| Zcash | 图中的 v5 限制已过时。Zebra 7.1.0 的 NU7 regtest 在高度 106 和 107 确认 ZIP-244 透明付款，第二笔同时花费 P2PKH 和 P2SH 单公钥 `CHECKSIG`。屏蔽池、JoinSplit 及其他 P2SH redeem script 仍在范围外。[交易与区块](validation) |
| Peercoin | `ppc` 网络配置可编码 P2PKH 地址。`peercoin_sighash_all()` 对 v1/v2 的 `nTime` 和 v3 格式有专用测试。PPC 尚无钱包签名策略、设备交易审阅或节点付款回执。 |
| Ethereum 未知 calldata | `evm_parse_for_review()` 先尝试结构化审阅，对支持原始审阅的载荷显示目标、原始数据、Keccak-256 和最高费用。屏幕原生币金额只表示 call value；代币转移或授权效果可能超出该金额。[手机协议](Phone-Link-zh) |
| TRON | owner 权限的原生转账、TRC-10 和登记过的 TRC-20 有适配。NFT、批量调用、多合约交易和其他 permission ID 缺少可用的签名路径。 |
| Cosmos | 六条链的 24 笔 direct 双收款人 `MsgSend` 与 CosmJS 逐字节一致，Hub 和 Osmosis 配置另有 10 笔签名对照。隔离 Gaia 和 Osmosis 节点各自执行了 Amino 付款、限额授权和撤销。双向 ICS-20 中继后，Osmosis 收款地址收到 1.234567 ATOM 的跨链凭证，Gaia 收款地址收到 2.345678 OSMO 的跨链凭证。两笔成功确认均已回到源链。[载荷](Chain-Payloads-zh#cosmos) · [节点回执](validation) |
| Dash | type-0 支付会核对资助交易并计算费用。可展示 InstantSend 意图，quorum 锁需在线验证。带 `extraPayload` 的特殊交易仍待适配。 |
| Stacks、Lightning、Grin | 缺少 STX 原生收付、Lightning 通道状态与撤销、Grin 钱包收付流程。Bitcoin 多签脚本和 Beam 双方交互分别有自己的交易边界。 |
| Beam | CLI 可执行单普通输入的双方协商转账，地址与交易有独立参考测试。生产托管、未花费输出发现、同步、链上恢复和双实机节点验收仍缺。[Beam 实现记录](Beam-zh) |
| AION、Qubitcoin | 两条链按既有决定排除。`policy_check.ps1` 检查它们是否重现于注册表。识别 Qubitcoin 时还要区分共用 `QTC` 的项目。[准入策略](Admission-Policy-zh) |
| SLIP-0044、Zephyr、Alephium、Quantus、Xelis | 默认要求有依据的 coin type。Zephyr 有明确记录的 XMR 128 例外，同路径复用花费和查看密钥。Zephyr 的普通 ZPH 转账、Alephium 的 P2PKH 转账和 Quantus 的透明余额转账有原生审阅与签名。Xelis 有原生恢复、地址和签名原语，保密余额同步、转账证明和生产托管待完成。[逐链能力](Supported-Chains-zh) |

## 图二　钱包和外设

原图二，338 × 371；待恢复文件：`Review-Wallet-Features.png`。

| 项目 | 当前实现 | 待验收或实现 |
| --- | --- | --- |
| FIDO2 | CTAP HID 分帧、取消和超时，ES256 已知答案测试 | CTAP2 命令、凭据持久化、PIN/UV、浏览器注册和登录 |
| 摄像头和二维码 | 已验证 OV9281 探测、二维码输出和分片重组。ZXing 从中英文收款页的三个滚动位置、三种采样尺寸均读回预期地址。双向配对签名记录通过 Node／原生互操作。[66 个状态的中英文画面](UI-Gallery) | 实板 CSI 收流、配对挑战显示、二维码解码及摄像头扫码至完整交易导入 |
| NFC | PN7161 与屏幕共用 GPIO7/8/9，独立片选。主机覆盖手机离场撤销审阅、Type 4 标签备份读取、取消及恢复手机 APDU。 | 实物标签读取、手机配对、场强变化、共享 SPI 刷屏期间的延迟 |
| TOTP | 会话账户、设备确认校时与屏幕显示验证码 | 可信 RTC、安全持久化、脱离主机的完整管理 |
| Ryo | 官方校验器识别标准地址和子地址。手机侧验证资金归属、金额承诺及带签名的 key image 后构建 v3 付款。主机固件审阅收款、找零、费用和 payment ID，验证 Bulletproof，经一次性模拟按键批准后签名。官方 `ryod` 在隔离分叉确认两笔付款，收款方均已扫描。[交易与区块](validation) | 发布钱包禁收，待完成签名准入。实物面板批准、卡内生成带签名的 key image、卡内交易签名及手机到主网的端到端广播待验收。 |
| Zano | 官方节点接受手机派生的地址。手机验证了两笔已有主网 v4 付款的全部证明，也为两笔新的原生资产付款生成了资产成员、范围聚合、Bulletproof+ 和余额证明。主机固件核对收款人、找零、费用及 payment ID，模拟批准后签署三个输入。两笔付款均在隔离测试链入块。[交易回执](validation) | 发布钱包禁收，待完成签名准入。实板按键批准、卡内生成 key image 及签名、实机签名后的手机广播和 GGXXG 质押仍待验收。 |
| Xelis、Beam | 各自已有的密钥、地址或交互付款组件见图一 | 从真实链状态发现可花余额、同步恢复、卡内托管和完整节点交互 |
| NFT、兑换、质押和 DApp | Chromium 页面发现 Ethereum provider 后发起 ETH、Lido、Uniswap V2、ERC-721 四笔交易，本地 Anvil 分叉全部执行成功。Solana LiteSVM 有 8 笔执行记录，含单发行量 SPL 转账、原生质押与指定兑换程序 | 任意合约语义、跨链批量调用、全部 NFT 标准和实体手机付款均需单独验收。[账本回执](validation) |

## 图三　生产和恢复

原图三，328 × 265；待恢复文件：`Review-Production.png`。

| 项目 | 当前证据与缺口 |
| --- | --- |
| 备份、恢复、迁移、销毁 | 主机创建与导入支持英文 BIP39 助记词和最长 128 字节的 ASCII passphrase，公开 `TREZOR` 种子向量通过。SE051 主机测试已核对对象间 PBKDF2 命令字节。本机助记词输入、受保护的 BIP32、BIP38 和换卡恢复待完成。模拟分区迁移保留凭据，QRL 在已有密钥丢失 XMSS 索引日志时拒签。[安全芯片](Secure-Element-zh) |
| 工厂 provisioning | 已有 SCP03 与部分 applet 命令。每台设备唯一密钥的安全注入、备份与实卡不可导出派生和签名仍待接通。[安全芯片](Secure-Element-zh) |
| 发布和升级 | 空板镜像恰为 8,388,608 字节，双 OTA 之外有 24 MiB `assets`。可校验 ELF 摘要并模拟断写。生产签名发布、独立可复现构建、升级密钥管理和实机防回滚仍待验收。[构建与刷写](Build-and-Flash-zh) |
| 长期负载 | 有主机 ASan/UBSan 测试、UI 回归、SPI 驱动和空闲休眠逻辑。实板长时堆增长、任务栈峰值、PSRAM 余量、温度、电流及电池续航均无测量结论。 |
| 真实资产 | 当前 SDK 配置未启用 Secure Boot、Flash Encryption 或 NVS Encryption。生产会话拒绝开钱包。逐链向量与本地节点回执只覆盖各自测试的交易。 |

## 图四　安全边界

原图四，333 × 243；待恢复文件：`Review-Physical-Security.png`。

| 项目 | 当前证据与缺口 |
| --- | --- |
| 解析器与链路 fuzz | Ryo 的四个序列化夹具各有全截断检查、10,000 次确定性变异和 1,000 组随机输入。链路有帧和状态机回归。跨解析器及传输的持续覆盖引导 fuzz 尚无验收记录。 |
| 形式化验证 | 有已知答案、独立实现比对和节点回执。项目未提供形式化证明。 |
| MCU 常量时间 | 秘密值比较、部分曲线运算及中间值清零已有实现。全部大数路径的常量时间性质及实物侧信道仍未验证。 |
| 故障注入 | 尚无整机电压、时钟等故障注入防护的验收证据。 |
| 屏幕与 SE 总线 | 屏幕 SPI 缺少密码学完整性。SE 的 SCP03 实现含双向 MAC 与加密，经过主机向量验证；目标实卡上的密钥置备、认证及生产端到端执行仍待验证。 |
| NFC 中继 | 配对身份与帧认证绑定对端，本地按键绑定交易批准。物理距离与抗中继能力未验证。 |
| NVS PIN verifier | 使用带盐 PBKDF2 和在线重试退避。若可读取 verifier，仍有离线猜测风险；诊断 SDK 的 NVS 加密关闭。 |
| 胁迫 | 未实现胁迫 PIN、隐藏钱包或合理否认流程。 |
| 认证 | 无整机 FIPS、Common Criteria 或第三方硬件安全认证记录。独立第三方安全审计仍缺。[威胁模型](Threat-Model-zh) |
