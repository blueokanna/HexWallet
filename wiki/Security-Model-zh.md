# 安全模型

[English](Security-Model) · [首页](Home-zh)

这一页只写代码真正强制的东西，以及它在哪里强制。每一行都点名实现文件；文件改了，这一页就是错的，
必须跟着改。

## 资产与边界

| 资产 | 存放位置 | 会离开设备吗 |
| --- | --- | --- |
| BIP39 助记词 | `WalletSession`（仅 host 测试构建） | 不会 |
| 种子、BIP32 节点、私钥 | 栈上的 `SensitiveValue<T>` | 不会 |
| PIN 校验值 `PBKDF2-SHA256(PIN, salt)` | NVS | 不会 |
| 审查文本与批准状态 | RAM + 屏幕 | 只以被签名的载荷形式离开 |
| 链路身份密钥（Ed25519） | NVS | 配对时只给公钥 |
| 已签名交易 | 调用方缓冲区 | 会，这就是产品输出 |

信任边界：MCU 可信；主机、手机，以及从串口/USB/NFC/蓝牙进来的一切都是不可信输入；屏幕和按键只有在
审查封印证明"这一帧已经提交"且"这次批准还没被用过"时才可信。

## 控制项

| 控制项 | 实现位置 | 行为 |
| --- | --- | --- |
| 密钥不可导出 | `WalletConfig.h` | 定义 `HEXWALLET_ENABLE_SECRET_EXPORT` 直接 `#error`，没有运行时路径 |
| 身份认证 | `WalletCli.cpp` | PIN 8–64 字符；verifier = PBKDF2-SHA256，12 万轮，32 字节随机盐；解锁 = `HMAC-SHA256(verifier, nonce)` 常量时间比较；证明错误会清空所有挂起审查和钱包会话 |
| 失败退避 | `WalletCli.cpp` | 失败次数写入 NVS；延迟 `1 s << 次数`，上限 10 分钟；退避期间 `auth begin` 直接拒绝 |
| 会话寿命 | `WalletCli.cpp` | 空闲 5 分钟；`lock` 立即生效；两者都会清掉助记词和挂起审查 |
| 传输策略 | `WalletTransportPolicy.cpp` | 任何传输上的签名/批准都要求"已认证 + 可信显示"；主机确认只在串口、且只有编译期打开时才存在 |
| 审查完整性 | `TrustAnchor.cpp` | `ReviewSeal` 对实际渲染的文本做哈希，只有面板报告帧已提交才武装，一次即废，随审查一起过期 |
| 批准有效期 | `WalletSigning.cpp`、`WalletCli.cpp` | 120 秒；过期即清会话；被拒绝的审查不能翻回"已批准" |
| 批准消耗 | `WalletSigning.cpp` | 先消耗批准，再解封密钥；之后失败也不会恢复批准 |
| Dash 手续费可计算 | `DashTransaction.cpp` | 每个输入必须带资助交易；txid、输出序号、金额、脚本全部重新证明，手续费从被证明的值算出来，而不是采信主机。没有证明的旧载荷返回 `missing-field` |
| 输出清零 | `SensitiveValue.h` | `SigningOutputGuard` 在生产者没有提交合法非零长度时清零调用方缓冲区 |
| 托管门禁 | `WalletCustody.cpp` | 五个事实全部成立才算数；缺哪个就返回哪个 `CustodyBlocker`，没有静默降级 |
| 启动信任 | `TrustAnchor.cpp` | `HEXWALLET_REQUIRE_VERIFIED_BOOT=1` 时，安全启动或 Flash 加密关闭就拒绝签名；"读不到"和"关着"分开报告 |
| 随机数 | `RandomSource.cpp` | 逐块健康测试 + HMAC-SHA256 DRBG；熵块失败会在本次开机内锁死钱包 |
| 一次性签名 | `QrlOtsJournal.cpp` | 签名前把 OTS 叶子写进两个冗余槽并回读验证；写坏的槽跳过；状态不明就拒绝 |
| 没有网络栈 | `tests/host/policy_check.ps1` | 固件文件一旦 include WiFi/HTTP/TLS/lwIP/esp_netif 头，构建直接失败 |

## 密钥处理

- BIP39：24 个英文单词，256 位熵，空口令。词表编译进固件（`word_list.h`），不下载、不切换语言。
- BIP32：先硬化账户层，再走各链自己的路径。每次派生都写进 `SensitiveValue`，中间值全部清零。
- 曲线运算跑在 worker 任务上，UI 不会卡死；worker 持有的是借用指针，所以调用方绝不能提前返回
  （见 [架构](Architecture-zh)）。
- 清零用 `mbedtls_platform_zeroize`（host 上是等价实现），不会被优化掉。
- 助记词缓冲 256 字节；超长导入在写入任何数据之前就被拒绝。

## 显示与批准

批准不是一个由调用方置位的布尔量，它只能由面板回调产生：

1. `wallet_ui_show_transaction()` 渲染审查文本，并对文本建立 `ReviewSeal`。
2. 面板驱动报告这一帧已提交，封印才被武装。
3. 用户按下 `APPROVE`，回调把会话标成已批准。
4. `wallet_signing_sign()` 重新检查封印（新鲜、匹配、未使用），消耗它，然后解封密钥。

所以没有屏幕的构建没有批准来源。串口签名只有在编入 `HEXWALLET_ALLOW_HOST_ONLY_CONFIRMATION=1`
时才可能，而且只限串口；手机链路仍然拒绝，因为"自己批准自己请求"的手机不是可信显示。

## 审查行就是契约

适配器填一个 `ChainReview`，屏幕渲染它，批准动作把它封死。这三步之间有两种会亏钱的失效模式，
它们都在 `ChainTransaction.cpp` 里统一关掉，而不是交给 25 个家族各自记得：

- `chain_review_transaction()` 会拒绝 `symbol`、`recipient`、`amount`、`fee` 任一为空的审查。
  空的 recipient 在屏上就是一行空白，用户完全可以在上面按批准；而签名路径会重新审查并比较两个
  空字符串——它们相等，于是批准就通过了。
- 某个字段把缓冲区填到最后一个字节，一律当作被截断并拒绝。`snprintf` 是静默截断的，而"地址被
  截断"是这台设备唯一无法挽回的错误。136 字节足够放下所有已准入的地址形式（最长的是 Cardano
  Shelley base，103 字节），所以顶到上限就是 bug，不是长地址。

这条闸门由 `run_chain_self_tests()` 钉住：它接受完整审查，逐个清空字段必须被拒，135 字节的
recipient 被拒而 134 字节被接受。

## 供电与签名面

一笔签名是这台设备最费电的动作：射频、屏幕和 MCU 同时拉电流，真正结束会话的是一个快没电的电芯在
这一瞬间的压降。所以这个决定由 `BatteryMonitor.cpp` 统一持有，而不是散落在各个适配器里：

- ADC 最多每 5 秒采一次，进五格环形缓冲，等级取**中位数**——USB 插入或屏幕刷新带偏的一次转换
  不会改变结论。
- `Critical`（≤ 3350 mV）在 `wallet_transport_allows()` 里同时关掉 `SigningRequest` 和
  `ApprovalResponse`，对所有传输都一样；只读操作保持开放，`status` 和目录照常回答。
- 回升要高出阈值 60 mV 才升级，没有这个回差，压在阈值上的电芯会在 ADC 噪声里来回跳。
- 没有分压电阻的板子报 `Unknown`，而 `Unknown` 从不阻止签名——USB 供电的设备不能因为看不见电池
  就拒绝干活。
- `status` 会打出 `battery=<mV> <level>`，被拒绝的原因不用接调试器就能看到。

屏幕空闲熄屏**没有**实现。AMOLED、墨水屏和 TFT 的电源轨行为各不相同，必须在硬件上验证；假定它
能用，比不做更糟。

## 安全芯片现状

SE051 这条路径实现到"认证通道 + applet 命令"为止，并用 mock 传输做过测试。它**不是**签名后端：
`secure_custody_backend_ready()` 为 false，因为 `wallet_uses_handles` 为 false——派生和签名仍然需要
MCU RAM 里的明文种子。设备默认 `HEXWALLET_REQUIRE_SECURE_CUSTODY=1`，此时 `WalletSession` 编译成
一律拒绝，所以现在的设备固件无法生成、导入或使用钱包。

这是有意为之。种子在 RAM 里却对外宣称"安全芯片托管"，比老老实实说没做完更糟。

## 验证过的内容

| 断言 | 对应测试 |
| --- | --- |
| 密码学原语与 KDF | `tests/host/build.ps1`（`crypto-primitives`、`bip39`、`bip32` 等） |
| 策略层拒绝 WiFi/TLS 头 | `policy_check.ps1` |
| 传输矩阵 | `run_transport_policy_self_test()` |
| 托管阻塞项顺序 | `run_custody_self_tests()` |
| 随机数健康规则与 DRBG 分离性 | `run_random_source_self_tests()` |
| 审查封印一次性 | `run_trust_anchor_self_tests()` |
| 失败时输出缓冲被清零 | `host_test_main.cpp` 里的签名测试 |
| QRL 一次性索引预留 | host 套件中的 `qrl-ots` 检查 |

套件全绿只证明代码符合这些测试，不证明能挡住物理攻击，也不证明网络会接受这笔交易。这些边界写在
[威胁模型](Threat-Model-zh)。
