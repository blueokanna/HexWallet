> 2026-10-24：MSR 已移除，不再接受地址或签名请求。下文 MSR 段落仅保留为历史协议记录；不代表当前支持。SOL 使用 kind=6，详见 [solana-signing.md](solana-signing.md)。

# XMR / MSR 签名与离线边界

## 设备不联网

硬件只通过 NFC 或用户主动开启的 USB 数据通道接收候选交易，在本机审阅并签名。区块下载、节点查询、广播和节点验收由手机或电脑完成。固件没有 WiFi/HTTP/以太网客户端；PC 侧开发工具访问参考实现或节点，不属于固件联网能力。

## 现在开放的路径

`WalletCatalog` 已开放 XMR 与 MSR 的地址、审阅和签名。链路使用 `BEGIN_SIGN` 的 `kind=5`，请求体携带序列化交易、交易密钥、每个输入的本机输出位置、ring、key offsets 与主机提供的伪输出掩码。请求上限 16 KiB。

审阅通过后：

- 屏幕显示每个输出的金额与地址、找零、手续费和总支出；
- 屏幕明确注明 ring 诱饵由手机提供、离线设备无法证明其链上存在；
- 用户必须按设备上的 APPROVE，手机不能代替按键；
- 签名只在这次批准后执行一次，随后会话清零。

## 地址与签名密钥必须同源

地址派生使用 BIP32 子密钥作为 CryptoNote 种子：

```
m/44'/128'/0'/0/<address_index>  -> child.private_key -> Hs() -> spend, Hs(spend) -> view
```

签名也必须使用同一个子密钥。早期实现直接从 BIP39 种子派生签名密钥，会导致屏幕地址与签名密钥不一致；现在 `derive_cryptonote_keys()` 复用 `derive_address()` 的同一条路径。

### 子地址消费

XMR 子地址已开放消费：

```
m               = Hs("SubAddr" || a || major || minor)
spend_secret    = b + m
spend_public    = B + m·G
view_public     = a·spend_public        (Monero 的 C = a·D)
```

- 每个输入携带自己的 `(major, minor)`，设备用该子地址的 spend secret 派生一次性私钥并签名；`(0,0)` 就是标准地址，路径不变。
- 当前仅允许向标准地址发送和找零。子地址发送需要绑定 `R = rD` 或每输出的附加交易公钥；原来的公钥所有权检查没有覆盖这一点，现已拒绝这类请求，避免签出收款方无法扫描的输出。
- `cryptonote_subaddress_keys()` 的输出与地址编码器 `cryptonote_subaddress_public_keys()` 在同一自检里交叉验证，并对齐 Monero 固定的子地址地址向量 `8AGiXjGVUbB7…`(0,1) 与 `8AGDdrcnAd7R…`(1,0)。
- 自检还证明：用标准 spend secret 无法对子地址输出签出有效 CLSAG（`cryptonote_clsag_sign` 内部要求 `p·G == dest`），只有 `b + m` 可以。
- Masari 的子地址输入采用相同的密钥派生；子地址发送和子地址找零同样关闭，等待独立的交易公钥与接收扫描回归。

## Monero（XMR）

- RCT type 6、CLSAG、Bulletproofs+、16 成员 ring。
- 每个输出：一次性公钥、8 字节金额密文、view tag、承诺全部重算；显示金额是承诺的输入。
- 每个输入：本机输出在 ring 中的位置、一次性密钥、承诺、key image 全部重算。
- `pseudoOut_i == commit(c_out_i, amount_i)`，`Σ pseudoOut == Σ outPk + fee·H`。
- CLSAG 辅助 key image `D = z·Hp(P)/8` 与线上字节比对。
- ring offsets 必须与序列化交易逐字节一致且严格递增。
- 手续费上限 `HEXWALLET_XMR_MAX_FEE_ATOMIC`（默认 0.1 XMR）在任何曲线运算前拒绝超限。

### CLSAG 消息哈希

`Keccak(prefix_hash || rct_base_hash || proof_fields_hash)`

`proof_fields_hash` 按 Monero v0.18.4.0 `get_pre_mlsag_hash` 的顺序包含每个 BP+ 的 A、A1、B、r1、s1、d1、L、R；不加入向量长度、V 或 pseudoOut。这是共识消息构造，**不是 BP+ 证明验证**。

### 签名前不变量

- 全部输入的 key image 与 key offsets 必须在任何一个输入签名前确定；签名函数核对既定 key image，不在签名途中修改 prefix。双输入回归用最终 prefix 校验两个签名，避免单输入自测掩盖问题。
- 构造器要求传入已经确定的证明字节；不能先生成 CLSAG 再补证明。
- `CryptoNoteSpendInput` 含设备内部秘密，不是手机请求格式，禁止直接把手机输入反序列化成该结构。手机格式由 `cryptonote_signing_prepare` 独立解析并核验所有权后才生成内部结构。

## Masari（MSR）

Masari 使用自己的历史 RCT 枚举与 legacy ECDH，不能复用 type-6：

| 类型 | 范围证明 | 签名 | 状态 |
| --- | --- | --- | --- |
| 1 RCTTypeFull | Borromean | 全输入一个 MLSAG | 已实现 |
| 2 RCTTypeSimple | Borromean | 每输入一个 MLSAG | 已实现；用上游真实 TX2 向量验证 Borromean |
| 3 RCTTypeBulletproof | Bulletproofs | 每输入一个 MLSAG | 验证器已实现；默认 `HEXWALLET_MSR_ENABLE_RCT_TYPE3=0`，缺主网向量时返回 `unsupported` |

类型 3 的验证器不是“写完就算”：它必须有链上向量才能启用。流程是

```
python tools/fetch_masari_bulletproof_vector.py --hash <txid> --url <masari-daemon>
```

该工具把节点返回的原始交易写成 `tests/fixtures/masari/tx3.bin` 与 `tx3.json`（记录 txid、来源与 SHA-256）。主机自检一旦看到这个文件就会解析它、校验其中的标准 Bulletproof，并要求单字节篡改被拒绝；没有文件时自检反而要求 type 3 继续 fail-closed。通过后才用 `-DHEXWALLET_MSR_ENABLE_RCT_TYPE3=1` 构建发行固件。

legacy ECDH 为标量加法：`mask + Hs(shared)`、`amount + Hs(Hs(shared))`，不是 ChaCha8，也不是 compact amount。MLSAG 消息为 `Keccak(prefix_hash || rct_base_hash || proofs_hash)`。手续费上限 `HEXWALLET_MSR_MAX_FEE_ATOMIC` 默认 0.1 MSR。

## 性能（可信数字，不夸大）

Bulletproofs+ 验证是审阅阶段的主要成本。`mn`（填充后的标量数量）为 `64 * next_pow2(输出数)`，与 Monero 一致：16 个输出对应 1024 项多指数运算，2 个输出对应 128 项。

主机实测（x86-64，MSVC `/O2`，`bp_plus_probe.exe --bench`）：

| 输出数 | rounds | `mn` | 单证明耗时 |
| --- | --- | --- | --- |
| 1 | 6 | 64 | 67 ms |
| 2 | 7 | 128 | 127 ms |
| 16 | 10 | 1024 | 932 ms |

两项优化把耗时降到原来的约 1/2.2，且结论都通过了 8 份参考证明、真实主网证明与全部篡改测试：

- `point_mul8` 改为扩展坐标下三次倍增（`ed25519_point_mul8_compressed`），一次求逆代替五次；每个 BP+ 生成元都要用它。
- 验证器用扩展坐标累加 + 3 位窗口（`ed25519_extended_add_scaled`），每项不再求逆、不再反复重编码点；窗口表只有 2.5 KiB，验证器整体仍能装进调用方栈。

Bulletproofs+ 验证需要约 7 KiB 栈，接近 Arduino 主循环任务的 8 KiB 上限，因此 CryptoNote 审阅在 24 KiB 的加密 worker 任务上执行（`wallet_worker_begin` / `wallet_worker_wait`），LVGL 更新仍留在调用任务上（LVGL 不是线程安全的）。

尚无这块 ESP32-P4 实机的延迟、栈水位和看门狗数据，不能从主机成绩推算设备性能。审阅与签名均在加密 worker 上执行；调用任务轮询完成状态、刷新 LVGL 并让出 CPU，不处理新的主机请求。启动 worker 失败会拒绝请求，不回退到较小的主循环栈。

任务超过截止时间后，结果失效；调用方仍等到任务实际结束才清除它借用的请求、密钥和缓冲区，避免超时导致悬空指针。超时签名的输出会清零并拒绝返回。此处不是强制取消：如果 worker 不结束，仍需硬件看门狗/复位策略，不能宣称已完成异常实机验收。

## 仍然存在的边界

- **诱饵真实性**：设备能证明 ring 内部一致、包含本机输出、offsets 与交易一致，但无法证明诱饵真的在链上。离线签名器没有链访问；手机只被信任“提供活跃诱饵”，永远不被信任金额、手续费或目的地址。设备额外强制：同一 ring 内成员不得重复、不同输入的 key image 不得重复。
- **Masari type 3**：验证器已实现且默认关闭；用 `tools/fetch_masari_bulletproof_vector.py` 取到主网向量并通过自检后才可启用。
- **子地址目的地址/找零**：XMR/MSR 均拒绝；子地址输入消费与目的地址构造是不同路径。
- **主网接收验收**：本地审查/签名回归不等于全节点会接收；广播后仍需手机侧节点验收。

## 自测

- `run_cryptonote_review_self_tests()`：13 类篡改拒绝。
- `run_cryptonote_signing_self_tests()`：完整请求 -> 审阅 -> 逐输入 CLSAG -> 序列化 -> 验证，另含子地址消费路径（与固定的 Monero 子地址向量交叉验证）。
- `run_masari_self_tests()`：MLSAG 签名/验证、legacy ECDH 解码、真实 TX2 Borromean、type-2 端到端审阅/签名，以及 type 3 的 fail-closed 门禁（有向量时必须通过并拒绝篡改）。
- 主机 `tests/host/build.ps1` 与设备 `device_compile_check.ps1` / `p4_runtime_compile_check.ps1` 都必须通过。

不要把 `cryptonote-signing=pass` 或 `masari=pass` 解释为主网收发已验收。

来源：[Monero v0.18.4.0 rctSigs.cpp](https://github.com/monero-project/monero/blob/v0.18.4.0/src/ringct/rctSigs.cpp)、[masari-project/masari](https://github.com/masari-project/masari)。
