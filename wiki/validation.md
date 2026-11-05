> Dated validation log. Kept as the evidence trail; entries are not rewritten.

# HexWallet - validation

最新本地回归及未验收边界见 [2026-10-31 生产签名补齐记录](hardening-2026-10-31.md) 与 [2026-10-31 代币登记与自定义代币](hardening-2026-10-31-tokens.md)。历史记录保留当时运行范围，不代表后续修改自动通过。

## 2026-11-01：Groestlcoin 锚定交易取证（结论：先要 Groestl-512）

- 取到一条真实主网交易做锚，块高 6323381，txid
  `e32bec4eaeccf21bb5dd88b8ec9c582374a111e5dc82b84d1e4d60bfceadcffd`：1 个 P2PKH 输入
  （`scriptSig` 带 DER 签名 + `02a7863e…` 压缩公钥，SIGHASH_ALL），输出 25.18313539 GRS 到
  `Fa5oaNLoshov4C6HtcnwVYnGamYJ7qXN9W` 与 109.63742195 GRS 到
  `grs1qj0w0z9ggm50nw74xzyclf3m4xp7wyqyp3hzrs4`，`locktime` 6323380。
- 本想把这条交易当作地址层 KAT 落进 `run_network_profile_self_tests()`，实测直接否掉了这个
  方案：把该输出的 hash160 用双 SHA-256 做 base58check（版本 0x24）得到
  `Fa5oaNLoshov4C6HtcnwVYnGamYJ7qnnEn`，链上是 `…J7q**XN9W**`。Groestlcoin 把校验和与
  txid 的哈希换成了**双 Groestl-512**，因此连地址渲染都依赖这个哈希。
- 结论：注册表里没有留 GRS。加一个用 SHA-256 校验和的 GRS 地址会生成链上不存在的地址，
  比"暂不支持"危险得多。改动已整体回退，`networks=pass`、`catalog=pass`。
- 下一步只需补 `Groestl512.cpp`（P/Q 各 14 轮、1024-bit 状态），用上面这条交易的
  `scriptSig` 验签作为验收：sighash 算错、序列化错、哈希错，三种情况都会验签失败。
  锚定交易与期望地址已写入 [chain-support.md](chain-support.md)。

## 2026-11-01：airgap 传输状态机（发送/接收/重扫）落地

- `AirgapFrame` 之前只有帧格式和计划枚举，没有"谁来驱动动画"。本轮补上两端状态机：
  - `AirgapSender`：按 blob 哈希派生计划索引，切块，逐帧渲染。chunk 数与帧数会一起收缩直到
    存在合法计划（小 blob 不会要求超过它能填满的帧数）。
  - `AirgapReceiver`：第一帧定计划（unrank 校验分组和等于 chunk 数），其余帧按 chunk_index
    落到计划区间；乱序、重复扫描、中途漏帧都能处理，重复帧是幂等的，缺帧时
    `airgap_receiver_next()` 直接给出该重扫的帧号。
- 两处帧头字段是被实测逼出来的，不是设计洁癖：
  - `max_group` 必须上线。同一个 `plan_index` 在不同上界下表示**不同**分组，接收端无法从索引
    反推上界，早期版本因此永远解不出计划（`airgap_plan_count` 直接 `OutOfRange`）。
  - `chunk_bytes` 必须上线。首帧可能携带 4 个 chunk，用"首帧 payload 长度"当 chunk 大小会得到
    76 而真实值是 19，随后每帧都被判成截断。帧头因此从 24 字节变为 26 字节，CRC 覆盖到它。
- 自检覆盖：300 字节 blob（不能被 chunk 数整除，末块短）的正序/逆序重组、丢第 2 帧后按提示
  补扫、重复帧幂等、异号 blob_tag 拒绝、CRC 损坏拒绝且不破坏已接受状态、计划外的 chunk_index
  拒绝、5 类参数边界。`airgap=pass`。
- 回归：`build.ps1` exit 0；`device_compile_check.ps1 -Target esp32p4` 全源通过；
  `policy_check.ps1` pass。

## 2026-11-01：Groestlcoin 取证（txid 之谜解开，地址校验和仍缺）

按官方规范文档（`http://www.groestl.info/Groestl.pdf`，3.4.4 与 3.4.6 节）核对了自己写的
Groestl 原型，抓到两处真实偏差：

- **ShiftBytes 表用错了**。规范里短变体（8 列，摘要 ≤256）用 `P=[0,1,2,3,4,5,6,7]`、
  `Q=[1,3,5,7,0,2,4,6]`；长变体（16 列，摘要 >256）用 **ShiftBytesWide**
  `P=[0,1,2,3,4,5,6,11]`、`Q=[1,3,5,11,0,2,4,6]`。我一开始把 wide 的
  `[1,3,5,11,…]` 当成了两种变体共用的 Q 表，于是 512 位的 P 少了 `11`、256 位的 Q 把
  `11 mod 8 = 3` 当成了 `7`。
- **漏了输出变换**。`Ω(x) = trunc_n(P(x) ⊕ x)`，我原来直接取了链值。

改掉之后仍未复现链上数值，所以 `grs`/`grs49`/`grs84` 没有进注册表，`kUtxoGroestl` 也已删除。

同时用一条真实主网交易（块 6323381，txid `e32bec4e…dcffd`）做了一次决定性测量：

| 假设 | 结果 |
| --- | --- |
| `txid == SHA-256(raw_tx)` 反转 | **成立** |
| `txid == SHA-256d(raw_tx)` 反转 | 不成立 |
| `txid == BLAKE2b-256(raw_tx)` 反转 | 不成立 |

256 位对上不可能是巧合，所以 **Groestlcoin 的交易哈希是单次 SHA-256**，legacy sighash 仍是
Bitcoin 那套（`SHA256d`）。这推翻了我上一轮"txid 用双 Groestl-512"的判断。

仍然阻塞的是 base58check：真实地址反解得 `version=0x24`、`hash160=35ead48b…16fc43`、
校验和 `b77ec511`；`sha256`/`sha256d` 的首/尾、正/反四种截断分别是
`56541b08`/`b7fc49cd`/`b7aca9fb`/`eaa3c044`，都不匹配。也就是说 Groestl-512 只用于地址
校验和这一处，但必须是已验证的实现。等在规范文档里拿到附录测试向量再落 `Groestl512.cpp`。

## 2026-11-01：airgap 分帧器（枚举帧索引）、Kava 拆分与 Cosmos 表校验

- `AirgapFrame.cpp`：分帧头（magic/version/blob tag/plan index/chunk index/chunk count/
  CRC-32）与**枚举帧索引**。帧计划定义为把 `chunks` 拆成 `frames` 个非空组、相邻组相差
  ≤1 的有界合成：连续帧的符号密度不会突变，摄像头不用反复拉风箱找对焦。计数用精确 64 位
  DP，溢出即 `CountOverflow`，不截断——截断会破坏 rank/unrank 的双射。`airgap=pass`：
  - 穷举证明双射：`chunks=6, frames=3, max_group=3` 逐索引 unrank→rank 回到原索引，
    总数与手写三重循环的暴力计数一致；
  - 64×8×6 的宽空间做中点取值往返；
  - `IndexOutOfRange`、`OutOfRange`、`EmptyPlanSpace`、非法参数、步长为 2、和不对齐，
    六类拒绝；
  - 帧头在 `frame_size` 内**逐字节翻转**都必须被拒（CRC 覆盖头部与载荷）；
  - 计划索引由 `SHA-256(seed‖blob_tag‖counter)` 做拒绝采样得到，避免取模偏置，且同一
    (种子, 标签) 必然得到同一索引——索引不上线传输。
- Kava 拆分：EVM 侧改名 `kavaevm`（chain 2222，仍在 EIP-1559 名单），Cosmos 侧新增
  `kava`（`kava_2222-N`、`ukava`）。之前 `kava` 同时想当两个东西，结果只有 EVM 能用、
  Cosmos 侧根本调不到参数表。
- Cosmos 新增 `terra`（`phoenix-N`、`uluna`，BIP44 330）与 `terraclassic`（`columbus-N`、
  `uluna`）。三者的 bank `MsgSend` 编码与 atom/osmo/tia 完全一致，差别只有 bech32 前缀、
  chain-id 前缀和显示 denom，所以是参数而不是新代码路径。
- 新增 `cosmos_chain_table_is_consistent()`：参数表的 id 必须能在网络注册表里找到且
  `Bech32Cosmos` + hrp 一致，hrp 只能小写字母数字，denom 非空，decimals ≤ 18，id 不许重复，
  (denom, chain_prefix, decimals, symbol) 组合不许撞车。这类错误以前只会表现为"某条链的地
  址前缀莫名不对"。
- 回归：`build.ps1` 全项通过（新增 `airgap`；`cosmos`、`networks`、`catalog` 均 pass）。

## 2026-11-01：SE051 安全通道、曲线装载编排与 EVM 网络补登记

- `Se051Scp03.cpp`：SCP03 全链路实现（AES-CMAC KDF、卡/主机 cryptogram、命令包裹与
  C-MAC、响应 R-MAC 校验与解密、链值与计数推进、失败即清会话）。`SecureElementPort` 补
  AES-128 逆密码（`aes128_decrypt_block`），自检里用 FIPS-197 C.1 的加密向量做双向验证。
  `build.ps1` 输出 `scp03=pass`。
- 对照值来自独立的纯 Python AES-128/CMAC 实现（先用 FIPS-197 C.1 与 RFC 4493 自证），钉死
  S-ENC/S-MAC/S-RMAC、两个 cryptogram、一条 21 字节命令的密文与 C-MAC、一条响应的 R-MAC；
  另有篡改 R-MAC、截断响应、超长数据、无会话包裹、缓冲不足五类拒绝路径。
- `Se051Provisioning`：把 `0x6A80`/`0x6A88` 归类为"曲线未装载"，只允许装载一次 + 重试一次，
  重试再报缺曲线即判死；其它状态字不触发装载。`se051-provisioning=pass` 覆盖 9 种分支，
  含"回调失败"与"装载成功但重试失败"。`WriteECCurve` 的实际 APDU 属于 applet 协议，仓库里
  没有可核对来源，因此没有编造字节。
- EVM 网络补登记：`ronin`（chain 2020）、`theta`（chain 361，只能搬 TFUEL）、`acalaevm`
  （chain 787）。三者都没有进 EIP-1559 名单，只签 EIP-155 legacy——typed envelope 在拒绝它的
  链上等于一笔花不出去的签名。`networks=pass`、`catalog=pass`。
- CI：`qr_cross_check.ps1` 不再写死 `%ProgramFiles%\Microsoft Visual Studio\2022\Community`，
  改用 `vswhere`（保留 `HEXWALLET_VS_INSTALL` 覆盖）。本机跑通：
  `qr-cross-check: cases=320 matrix_mismatches=0`。
- 回归：`build.ps1` 全项通过（新增 `scp03`、`se051-provisioning`）；`device_compile_check.ps1
  -Target esp32p4` 全源编译通过（含两个新文件）。

## 2026-11-02：面板双配置、P-256/ES256 原语与认证传输边界

- 墨水屏驱动拆成两种物理模式：`EinkColorMode::Mono`（1bpp，SSD1680）与
  `EinkColorMode::FourColor`（2bpp，SSD1683 类，128×296，黑/白/红/黄）。`EinkFrame` 按模式
  给出行宽与整帧字节数，`EinkPanel` 用 `0x21`/`0x18` 打开四色窗口与内部 LUT 选择，四色走
  `0x10` RAM + `0x12` 刷新，黑白继续走 `0x24`/`0x22`/`0x20`。四色没有局刷波形，
  `partial_refresh()` 在碰 BUSY 之前返回 `PartialUnsupported`；`begin()` 见到四色 + LUT 直接拒绝。
- 局刷波形改为控制器 OTP：驱动不再向 `0x32` 写任何厂商表，`third_party/` 整个目录已删除，
  仓库内不再有第三方代码或数据文件。板子若确实需要 tuned 波形，在自己的 pins 头文件里定义
  153 字节 `HEXWALLET_EPD_PARTIAL_LUT`，驱动检测到才写。自检把原来的
  “无 LUT 必须拒绝” 换成 “无 LUT 走 OTP：不写 `0x32`、窗口与 `0x22` 模式仍然生效”。
- `src/P256Sign.h`：P-256 ECDSA 全在仓库内实现（8×32-bit Montgomery 域、全宽乘积 + REDC、
  Jacobian a=−3 点运算、double-and-add-always、RFC 6979 nonce、low-S 归一、严格 DER、签名前自验）。
  KAT 用 RFC 6979 A.2.5（P-256/SHA-256/"sample"）：`r` 与 `k` 逐字节一致，`s` 与 `n − s_RFC` 一致；
  RFC 原文的高 `s` 也必须验签通过；DER 逐字节检查最短编码（INTEGER 长度非零、无多余前导零、
  总长与 `SEQUENCE` 头一致）；篡改 `r`、零 `s`、错误摘要、私钥 `0` 与私钥 `n` 全部拒绝。
  `build.ps1` 输出 `p256-ecdsa=pass`。
- 这套自检抓出两个真 bug：`add_mod()` 在 `a+b ≥ 2^256` 时用“减模数”处理进位，正确做法是
  加 `2^256 − modulus`（可观测后果是 `3α` 少 2，公钥直接错）；签名 `s` 曾写成
  `k·(e+rd)^{-1}`，应为 `(e+rd)·k^{-1}`。两者都由 KAT 钉死，不靠人工审查发现。
- `tests/host/build.ps1` 改为在仓库根目录执行测试二进制：Masari 向量按
  `tests/fixtures/...` 相对路径打开，从 `tests/host` 启动会误报 `masari-stage=55`。
- 认证部分的实现边界（TOTP 账户表、USB/NFC 传输、CTAPHID 只到传输层、没有 CTAP2 命令）
  单独记在 [authentication-status.md](authentication-status.md)，不在这里重复宣称能力。
- 回归：`build.ps1` 全项通过（含 `eink-panel=pass`、`p256-ecdsa=pass`、`masari=pass`）；
  `build_chain_native.ps1`、`build_clang_ubsan.ps1`、`policy_check.ps1` 通过；
  `device_compile_check.ps1 -Target esp32p4` 全源编译通过。`epd_driver_compile_check.ps1`
  需要外部 GxEPD2 检出（`build/epd-deps/GxEPD2`），本机没有该目录，因此这一项未运行。

## 2026-11-02：Starknet 批量调用与跨链自定义代币

- `StarknetTransaction.cpp` 从"恰一笔 transfer"扩到 1–4 笔：calldata 布局改成
  `[N, (token, transfer, 3, recipient, low, high)*, 3N, span...]`，设备重算 `2+9N` 与载荷长度、
  要求每笔 span 为 3、行内数组与尾部 span 逐 felt 相同；第 5 笔起 `unsupported`。
  每笔一行写进 `ChainReview.calls`（target/recipient/amount/declared），
  `WalletSigning::show_chain_review` 按行渲染，不再把多笔压成一句摘要。
- 两笔批量的 v3 摘要与 r/s 签名由独立 Python 参考实现产出并钉死在 `chain.starknet`：
  `0x6cf464fb…b673b` / `0x74c2bcca…f0a2` / `0x13b96249…dc059`。
- 代币元数据：`custom_token_add("stark", <32 字节合约>, …, decimals)` 后同一笔交易的金额按记录换算
  （`1.5 USDC`），记录移除后回到 `1500000 raw`；两次的 v3 摘要逐字节相同——标签不参与签名。
- `WalletCustomTokens` 的 `standard_for_network()` 接受 `AddressEncoding::StarknetKey`，键宽固定 32 字节；
  自检里补了"20 字节的以太坊式地址塞进 Starknet 记录必须 `InvalidArgument`"。
- 拒绝路径从 14 条扩到 17 条（新增零代币地址、零调用、超过四笔）；`zero_amount` 一例改为同时清零
  行内与尾部两份拷贝，否则先命中的是 span 不一致而不是金额为零。
- 回归：`build.ps1` 输出 `chain=pass`、`custom-tokens=pass`；`build_chain_native.ps1` 输出
  `stark-derivation=pass`、`production_policy=pass`；UBSan 与 esp32p4 编译通过。

## 2026-11-02：Starknet（STRK）密码学核心与 v3 交易适配器

- `StarknetCrypto.cpp`：Stark 曲线（`p = 2^251 + 17·2^192 + 1`，`y² = x³ + x + β`）的
  8×32-bit limb Montgomery 域运算（CIOS 乘法、模幂逆元）、仿射点加/倍、固定 252 轮
  double-and-add-always 标量乘、Pedersen（SHIFT + low248/high4 四点组合与链式多元素）、
  Poseidon（Hades，8 全轮 + 83 部分轮、立方 S-box、[[3,1,1],[1,-1,1],[1,1,-2]] MDS、
  `SHA-256("Hades" + i)` 轮常数）、RFC 6979 Stark ECDSA（`r,w < 2^251−256`，不做 low-S
  归一，签名前自验）、`grindKey`、SNIP-5 合约地址、Cairo v3 `invoke`/`deploy_account` 摘要。
- 公开向量锚定：StarkWare `pedersen_params.json`（506 个常量点）的 Pedersen 向量、
  `@scure/starknet` 的 Stark key 与 ECDSA 签名向量（`0x5f49…`/`0x4e86…`）、`@scure`
  的 `hashOnElements([1,2,3])`、`starknet-rs` 的 Poseidon pair/single 向量。以上全部在
  `run_starknet_crypto_self_tests()` 内逐字节比对，`build.ps1` 输出 `starknet-crypto=pass`。
- `StarknetTransaction.cpp`：只准入 Cairo v3 `deploy_account` 与「账户 `execute` 入口 +
  单笔 ERC-20 `transfer`」两种 `invoke`。账户地址由设备按
  `pedersen_many([0x5354…4553, 0, salt, class_hash, pedersen_many([pubkey])]) mod (2^251−256)`
  现算；构造参数只接受单公钥且必须等于本机 Stark 公钥；链 ID 钉死 `SN_MAIN`。
  `invoke` 的编译 calldata 按 Cairo 序列化解析（调用数组长度=1、span=3、行内数组与尾部
  span 逐 felt 相同），因此屏上收方/金额就是摘要覆盖的 felt。
- `chain.starknet` 自检钉死：`execute` 与 `transfer` 选择子
  （`0x240060cd…c44` / `0x83afd3f4…d12e`）、账户地址、两种 v3 摘要、r/s 签名，全部由独立
  Python 参考实现（Pedersen/Poseidon/keccak 均为独立代码，且先通过公开向量）产出；
  另覆盖 14 条拒绝路径：伪造构造参数（`WrongWallet`）、未知 kind / 多公钥构造 / 非法 DA /
  错误入口 / 错误选择子（`Unsupported`）、span 不一致 / 截断 / 错误魔数（`Malformed`）、
  零金额 / 零收方（`InvalidAmount`）、零 gas 上限（`FeePolicy`）、错误钱包（`WrongWallet`
  且输出长度归零）、缓冲区不足（`BufferTooSmall`）。
- 目录/网络：`WalletNetworks.cpp` 新增 `stark` profile（BIP44、coin type 9004、
  `AddressEncoding::StarknetKey`），`WalletCustody.cpp` 新增 `StarkEcdsa` 托管方案
  （SE050/SE051 无 Stark 曲线能力，密钥留在 MCU RAM 并如实标注），`WalletCatalog.cpp`
  新增 `stark` 行，`ChainTransaction` 增加 `ChainFamily::Starknet` 审阅/签名分派。
- 金额显示策略：任意 ERC-20 的小数位无法由设备证明，因此代币金额按 base unit 原样显示并
  标注 `raw`；最大费用 `tip + Σ max_amount×max_price` 用 256 位精确十进制显示为 STRK，
  不做浮点近似。
- 派生：`tests/host/chain/chain_probe.cpp` 新增 `stark-selftest`，在真实 Mbed TLS 上按
  `m/44'/9004'/0'/0/0` 派生，校验 profile→编码器映射与 SNIP-5 地址随 class hash/salt 变化；
  `build_chain_native.ps1` 输出 `stark-derivation=pass`。主机套件的 `mbedtls_host.c` 不含
  secp256k1 曲线运算，因此 `derive_address` 在 `build.ps1` 里对任何 BIP32 链都返回
  `CryptoFailure`（ETH 同样如此），这是既有主机限制，不是本次改动引入的回归。
- 回归：`tests/host/build.ps1` 输出 `starknet-crypto=pass`、`chain=pass`
  （内含 `chain.starknet=pass`）、`catalog=pass`、`networks=pass`；
  `build_chain_native.ps1` 输出 `stark-derivation=pass`、`production_policy=pass`。

## 2026-11-01：多链自定义代币（TRON / Solana / Stellar）

- `WalletCustomTokens` 升级到 v2 记录：`network_id + standard + identifier(≤32) + issuer(32) +
  code(13) + symbol + name + decimals`。EVM 20 字节合约、TRON 21 字节账户地址（含 0x41）、
  Solana 32 字节 mint、Stellar 32 字节 issuer + 资产代码各有固定宽度，`custom_token_add`
  按网络派生标准并拒绝宽度不符的键。v1（EVM-only）blob 在加载时按原布局解析并升级，
  不需要用户重新录入。
- **TRON TRC-20**：`find_trc20()` 未命中注册表时查询自定义表；命中后 `TronTransferReview.
  token_user_declared = true`，屏上额外显示 `TOKEN NOT VERIFIED`，签名前重解析仍要求同一
  记录。自检把一条真实 TRC-20 主网向量的合约字段替换成未登记地址：无记录时
  `UnknownToken`，录入后 review 通过且 symbol/decimals 来自记录，删除后再次拒绝。
- **Solana SPL**：`solana_review_message()` 在解析 `TransferChecked` 后按 mint 查询自定义表，
  只填充分显示标签；签名仍绑定消息里的 mint/decimals。新增 `run_solana_self_tests()`：
  手工构造 legacy 消息（5 个账户、1 条 TransferChecked），校验金额/精度/mint、录入后
  `token_user_declared` 与符号、签名输出可由 Ed25519 验证、篡改金额返回 `Malformed`、
  每个截断前缀被拒绝、外部 payer 返回 `WrongWallet`。
- **Stellar 发行资产**：`stellar_review_request()` 用 issuer 原始 32 字节 + 资产代码查询
  自定义表；XDR 里的 issuer/code 仍是签名对象。自检构造一条 USDC/4 字符资产的 Payment
  XDR：未录入时可审阅且 `asset_user_declared=false`，录入后标记与标签生效，签名成功。
- 设备侧入口：`token custom-list`、`token custom-add <network> <id-hex> <symbol> <name>
  <decimals>`、`token custom-add-stellar <issuer-hex> <code> <symbol> <name> <decimals>`、
  `token custom-remove` / `token custom-remove-stellar`。
- 回归：`build.ps1` 输出 `tron=pass`、`stellar=pass`、`solana=pass`、`custom-tokens=pass`；
  `build_clang_ubsan.ps1` 与 `build_chain_native.ps1` 通过；`device_compile_check.ps1
  -Target esp32p4` 通过。

## 2026-11-01：QRL v2（ML-DSA-87）账户与动态费信封

- `MlDsa87.cpp`：FIPS 204 ML-DSA-87 的 keygen / sign / verify 全部在仓库内实现，
  只用 SHAKE-128、SHAKE-256 与普通模运算；没有 `third_party`，也没有外部 PQC 库。
- KAT：`run_ml_dsa_87_self_tests()` 用 NIST ACVP 的 keyGen tc51 校验 `pk`/`sk`
  逐字节一致，用 sigGen tc61 校验签名逐字节一致，再从签名私钥反推公钥验证 ACVP
  签名，并拒绝篡改签名与错误消息。`build.ps1` 输出 `ml-dsa-87=pass`。
- UBSan：`build_clang_ubsan.ps1` 发现并修复了 keygen 中 `t1` 借用 `y`（长度 `kL`）
  导致的越界写；修复后整套 UBSan 通过。
- `QrlV2Transaction.cpp`：严格 RLP（规范整数、无尾随字节、11 个字段）、
  `chain_id == 1`、`descriptor == 01 00 00`、空 `extra_params`、`fee_cap >= tip_cap`、
  64 字节或空的 `to`；`keccak256` 只对收到的原始字节计算，签名消息为
  `00 08 "ZOND" 01 01 00 00 ‖ digest`；签名前重建账户并拒绝不是屏上发送方的请求。
- 地址：BIP32 子私钥 → ML-DSA 种子 → `SHAKE256(01 00 00‖pk)` → `Q`+128 hex。
  两组校验和向量由独立 Python `hashlib.shake_256` 生成后在自检中钉死。
- `build_chain_native.ps1`：`chain=pass` 覆盖带真实 BIP32 的完整签名路径；
  `production_policy=pass` 现在要求 Chia 派生成功（仓内 BLS 已常时化，旧的手动禁用
  已删除）。
- 以上均为宿主机与交叉编译验证，没有连接实体钱包或广播 QRL v2 交易。

## 2026-10-31：QRL / Chia / DOT-KSM / Aptos 生产签名，EVM 任意 calldata

- `tests/host/qrl_oracle_check.ps1`：本仓库的 `qrl_xmss_sign_digest()` 与 qrllib
  `xmss_alt` 的 `xmss_Signmsg()` 在 h=4/6/10、索引 0/1/末叶逐字节相同；同一测试还验证
  了预留失败必须不产出签名、高水位只会前进。oracle 固定在同一 qrllib 提交
  （`2492c60788b47055994e5d123b02482202f38262`），`diff --exit-code` 保证没被本地改过。
- `build.ps1`：`chain.qrl` 用真实种子走完整路径——派生账户、重建 QRL 转账预映像、
  预留叶、签名、自检验签，并验证第二次签名使用下一片叶、写入失败时不释放签名。
- `chain.aptos`：地址、`RawTransaction` BCS 摘要与 Ed25519 authenticator 与
  Python `hashlib.sha3_256` + libsodium 独立实现逐字节一致；零金额、错误 chain id、
  未准入 EntryFunction、零收款、截断与“密钥不拥有该地址”全部拒绝。
- `chain.polkadot`：`DOT2` 摘要用独立 Python `blake2b` 复现；`spec_version` 不在钉死
  表内时返回 `RuntimeMismatch`。
- `device_compile_check.ps1 -Target esp32p4`：全部固件源文件（含仓内
  `Bls12381.cpp`）在 riscv32 工具链下编译通过；`QrlOtsStore.cpp` 另以 `-DARDUINO`
  的真实 Arduino 包含集编译，证明 NVS 分支可构建。
- `p4_runtime_compile_check.ps1`：WalletSigning / LinkService / CLI / 草图对真实 P4
  头文件编译通过。
- 以上都是主机编译与自检通过，**没有**连接实体钱包、没有广播交易，也没有对主网
  runtime 做在线校验。

## 2026-10-29：access list、安全托管边界与显示修正

- `evm_access_list_check.ps1`：201 项检查通过。六组有效交易与 ethers 6.15.0
  的完整签名和摘要一致，另含完整审阅文本、结构错误、截断、变造与输出清零检查。
  具体协议边界见 [EVM access list](evm-access-lists.md)。
- `build.ps1`：退出码 0，含密码核心、链解析、托管、宠物行为和 QR 自检。
  该套测试使用 host crypto shim；原生 Mbed TLS 的 chain-selftest 和 EVM 独立向量另行通过。
- P4 核心编译、真实 P4 Arduino 签名编排编译，以及六种板型的真实 LVGL 9.5
  头文件编译通过。编译成功不代表已经完成固件整包链接、真实显示或烧录测试。
- `policy_check.ps1`：143 个 graveyard 身份、五张注册表检查通过，名单日期仍为
  2026-10-23。递归扫描漏检和缺少生产策略二进制时错误放行的回归检查通过。
- NXP 固定版本的 Arduino Wire 端口已通过故障注入单测和 P4 编译；这不包括
  实际 SCP03 配钥、applet 会话或非导出钱包密钥托管。详见 [SE051 状态](se051-integration.md)。

单色 QR 和宠物缓冲都为调色板保留八字节，像素跟随实际 stride。宠物素材由
`pack_maid_sprite.ps1` 转为八张 64×64 位图，确认和拒绝交易均不影响亲密度。
新增加的 Node 脚本只用于复现独立 ethers 向量，正常测试与固件都不依赖 Node。

> **Tooling note (2026-10-28).** The Python/Node oracle harness (	ests/*.py, 	ests/reference/*, 	ools/*.py) was removed at the owner's request: this repository now needs exactly two toolchains, Arduino/xtensa for the device and MSVC or clang plus PowerShell for the host. Every vector those harnesses produced is still pinned in `src/generated/*.inc` and executed by `tests/host/host_test.exe`, so the checks still run on every build. The prose below records the original independent-SDK comparisons; bring the SDKs back if you need to regenerate a fixture.

## 2026-10-28 地址扩展与 BEP-20 验证

本轮只增加**可证明**的能力，没有把“看起来像地址”的字符串塞进目录。

| 检查 | 结果 | 说明 |
| --- | --- | --- |
| `tests/host/build.ps1` | 退出码 0 | 新增 `aeternity`、`ryo`、`zano` 地址向量与 20 个 BEP-20 profile 全部通过 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 退出码 0 | 32 位 P4 编译，`NetworkProfile` 新增 64 位 CryptoNote profile 指针未破坏布局 |
| `tests/host/build_clang_ubsan.ps1` | 退出码 0 | 补上 CameraPort/TrustAnchor/Mascot 三个源文件后，UBSan 链接与全部自检通过 |
| `tests/host/build_chain_native.ps1` | 退出码 0 | 链接真实 BIP32/ECDSA，执行 `chain_probe zcash-sign-selftest`：ZEC t1 P2PKH 与 t3 P2SH-P2PK 的完整签名、scriptSig 结构与 DER 验签；并执行 `chain_probe dash-sign-selftest`：Dash 先用两笔真实主网交易的摘要锚定序列化与 legacy sighash，再用 RFC 6979 生成的向量逐字节比对设备产出的签名交易，并从 scriptSig 反解 DER 与公钥做曲线验签 |
| `tests/host/build_chain_native.ps1` | 退出码 0 | `chain_probe cosmos-sign-selftest`：逐条签名 Cosmos v1/v2 固定向量并与 `TxRaw` 逐字节比较，同时验证错误私钥被拒绝 |
| `tests/host/policy_check.ps1` | 退出码 0 | 新增“助记词/私钥不得进入任何输出路径”的静态门禁与 `HEXWALLET_ENABLE_SECRET_EXPORT` 编译期拒绝检查 |
| `tests/host/board_port_compile_check.ps1` | 退出码 0 | 真实 LVGL 9.5 下 `WalletUi.cpp` / `WalletBoardPort.cpp` 全板卡编译 |
| `tests/host/p4_runtime_compile_check.ps1` | 退出码 0 | `WalletCli` / `WalletSigning` / `WalletLinkService` / `.ino` 使用真实 P4 头文件编译 |
| BSC RPC `eth_call(symbol, decimals)` | 20/20 匹配 | WBNB、CAKE、FDUSD、TUSD、LINK、DOT、ADA、XRP、DOGE、SHIB、UNI、AAVE、ATOM、XVS、BSW、ANKR、COMP、BETH、AVAX、PENDLE；CAKE 链上 symbol 为 `Cake` |

证据边界：

- **Aeternity**：`ak_` 地址 = `base58(ed25519_pubkey || SHA-256d(pubkey)[0..3])`，来源是 `aeserialization/src/aeser_api_encoder.erl`；固定 Ed25519 公钥向量在 `run_alt_address_self_tests()`。
- **RyoCurrency**：CryptoNote long address 的 3 字节 varint 前缀 `0x2ce192` 已用官方 `cryptonote_config.h` 和 dev-fund 地址逐字节复核；`RYoL...` 向量在 `run_cryptonote_self_tests()`。
- **Zano**：直接复现 `hyle-team/zano/tests/unit_tests/base58.cpp` 的 `ZxDqHy6...` 向量；`0xc5` 前缀和双密钥 body 一致。
- 这三条链**没有**交易审阅/签名路径，目录能力只有 `ADDRESS`。不要把地址可用当成收付可用。
- Beam / Grin / MimbleWimbleCoin / Epic Cash 没有静态链上地址；SERO 是 superzk 公钥包；Swap / Evolution / VeriBlock 没有 SLIP-0044 coin type。原因与拒绝策略见 [chain-protocols.md](chain-protocols.md#aeternity-ryocurrency-和-zano--address-profiles-only)。

## 2026-10-23 验证记录

*Merged from docs/validation-2026-10-23.md.*

本次检查针对当前工作区，不能替代完整固件链接、实机测试或新签交易的节点验收。设备代码未增加联网客户端；参考实现下载和广播属于电脑/手机侧工作。

### 已执行

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| `tests/host/build.ps1` | 退出码 0 | 加密、交易、目录、NFC 协议自检及 worker 生命周期回归 |
| `python -m unittest discover -s tests -p "test_*.py"` | 33 项通过 | 生成物、独立 Monero 证据、篡改拒绝、链路与覆盖报告 |
| `tests/host/build_clang_ubsan.ps1` | 退出码 0 | 启用 undefined-behavior sanitizer，出错即停止 |
| `tests/host/device_compile_check.ps1 -Target esp32p4` | 退出码 0 | P4 32 位目标的加密与交易模块编译 |
| `tests/host/p4_runtime_compile_check.ps1` | 退出码 0 | 使用真实 P4 Arduino/FreeRTOS 头文件编译 worker、签名调度和草图 |

主机使用 MSVC/Clang；目标 SDK 为 Arduino ESP32 3.3.10。CI 已加入 P4 运行流程编译检查，但本次没有提交或执行 GitHub Actions。

### 修复与拒绝边界

- worker 超时不会释放仍被任务借用的栈对象、密钥或交易缓冲区。结果过期后等待任务结束，再清除数据；超时签名不会返回给手机。等待期间服务 UI，不接收新的签名请求。
- XMR/MSR 签名也在 worker 执行。worker 不可用时拒绝请求，不在主循环的小栈上重试。
- 新的签名请求先使旧批准失效；拒绝时清除请求内容。无效参数会清除 CryptoNote 签名状态。
- 无法生成完整目的地址时不显示批准按钮；签名输出数量不能超过显示容量。
- 审阅检查完整 `extra`，拒绝重复交易公钥、重复附加公钥向量、未知字段、重复 nonce、截断字段和非法填充；XMR payload v3 会继续逐项验证 additional public key 与秘密、公钥和输出索引的绑定。
- XMR 标准输出和找零使用 `R = rG`；单一子地址目的地使用已绑定的 `R = rD`，混合/多目的地使用 payload v3 的逐输出 additional transaction-key 绑定。设备核对 `tx_extra` 公钥、输出索引、金额密文、view tag 和 commitment；MSR 子地址输出仍拒绝。子地址输入消费保留。

### 尚未完成

币种范围以 `coin-coverage.md` 为准。SIGN 只表示目录声明签名入口，并不表示全部交易类型可用。SOL、ADA、DOT、FIL、XCH、DCR、FIRO、FLUX 等仍缺已接入的交易适配器；不能用地址原语代替发送支持。

MSR RCT type 3 默认关闭。Monero 的独立 BP+ 基线和历史主网交易向量已进入回归，但新签交易仍需手机/电脑侧节点验收。SE050 安全会话、秘密解封策略、PN7161 实际连线、可信显示、看门狗、断电恢复与整机性能尚无这块硬件的完整验收证据。当前工程不能称为已完成生产验证的百链硬件钱包。

## 2026-10-24 变更与验收范围

*Merged from docs/validation-2026-10-24.md.*

MSR 不再作为 GRAVEYARD 例外：网络配置、设备目录、主机签名选择及设备启动自检均已移除。底层遗留 Masari 回归材料仍保留供历史算法检查，不表示产品支持。XMR 保留。

SOL 转账新增真实消息解析、费用计算、可信显示数据、单次批准签名和完整交易输出。范围扩展为单付款账户的 legacy/v0 System Transfer、经典 SPL 与 Token-2022 TransferChecked；不含 ATA 创建、质押和地址查找表。Token-2022 会显示“扩展不可离线核验”警告，要求额外 hook 账户的指令在解析阶段即被拒绝。未登记 mint 可通过精确 mint/代币账户/数量审阅转账，但不信任手机提供的代币名称或账户 owner。协议与离线限制见 [solana-signing.md](chain-protocols.md)。

本机 MSVC 主机自检通过，45 项 Python 测试通过；P4 加密模块和使用真实 Arduino/FreeRTOS 头文件的签名、链路及 worker 编译检查通过。SOL 独立向量来自 solders 0.26.0，SPL 指令由 solana-py 0.36.6 编码，包含完整预期签名交易字节，未使用待测钱包生成期望值。

经典 SPL 新增 16 组合法 SDK 向量、26 组拒绝案例、legacy/v0 全截断和批准摘要篡改检查。固件实际签出的交易在 solders 0.28.0 LiteSVM 中通过 9 项执行检查：2 项成功转账验证资产变动及费用，7 项错误状态/签名验证拒绝且代币账户不变。签名及 blockhash 验证开启；初始账户是明确注入的测试状态。记录见 `build/spl-svm-execution.json`，CI 已增加对应执行步骤及证据上传，尚未远程触发 Actions。

Clang UBSan 主机自检及 11 项 SOL/SPL Python 测试通过；真实 LVGL 9.5.0 头文件下的全部既有屏幕配置编译检查通过。主机构建仍有既有 mbedtls 测试兼容层和 Bitcoin 模块的整数窄化警告，不能称为全仓零警告。

尚未执行整机烧录、屏幕按键验收、NFC 电气/时序测量、SE050 解封或链上广播。SDK 向量使用合成 blockhash，不能作为全节点验收证据。

SE050 目前仍只有探测与能力规划，`WalletSession.cpp` 的助记词保存在 MCU RAM；不能称为已由安全芯片托管。接入前需要完整芯片料号、Applet 版本、设备独立 SCP03 配置方式以及板级连线。不要把生产密钥写进代码或提交到仓库，也不要用 NXP 默认演示凭据宣称完成保护。

ADA、DOT、FIL、CHIA、DCR、FIRO、FLUX 等交易适配器尚未补齐。当前完成度以 [coin-coverage.md](chain-support.md) 为准，不将目录或地址生成能力视作完整链支持。

### 同日追加：TRON、Token-2022 与 EVM 网络扩展

- 原生 TRX 与已登记 TRC-20 的 `raw_data` 严格解析、owner 权限校验、SHA-256 txID 绑定和 65 字节 `r||s||v` 签名接入 `BEGIN_SIGN kind=7`；范围与限制见 [tron-signing.md](chain-protocols.md)。
- TRON 向量由 `tools/generate_tron_vectors.py` 用纯 Python 实现 protobuf/BIP32/RFC 6979/secp256k1 生成，每条签名先经 OpenSSL 独立验签；`tests/test_tron.py` 用真实 C++ probe 覆盖完整字段、14 组拒绝、截断与外部 owner。设备启动自检在真实 mbedtls 上比较完整签名。
- Token-2022 使用 vendored solders 0.28.0 生成独立向量；`tests/test_spl2022.py` 比较完整签名字节、5 组合法交易、7 组拒绝指令与全截断。经典 SPL 夹具中“Token-2022 必须拒绝”的旧断言已移除，改由新夹具覆盖。
- 新增 EVM 网络 Unichain(130)、Monad(143)、Plasma(9745)、Berachain(80094)、Arc(5042)，链 ID 取自各自官方网络文档；USDC 合约取自 Circle 官方合约表，XAUT 取自 Tether 官方协议表且精度经链上 API 核实。Arc 的原生气体质押代币是 18 位 USDC，因此只登记网络、不重复登记代币合约。
- 当前主机自检 59 项 Python 测试通过；ESP32-S3/ESP32-P4 纯 C++ 编译与 P4 运行时签名/链路/ino 编译检查通过。
- 仍未执行 TRON 主网广播、能量/带宽实测、整机按键验收或 Token-2022 扩展的链上执行验证。

### 同日追加：Cosmos SDK 原生 MsgSend

- ATOM/OSMO/TIA 接入 `BEGIN_SIGN kind=8`：设备自行构建 `MsgSend`、`TxBody`、`AuthInfo`（`SIGN_MODE_DIRECT`）、`SignDoc` 与 `TxRaw`；手机只提供紧凑审阅字段，不提供交易结构。
- 严格校验 chain-id 前缀、bech32 HRP/校验和/20 字节 payload、本机地址与公钥绑定、原生 denom、单消息、无 memo、fee ≤ 10 枚、gas ≤ 2,000,000；签名前重建 `SignDoc` 并比较摘要。
- `tools/generate_cosmos_vectors.py` 用独立 Python 实现 protobuf/bech32/BIP32/RFC 6979/secp256k1，签名经 OpenSSL 验签；`tests/test_cosmos.py` 比较 C++ 实际构建的 `body`/`auth_info`/摘要与三组向量，并覆盖 12 组拒绝、采样截断、外部 owner/公钥。
- 顺带修复设备端 `EvmTransaction.cpp` 的 `evm_same_review` 未定义导致 ESP32-S3/P4 编译失败的问题：新增对审阅字段的显式比较（类型、网络、代币、金额、收款方、calldata 与全部显示文本）。
- 当前 67 项 Python 测试通过；ESP32-S3/ESP32-P4 编译与 P4 运行时检查通过。尚未执行 Cosmos 主网广播或节点验收。

### 同日追加：EVM 网络与证据整理

- X Layer(196)、zkSync Era(324)、OKT Chain(66) 通过 `chainid.network` 的 EIP-155 注册表加入；
  X Layer 与 zkSync Era 的 USDC 使用 Circle 官方合约表，OKT 暂不登记代币。
- 清理并发修改产生的重复 `xlayer`/`zksync` profile、catalog 行与 EIP-1559 名单重复项；
  重复 id 会让 `run_network_profile_self_tests()` 失败。
- 新增 `docs/chain-protocols.md` 记录链 ID 与代币来源；Starknet（Cairo）、Aptos、Sui、
  TON、NEAR 明确不是 EVM，不能用 EVM profile 冒充。
- `USDT0` 行按部署地址登记，尚未由本仓库独立核实发行方公告；正式资金路径前必须再次确认。

### 同日追加：Stellar XDR 与能力声明修正

- 新增 `StellarTransaction`：SEP-0005 派生和 G 地址、主网签名域、严格 XDR 解析、1–8 个 Payment/CreateAccount、原生/发行资产、memo、有限有效期和费用策略。接入 `BEGIN_SIGN kind=9`、设备审阅和单次批准；签名前逐字段重验。设备不增加网络访问。
- 固件启动自检比较官方 SEP-0005 地址及独立 SDK 生成的完整签名 envelope。测试同时经过实际 `WalletEngine::derive_address`，检查收款地址、派生路径、签名者和 Ed25519 托管类型一致。
- 固定 `stellar-sdk==13.1.0` 的 12 组合格交易和 13 组拒绝向量已生成并独立重生成一致；覆盖金额边界、全部 memo 类型、发行者、多个操作、截断、XDR 填充、错误网络/账户及签名前审阅篡改。CI 已添加 SDK 重生成校验，未远程执行。
- 修复主机测试退出码漏算 TRON/Cosmos 自检结果的问题；新增 Stellar 的结果也参与总判定。修正 EVM 目录和中文说明：NFT ABI 解析器存在，但当前未登记 NFT 合约，不能宣称已完成 NFT 转账。
- MSVC 主机自检通过；74 项 Python 测试全部通过、无跳过。ESP32-S3/P4 模块编译及 P4 运行时签名/链路/ino 编译通过。本机日志位于 `build/stellar-*.log`。
- Clang UBSan 主机自检通过，7 项 Stellar 专项测试在 UBSan probe 上通过，无未定义行为诊断；已有其他模块的编译警告仍存在，不宣称全仓零警告。
- 这仍不是全链实现或生产验收。未执行 Stellar 节点提交、整机屏幕/按键验收及物理安全验证。剩余适配器和 NFT 缺口见 [adapter-status.md](chain-support.md)，XLM 精确边界见 [stellar-signing.md](chain-protocols.md)。

### 同日追加：Algorand / NEAR 适配器与 SHA-512/256 修复

- Algorand 与 NEAR 均已接入独立解析、设备审阅、Ed25519 签名和 `BEGIN_SIGN` 分发；两者不访问网络，交易由手机或桌面端组装，设备只接受原始未签名字节。
- **关键修复**：`CryptoExtended.cpp` 的 SHA-512/256 单次实现对 ≥126 字节消息复用了上一分块，未清零 128 位长度字段的高 64 位，导致 Algorand 交易 txID 错误（真实支付交易均超过该长度）。现已清零整个尾块并写入高位长度，新增 128 字节分块 KAT；`extended-crypto` 启动自检通过。
- Algorand：严格 canonical MessagePack，主网 genesis 绑定，仅 `pay`/`axfer`；拒绝 group、rekey、close、clawback、LogicSig 和应用调用；fee 1,000–1,000,000 microAlgo，有效期窗口 ≤1000 轮；输出 canonical `{sig, txn}`。
- NEAR：严格 Borsh `TransactionV0`，仅 1–16 个原生 Transfer；128 位总额溢出拒绝；签名 SHA-256 摘要；输出 `tx || 0x00 || sig`；不声称命名账户所有权或 block hash 的链上新鲜性。
- 新增 `tests/fixtures/algorand-sdk.json`（py-algorand-sdk 2.11.1，11 合格/12 拒绝）与 `tests/fixtures/near-sdk.json`（near-api-js 5.1.1，11 合格/16 拒绝）；`algorand_probe`、`near_probe` 在 MSVC 与 Clang UBSan 下逐组匹配全部字段和签名字节，Python 测试用派生公钥独立验签。
- 新增 `src/generated/AlgorandVectorsTest.inc`、`NearVectorsTest.inc` 与对应 `--check` 生成器；固件启动自检比较完整 SDK 签名并验证错误 owner 被拒绝。`HexWallet.ino` 自检清单加入 algorand/near。
- 结果：86 项 Python 测试通过；MSVC 主机自检 `algorand=pass`、`near=pass`；Clang UBSan 主机自检通过；ESP32-S3、ESP32-P4 模块编译及 P4 运行时（WalletWorker/WalletSigning/WalletLinkService/ino）编译通过。
- 边界与缺口见 [algorand-signing.md](chain-protocols.md)、[near-signing.md](chain-protocols.md)。尚未执行主网广播、节点验收或整机物理安全测试；ADA、DOT/KSM、XRP、TON、SUI 等仍未实现，不以地址编码或原语存在冒充完整适配器。

### 同日追加：Algorand / NEAR 签名入口实现

- 补齐 `wallet_signing_begin_algorand`、`wallet_signing_begin_near` 及审阅 UI、签名分发和 worker 签名任务；`WalletLinkService` 的 kind=10/11 不再引用未定义符号。
- 审阅显示：Algorand 的发送方、收款方、金额/ASA id、费用、有效轮次、lease、完整 note hex 与路径；NEAR 的 signer、public key、block hash、nonce、逐笔金额、总额与路径。NEAR 无交易内手续费字段，UI 不伪造费用。
- 两个入口均先校验网络、catalog 签名能力和本机 owner，再解析；签名前由 `algorand_sign_transaction`/`near_sign_transaction` 重新解析并逐字段比较。P4 运行时编译通过，`HexWallet.ino` 自检包含 algorand/near。

### 同日追加：PAXG/XAUT/MANA、离线 TOTP、TRC-721/1155 与 EPD 刷新

- 代币登记：新增 Ethereum PAXG（`0x45804880De22913dAFE09f4980848ECE6EcbAf78`，18 位）、
  Ethereum MANA（`0x0F5D2fB29fb7d3CFeE444a200298f468908cC942`，18 位）和 Polygon MANA
  （`0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4`，18 位）。三者与既有 XAUT 均通过公开 RPC
  的 `symbol()`/`decimals()` 复核；PAXG、MANA 已进入 `coin-coverage` 的 TOKEN 行。
- TRON：`TronTransaction` 新增唯一 selector 的 TRC-721 `safeTransferFrom(0x42842e0e)` 与
  TRC-1155 `safeTransferFrom(0xf242432a，空 bytes 尾)`；校验 calldata `from == owner`，
  拒绝共享 selector 的 `transferFrom`、批量转移和回调数据。NFT 合约未登记时仍可审阅，但
  设备显示合约地址、标准、token id 与 UNREGISTERED 警告。生成器扩为 4 组合格/19 组拒绝，
  `tests/test_tron.py` 与设备启动自检均覆盖。
- TOTP：新增 `Totp.cpp`，严格 Base32、HMAC-SHA1/256/512、RFC 4226 动态截断、6–8 位、
  可配置周期；`millis()` 锚点时钟对回绕安全、对倒退 fail-closed。认证 CLI 提供
  `totp time <unix>` / `totp <base32> [digits] [period] [sha1|sha256|sha512]`，密钥不回显、
  不落盘。自检覆盖 RFC 6238 的 18 个向量、RFC 2202 HMAC-SHA1 与 RFC 4648 Base32；
  `tests/test_totp.py` 用 hashlib/hmac 独立复算并由 C++ 探针比对。
- EPD：LVGL 全帧 flush 改为 dirty 标记 + 120 ms 合并提交；每次提交使用完整刷新
  (`refresh(false)`)，写屏前 `powerOn()`、刷新后 `powerOff()`，修正了此前直接局刷和
  4×4 Bayer 阈值方向的问题。`board_display_colors()` 暴露 1/3/4 色能力；当前后端仍只有
  1bpp，若把 `HEXWALLET_EPD_COLORS` 设为 3/4 而没有匹配的 GxEPD2 3C/4C 驱动类，初始化
  会明确失败，不会用黑白类冒充彩色。具体面板型号/控制器/BUSY 极性未提供，三色/四色驱动
  仍未实现（边界见 `epd-lvgl.md`）。
- 结果：92 项 Python 测试通过；MSVC 主机自检 `totp=pass`、`tron=pass`、`tokens=pass`；
  Clang UBSan 主机自检通过；ESP32-S3/P4 模块编译、P4 运行时（含 `WalletCli.cpp`/`Totp.cpp`）
  与全板卡 `WalletBoardPort`/`WalletUi` 编译检查通过。
- 本轮未新增 ADA、DOT/KSM、XRP、TON、SUI、FIL 等原生适配器；没有独立序列化/签名向量
  就不写入占位实现。列表与缺口仍以 `adapter-status.md` 为准。
- 三色/四色 EPD 仍缺具体面板型号、控制器与排线，当前只验证 1bpp；把
  `HEXWALLET_EPD_COLORS` 设为 3/4 会 fail-closed，不会静默按黑白驱动。

### 同日追加：EinkFrame 与 128×296/四色 UI 准备

- 新增 `EinkFrame.cpp`：RGB565 → 1bpp/2bpp 原生帧转换，支持 1/3/4 色；红色先于亮度
  分类（纯红亮度仅 76，不能先判黑），2bpp 按 MSB-first 每字节四像素；3 色面板将黄色降级
  为白色。启动自检覆盖黑/白/红/黄、字节交换、容量与非法深度，`eink=pass`。
- `WalletBoardPort.cpp` 的 1bpp 转换改用该模块，移除本地 Bayer 表。
- `WalletUi.cpp`：128 px 宽目标使用 12 px 字体、缩放下限 0.45；3/4 色主题的标题、费用、
  确认码改用主题色（红/黄），不再硬编码绿色/深红。
- 新增 `docs/hardware-e029a182.md`，记录照片可确认的 ESP32-S3、四按键、128×296 EPD、
  USB-C 与缺失的网表/面板 datasheet。E029A182/SSD1680/四色三项在公开资料上不完全一致，
  未拿到厂商 demo 前不写驱动。

### 同日追加：Tezos 验证与 XRP r-address 修复

- Tezos（XTZ）：确认 `TezosTransaction` 已接入 `BEGIN_SIGN kind=12`、catalog、WalletEngine 与启动自检；7 项 `tests/test_tezos.py` 全部通过，主机 `tezos=pass`。边界与证据补入 `tezos-signing.md`。
- XRP：发现并修复地址层错误——旧 `xrp` profile 用 Bitcoin base58 字母表生成 P2PKH，得到的是 `16...` 而不是合法的 `r...`。新增 `AddressEncoding::Ripple` 与 `address_ripple()`（Ripple base58 + hash160 + double-SHA256 校验），已知向量得到 `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`；catalog 只声明地址能力，Payment 二进制/签名仍未接入，避免把错误地址当收款地址。
- 结果：104 项 Python 测试通过；ESP32-S3 模块编译（含 Tezos/EinkFrame/Totp）、P4 runtime 与全板卡 UI 编译通过。XRP 仍不可发送，coverage 显示 ADDRESS，不是 SIGN。

### 同日追加：XRP Payment 收发签名接入

- 新增 `XrpTransaction`：设备从 50 字节紧凑审阅结构构建规范 XRPL Payment 二进制，校验 amount/fee/sequence/last ledger/destination tag、目的账户与 source 绑定；签名摘要为 `SHA-512Half(0x53545800 || unsigned)`，签名以低 S secp256k1 DER 插入 `0x74` TxnSignature 字段。
- 修复 XRP 地址层：旧 profile 误用 Bitcoin base58，现为 Ripple base58 + hash160；固定向量 `rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH`，接入 `address_ripple()`、`AddressEncoding::Ripple`、catalog 与 WalletEngine。
- 接入 `BEGIN_SIGN kind=13`、设备审阅（source/destination/r-address、金额、fee、sequence、last ledger、tag、hash）、worker 签名、catalog 签名能力与启动自检 `xrp`。
- `tests/fixtures/xrp-sdk.json` 由 xrpl-py binary codec 生成：3 组合格（无 tag、tag、零 tag）、10 组拒绝；`xrp_probe` 与 `tests/test_xrp.py` 独立比较 unsigned/hash/字段。
- 结果：107 项 Python 测试通过；主机 `xrp=pass`、`tezos=pass`、`extended-crypto=pass`；S3 编译与 Clang UBSan 通过；P4 runtime 编译通过。
- 未执行 rippled 提交、主网 sequence/费用实测或硬件按键验收；不支持 issued currency、path、memo、partial payment、多签名。

## 2026-11-02（续）：airgap 栈清理、面板配置对齐与首编译修正

这一轮没有新增协议，全部是把已有代码改成能在真实任务栈和真实编译选项下跑起来的样子。

- **airgap 去掉两处 2 KB 栈临时**：`airgap_sender_render()` 不再把 payload 拼进中间缓冲，chunk 在
  blob 里本来就是连续的，直接切 `blob + chunk_offset[first_chunk]` 交给 `airgap_frame_pack()`；
  `airgap_receiver_blob()` 直接按 chunk 序号写进调用方的 `out`。4 KB 任务栈上省下的这 4 KB
  不是优化，是能不能跑起来的区别。
- **`AirgapScratch` 不再藏在函数里**：`airgap_receiver_accept()` 原来用函数内 `static` 持有
  37 KB 的取样表，等于把它钉在 .bss 且整个函数不可重入。现在它是显式参数，由调用方持有；
  唯一保留 `static` 的是自检函数，因为启动任务栈放不下，而且自检只跑一次。
- **`Se051Provisioning.cpp` 第一次真正被编译**：上一轮它是靠 `device_compile_check` 报
  `C1083` 才发现的，主机侧从没编译过。第一次编译就炸出两处：自检里
  `for (const uint16_t w : {...})` 需要 `std::initializer_list`，而文件只有 `<stdint.h>`，
  MSVC 直接给 `C3312 no callable 'begin'`；还有 `size_t` 缺 `<stddef.h>`。前者改成普通数组
  循环，后者补头文件。**结论：文件存在不等于编译过。**
- **面板配置头/源对齐**：`EinkPanel.h` 和 `EinkPanel.cpp` 当时已经是两个版本——头文件还叫
  `EinkController::Waveshare29G`，源文件和板级已经在用 `Ssd1683`；头文件还留着
  `otp_partial_verified` 开关，`partial_supported()` 因此要求"有 LUT 或显式声明 OTP 已验证"，
  而实际驱动早就默认走 OTP。对齐后的规则是：黑白面板只要初始化成功就支持局刷，LUT 是可选
  覆盖项；四色一律拒绝 LUT 和局刷；`Ssd1683` 必须由板级提供 `color_init` 表，驱动不猜模拟
  电压。自检补了这张表，四色路径才真正被跑起来。
- **局刷表长度统一成 159 字节**：前 153 字节写 `0x32`，其余是 EOPT `0x3f`、VGH `0x03`、
  VSH1/VSH2/VSL `0x04`、VCOM `0x2c`。文档之前写的 153 只覆盖波形，漏掉了电压和收尾，按那个
  长度给出的表会被 `begin()` 拒掉。
- 结果：`build.ps1` 61 项全 pass（含 `airgap`、`scp03`、`se051-provisioning`、`eink-panel`、
  `eink`）；`build_clang_ubsan.ps1` 通过；`device_compile_check.ps1 -Target esp32p4` 全源通过；
  `policy_check.ps1` 通过。仍没有实机：SCP03 与曲线装载没有实卡互验，airgap 也没有接屏幕
  动画和摄像头解码。
- **四色档位原本是条死路**：`EinkPanel::begin()` 要求 `Ssd1683` 必须带板级 `color_init` 表，
  但 `WalletBoardPort` 从来没有接过这张表，选了 `HEXWALLET_EPD_PROFILE=1` 只会在开屏时报
  `ERR: e-paper panel did not initialise`。现在板级用 `HEXWALLET_EPD_COLOR_INIT` 提供表，
  `p4_runtime_compile_check.ps1` 的三个档位会真的把这行编译进去（档位 1 用带花括号的
  `-D` 传一张样例表），不再只是"编过就行"。

## 2026-11-02（三）：Groestl-512、Groestlcoin 地址与原生 THETA SendTx

这一轮全部用可核对的外部数据推进，没有一项是靠"看起来对"落地的。

- **Groestl-512 落地**（`Groestl512.h/.cpp`）。关键细节是输出变换
  `Ω(x) = trunc_n(P(x) ⊕ x)` 取的**不是首 n 字节而是末 n 字节**：之前几轮实现把 128 字节的
  `P(x) ⊕ x` 整段当摘要，于是空串的输出末尾明明已经等于官方值、却被自己的截断规则判成错误。
  S 盒不粘贴 256 项常量表，而是按规范定义 `inv(x) ⊕ rotl(inv,1..4) ⊕ 0x63` 在首次使用时算出来，
  表有问题就只能说明公式照抄错了。
- 验收用的是 NIST 提交包里的 `KAT_MCT/ShortMsgKAT_512.txt`（8 组：空串、1/2/3 字节、
  32 字节、64 字节、128 字节、`abc`）。注意 KAT 的 `Len` 是**位**长度，非 8 倍数时消息最后
  一个字节要按位掩码，按字节取会全线失败——第一次就踩了这个坑，所以自检只取字节对齐的组。
- **Groestlcoin 的校验和定案**：`base58check` 的 4 字节校验和是 **Groestl-512 做两次取前 4 字节**，
  单次不行、取末尾 4 字节也不行。用 `0x24 ‖ 35ead48b…16fc43` 能精确还原主网地址
  `Fa5oaNLoshov4C6HtcnwVYnGamYJ7qXN9W`，这就是 `grs-address=pass` 的锚点。网络登记为
  `grs`（SLIP-44 17、p2pkh version 0x24、bech32 hrp `grs`），能力只有 `WalletCapabilityAddress`。
- **GRS 的 legacy sighash 仍然没有解开，而且这次证伪了上一轮的猜测**。上一轮文档写过"txid 是
  SHA-256，所以 sighash 也还是 Bitcoin 那套"。实际上把那条主网交易的两个输出、`0xfffffffd`
  序列号、`SIGHASH_ALL` 和 P2PKH/P2PK 两种 scriptCode 都还原之后，签名在
  `sha256`、`sha256d`、`Groestl-512` 单/双次的三种截断、`Groestl-256` 单/双次下**全部验不过**，
  高低 S 都试过。结论：这条链的 legacy sighash 不是上述任何一种朴素组合，缺一份能对上签名的
  来源就不能开签名——GRS 保持"能收不能发"。（`sha256(raw)=txid` 这一条仍然成立，是独立事实。）
- **原生 THETA SendTx 打通**（`ThetaTransaction.h/.cpp`）。方案本身在 Theta 的
  `ledger/types/tx.go` 里：`SignBytes = RLP(chainID) ‖ RLP(type=2) ‖ RLP({fee, inputs, outputs})`，
  再套一层只有 `input` 非零的六字段以太坊信封，摘要取 `keccak-256`。
- 三处实测踩点：① `TxInput.Signature` 为空时是 `0x80`（空串），不是零长度——写成"什么都不写"
  整条 RLP 长度全错；② 信封里 nonce/gasPrice/gasLimit/value 四个 0 同样是 `0x80`；③ chain id
  是 **`mainnet`** 而不是 `theta-mainnet-1`，试错前四种全不匹配。
- 验收：`explorer.thetatoken.org:8443` 的 `/api/transaction/<hash>` 取到 block 1000000 里的真实
  转账 `0x1ccc4b6e…063e17bca`（该浏览器把 SendTx 标成 `type: 2`，coinbase 才是 `0`）。
  `theta_sendtx_sign_bytes()` 逐字节复现 121 字节信封，`theta_sendtx_digest()` 得到
  `03490f71…e01cbe`，而这个摘要正是让那笔交易的 65 字节签名恢复出输入地址
  `0x2623912…98de62` 的那个。另外覆盖了 chain id、fee、sequence、输出数量任一变化都必须换摘要，
  以及空输入、零发送方、零输出、缓冲不足四类拒绝。
- 结果：`build.ps1` 全项 pass（新增 `groestl512`、`grs-address`、`theta`）；
  `build_clang_ubsan.ps1` 通过；`device_compile_check.ps1 -Target esp32p4` 全源通过；
  `policy_check.ps1` 通过。
- 仍未做：THETA 还没接进 `ChainFamily`/审阅界面/APDU，也就是"能算对、还不能点"；
  GRS 签名、P-256 验签命令、SE051 的 T=1 帧与 APDU 常量这一轮都没有动，也没有编任何字节。

## 2026-11-02（四）：原生 THETA 接入链适配层

`ThetaTransaction` 从"算得对"变成"点得动"：`ChainFamily::Theta` 已进 `kFamilyMap`、审阅分支、
签名分支和 `run_chain_self_tests`，`chain_family_for_network("theta")` 现在返回 `Theta`。

- 设备请求固定 46 字节：版本(1) / 链选择(1，0=mainnet、1=testnet、2=privatenet) / 收款方(20) /
  金额(8，TFuelWei) / 手续费(8) / sequence(8)，全部大端。没有发送方字段——发送方永远是派生地址，
  否则设备就会替别人的币签名。
- 审阅把 `TFUEL`、收款方 `0x…`、金额、手续费、"seq N mainnet" 打进 `ChainReview`，摘要就是
  要签的那 32 字节。自检把**同一笔主网交易的请求形式**喂进适配器，摘要必须还是
  `03490f71…e01cbe`，这样"面板显示"和"签名覆盖"就不可能各说各话。
- 拒绝路径：版本号错、链选择器越界、金额为 0、手续费为 0、收款方全零、载荷长度不对，一律
  `Malformed`；签名缓冲小于 65 返回 `BufferTooSmall`；零私钥返回 `CryptoFailure`。
- 一个诚实的边界：主机测试链接的是**桩版 mbedtls**（`mbedtls_ecp_mul`、`mbedtls_ecdsa_sign_det_ext`
  直接返回 `MBEDTLS_ERR_ECP_BAD_INPUT_DATA`），所以 secp256k1 的签名/派生在主机上跑不了。
  自检因此只验证"签名前必须拒绝什么"，真正的签名输出由设备与原生探针覆盖。这也是为什么
  `public_key_from_private` 在这条路径上不再被调用——发送方地址从审阅结果传入，少一层依赖。
- 网络 id 复用 `theta`：EVM 转账继续走 EVM 适配器，原生 SendTx 走 `ChainFamily::Theta`，
  由载荷格式决定走哪条路。两边都动 TFUEL，别把两者的签名字节混为一谈。
- 结果：`build.ps1` 全项 pass（`theta=pass`）、`build_clang_ubsan.ps1` 通过、
  `device_compile_check.ps1 -Target esp32p4` 全源通过、`policy_check.ps1` 通过。

## SUI/FIL 验证记录 — 2026-10-26

*Merged from docs/sui-filecoin-validation-2026-10-26.md.*

按用户后续要求，本会话集中 SUI/FIL；其他会话正在继续修改同一工作区的其他链。
本记录不对并发产生的其他适配器作完整性结论。

### 已完成

- SUI Ed25519 地址派生、原生 BCS 两命令转账解析与 97 字节签名输出。
- FIL f1 地址编码修复：未压缩公钥、`f1` 前缀与 BLAKE2b 校验和。
- FIL canonical CBOR Send、发送人归属校验、CID 签名域与 SignedMessage CBOR 输出。
- 签名入口容量传递、失败清除输出、批准后重解析/对比；屏幕审阅增加发送人和地址索引。
- SUI/FIL 接入既有 `kind=14` 设备签名入口、网络/目录、密钥类型与构建清单。
- 增加真实 `WalletSecurity.cpp` + Mbed TLS 3.6.5 主机探针，CI 构建步骤及独立 SDK fixture。

### 实际运行结果

| 检查 | 结果 | 范围 |
| --- | --- | --- |
| 原主机回归 `tests/host/build.ps1` | 通过 | 执行时的整个工作区；不能覆盖随后其他会话的修改 |
| 真实密钥/签名探针构建 | 通过 | MSVC + 固件 WalletSecurity.cpp + Mbed TLS；平台 RNG 使用 BCrypt |
| `test_sui_filecoin.py` | 6 个测试组通过 | 12 个 SDK 正向向量、75 个拒绝向量；另含完整截断、尾随字节、非规范格式、异账户、批准内容替换与缓冲区边界 |
| SUI/FIL SDK fixture 重生成 `--sui-filecoin --check` | 通过 | 专用 fixture 与 SDK 重新生成的结果一致 |
| 嵌入的 SDK 自测向量 `generate_chain_selftest.py --check` | 通过 | 生成文件未发生漂移 |
| 相关已跟踪文件 `git diff --check` | 通过 | 无补丁空白错误 |
| ESP32-P4 目标编译 | 未执行 | 自动审批服务额度耗尽，无法完成该命令的自动审核；不是编译失败，也不是判定命令不安全 |
| 真机地址/屏幕/NFC/批准/锁定/断电 | 未执行 | 尚无本会话的设备操作证据 |
| 节点接收/广播/执行 | 未执行 | SDK 离线一致性不等于节点验收 |

因此，这次完成了限定交易类型的固件实现和主机独立验证，不能称为
“所有硬件钱包全部功能完成”或“所有主网交易均已可用”。

接口、支持子集、手机广播适配及构建命令见 [sui-filecoin-signing.md](chain-protocols.md)。
审批可用后，仍需执行：

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/device_compile_check.ps1 -Target esp32p4
```

## 2026-11-02（五）：GRS 签名解封、双曲线 ECDSA、X25519、THETA CLI 与 SE051 APDU

这一轮的每一项都对得上外部来源：链上数据、NXP 公开源码、或两个互不相关的库。

### GRS 的 legacy sighash 解开了，而且上一轮的"证伪"是错的

结论：**预映像就是 Bitcoin 的 `CTransactionSignatureSerializer`，一个字节都不差；摘要只做
一次 SHA-256**。依据是 Groestlcoin Core 的 `src/hash.h` —— `HashWriter::GetHash()` 里第二次
`ctx.Reset().Write(...).Finalize(...)` 被注释掉了，只剩一次 `ctx.Finalize()`；`src/script/
interpreter.cpp` 的 `SignatureHash()` 最后就是 `ss << nHashType; return ss.GetHash();`。同一条
链上 `CTransaction::GetHash()` 也是这条路径，所以 txid = `SHA256(raw)` 而不是 `SHA256d(raw)`
—— 这与上一轮量到的 txid 事实其实是同一个原因，只是当时没往这一步想。该链
`git grep -i forkid -- src/` 为 0 命中，没有 SIGHASH_FORKID。

判定用的是链上签名，不是"看起来对"：块 6324419 的交易
`b566ddf7ae1374d13081bc01ddee3d5a1f2390773c6c910b4414063ba95f6c92`，1 入 2 出，
`8d6026d9…:0`、`0xfffffffd`、`SIGHASH_ALL`、`nLockTime` 6324417。用它 scriptSig 里的 DER 签名
和压缩公钥：

| 摘要 | 结果 |
| --- | --- |
| 单次 SHA-256 = `df00bdc1…11b3be` | **验签通过** |
| 双 SHA-256 = `eb2479aa…a79f0d` | 验签失败 |

先用 libsecp256k1（`coincurve`）独立复核同一结论，再在固件里用新写的 in-tree 验签器复现。
`run_groestlcoin_sighash_self_tests()` 现在钉死四件事：预映像→单次摘要、该摘要验签通过、
改成 `SighashFamily::Bitcoin` 后摘要变成 `eb2479aa…`、同一签名对它必须**失败**，以及
`SIGHASH_FORKID` 位在 GRS 上返回 `InvalidArgument` 而不是被悄悄改走 BIP143。

落地方式：新增 `SighashFamily::GroestlLegacy`（不是给 Bitcoin 分支加 if，而是让 family 决定
最后一次哈希），`legacy_digest()` 里只有终止哈希不同；`kNetworkSigningPolicies` 增加
`{"grs", GroestlLegacy, 0}`，`grs` 因此获得 `TransactionReview | Signing`。网络自检增加双向
约束：`GroestlLegacy` 只能配 `P2pkhGroestl`，非 `GroestlLegacy` 不能配 `P2pkhGroestl`。

顺带补了一个会露馅的地方：`review` 里渲染收款地址原来走 `address_from_script()`（SHA-256
校验和），GRS 必须走新的 `address_from_script_groestl()`，否则屏上显示的是一条链上不存在的
地址。自检把这个也钉住了：同一笔交易的 P2WPKH 输出必须渲染成
`grs1q94gj9xhh0kgfkwe7ca9f8jertlm56es75xlrpg`（bech32 只依赖 program 与 hrp，可以独立复算），
而 P2PKH 输出在两种校验和下必须得到不同字符串。

### 双曲线 ECDSA：`src/EcdsaCurve.h`

secp256k1 一直只经 mbedtls 签名，而主机链接的是**桩版 mbedtls**，所以"产出的签名是否正确"
在主机上从来没被验证过，也没法验签链上数据。新引擎把两条 256 位素数曲线放进同一个实现：

- 8×32 位 Montgomery 域、全宽乘积 + REDC、Jacobian 点运算，`a` 作为曲线参数
  （P-256 `a = -3` 用 `3(X-Z²)(X+Z²)`，secp256k1 `a = 0` 只剩 `3X²`）；
- RFC 6979 §3.2 确定性 nonce、low-S、严格 DER（最小长度、非负、单字节补零、无尾随字节）；
- 最容易抄错的两个常量不抄：`n0 = -p⁻¹ mod 2³²` 用牛顿迭代从模数算，`R² = 2⁵¹² mod p` 用
  512 次模加倍算。算出来的 `n0`/`R²` 与 libsecp256k1 和本仓库 P-256 的既有常量逐字节一致。

自检不用自己的输出当期望值：G 在曲线上、`n·G = ∞`、`(n-1)·G` 的 x 等于 Gx 且 y 等于 -Gy；
P-256 复现 RFC 6979 A.2.5 的 r 与 low-S 化的 s；secp256k1 用同一把钥匙和同一条消息，r/s 取自
libsecp256k1 与 python-ecdsa（两者互相一致）；再验一遍上面那条 GRS 主网签名。拒绝路径覆盖
篡改、零 r/s、错摘要、坐标 ≥ p、曲线外压缩公钥、零私钥、私钥 = n、DER 截断/尾随/非最小补零。

### X25519 与 Ed25519↔Curve25519

原树只有 Edwards 群上的 `ed25519_ecdh`，说 "x25519" 的对手方（HPKE、age 一类）用不了。新增
`x25519_scalar_mult` / `x25519_public_key` / `x25519_ecdh`（常数时间 Montgomery ladder，a24 走
真正的域乘而不是裸标量乘 —— 后者会把 limb 撑到 43 位、下一次乘直接溢出 int64）、
`ed25519_public_to_x25519`（`u = (1+y)/(1-y)`，把 Ed25519 基点映到 u=9）与
`ed25519_seed_to_x25519`。没有提供 x25519→ed25519：那个方向恢复不出 x 的符号，编一个"某个"
符号等于给上层埋一个会产生不同公钥的坑。

自检：RFC 7748 §5.2 两条向量、§6.1 Alice/Bob 双向共享密钥、迭代 1 次与 1000 次、
`ed25519_public_key(RFC8032 种子1)` 的 Curve25519 对应值（`d85e07ec…f6b62e`）、以及
小阶点（全零、u=1）必须被 `x25519_ecdh` 拒绝而不是返回全零。

### THETA 的主机侧入口

`wallet_signing_begin_chain()` 已经在手机链路（`kTxChain = 14`）上工作，缺的是串口侧。新增：

```text
chain begin <network> <index> <payload-hex>    # THETA 原生 SendTx 载荷是 46 字节
chain sign <code>
chain reject
```

走的是和 `tx` / `zec` 相同的流程：`SigningRequest` 传输策略先要求可信显示、六位批准码、
两分钟过期、失败即清、`clear_pending_transaction()` 一并擦掉新的 `pending_chain_transaction`。
链适配器自己重算发送方与摘要，主机不能指定发送方。

**顺带发现一个真实的死路**：`wallet_signing_begin_chain()` 会先问
`catalog_can_sign(network_id)`，而目录里 `theta` 一项只有
`Address | TokenAccount`——也就是说 46 字节载荷在手机链路（`kTxChain = 14`）和串口上都会在
进适配器之前被拒，"`wallet_signing_begin_chain` 已经能用"只对代码成立、对 `theta` 不成立。
现在补上 `TransactionReview | Signing` 两个位，并在 `run_chain_self_tests()` 里加了断言：
只测 `chain_family_for_network("theta")` 是不够的，目录能力必须同时为真，否则这条链会再次
静默变成"能编不能点"。目录自检里"声明签名必须有适配器背书"的规则本来就把
`chain_family_for_network` 认作合法来源，所以这不是绕过规则。

同时把 `WalletCli.cpp` 纳入了本地目标编译检查：此前它只在 CI 的 arduino-cli 构建里被编译，
而 `tests/host/device_compile_check.ps1` 的 arduino-parity 段已经证明可以本地复现——现在它直接
读 SDK 自带的 `flags/includes` 生成包含路径（经响应文件传入，避免 Windows 命令行长度限制），
`WalletCli.cpp` 因此进入该段，P4 与 ESP32 两个目标都 rc=0。

### SE051：命令字节有了，出处可核对

见 [se051-integration.md](se051-integration.md)。`Se051Apdu.h/.cpp` 按 NXP plug-and-trust 的
`se05x_tlv.h` / `se05x_enums.h` / `se05x_APDU_impl.h` / `se05x_tlv.c` / `sm_const.h` 逐项实现：
CLA 0x80、INS 位域、P1/P2 表、TLV 标签、AID、曲线 id 与曲线参数类型。
`CreateECCurve`、`SetECCurveParam`、`ReadECCurveList`、`Sign`、`ECDH`、单次 HMAC、会话创建/策略/
`VerifySessionUserID`、`GetRandom` 都能生成完整帧，主机自检把每条帧逐字节钉死。
仍然没有实卡互验；空命令（`GetVersion`/`ReadECCurveList`）的 Le 编码是按 ISO 7816-4 case 2
推出的，第一次上卡应先复核这两帧。

### 结果

`build.ps1` 全项 pass（新增 `ecdsa-curve`、`x25519`、`se051-apdu`；`sighash` 现在同时包含
GRS 用例）；`device_compile_check.ps1 -Target esp32p4` 与不带参数的 ESP32 目标全源通过；
`policy_check.ps1` 通过。

### 仍未做

- GRS：只开了 P2PKH legacy 输入的单笔转账；P2SH/bech32 花费、多输入费策略、实机与节点接收未验收。
- 曲线：secp256k1 的**生产**签名仍走 mbedtls（有 RNG 盲化）；in-tree 引擎目前用于验签与
  主机可测性，没有替换生产签名路径。Ed25519 PKCS#8/SPKI 导入、P-256 密钥协商（ECDH）未做。
- `WalletLinkCrypto` 仍用 Ed25519 群上的 ECDH，没有切到 X25519：改握手要同时改手机端，
  这一轮只补了原语。
- SE051：实卡、曲线参数块、PIN 会话接续、托管门。

## 2026-11-02（六）：修掉两条 CI 断链，曲线收拢成一个引擎

这一轮的起点是两个 CI 失败，两处都修在根因上，不是绕过。

### `dash_validate_inputs` 从未有定义

`WalletSigning.cpp` 在展示审阅前调用它，头文件声明了它，`DashTransaction.cpp` 里却没有实现——arduino-cli 全量编译时立刻 `undefined reference`。修法不是补一个空壳，而是把 `dash_sign_transaction()` 里那段"结构 + 手续费 + 归属"的校验抽成 `validate_request()`，`dash_validate_inputs()` 与签名器共用同一条路径：

```text
dash_validate_inputs(req, master)  -> validate_request(req, master, nullptr, nullptr)
dash_sign_transaction(req, ...)    -> validate_request(req, master, keys, pubs) -> 签名
```

好处不只是链接通过：审阅和签名不再可能用两套规则判断同一笔交易。派生结果按需回传，`nullptr` 时在循环内清零，所以校验路径不会把私钥留在栈上。

### `build_chain_native.ps1` 的链接错误

`tests/host/chain/CMakeLists.txt` 的源列表缺 `Groestl512.cpp` 与 `ThetaTransaction.cpp`，所以 `chain_probe` 与 `production_policy` 都找不到 `groestl512`、`theta_review_payload`、`theta_sign_payload`。补进列表即可——这两个文件是本轮之前新增的，CMake 那边没跟。

### `WalletMiningCatalog.cpp` 的断链

`tests/host/catalog_dump.cpp` 的 `--selftest` 调用 `run_mining_catalog_self_tests()`，但 `build.ps1` 的 `catalogSources` 里没有 `WalletMiningCatalog.cpp`；同时自检本身把 `MiningCoinType::Merged` 当成越界值，而目录里确实有合并挖矿条目。现在源文件进了列表，类型上界改成 `Merged`。

自检顺带变强了，而且每一条都能从这个数据集合里证伪：

- 每一行都必须解析到一个**同符号**的目录条目——这条取代了原来"BIT 不能存在"式的硬编码名单，因为一条解析不到的挖矿条目会让矿机页面提供钱包根本不能寻址的币；
- `source_id` 是矿池列表主键，必须唯一（符号可以重复，一个币按算法出现多次）；
- 仍要求 `BTC` 可签名、`XMR`/`XCH` 按名称解析到各自的目录 id。

### secp256k1 的生产签名搬进仓库

`src/Secp256k1Sign.h` 原来是 mbedtls 的 `mbedtls_ecdsa_sign_det_ext`。它有三个问题：主机链接的是桩版 mbedtls（所有 EC 操作直接 `BAD_INPUT`），所以**主机测试从来没有验证过任何一枚产出的签名**；设备为这一个操作把 mbedtls 的 EC 代码整段链接进来；仓库里因此同时存在两份 256 位曲线实现。

现在 `WalletSecurity.cpp` 里已经没有任何 mbedtls EC 调用（`grep mbedtls_ecp|mbedtls_ecdsa|mbedtls_mpi` 为 0），全部走 `src/EcdsaCurve.h`：

- `public_key_from_private` / `uncompressed_…`：`ecdsa_public_key[_compressed]`
- `valid_private_key`：`ecdsa_scalar_is_valid`
- `hd_private_derive`：`ecdsa_scalar_add`（`k_child = (IL + k_par) mod n`，零结果与越界 IL 都返回 `InvalidChild`）
- `hd_public_derive`：`point(IL) + K_par`，结果必须能编码成 SEC1 压缩点
- `secp256k1_sign_digest_recoverable`：`ecdsa_sign_digest_recoverable`，恢复位随 low-S 归一翻转；`R.x` 溢出（恢复位 bit 1）在 65 字节 `r||s||v` 里没有表示，直接失败而不是签一个 `v` 错的签名
- `secp256k1_schnorr_sign` / `_verify` / `xonly`：BIP340 落在 `EcdsaCurve` 里，签名返回前按验证器的方式自检

BIP340 那次 `tagged_hash` 一上来就写错了：`SHA256(tag)` 被算了两次而不是重复一次，`bip340=FAIL` 立刻抓出来。这就是为什么这些向量必须真的跑。

### P-256 的两份实现合成一份

`src/P256Sign.h` 从 841 行降到 193 行：Montgomery 域、Jacobian 点运算、RFC 6979、DER 编解码全部删掉，只留下 ES256 的视角（`X||Y` 公钥、`r||s` 签名）转发给 `EcdsaCurve`。RFC 6979 A.2.5 的 KAT、high-S 接受、篡改/零 r,s/错摘要/曲线外公钥/零私钥/私钥=n 全部保留并通过。两份 1300 行的手写曲线算术，风险从来不在"写得对不对"，而在"只改对了一份"。

### GRS：P2SH 与 bech32 花费

上一轮只解封了 legacy P2PKH。这次读了 Groestlcoin Core 的真实源码（`git clone --filter=blob:none --sparse`，只取 `src`）：

```c
/* src/script/interpreter.cpp */
uint256 GetPrevoutsSHA256(const T& txTo)  { HashWriter ss{}; ... return ss.GetSHA256(); }
uint256 GetSequencesSHA256(const T& txTo) { ... ss.GetSHA256(); }
uint256 GetOutputsSHA256(const T& txTo)   { ... ss.GetSHA256(); }
/* src/hash.h */
uint256 GetHash() { ctx.Finalize(result.begin()); /* GRS ctx.Reset()... */ return result; }
```

也就是说 GRS 的 BIP143 等价预映像在**四个位置**都是单次 SHA-256，而 Bitcoin 的 BIP143 三个子哈希是双次（用 BIP143 自己的向量验证过：outpoints 的 dSHA256 才是 `96b827c8…`）。只把最后一步改成单次会得到一个没有节点接受的预映像。

`bip143_digest()` 现在统一走 `sighash_hash(family, …)`，四个哈希一起切。`grs49`/`grs84` 两个账户（coin type 17、派生 49/84、地址 `P2shP2wpkh`/`P2wpkh`）随之进网表与目录，`SighashFamily::GroestlLegacy` 与 GRS 地址族的绑定改成按 **utxo 档案**判定（0x24/0x05/`grs`），因为三条 GRS 账户只有导出路径和地址形式不同，编码并不都是 `P2pkhGroestl`。

自检新增 segwit 用例，两个期望值都来自独立的 Python 实现（同一份字段、两种哈希规则），并且互相为反面：GRS 得到 `390905ce…1978f`，同一笔按 Bitcoin 规则得到 `94828586…af3b4f`；`grs1q…` 地址必须渲染出来。

诚实边界：legacy 路径有真实主网签名作锚，segwit 路径**没有**链上签名向量——它的依据是 GRS 源码本身加上独立实现的交叉复算。首次实机/节点验收应优先补这一条。

### 手机链路改成 X25519

`WalletLink` 的临时交换从 Ed25519 群换成 RFC 7748：`scalar = SHA512(seed)[0..31]`，`shared = X25519(scalar, peer)`。身份密钥仍是 Ed25519（签名不变），但线上的 `PK_*_eph` 现在是 Curve25519 u 坐标，**协议版本从 1 升到 2**——v1 手机与 v2 设备必须直接失败，否则两端对同一段 transcript 派生出不同密钥，症状是"握手成功、之后每帧都认证失败"。手机端要同步改，这是有意的破坏性变更。

### SE051：参数块、装载序列、PIN 会话

`Se051Curves.cpp` 把 `se05x_ecc_curves_values.h` 里 secp256k1 与 prime256v1 的 prime/a/b/G/order 逐字节搬进来，并提供：

- `se051_install_curve()`：`CreateECCurve` + A/B/G/N/PRIME 五条 `SetECCurveParam`（顺序与 SDK 的 `Se05x_API_CreateCurve_*` 一致），任何一条非 `0x9000` 立即停止并交回状态字；
- `se051_curve_present()`：`0x6A88`/`0x6A80` 当错误，不当"没有曲线"；
- `Se051PinSession`：会话创建 → 策略 → `VerifySessionUserID`，只按 ISO 7816-4 的 `0x63Cx` 解释剩余次数，`0x63C0` 锁死；未认证会话里 `se051_pin_hmac()` 在本地就拒绝，不把命令发给卡。

自检最硬的一条是**反向校验参数块**：从 `src/EcdsaCurve.h` 重算 prime/order/b/G 再逐字节比对（`a` 按 `a=-3`/`a=0` 现算）。写错一个字节的后果是卡接受参数、然后签出固件验不过的签名——静默、且只有网络能发现。

装载序列、列表解析、PIN 状态机都用假卡验证：帧数、帧内偏移、部分失败时的停止点（第 2 条失败 → 只发出 2 条）、`0x63C2` → `attempts_left=2`、`0x63C0` → `Locked`。

策略层和驱动层之间原来要调用方自己写接线，两处规则（每条命令必须 `0x9000`；`0x6A88` 不等于缺曲线）很容易漏一个。现在 `Se051Provisioning` 里有 `se051_curve_query()` / `se051_curve_provision()`，自检用一张"第 6 条命令之后才把曲线列进列表"的假卡把 `Absent → 装载 → Ready → Ready` 整条路径跑完。半装载的曲线只能报成 `Absent`（`ReadECCurveList` 不区分"没建过"和"没写完"），重复 `CreateECCurve` 会失败，所以调用方拿到的是 `ProvisionFailed`，不会拿到一条参数是 0 的曲线去签名。

顺手清掉了 `Se051Apdu.cpp` 里的调试脚手架：一个从未被用到的 `SAY()` 宏（连带 `<stdio.h>`）、两处 `::printf("sw-fail …")`、一句 `passed = passed && true;`，以及 6 个未初始化的 `FakeCard`（`response_size` 是随机值，靠运气才能通过）。`AirgapFrame.cpp` 里也有一处同样的残留：同一调用被打印一遍再断言一遍，把调试输出写到了 stderr，CI 上表现为一串 PowerShell `NativeCommandError`。这些都在，说明自检里混进了没清干净的一次性代码；它们不影响断言，但会让人以为测试跑出了错。

### 托管门

`secure_custody_backend_ready()` 原来是字面 `return false;`。这个结论本身是对的，但写法有隐患：真正接入后端的人只要"顺手"改成 `true`，没有任何地方能证明那是对的。

现在是五个事实的合取，每个来自不同的层：

| 事实 | 来源 |
| --- | --- |
| `backend_registered` | `secure_element_name()` |
| `channel_authenticated` | `secure_element_ready()`（SCP03，认证的是主机） |
| `user_authenticated` | 后端新钩子 `user_authenticated()`（认证的是人，接 `Se051PinSession`） |
| `keys_non_exportable` | 后端新钩子 `keys_non_exportable()` |
| `wallet_uses_handles` | `WalletSession` 自己注册的查询 |

`custody_gate_blocker()` 按修复顺序返回第一个不成立的事实，`custody_blocker_text()` 给可读原因，`custody <coin>` 直接打进 CLI。自检逐条伪证：五个事实全真必须开；分别打掉一个必须落到各自的 blocker；打掉两个必须报顺序更靠前的那个；再验证注册钱包层查询后门不会被它单独打开，且查询恢复后状态回到原样。

`production_policy` 里那个"已认证传输"的假后端现在把 `user_authenticated` 和 `keys_non_exportable` 都答成 `true`——它能开的最多到卡这一侧，门仍然由 `WalletLayerNotConverted` 关着。这正是想要的性质：**换后端不改变结论，改钱包层才会。**

### 结果

- `build.ps1` 全项 pass（`se051-apdu`、`ecdsa-curve`、`x25519`、`p256-ecdsa`、`sighash`、`mining-catalog` 均 pass）；
- `device_compile_check.ps1 -Target esp32p4` 与 ESP32 目标全源通过（含 `WalletCli.cpp` 的 arduino-parity 段）；
- `build_chain_native.ps1` 新增 `wallet-selftest` 子命令并接入：`bip39/bip32/bip84/evm-derive/secp256k1/bip340` 六项全部在真实密钥、真曲线、真 mbedtls 哈希下 pass——这是主机套件（桩 mbedtls）根本跑不到的一层；
- `build_clang_ubsan.ps1`、`policy_check.ps1` 通过。

### 仍未做

- GRS segwit 缺链上签名向量（见上）；P2SH 多签、非 P2WPKH 的 bech32 花费不在范围。
- SE051 实卡互验、曲线装载权限、PIN 派生（PIN → user id）、PIN 会话接续；托管门已经会用这些事实，但它们目前都还不成立。
- `Ed25519` 的 PKCS#8/SPKI 导入、P-256 密钥协商未做。
- 手机端 X25519 同步改造在固件之外。

## 2026-11-02（七）：PSBT v2 与 ZERO

### PSBT 只有两个版本，第三个不存在

要求里写的是"PSBT v1 和 v2"。线上没有 v1：BIP370 自己的脚注交代得很清楚，这个编号被跳过了，因为 v0 在设计阶段一直被口头叫作"版本 1"，定稿时干脆改成 2 以免混淆。所以这里做的是 **v0 与 v2**，并且明确拒绝 `PSBT_GLOBAL_VERSION = 1`——接受一个不存在的版本号，等于替对手方定义共识。

v0 把整笔交易塞在 `PSBT_GLOBAL_UNSIGNED_TX` 里；v2 把它拆开：全局放交易版本、兜底 locktime、输入/输出条数，每个输入 map 自带 outpoint 与 sequence，每个输出 map 自带金额与脚本。两套读取器最后汇到同一个 `BitcoinSigningRequest`，所以**审阅和签名只有一条路径**，不存在"v2 走了另一段代码"这种事。

自检里最硬的一条不是"两个都能解析"，而是**同一笔交易分别编码成 v0 和 v2，必须签出逐字节相同的交易**。结构一致只说明字段读对了；签名一致才说明摘要、脚本、vsize、手续费判定全部落在同一个结论上。

字段顺序在 BIP370 里没有规定，所以读取器从不假设顺序：non-witness UTXO 要等整个输入 map 读完，才拿 outpoint 去校验前一交易；输出的 BIP32 派生要等脚本出现才应用。这两种"逆序"在自检里都真的写了一遍。

拒绝规则逐条独立，每条有自己的错误码，构造器的 bug 因此是可定位的，而不是被悄悄重新解释：v2 带 unsigned tx → `NonCanonical`；v0 带任何 v2 专有全局 → `NonCanonical`；v2 缺 tx version / 输入数 / 输出数 → `MissingField`；`PSBT_GLOBAL_TX_MODIFIABLE` 任一位置位 → `Unsupported`（构造器还没定稿的交易不签）；required time locktime < 500000000 或 height ≥ 500000000 → `NonCanonical`（把一个高度当时间戳收下，等于悄悄换了交易语义）；同时存在"只要高度"和"只要时间"的输入 → `Unsupported`。

`PSBT_GLOBAL_XPUB` 接受但忽略：本机每个签名密钥都由设备种子派生，主机塞进来的账户 xpub 影响不了任何签名，拒绝它只会把正常构造器挡在门外。其它未知或专有全局一律拒绝——签名器看不懂的字段，不该出现在它即将授权的花费里。

顺带修掉一个真问题：`run_bitcoin_transaction_self_test()` 之前**只在设备上跑**（`HexWallet.ino` 与 `selftest` 命令），CI 的主机套件从来没碰过 PSBT。现在 `chain_probe` 增加 `bitcoin-tx-selftest` 模式并接进 `build_chain_native.ps1`，用真 mbedtls、真 BIP32、真曲线，PSBT v0 与 v2 的解析和签名每次 CI 都真的执行。失败时它打印 `bitcoin-stage=N`（`bitcoin_self_test_stage()`）：设备上没有可读控制台，这一步把"比特币测试挂了"变成"挂在第 120 步"。

### ZERO（ZER）

`zerocurrency.io` 指向的 ZERO 是 Zcash 的分叉，节点源码在 `github.com/zerocurrencycoin/Zero`。新网络不是靠"看起来像 Zcash"加进去的，是照着它自己的 `chainparams.cpp` 与 `consensus/upgrades.cpp` 抄的：

- 透明地址版本字节 `0x1CB8` / `0x1CBD`（与 Zcash 相同），只有 P2PKH/P2SH，没有 segwit；
- 网络升级表 Sprout → Overwinter `0x6f76727a` → Sapling/Cosmos `0x7361707a` → Blossom `0x2bb40e60`，主网 `vUpgrades` 里 Blossom 是 `NO_ACTIVATION_HEIGHT`，COSMOS 在高度 620450 激活，所以 ZIP-243 的 branch id 是 `0x7361707a`；
- SLIP-0044 323，总量 17,000,000 ZER。

这几条让 ZER 落在既有的 ZIP-243 引擎上，而不是复制一份 Zcash 代码。网络自检里专门加了一条：两条链**共用地址字节但不共用 branch id**。这一条值得单独写，因为把 Zcash 的分支 ID 和 ZERO 的地址拼在一起，能签出一个"本地验得过、链上没人收"的签名——"它签出来了"这类测试永远发现不了这种错。

屏蔽地址（z/zs）两条链都不支持：花屏蔽池需要 Sapling 证明与 note 追踪，看不见 note 的设备没有资格声称审阅过这笔花费。Ledger 和 Trezor 对 Zcash 画的也是这条线。

### 没做的，写在这里

- **BIP86 / Taproot**：地址派生、BIP341 key-path 摘要、BIP340 签名是三块活，其中 BIP341 摘要要按脚本公钥、金额、annex 逐段哈希，并对着 BIP341 的 wallet test vectors 校准。本轮没有动：半套 taproot 比没有更危险——能算出地址却签不对摘要，或者反过来。
- **Stacks（STX）**：c32check 地址、anchored/Nakamoto 交易格式、Clarity post-condition 是独立一条链的工作量，不能拿 EVM profile 或 UTXO 交易冒充。
- **Lightning**：链下通道，硬件钱包在这里没有"普通转账"可签；没有 validating signer（通道状态机）就无从谈起，Trezor/Ledger 也只做通道开启/关闭这类链上交易。
- 要求的 EVM 网络（BSC、Polygon、Flare、Arbitrum One、AVAX C-Chain、Arc、Aurora、Fantom、Bitlayer、Base、X Layer、Rootstock、opBNB）在 `WalletNetworks.cpp` 里**本来就已经全部存在**，chain id 也都对得上（56/137/14/42161/43114/5042/1313161554/250/200901/8453/196/30/204）。这轮做的是逐个核对，不是新增。

### 结果

- `build.ps1`：67 项 pass；
- `build_chain_native.ps1`：`wallet-selftest`、`bitcoin-tx-selftest`、`chain/zcash/cosmos/dash/evm/stark` 与 `production_policy` 全 pass；
- `psbt_audit`（独立审计程序）：64 项检查 0 失败；
- `build_clang_ubsan.ps1`、`policy_check.ps1`、`device_compile_check.ps1`（esp32 与 esp32p4）通过。

## 2026-11-03（八）：BIP86 Taproot 单密钥花费打通

### 先纠正一个说法

"BIP341 签名摘要"和"BIP371 的 PSBT 字段"不是两件独立的事：BIP341 定的是摘要怎么算，BIP371 定的是 PSBT 里怎么表达一棵脚本树的承诺。本轮做的是 **BIP86 单密钥 key-path 花费**：没有脚本树，所以 BIP371 只需要 `PSBT_IN_TAP_BIP32_DERIVATION`(0x16) 与 `PSBT_IN_TAP_INTERNAL_KEY`(0x17)，`PSBT_IN_TAP_MERKLE_ROOT`(0x18) 出现即拒绝——有 merkle root 就说明输出键不是 BIP86 的 tweak，本机签不了。

### TapTweak 与地址

`taproot_bip86_output_key()` 与 `taproot_bip86_private_key()`（`WalletSecurity.cpp`，走仓库内 secp256k1）：`t = TaggedHash("TapTweak", xonly(P))`，`Q = P + t·G`；私钥侧先把 k 归一到偶 Y（`k' = n - k`，当 P 的 Y 是奇数），再 `k_Q = k' + t`。地址是 bech32m(witness v1, 32 字节 Q)，编码放在 `WalletAddresses`，tweak 留在 `WalletSecurity`——地址层不该拿到曲线运算。

对 BIP86 官方向量跑通：助记词 `abandon … about`、路径 `m/86'/0'/0'/0/0`，内部键 `cc8a4bc6…6fc115`、输出键 `a60869f0…dc684c`、地址 `bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr` 三者逐字节一致。

### BIP341 摘要

`bitcoin_sighash_taproot()` 实现完整的 SigMsg：epoch `0x00`、hash type、nVersion、nLockTime、`sha_prevouts`/`sha_amounts`/`sha_scriptpubkeys`/`sha_sequences`、`sha_outputs`（SIGHASH_SINGLE 时改为 `sha_single_output`）、spend_type、input_index，外加可选 annex。**完整的六种 hash type 都实现**，因为 BIP341 的官方向量用的正是 `SIGHASH_SINGLE`——只实现钱包自己要签的那两种，就等于给自己判卷。

验证用的是 BIP341 `wallet-test-vectors.json` 的第一组：9 输入 2 输出、`hashType=3`。三条独立检查同时成立：

1. 本机算出的摘要必须等于向量公布的 `sigHash`（`2514a627…5526d555`）；
2. 向量公布的签名必须能被本机的 BIP340 验签通过（说明摘要是签名者真正签的那一个）；
3. 用向量公布的内部键重算 TapTweak，必须得到该 UTXO 的 `scriptPubKey`（说明 tweak 也没错）。

顺带把 `kBitcoinMaxInputs` 从 8 提到 16：BIP341 的向量就是 9 个输入，原来的上限让"逐字节核对上游向量"这件事根本做不到。内存代价是一个 `BitcoinSigningRequest` 多几百字节，换来的是上游向量可复现。

一个坑值得记下来：`secp256k1_schnorr_detail::tagged_hash()` 的输入有 96 字节上限（它是为 BIP340 的 32 字节消息写的）。BIP341 的 SigMsg 有 175 字节，直接复用会静默返回 `CryptoFailure`。现在摘要函数自己拼 `SHA256(tag)||SHA256(tag)||SigMsg`，没有这个上限。

### 端到端：PSBT v2 花掉一个 BIP86 输出

自检里有一条完整链路：用同一个助记词派生 `m/86'/0'/0'/0/0`，构造一个 PSBTv2（witness_utxo = `5120||Q`、`0x16` 带 leaf-count=0 的派生、`0x17` 内部键），解析 → 签名 → 检查最终交易：

- witness 恰好是 **1 项 64 字节**（SIGHASH_DEFAULT 不追加 sighash 字节）；
- 把那一项取出来，用输出键对本机重算的摘要做 BIP340 验签，必须通过。

这条路径上有三个"顺序无关"的细节是真的写进去过的：non-witness UTXO 在 outpoint 之前、输出的 BIP32 派生在脚本之前、`0x16` 派生在 witness_utxo 之前。任何一条读错，签出来的东西自己验不过。

### 明确不做的部分

- **脚本树 / 多签 / Lightning 通道签名**：BIP341 的 script-path 需要 leaf script 的承诺、control block 校验和脚本解释器（至少 CHECKSIG/CHECKSIGADD/multi_a 的语义），那是"在设备上跑一个受限解释器"的工程量，不是补几个字段。Lightning 通道签名更是长期在线状态机（revocation、commitment 编号、数据丢失保护），Trezor/Ledger 也没有在设备上做。
- **Taproot 多签**：需要 MuSig2 nonce 管理（两次交互、nonce 复用即致命），以及 `PSBT_IN_TAP_SCRIPT_SIG`/`TAP_LEAF_SCRIPT` 的准入策略。
- BEAM、PRL：见下。

### BEAM 与 PRL

**BEAM** 是 Mimblewimble：没有地址、没有"输入→输出"的交易，只有交互式构造的 kernel 与 rangeproof，双方要在线交换部分签名。硬件钱包在这里能做的只有存密钥并参与交互，而"审阅一笔交易"这件事本身不成立——屏上显示不了没有地址、没有接收方、金额还被承诺隐藏的交易。这里不做，是因为做不到诚实，不是因为难。

**PRL**：CoinGecko 上叫 PRL 的至少有三个（Perle、Parallel Governance、Pearl 的桥接 WPRL），地址格式、coin type、是否 EVM 各不相同。没有官方链参数就加一条网络，等于编一个地址出来。等拿到确切项目（官网或区块浏览器），一个 profile + 一条签名策略就能接上。

### 结果

- `build.ps1`：67 项 pass；
- `build_chain_native.ps1`：`bitcoin-tx=pass`（BIP341 向量 + BIP86 地址 + BIP86 端到端签名）、`wallet-selftest`、chain/zcash/cosmos/dash/evm/stark、`production_policy` 全 pass；
- `psbt_audit`：64 项检查 0 失败；
- `build_clang_ubsan.ps1`、`policy_check.ps1`、`device_compile_check.ps1`（esp32 与 esp32p4）通过。

### 仍未做

- Taproot script-path、多签、Lightning 通道签名（见上）。
- SE051 实卡：曲线装载权限、PIN 派生、会话接续、托管门——全是实卡才能定的问题。
- Kaspa/Zcash/Monero 的确切边界仍按各自文档：KAS 只签原生转账，ZEC/ZER 只签透明，XMR 只签标准地址单笔；不宣称全面生产可用。
- Stacks（STX）与 Lightning 仍未接入。

## 2026-11-03（九）：Taproot 与 BIP371 的对抗性审计，以及为什么 Lightning / Stacks 这一轮没有进代码

### 本轮做了什么

上一轮把 BIP86 单密钥花费打通了，但"能签出正确的东西"和"会拒绝错误的东西"是两件事。这一轮补的是后者：每一行都对应一条会被伪造者利用的规则，测试的期望值是**拒绝**。

新增的对抗性用例（都在 `run_bitcoin_transaction_self_test()` 里，真曲线上跑）：

| 伪造方式 | 期望结果 |
| --- | --- |
| v2 输出 map 只有脚本、没有金额 | `MissingField` |
| v2 输出 map 两个必需字段都没有 | `MissingField` |
| `0x16` 派生里 leaf-count = 1（即脚本树） | `Unsupported` |
| PSBT 自带 `0x13`（主机收集的 taproot 签名） | `Unsupported` |
| 带 `0x18` merkle root（输出键不是 BIP86 tweak） | `Unsupported` |
| 非 taproot 输入带 taproot 专有字段 | `Unsupported` |
| taproot 输入的 sighash 声明为 2 | `Unsupported` |
| `0x17` 内部键与路径派生结果不一致 | `WrongWallet` |
| `SIGHASH_SINGLE` 但 input_index ≥ 输出数 | `InvalidArgument` |
| annex 首字节不是 `0x50` | `InvalidArgument` |
| hash type 0x04 / 0x84（保留位） | `InvalidArgument` |
| hash type 0x83（ANYONECANPAY\|SINGLE） | `Ok`（合法组合必须仍能算） |

写这些用例的过程中暴露了一个测试自身的陷阱，值得记下来：`0x84 & 0x7f = 4`，所以 0x84 是**非法**的 hash type，而 `ANYONECANPAY|SINGLE` 是 `0x83`。差点把非法值写成"合法"的期望——如果那条断言通过了，恰恰说明实现漏了保留位检查。

另外确认了一件此前没有明说的事：`SIGHASH_SINGLE` 在 input_index 超出输出数时，BIP341 要求**失败**而不是套用 Bitcoin legacy 的 "hash 等于 1" 特例。代码原本就是 `InvalidArgument`，现在有测试钉住。

### 顺带核对：v2 输出 map 的"提前返回"问题

2026-11-02 的独立审计记录里提到过 v2 输出 map 在遇到 map 终止符时提前 `return`，导致 `!has_amount || !has_script` 的检查不可达。当前代码里这个位置是对的：

```cpp
if (result != TransactionError::Ok)
  return result;
if (end)
  break;
```

本轮把它写进了测试（"只有脚本没有金额"这条），这条路径以后不会再退化。

### Lightning：为什么不是"再补几个字段"

硬件钱包能在 Lightning 里签的唯一**链上**交易是通道开启的 funding transaction，以及协作关停的 closing transaction。这两笔本身是普通 Bitcoin 交易，funding 输出是 `P2WSH 2-of-2`，closing 输出是 `P2WPKH`——也就是说，**要先把 P2WSH 多签的准入和签名做出来**，Lightning 的链上部分才谈得上。

真正的通道签名（commitment 与 HTLC 的 `SIGHASH_SINGLE|ANYONECANPAY`）不是交易签名，是一个长期在线的状态机：commitment 编号单调递增、revocation secret 必须保存到确认对手方已失去旧状态、数据丢失时要用 `option_data_loss_protect` 恢复。Trezor 和 Ledger 都不在设备侧实现它，正是因为它需要持久化状态与在线交互，而这两样恰好是"离线签名设备"的反面。

所以 Lightning 的正确顺序是：P2WSH 多签 → funding/closing 交易 → （若要做）通道状态机。本轮没有动，因为它前面那一层还没做。

### Stacks：能验证的部分和不能验证的部分

本轮把 SIP-005 读到可以动手的深度，也拉了真实主网交易做对照，结论是**不能就这样进代码**：

- 能从真实数据确认的：`chain_id` 实际是 `0x00000001`（SIP-005 正文写的是 `0x00000000`，已经过时，以链上为准）；标准单签的 hash mode 是 `0x00`、地址版本 22（`SP`）；`0x04` 授权、`0x03` anchor、`0x02` post-condition mode、`0x00` 载荷、`0x05` 收款方类型这些字段位置与 API 报出的 nonce/fee/收款地址逐字节吻合。
- **不能**确认的：`presign-sighash` 的具体构造。按 SIP-005 描述（`sha256(h1 ‖ 0x04 ‖ fee_be ‖ nonce_be)`）从主网交易反推，恢复出的公钥 hash160 与发送方地址对不上；`/extended/v1/tx/{id}/raw` 返回的字节算出的 sha256 也不等于该交易的 txid，说明那个接口给的不是签名字节的原像。

一段签不出、也验不了的 Stacks 代码，比没有更危险：地址看着对，签名上不了链，用户的钱就卡在"能收不能花"。所以本轮不写。需要的是一条能对上 txid 的原始字节，或者官方 SDK（`@stacks/transactions`）生成的固定向量——拿到任一条，c32check 与 SIP-005 编码就能一次做完并钉死。

### BEAM 与 PRL

同上一轮的结论，且这一轮没有变化：BEAM 是 Mimblewimble，没有地址、没有可显示的输入输出，交易靠双方在线交换部分签名构造，硬件钱包在这里连"审阅"都不成立；PRL 至少有三种资产共用这个代号（Perle、Parallel Governance、Pearl 的桥接 WPRL），链参数各不相同，没有官方链参数就加 profile 等于编一个地址出来。

### 结果

- `build.ps1`：67 项 pass；
- `build_chain_native.ps1`：`bitcoin-tx=pass`（BIP341 向量、BIP86 地址、BIP86 端到端签名、12 条对抗性用例）、`wallet-selftest`、chain/zcash/cosmos/dash/evm/stark、`production_policy` 全 pass；
- `psbt_audit`：**90 项检查 0 失败**（上一轮是 64 项）；
- `build_clang_ubsan.ps1`、`policy_check.ps1`、`device_compile_check.ps1`（esp32 与 esp32p4）通过。

### 并发审计在我这版代码里找出的五个真缺陷

同一时间另一路审计用 BIP341 官方向量和自造的 annex 边界向量跑了我上一轮写的 `bitcoin_sighash_taproot()`，发现五处实打实的错误，全部已修：

1. **`SIGHASH_NONE` 仍然提交了输出集合**。BIP341 只在 hash type 既不是 NONE 也不是 SINGLE 时才把 `sha_outputs` 放进 SigMsg，我写成了 `output_type != 3`，漏掉 NONE（2）。
2. **`ANYONECANPAY` 没有提交当前输入的 outpoint/金额/scriptPubKey/sequence**。ACP 省略的是那四个聚合值，代之以当前输入自身的这四个字段；只省不补，等于签了一个不绑定自己输入的摘要。
3. **annex 少了 CompactSize 长度前缀**。BIP341 定义的是 `SHA256(CompactSize(len) || annex)`，我直接哈希了 annex 本身，1–252 与 ≥253 字节两种编码因此都不对。
4. **SigMsg 缓冲区容量不够**。annex 长度前缀最长 3 字节，原容量把这种情形算漏了。
5. **`0x80` 这种未定义的 hash type 没被拒绝**，而 `SIGHASH_DEFAULT` 在非 taproot 输入上被解析接受、签名时又悄悄当成 ALL。

第 1、2 条尤其说明"照着自己的理解实现一遍再自测"是不够的：这两处用自造向量永远测不出来，因为自造向量也是按同样的误解构造的。只有拿官方钱包向量逐字节比对才会暴露。

独立回归（`tests/host/taproot_audit/`）：七组官方 key-path 摘要 + 三组 annex 边界 + 非法参数，**13/13 通过**，用的是未修改的上游向量文件并校验源码 SHA-256。

### 明确的边界

- BIP86 key-path 可签；**脚本树、多签、Lightning 通道签名未实现**。
- Stacks、Lightning 未接入。
- SE051：曲线装载权限、PIN 派生、会话接续、托管门仍只有实卡能定。
- KAS / ZEC / ZER / XMR：仍是各自的受限路径（KAS 原生转账、ZEC/ZER 仅透明、XMR 标准地址单笔），不宣称全面生产可用。

## 2026-11-03（十）：P2WSH 多签的密码学地基，用 BIP143 自己的 6-of-6 向量锚住

这一轮做的正是原计划的第一步：**先把能对上 BIP143 官方向量的那部分做完**。签名准入没开——原因在最后一节。

### 一个必须先纠正的映射错误

BIP143 的 hash type 是 `ALL=1 / NONE=2 / SINGLE=3`，不是 `0/1/2`。我第一版独立复算时按 `0/1/2` 写，结果六组官方向量里只有两组 ANYONECANPAY 的对上——因为 ACP 恰好把 `hashPrevouts`/`hashSequence` 全置零，掩盖了错位。把映射改对之后六组全中。

这件事的教训比代码本身重要：**如果只实现钱包自己要签的那一种 hash type，这个错误永远不会暴露**。正是因为照抄了向量里的全部六种，`NONE` 和 `SINGLE` 才会逼出"hashSequence 在 NONE/SINGLE 下也要置零"这条规则——BIP143 写的是 "$hashSequence$ is the double SHA256 of the serialization of all input nSequence ... **unless** ANYONECANPAY, SINGLE, or NONE is set"。这一条我第一版也漏了。

### 新增的密码学原语

`BitcoinTransaction.h` 里三个纯函数，都不碰密钥：

- `bitcoin_sighash_witness_v0(request, index, hash_type, script_code, script_code_size, out)` —— 通用 witness-v0 摘要，`scriptCode` 由调用方给（P2WPKH 是 25 字节 P2PKH 脚本，P2WSH 是整个 witnessScript）。支持 ALL/NONE/SINGLE × ANYONECANPAY，因为向量就是这么给的。`scriptCode` 按 CompactSize 前缀序列化，这是 BIP143 的原始要求，P2WSH 的 witnessScript 长度不是 25。
- `bitcoin_multisig_script()` / `bitcoin_parse_multisig_script()` —— 规范的 `OP_m <33 字节公钥>… OP_n OP_CHECKMULTISIG`，只用 `OP_1..OP_16` 小整数操作码。用 `OP_PUSHBYTES_1 0x06` 代替 `OP_6` 在 VM 里等价，但本机解析器拒绝：**设备复现不出逐字节相同的脚本，就没有资格把它当成自己的脚本显示**。
- `bitcoin_p2wsh_program()` / `bitcoin_p2sh_p2wsh_redeem()` —— `sha256(witnessScript)` 与 `0x0020||sha256(witnessScript)`。

`bip143_digest()` 重构成 `witness_v0_digest()` 的薄包装，自己拼 25 字节 P2PKH scriptCode。行为不变，但**顺带修好了 `hashSequence` 在 NONE/SINGLE 下忘记置零**这个问题（此前 `valid_digest_request` 只放行 ALL，所以没被触发过，属于潜伏 bug）。

### 用官方向量钉住

拿 BIP143 的 **P2SH-P2WSH 6-of-6** 那组（一个输入、两个输出、`SIGHASH_*` 六种各签一次），逐项断言：

| 断言 | 值 |
| --- | --- |
| 6 个公钥重建 witnessScript | 与向量 207 字节逐字节相同 |
| `sha256(witnessScript)` | `a16b5755…0dcb54` |
| redeemScript `0x0020‖…` | `0020a16b…0dcb54` |
| `hash160(redeemScript)`（P2SH 地址载荷） | `9993a429037b5d912407a71c252019287b8d27a5` |
| 六组摘要 | `185c0be5…`/`e9733bc6…`/`1e1f1c30…`/`2a67f03e…`/`781ba15f…`/`511e8e52…` 全部命中 |

另外两条否定用例：`SINGLE` 但 `input_index ≥ output_count` 必须 `InvalidArgument`；非规范多签脚本（`OP_PUSHBYTES_1 0x01` 当 OP_1）必须解析失败。

### 为什么签名准入还没开

`bitcoin_sign_request()` 返回的是**完整已签交易**，而多签的本质是"设备签一份，别的签名者签其余"。要让多签真正可用，需要的是**返回部分签名**（逐输入签名 + 保留其它输入的现有 witness），也就是一次输出格式的改动：现在 `bitcoin_sign_request` 会重建整笔交易并把自己的签名塞进每个输入，多签场景下这会把别人已经收集好的签名丢掉。

这不是"再写几个函数"，而是产品形态的选择：Ledger 的 `signPsbt` 是就地更新 PSBT，Trezor 是返回 serialized tx 加 `signatures` 数组。这个决策要一次做对，所以本轮先把摘要、脚本、program 这三块**可独立验证**的地基打牢，而不是先接一个会丢签名的半成品。

下一步（顺序不变）：`bitcoin_sign_request_psbt()` 逐输入签名 + 部分结果回填 → P2WSH 2-of-2 准入 → Lightning funding/closing 交易。通道状态机仍在最后，理由见上一轮。

### 结果

- `build_chain_native.ps1`：`bitcoin-tx=pass`（BIP341 官方七组、BIP86 地址与端到端签名、BIP143 P2SH-P2WSH 6-of-6 六组摘要、12 条 taproot 对抗用例、4 条多签脚本用例）；
- `build.ps1` 67 项 pass；`psbt_audit` 90/90；`taproot_audit` 13/13；
- `build_clang_ubsan.ps1`、`policy_check.ps1`、`device_compile_check.ps1`（esp32 与 esp32p4）通过。

### 仍未做

- 多签的**部分签名输出格式**与准入（见上）。
- Lightning funding/closing 与通道状态机。
- Stacks：仍等一条能对上 txid 的原始字节，或官方 SDK 生成的固定向量。
- SE051 实卡项（曲线装载权限、PIN 派生、会话接续、托管门）。

## 2026-11-03（十一）：PSBT in / PSBT out —— 部分签名回填

### 为什么先做这一层

`bitcoin_sign_request()` 返回的是一笔**完整已签交易**。多签的本质是"设备签一份、别人签其余"，所以在它能用之前，必须先有一个能表达"我签了，但还差别人"的输出格式。这一轮做的就是这个格式，以及它需要的写入路径。

### `bitcoin_sign_psbt()`

```cpp
TransactionError bitcoin_sign_psbt(const uint8_t *psbt, size_t psbt_size,
                                   const HdPrivateNode &master,
                                   const BitcoinChainParams &chain,
                                   uint8_t *out_psbt, size_t out_capacity,
                                   size_t *out_size,
                                   BitcoinPsbtSignSummary *summary);
```

契约三句话：

1. **只加自己那一条**。每个输入写入 `0x02 || 33 字节压缩公钥 → DER ‖ sighash` 一条（taproot 是 `0x13`）。全局 map、其它输入、所有输出 map 全部**原样拷贝**，不重新序列化字段——构造函数放进去的东西（包括本固件只是"容忍"的字段）不会被改写。
2. **别人的签名不动**。输入 map 里已有的、key 不是我们的 `0x02` 条目原样保留。这是多签能协作的前提。
3. **同 key 同值幂等，同 key 异值拒绝**。`ECDSASign` 走 RFC 6979、BIP340 也确定性，所以重复调用会得到逐字节相同的结果，此时返回 `unchanged_inputs=1` 且输出与输入相同；如果同一个 key 下已有一条值不同的条目，返回 `DuplicateField` 而不是覆盖——覆盖等于扔掉别人（或另一次我们自己）的签名。

实现上没有重新拼装 PSBT，而是先**扫描出三段的字节区间**（global / 每个 input / 每个 output，含各自的 `0x00` 终止符），然后逐段原样拷贝、只在输入段终止符前插入新条目。这样"不碰别人东西"是结构保证，而不是靠枚举已知字段。

同时把逐输入签名抽成 `sign_one_input()`，让完整交易路径和 PSBT 路径**共用同一段代码**——两条路径若各自复制一份，迟早会签出不同的字节。

### 顺带修掉一个真 bug：解析器拒绝已经带签名的 PSBT

写测试时第一次跑就撞上：`bitcoin_sign_psbt()` 的输出**自己解析不了**。原因是输入 map 解析器只认识它枚举过的 key，遇到 `0x02`（partial signature）直接 `Unsupported`。也就是说，**任何已经被别人签过的 PSBT 都进不了这台设备**——多签流程第一步就断在这里。

现在 v0 与 v2 两套输入 map 都接受 `0x02`：要求 key 是 `0x02 || 33 字节`、值长度 2..73，并且限制单个输入的条目数。这里只校验形状，**不校验别人的签名是否正确**——那是验证者的事，而且本机不该因为别人签名格式瑕疵就拒绝整笔（它仍会照常拒签自己没有密钥的输入）。

### 测试钉住的四件事

| 断言 | 含义 |
| --- | --- |
| 签名后 PSBT 仍能被 `bitcoin_parse_psbt` 接受，且手续费不变 | 输出是合法 PSBT，不是自发明的格式 |
| 我们那条 `0x02` 存在，值末字节是 sighash | 条目形状正确 |
| 构造时预置的**外来** `0x02`（另一个公钥、另一段值）在签名后逐字节仍在 | 别人的签名没被抹掉 |
| 第二次调用：`unchanged=1`、输出与第一次逐字节相同；把我们的值改一位后调用 → `DuplicateField` | 幂等与冲突拒绝 |

### 结果

- `build_chain_native.ps1`：`bitcoin-tx=pass`（BIP341 官方七组、BIP86 地址与端到端、BIP143 6-of-6、12 条 taproot 对抗用例、4 条多签脚本用例、4 条 PSBT 回填用例）；
- `build.ps1` 67 项 pass；`psbt_audit` 90/90；`taproot_audit` 13/13；
- `build_clang_ubsan.ps1`、`policy_check.ps1`、`device_compile_check.ps1`（esp32 与 esp32p4）通过。

### 下一步（顺序不变）

1. **P2WSH 2-of-2 准入**：解析 `PSBT_IN_WITNESS_SCRIPT`(0x05) 与嵌套时的 `PSBT_IN_REDEEM_SCRIPT`(0x04)，允许**多条** `0x06` 派生（其中至少一条属于本机），用 `bitcoin_parse_multisig_script()` 逐字节重建脚本并核对 `sha256` / `hash160`。这里的关键约束是：脚本必须能被设备**完整复现并显示**，否则不签。
2. Lightning funding/closing 交易（形状就是 P2WSH 2-of-2 的花费）。
3. 通道状态机——仍在最后，它要求持久化状态与在线交互，与离线签名设备的前提相反。

### 仍未做

- 多签准入与部分签名的 witness 组装（本轮只把格式和写入打通，解析器仍要求每个输入都是本机的单签密钥）。
- Lightning funding/closing 与通道状态机。
- Stacks（等一条能对上 txid 的向量，或授权用官方 SDK 生成固定 fixture）。
- SE051 实卡项。

## 2026-11-03（十二）：多签准入的尝试失败并回退——一次诚实的记录

### 做了什么，为什么退回来

这一轮的目标是把多签准入接上：解析 `PSBT_IN_WITNESS_SCRIPT`(0x05)、允许多条 `0x06` 派生、用 `bitcoin_parse_multisig_script()` 重建脚本并核对 `sha256`/`hash160`。

改动写完了，编译通过，然后 `bitcoin-tx` 立刻红了：**上一轮已经验证通过的 BIP86 端到端用例失败**。原因是把"每次遇到 `0x06`/`0x16` 就地解析"改成"先收集、map 结束再解析"之后，taproot 输入走的单签分支拿到的公钥偏移错了（`0x16` 的键是 33 字节 `0x16 ‖ x-only`，我按 34 字节 `0x06 ‖ 压缩键` 去还原，随后又用 `public_key + 1` 取 x-only，多错了一位）。修了两次仍停在 `WrongWallet`。

到这一步只剩两个选择：继续在 12 分钟里盲改一个安全关键的状态机，或者退回。**退回**——因为一个"看着支持多签、实际把 taproot 弄坏"的解析器，比完全没有多签更危险。当前工作树已回到上一轮结束时的状态，全部检查重新变绿：

- `build.ps1` 67 项 pass；
- `build_chain_native.ps1`：`bitcoin-tx=pass`（BIP341 官方七组、BIP86 地址与端到端、BIP143 6-of-6、12 条 taproot 对抗用例、4 条多签脚本用例、4 条 PSBT 回填用例）；
- `psbt_audit` 90/90、`taproot_audit` 13/13；
- UBSan、policy、esp32、esp32p4 全通过。

### 这次失败暴露的真问题

**`BitcoinInput` 只有一个 `path`/`public_key` 字段，这是多签的结构性障碍。** 单签的模型是"一个输入 = 一把钥匙"，而多签是"一个输入 = 一个脚本 + 其中若干把钥匙属于我"。把后者的信息硬塞进前者的字段里，就必然要在解析顺序上做假设（先看到脚本还是先看到派生），而 BIP174 的 map 是无序的。

正确的做法是**先把数据模型改对**，而不是先改解析器：

```cpp
struct BitcoinInput {
  ...
  // 一个输入可能引用多把本机钥匙，每把都有自己的脚本位置与派生路径
  uint8_t device_key_count;
  uint8_t device_key_index[kMaxDeviceKeys];      // 在 witnessScript 中的位置
  uint32_t device_key_path[kMaxDeviceKeys][kMaxPathDepth];
  uint8_t device_key_path_depth[kMaxDeviceKeys];
  uint8_t witness_script[kMaxWitnessScript];     // 逐字节保留，witness 按脚本顺序组装
  uint8_t witness_script_size;
  uint8_t multisig_threshold;
};
```

而且这个结构的体积决定了准入上限：`kMaxWitnessScript` 取多大，就直接决定能签 2-of-3 还是 6-of-6，也决定 `BitcoinSigningRequest` 能不能塞进任务栈（现在 `bitcoin_parse_psbt()` 用的是**局部变量**，ESP32-P4 的默认任务栈只有 8 KB）。120 字节的脚本上限 + 每个输入两把本机钥匙，是能同时满足"2-of-2/2-of-3 + Lightning funding"和栈预算的取值——但这必须先算清楚，再动解析器。

### 下一步的做法（这次先设计再动手）

1. 先把 `BitcoinInput` 的多签字段定下来，并把 `bitcoin_parse_psbt()` 的局部 `BitcoinSigningRequest` 改成写入调用方提供的目标对象（现在它在栈上复制一整份，加了多签字段后必然溢出）。
2. 再改 v0 与 v2 两个解析器，**一次只改一个**，每改完立刻跑 `bitcoin-tx`。派生收集必须在 map 结束时解析，且 `0x06`（34 字节键）与 `0x16`（33 字节键）必须各自保留自己的键长与偏移。
3. 最后接签名：`bitcoin_sign_psbt()` 每个本机钥匙写一条 `0x02`；`bitcoin_sign_request()` 只在本机钥匙数 ≥ 阈值时组装完整 witness（dummy 空项 + 按脚本顺序的签名 + 脚本）。

### 仍未做（与前几轮一致）

- 多签准入与 multisig witness 组装；
- Lightning funding/closing 与通道状态机；
- Stacks；
- SE051 实卡项。

这一轮唯一的产出是一份"什么不该做"的记录，以及一个仍然全绿的树。写下来是因为下一轮（或下一个人）会再次想从解析器下手——而这次失败说明那不是最短路径。
## 2026-11-03（十三）：多签准入第二次回退——换一个顺序

上一节写下的"先设计再动手"清单，这一轮照做了：先定 `BitcoinInput` 的多签字段，再改解析器，最后接签名。结果**仍然红**，并且这次暴露出一个与解析无关的独立缺陷。两次失败在同一处，说明问题不在细节而在顺序，所以这一节的价值主要是把顺序定下来。

### 这一轮实际写了什么

- `BitcoinSpendType::P2wshMultisig`，`BitcoinInput` 增加 `witness_script_hash[32]` / `witness_script[105]` / `witness_script_size` / `multisig_threshold` / `multisig_key_count` / `device_key_count` / `device_key_index[2]` / `device_key_path[2][10]` / `device_key_path_depth[2]`；
- v2 解析器：`0x05` 读入脚本，`0x06` 收集进 `PendingDerivation[]`，map 结束时 `resolve_multisig_keys()` 用 `bitcoin_parse_multisig_script()` 重建脚本、核对 `sha256` 与 `hash160`，再记账"第 i 把钥匙是本机的、第几个槽位"；
- `bitcoin_sign_request()`：按槽位逐个 `SIGHASH_ALL` 签，witness 组装成 `dummy ‖ 按脚本顺序的签名 ‖ witnessScript`，vsize 按 `threshold` 重算；
- `bitcoin_sign_psbt()`：每把本机钥匙写一条 `0x02`；
- 一个 2-of-2 native P2WSH 端到端用例（两把钥匙都从 mnemonic 派生）。

编译干净，然后 `bitcoin-tx=FAIL`、`bitcoin-stage=801`。

### 801 说明什么，以及我为什么停下来

801 = `800 + (int)ms_sign`，即 `bitcoin_sign_request()` 返回 `InvalidArgument`。而这个函数里能返回 `InvalidArgument` 的只有开头那一个 guard，和 `sign_multisig_key()` 自己的 guard——按用例传进去的 `input_count=1`、`output_count=1`、`version=2`、非空指针、`slot < device_key_count`，这两处**都不该触发**。

也就是说：**我对"解析器最后交给我什么"的判断是错的**，而且错在我看不见的地方。这和上一节那次失败是同一类错误——不是算错了某个字节，而是默认了某个中间状态成立。连续两轮都栽在同一个假设上，再改一版大概率还是栽。

### 独立发现的真缺陷（这条本身就足以回退）

签名路径里我写了：

```cpp
uint8_t signatures[kBitcoinMaxInputs][kBitcoinMaxDeviceKeys][kBitcoinMaxDerSignatureSize + 1];
```

展开是 `16 × 2 × 74 = 2368` 字节，**无条件**分配在 `bitcoin_sign_request()` 的栈上——单签交易也一样付这个代价。ESP32-P4 的默认任务栈是 8 KB，`BitcoinSigningRequest` 本身已经占掉一大块。这一行会把"多签支持"直接变成"所有 Bitcoin 签名的栈预算被吃掉四分之一"。

安全关键路径上的栈溢出不会给你一个错误码，它会给你一次随机复位，或者更糟：在别处崩。这类改动不该混在一个还没跑通的特性里进来。

### 所以：回退，但换顺序

工作树已回到上一版（`bitcoin-tx=pass`，`psbt_audit` 90/90，`taproot_audit` 13/13，UBSan/esp32/esp32p4 全绿）。这一轮的 diff 没有丢，存成了补丁：`files/multisig-attempt-v2.patch`（444 插入 / 37 删除），下一轮可以直接读，不用重写。

下一轮**不再从解析器下手**，顺序反过来：

1. **先写一个不碰 PSBT 的纯内存用例**：手工填一个 `BitcoinSigningRequest`（2-of-2 native P2WSH，两把钥匙都本机），断言 `bitcoin_sign_request()` 产出的 witness 逐字节正确、`txid` 与独立算出来的一致。想上 BIP143 官方 6-of-6 向量也可以——`bitcoin_sighash_witness_v0()` 已经对齐那六条摘要，缺的只是 witness 组装。
2. 签名路径跑通后，再把 `bitcoin_sign_psbt()` 的"每把钥匙一条 `0x02`"接上，用第一步的请求对象驱动，**PSBT 只作为输入源参与一次**。
3. **最后**才是解析器：`0x05`/`0x06` 的收集与解析。到这一步，任何失败都只剩"解析出来的字段对不对"，而字段对不对可以在第 1 步那个已知正确的请求对象上逐字段比对。

这样做还有一个好处：第 1 步和第 2 步完全在主机上可测，不依赖 PSBT 编码，一旦红了，搜索范围只有 witness 序列化和 sighash——现在这个范围是"解析器 + 请求模型 + 签名 + 组装"四件事一起。

### 仍未做（与上几轮一致，不再重复理由）

- 多签准入与 multisig witness 组装；
- Lightning funding/closing 与通道状态机；
- Stacks（等一条能对上 txid 的向量，或授权用官方 SDK 生成固定 fixture）；
- SE051 实卡项。

### 顺带说明为什么这轮没有别的产出

用户这一轮要的四件事里，三件依赖多签准入（Lightning funding/closing 就是 P2WSH 2-of-2 的花费），Stacks 缺可验证向量，SE051 缺实卡。多签不通过，其余三件没有可交付的部分——与其把 `bitcoin_sign_psbt()` 的 `0x02` 写入说成"多签已支持"（它只写了自己那把钥匙的签名，组装不出完整 witness，广播必然失败），不如留着这个空档。
