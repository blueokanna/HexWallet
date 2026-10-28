# Solana、SPL Token 与 Token-2022 转账

实现位于 `SolanaTransaction.cpp`，通过 `WalletSigning` 的设备批准流程接入。手机使用 `BEGIN_SIGN kind=6`、币种 `sol`，payload 为**原始序列化 message**，不是 JSON，也不是带签名的 transaction。`RESULT` 返回完整的 `shortvec(1) || signature || message`，广播由手机完成。

接收地址与签名共用 `SolanaDerivation.h` 的路径 `m/44'/501'/0'/0'/index'`，沿用工程既有地址路径。不能无提示地改成其他钱包常用的四级路径，否则同一助记词会得到不同账户。

## 已接入范围

- Legacy 和 v0 message；v0 的地址查找表数量必须为零。
- 单签名者，付款账户和转账授权者必须是当前设备派生的账户；原生 SOL 和经典 SPL 转账合计最多 16 条，完整交易不超过 1232 字节。
- System Program 的 Transfer 指令。每条接收地址和 lamports 从原始字节解析，在设备显示后才允许签名。
- 经典 Token Program `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` 与 Token-2022 Program `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` 的 `TransferChecked`。不要求 mint 预先登记，所以可处理这两个程序下未登记的代币；这不表示支持任意区块链或任意自定义程序。
- Token-2022 的 mint 扩展无法离线核验：转账税会让收款方实际到账少于显示金额，transfer hook 可能在转账中执行额外程序。审阅页对每条 Token-2022 转账显示独立的 `TOKEN-2022` 标签和警告；要求额外 hook 账户的指令一律拒绝（账户数必须恰好为 4），`TransferCheckedWithFee`、unchecked `Transfer`、confidential transfer 等其余指令全部拒绝。
- SPL 指令必须严格为 `[source, mint, destination, authority]`，source/destination 可写、mint 只读、authority 为设备账户，不接受额外账户。同一 mint 的精度必须一致，同一代币账户不能在同一交易里被声明为不同 mint。
- 屏幕显示完整 mint、来源代币账户、目的代币账户、精确数量、原始整数数量及签入的 decimals。未知代币仅标为 `token`，不使用手机提供的名称、符号或价格。精度 0–19 用整数运算显示小数，20–255 显示精确的 `整数 x 10^-精度`，没有浮点舍入。
- 不同 mint 的数量不会相加；`TOTAL` 只统计原生 SOL 转账和预计 SOL 费用。SPL 数量单列。
- 可选的 Compute Budget limit/price 必须各有一条，且位于所有转账之前。优先费按 `ceil(limit × price / 1000000)` 计算，检查乘法溢出及本地费用上限。
- 签名前再次解析消息，比较付款账户、来源、目的账户、mint、精度、转账类型、金额、原生总额和费用摘要。失败、拒绝或超时均不能继续使用批准。

拒绝额外签名者、非规范 shortvec、重复账户、越界索引、未使用账户、未知指令、未知版本、ALTs、耐久 nonce、质押及任意程序调用。两个 Token Program 的 unchecked Transfer、Approve、SetAuthority、Burn、CloseAccount、ATA 创建、批量指令与多签账户均拒绝。Token-2022 的扩展语义不做猜测：设备只按 `TransferChecked` 的精确字节签名，并明确告知扩展风险。

## 接收与账户身份

现有 SOL 接收地址是设备派生的 owner 地址。接收经典 SPL 时，发送方或手机需要为这个 owner 和指定 mint 查询或创建代币账户；链上建账户和广播均由外部主机完成。当前设备不签 ATA 创建交易，首次发送前目的代币账户必须已存在。

`TransferChecked` 绑定 mint 和精度，由链上 Token Program 检查账户状态。消息没有携带目的代币账户的 owner，离线设备不能把手机声称的 owner 当作已验证的钱包地址。本实现显示的是**目的代币账户本身**，不显示虚构的接收人 owner，也不将其标为已验证 ATA。必须按完整 mint 与完整目的代币账户核对收款信息；设备暂不提供独立 ATA 派生/确认接口。

## 离线边界

基础费 5000 lamports 是当前离线费率假设，不是交易内签入的上限。屏幕使用 `EST. FEE`，不能伪称节点确认的实际费用。节点费率、付款账户状态、区块哈希有效期及目标 cluster 由手机验证；Solana message 本身不包含主网/测试网标识。

固件不请求 RPC、不下载元数据，也不查询余额、冻结状态或 mint 状态。无效账户状态可能导致已签交易被节点拒绝并收取网络费。显示、批准及签名都不能证明代币的市场价值或发行方身份。

## 证据

`tests/reference/generate_solana_vectors.py` 使用固定的 solders 0.26.0 生成 `tests/fixtures/solana-sdk.json`；不调用钱包代码。使用公开测试种子及合成 blockhash，**禁止收款，也不代表节点验收**。

`tests/test_solana.py` 对真实 C++ 适配器检查：6 组完整交易字节和显示字段、所有截断位置、错误所有者、批准摘要篡改、短输出缓冲、未知程序、非法账户权限、费用溢出和未解析查找表。Python 测试调用 `solana_probe.exe`；UBSan 构建可通过 `HEXWALLET_SOLANA_PROBE` 指向 `solana_probe_clang.exe`。

`tests/reference/generate_spl_vectors.py` 独立使用 solana-py 0.36.6 编码 SPL 指令、solders 0.26.0 编译并签名；输出 `tests/fixtures/spl-sdk.json`，记录生成器哈希、版本、公开测试种子和合成账户来源。`tests/test_spl.py` 比较 16 组合法交易的完整签名字节及全部审阅字段，覆盖 legacy/v0、多个 mint、SOL 混合转账、16 条转账、uint64 最大值及精度边界。另检查 25 组拒绝案例、每个截断位置、批准后 mint/来源/目的/精度/类型/数量篡改。

`tools/generate_spl2022_vectors.py` 只用 vendored solders 0.28.0（`build/spl-svm-reference`）编译消息、派生 ATA 并签名，输出 `tests/fixtures/spl-2022-sdk.json`；签名由 SDK 完成，不调用固件。`tests/test_spl2022.py` 校验 5 组合法交易的完整签名字节与全部审阅字段（含 legacy/v0、优先级费、0/18 位精度、经典与 Token-2022 混合），以及 7 组拒绝指令（unchecked Transfer、`TransferCheckedWithFee`、hook 额外账户、只读来源、零金额、同 mint 冲突精度、payer 作为来源）、全截断和批准后篡改。`--check` 可验证仓库产物未过期。

`tests/reference/verify_spl_execution.py` 在 solders 0.28.0 自带 LiteSVM 中执行 **C++ 固件实际签出的交易**，保持签名和 blockhash 检查开启。两组正常交易验证扣账、到账和实际费用；七组异常覆盖精度、授权、mint 不匹配、冻结、余额及签名损坏。测试注入账户初始状态，记录 Token Program 内容哈希及执行结果到 `build/spl-svm-execution.json`；CI 保存这个文件。它是独立虚拟机执行证据，不是主网节点验收。

审阅文本使用固定大小的主循环专用缓冲，结束后清空；mint 和来源地址独立渲染并允许换行，避免通用摘要缓冲截断关键身份字段。此处尚无实机帧率或栈余量测量，不能把编译结果当成性能验收。

协议依据：[Solana transactions](https://solana.com/docs/core/transactions)、[fees](https://solana.com/docs/core/fees)、[TransferChecked](https://solana.com/docs/tokens/basics/transfer-tokens)、[经典 Token Program v9.0.0](https://github.com/solana-program/token/tree/program%40v9.0.0)、[Token-2022 extensions](https://spl.solana.com/token-2022/extensions)。整机触屏、SE050 保护和新签交易的节点验收仍需独立证据。
