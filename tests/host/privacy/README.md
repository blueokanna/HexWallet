# Ryo MLSAG / Zano CLSAG_GGX

固件实现位于 `RyoMlsag.cpp`、`ZanoClsag.cpp`。两者使用不同的挑战转录和签名格式；共享层只负责规范标量、子群检查、流式 Keccak、秘密标量运算与 nonce 派生。

`RyoBulletproof.cpp` 验证 Ryo 原始 64 位 Bulletproof，逐个检查多项式承诺和内积两条方程，支持 1–16 输出。生成元按上游的 `bulletproof` 域及双重 Keccak 派生；验证过程使用有界栈内存，无堆分配或随机批验证权重。

这两个接口是交易签名器的密码学后端。它们不会验证收款地址、金额、范围证明或设备确认状态，不能直接作为接收主机摘要的签名命令。Ryo/Zano 的 `SIGN_TX` 准入没有开放。

## 协议边界

- Ryo：Simple/Bulletproof 双行 MLSAG，关联 key image 的花费行和无 key image 的承诺差额行。支持 2–241 个环成员；当前分叉的最小环规则由交易准入层另行校验。不是 Monero CLSAG 或 Bulletproofs+。
- Zano：普通隐私花费 CLSAG_GGX。三个见证分别对应花费密钥、金额承诺差额、资产承诺差额；资产行使用 X。承诺、K1/K2 按协议使用除以 8 的编码。容量为 1–256 个环成员，这是实现限制，不是共识声明。不包含 GGXXG 质押。
- 输入点必须采用规范编码并属于主子群，花费公钥不得为单位元或重复。零承诺差额允许对应单位元辅助 key image。
- nonce 使用 HMAC-SHA512，把私有见证、完整公共转录、链/算法域、真实位置、用途及设备熵绑定后规约为标量。消息或环改变时，即便熵重复，也会重新派生 nonce。调用方仍必须使用设备随机源。
- 秘密标量与未发布的响应使用常数步数的点乘路径。公有验签才使用变时双标量乘。所有私有临时状态以 RAII 清零；任意失败擦除整个输出结构；输出前重新验签。

签名输出由调用方持有：Ryo 结构为 15,490 字节，Zano 为 16,514 字节。设备集成应把它们放入有明确生命周期的事务状态区，不能只依据签名函数自身的栈帧大小估计完整调用链预算。

这些设计与回归测试不能代替针对具体 MCU、编译器和固件版本的侧信道、故障注入及实体设备测试。

## 独立验证器

固定源码版本：

- [Ryo 185dd1fa33ba88c88bb22df9069ad368c0f9a27e](https://github.com/ryo-currency/ryo-currency/tree/185dd1fa33ba88c88bb22df9069ad368c0f9a27e)
- [Zano b543053953f74c38a32d29a087ec586943b4a321](https://github.com/hyle-team/zano/tree/b543053953f74c38a32d29a087ec586943b4a321)

`prepare_oracle.py` 检查 LF 规范化后的源码 SHA-256，原样提取 Ryo `MLSAG_Ver` 和 Zano `verify_CLSAG_GGX` 函数，保留上游许可声明。测试适配层把上游容器类型连接到 Zano 的 ref10 和 Keccak；两种验证器均不使用 HexWallet 的曲线或散列实现。G/X 常量与域分隔符直接取自固定上游源码。

Ryo `bulletproof_VERIFY` 也从同一固定提交原样提取。适配器每次只验证一个证明，使用非零固定权重 1，保留两条独立方程检查；多标量运算由上游 ref10 逐项累加。上游测试中的四个固定证明连同许可声明保存在夹具里；其他输出形状由独立 Python 测试证明器产生，并先经过上游验证器验收。

准备对应提交的源码后，在已初始化 MSVC 的 PowerShell 中运行：

```powershell
cmake -S tests/host/privacy -B build/privacy-oracle -G 'Ninja Multi-Config' `
  -DRYO_SOURCE=<Ryo源码绝对路径> -DZANO_SOURCE=<Zano源码绝对路径>
cmake --build build/privacy-oracle --config Release
python tests/host/privacy/privacy_interop.py `
  --probe build/chain-native/Release/chain_probe.exe `
  --oracle build/privacy-oracle/Release/privacy_oracle.dll --large-rings
```

`--write-fixtures` 会重新生成 `tests/fixtures/privacy/ring-signatures.json`，只有加载独立验证器后才允许使用。每份夹具记录两个签名：固件产生的确定性测试签名，以及 Python 独立生成、经上游验签的签名。公开测试见证不能用于保管资产。

常规回归不需要上游源码或 DLL：

```powershell
python tests/host/privacy/privacy_interop.py --probe build/chain-native/Release/chain_probe.exe
python tests/host/privacy/bulletproof_interop.py --probe build/chain-native/Release/chain_probe.exe
```

覆盖环首、中间、末尾的真实位置、零差额、Ryo 的 25/241 成员环及 Zano 的 1/16/256 成员环。负例包括错误见证、错误伪输出、非规范标量、低阶点、重复成员、签名各组成项篡改和截断的测试输入。测试桥在签名失败时逐字节检查输出结构已清零。

范围证明的独立复现及夹具更新命令：

```powershell
python tests/host/privacy/bulletproof_interop.py `
  --probe build/chain-native/Release/chain_probe.exe `
  --oracle build/privacy-oracle/Release/privacy_oracle.dll `
  --ryo-source <Ryo源码绝对路径> --write-fixtures
```

## Ryo 原生交易验证

`RyoTransaction.cpp` 解析 v2/v3、RingCT type-3，计算交易 ID 与 pre-MLSAG 摘要，并验证原始 Bulletproof、承诺平衡及逐输入 MLSAG。v3 前缀哈希带 `ryo-currency` 域；proof count 是固定 u32 LE，ECDH 是旧版 64 字节编码，不能用 Monero type-6 格式替代。

`ryo_transaction_interop.py` 从独立范围证明与公开测试见证生成完整合成交易。Python 独立组装字节，使用上游 Keccak/ref10 与原始 `MLSAG_Ver` 验收签名；固件核对固定的五种摘要并验证交易中的证明和签名。它没有执行上游节点的完整交易解析器，不是主网接收记录。

```powershell
python tests/host/privacy/ryo_transaction_interop.py --probe build/chain-native/Release/chain_probe.exe
# 重建公开夹具；会校验固定上游协议源文件的 SHA-256。
python tests/host/privacy/ryo_transaction_interop.py --probe build/chain-native/Release/chain_probe.exe `
  --oracle build/privacy-oracle/Release/privacy_oracle.dll --ryo-source <Ryo源码目录> --write-fixtures
```

4 组夹具包含 v2/v3、25/241 成员环、8 输入及 16 输出。负例覆盖非最短 varint、计数越界、相对索引溢出/重复、证明布局、身份点、非规范标量、金额密文、费用、extra、伪输出、MLSAG 和环成员篡改。每组还遍历全部截断位置，运行 10,000 次定向变异及 1,000 组随机输入；失败时解析视图和摘要输出必须清零。

## 付款夹具

`tests/fixtures/privacy/ryo-historical-spends.json` 保存前一轮两笔各付 1,000,000 原子单位的完整签名字节与按输入排序的环。它们的 SHA-256 与历史验签记录一致；按当前节点费用规则，这两笔交易均低于下限。

在仓库根目录运行 `python tests/host/privacy/payment_interop.py --probe <chain_probe.exe> --oracle <privacy_oracle.dll>`。116 项检查涵盖 Ryo 输入来源与环索引、复核费用和 payment ID 后的整笔签名，以及 Zano 普通输出的构建和归属扫描。Ryo 的两个 25 成员环付款例分别使用一个和两个输入，手续费均恰好达到 `Blockchain::check_fee()` 的分叉下限。另一个金额守恒的付款少付一个原子单位，审阅失败。独立验证器按输入检查实际签名字节。固定夹具保留完整签名交易的 SHA-256。省略 `--oracle` 时仍检查固定摘要和固件验签。

开启 `TEST_RYO_PHONE_PAYMENTS` 的专用探针通过模拟按键批准。`ryo_ledger_check.py --probe <专用探针> --oracle <privacy_oracle.dll> --ryod <ryod> --wallet-rpc <ryo-wallet-rpc>` 会创建隔离链、开采成熟输入并等待两笔入块。官方只读钱包核对交易 ID、高度、金额、收款地址和完整 payment ID。`phone_payment_check.py` 使用相同的探针和上游库，另传 `--release-probe <默认探针>` 以核对默认目录拒签。

`node tests/host/privacy/zano_ledger_check.cjs <chain_probe>` 读取 `tests/fixtures/privacy/zano-mainnet-payments.json`，用主网原始前缀哈希调用固件验签，使用手机代码验证普通 v4 付款的全部证明，并逐字节对照重编码。CLSAG_GGX 的 `add_scalar(m)` 会将前缀哈希以小端整数模 L 规约。两笔交易的其他证明分别按上游转录规则使用前缀哈希。[实链证据](../../../wiki/validation.md)

## Zano 自建付款与收款扫描

在仓库根目录安装 `tools` 的锁定依赖。准备好前述 Mbed TLS 3.6.5 和默认 `chain_probe` 后，另建专用主机探针。

```powershell
npm ci --prefix tools --ignore-scripts
cmake -S tests/host/chain -B build/zano-phone-host -A x64 -DTEST_ZANO_PHONE_PAYMENTS=ON
cmake --build build/zano-phone-host --config Release --target chain_probe
node tests/host/privacy/zano_phone_check.cjs build/zano-phone-host/Release/chain_probe.exe build/chain-native/Release/chain_probe.exe
```

脚本使用公开测试助记词检查默认目录拒签、归属、金额、找零、费用、payment ID 和一次性批准。单输入案例恰好花完，给同一地址生成两个输出。双输入案例有找零。广播成功路径使用模拟 RPC，校验错误创世哈希或签名时会检查提交次数为零。

隔离链使用单独的 Zano 源码目录。固定提交及子模块后应用附带的补丁，只调整测试网 HF4 至 HF7 的激活高度。按上游依赖说明配置 Boost 和 OpenSSL 并编译同一套 `zanod` 和 `simplewallet`。Windows 实测使用 Boost 1.84 和 OpenSSL 3。

```powershell
git clone https://github.com/hyle-team/zano.git build/zano-private
git -C build/zano-private checkout b543053953f74c38a32d29a087ec586943b4a321
git -C build/zano-private submodule update --init --recursive
git -C build/zano-private apply (Resolve-Path tests/host/privacy/zano-private-testnet.patch).Path
micromamba create -y -p build/zano-native-deps/env -c conda-forge 'libboost-devel=1.84.*' 'openssl=3.*'
$deps = (Resolve-Path build/zano-native-deps/env/Library).Path.Replace('\','/')
$libs = (Get-ChildItem "$deps/lib/boost_*.lib" | ForEach-Object { $_.FullName.Replace('\','/') }) -join ';'
$flags = '/DWIN32 /D_WINDOWS /DBOOST_ALL_NO_LIB /DBOOST_THREAD_USE_DLL /DBOOST_FILESYSTEM_DYN_LINK /DBOOST_LOG_DYN_LINK /DBOOST_PROGRAM_OPTIONS_DYN_LINK /DBOOST_CHRONO_DYN_LINK /DBOOST_ATOMIC_DYN_LINK /DBOOST_LOCALE_DYN_LINK /DBOOST_REGEX_DYN_LINK /DBOOST_DATE_TIME_DYN_LINK'
$env:PATH = "$deps/bin;$env:PATH"
cmake -S build/zano-private -B build/zano-private-core -A x64 -DTESTNET=ON -DSTATIC=OFF -DDISABLE_MDBX=ON -DCOMMIT_ID_IN_VERSION=OFF '-DCMAKE_POLICY_VERSION_MINIMUM=3.5' "-DBoost_FATLIB=$libs" "-DBoost_INCLUDE_DIRS=$deps/include" "-DOPENSSL_ROOT_DIR=$deps" "-DCMAKE_CXX_FLAGS=$flags"
cmake --build build/zano-private-core --config Release --target daemon simplewallet
python tests/host/privacy/zano_private_ledger.py --probe build/zano-phone-host/Release/chain_probe.exe --release-probe build/chain-native/Release/chain_probe.exe --zanod build/zano-private-core/src/Release/zanod.exe --simplewallet build/zano-private-core/src/Release/simplewallet.exe
```

脚本创建临时节点和收款钱包，在付款前导出只读钱包。测试收集成熟输出和每个输入的 15 个诱饵，提交签名交易，核对内存池、区块高度及节点保存的完整字节，再查询只读钱包的 `payments` 记录。每次运行独立生成交易密钥、收款钱包及证明，交易 ID 随之变化。[回执](../../../wiki/validation.md)
