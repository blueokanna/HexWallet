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

完整交易验收仍需要：Ryo 发送交易构建、输入/输出所有权与金额审阅、uniform payment ID、分叉策略；Zano 的资产、范围和平衡证明及交易序列化；两条链的签名前复核、设备确认和节点接受真实交易的记录。原生验证层没有开放 Ryo/Zano 生产签名准入。
