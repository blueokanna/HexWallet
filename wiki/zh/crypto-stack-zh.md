# 密码学栈

扩展密码学栈位于 `Ed25519.cpp`、`BlsG1.cpp`、`CryptoExtended.cpp`、
`WalletAltAddresses.cpp` 以及编码器辅助文件（`base58`、`local_bech32`、
`local_segwit`、`keccak256`、`local_ripemd160`）。每个原语都在固件启动前
于主机上对照官方测试向量验证。

严格构建说明：CryptoNote、QRL、Chia/BLS 等仅地址原语是内部库，只有在完整收/发/签名路径同时交付时才会进入钱包目录；当前不会作为钱包暴露。

## Ed25519（RFC 8032）

- 纯域/群运算，位于 `Ed25519.cpp`，不依赖外部大数库。
- 挑战标量是 `SHA-512(R ‖ A ‖ M)` 的**完整 64 字节**摘要对群阶 `L` 取模
  —— 经典错误是只对前 32 字节取模。我们使用专用的全宽归约处理完整
  512 位摘要。
- 已用 RFC 8032 TC1/TC2 验证（公钥 `d75a9801…`、签名 `e5564300…`）。

## SLIP-10 Ed25519

- `slip10_ed25519_derive(seed, seed_size, path, path_len, out)`。
- seed 长度是显式参数 —— 静默假设 32 字节会破坏官方 16 字节向量
  （`000102…0f` → 子密钥 `0'` = `68e0fe46…`）。

## EIP-2333 / ERC-2333（BLS12-381 密钥树）

Chia/BLS 密钥树。规范已迁移到 ERC-2333；要点如下：

- `hkdf_mod_r`：`salt = "BLS-SIG-KEYGEN-SALT-"`，然后进入 **salt 循环**
  （`salt = H(salt)`），再 `PRK = HKDF-Extract(salt, IKM ‖ 0x00)`、
  `OKM = HKDF-Expand(PRK, I2OSP(48,2), 48)`；对群阶 `r` 取模。
- `parent_SK_to_lamport_PK`：`salt = I2OSP(index, 4)`；
  `lamport_0 = IKM_to_lamport_SK(parent_SK, salt)`；
  `not_IKM = flip_bits(parent_SK)`；`lamport_1 = IKM_to_lamport_SK(not_IKM, salt)`。
  **`IKM_to_lamport_SK` 是「一次」HKDF-Extract + HKDF-Expand（info 为空），
  产出 255 个 32 字节块** —— 不是 255 次独立 HMAC。对每个块做 SHA-256
  （先全部 `lamport_0`，再全部 `lamport_1`），再对拼接结果做 SHA-256，
  得到 32 字节压缩 Lamport 公钥。
- `derive_child_SK(parent, index) = hkdf_mod_r(compressed_lamport_PK)`。

已对照官方 ERC-2333 Test Case 0 验证：主私钥、压缩 Lamport 公钥
（`dd635d27…`）、子私钥全部匹配。

## BLS12-381 G1

- `BlsG1.cpp` 使用 mbedtls 大数 shim 实现域/群运算、标准生成元（取 `y`
  较小根：`x = 17f1d3a7…`、`y = 08b3f481…`），以及 48 字节 ZCash 风格压缩
  （`C=0x80`、`I=0x40`、`S=0x20` 当 `y > p - y`）。
- `bls pk(sk=1)` = `97f1d3a7…`，派生密钥公钥 `a5336788…` 均对照独立纯
  Python 实现校验。

### 踩过的大数陷阱

`mbedtls_mpi_mod_mpi` 对负数输入必须返回**最小非负剩余**
（`A mod B`、`B > 0` → `[0, B)`）。点公式
`x3 = λ² − x1 − x2`、`y3 = λ(x1 − x3) − y1` 会频繁产生负中间值。如果
`mod` 直接把负数原样返回（朴素 `cmp(A,B) < 0 ? copy(A)` 就会这样），点累加器
会静默累积出**未约减的 12-limb** 坐标，下一次 `inv_mod(2y, p)` 就返回
`NOT_ACCEPTABLE`。所有"纯正数"单测（`3^100 mod 7`、`P mod P`、
`okm mod r`）都能通过，只有完整点运算才会暴露。修法：先约减 `|A|`，
非零时再 `B − |A|`。

## Zcash 透明 v4 / ZIP-243

- `ZcashTransaction` 只签名 Overwinter/Sapling v4 透明 t1 P2PKH 输入。屏蔽
  spend/output、JoinSplit、v3/v5 和已有 scriptSig 在派生任何密钥之前就被拒绝。
- 摘要使用 `"ZcashSigHash" || branch_id_le` 个性化的 BLAKE2b-256，覆盖 v4
  header、`hashPrevouts`、`hashSequence`、`hashOutputs`、
  `hashJoinSplits`、`hashShieldedSpends`、`hashShieldedOutputs`、lock time、
  expiry height、value balance 和 hash type，再追加当前输入的
  outpoint/scriptCode/amount/sequence。`Blake2b` 新增了 personalization；
  keyed hash 不能替代它。
- 主网分支 ID 是显式网络策略（`0x5437f330`，NU6.2），不是主机任意传入的
  参数。`zec inspect` 审查带每个 prevout 金额和 scriptPubKey 的紧凑 payload；
  `zec sign` 重新派生 `m/44'/133'/account'/change/index`、校验 prevout
  HASH160，并输出 v4 交易和 txid。
- 启动自检校验官方 ZIP-243 test vector 3（`f3148f80…`）以及解析/手续费失败
  路径；完整签名路径由设备上的 `run_zcash_transaction_self_test()` 覆盖。

## CryptoNote（Monero / Masari）

- Spend key = `sc_reduce32(Keccak-256(seed))`，view key =
  `sc_reduce32(Keccak-256(spend))`，与 32 字节 seed 下的
  `crypto::generate_keys` 一致。
- 公钥使用 Edwards25519 群和 Monero 编码（小端 `y` 加 `x` 的符号位）。
  点解压、加法和标量乘实现在 `Ed25519.cpp`（`edwards_decompress`、
  `edwards_add`、`scalarmult_point`），这条曲线不再依赖外部大数库。
- 子地址遵循 `device_default.cpp`：`m = sc_reduce32(Keccak-256(
  "SubAddr" ‖ view_secret ‖ major_le32 ‖ minor_le32))`、`D = B + mG`、
  `C = view_secret · D`，主网前缀 `42`。集成地址追加 8 字节 payment ID，
  前缀 `19`；`(0,0)` 即标准地址。
- 标量乘始终执行加法并用常数时间掩码选择结果，标量位不控制分支。
- 向量：零 seed 的 spend/view key 与标准地址、两个子地址、集成地址、
  以及原有合成基点向量，均对照独立 Keccak/Edwards 参考实现。

## QRL XMSS-SHAKE256

- QRL 没有 BIP32 树。`qrl_seed_from_bip39` 用 SHAKE-256 和域字符串
  `HexWallet/QRL/v1` 把 BIP39 seed 扩展为 48 字节。
- `qrl_xmss_public_key` 执行高度 10 的 XMSS treehash：SHAKE-256 扩展出
  `sk_seed ‖ sk_prf ‖ pub_seed`，WOTS+ `w=16`（67 条链）、L-tree 压缩、
  Merkle 栈。公钥为 `descriptor ‖ root ‖ pub_seed`（67 字节）。
- 地址为 `Q` + `descriptor ‖ SHA-256(pubkey) ‖ SHA-256(descriptor ‖
  hash)[-4:]` 的十六进制（39 字节），与 `QRLHelper::getAddress` 一致。
- 已对照 qrllib 的 `XmssBasicSHAKE256` 向量（48 字节零 seed、高度 4、
  地址 `Q0202000f9ec8…`）。生产高度 10 约需三百万次 SHAKE-256；进度回调
  让 MCU 调用方可以喂狗。有状态签名故意未实现。

## 安全芯片托管

`WalletCustody` 把每个 `AddressEncoding` 映射为 `KeyScheme`，回答安全芯片
能否持有密钥并产生该链需要的精确签名。默认活动配置是纯 MCU；只有板级移植
探测 applet 并调用 `set_active_secure_element_profile()` 后才会改变。保守的
SE050C1H1 目标配置只声明 secp256k1 + ECDSA + seed 封装：BTC/LTC/ETH 类密钥可以导入并在
applet 内签名；Kaspa（BIP340 Schnorr）以及内部保留的 Ed25519/BLS/XMSS
密钥都保留在 MCU RAM，直到 applet 路径在硬件上验证通过。BIP32/SLIP-0010 派生本身始终在 MCU 完成，因为 SE050 没有
BIP32 引擎。该策略是代码而非宣传：`wallet custody <id>` 会输出结论与原因。

## Chia 标准地址

`chia_standard_address(seed, address_index)`：

1. `sk = master(seed)`；然后对 `i ∈ {12381, 8444, 0, index}` 依次
   `sk = child(sk, i)`。
2. `pubkey = compress(sk · G)`。
3. `hidden_hash = shatree_pair(shatree_atom(0x09), shatree_atom(nil))`
   （`ff0980` 默认隐藏谜题）。
4. `offset = int(SHA256(pubkey ‖ hidden_hash)) mod r`。
5. 合成公钥 = `(sk + offset) · G`，压缩。
6. `puzzle_hash = curry_and_treehash(P2_DELEGATED…, synthetic)`，使用
   `e9aaa49f…` 模块哈希与 CLVM `shatree` 规则（`0x01 ‖ atom`、
   `0x02 ‖ left ‖ right`）。
7. `bech32m("xch", puzzle_hash)`。

已验证地址（权威）：seed `c55257…`（64 B）→ `xch1yvsm3y…`；64×`0x01`
seed → `xch14e2x9…`。向量由 blspy 生成；Chia 的 HKDF 使用原始盐，而不是先哈希。

## 备选地址编码器

`WalletAltAddresses.cpp` 实现了 Solana（base58）、Algorand、Tezos `tz1`、
cashaddr（BCH + eCash）、Avalanche `X-`、Cosmos bech32
（CRO/SEI）、Cardano base 地址，并通过完整 `alt-addresses` 主机套件。

Qubic 被有意排除：它的身份是 FourQ 曲线点经 KangarooTwelve 得到的，旧的
Ed25519/SHA3/base26 替代实现只会产出不可花费的身份。该编码器、网络 profile
和枚举项已整体删除，而不是留着一个“看起来合理”的地址来源。

## 大数卫生（经验教训）

- 绝不让 `mod` 返回负数或未约减值；统一归一到 `[0, B)`。
- 长除法对「被除数 limb 数约为除数 2 倍」必须精确。
- add/mul/mod 必须处理别名（`X == A`）—— 点运算里到处都是别名。
- 标量乘在高位"随机"失败时，先怀疑累加器的**符号**，而不是标量本身。
