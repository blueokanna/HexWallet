# 密码学栈

扩展密码学栈位于 `Ed25519.cpp`、`BlsG1.cpp`、`CryptoExtended.cpp`、
`WalletAltAddresses.cpp` 以及编码器辅助文件（`base58`、`local_bech32`、
`local_segwit`、`keccak256`、`local_ripemd160`）。每个原语都在固件启动前
于主机上对照官方测试向量验证。

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

已验证地址（权威）：seed `c55257…`（64 B）→ `xch1sqh8a9…`；64×`0x01`
seed → `xch1wv0k6…`；16 字节 `000102…0f` seed → `xch14jaaa4…`。

## 备选地址编码器

`WalletAltAddresses.cpp` 实现了 Solana（base58）、Algorand、Tezos `tz1`、
Qubic、cashaddr（BCH + eCash）、Avalanche `X-`、Cosmos bech32
（CRO/SEI）、Cardano base 地址，并通过完整 `alt-addresses` 主机套件。

## 大数卫生（经验教训）

- 绝不让 `mod` 返回负数或未约减值；统一归一到 `[0, B)`。
- 长除法对「被除数 limb 数约为除数 2 倍」必须精确。
- add/mul/mod 必须处理别名（`X == A`）—— 点运算里到处都是别名。
- 标量乘在高位"随机"失败时，先怀疑累加器的**符号**，而不是标量本身。
