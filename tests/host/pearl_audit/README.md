# Pearl native key-path audit

The upstream oracle is [pearl-research-labs/pearl at d7c517d267f10f5bcbbdc366f3e603942f9a5ab5](https://github.com/pearl-research-labs/pearl/tree/d7c517d267f10f5bcbbdc366f3e603942f9a5ab5). `oracle/main.go` calls its BIP32 derivation, Taproot tweak, BIP341 digest, Schnorr signer, transaction serializer and script engine. No firmware code is used to generate expected values.

`vectors.txt` SHA-256: `c9cc8ded1b77d0124bc10425b1d0e1aa4b6b84874ead3e5bd15b4b85411ae06d`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/host/pearl_audit/run.ps1
```

The normal run uses the checked-in vectors and Mbed TLS 3.6.5 at `build/chain-mbedtls`, revision `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`. `-RefreshOracle` first regenerates the fixture and requires:

- The clean, pinned Pearl checkout in `build/pearl-oracle`.
- Go in `build/pearl-toolchain/go/bin/go.exe`. The verified toolchain used here is [Go 1.26.10 for Windows amd64](https://go.dev/dl/go1.26.10.windows-amd64.zip), archive SHA-256 `7ecd2d7260e82c59bcbd7f1077a07cee2dea607295b858df67195a1e4e09629b`. Extract locally; no system installation is needed.
- Network access for Go modules on the first run. Module versions and checksums come from the pinned upstream `go.mod` and `go.sum`; CGO and automatic toolchain downloads are disabled.

Six public fixtures cover receive/change keys and input values 100,000, 2,100,000,000,000,001 and 2,100,000,000,000,000,000 grains. Each has DEFAULT and ALL signatures. The upstream engine validates every witness and rejects a corrupted signature for each. Firmware addresses, digests and complete signed transactions must match; both PSBT versions are exercised. Negative checks cover network/coin-type substitution, unsafe sighashes, excessive values and unsupported witness versions. Tests use only the explicitly public seed `000102...1f`.

This proves compatibility of the bounded native key-path implementation with the pinned node's script engine. It does not establish mempool acceptance of funded transactions, mainnet settlement, script-path/P2MR/XMSS support, firmware physical confirmation, SE051 custody or side-channel resistance. The runner records source hashes and rejects a result if sources change during the audit.
