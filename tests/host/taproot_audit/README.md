# Taproot independent checks

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/taproot_audit/run.ps1
```

`bip341-wallet-test-vectors.json` is the unmodified [Bitcoin BIP341 wallet fixture](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json), downloaded 2026-11-03. SHA-256: `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f`. The BIP is BSD-3-Clause licensed. `prepare.ps1` verifies this digest before producing `vectors.txt`.

The executable loads the published unsigned transaction and prevouts, then calls the firmware's public sighash API. All seven published key-path cases are checked, including NONE, SINGLE and ANYONECANPAY. This tests the hash primitive; wallet signing policy remains DEFAULT/ALL only.

Three additional expectations extend the published DEFAULT SigMsg with annex lengths 1, 252 and 253. They are calculated with .NET SHA256 independently of the firmware, following BIP341's CompactSize-prefixed annex hash. These are locally constructed regression vectors, not published Bitcoin test vectors.

The runner records source hashes and rejects a run if source files change during the build/test. Actual BIP32/Schnorr, BIP371 v0/v2 parsing, change ownership and final witness verification are checked separately by `tests/host/psbt_audit/run.ps1`. Neither suite proves script-path or multisig support, full-node acceptance, physical approval, side-channel resistance or non-exportable SE custody.
