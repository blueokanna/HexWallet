# Kaspa v0 reference checks

Reference revision: [`kaspanet/rusty-kaspa@5417ed03f4732459cdd594ee0d1bb868c3838bde`](https://github.com/kaspanet/rusty-kaspa/tree/5417ed03f4732459cdd594ee0d1bb868c3838bde).

`p2p.proto` is the unmodified upstream `protocol/p2p/proto/p2p.proto`, under the accompanying ISC license. Its SHA-256 with LF line endings is `4b7e0a1d4123cda5b5ca2257d04e61d0a6b25fe244a7a19d8bb588535a702f3f`; the test checks this before loading descriptors.

The reference test reads the schema and uses Google Protobuf 6.33.5 to encode transactions. It does not call the firmware's serializer. The fixed `selftest-wire.hex` contains a synthetic signature and must never be broadcast. Regenerate it with:

```powershell
python -m pip install -r tests/host/reference-requirements.txt
python tests/host/kaspa_reference.py --print-selftest
python tests/host/kaspa_reference.py --probe build/chain-native/Release/chain_probe.exe
```

Protocol decisions were checked against these files at the same revision:

- `protocol/p2p/src/convert/tx.rs`: conversion between v0 sigop counts and `compute_commit`, native subnetwork length, storage mass.
- `consensus/core/src/sign.rs`: the 66-byte P2PK signature script (`OP_DATA_65 || Schnorr[64] || sighash[1]`).
- `consensus/core/src/hashing/tx.rs`: v0 transaction ID encoding, including exactly one payload length.
- `consensus/core/src/hashing/sighash.rs`: all six v0 sighash modes.
- `consensus/core/src/mass/mod.rs`: transaction size and mass equations.

Four synthetic transactions cover nonzero sequence/outpoint/lock time, maximum input/output counts, storage mass and nonempty payload encoding. Seventy-two sighashes are calculated independently with Python's BLAKE2b. A separate transfer is signed with the firmware's real BIP32 and Schnorr implementation, decoded by Protobuf, and checked using independent test-only secp256k1 arithmetic. Altering its digest must invalidate the signature. Every insufficient serializer capacity is also checked for erased output and an intact guard byte.

These checks validate the v0 codec and signature equations, not node acceptance or activation rules for future transaction versions. Firmware signing currently rejects nonempty payloads because the approval screen does not review their semantics. The low-level hash/serializer tests still cover payloads. The returned bytes are a P2P `TransactionMessage`; gRPC `RpcTransaction` has a different schema.
