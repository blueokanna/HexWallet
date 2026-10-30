# EVM typed transactions and trusted review

Ethereum mainnet accepts EIP-2930 type-1 transactions with a fixed gas price.
Type-2 transactions retain the existing `network_supports_eip1559` network
policy and EIP-1559 fee caps. Both types use the same canonical RLP, access-list,
review and signing implementation; the serialized fields and envelope byte
remain specific to their EIP. Type 1 has its own explicit admission policy,
`network_supports_eip2930`, currently limited to `eth` with chain ID 1.
An EVM address profile alone does not enable either typed envelope.

The parser requires canonical RLP. Each entry contains exactly a 20-byte address
and a list of 32-byte storage keys. The firmware accepts at most eight address
entries, eight storage keys in total and 384 bytes of encoded list payload,
within the existing 768-byte transaction limit. Oversized lists are rejected.
Duplicates and ordering are preserved byte for byte. Every occurrence adds
2400 gas per address and 1900 gas per key to the existing admission lower bound.
These checks do not simulate execution or guarantee sufficient execution gas.

The trusted display shows every address and every storage key under
`ACCESS LIST (gas scheduling)`, separately from the payment destination and
contract identity. The access list is a gas-scheduling declaration, not a list
of recipients or a grant of spending authority. Formatting failure rejects the
review; the display wraps complete values without abbreviating them. Signing
reparses the original transaction and compares the list, counts and review
fields before producing any signature. Failure clears the bounded output.

The shared `evm_review_details` formatter is used by the serial and phone-link
review paths. It includes the envelope type, chain ID, full sender, nonce, gas
limit and per-gas price/caps. Registered contract calls include the full
contract address, decoded method and applicable source/refund/value/destination
fields. Formatting is bounded and rejects an incomplete result. Signing checks
every decoded call field and every fixed-size review string against a fresh
parse; an altered or unterminated review string cannot bypass that comparison.

Unknown contracts, arbitrary calldata, contract creation, unsupported typed
envelopes and already signed transaction envelopes are rejected. Showing a
calldata hash does not establish what a contract will execute. Supporting these
operations needs an explicit review model and contract/state verification;
the present implementation does not claim them. Gas checks are lower bounds,
not execution simulation, and network-specific fork rules still apply.

The wire format and gas charges follow [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)
and [EIP-2930](https://eips.ethereum.org/EIPS/eip-2930).

## Independent checks

`tests/fixtures/evm-access-list.json` contains hashes and complete signed
transactions produced by ethers 6.15.0, using a public all-zero test seed.
The generator in `tools/generate_evm_access_vectors.cjs` checks the SHA-256 of
the official ethers distribution before loading it. Node and ethers are only
needed to regenerate fixtures. They are not firmware dependencies.

After building the native Mbed TLS chain probe, run:

```powershell
powershell -ExecutionPolicy Bypass -File tests/host/evm_access_list_check.ps1
```

For both admitted envelope types, checks cover native transfers and a registered
USDC transfer, empty lists, an address without slots, multiple slots, preserved
duplicates, limits, malformed structures, wrong chain, insufficient intrinsic
gas and every prefix truncation. Exact display text is checked independently,
including full contract identity. Buffer tests cover exact fit, one-byte-short
rejection, clearing and a guard byte. Review/hash/list/type/nonce/call-field
mutations and unterminated strings must fail signing. Type-1 requests on other
profiles must be refused by policy. These checks do not establish node
acceptance, physical-display behavior or secure-element safety.
