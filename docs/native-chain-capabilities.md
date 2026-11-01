# Native network capabilities

Generated from the compiled, resolved catalog by `tools/native_coverage.ps1`. No token contract registry is read.

Profiles: 205. Distinct execution/address domains: 176. Domains with a signing-code claim: 173.

EVM domains use chain ID; Bitcoin-family address variants merge when coin type and both Base58 versions agree (legacy rows may omit the SegWit HRP). Other adapters keep their explicit network IDs. These are conservative catalog groups, not independently attested chain identities. A domain is not necessarily an independent L1 or a distinct native coin: for example, several rollups use ETH.

**SIGN means a registered code path, not complete protocol support, node acceptance or hardware certification.** Production custody, display and boot policies still apply. ADDRESS has no admitted signing path.

| Domain | Profiles | Native asset | Code capability | Implemented scope |
| --- | --- | --- | --- | --- |
| evm:1 | eth | ETH | SIGN | EIP-155/EIP-2930/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:10 | opt | ETH | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:100 | xdai | XDAI | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:10001 | ethw | ETHW | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1030 | cfx | CFX | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1088 | metis | METIS | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1101 | zkevm | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1116 | core | CORE | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:122 | fuse | FUSE | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1284 | glmr | GLMR | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:1285 | movr | MOVR | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:130 | unichain | ETH | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:1313114 | etho | ETHO | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1313161554 | aurora | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:1329 | seievm | SEI | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:137 | matic | POL | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:14 | flare | FLR | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:143 | monad | MON | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:1666600000 | harmony | ONE | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:196 | xlayer | OKB | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:2000 | dogechain | DOGE | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:200901 | bitlayer | BTC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:204 | opbnb | BNB | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:210 | btn | BTN | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:2222 | kava | KAVA | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:23294 | rose | ROSE | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:25 | cro | CRO | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:250 | ftm | FTM | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:30 | rsk | RBTC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:3003 | cau | CAU | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:324 | zksync | ETH | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:329 | vbc | VBC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:33333 | avs | AVS | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:40 | telos | TLOS | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:4200 | merlin | BTC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:42161 | arb1 | ETH | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:42220 | celo | CELO | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:43114 | avaxc | AVAX | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:4663 | robinhood | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:50 | xdc | XDC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:5000 | mantle | MNT | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:5042 | arc | USDC | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:534352 | scroll | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:56 | bsc | BNB | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:59144 | linea | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:592 | astar | ASTR | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:61 | etc | ETC | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:61803 | egaz | EGAZ | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:66 | okt | OKT | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:7332 | zen | ZEN | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:747 | flow-evm | FLOW | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:7700 | canto | CANTO | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:800001 | octa | OCTA | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:80094 | bera | BERA | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:81457 | blast | ETH | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:820 | clo | CLO | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:8217 | kaia | KAIA | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:8453 | base | ETH | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:9001 | evmos | EVMOS | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| evm:9745 | plasma | XPL | SIGN | EIP-155/EIP-1559 signing: native transfers, registered token calls, arbitrary calldata and contract creation; undecoded code is reviewed as raw bytes with its keccak-256 |
| evm:9898 | lrs | LRS | SIGN | EIP-155 legacy signing: native transfers, registered token calls, arbitrary calldata and contract creation; type-2 envelopes are rejected by chain policy |
| native:ada | ada | ADA | SIGN | CIP-0003 Ledger/BitBox02 root, CIP-1852 BIP32-Ed25519; mainnet ADA-only transfer; UTxO ownership/value must be checked by the node; no tokens, scripts, staking or governance |
| native:ae | ae | AE | ADDRESS | Ed25519 ak_ address at m/44'/457'/0'/0'/i'; receive/address verification only - native spend signing is not enabled |
| native:algo | algo | ALGO | SIGN | Mainnet canonical MessagePack payments, ASA transfers and opt-in; no groups, rekey or account closing |
| native:apt | apt | APT | SIGN | Ed25519 account address (sha3-256 of key \|\| 0x00); 0x1::aptos_account::transfer only, signed over sha3-256("APTOS::RawTransaction" \|\| BCS RawTransaction); no EntryFunction calls, sponsored transactions, multisig or tokens |
| native:atom | atom | ATOM | SIGN | Cosmos SDK native MsgSend; direct sign mode, strict protobuf review |
| native:bch | bch | BCH | SIGN | P2PKH PSBT signing, BIP143 + SIGHASH_FORKID |
| native:ckb | ckb | CKB | SIGN | native CKB single-input transfer to SECP256K1/blake160 locks; no type scripts or DAO operations |
| native:dcr | dcr | DCR | SIGN | transparent P2PKH single-input transfer; no stake tickets, treasury or mix transactions |
| native:dot | dot | DOT | SIGN | Ed25519 SS58 account; balances.transfer / transferKeepAlive with mortal era and tip. Signed extensions are pinned to runtime 2005002/26 with genesis pinned, and CheckMetadataHash is carried as an explicit disabled mode; a runtime upgrade needs a firmware update |
| native:erg | erg | ERG | SIGN | P2PK (ProveDlog) transfers: device rebuilds the tx-id preimage, signs the Schnorr proof and returns the signed transaction. Review displays the single external output plus every token it carries and refuses a second external output or an undisplayable token list; only inputs owned by this key are signed |
| native:fil | fil | FIL | SIGN | f1 sender, f0/f1/f3 recipient; canonical CBOR Send, CID signing; no actor calls or BLS signing |
| native:hbar | hbar | HBAR | SIGN | Ed25519 key alias receive; numeric-account HBAR CryptoTransfer, one debit/credit; no HTS, allowances or contracts; node must verify payer ownership and network |
| native:hive | hive | HIVE | SIGN | Single transfer; derived STM value is an active PUBLIC KEY, not a receive address. Named account/authority must be checked by node; no encrypted memo |
| native:icp | icp | ICP | SIGN | Ed25519 default ledger account; pinned ICP ledger Candid transfer and signed CBOR request; no arbitrary canisters or staking; not Ledger seed/path compatible |
| native:icx | icx | ICX | SIGN | native ICX transfer with canonical icx_sendTransaction serialization; no SCORE calls |
| native:kas | kas | KAS | SIGN | Kaspa bech32 address; BIP340 Schnorr v0 transaction review and signing |
| native:ksm | ksm | KSM | SIGN | Ed25519 SS58 account; balances.transfer / transferKeepAlive with mortal era and tip. Signed extensions are pinned to runtime 2005001/26 with genesis pinned, and CheckMetadataHash is carried as an explicit disabled mode; a runtime upgrade needs a firmware update |
| native:near | near | NEAR | SIGN | Implicit receive accounts; Borsh V0 native Transfer; named account key membership and block network cannot be checked offline |
| native:osmo | osmo | OSMO | SIGN | Cosmos SDK native MsgSend; direct sign mode, strict protobuf review |
| native:qrl | qrl | QRL | SIGN | QRL v1 XMSS/SHAKE-256 tree height 10: native transfers only, the one-time leaf is reserved in durable storage before the WOTS+ signature exists and the device verifies its own signature before releasing it. Use the qrl2 entry for v2 accounts |
| native:qrl2 | qrl2 | QRL | SIGN | QRL v2 (Zond) ML-DSA-87 accounts and dynamic-fee transactions: BIP44 m/44'/238'/account'/change/index, SHAKE-256 checksummed Q address, ML-DSA-87 over keccak-256 of the reviewed envelope. Mainnet chain id 1 only; unknown descriptors or non-empty extra_params are refused |
| native:ryo | ryo | RYO | ADDRESS | CryptoNote long address (prefix 0x2ce192); receive/address verification only - review and signing are not enabled |
| native:sc | sc | SC | SIGN | v2 PolicyPublicKey single-input transfer; node must validate parent/proof/maturity; no contracts; wallet-specific SLIP10 seed derivation |
| native:sol | sol | SOL | SIGN | SOL, SPL Token and Token-2022 TransferChecked: legacy/v0, single payer; exact mint/token accounts reviewed; Token-2022 extension warning; no ALTs or ATA creation |
| native:stark | stark | STRK | SIGN | Stark curve keys (grindKey of the BIP32 child) and Cairo v3 transactions: deploy_account and one ERC-20 transfer through the account's execute entry point. The device rebuilds the SNIP-5 account address from the class hash, salt and single-key constructor it displays, and pins the chain id to SN_MAIN. Multi-call accounts, declare, paymaster, multisig and non-mainnet networks are refused |
| native:sui | sui | SUI | SIGN | Ed25519 BCS split-gas native SUI transfer; no Move calls, sponsored transactions or tokens |
| native:tia | tia | TIA | SIGN | Cosmos SDK native MsgSend; direct sign mode, strict protobuf review |
| native:ton | ton | TON | SIGN | wallet v4R2 native transfer; empty body only; no comments, jettons or multi-message orders |
| native:trx | trx | TRX | SIGN | native TRX and registered TRC-20 transfer signing; owner permission only, strict protobuf review |
| native:vet | vet | VET | SIGN | native VET transfer; one clause, empty data, mainnet chain tag; no VIP-191 delegation or contract calls |
| native:xch | xch | XCH | SIGN | Standard-coin spends: the device rebuilds the delegated puzzle and the AGG_SIG_ME message from the conditions it displays, then signs in G2 with the in-tree BLS12-381 backend (no variable-time MPI on the secret scalar). CAT/NFT, plot-NFT and offer spends are not admitted |
| native:xec | xec | XEC | SIGN | P2PKH PSBT signing, BIP143 + SIGHASH_FORKID |
| native:xem | xem | XEM | SIGN | Keccak-Ed25519 native transfer v1, printable plaintext memo; no mosaics or multisig |
| native:xlm | xlm | XLM | SIGN | SEP-0005; public-network XDR Payment/CreateAccount; G addresses and explicit memo review |
| native:xmr | xmr | XMR | SIGN | RingCT type-6 review and CLSAG signing; fully offline, host supplies decoys |
| native:xrp | xrp | XRP | SIGN | Classic r-addresses; native Payment only; no issued currencies, paths, memos or partial payments |
| native:xtz | xtz | XTZ | SIGN | Modern Ed25519 reveal and native implicit-account transfers; no KT1, FA tokens or NFT calls; branch origin unverified offline |
| native:zano | zano | ZANO | ADDRESS | CryptoNote Zx address (prefix 0xc5); receive/address verification only - review and signing are not enabled |
| native:zec | zec | ZEC | SIGN | Zcash v4 transparent ZIP-243 review and signing (NU6.2) |
| utxo:0:0:5 | btc, btc44, btc49 | BTC | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:10226:60:16 | fork_utxo_raptoreum | RTM | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:13:50:9 | fork_maza | MAZA | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1313:38:122 | fork_utxo_gaelium | GAEL | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:136:82:7 | firo | FIRO | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:140:85:122 | fork_lbry | LBC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1420:30:22 | fork_utxo_dogecoinev | DEV | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:156:38:23 | btg, btg49, btg84 | BTG | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:160:3:125 | fork_bitcore | BTX | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:166:70:10 | fork_vivo | VIVO | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1668:38:122 | fork_utxo_neoxa | NEOX | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1707:65:28 | fork_utxo_trumpow | TRMP | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:175:60:122 | rvn | RVN | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:176:38:10 | fork_gobyte | GBX | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1777:25:16 | fork_utxo_biblepay | BBP | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:179:60:22 | fork_newyorkc | NYC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:18:30:5 | fork_digitalcoin | DGC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1900:53:117 | fork_utxo_neurai | XNA | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:19169:25:105 | fork_ritocoin | RITO | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1919:70:50 | fork_utxo_vipstarcoin | VIPS | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1948:30:5 | fork_utxo_doriancoin, fork_utxo_doriancoin84 | DSV | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1995:51:30 | fork_utxo_mydogecoin | MYDOGE | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:1996:1:0 | fork_utxo_mytherra, fork_utxo_mytherra84 | MYT | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:2:48:50 | ltc, ltc49, ltc84 | LTC | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:20:30:63 | dgb, dgb49, dgb84 | DGB | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:2013:16:5 | fork_utxo_junkcoin, fork_utxo_junkcoin84 | JKC | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:202:27:5 | fork_utxo_ufocoin | UFO | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:20760:73:5 | fork_utxo_wojakcoin, fork_utxo_wojakcoin84 | WJK | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:216:35:8 | fork_utxo_florincoin | FLO | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:22:50:5 | fork_monacoin | MONA | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:228:53:5 | fork_utxo_actinium, fork_utxo_actinium84 | ACM | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:2301:58:50 | qtum | QTUM | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:231:100:40 | fork_utxo_helpthehomeless | HTH | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:236:0:5 | bsv | BSV | SIGN | P2PKH PSBT signing, BIP143 + SIGHASH_FORKID |
| utxo:25252:25:85 | fork_utxo_bellcoin, fork_utxo_bellcoin84 | BELL | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:2686:23:23 | fork_utxo_aipowergrid | AIPG | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:28:71:5 | vtc, vtc49, vtc84 | VTC | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:3:30:22 | doge | DOGE | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:3141:25:22 | fork_utxo_bit | B1T | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:3381:30:10 | fork_utxo_dynamic | DYN | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:363:28:30 | fork_cpuchain | CPU | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:37992:95:36 | fork_utxo_fxtc, fork_utxo_fxtc84 | FXTC | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:399:80:10 | fork_utxo_zeroonecoin | ZOC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:408:63:125 | fork_sugarchain, fork_sugarchain49, fork_sugarchain84 | SUGAR | SIGN | BIP49 nested SegWit PSBT signing (BIP143); BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:41:33:5 | fork_einsteinium | EMC2 | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:4242:140:19 | axe | AXE | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:4474:63:22 | fork_utxo_shibacoin | SHIC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:481:3:22 | fork_utxo_mooncoin, fork_utxo_mooncoin84 | MOON | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:5:76:16 | dash | DASH | SIGN | P2PKH plain payments (type 0) through the Dash adapter; special transaction types refused; InstantSend lock state is node-side |
| utxo:522:125:117 | fork_utxo_stakecubecoin | SCC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:608:65:16 | fork_utxo_cointaft | TAFT | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:658:73:10 | fork_utxo_whive, fork_utxo_whive84 | WHIVE | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:664:77:139 | fork_utxo_globalboost-y, fork_utxo_globalboost-y84 | BSTY | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:681:53:5 | fork_utxo_newenglandcoin | NENG | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:682:28:5 | fork_utxo_cheetahcoin | CHTA | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:69420:38:50 | fork_utxo_garlicoin, fork_utxo_garlicoin84 | GRLC | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:6969:61:13 | fork_utxo_theholyrogercoin, fork_utxo_theholyrogercoin84 | ROGER | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:698:70:5 | fork_utxo_veil | VEIL | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:7:52:13 | nmc | NMC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:711:28:4 | fork_utxo_chaincoin, fork_utxo_chaincoin84 | CHC | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:735:53:21 | fork_utxo_neobytes | NBY | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:746:55:5 | fork_utxo_palladium, fork_utxo_palladium84 | PLM | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:770:28:13 | fork_utxo_cosanta | COSA | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:78:48:5 | fork_egulden | EFL | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:8:14:5 | fork_feathercoin | FTC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:802:28:77 | fork_utxo_cyberyen, fork_utxo_cyberyen84 | CY | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:816:35:95 | fork_utxo_fsociety | FSC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:82:58:9 | fork_utxo_quarkcoin | QRK | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:85:23:5 | fork_auroracoin | AUR | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:881:24:5 | fork_utxo_aegisum, fork_utxo_aegisum84 | AEGS | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:8997:25:102 | fork_utxo_babacoin | BBC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:8998:43:102 | fork_utxo_jagoancoin | JGC | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:90:50:9 | fork_myriadcoin | XMY | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:9007:63:122 | fork_utxo_satoxcoin | SATOX | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:9555:60:122 | fork_utxo_rincoin, fork_utxo_rincoin84 | RIN | SIGN | BIP84 native SegWit PSBT signing (BIP143); P2PKH legacy sighash and BIP143 witness PSBT signing |
| utxo:9969:63:15 | fork_utxo_osmium | OSMI | SIGN | P2PKH legacy sighash and BIP143 witness PSBT signing |
