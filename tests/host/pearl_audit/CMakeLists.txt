cmake_minimum_required(VERSION 3.20)
project(hexwallet_pearl_audit LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
get_filename_component(root "../../.." ABSOLUTE)
# Keep this target independent of the concurrently edited chain probe target.
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory("${root}/build/chain-mbedtls" mbedtls EXCLUDE_FROM_ALL)
set(wallet_sources
  CryptoPrimitives.cpp WalletSecurity.cpp WalletEngine.cpp WalletAddresses.cpp
  WalletAltAddresses.cpp WalletNetworks.cpp WalletCatalog.cpp WalletMiningCatalog.cpp
  WalletTokens.cpp Blake2b.cpp Blake256.cpp CryptoExtended.cpp Ed25519.cpp BlsG1.cpp
  Bls12381.cpp base58.cpp local_bech32.cpp local_segwit.cpp keccak256.cpp local_ripemd160.cpp
  Groestl512.cpp ThetaTransaction.cpp ChainCommon.cpp ChainTransaction.cpp
  VeChainTransaction.cpp IconTransaction.cpp PolkadotTransaction.cpp SuiTransaction.cpp
  FilecoinTransaction.cpp TonTransaction.cpp TonCell.cpp DecredTransaction.cpp
  CkbTransaction.cpp ZcashTransaction.cpp CardanoDerivation.cpp CardanoTransaction.cpp
  HiveTransaction.cpp HederaTransaction.cpp SiaTransaction.cpp NemTransaction.cpp
  IcpTransaction.cpp ErgoTransaction.cpp Clvm.cpp ChiaTransaction.cpp BlsG2.cpp
  EvmTransaction.cpp TokenCalldata.cpp CosmosTransaction.cpp StellarTransaction.cpp
  AlgorandTransaction.cpp DashTransaction.cpp NearTransaction.cpp TezosTransaction.cpp
  QrlXmss.cpp QrlOtsJournal.cpp QrlOtsStore.cpp QrlTransaction.cpp QrlV2Transaction.cpp
  MlDsa87.cpp StarknetCrypto.cpp AptosTransaction.cpp StarknetTransaction.cpp
  WalletCustomTokens.cpp WalletCustody.cpp WalletSession.cpp SecureElementPort.cpp
  Se051Apdu.cpp Se051Curves.cpp RandomSource.cpp EinkPanel.cpp QrCode.cpp
  CryptoNoteAddress.cpp CryptoNoteRingCt.cpp CryptoNoteAmounts.cpp CryptoNoteSpend.cpp
  CryptoNoteTransaction.cpp CryptoNoteReview.cpp CryptoNoteBulletproofPlus.cpp)
list(TRANSFORM wallet_sources PREPEND "${root}/")
add_executable(pearl_audit ${wallet_sources} "${root}/BitcoinTransaction.cpp"
  ../chain/platform.cpp pearl_audit.cpp)
target_include_directories(pearl_audit PRIVATE "${root}" "${root}/tests/host"
  "${root}/tests/host/mock" "${root}/tests/host/chain")
target_compile_definitions(pearl_audit PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS
  HEXWALLET_HOST_TEST=1 HEXWALLET_REAL_MBEDTLS=1
  HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
target_compile_options(pearl_audit PRIVATE /utf-8 /W3)
target_link_libraries(pearl_audit PRIVATE mbedcrypto bcrypt)
