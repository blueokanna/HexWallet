cmake_minimum_required(VERSION 3.20)
project(hexwallet_chain_probe LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
get_filename_component(WALLET_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
if(NOT EXISTS "${WALLET_ROOT}/build/chain-mbedtls/CMakeLists.txt")
  message(FATAL_ERROR "Clone Mbed TLS mbedtls-3.6.5 with submodules into build/chain-mbedtls first")
endif()
add_subdirectory("${WALLET_ROOT}/build/chain-mbedtls" mbedtls EXCLUDE_FROM_ALL)
set(WALLET_SOURCES
  CryptoPrimitives.cpp WalletSecurity.cpp WalletEngine.cpp WalletAddresses.cpp
  WalletAltAddresses.cpp WalletNetworks.cpp WalletCatalog.cpp WalletMiningCatalog.cpp
  WalletTokens.cpp Blake2b.cpp Blake256.cpp CryptoExtended.cpp Ed25519.cpp BlsG1.cpp base58.cpp
  local_bech32.cpp local_segwit.cpp keccak256.cpp local_ripemd160.cpp
  ChainCommon.cpp ChainTransaction.cpp VeChainTransaction.cpp IconTransaction.cpp
  PolkadotTransaction.cpp SuiTransaction.cpp FilecoinTransaction.cpp TonTransaction.cpp TonCell.cpp
  DecredTransaction.cpp CkbTransaction.cpp ZcashTransaction.cpp CardanoDerivation.cpp CardanoTransaction.cpp HiveTransaction.cpp HederaTransaction.cpp SiaTransaction.cpp NemTransaction.cpp IcpTransaction.cpp ErgoTransaction.cpp Clvm.cpp ChiaTransaction.cpp BlsG2.cpp EvmTransaction.cpp TokenCalldata.cpp
  CosmosTransaction.cpp StellarTransaction.cpp AlgorandTransaction.cpp
  NearTransaction.cpp TezosTransaction.cpp QrlXmss.cpp WalletCustody.cpp SecureElementPort.cpp RandomSource.cpp EinkPanel.cpp QrCode.cpp
  CryptoNoteAddress.cpp CryptoNoteRingCt.cpp CryptoNoteAmounts.cpp CryptoNoteSpend.cpp
  CryptoNoteTransaction.cpp CryptoNoteReview.cpp CryptoNoteBulletproofPlus.cpp)
list(TRANSFORM WALLET_SOURCES PREPEND "${WALLET_ROOT}/")
add_executable(chain_probe ${WALLET_SOURCES} chain_probe.cpp platform.cpp)
target_include_directories(chain_probe PRIVATE . "${WALLET_ROOT}" "${WALLET_ROOT}/tests/host" "${WALLET_ROOT}/tests/host/mock")
target_compile_definitions(chain_probe PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS
  HEXWALLET_HOST_TEST=1 HEXWALLET_REAL_MBEDTLS=1 HEXWALLET_LEGACY_SUBSTRATE_TEST_ONLY=1
  HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(chain_probe PRIVATE /utf-8 /W3)
endif()
target_link_libraries(chain_probe PRIVATE mbedcrypto bcrypt)

# Compile the real policy WITHOUT the host-only historical Substrate admission.
# This target also exercises the production secure-custody requirement.
add_executable(production_policy ${WALLET_SOURCES}
  "${WALLET_ROOT}/WalletSession.cpp" production_policy.cpp platform.cpp)
target_include_directories(production_policy PRIVATE . "${WALLET_ROOT}"
  "${WALLET_ROOT}/tests/host" "${WALLET_ROOT}/tests/host/mock")
target_compile_definitions(production_policy PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS
  HEXWALLET_REAL_MBEDTLS=1 HEXWALLET_REQUIRE_SECURE_CUSTODY=1
  HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(production_policy PRIVATE /utf-8 /W3)
endif()
target_link_libraries(production_policy PRIVATE mbedcrypto bcrypt)

