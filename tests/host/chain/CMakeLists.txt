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
  CryptoPrimitives.cpp WalletSecurity.cpp WalletKeyBackup.cpp UnicodeNormalizer.cpp src/unicode/utf8proc.c WalletEngine.cpp WalletAddresses.cpp
  WalletAltAddresses.cpp WalletNetworks.cpp WalletCatalog.cpp WalletMiningCatalog.cpp
  WalletTokens.cpp Blake2b.cpp Blake256.cpp CryptoExtended.cpp Ed25519.cpp BlsG1.cpp Bls12381.cpp base58.cpp
  local_bech32.cpp local_segwit.cpp keccak256.cpp local_ripemd160.cpp
  Groestl512.cpp ThetaTransaction.cpp BitcoinTransaction.cpp AeternityTransaction.cpp AlephiumTransaction.cpp
  Blake3.cpp WalletAdmission.cpp QuaiTransaction.cpp QuantusAccount.cpp QuantusTransaction.cpp
  ChainCommon.cpp ChainTransaction.cpp VeChainTransaction.cpp IconTransaction.cpp
  PolkadotTransaction.cpp SuiTransaction.cpp FilecoinTransaction.cpp TonTransaction.cpp TonCell.cpp
  DecredTransaction.cpp CkbTransaction.cpp ZcashTransaction.cpp CardanoDerivation.cpp CardanoTransaction.cpp HiveTransaction.cpp HederaTransaction.cpp SiaTransaction.cpp NemTransaction.cpp IcpTransaction.cpp ErgoTransaction.cpp Clvm.cpp ChiaTransaction.cpp BlsG2.cpp EvmTransaction.cpp TokenCalldata.cpp
  CosmosTransaction.cpp StellarTransaction.cpp AlgorandTransaction.cpp DashTransaction.cpp
  NearTransaction.cpp TezosTransaction.cpp QrlXmss.cpp QrlOtsJournal.cpp QrlOtsStore.cpp
  QrlTransaction.cpp QrlV2Transaction.cpp MlDsa87.cpp StarknetCrypto.cpp AptosTransaction.cpp StarknetTransaction.cpp WalletCustomTokens.cpp WalletCustody.cpp WalletSession.cpp SecureElementPort.cpp Se051Apdu.cpp Se051Curves.cpp RandomSource.cpp EinkPanel.cpp QrCode.cpp
  CryptoNoteAddress.cpp CryptoNoteRingCt.cpp CryptoNoteAmounts.cpp CryptoNoteSpend.cpp
  CryptoNoteTransaction.cpp CryptoNoteReview.cpp CryptoNoteBulletproofPlus.cpp CryptoNoteSigning.cpp
  RyoMlsag.cpp ZanoClsag.cpp ZanoOutput.cpp RyoBulletproof.cpp RyoTransaction.cpp CryptoNoteOutputScan.cpp XrpTransaction.cpp KaspaTransaction.cpp)
list(TRANSFORM WALLET_SOURCES PREPEND "${WALLET_ROOT}/")
add_executable(chain_probe ${WALLET_SOURCES} chain_probe.cpp platform.cpp security_regression.cpp privacy_probe.cpp signing_audit.cpp key_backup_probe.cpp)
target_sources(chain_probe PRIVATE ../link_pipe.cpp)
target_sources(chain_probe PRIVATE "${WALLET_ROOT}/WalletBackupJob.cpp")
set_property(SOURCE "${WALLET_ROOT}/WalletKeyBackup.cpp" APPEND PROPERTY COMPILE_DEFINITIONS
  "$<$<STREQUAL:$<TARGET_PROPERTY:NAME>,chain_probe>:HEXWALLET_TEST_BACKUP_HEAP=1>")
set_source_files_properties(../link_pipe.cpp PROPERTIES COMPILE_DEFINITIONS HEXWALLET_LINK_PIPE_EMBEDDED=1)
set_property(SOURCE phone_review.cpp APPEND PROPERTY OBJECT_DEPENDS "${WALLET_ROOT}/WalletLinkService.cpp;${WALLET_ROOT}/WalletLink.h")
target_sources(chain_probe PRIVATE phone_review.cpp "${WALLET_ROOT}/SolanaTransaction.cpp"
  "${WALLET_ROOT}/RyoPhonePayment.cpp"
  "${WALLET_ROOT}/WalletSigning.cpp" "${WALLET_ROOT}/WalletWorker.cpp" "${WALLET_ROOT}/WalletWorkerExecution.cpp"
  "${WALLET_ROOT}/TrustAnchor.cpp" "${WALLET_ROOT}/TronTransaction.cpp" "${WALLET_ROOT}/WalletTransportPolicy.cpp"
  "${WALLET_ROOT}/WalletNfcApdu.cpp" "${WALLET_ROOT}/WalletLink.cpp" "${WALLET_ROOT}/WalletLinkCrypto.cpp"
  "${WALLET_ROOT}/XelisAccount.cpp" "${WALLET_ROOT}/src/xelis/Port.c"
  "${WALLET_ROOT}/src/xelis/ref10/ed25519_ref10.c"
  "${WALLET_ROOT}/BeamOutput.cpp" "${WALLET_ROOT}/BeamPayment.cpp" "${WALLET_ROOT}/BeamAddress.cpp"
  "${WALLET_ROOT}/src/beam/core/ecc.cpp" "${WALLET_ROOT}/src/beam/core/ecc_bulletproof.cpp"
  "${WALLET_ROOT}/src/beam/core/uintBig.cpp" "${WALLET_ROOT}/src/beam/core/numeric_utils.cpp")
target_include_directories(chain_probe PRIVATE . "${WALLET_ROOT}" "${WALLET_ROOT}/tests/host" "${WALLET_ROOT}/tests/host/mock")
target_compile_definitions(chain_probe PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS
  HEXWALLET_HOST_TEST=1 HEXWALLET_REAL_MBEDTLS=1 HEXWALLET_LEGACY_SUBSTRATE_TEST_ONLY=1
  HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(chain_probe PRIVATE /utf-8 /W3)
endif()
target_link_libraries(chain_probe PRIVATE mbedcrypto bcrypt)

option(TEST_RYO_PHONE_PAYMENTS "Admit Ryo payments in the host probe's catalog for integration testing" OFF)
if(TEST_RYO_PHONE_PAYMENTS)
  target_compile_definitions(chain_probe PRIVATE HEXWALLET_TEST_RYO_PHONE_PAYMENTS=1)
endif()
option(TEST_ZANO_PHONE_PAYMENTS "Admit ordinary native Zano payments in the host integration probe" OFF)
if(TEST_ZANO_PHONE_PAYMENTS)
  target_compile_definitions(chain_probe PRIVATE HEXWALLET_TEST_ZANO_PHONE_PAYMENTS=1)
  target_sources(chain_probe PRIVATE "${WALLET_ROOT}/ZanoPhonePayment.cpp")
endif()

# Exercise the actual CLI init, provisioning, challenge and lock paths. The
# linker discards unrelated CLI commands and their device-only dependencies.
add_executable(cli_auth_storage cli_auth_storage.cpp platform.cpp
  "${WALLET_ROOT}/WalletTransportPolicy.cpp"
  "${WALLET_ROOT}/CryptoPrimitives.cpp" "${WALLET_ROOT}/local_ripemd160.cpp" "${WALLET_ROOT}/keccak256.cpp"
  "${WALLET_ROOT}/RandomSource.cpp")
target_include_directories(cli_auth_storage PRIVATE . "${WALLET_ROOT}" "${WALLET_ROOT}/tests/host"
  "${WALLET_ROOT}/tests/host/auth")
target_compile_definitions(cli_auth_storage PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS HEXWALLET_HOST_TEST=1
  HEXWALLET_REAL_MBEDTLS=1 HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(cli_auth_storage PRIVATE /Gy /Gw /utf-8)
  target_link_options(cli_auth_storage PRIVATE /OPT:REF /INCREMENTAL:NO)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(cli_auth_storage PRIVATE /Zc:inline)
  endif()
endif()
target_link_libraries(cli_auth_storage PRIVATE mbedcrypto bcrypt)

add_executable(p4_token_storage p4_storage/storage_test.cpp
  "${WALLET_ROOT}/WalletCustomTokens.cpp" "${WALLET_ROOT}/WalletCustomTokensNvs.cpp"
  "${WALLET_ROOT}/CryptoPrimitives.cpp" "${WALLET_ROOT}/local_ripemd160.cpp" "${WALLET_ROOT}/keccak256.cpp")
target_include_directories(p4_token_storage PRIVATE p4_storage . "${WALLET_ROOT}")
target_compile_definitions(p4_token_storage PRIVATE ARDUINO=10819 HEXWALLET_BOARD=7 HEXWALLET_ENABLE_LVGL=0
  HEXWALLET_REAL_MBEDTLS=1 MBEDTLS_ALLOW_PRIVATE_ACCESS _CRT_SECURE_NO_WARNINGS)
target_link_libraries(p4_token_storage PRIVATE mbedcrypto)

# Compile the real policy WITHOUT the host-only historical Substrate admission.
# This target also exercises the production secure-custody requirement.
add_executable(production_policy ${WALLET_SOURCES} "${WALLET_ROOT}/CoinIcons.cpp"
  production_policy.cpp platform.cpp)
target_include_directories(production_policy PRIVATE entropy . "${WALLET_ROOT}"
  "${WALLET_ROOT}/tests/host" "${WALLET_ROOT}/tests/host/mock")
target_compile_definitions(production_policy PRIVATE MBEDTLS_ALLOW_PRIVATE_ACCESS
  HEXWALLET_REAL_MBEDTLS=1 HEXWALLET_REQUIRE_SECURE_CUSTODY=1 HEXWALLET_TEST_BOOT_ENTROPY=1
  HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0 _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  target_compile_options(production_policy PRIVATE /utf-8 /W3)
endif()
target_link_libraries(production_policy PRIVATE mbedcrypto bcrypt)

