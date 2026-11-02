cmake_minimum_required(VERSION 3.20)
project(hexwallet_auth_transport LANGUAGES C CXX)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory("${ROOT}/build/chain-mbedtls" mbedtls EXCLUDE_FROM_ALL)
add_executable(auth_test auth_test.cpp service_test.cpp "${ROOT}/WalletTotp.cpp"
  "${ROOT}/Totp.cpp" "${ROOT}/TotpAccounts.cpp" "${ROOT}/CtapHid.cpp"
  "${ROOT}/EinkPanel.cpp" "${ROOT}/CryptoPrimitives.cpp"
  "${ROOT}/keccak256.cpp" "${ROOT}/local_ripemd160.cpp")
target_include_directories(auth_test PRIVATE . "${ROOT}" "${ROOT}/tests/host")
target_compile_definitions(auth_test PRIVATE HEXWALLET_ENABLE_LVGL=0 HEXWALLET_BOARD=0)
target_compile_features(auth_test PRIVATE cxx_std_17)
target_link_libraries(auth_test PRIVATE mbedcrypto)
if(MSVC)
  target_compile_options(auth_test PRIVATE /utf-8 /W4)
endif()
