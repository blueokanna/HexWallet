cmake_minimum_required(VERSION 3.20)
project(hexwallet_qrl_oracle LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
get_filename_component(ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(ORACLE "${ROOT}/build/qrl-oracle/src")
set(UPSTREAM
  ${ORACLE}/xmss-alt/algsxmss.c ${ORACLE}/xmss-alt/xmss_common.c
  ${ORACLE}/xmss-alt/wots.c ${ORACLE}/xmss-alt/hash.c
  ${ORACLE}/xmss-alt/hash_address.c ${ORACLE}/xmss-alt/fips202.c
  ${ORACLE}/crypto/secure_memory.cpp)
set_source_files_properties(${UPSTREAM} PROPERTIES LANGUAGE CXX)
add_executable(qrl_oracle qrl_oracle.cpp ${UPSTREAM}
  ${ROOT}/QrlXmss.cpp ${ROOT}/CryptoPrimitives.cpp
  ${ROOT}/keccak256.cpp ${ROOT}/local_ripemd160.cpp)
target_include_directories(qrl_oracle PRIVATE ${ROOT} ${ORACLE}
  ${ROOT}/build/chain-mbedtls/include)
target_compile_definitions(qrl_oracle PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(qrl_oracle PRIVATE
  ${ROOT}/build/chain-native/mbedtls/library/Release/mbedcrypto.lib)
if(WIN32)
  # mbedtls' entropy_poll on Windows calls BCryptGenRandom.
  target_link_libraries(qrl_oracle PRIVATE bcrypt)
endif()
if(MSVC)
  target_compile_options(qrl_oracle PRIVATE /utf-8 /W3)
endif()
