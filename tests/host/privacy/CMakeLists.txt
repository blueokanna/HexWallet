cmake_minimum_required(VERSION 3.20)
project(hexwallet_privacy_oracle LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(NOT RYO_SOURCE OR NOT ZANO_SOURCE)
  message(FATAL_ERROR "Supply pinned RYO_SOURCE and ZANO_SOURCE directories; see prepare_oracle.py")
endif()
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/prepare_oracle.py"
  "${RYO_SOURCE}" "${ZANO_SOURCE}" "${CMAKE_CURRENT_BINARY_DIR}"
  COMMAND_ERROR_IS_FATAL ANY)
add_library(privacy_oracle SHARED oracle.cpp
  "${ZANO_SOURCE}/src/crypto/crypto-ops.c" "${ZANO_SOURCE}/src/crypto/crypto-ops-data.c"
  "${ZANO_SOURCE}/src/crypto/hash.c" "${ZANO_SOURCE}/src/crypto/keccak.c")
target_include_directories(privacy_oracle PRIVATE "${CMAKE_CURRENT_BINARY_DIR}"
  "${ZANO_SOURCE}/src/crypto" "${ZANO_SOURCE}/src/currency_core"
  "${ZANO_SOURCE}/src" "${ZANO_SOURCE}/contrib/epee/include")
if(MSVC)
  target_compile_options(privacy_oracle PRIVATE /utf-8 /W3)
endif()
