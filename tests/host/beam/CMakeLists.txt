cmake_minimum_required(VERSION 3.20)
project(beam_reference LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(BEAM_REFERENCE "" CACHE PATH "Local checkout of the upstream Beam reference")
if(NOT MSVC)
  message(FATAL_ERROR "This reference target uses the native Windows entropy backend.")
endif()
function(check_commit directory expected)
  execute_process(COMMAND git -C "${directory}" rev-parse HEAD
    RESULT_VARIABLE result OUTPUT_VARIABLE revision OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT result EQUAL 0 OR NOT revision STREQUAL expected)
    message(FATAL_ERROR "Unexpected revision of ${directory}. Expected ${expected}.")
  endif()
endfunction()
set(secp "${BEAM_REFERENCE}/3rdparty/secp256k1")
check_commit("${BEAM_REFERENCE}" "90a8be3ba2bed3e3adac748867658e9381b3f462")
check_commit("${secp}" "3ac4050e7bf914c59677c22aa4b9dba95cc40944")
add_executable(beam_reference reference.cpp platform.cpp
  "${BEAM_REFERENCE}/wallet/core/base58.cpp"
  "${BEAM_REFERENCE}/core/ecc.cpp" "${BEAM_REFERENCE}/core/ecc_bulletproof.cpp"
  "${BEAM_REFERENCE}/core/uintBig.cpp" "${BEAM_REFERENCE}/core/numeric_utils.cpp"
  "${secp}/src/secp256k1.c" "${secp}/src/precomputed_ecmult.c" "${secp}/src/precomputed_ecmult_gen.c")
target_include_directories(beam_reference PRIVATE "${BEAM_REFERENCE}" "${BEAM_REFERENCE}/3rdparty")
target_compile_definitions(beam_reference PRIVATE WIN32 NOMINMAX ECMULT_GEN_PREC_BITS=4 ECMULT_WINDOW_SIZE=15)
target_link_libraries(beam_reference PRIVATE bcrypt)
