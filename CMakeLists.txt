# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
# PQCP Zephyr Trust Stack - CMake Build Configuration
#
# This module provides ML-KEM (FIPS-203) and ML-DSA (FIPS-204) implementations
# using the PQ Code Package's mlkem-native and mldsa-native libraries.

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_PROJECT_VERSION "1.0.0")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(PQCPZephyrTrustStack VERSION ${PQCP_PROJECT_VERSION} LANGUAGES C)
endif()

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/pqcp_zephyr/version.h" PQCP_VERSION_HEADER_TEXT)
string(
  REGEX MATCH
  "#define[ \t]+PQCP_VERSION_STRING[ \t]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\""
  PQCP_VERSION_HEADER_MATCH
  "${PQCP_VERSION_HEADER_TEXT}"
)

if(NOT CMAKE_MATCH_1)
  message(FATAL_ERROR
    "Unable to parse PQCP_VERSION_STRING from "
    "${CMAKE_CURRENT_SOURCE_DIR}/include/pqcp_zephyr/version.h"
  )
endif()

set(PQCP_HEADER_VERSION "${CMAKE_MATCH_1}")

if(NOT PQCP_PROJECT_VERSION STREQUAL PQCP_HEADER_VERSION)
  message(FATAL_ERROR
    "PQCP version mismatch: CMakeLists.txt declares ${PQCP_PROJECT_VERSION} "
    "but version.h declares ${PQCP_HEADER_VERSION}"
  )
endif()

# Module registration for west
if(CONFIG_PQCP)

# =============================================================================
# Module Paths
# =============================================================================
set(PQCP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(PQCP_INC ${PQCP_DIR}/include)
set(PQCP_SRC ${PQCP_DIR}/src)
set(PQCP_EXT ${PQCP_DIR}/ext)
set(PQCP_WORKSPACE_CRYPTO_DIR ${PQCP_DIR}/../modules/crypto)

# External library paths
if(EXISTS ${PQCP_EXT}/mlkem-native/mlkem)
    set(MLKEM_NATIVE_DIR ${PQCP_EXT}/mlkem-native)
elseif(EXISTS ${PQCP_WORKSPACE_CRYPTO_DIR}/mlkem-native/mlkem)
    set(MLKEM_NATIVE_DIR ${PQCP_WORKSPACE_CRYPTO_DIR}/mlkem-native)
else()
    set(MLKEM_NATIVE_DIR ${PQCP_EXT}/mlkem-native)
endif()

if(EXISTS ${PQCP_EXT}/mldsa-native/mldsa)
    set(MLDSA_NATIVE_DIR ${PQCP_EXT}/mldsa-native)
elseif(EXISTS ${PQCP_WORKSPACE_CRYPTO_DIR}/mldsa-native/mldsa)
    set(MLDSA_NATIVE_DIR ${PQCP_WORKSPACE_CRYPTO_DIR}/mldsa-native)
else()
    set(MLDSA_NATIVE_DIR ${PQCP_EXT}/mldsa-native)
endif()

# =============================================================================
# Include Paths
# =============================================================================
zephyr_include_directories(${PQCP_INC})

# =============================================================================
# Common Sources
# =============================================================================
zephyr_library_named(pqcp_common)

# RNG abstraction - select ONE backend
if(CONFIG_PQCP_RNG_DETERMINISTIC_TEST)
    # Deterministic RNG for testing (overrides custom)
    zephyr_library_sources(${PQCP_SRC}/rng_deterministic.c)
elseif(CONFIG_PQCP_RNG_ZEPHYR_ENTROPY)
    zephyr_library_sources(${PQCP_SRC}/rng_zephyr_entropy.c)
elseif(CONFIG_PQCP_RNG_PSA)
    zephyr_library_sources(${PQCP_SRC}/rng_psa.c)
elseif(CONFIG_PQCP_RNG_CUSTOM)
    zephyr_library_sources(${PQCP_SRC}/rng_custom.c)
endif()

# Common RNG interface
zephyr_library_sources(${PQCP_SRC}/rng_common.c)

if(CONFIG_PQCP_ASSURANCE_STATUS)
    zephyr_library_sources(${PQCP_SRC}/assurance_status.c)
endif()

if(CONFIG_PQCP_PROVIDER_CONTRACT)
    zephyr_library_sources(${PQCP_SRC}/provider_contract.c)
endif()

if(CONFIG_PQCP_BUILD_MANIFEST)
    zephyr_library_sources(${PQCP_SRC}/build_manifest.c)
endif()

if(CONFIG_PQCP_EVIDENCE_SESSION)
    zephyr_library_sources(${PQCP_SRC}/evidence_session.c)
endif()

if(CONFIG_PQCP_EVIDENCE_TRANSCRIPT)
    zephyr_library_sources(${PQCP_SRC}/evidence_transcript.c)
endif()

if(CONFIG_PQCP_FIRMWARE_POLICY)
    zephyr_library_sources(${PQCP_SRC}/firmware_policy.c)
endif()

if(CONFIG_PQCP_CAPABILITY_DESCRIPTOR)
    zephyr_library_sources(${PQCP_SRC}/capability_descriptor.c)
endif()

if(CONFIG_PQCP_FIRMWARE_SCORECARD)
    zephyr_library_sources(${PQCP_SRC}/firmware_scorecard.c)
endif()

if(CONFIG_PQCP_DEPLOYMENT_ADVISOR)
    zephyr_library_sources(${PQCP_SRC}/deployment_advisor.c)
endif()

if(CONFIG_PQCP_FIRMWARE_EVIDENCE)
    zephyr_library_sources(${PQCP_SRC}/firmware_evidence.c)
endif()

# =============================================================================
# ML-KEM Library
# =============================================================================
if(CONFIG_PQCP_MLKEM)
    zephyr_library_named(pqcp_mlkem)

    # Check for mlkem-native availability
    if(EXISTS ${MLKEM_NATIVE_DIR}/mlkem)
        set(PQCP_MLKEM_LEVEL_COUNT 0)
        if(CONFIG_PQCP_MLKEM_LEVEL_512)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLKEM_LEVEL_768)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLKEM_LEVEL_1024)
            math(EXPR PQCP_MLKEM_LEVEL_COUNT "${PQCP_MLKEM_LEVEL_COUNT} + 1")
        endif()

        if(CONFIG_PQCP_MLKEM_MULTI_LEVEL OR PQCP_MLKEM_LEVEL_COUNT GREATER 1)
            set(MLKEM_MULTILEVEL_DIR
                ${MLKEM_NATIVE_DIR}/examples/monolithic_build_multilevel)
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR})
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR}/mlkem_native)
            zephyr_include_directories(${MLKEM_MULTILEVEL_DIR}/mlkem_native/src)
            zephyr_compile_definitions(PQCP_MLKEM_MULTILEVEL_BUILD=1)
        else()
            zephyr_include_directories(${MLKEM_NATIVE_DIR})
            zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem)
            zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem/src)
            # Determine security level to build
            if(CONFIG_PQCP_MLKEM_LEVEL_512)
                set(MLKEM_K 2)
                set(MLK_PARAM_SET 512)
            elseif(CONFIG_PQCP_MLKEM_LEVEL_768)
                set(MLKEM_K 3)
                set(MLK_PARAM_SET 768)
            elseif(CONFIG_PQCP_MLKEM_LEVEL_1024)
                set(MLKEM_K 4)
                set(MLK_PARAM_SET 1024)
            else()
                # Default to ML-KEM-768
                set(MLKEM_K 3)
                set(MLK_PARAM_SET 768)
            endif()

            zephyr_compile_definitions(MLKEM_K=${MLKEM_K})
            zephyr_compile_definitions(MLK_CONFIG_PARAMETER_SET=${MLK_PARAM_SET})
        endif()

        # Backend selection
        if(CONFIG_PQCP_IMPLEMENTATION_BASELINE OR CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLKEM_USE_NATIVE=1)
        endif()

        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLKEM_USE_REDUCE_RAM=1)
        endif()

        # Compile mlkem-native either in single-level or multilevel mode.
        if(CONFIG_PQCP_MLKEM_MULTI_LEVEL OR PQCP_MLKEM_LEVEL_COUNT GREATER 1)
            zephyr_library_sources(${MLKEM_MULTILEVEL_DIR}/mlkem_native_all.c)
        else()
            zephyr_library_sources(${MLKEM_NATIVE_DIR}/mlkem/mlkem_native.c)
        endif()

        # Compile our Zephyr wrapper
        zephyr_library_sources(${PQCP_SRC}/mlkem_zephyr.c)

        # FIPS-202 (SHA-3/SHAKE) - use bundled or external
        if(NOT CONFIG_PQCP_FIPS202_EXTERNAL)
            # Use bundled FIPS-202 from mlkem-native
            if(EXISTS ${MLKEM_NATIVE_DIR}/mlkem/src/fips202)
                zephyr_include_directories(${MLKEM_NATIVE_DIR}/mlkem/src/fips202)
            endif()
        endif()
    else()
        message(WARNING "mlkem-native not found at ${MLKEM_NATIVE_DIR}. "
                        "Please run 'git submodule update --init' or use FetchContent.")
        # Provide stub implementation
        zephyr_library_sources(${PQCP_SRC}/mlkem_zephyr.c)
    endif()

    zephyr_library_link_libraries(pqcp_common)
endif()

# =============================================================================
# ML-DSA Library
# =============================================================================
if(CONFIG_PQCP_MLDSA)
    zephyr_library_named(pqcp_mldsa)

    # Check for mldsa-native availability
    if(EXISTS ${MLDSA_NATIVE_DIR}/mldsa)
        set(PQCP_MLDSA_LEVEL_COUNT 0)
        if(CONFIG_PQCP_MLDSA_LEVEL_44)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLDSA_LEVEL_65)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()
        if(CONFIG_PQCP_MLDSA_LEVEL_87)
            math(EXPR PQCP_MLDSA_LEVEL_COUNT "${PQCP_MLDSA_LEVEL_COUNT} + 1")
        endif()

        if(CONFIG_PQCP_MLDSA_MULTI_LEVEL OR PQCP_MLDSA_LEVEL_COUNT GREATER 1)
            set(MLDSA_MULTILEVEL_DIR
                ${MLDSA_NATIVE_DIR}/examples/monolithic_build_multilevel)
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR})
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR}/mldsa_native)
            zephyr_include_directories(${MLDSA_MULTILEVEL_DIR}/mldsa_native/src)
            zephyr_compile_definitions(PQCP_MLDSA_MULTILEVEL_BUILD=1)
        else()
            zephyr_include_directories(${MLDSA_NATIVE_DIR})
            zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa)
            zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa/src)
            # Determine security level
            if(CONFIG_PQCP_MLDSA_LEVEL_44)
                set(MLDSA_MODE 2)
                set(MLD_PARAM_SET 44)
            elseif(CONFIG_PQCP_MLDSA_LEVEL_65)
                set(MLDSA_MODE 3)
                set(MLD_PARAM_SET 65)
            elseif(CONFIG_PQCP_MLDSA_LEVEL_87)
                set(MLDSA_MODE 5)
                set(MLD_PARAM_SET 87)
            else()
                # Default to ML-DSA-65
                set(MLDSA_MODE 3)
                set(MLD_PARAM_SET 65)
            endif()

            zephyr_compile_definitions(MLDSA_MODE=${MLDSA_MODE})
            zephyr_compile_definitions(MLD_CONFIG_PARAMETER_SET=${MLD_PARAM_SET})
        endif()

        # Backend selection
        if(CONFIG_PQCP_IMPLEMENTATION_BASELINE OR CONFIG_PQCP_BACKEND_FORCE_C)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=0)
        elseif(CONFIG_PQCP_BACKEND_FORCE_NATIVE)
            zephyr_compile_definitions(MLDSA_USE_NATIVE=1)
        endif()

        # Reduced RAM mode
        if(CONFIG_PQCP_REDUCE_RAM)
            zephyr_compile_definitions(MLDSA_USE_REDUCE_RAM=1)
        endif()

        # Compile mldsa-native either in single-level or multilevel mode.
        if(CONFIG_PQCP_MLDSA_MULTI_LEVEL OR PQCP_MLDSA_LEVEL_COUNT GREATER 1)
            zephyr_library_sources(${MLDSA_MULTILEVEL_DIR}/mldsa_native_all.c)
        else()
            zephyr_library_sources(${MLDSA_NATIVE_DIR}/mldsa/mldsa_native.c)
        endif()

        # Compile our Zephyr wrapper
        zephyr_library_sources(${PQCP_SRC}/mldsa_zephyr.c)

        # Streaming API
        if(CONFIG_PQCP_MLDSA_STREAMING)
            zephyr_library_sources(${PQCP_SRC}/mldsa_streaming.c)
        endif()

        # FIPS-202 (SHA-3/SHAKE) - use bundled or external
        if(NOT CONFIG_PQCP_FIPS202_EXTERNAL)
            if(EXISTS ${MLDSA_NATIVE_DIR}/mldsa/src/fips202)
                zephyr_include_directories(${MLDSA_NATIVE_DIR}/mldsa/src/fips202)
            endif()
        endif()
    else()
        message(WARNING "mldsa-native not found at ${MLDSA_NATIVE_DIR}. "
                        "Please run 'git submodule update --init' or use FetchContent.")
        zephyr_library_sources(${PQCP_SRC}/mldsa_zephyr.c)
    endif()

    zephyr_library_link_libraries(pqcp_common)
endif()

# Shared TLS self-test helpers
if(CONFIG_PQCP_TLS_SELFTEST)
    zephyr_library_named(pqcp_tls_selftest)
    zephyr_library_sources(${PQCP_SRC}/tls_selftest.c)
    zephyr_library_link_libraries(pqcp_common)
    zephyr_library_link_libraries(pqcp_mlkem)
    zephyr_library_link_libraries(pqcp_mldsa)
endif()

# Boot-time power-on self-test (FIPS-style)
if(CONFIG_PQCP_KAT_BOOT_VERIFY)
    zephyr_library_named(pqcp_kat_boot_verify)
    zephyr_library_sources(${PQCP_SRC}/kat_boot_verify.c)
    zephyr_library_link_libraries(pqcp_common)
    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()
    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()
endif()

# =============================================================================
# PSA Crypto Driver Shims
# =============================================================================
if(CONFIG_PQCP_PSA_DRIVER)
    zephyr_library_named(pqcp_psa_driver)

    if(CONFIG_PQCP_PSA_DRIVER_MLDSA)
        zephyr_library_sources(${PQCP_SRC}/psa_mldsa_driver.c)
    endif()

    if(CONFIG_PQCP_PSA_DRIVER_MLKEM)
        zephyr_library_sources(${PQCP_SRC}/psa_mlkem_driver.c)
    endif()

    zephyr_library_link_libraries(pqcp_common)

    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()

    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

endif()

# =============================================================================
# ACVP Command Library
# =============================================================================
if(CONFIG_PQCP_ACVP)
    zephyr_library_named(pqcp_acvp)

    zephyr_library_sources(${PQCP_SRC}/acvp_cmd.c)

    zephyr_library_link_libraries(pqcp_common)

    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()

    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_link_libraries(pqcp_tls_selftest)
    endif()
endif()

# =============================================================================
# Benchmarking Support
# =============================================================================
if(CONFIG_PQCP_BENCH)
    zephyr_library_named(pqcp_bench)

    zephyr_library_sources(${PQCP_SRC}/bench_primitive.c)

    # Protocol benchmark is always included (simulated mode)
    # Real networking benchmarks require CONFIG_PQCP_BENCH_PROTOCOL
    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_sources(${PQCP_SRC}/bench_protocol.c)
    endif()

    zephyr_library_link_libraries(pqcp_common)

    if(CONFIG_PQCP_MLKEM)
        zephyr_library_link_libraries(pqcp_mlkem)
    endif()

    if(CONFIG_PQCP_MLDSA)
        zephyr_library_link_libraries(pqcp_mldsa)
    endif()

    if(CONFIG_PQCP_TLS_SELFTEST)
        zephyr_library_link_libraries(pqcp_tls_selftest)
    endif()
endif()

endif() # CONFIG_PQCP
