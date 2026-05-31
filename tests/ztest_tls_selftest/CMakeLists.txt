# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ztest_tls_selftest)

target_sources(app PRIVATE src/main.c)
