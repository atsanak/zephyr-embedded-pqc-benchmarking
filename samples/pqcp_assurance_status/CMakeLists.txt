# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

cmake_minimum_required(VERSION 3.20.0)

set(PQCP_LOCAL_MODULE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
include(${PQCP_LOCAL_MODULE_ROOT}/cmake/pqcp_local_module.cmake)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqcp_assurance_status)

if(DEFINED PQCP_ASSURANCE_DIGEST_INCLUDE_DIR)
  target_include_directories(app BEFORE PRIVATE ${PQCP_ASSURANCE_DIGEST_INCLUDE_DIR})
endif()
target_include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_sources(app PRIVATE src/main.c)
