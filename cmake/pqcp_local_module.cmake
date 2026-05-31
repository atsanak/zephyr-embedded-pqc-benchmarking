# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation

# Allow repo-local samples and tests to build even when this repository is not
# listed as a west project in the active workspace manifest.

if(NOT DEFINED PQCP_LOCAL_MODULE_ROOT)
  message(FATAL_ERROR "PQCP_LOCAL_MODULE_ROOT must be defined before including pqcp_local_module.cmake")
endif()

get_filename_component(PQCP_LOCAL_MODULE_ROOT "${PQCP_LOCAL_MODULE_ROOT}" ABSOLUTE)

if(EXISTS "${PQCP_LOCAL_MODULE_ROOT}/zephyr/module.yml")
  list(APPEND ZEPHYR_EXTRA_MODULES "${PQCP_LOCAL_MODULE_ROOT}")
endif()
