# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

# Zephyr's auto-generated module variable is unset on some build systems; fall back to this
# directory so blob paths resolve correctly when the module name differs (e.g. mm-iot-zephyr).
if(NOT DEFINED ZEPHYR_MORSEMICRO_MODULE_DIR)
	set(ZEPHYR_MORSEMICRO_MODULE_DIR ${CMAKE_CURRENT_LIST_DIR})
endif()

set(BLOB_DIR ${ZEPHYR_MORSEMICRO_MODULE_DIR}/zephyr/blobs)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE    components)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE    drivers)