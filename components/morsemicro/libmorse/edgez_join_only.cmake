# EdgeZ join-only build: Morse lower-MAC/RF boundary plus the vendor-neutral
# EdgeZ UMAC.  Keep the source list explicit so the reference Morse UMAC and
# wpa_supplicant cannot be pulled into this image accidentally.

set(MORSELIB_ROOT ${MMIOT_ROOT}/framework/morselib)
set(EDGEZ_RF_MORSEMICRO_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-rf-morsemicro)
set(EDGEZ_RF_API_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-rf-api)
set(EDGEZ_HOSTAP_ROOT ${MMIOT_ROOT}/framework/src/hostap)
set(EDGEZ_PREBUILT_ROOT
  ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-halow-mesh-prebuilt)
set(EDGEZ_PREBUILT_PLATFORM_LIBRARY
  ${EDGEZ_PREBUILT_ROOT}/lib/libedgez_halow_mesh_platform.a)

if(NOT EXISTS "${EDGEZ_PREBUILT_PLATFORM_LIBRARY}")
  message(FATAL_ERROR
    "Missing EdgeZ nRF54 platform library under: ${EDGEZ_PREBUILT_ROOT}/lib")
endif()
if(NOT DEFINED ENV{EDGEZ_HALOW_MESH_SOURCE_ROOT})
  message(FATAL_ERROR
    "EDGEZ_HALOW_MESH_SOURCE_ROOT is required for the debug source build")
endif()
set(EDGEZ_HALOW_MESH_SOURCE_ROOT "$ENV{EDGEZ_HALOW_MESH_SOURCE_ROOT}")
if(NOT EXISTS "${EDGEZ_HALOW_MESH_SOURCE_ROOT}/ports/zephyr/component.cmake")
  message(FATAL_ERROR
    "Invalid EdgeZ HaLow mesh source checkout: ${EDGEZ_HALOW_MESH_SOURCE_ROOT}")
endif()
include(${EDGEZ_HALOW_MESH_SOURCE_ROOT}/ports/zephyr/component.cmake)
set(EDGEZ_MESH_INCLUDE_ROOT ${EDGEZ_HALOW_MESH_INCLUDE_DIR})

set(EDGEZ_RF_SOURCES
  ${MORSELIB_ROOT}/src/common/common.c
  ${MORSELIB_ROOT}/src/common/mac_address.c
  ${MORSELIB_ROOT}/src/common/mmpkt.c
  ${MORSELIB_ROOT}/src/common/mmpkt_list.c
  ${MORSELIB_ROOT}/src/dot11/dot11_utils.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm6108/mm6108.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm6108/pager_if_hw.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm6108/pager_if.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm6108/pageset.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm8108/mm8108.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm8108/yaps-hw.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/mm8108/yaps.c
  ${MORSELIB_ROOT}/src/driver/beacon/beacon.c
  ${MORSELIB_ROOT}/src/driver/driver.c
  ${MORSELIB_ROOT}/src/driver/driver_task.c
  ${MORSELIB_ROOT}/src/driver/puff/puff.c
  ${MORSELIB_ROOT}/src/driver/morse_crc/morse_crc.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/command.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/coredump.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/event.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/ext_host_table.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/firmware.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/firmware_mbin.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/hw.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/ps.c
  ${MORSELIB_ROOT}/src/driver/morse_driver/skbq.c
  ${MORSELIB_ROOT}/src/driver/transport/sdio.c
  ${MORSELIB_ROOT}/src/driver/transport/sdio_spi.c
  ${EDGEZ_RF_MORSEMICRO_ROOT}/src/edgez_mmdrv_host.c
)

foreach(source IN LISTS EDGEZ_RF_SOURCES)
  if(source MATCHES "/morselib/src/umac/" OR source MATCHES "/framework/src/hostap/")
    message(FATAL_ERROR "Join-only RF boundary contains upper-MAC source: ${source}")
  endif()
endforeach()

set(MORSELIB_INCLUDES
  ${MORSELIB_ROOT}/include
  ${MORSELIB_ROOT}/src
  ${MORSELIB_ROOT}/src/internal
  ${MORSELIB_ROOT}/src/umac/rc/mmrc_osal
  ${MORSELIB_ROOT}/mmrc/src/core
)

add_library(libmorse STATIC ${EDGEZ_RF_SOURCES})
# Keep the archive name compatible with Morse Micro's normal mangled target.
# PlatformIO adds libmorse.a as an explicit Zephyr link dependency.
set_target_properties(libmorse PROPERTIES OUTPUT_NAME morse)
target_include_directories(libmorse PRIVATE
  ${ZEPHYR_CURRENT_MODULE_DIR}/components/morsemicro/compat
  ${MORSELIB_INCLUDES}
  ${EDGEZ_MESH_INCLUDE_ROOT}
  ${EDGEZ_RF_API_ROOT}/include
  ${EDGEZ_RF_MORSEMICRO_ROOT}/include
  ${APPLICATION_SOURCE_DIR}/../include
)
target_compile_definitions(libmorse PRIVATE MMDRV_TASK_STACK_SIZE_WORDS=2048)
target_compile_definitions(libmorse PRIVATE EDGEZ_PLATFORM_NRF54=1)
target_compile_options(libmorse PRIVATE ${COMPILE_OPTIONS} -w)
target_link_libraries(libmorse PRIVATE libmorse_interface mmutils mmpktmem)
# PlatformIO's Zephyr integration prebuilds this conventional Morse target.
add_custom_target(libmorse_build DEPENDS libmorse)
# The PlatformIO integration compiles Zephyr sources after this prebuild step.
# Generate the firmware/BCF include files before that second phase starts.
add_dependencies(libmorse_build firmware)

add_library(edgez_umac_core STATIC ${EDGEZ_HALOW_MESH_COMMON_SOURCES})
target_include_directories(edgez_umac_core PUBLIC
  ${EDGEZ_MESH_INCLUDE_ROOT}
  ${EDGEZ_RF_API_ROOT}/include
)
target_compile_definitions(edgez_umac_core PUBLIC
  EDGEZ_DIAGNOSTICS_ENABLED=1
)
target_compile_definitions(edgez_umac_core PRIVATE EDGEZ_PLATFORM_NRF54=1)
target_compile_options(edgez_umac_core PRIVATE ${COMPILE_OPTIONS})
set_property(TARGET edgez_umac_core PROPERTY C_STANDARD 11)
add_library(edgez_mesh_platform STATIC IMPORTED GLOBAL)
set_target_properties(edgez_mesh_platform PROPERTIES
  IMPORTED_LOCATION "${EDGEZ_PREBUILT_PLATFORM_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${EDGEZ_MESH_INCLUDE_ROOT};${EDGEZ_RF_API_ROOT}/include"
  INTERFACE_LINK_LIBRARIES edgez_umac_core
)

# The Morse adapter is deliberately a separate archive.  Only this target may
# include or link Morse SDK interfaces; edgez_umac_core stays vendor-neutral.
add_library(edgez_rf_morsemicro STATIC
  ${EDGEZ_RF_MORSEMICRO_ROOT}/src/edgez_mesh_ccm_morse.c
  ${EDGEZ_RF_MORSEMICRO_ROOT}/src/edgez_umac_morse_adapter.c
  ${EDGEZ_RF_MORSEMICRO_ROOT}/src/edgez_umac_rf_binding.c
)
target_include_directories(edgez_rf_morsemicro PUBLIC
  ${EDGEZ_MESH_INCLUDE_ROOT}
  ${EDGEZ_RF_API_ROOT}/include
)
target_include_directories(edgez_rf_morsemicro PRIVATE
  ${EDGEZ_RF_MORSEMICRO_ROOT}/include
  ${MORSELIB_INCLUDES}
)
target_link_libraries(edgez_rf_morsemicro PRIVATE
  edgez_umac_core libmorse_interface mmutils mmpktmem
)
target_compile_options(edgez_rf_morsemicro PRIVATE ${COMPILE_OPTIONS})
target_compile_definitions(edgez_rf_morsemicro PRIVATE EDGEZ_PLATFORM_NRF54=1)

zephyr_library_named(edgez_mesh_security)
target_sources(edgez_mesh_security PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/edgez_hostap_os_zephyr.c
  ${MMIOT_ROOT}/framework/src/mbedtls/library/entropy.c
  ${EDGEZ_HOSTAP_ROOT}/crypto_mbedtls_mm.c
  ${EDGEZ_HOSTAP_ROOT}/src/common/dragonfly.c
  ${EDGEZ_HOSTAP_ROOT}/src/common/sae.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/aes-ctr.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/aes-siv.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/dh_groups.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/sha256-kdf.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/sha384-kdf.c
  ${EDGEZ_HOSTAP_ROOT}/src/crypto/sha512-kdf.c
  ${EDGEZ_HOSTAP_ROOT}/src/utils/common.c
  ${EDGEZ_HOSTAP_ROOT}/src/utils/wpabuf.c
)
target_include_directories(edgez_mesh_security PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${ZEPHYR_CURRENT_MODULE_DIR}/components/morsemicro/compat
  ${APPLICATION_SOURCE_DIR}/../include
  ${EDGEZ_MESH_INCLUDE_ROOT}
  # PlatformIO's Zephyr bridge recompiles custom CMake targets and only
  # preserves their direct include paths, not transitive interface paths.
  ${ZEPHYR_BASE}/include
  ${PROJECT_BINARY_DIR}/zephyr/include/generated
  ${ZEPHYR_MBEDTLS_3_6_MODULE_DIR}/include
  ${EDGEZ_HOSTAP_ROOT}/..
  ${EDGEZ_HOSTAP_ROOT}
  ${EDGEZ_HOSTAP_ROOT}/src
  ${EDGEZ_HOSTAP_ROOT}/src/common
  ${EDGEZ_HOSTAP_ROOT}/src/utils
  ${EDGEZ_HOSTAP_ROOT}/src/crypto
  ${MMIOT_ROOT}/framework/src/mmutils
  ${MMIOT_ROOT}/framework/src/mbedtls/library
)
target_compile_definitions(edgez_mesh_security PRIVATE
  EDGEZ_PLATFORM_NRF54=1
  CONFIG_SAE=1 CONFIG_ECC=1 CONFIG_SHA256=1 CONFIG_SHA384=1 CONFIG_SHA512=1
  CONFIG_FIPS=1 CONFIG_NO_RANDOM_POOL=1 CONFIG_NO_STDOUT_DEBUG=1
  CONFIG_EDGEZ_SAE_DIAGNOSTICS=1
  # Zephyr 4.4's TF-PSA-Crypto backend uses compact ECP group IDs while the
  # public Mbed TLS 3.6 compatibility headers retain the legacy enum values.
  EDGEZ_TF_PSA_COMPACT_ECP_GROUP_IDS=1
  # Apply the legacy ECP symbols after Zephyr's base Mbed TLS configuration.
  # Keeping this user configuration target-local avoids changing TF-PSA.
  MBEDTLS_USER_CONFIG_FILE="edgez_mbedtls_user_config.h"
  ENABLE_HOSTAP_CRYPTO_API_MANGLING=1 MM_IOT
)
target_compile_options(edgez_mesh_security PRIVATE ${COMPILE_OPTIONS} -w)
target_link_libraries(edgez_mesh_security PRIVATE
  edgez_mesh_platform mbedTLS mmutils zephyr_interface
)
