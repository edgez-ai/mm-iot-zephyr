# EdgeZ join-only build: Morse lower-MAC/RF boundary plus the vendor-neutral
# EdgeZ UMAC.  Keep the source list explicit so the reference Morse UMAC and
# wpa_supplicant cannot be pulled into this image accidentally.

set(MORSELIB_ROOT ${MMIOT_ROOT}/framework/morselib)
set(EDGEZ_RF_MORSEMICRO_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-rf-morsemicro)
set(EDGEZ_RF_API_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-rf-api)
set(EDGEZ_PREBUILT_ROOT
  ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/edgez-halow-mesh-prebuilt)
set(EDGEZ_PREBUILT_CORE_LIBRARY
  ${EDGEZ_PREBUILT_ROOT}/lib/libedgez_halow_mesh.a)
set(EDGEZ_PREBUILT_PLATFORM_LIBRARY
  ${EDGEZ_PREBUILT_ROOT}/lib/libedgez_halow_mesh_platform.a)
set(EDGEZ_PREBUILT_SECURITY_LIBRARY
  ${EDGEZ_PREBUILT_ROOT}/lib/libedgez_halow_mesh_security.a)

if(NOT EXISTS "${EDGEZ_PREBUILT_CORE_LIBRARY}" OR
   NOT EXISTS "${EDGEZ_PREBUILT_PLATFORM_LIBRARY}")
  message(FATAL_ERROR
    "Missing EdgeZ nRF54 prebuilt libraries under: ${EDGEZ_PREBUILT_ROOT}/lib")
endif()
set(EDGEZ_HALOW_MESH_SOURCE_BUILD OFF)
if(DEFINED ENV{EDGEZ_HALOW_MESH_SOURCE_ROOT} AND
   NOT "$ENV{EDGEZ_HALOW_MESH_SOURCE_ROOT}" STREQUAL "")
  set(EDGEZ_HALOW_MESH_SOURCE_ROOT "$ENV{EDGEZ_HALOW_MESH_SOURCE_ROOT}")
  if(NOT EXISTS "${EDGEZ_HALOW_MESH_SOURCE_ROOT}/ports/zephyr/component.cmake")
    message(FATAL_ERROR
      "Invalid EdgeZ HaLow mesh source checkout: ${EDGEZ_HALOW_MESH_SOURCE_ROOT}")
  endif()
  set(EDGEZ_HALOW_MESH_SOURCE_BUILD ON)
  include(${EDGEZ_HALOW_MESH_SOURCE_ROOT}/ports/zephyr/component.cmake)
  set(EDGEZ_MESH_INCLUDE_ROOT ${EDGEZ_HALOW_MESH_INCLUDE_DIR})
  set(EDGEZ_HOSTAP_ROOT
    ${EDGEZ_HALOW_MESH_SOURCE_ROOT}/overrides/mm_iot_sdk/framework/src/hostap)
  message(STATUS
    "Using EdgeZ HaLow mesh source checkout: ${EDGEZ_HALOW_MESH_SOURCE_ROOT}")
else()
  if(NOT EXISTS "${EDGEZ_PREBUILT_SECURITY_LIBRARY}")
    message(FATAL_ERROR
      "The EdgeZ prebuilt package does not contain its HostAP security runtime: "
      "${EDGEZ_PREBUILT_SECURITY_LIBRARY}. Provide EDGEZ_HALOW_MESH_SOURCE_ROOT "
      "or install a complete EdgeZ prebuilt package. Falling back to the "
      "mm-iot-sdk HostAP is not supported.")
  endif()
  set(EDGEZ_MESH_INCLUDE_ROOT ${EDGEZ_PREBUILT_ROOT}/include)
  # Keep every consumer translation unit aligned with the release archive.
  # The archive intentionally excludes diagnostic code even when the Zephyr
  # application enables its normal debug-log Kconfig option.
  zephyr_compile_definitions(EDGEZ_PLATFORM_ARCHIVE_BUILD=1)
  message(STATUS "Using EdgeZ HaLow mesh release prebuilt")
endif()

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

if(EDGEZ_HALOW_MESH_SOURCE_BUILD)
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
else()
  add_library(edgez_umac_core STATIC IMPORTED GLOBAL)
  set_target_properties(edgez_umac_core PROPERTIES
    IMPORTED_LOCATION "${EDGEZ_PREBUILT_CORE_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES
      "${EDGEZ_MESH_INCLUDE_ROOT};${EDGEZ_RF_API_ROOT}/include"
  )
endif()
if(EDGEZ_HALOW_MESH_SOURCE_BUILD)
  # Register this as a Zephyr library. PlatformIO's second build phase
  # otherwise rediscovers plain CMake library sources but drops their
  # target-local include paths.
  zephyr_library_named(edgez_mesh_platform)
  target_sources(edgez_mesh_platform PRIVATE
    ${EDGEZ_HALOW_MESH_SOURCE_ROOT}/ports/esp_idf/src/edgez_mesh_sae_provider.c
    ${EDGEZ_HALOW_MESH_SOURCE_ROOT}/overrides/esp_halow/components/shims/mesh_ccm_bulk.c
  )
  target_include_directories(edgez_mesh_platform
    PUBLIC
      ${EDGEZ_MESH_INCLUDE_ROOT}
      ${EDGEZ_RF_API_ROOT}/include
    PRIVATE
      # PlatformIO recompiles this custom target without all transitive Zephyr
      # interface include paths, so expose the crypto headers used by the
      # EdgeZ CCM platform shim directly (as for edgez_mesh_security below).
      ${ZEPHYR_BASE}/include
      ${PROJECT_BINARY_DIR}/zephyr/include/generated
      ${ZEPHYR_MBEDTLS_3_6_MODULE_DIR}/include
      ${ZEPHYR_CURRENT_MODULE_DIR}/components/morsemicro/compat
      ${EDGEZ_HOSTAP_ROOT}/..
      ${EDGEZ_HOSTAP_ROOT}
      ${EDGEZ_HOSTAP_ROOT}/src
      ${EDGEZ_HOSTAP_ROOT}/src/common
      ${EDGEZ_HOSTAP_ROOT}/src/utils
      ${EDGEZ_HOSTAP_ROOT}/src/crypto
  )
  target_compile_definitions(edgez_mesh_platform PRIVATE
    EDGEZ_PLATFORM_NRF54=1 MM_IOT=1
  )
  target_compile_options(edgez_mesh_platform PRIVATE ${COMPILE_OPTIONS})
  target_link_libraries(edgez_mesh_platform PRIVATE
    edgez_umac_core mbedTLS zephyr_interface
  )
  set_property(TARGET edgez_mesh_platform PROPERTY C_STANDARD 11)
  message(STATUS "Using EdgeZ mesh platform source from source checkout")
else()
  add_library(edgez_mesh_platform STATIC IMPORTED GLOBAL)
  set_target_properties(edgez_mesh_platform PROPERTIES
    IMPORTED_LOCATION "${EDGEZ_PREBUILT_PLATFORM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES
      "${EDGEZ_MESH_INCLUDE_ROOT};${EDGEZ_RF_API_ROOT}/include"
    INTERFACE_LINK_LIBRARIES edgez_umac_core
  )
endif()

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

if(EDGEZ_HALOW_MESH_SOURCE_BUILD)
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
  message(STATUS "Using EdgeZ HostAP source tree: ${EDGEZ_HOSTAP_ROOT}")
else()
  zephyr_library_import(edgez_mesh_security
    ${EDGEZ_PREBUILT_SECURITY_LIBRARY})
  target_link_libraries(edgez_mesh_security INTERFACE
    edgez_mesh_platform mbedTLS mmutils zephyr_interface
  )
  zephyr_library_named(edgez_mesh_security_glue)
  target_sources(edgez_mesh_security_glue PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/edgez_hostap_os_zephyr.c
    ${MMIOT_ROOT}/framework/src/mbedtls/library/entropy.c
  )
  target_include_directories(edgez_mesh_security_glue PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${ZEPHYR_CURRENT_MODULE_DIR}/components/morsemicro/compat
    ${ZEPHYR_BASE}/include
    ${PROJECT_BINARY_DIR}/zephyr/include/generated
    ${ZEPHYR_MBEDTLS_3_6_MODULE_DIR}/include
    ${MMIOT_ROOT}/framework/src/mmutils
    ${MMIOT_ROOT}/framework/src/mbedtls/library
  )
  target_compile_definitions(edgez_mesh_security_glue PRIVATE
    EDGEZ_PLATFORM_NRF54=1
    CONFIG_SAE=1 CONFIG_ECC=1 CONFIG_SHA256=1 CONFIG_SHA384=1 CONFIG_SHA512=1
    CONFIG_FIPS=1 CONFIG_NO_RANDOM_POOL=1 CONFIG_NO_STDOUT_DEBUG=1
    EDGEZ_TF_PSA_COMPACT_ECP_GROUP_IDS=1
    MBEDTLS_USER_CONFIG_FILE="edgez_mbedtls_user_config.h"
    ENABLE_HOSTAP_CRYPTO_API_MANGLING=1 MM_IOT
  )
  target_compile_options(edgez_mesh_security_glue PRIVATE ${COMPILE_OPTIONS} -w)
  target_link_libraries(edgez_mesh_security_glue PRIVATE
    edgez_mesh_security edgez_mesh_platform mbedTLS mmutils zephyr_interface
  )
  message(STATUS
    "Using EdgeZ prebuilt HostAP security runtime: ${EDGEZ_PREBUILT_SECURITY_LIBRARY}")
endif()
