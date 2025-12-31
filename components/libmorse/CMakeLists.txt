# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0


set(MORSE_CPU_ARCH     arm-cortex-m33f)


# BLOB_DIR layout is lib/<chip>/<arch>/libmorse.a (e.g., lib/mm6108/arm-cortex-m33f/libmorse.a)
set(MORSE_CHIP mm6108)
set(MORSE_LIB_DIR ${BLOB_DIR}/lib/${MORSE_CHIP}/${MORSE_CPU_ARCH})

find_library(LIBMORSE_FOUND "morse" HINTS "${MORSE_LIB_DIR}")

if(NOT LIBMORSE_FOUND)
  message(FATAL_ERROR
  "Morse Micro driver library not found.\n"
  "Run the command below to download the necessary files:\n"
  "> west blobs fetch morsemicro")
  return()
endif()

add_library(libmorse STATIC IMPORTED GLOBAL)
set_target_properties(libmorse PROPERTIES IMPORTED_LOCATION             ${MORSE_LIB_DIR}/libmorse.a)
set_target_properties(libmorse PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_compile_definitions(libmorse INTERFACE
  MMOSAL_NOASSERT
  MMOSAL_NO_DEBUGLOG
)
