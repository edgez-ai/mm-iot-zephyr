/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MORSEMICRO_ZEPHYR_ENDIAN_H
#define MORSEMICRO_ZEPHYR_ENDIAN_H

#include <stdint.h>

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __BYTE_ORDER __LITTLE_ENDIAN

#define htole16(value) ((uint16_t)(value))
#define htole32(value) ((uint32_t)(value))
#define htole64(value) ((uint64_t)(value))
#define le16toh(value) ((uint16_t)(value))
#define le32toh(value) ((uint32_t)(value))
#define le64toh(value) ((uint64_t)(value))

#define htobe16(value) __builtin_bswap16((uint16_t)(value))
#define htobe32(value) __builtin_bswap32((uint32_t)(value))
#define htobe64(value) __builtin_bswap64((uint64_t)(value))
#define be16toh(value) __builtin_bswap16((uint16_t)(value))
#define be32toh(value) __builtin_bswap32((uint32_t)(value))
#define be64toh(value) __builtin_bswap64((uint64_t)(value))

#endif /* MORSEMICRO_ZEPHYR_ENDIAN_H */
