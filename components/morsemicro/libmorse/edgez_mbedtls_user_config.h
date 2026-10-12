/*
 * Copyright 2026 EdgeZeron AI AB
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/* The standalone SAE hostap shim uses Mbed TLS' legacy point-arithmetic API.
 * Zephyr links these objects from the PSA secp256r1 selection but does not
 * expose the corresponding legacy feature symbols to consumers. */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED

/* The public Morse HostAP adapter checks the legacy Mbed TLS feature names.
 * Zephyr enables these algorithms through PSA Kconfig, so expose the
 * matching compatibility symbols to this target's headers. */
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

/* v0.0.5's nRF platform archive uses the legacy AES-CBC entry point, and the
 * public Morse HostAP adapter keeps a legacy entropy accumulator. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* Zephyr 4.4 pairs the Mbed TLS 3.6 public headers with TF-PSA-Crypto 1.1.
 * The latter uses compact ECP group IDs after removing legacy curves. */
#define EDGEZ_TF_PSA_COMPACT_ECP_GROUP_IDS 1
