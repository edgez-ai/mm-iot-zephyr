/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_umac.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_CCMP_KEY_LEN 16U
#define EDGEZ_MESH_CCMP_HEADER_LEN 8U
#define EDGEZ_MESH_CCMP_MIC_LEN 8U

enum edgez_mesh_ccmp_frame_kind
{
    EDGEZ_MESH_CCMP_DATA = 0,
    EDGEZ_MESH_CCMP_MANAGEMENT,
};

struct edgez_mesh_ccmp_header
{
    uint8_t key_id;
    uint64_t packet_number;
};

typedef int (*edgez_mesh_ccmp_encrypt_fn)(
    const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t mic_len,
    const uint8_t *plain, size_t plain_len, const uint8_t *aad,
    size_t aad_len, uint8_t *crypt, uint8_t *tag);

typedef int (*edgez_mesh_ccmp_decrypt_fn)(
    const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t mic_len,
    const uint8_t *crypt, size_t crypt_len, const uint8_t *aad,
    size_t aad_len, const uint8_t *tag, uint8_t *plain);

struct edgez_mesh_ccmp_crypto_ops
{
    edgez_mesh_ccmp_encrypt_fn encrypt;
    edgez_mesh_ccmp_decrypt_fn decrypt;
};

int edgez_mesh_ccmp_parse_header(const uint8_t *body, size_t body_len,
                                 struct edgez_mesh_ccmp_header *header);

/** Encrypt a frame body into CCMP header | ciphertext | MIC. */
int edgez_mesh_ccmp_encrypt(
    const struct edgez_mesh_ccmp_crypto_ops *crypto,
    enum edgez_mesh_ccmp_frame_kind kind, const uint8_t *mac_header,
    size_t mac_header_len, uint8_t qos_tid, const uint8_t *key,
    size_t key_len, uint8_t key_id, uint64_t packet_number,
    const uint8_t *plain, size_t plain_len, uint8_t *output,
    size_t output_capacity, size_t *output_len);

/** Decrypt a CCMP body into plaintext after authenticating its MIC. */
int edgez_mesh_ccmp_decrypt(
    const struct edgez_mesh_ccmp_crypto_ops *crypto,
    enum edgez_mesh_ccmp_frame_kind kind, const uint8_t *mac_header,
    size_t mac_header_len, uint8_t qos_tid, const uint8_t *key,
    size_t key_len, const uint8_t *body, size_t body_len, uint8_t *plain,
    size_t plain_capacity, size_t *plain_len,
    struct edgez_mesh_ccmp_header *header);

#ifdef __cplusplus
}
#endif
