/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "edgez_mesh_mpm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_AMPE_MGTK_LEN 16U
#define EDGEZ_MESH_AMPE_MGTK_RSC_LEN 8U
#define EDGEZ_MESH_AMPE_IGTK_LEN 16U
#define EDGEZ_MESH_AMPE_IGTK_IPN_LEN 6U
#define EDGEZ_MESH_AMPE_IGTK_KEY_ID 4U
#define EDGEZ_MESH_AMPE_OPEN_KEY_DATA_LEN \
    (EDGEZ_MESH_AMPE_MGTK_LEN + EDGEZ_MESH_AMPE_MGTK_RSC_LEN + 4U + \
     2U + EDGEZ_MESH_AMPE_IGTK_IPN_LEN + EDGEZ_MESH_AMPE_IGTK_LEN)

struct edgez_mesh_ampe_open_keys
{
    uint8_t mgtk[EDGEZ_MESH_AMPE_MGTK_LEN];
    uint8_t mgtk_rsc[EDGEZ_MESH_AMPE_MGTK_RSC_LEN];
    uint32_t gtk_expiration_seconds;
    uint16_t igtk_key_id;
    uint8_t igtk_ipn[EDGEZ_MESH_AMPE_IGTK_IPN_LEN];
    uint8_t igtk[EDGEZ_MESH_AMPE_IGTK_LEN];
};

bool edgez_mesh_ampe_encode_open_keys(
    uint8_t *output, size_t output_capacity,
    const struct edgez_mesh_ampe_open_keys *keys);

bool edgez_mesh_ampe_decode_open_keys(
    struct edgez_mesh_ampe_open_keys *keys,
    const uint8_t *input, size_t input_length,
    uint16_t expected_igtk_key_id);

/** MTK installation follows accepted CONFIRM, never accepted OPEN. */
bool edgez_mesh_ampe_should_install_mtk(
    enum edgez_mesh_mpm_action accepted_action);

#ifdef __cplusplus
}
#endif
