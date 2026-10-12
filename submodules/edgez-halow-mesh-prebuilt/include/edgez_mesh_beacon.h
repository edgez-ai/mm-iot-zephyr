/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_BEACON_HEADER_LEN 24U
#define EDGEZ_MESH_BEACON_FIXED_LEN 12U

struct edgez_mesh_beacon_frame_config
{
    uint8_t source[6];
    uint8_t bssid[6];
    const uint8_t *mesh_id;
    size_t mesh_id_len;
    const uint8_t *extra_ies;
    size_t extra_ies_len;
    uint16_t beacon_interval_tu;
    uint16_t sequence_number;
    bool secure;
};

int edgez_mesh_beacon_ies_encode(const uint8_t *mesh_id, size_t mesh_id_len,
                                 bool secure, uint8_t *output,
                                 size_t output_capacity,
                                 size_t *encoded_length);

/** Encode a complete raw 802.11 beacon without vendor SDK structures. */
int edgez_mesh_beacon_frame_encode(
    const struct edgez_mesh_beacon_frame_config *config,
    uint8_t *output, size_t output_capacity, size_t *encoded_length);

#ifdef __cplusplus
}
#endif
