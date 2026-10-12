/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "edgez_umac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_CONTROL_BASE_LEN 6U
#define EDGEZ_MESH_CONTROL_MAX_LEN 18U

enum edgez_mesh_address_extension
{
    EDGEZ_MESH_AE_NONE = 0,
    EDGEZ_MESH_AE_ADDR5 = 1,
    EDGEZ_MESH_AE_ADDR5_ADDR6 = 2,
};

struct edgez_mesh_control
{
    enum edgez_mesh_address_extension address_extension;
    uint8_t flags;
    uint8_t ttl;
    uint32_t sequence_number;
    uint8_t address5[EDGEZ_UMAC_MAC_LEN];
    uint8_t address6[EDGEZ_UMAC_MAC_LEN];
};

size_t edgez_mesh_control_encoded_length(enum edgez_mesh_address_extension extension);
int edgez_mesh_control_encode(uint8_t *output, size_t output_capacity,
                              const struct edgez_mesh_control *control,
                              size_t *encoded_length);
int edgez_mesh_control_encode_tx(bool multicast, uint32_t sequence_number,
                                 const uint8_t destination[EDGEZ_UMAC_MAC_LEN],
                                 const uint8_t source[EDGEZ_UMAC_MAC_LEN],
                                 uint8_t *output, size_t output_capacity,
                                 size_t *encoded_length);
int edgez_mesh_control_decode(struct edgez_mesh_control *control,
                              const uint8_t *input, size_t input_length,
                              size_t *consumed_length);

#ifdef __cplusplus
}
#endif
