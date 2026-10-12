/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_control.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_ETHERNET_HEADER_LEN 14U
#define EDGEZ_RFC1042_HEADER_LEN 8U

/** Decoded Ethernet payload carried by an IEEE 802.11 mesh MSDU. */
struct edgez_mesh_msdu
{
    struct edgez_mesh_control mesh_control;
    uint8_t destination[EDGEZ_UMAC_MAC_LEN];
    uint8_t source[EDGEZ_UMAC_MAC_LEN];
    uint16_t ether_type;
    const uint8_t *payload;
    size_t payload_length;
};

/**
 * Decode Mesh Control and RFC1042 LLC/SNAP from decrypted mesh data.
 *
 * base_destination/base_source are canonical addresses supplied by the RF
 * adapter. Address-extension fields in the standard Mesh Control header take
 * precedence when present.
 */
int edgez_mesh_msdu_decode(
    struct edgez_mesh_msdu *output,
    const uint8_t base_destination[EDGEZ_UMAC_MAC_LEN],
    const uint8_t base_source[EDGEZ_UMAC_MAC_LEN],
    const uint8_t *plaintext, size_t plaintext_length);

/** Copy a decoded MSDU into a normal Ethernet II frame. */
int edgez_mesh_msdu_to_ethernet(const struct edgez_mesh_msdu *msdu,
                                uint8_t *output, size_t output_capacity,
                                size_t *output_length);

/** Encode Mesh Control plus RFC1042 LLC/SNAP from an Ethernet II frame. */
int edgez_mesh_msdu_from_ethernet(
    const struct edgez_mesh_control *mesh_control,
    const uint8_t *ethernet_frame, size_t ethernet_length,
    uint8_t *output, size_t output_capacity, size_t *output_length);

#ifdef __cplusplus
}
#endif
