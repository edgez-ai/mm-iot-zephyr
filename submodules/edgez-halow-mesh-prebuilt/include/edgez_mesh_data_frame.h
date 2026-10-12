/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_mesh_control.h"

#include <stdbool.h>

#define EDGEZ_MESH_QOS_4ADDR_HEADER_LEN 32U

struct edgez_mesh_data_header
{
    uint8_t receiver[EDGEZ_UMAC_MAC_LEN];
    uint8_t transmitter[EDGEZ_UMAC_MAC_LEN];
    uint8_t destination[EDGEZ_UMAC_MAC_LEN];
    uint8_t source[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    uint8_t tid;
    bool protected_frame;
    struct edgez_mesh_control mesh_control;
};

int edgez_mesh_data_header_encode(uint8_t *output, size_t output_capacity,
                                  const struct edgez_mesh_data_header *header,
                                  size_t *encoded_length);

/** Encode a complete plaintext QoS mesh data frame from Ethernet II input. */
int edgez_mesh_data_frame_encode(uint8_t *output, size_t output_capacity,
                                 const struct edgez_mesh_data_header *header,
                                 const uint8_t *ethernet_frame,
                                 size_t ethernet_length,
                                 size_t *encoded_length);
