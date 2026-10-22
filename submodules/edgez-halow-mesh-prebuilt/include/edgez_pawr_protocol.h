/*
 * Copyright 2026 EdgeZeron AI AB
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_PAWR_HEADER_LENGTH 24U
#define EDGEZ_PAWR_ACTION_HEADER_LENGTH 29U
/* Public Action frames can carry a normal HaLow-sized MSDU. Keep the complete
 * management frame below the Morse 1600-byte raw-frame buffer. */
#define EDGEZ_PAWR_MAX_ACTION_PAYLOAD 1536U

enum edgez_pawr_request_type
{
    EDGEZ_PAWR_REQUEST_BEACON = 2U,
    EDGEZ_PAWR_REQUEST_MESH_PACKET = 4U,
    /** Bulk data/control does not use the legacy per-payload hash ACK. */
    EDGEZ_PAWR_REQUEST_BULK_STREAM = 5U,
};

struct edgez_pawr_request_view
{
    enum edgez_pawr_request_type type;
    uint32_t request_id;
    uint32_t wake_interval_ms;
    uint8_t slot;
    const uint8_t *payload;
    size_t payload_length;
};

struct edgez_pawr_action_view
{
    uint8_t source[6];
    uint8_t destination[6];
    const uint8_t *payload;
    size_t payload_length;
};

/** Wrap an EdgeZ PAwR protocol packet in an unprotected vendor-specific
 * 802.11 Public Action frame. Public Action works without association. */
bool edgez_pawr_encode_action_frame(
    uint8_t *output, size_t output_capacity, uint16_t sequence_number,
    const uint8_t local_mac[6], const uint8_t destination[6],
    const uint8_t *payload, size_t payload_length, size_t *output_length);

bool edgez_pawr_decode_action_frame(const uint8_t *frame, size_t frame_length,
                                    struct edgez_pawr_action_view *action);

bool edgez_pawr_encode_typed_request(
    uint8_t *output, size_t output_capacity,
    enum edgez_pawr_request_type type,
    uint32_t request_id, uint32_t wake_interval_ms,
    const uint8_t *payload, size_t payload_length,
    size_t *output_length);

uint32_t edgez_pawr_payload_hash(const uint8_t *payload, size_t payload_length);

bool edgez_pawr_encode_request(uint8_t *output, size_t output_capacity,
                               uint32_t request_id, uint32_t wake_interval_ms,
                               const uint8_t *payload, size_t payload_length,
                               size_t *output_length);

bool edgez_pawr_encode_mesh_packet(uint8_t *output, size_t output_capacity,
                                   uint32_t request_id,
                                   const uint8_t *payload,
                                   size_t payload_length,
                                   size_t *output_length);

bool edgez_pawr_decode_request(const uint8_t *frame, size_t frame_length,
                               struct edgez_pawr_request_view *request);

bool edgez_pawr_encode_response(uint8_t *output, size_t output_capacity,
                                uint32_t payload_hash, size_t *output_length);

bool edgez_pawr_decode_response(const uint8_t *frame, size_t frame_length,
                                uint32_t *payload_hash);

#ifdef __cplusplus
}
#endif
