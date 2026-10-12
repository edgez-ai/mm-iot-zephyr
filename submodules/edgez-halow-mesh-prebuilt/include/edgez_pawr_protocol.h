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

struct edgez_pawr_request_view
{
    uint32_t request_id;
    uint32_t wake_interval_ms;
    uint8_t slot;
    const uint8_t *payload;
    size_t payload_length;
};

uint32_t edgez_pawr_payload_hash(const uint8_t *payload, size_t payload_length);

bool edgez_pawr_encode_request(uint8_t *output, size_t output_capacity,
                               uint32_t request_id, uint32_t wake_interval_ms,
                               const uint8_t *payload, size_t payload_length,
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
