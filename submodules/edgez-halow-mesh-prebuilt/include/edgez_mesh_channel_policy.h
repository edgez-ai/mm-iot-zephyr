/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    EDGEZ_MESH_CHANNEL_INVALID,
    EDGEZ_MESH_CHANNEL_LEGACY,
    EDGEZ_MESH_CHANNEL_PARSED,
} edgez_mesh_channel_parse_result_t;

typedef struct {
    uint8_t channel_number;
    uint8_t operating_bw_mhz;
    uint8_t primary_bw_mhz;
} edgez_mesh_channel_operation_t;

edgez_mesh_channel_parse_result_t edgez_mesh_channel_parse_operation(
    const uint8_t *ies, size_t ies_len,
    edgez_mesh_channel_operation_t *operation);

bool edgez_mesh_channel_rx_matches(uint32_t rx_hz, uint8_t rx_bw_mhz,
                                   uint32_t operating_hz,
                                   uint8_t operating_bw_mhz);

bool edgez_mesh_channel_matches_home(uint32_t operating_hz,
                                     uint8_t operating_bw_mhz,
                                     uint32_t home_hz,
                                     uint8_t home_bw_mhz);

/** Country-aware control-traffic pacing for the EU/UK sub-GHz profiles. */
bool edgez_mesh_country_uses_eu_duty_cycle(const char country_code[3]);
uint16_t edgez_mesh_country_beacon_interval_tu(
    const char country_code[3], uint16_t requested_interval_tu);
uint32_t edgez_mesh_country_control_interval_ms(
    const char country_code[3], uint32_t requested_interval_ms);
uint32_t edgez_mesh_control_liveness_timeout_ms(
    uint32_t control_interval_ms, uint32_t minimum_timeout_ms);
