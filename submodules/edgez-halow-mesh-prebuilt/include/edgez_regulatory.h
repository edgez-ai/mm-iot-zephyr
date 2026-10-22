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

/** Portable representation of one resolved Morse regulatory rule.
 * Duty-cycle values are hundredths of one percent; all airtime values are us. */
struct edgez_regulatory_policy {
    char country_code[3];
    uint32_t start_frequency_khz;
    uint32_t end_frequency_khz;
    uint32_t max_bandwidth_khz;
    int16_t max_antenna_gain_dbi;
    int8_t max_eirp_dbm;
    bool auto_bandwidth;
    uint16_t duty_cycle_ap_centi_percent;
    uint16_t duty_cycle_sta_centi_percent;
    bool duty_cycle_omit_control_response;
    uint32_t airtime_min_us;
    uint32_t airtime_max_us;
    uint32_t window_length_us;
};

typedef bool (*edgez_regulatory_resolve_fn)(
    void *ctx, const char country_code[3], uint32_t frequency_khz,
    uint32_t bandwidth_khz, struct edgez_regulatory_policy *policy);

/** Provider boundary for a platform-owned authoritative regulatory database.
 * The EdgeZ core deliberately does not ship or reinterpret a country table. */
struct edgez_regulatory_provider {
    edgez_regulatory_resolve_fn resolve;
    void *ctx;
};

bool edgez_regulatory_resolve(
    const struct edgez_regulatory_provider *provider,
    const char country_code[3], uint32_t frequency_khz,
    uint32_t bandwidth_khz, struct edgez_regulatory_policy *policy);

#ifdef __cplusplus
}
#endif
