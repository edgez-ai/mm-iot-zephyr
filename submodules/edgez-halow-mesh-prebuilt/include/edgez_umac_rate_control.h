/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct edgez_umac_rate_config
{
    bool enabled;
    uint8_t initial_mcs;
    uint8_t maximum_mcs;
    uint8_t successes_to_increase;
};

struct edgez_umac_rate_control
{
    struct edgez_umac_rate_config config;
    uint8_t current_mcs;
    uint8_t consecutive_successes;
    uint32_t successful_frames;
    uint32_t retried_frames;
    uint32_t failed_frames;
};

bool edgez_umac_rate_config_valid(
    const struct edgez_umac_rate_config *config);
void edgez_umac_rate_control_init(
    struct edgez_umac_rate_control *control,
    const struct edgez_umac_rate_config *config);
uint8_t edgez_umac_rate_control_select(
    const struct edgez_umac_rate_control *control);
void edgez_umac_rate_control_feedback(
    struct edgez_umac_rate_control *control, uint8_t attempts, bool failed);

#ifdef __cplusplus
}
#endif
