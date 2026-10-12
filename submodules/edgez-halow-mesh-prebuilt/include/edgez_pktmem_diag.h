/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return transmit-packet capacity reported by the active RF backend. */
uint32_t edgez_rf_tx_packet_free_count(void);
uint32_t edgez_rf_tx_packet_total_count(void);

#ifdef __cplusplus
}
#endif
