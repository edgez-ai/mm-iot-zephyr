/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

/* Tick deadlines must be less than INT32_MAX ticks into the future. CAS
 * prevents a shorter concurrent request from overwriting a longer hold. */
static inline void edgez_scan_defer(atomic_uint_least32_t *deadline,
                                      uint32_t now, uint32_t duration)
{
    uint_least32_t current = atomic_load(deadline);
    const uint_least32_t proposed = now + duration;
    while (((int32_t)(current - now) <= 0 ||
            (int32_t)(proposed - current) > 0) &&
           !atomic_compare_exchange_weak(deadline, &current, proposed)) {}
}

static inline bool edgez_scan_held(uint32_t now, uint32_t deadline,
                                    unsigned authorized_peers)
{
    return authorized_peers != 0 || (int32_t)(deadline - now) > 0;
}
