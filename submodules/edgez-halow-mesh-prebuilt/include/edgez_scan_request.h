/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once
#include <stdbool.h>
#include <stdatomic.h>

/* enqueue returns zero on successful queueing. Completion/abort callbacks
 * clear busy independently, possibly before enqueue returns. */
static inline int edgez_scan_submit(atomic_bool *busy,
                                     int (*enqueue)(void *), void *ctx,
                                     int busy_status)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(busy, &expected, true)) return busy_status;
    int status = enqueue(ctx);
    if (status != 0) atomic_store(busy, false);
    return status;
}
