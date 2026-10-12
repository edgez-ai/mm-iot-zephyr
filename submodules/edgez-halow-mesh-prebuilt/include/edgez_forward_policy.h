/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Portable policy shared by the ESP-IDF worker and deterministic host tests.
 * Only a failure before successful enqueue may be classified as RETRY. */
typedef enum {
    EDGEZ_FORWARD_OK,
    EDGEZ_FORWARD_RETRY,
    EDGEZ_FORWARD_FAILED,
    EDGEZ_FORWARD_UNAUTHORIZED,
} edgez_forward_status_t;

typedef struct {
    edgez_forward_status_t status;
    unsigned attempts;
    unsigned retries;
} edgez_forward_result_t;

static inline edgez_forward_result_t edgez_forward_run(
    void *ctx, bool (*authorized)(void *),
    edgez_forward_status_t (*send)(void *),
    void (*backoff)(void *, uint32_t))
{
    edgez_forward_result_t result = {EDGEZ_FORWARD_UNAUTHORIZED, 0, 0};
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        if (!authorized(ctx)) {
            result.status = EDGEZ_FORWARD_UNAUTHORIZED;
            break;
        }
        ++result.attempts;
        result.status = send(ctx);
        if (result.status != EDGEZ_FORWARD_RETRY || attempt == 2) break;
        ++result.retries;
        backoff(ctx, 10U * (attempt + 1U));
    }
    return result;
}
