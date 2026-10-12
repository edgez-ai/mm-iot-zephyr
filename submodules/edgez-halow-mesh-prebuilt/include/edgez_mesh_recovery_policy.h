/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define EDGEZ_MESH_ADDR_LEN 6U

typedef struct {
    uint8_t addr[EDGEZ_MESH_ADDR_LEN];
    uint32_t retry_after_ms;
    bool valid;
} edgez_mesh_recovery_peer_t;

typedef struct {
    edgez_mesh_recovery_peer_t *peers;
    size_t peer_capacity;
    uint32_t cooldown_ms;
} edgez_mesh_recovery_policy_t;

typedef struct {
    uint8_t transmitter[EDGEZ_MESH_ADDR_LEN];
    uint32_t now_ms;
    bool mesh_mode;
    bool protected_frame;
    bool data_frame;
    bool multicast_transmitter;
} edgez_mesh_unknown_peer_t;

/* Returns true when the SDK should recreate supplicant state for the peer.
 * The caller supplies fixed storage so the policy performs no allocation. */
static inline bool edgez_mesh_should_recover_unknown_peer(
    edgez_mesh_recovery_policy_t *policy,
    const edgez_mesh_unknown_peer_t *event)
{
    if (policy == NULL || event == NULL || policy->peers == NULL ||
        policy->peer_capacity == 0U || !event->mesh_mode ||
        !event->protected_frame || !event->data_frame ||
        event->multicast_transmitter) {
        return false;
    }

    size_t slot = 0U;
    for (size_t i = 0U; i < policy->peer_capacity; ++i) {
        edgez_mesh_recovery_peer_t *peer = &policy->peers[i];
        if (peer->valid &&
            memcmp(peer->addr, event->transmitter, EDGEZ_MESH_ADDR_LEN) == 0) {
            if ((int32_t)(event->now_ms - peer->retry_after_ms) < 0) {
                return false;
            }
            slot = i;
            break;
        }
        if (!peer->valid) {
            slot = i;
            break;
        }
        if ((int32_t)(peer->retry_after_ms -
                      policy->peers[slot].retry_after_ms) < 0) {
            slot = i;
        }
    }

    edgez_mesh_recovery_peer_t *selected = &policy->peers[slot];
    selected->valid = true;
    memcpy(selected->addr, event->transmitter, EDGEZ_MESH_ADDR_LEN);
    selected->retry_after_ms = event->now_ms + policy->cooldown_ms;
    return true;
}

