/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_HWMP_MAC_LEN 6U
#define EDGEZ_MESH_HWMP_PREQ_ACTION_LEN 41U
#define EDGEZ_MESH_HWMP_PREP_ACTION_LEN 35U
#define EDGEZ_MESH_HWMP_MAX_ACTION_LEN EDGEZ_MESH_HWMP_PREQ_ACTION_LEN

struct edgez_mesh_hwmp_state
{
    uint32_t own_sequence;
    uint32_t next_preq_id;
};

struct edgez_mesh_hwmp_reply
{
    uint8_t next_hop[EDGEZ_MESH_HWMP_MAC_LEN];
    uint8_t local_address[EDGEZ_MESH_HWMP_MAC_LEN];
    uint8_t originator[EDGEZ_MESH_HWMP_MAC_LEN];
    uint32_t target_sequence;
    uint32_t originator_sequence;
    uint32_t lifetime;
};

void edgez_mesh_hwmp_init(struct edgez_mesh_hwmp_state *state);

size_t edgez_mesh_hwmp_next_preq_action(
    struct edgez_mesh_hwmp_state *state,
    const uint8_t local_address[EDGEZ_MESH_HWMP_MAC_LEN],
    uint8_t *action, size_t capacity);

bool edgez_mesh_hwmp_process_action(
    struct edgez_mesh_hwmp_state *state,
    const uint8_t local_address[EDGEZ_MESH_HWMP_MAC_LEN],
    const uint8_t transmitter[EDGEZ_MESH_HWMP_MAC_LEN],
    const uint8_t *action, size_t action_len,
    struct edgez_mesh_hwmp_reply *reply);

size_t edgez_mesh_hwmp_build_prep_action(
    const struct edgez_mesh_hwmp_reply *reply,
    uint8_t *action, size_t capacity);

#ifdef __cplusplus
}
#endif
