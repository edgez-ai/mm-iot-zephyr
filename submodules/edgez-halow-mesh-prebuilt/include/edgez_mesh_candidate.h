/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_CANDIDATE_CAPACITY 4U
#define EDGEZ_MESH_CANDIDATE_IE_MAX_LEN 256U

struct edgez_mesh_candidate
{
    bool valid;
    bool replay_scheduled;
    bool observed_on_mesh_channel;
    uint8_t bssid[6];
    uint16_t ies_len;
    uint8_t ies[EDGEZ_MESH_CANDIDATE_IE_MAX_LEN];
};

struct edgez_mesh_candidate_table
{
    struct edgez_mesh_candidate entries[EDGEZ_MESH_CANDIDATE_CAPACITY];
};

void edgez_mesh_candidate_table_init(struct edgez_mesh_candidate_table *table);

bool edgez_mesh_candidate_cache(struct edgez_mesh_candidate_table *table,
                                const uint8_t bssid[6],
                                const uint8_t *ies, size_t ies_len,
                                const uint8_t *mesh_id, size_t mesh_id_len,
                                bool observed_on_mesh_channel,
                                uint8_t *slot_out);

bool edgez_mesh_candidate_recover(struct edgez_mesh_candidate_table *table,
                                  const uint8_t peer_addr[6],
                                  const uint8_t *mesh_id, size_t mesh_id_len,
                                  uint8_t *slot_out);

bool edgez_mesh_candidate_get(const struct edgez_mesh_candidate_table *table,
                              uint8_t slot,
                              struct edgez_mesh_candidate *candidate_out);

const struct edgez_mesh_candidate *edgez_mesh_candidate_peek(
    const struct edgez_mesh_candidate_table *table, uint8_t slot);

bool edgez_mesh_candidate_set_scheduled(
    struct edgez_mesh_candidate_table *table, uint8_t slot, bool scheduled);

void edgez_mesh_candidate_remove(struct edgez_mesh_candidate_table *table,
                                 uint8_t slot);

#ifdef __cplusplus
}
#endif
