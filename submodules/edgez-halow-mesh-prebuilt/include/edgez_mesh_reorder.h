/* Copyright 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum edgez_mesh_reorder_action
{
    EDGEZ_MESH_REORDER_DELIVER = 0,
    EDGEZ_MESH_REORDER_QUEUE,
    EDGEZ_MESH_REORDER_DROP_OUTDATED,
};

bool edgez_mesh_sequence_before(uint16_t sequence_control_a,
                                uint16_t sequence_control_b);

enum edgez_mesh_reorder_action edgez_mesh_reorder_classify(
    uint16_t sequence_control, uint16_t expected_sequence_control);

bool edgez_mesh_reorder_release_head(uint16_t head_sequence_control,
                                     bool expected_is_valid,
                                     uint16_t expected_sequence_control,
                                     bool timed_out);

#ifdef __cplusplus
}
#endif
