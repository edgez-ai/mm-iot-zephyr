/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_mesh_rx.h"

enum edgez_mesh_mgmt_disposition
{
    EDGEZ_MESH_MGMT_PASS = 0,
    EDGEZ_MESH_MGMT_CONSUMED,
    EDGEZ_MESH_MGMT_DROP,
};

typedef int (*edgez_mesh_mgmt_handler_fn)(
    void *ctx, enum edgez_mesh_rx_kind kind,
    const uint8_t *frame, size_t length);

struct edgez_mesh_mgmt_gate_metrics
{
    uint32_t observed;
    uint32_t passed;
    uint32_t consumed;
    uint32_t dropped;
    uint32_t handler_failures;
};

struct edgez_mesh_mgmt_gate
{
    edgez_mesh_mgmt_handler_fn handler;
    void *handler_ctx;
    struct edgez_mesh_mgmt_gate_metrics metrics;
    bool authoritative;
};

int edgez_mesh_mgmt_gate_init(
    struct edgez_mesh_mgmt_gate *gate,
    edgez_mesh_mgmt_handler_fn handler, void *handler_ctx,
    bool authoritative);
enum edgez_mesh_mgmt_disposition edgez_mesh_mgmt_gate_route(
    struct edgez_mesh_mgmt_gate *gate,
    const uint8_t *frame, size_t length);

