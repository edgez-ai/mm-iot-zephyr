/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_rx.h"

#ifdef __cplusplus
extern "C" {
#endif

struct edgez_umac_rx_pipeline_ops
{
    int (*data)(void *ctx, const struct edgez_umac_rx_frame *radio,
                const struct edgez_mesh_rx_data *frame);
    int (*protected_data)(
        void *ctx, const struct edgez_umac_rx_frame *radio,
        const struct edgez_mesh_rx_protected_data *frame);
    int (*qos_null)(void *ctx, const struct edgez_umac_rx_frame *radio,
                    const struct edgez_mesh_rx_qos_null *frame);
    int (*beacon)(void *ctx, const struct edgez_umac_rx_frame *radio,
                  const struct edgez_mesh_rx_management *frame);
    int (*authentication)(
        void *ctx, const struct edgez_umac_rx_frame *radio,
        const struct edgez_mesh_rx_authentication *frame);
    int (*peering_action)(
        void *ctx, const struct edgez_umac_rx_frame *radio,
        const struct edgez_mesh_rx_peering_action *frame);
    int (*unsupported)(void *ctx, const struct edgez_umac_rx_frame *radio);
};

struct edgez_umac_rx_pipeline_metrics
{
    uint32_t received;
    uint32_t data;
    uint32_t protected_data;
    uint32_t qos_null;
    uint32_t beacons;
    uint32_t authentications;
    uint32_t peering_actions;
    uint32_t unsupported;
    uint32_t malformed;
    uint32_t handler_failures;
};

struct edgez_umac_rx_pipeline
{
    struct edgez_umac_rx_pipeline_ops operations;
    void *operation_ctx;
    struct edgez_umac_rx_pipeline_metrics metrics;
};

int edgez_umac_rx_pipeline_init(
    struct edgez_umac_rx_pipeline *pipeline,
    const struct edgez_umac_rx_pipeline_ops *operations,
    void *operation_ctx);
int edgez_umac_rx_pipeline_dispatch(
    struct edgez_umac_rx_pipeline *pipeline,
    const struct edgez_umac_rx_frame *radio_frame);

/** Adapter for edgez_umac_event_ops.rx_frame. */
void edgez_umac_rx_pipeline_event(
    void *pipeline_ctx, const struct edgez_umac_rx_frame *radio_frame);

#ifdef __cplusplus
}
#endif
