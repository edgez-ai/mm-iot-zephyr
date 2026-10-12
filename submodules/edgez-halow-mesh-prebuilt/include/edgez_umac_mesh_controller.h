/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_mpm.h"
#include "edgez_mesh_peering_manager.h"
#include "edgez_umac_rx_pipeline.h"

#ifdef __cplusplus
extern "C" {
#endif

enum edgez_mesh_security_result
{
    EDGEZ_MESH_SECURITY_PENDING = 0,
    EDGEZ_MESH_SECURITY_ACCEPTED,
    EDGEZ_MESH_SECURITY_REJECTED,
};

typedef enum edgez_mesh_security_result (*edgez_mesh_sae_rx_fn)(
    void *ctx, const struct edgez_mesh_rx_authentication *frame);
typedef enum edgez_mesh_security_result (*edgez_mesh_ampe_rx_fn)(
    void *ctx, const struct edgez_mesh_rx_peering_action *action,
    const struct edgez_mesh_mpm_frame *mpm);

struct edgez_umac_mesh_controller_config
{
    struct edgez_mesh_peering_manager *peering_manager;
    edgez_mesh_sae_rx_fn sae_rx;
    edgez_mesh_ampe_rx_fn ampe_rx;
    void *security_ctx;
    bool secure;
};

struct edgez_umac_mesh_controller_metrics
{
    uint32_t discoveries;
    uint32_t authentication_frames;
    uint32_t peering_frames;
    uint32_t malformed_peering_frames;
    uint32_t rejected_security_frames;
    uint32_t state_errors;
};

struct edgez_umac_mesh_controller
{
    struct edgez_umac_mesh_controller_config config;
    struct edgez_umac_mesh_controller_metrics metrics;
};

int edgez_umac_mesh_controller_init(
    struct edgez_umac_mesh_controller *controller,
    const struct edgez_umac_mesh_controller_config *config);
int edgez_umac_mesh_controller_discover(
    struct edgez_umac_mesh_controller *controller,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN], uint32_t now_ms);

/** Functions compatible with edgez_umac_rx_pipeline_ops. */
int edgez_umac_mesh_controller_authentication(
    void *controller_ctx, const struct edgez_umac_rx_frame *radio,
    const struct edgez_mesh_rx_authentication *frame);
int edgez_umac_mesh_controller_peering_action(
    void *controller_ctx, const struct edgez_umac_rx_frame *radio,
    const struct edgez_mesh_rx_peering_action *frame);

#ifdef __cplusplus
}
#endif
