/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_candidate.h"
#include "edgez_mesh_recovery_policy.h"
#include "edgez_umac_mesh_controller.h"
#include "edgez_umac_mesh_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_UMAC_MESH_BEACON_MAX_BYTES 384U

struct edgez_umac_mesh_runtime;

struct edgez_umac_mesh_security_ops
{
    int (*start_sae)(void *ctx, const struct edgez_mesh_peering *peering);
    enum edgez_mesh_security_result (*receive_sae)(
        void *ctx, const struct edgez_mesh_rx_authentication *frame);
    enum edgez_mesh_security_result (*receive_ampe)(
        void *ctx, const struct edgez_mesh_rx_peering_action *action,
        const struct edgez_mesh_mpm_frame *mpm);
    int (*prepare_mpm)(
        void *ctx, const struct edgez_mesh_peering *peering,
        enum edgez_mesh_mpm_action action,
        struct edgez_umac_mesh_security_material *material);
};

struct edgez_umac_mesh_runtime_events
{
    int (*data)(void *ctx, const struct edgez_umac_rx_frame *radio,
                const struct edgez_mesh_rx_data *frame);
    int (*protected_data)(
        void *ctx, const struct edgez_umac_rx_frame *radio,
        const struct edgez_mesh_rx_protected_data *frame);
    int (*qos_null)(void *ctx, const struct edgez_umac_rx_frame *radio,
                    const struct edgez_mesh_rx_qos_null *frame);
    int (*unsupported)(void *ctx, const struct edgez_umac_rx_frame *radio);
    void (*tx_status)(void *ctx, const struct edgez_umac_tx_status *status);
    void (*tx_pause_changed)(void *ctx, uint16_t source_mask, bool paused);
    void (*hardware_restart_required)(void *ctx);
    void (*scan_complete)(void *ctx, int driver_scan_status);
};

struct edgez_umac_mesh_runtime_config
{
    const struct edgez_rf_backend_ops *radio;
    void *radio_ctx;
    char country_code[3];
    struct edgez_umac_channel channel;
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t mesh_id[EDGEZ_MESH_ID_MAX_LEN];
    size_t mesh_id_length;
    uint16_t beacon_interval_tu;
    uint8_t dtim_period;
    uint32_t compressed_ssid;
    uint8_t mcs;
    uint8_t attempts;
    bool short_guard;
    struct edgez_umac_rate_config rate_control;
    bool secure;
    struct edgez_umac_mesh_security_ops security;
    void *security_ctx;
    struct edgez_umac_mesh_runtime_events events;
    void *event_ctx;
};

struct edgez_umac_mesh_runtime
{
    struct edgez_umac_mesh_runtime_config config;
    struct edgez_umac umac;
    struct edgez_umac_radio_info radio_info;
    struct edgez_umac_rx_pipeline rx_pipeline;
    struct edgez_umac_mesh_ops mesh_ops;
    struct edgez_mesh_peering_manager peering_manager;
    struct edgez_umac_mesh_controller controller;
    struct edgez_mesh_candidate_table candidates;
    edgez_mesh_recovery_peer_t recovery_peers[EDGEZ_UMAC_MAX_PEERS];
    edgez_mesh_recovery_policy_t recovery_policy;
    uint32_t recovery_restarts;
    uint8_t beacon[EDGEZ_UMAC_MESH_BEACON_MAX_BYTES];
    size_t beacon_length;
    bool initialized;
    bool running;
};

/**
 * Initialize the private UMAC without starting the radio.
 *
 * This two-phase API lets a vendor adapter connect its RF event source to
 * runtime.umac before edgez_umac_mesh_runtime_start() enables the radio.
 */
int edgez_umac_mesh_runtime_init(
    struct edgez_umac_mesh_runtime *runtime,
    const struct edgez_umac_mesh_runtime_config *config);

int edgez_umac_mesh_runtime_start(struct edgez_umac_mesh_runtime *runtime);
int edgez_umac_mesh_runtime_stop(struct edgez_umac_mesh_runtime *runtime);
void edgez_umac_mesh_runtime_tick(struct edgez_umac_mesh_runtime *runtime,
                                  uint32_t now_ms);

#ifdef __cplusplus
}
#endif
