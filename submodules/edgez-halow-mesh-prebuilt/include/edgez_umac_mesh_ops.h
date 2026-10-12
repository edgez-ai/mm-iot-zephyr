/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_mpm.h"
#include "edgez_mesh_peering.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_UMAC_MESH_MAX_IE_BYTES 256U
#define EDGEZ_UMAC_MESH_MAX_FRAME_BYTES 768U

struct edgez_umac_mesh_security_material
{
    uint8_t chosen_pmk[EDGEZ_MESH_PMKID_LEN];
    uint8_t pre_mpm_ies[EDGEZ_UMAC_MESH_MAX_IE_BYTES];
    size_t pre_mpm_ies_length;
    uint8_t mesh_id_following_ies[EDGEZ_UMAC_MESH_MAX_IE_BYTES];
    size_t mesh_id_following_ies_length;
    uint8_t post_mpm_ies[EDGEZ_UMAC_MESH_MAX_IE_BYTES];
    size_t post_mpm_ies_length;
    uint8_t key_index;
    bool chosen_pmk_present;
    bool protected_frame;
    bool hardware_encrypt;
};

typedef int (*edgez_umac_mesh_start_sae_fn)(
    void *ctx, const struct edgez_mesh_peering *peering);
typedef int (*edgez_umac_mesh_prepare_security_fn)(
    void *ctx, const struct edgez_mesh_peering *peering,
    enum edgez_mesh_mpm_action action,
    struct edgez_umac_mesh_security_material *material);

struct edgez_umac_mesh_ops_config
{
    struct edgez_umac *umac;
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t bssid[EDGEZ_UMAC_MAC_LEN];
    uint8_t mesh_id[EDGEZ_MESH_ID_MAX_LEN];
    size_t mesh_id_length;
    uint16_t capability;
    uint16_t close_reason_code;
    uint8_t mcs;
    uint8_t attempts;
    uint8_t bandwidth_mhz;
    bool short_guard;
    bool secure;
    edgez_umac_mesh_start_sae_fn start_sae;
    edgez_umac_mesh_prepare_security_fn prepare_security;
    void *security_ctx;
};

/**
 * Concrete private-UMAC operations for the peering state machine.
 *
 * SAE/AMPE calculation remains injectable, but peer lifecycle, MPM framing,
 * raw management transmission, and authorization are owned by edgez-halow-mesh.
 */
struct edgez_umac_mesh_ops
{
    struct edgez_umac_mesh_ops_config config;
    struct edgez_mesh_peering_ops peering_ops;
    uint16_t next_sequence_number;
    uintptr_t next_tx_token;
};

int edgez_umac_mesh_ops_init(
    struct edgez_umac_mesh_ops *operations,
    const struct edgez_umac_mesh_ops_config *config);
const struct edgez_mesh_peering_ops *edgez_umac_mesh_ops_get(
    const struct edgez_umac_mesh_ops *operations);

#ifdef __cplusplus
}
#endif
