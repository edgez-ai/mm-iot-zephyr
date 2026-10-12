/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_mesh_rx.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_PEERING_MGMT_EID 117U
#define EDGEZ_MESH_ID_EID 114U
#define EDGEZ_MESH_PMKID_LEN 16U
#define EDGEZ_MESH_ID_MAX_LEN 32U
#define EDGEZ_MESH_MPM_HEADER_LEN 24U

enum edgez_mesh_mpm_action
{
    EDGEZ_MESH_MPM_OPEN = 1,
    EDGEZ_MESH_MPM_CONFIRM = 2,
    EDGEZ_MESH_MPM_CLOSE = 3,
};

struct edgez_mesh_mpm_frame
{
    enum edgez_mesh_mpm_action action;
    uint16_t protocol_id;
    uint16_t local_link_id;
    uint16_t peer_link_id;
    uint16_t reason_code;
    const uint8_t *chosen_pmk;
    bool peer_link_id_present;
    bool reason_code_present;
};

/**
 * Inputs for a raw Mesh Peering Management action frame.
 *
 * The optional IE blocks are already encoded as complete 802.11 information
 * elements. They let a platform-independent SAE/AMPE provider inject RSN,
 * capability, AMPE, and MIC elements without coupling this encoder to it.
 */
struct edgez_mesh_mpm_tx_config
{
    enum edgez_mesh_mpm_action action;
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t peer_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t bssid[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    uint16_t capability;
    uint16_t aid;
    uint16_t protocol_id;
    uint16_t local_link_id;
    uint16_t peer_link_id;
    uint16_t reason_code;
    const uint8_t *mesh_id;
    size_t mesh_id_length;
    const uint8_t *pre_mpm_ies;
    size_t pre_mpm_ies_length;
    const uint8_t *mesh_id_following_ies;
    size_t mesh_id_following_ies_length;
    const uint8_t *chosen_pmk;
    const uint8_t *post_mpm_ies;
    size_t post_mpm_ies_length;
    bool protected_frame;
};

/** Decode the standard Mesh Peering Management element from an action frame. */
int edgez_mesh_mpm_parse(const struct edgez_mesh_rx_peering_action *action,
                         struct edgez_mesh_mpm_frame *output);

/** Encode a complete raw 802.11 Mesh Peering Management action frame. */
int edgez_mesh_mpm_encode(uint8_t *output, size_t output_capacity,
                          const struct edgez_mesh_mpm_tx_config *config,
                          size_t *encoded_length);

#ifdef __cplusplus
}
#endif
