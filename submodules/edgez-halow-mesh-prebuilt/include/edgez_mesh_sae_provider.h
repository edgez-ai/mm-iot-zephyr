/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include "edgez_umac_mesh_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_SAE_MAX_PASSWORD_LEN 63U
#define EDGEZ_MESH_SAE_MAX_MESH_ID_LEN 32U

/**
 * EdgeZ-owned SAE state machine backed only by the BSD hostap primitives.
 *
 * The private implementation is intentionally opaque here. The provider is
 * independent of wpa_supplicant, hostapd, and the Morse UMAC.
 */
struct edgez_mesh_sae_provider
{
    struct edgez_umac *umac;
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t bssid[EDGEZ_UMAC_MAC_LEN];
    uint8_t password[EDGEZ_MESH_SAE_MAX_PASSWORD_LEN + 1U];
    size_t password_length;
    uint8_t mesh_id[EDGEZ_MESH_SAE_MAX_MESH_ID_LEN];
    size_t mesh_id_length;
    uint16_t next_sequence_number;
    uint16_t next_data_sequence_number;
    uint32_t next_mesh_sequence_number;
    uintptr_t next_tx_token;
    uint8_t next_ba_dialog_token;
    uint8_t mcs;
    uint8_t attempts;
    uint8_t bandwidth_mhz;
    bool short_guard;
    void *private_lock;
    void *private_peers[EDGEZ_UMAC_MAX_PEERS];
};

struct edgez_mesh_sae_provider_config
{
    struct edgez_umac *umac;
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    uint8_t bssid[EDGEZ_UMAC_MAC_LEN];
    const uint8_t *password;
    size_t password_length;
    const uint8_t *mesh_id;
    size_t mesh_id_length;
    uint8_t mcs;
    uint8_t attempts;
    uint8_t bandwidth_mhz;
    bool short_guard;
};

int edgez_mesh_sae_provider_init(
    struct edgez_mesh_sae_provider *provider,
    const struct edgez_mesh_sae_provider_config *config);
void edgez_mesh_sae_provider_deinit(
    struct edgez_mesh_sae_provider *provider);
void edgez_mesh_sae_provider_set_local_address(
    struct edgez_mesh_sae_provider *provider,
    const uint8_t local_mac[EDGEZ_UMAC_MAC_LEN]);
struct edgez_umac_mesh_security_ops edgez_mesh_sae_provider_ops(void);

/**
 * Authenticate and decrypt one protected mesh data body with the peer MTK.
 * Replay state advances only after the CCMP MIC has been verified.
 */
int edgez_mesh_sae_provider_decrypt_data(
    struct edgez_mesh_sae_provider *provider,
    const struct edgez_mesh_rx_protected_data *frame,
    uint8_t *plaintext, size_t plaintext_capacity,
    size_t *plaintext_length, uint64_t *packet_number);

/**
 * Authenticate and decrypt one protected 802.11 management frame.
 *
 * The input contains the complete 24-byte management header followed by the
 * CCMP header, encrypted action body, and MIC. Replay state advances only
 * after the CCMP MIC has been verified.
 */
int edgez_mesh_sae_provider_decrypt_management(
    struct edgez_mesh_sae_provider *provider,
    const uint8_t *frame, size_t frame_length,
    uint8_t *plaintext, size_t plaintext_capacity,
    size_t *plaintext_length, uint64_t *packet_number,
    uint8_t *key_id);

/** Encrypt and submit a robust unicast mesh Action frame with the peer MTK. */
int edgez_mesh_sae_provider_transmit_action(
    struct edgez_mesh_sae_provider *provider,
    const uint8_t receiver[EDGEZ_UMAC_MAC_LEN],
    const uint8_t *action, size_t action_length);

/** Process a decrypted Block Ack action and transmit any required response. */
int edgez_mesh_sae_provider_receive_block_ack_action(
    struct edgez_mesh_sae_provider *provider,
    const uint8_t transmitter[EDGEZ_UMAC_MAC_LEN],
    const uint8_t *action, size_t action_length);

/** Build and submit one protected QoS mesh frame through the RF backend. */
int edgez_mesh_sae_provider_transmit_ethernet(
    struct edgez_mesh_sae_provider *provider,
    const uint8_t receiver[EDGEZ_UMAC_MAC_LEN],
    const uint8_t *ethernet_frame, size_t ethernet_length, uint8_t tid);

#ifdef __cplusplus
}
#endif
