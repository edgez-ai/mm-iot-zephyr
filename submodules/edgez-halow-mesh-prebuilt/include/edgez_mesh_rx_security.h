/* Copyright 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_RX_KEY_SLOTS 8U
#define EDGEZ_MESH_RX_KEY_MAX_LEN 32U
#define EDGEZ_MESH_RX_REPLAY_SPACES 2U
#define EDGEZ_MESH_MAC_LEN 6U

struct edgez_mesh_rx_key
{
    bool valid;
    uint8_t peer[EDGEZ_MESH_MAC_LEN];
    uint8_t key_id;
    size_t key_len;
    uint8_t key[EDGEZ_MESH_RX_KEY_MAX_LEN];
    uint64_t replay[EDGEZ_MESH_RX_REPLAY_SPACES];
};

struct edgez_mesh_rx_security
{
    struct edgez_mesh_rx_key keys[EDGEZ_MESH_RX_KEY_SLOTS];
    uint8_t next_replacement;
};

enum edgez_mesh_replay_result
{
    EDGEZ_MESH_REPLAY_ACCEPT = 0,
    EDGEZ_MESH_REPLAY_REJECT,
    EDGEZ_MESH_REPLAY_UNKNOWN_KEY,
    EDGEZ_MESH_REPLAY_INVALID,
};

void edgez_mesh_rx_security_init(struct edgez_mesh_rx_security *security);

bool edgez_mesh_rx_security_set_key(struct edgez_mesh_rx_security *security,
                                    const uint8_t peer[EDGEZ_MESH_MAC_LEN],
                                    uint8_t key_id, const uint8_t *key,
                                    size_t key_len);

void edgez_mesh_rx_security_remove_key(struct edgez_mesh_rx_security *security,
                                       const uint8_t peer[EDGEZ_MESH_MAC_LEN]);

const struct edgez_mesh_rx_key *edgez_mesh_rx_security_find_key(
    const struct edgez_mesh_rx_security *security,
    const uint8_t peer[EDGEZ_MESH_MAC_LEN], uint8_t key_id);

enum edgez_mesh_replay_result edgez_mesh_rx_security_check_replay(
    const struct edgez_mesh_rx_security *security,
    const uint8_t peer[EDGEZ_MESH_MAC_LEN], uint8_t key_id,
    uint8_t replay_space, uint64_t packet_number);

bool edgez_mesh_rx_security_commit_replay(
    struct edgez_mesh_rx_security *security,
    const uint8_t peer[EDGEZ_MESH_MAC_LEN], uint8_t key_id,
    uint8_t replay_space, uint64_t packet_number);

#ifdef __cplusplus
}
#endif
