/* Copyright 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_MESH_BA_TID_COUNT 8U
#define EDGEZ_MESH_BA_DEFAULT_WINDOW 16U
#define EDGEZ_MESH_BA_ACTION_MAX_LEN 9U

enum edgez_mesh_ba_status
{
    EDGEZ_MESH_BA_DISABLED = 0,
    EDGEZ_MESH_BA_REQUESTED,
    EDGEZ_MESH_BA_REFUSED,
    EDGEZ_MESH_BA_ESTABLISHED,
};

struct edgez_mesh_ba_session
{
    enum edgez_mesh_ba_status status;
    uint32_t request_timestamp_ms;
    uint32_t retry_delay_ms;
    uint16_t starting_sequence_control;
    uint16_t timeout_tu;
    uint16_t window_size;
    uint8_t dialog_token;
};

struct edgez_mesh_block_ack
{
    struct edgez_mesh_ba_session originator[EDGEZ_MESH_BA_TID_COUNT];
    struct edgez_mesh_ba_session recipient[EDGEZ_MESH_BA_TID_COUNT];
    uint16_t local_window_size;
};

void edgez_mesh_block_ack_init(struct edgez_mesh_block_ack *block_ack,
                               uint16_t local_window_size);

/**
 * Produce the next originator control action, if one is required.
 *
 * A fresh TID produces an ADDBA request. A timed-out request first produces
 * DELBA; the following call starts a new request with exponential backoff.
 */
size_t edgez_mesh_block_ack_prepare_tx(
    struct edgez_mesh_block_ack *block_ack, uint8_t tid,
    uint16_t starting_sequence_control, uint8_t dialog_token,
    uint32_t now_ms, uint8_t *action, size_t action_capacity);

/** Process one complete Block Ack action body and optionally build a reply. */
int edgez_mesh_block_ack_process_action(
    struct edgez_mesh_block_ack *block_ack, const uint8_t *action,
    size_t action_length, uint32_t now_ms, uint8_t *response,
    size_t response_capacity, size_t *response_length);

bool edgez_mesh_block_ack_tx_permitted(
    const struct edgez_mesh_block_ack *block_ack, uint8_t tid);
uint8_t edgez_mesh_block_ack_rx_window(
    const struct edgez_mesh_block_ack *block_ack, uint8_t tid);

#ifdef __cplusplus
}
#endif
