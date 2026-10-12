/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_umac.h"

enum edgez_mesh_peering_state
{
    EDGEZ_PEERING_IDLE = 0,
    EDGEZ_PEERING_SAE_AUTHENTICATING,
    EDGEZ_PEERING_OPEN_SENT,
    EDGEZ_PEERING_OPEN_RECEIVED,
    EDGEZ_PEERING_CONFIRM_RECEIVED,
    EDGEZ_PEERING_ESTABLISHED,
    EDGEZ_PEERING_HOLDING,
};

enum edgez_mesh_peering_event
{
    EDGEZ_PEERING_EVENT_PEER_DISCOVERED = 0,
    EDGEZ_PEERING_EVENT_SAE_ACCEPTED,
    EDGEZ_PEERING_EVENT_SAE_REJECTED,
    EDGEZ_PEERING_EVENT_OPEN_RECEIVED,
    EDGEZ_PEERING_EVENT_CONFIRM_RECEIVED,
    EDGEZ_PEERING_EVENT_AMPE_SECURED,
    EDGEZ_PEERING_EVENT_AMPE_REJECTED,
    EDGEZ_PEERING_EVENT_OPERATION_FAILED,
    EDGEZ_PEERING_EVENT_CLOSE_RECEIVED,
    EDGEZ_PEERING_EVENT_RETRY_TIMEOUT,
    EDGEZ_PEERING_EVENT_HOLDING_TIMEOUT,
};

enum edgez_mesh_peering_action
{
    EDGEZ_PEERING_ACTION_NONE = 0,
    EDGEZ_PEERING_ACTION_START_SAE = 1U << 0,
    EDGEZ_PEERING_ACTION_SEND_OPEN = 1U << 1,
    EDGEZ_PEERING_ACTION_SEND_CONFIRM = 1U << 2,
    EDGEZ_PEERING_ACTION_AUTHORIZE = 1U << 3,
    EDGEZ_PEERING_ACTION_DEAUTHORIZE = 1U << 4,
    EDGEZ_PEERING_ACTION_SEND_CLOSE = 1U << 5,
    EDGEZ_PEERING_ACTION_REMOVE = 1U << 6,
};

struct edgez_mesh_peering
{
    uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN];
    enum edgez_mesh_peering_state state;
    uint16_t local_link_id;
    uint16_t peer_link_id;
    uint8_t retries;
    uint8_t max_retries;
    bool open_received;
    bool confirm_received;
    bool ampe_secured;
};

typedef int (*edgez_mesh_peering_operation_fn)(
    void *ctx, const struct edgez_mesh_peering *peering);

struct edgez_mesh_peering_ops
{
    edgez_mesh_peering_operation_fn start_sae;
    edgez_mesh_peering_operation_fn send_open;
    edgez_mesh_peering_operation_fn send_confirm;
    edgez_mesh_peering_operation_fn authorize;
    edgez_mesh_peering_operation_fn deauthorize;
    edgez_mesh_peering_operation_fn send_close;
    edgez_mesh_peering_operation_fn remove;
};

void edgez_mesh_peering_init(struct edgez_mesh_peering *peering,
                             const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
                             uint16_t local_link_id, uint8_t max_retries);
int edgez_mesh_peering_handle(struct edgez_mesh_peering *peering,
                              enum edgez_mesh_peering_event event,
                              uint16_t peer_link_id,
                              uint32_t *actions);
int edgez_mesh_peering_execute(const struct edgez_mesh_peering *peering,
                               uint32_t actions,
                               const struct edgez_mesh_peering_ops *ops,
                               void *ctx);
