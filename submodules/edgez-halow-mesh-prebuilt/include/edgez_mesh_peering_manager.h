/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_mesh_peering.h"

enum edgez_mesh_peering_timer_kind
{
    EDGEZ_PEERING_TIMER_NONE = 0,
    EDGEZ_PEERING_TIMER_SAE,
    EDGEZ_PEERING_TIMER_RETRY,
    EDGEZ_PEERING_TIMER_CONFIRM,
    EDGEZ_PEERING_TIMER_HOLDING,
};

struct edgez_mesh_peering_manager_config
{
    uint32_t sae_timeout_ms;
    uint32_t retry_timeout_ms;
    uint32_t confirm_timeout_ms;
    uint32_t holding_timeout_ms;
    uint8_t max_retries;
    bool execute_actions;
};

struct edgez_mesh_peering_slot
{
    struct edgez_mesh_peering peering;
    enum edgez_mesh_peering_timer_kind timer_kind;
    uint32_t deadline_ms;
    bool in_use;
};

struct edgez_mesh_peering_manager
{
    struct edgez_mesh_peering_manager_config config;
    struct edgez_mesh_peering_ops operations;
    void *operation_ctx;
    struct edgez_mesh_peering_slot slots[EDGEZ_UMAC_MAX_PEERS];
    uint16_t next_link_id;
    uint32_t transitions;
    uint32_t timer_expirations;
    uint32_t operation_failures;
    uint32_t capacity_rejections;
};

typedef void (*edgez_mesh_peering_timeout_observer_fn)(
    void *ctx, const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
    uint32_t actions, int result);

int edgez_mesh_peering_manager_init(
    struct edgez_mesh_peering_manager *manager,
    const struct edgez_mesh_peering_manager_config *config,
    const struct edgez_mesh_peering_ops *operations,
    void *operation_ctx);
int edgez_mesh_peering_manager_event(
    struct edgez_mesh_peering_manager *manager,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
    enum edgez_mesh_peering_event event, uint16_t local_link_id,
    uint16_t peer_link_id, uint32_t now_ms, uint32_t *actions);
void edgez_mesh_peering_manager_tick(
    struct edgez_mesh_peering_manager *manager, uint32_t now_ms);
void edgez_mesh_peering_manager_tick_observed(
    struct edgez_mesh_peering_manager *manager, uint32_t now_ms,
    edgez_mesh_peering_timeout_observer_fn observer, void *observer_ctx);
int edgez_mesh_peering_manager_next_timeout(
    const struct edgez_mesh_peering_manager *manager, uint32_t now_ms,
    uint32_t *delay_ms);
const struct edgez_mesh_peering_slot *edgez_mesh_peering_manager_find(
    const struct edgez_mesh_peering_manager *manager,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN]);
int edgez_mesh_peering_manager_forget(
    struct edgez_mesh_peering_manager *manager,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN]);
