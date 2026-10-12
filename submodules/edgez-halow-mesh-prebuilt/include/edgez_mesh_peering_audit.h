/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_mesh_peering.h"

#define EDGEZ_PEERING_ACTION_COUNT 7U

struct edgez_mesh_peering_audit_slot
{
    uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN];
    uint8_t expected[EDGEZ_PEERING_ACTION_COUNT];
    uint8_t observed[EDGEZ_PEERING_ACTION_COUNT];
    bool in_use;
};

struct edgez_mesh_peering_audit_metrics
{
    uint32_t expected;
    uint32_t observed;
    uint32_t matched;
    uint32_t missing;
    uint32_t unexpected;
    uint32_t capacity_rejections;
};

struct edgez_mesh_peering_audit
{
    struct edgez_mesh_peering_audit_slot slots[EDGEZ_UMAC_MAX_PEERS];
    struct edgez_mesh_peering_audit_metrics metrics;
};

void edgez_mesh_peering_audit_init(struct edgez_mesh_peering_audit *audit);
int edgez_mesh_peering_audit_expect(
    struct edgez_mesh_peering_audit *audit,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN], uint32_t actions);
int edgez_mesh_peering_audit_observe(
    struct edgez_mesh_peering_audit *audit,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN], uint32_t action);
int edgez_mesh_peering_audit_checkpoint(
    struct edgez_mesh_peering_audit *audit,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN], bool forget_peer);
void edgez_mesh_peering_audit_snapshot(
    const struct edgez_mesh_peering_audit *audit,
    struct edgez_mesh_peering_audit_metrics *metrics);
