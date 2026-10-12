/* Copyright (c) 2026 EdgeZeron AI AB. All rights reserved. */
#pragma once

#include "edgez_mesh_control.h"

#include <stdbool.h>

enum edgez_mesh_rx_kind
{
    EDGEZ_MESH_RX_UNSUPPORTED = 0,
    EDGEZ_MESH_RX_DATA,
    EDGEZ_MESH_RX_PROTECTED_DATA,
    EDGEZ_MESH_RX_QOS_NULL,
    EDGEZ_MESH_RX_BEACON,
    EDGEZ_MESH_RX_AUTHENTICATION,
    EDGEZ_MESH_RX_PEERING_ACTION,
};

/** Four-address QoS Null frame used by a mesh peer as a link keepalive. */
struct edgez_mesh_rx_qos_null
{
    uint8_t receiver[EDGEZ_UMAC_MAC_LEN];
    uint8_t transmitter[EDGEZ_UMAC_MAC_LEN];
    uint8_t address3[EDGEZ_UMAC_MAC_LEN];
    uint8_t address4[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    uint8_t tid;
    bool end_of_service_period;
    bool protected_frame;
};

/** Header information available before CCMP decryption. */
struct edgez_mesh_rx_protected_data
{
    uint8_t receiver[EDGEZ_UMAC_MAC_LEN];
    uint8_t transmitter[EDGEZ_UMAC_MAC_LEN];
    uint8_t destination[EDGEZ_UMAC_MAC_LEN];
    uint8_t source[EDGEZ_UMAC_MAC_LEN];
    uint8_t address3[EDGEZ_UMAC_MAC_LEN];
    uint8_t address4[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    uint8_t tid;
    bool has_address4;
    bool mesh_control_present;
    const uint8_t *mac_header;
    size_t mac_header_length;
    const uint8_t *ccmp_body;
    size_t ccmp_body_length;
};

struct edgez_mesh_rx_data
{
    uint8_t receiver[EDGEZ_UMAC_MAC_LEN];
    uint8_t transmitter[EDGEZ_UMAC_MAC_LEN];
    uint8_t destination[EDGEZ_UMAC_MAC_LEN];
    uint8_t source[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    uint8_t tid;
    bool protected_frame;
    struct edgez_mesh_control mesh_control;
    const uint8_t *payload;
    size_t payload_length;
};

struct edgez_mesh_rx_management
{
    uint8_t receiver[EDGEZ_UMAC_MAC_LEN];
    uint8_t transmitter[EDGEZ_UMAC_MAC_LEN];
    uint8_t bssid[EDGEZ_UMAC_MAC_LEN];
    uint16_t sequence_number;
    bool protected_frame;
    bool s1g_beacon;
    const uint8_t *body;
    size_t body_length;
    const uint8_t *ies;
    size_t ies_length;
};

struct edgez_mesh_rx_authentication
{
    struct edgez_mesh_rx_management management;
    uint16_t algorithm;
    uint16_t transaction;
    uint16_t status_code;
    const uint8_t *payload;
    size_t payload_length;
};

struct edgez_mesh_rx_peering_action
{
    struct edgez_mesh_rx_management management;
    uint8_t action_code;
    const uint8_t *payload;
    size_t payload_length;
};

enum edgez_mesh_rx_kind edgez_mesh_rx_classify(const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_data(struct edgez_mesh_rx_data *output,
                             const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_protected_data(
    struct edgez_mesh_rx_protected_data *output,
    const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_qos_null(struct edgez_mesh_rx_qos_null *output,
                                 const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_management(struct edgez_mesh_rx_management *output,
                                   const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_authentication(
    struct edgez_mesh_rx_authentication *output,
    const uint8_t *frame, size_t length);
int edgez_mesh_rx_parse_peering_action(
    struct edgez_mesh_rx_peering_action *output,
    const uint8_t *frame, size_t length);
