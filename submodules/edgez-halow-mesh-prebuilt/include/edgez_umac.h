/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#pragma once

#include <stdbool.h>
#include "edgez_rf_backend.h"
#include "edgez_umac_rate_control.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_UMAC_MAX_PEERS 4U

enum edgez_umac_status
{
    EDGEZ_UMAC_OK = 0,
    EDGEZ_UMAC_INVALID_ARGUMENT = -1,
    EDGEZ_UMAC_INVALID_STATE = -2,
    EDGEZ_UMAC_DRIVER_ERROR = -3,
    EDGEZ_UMAC_ALREADY_EXISTS = -4,
    EDGEZ_UMAC_NO_CAPACITY = -5,
    EDGEZ_UMAC_NOT_FOUND = -6,
};

enum edgez_umac_state
{
    EDGEZ_UMAC_STATE_UNBOUND = 0,
    EDGEZ_UMAC_STATE_STOPPED,
    EDGEZ_UMAC_STATE_OBSERVING,
    EDGEZ_UMAC_STATE_RUNNING,
};

struct edgez_umac_peer
{
    uint8_t mac_addr[EDGEZ_UMAC_MAC_LEN];
    uint16_t aid;
    enum edgez_umac_peer_state state;
    struct edgez_umac_rate_control rate_control;
    bool in_use;
};

/** Borrowed event data is valid only for the duration of each callback. */
struct edgez_umac_event_ops
{
    void (*rx_frame)(void *event_ctx, const struct edgez_umac_rx_frame *frame);
    void (*tx_status)(void *event_ctx, const struct edgez_umac_tx_status *status);
    void (*tx_pause_changed)(void *event_ctx, uint16_t source_mask, bool paused);
    void (*hardware_restart_required)(void *event_ctx);
    void (*scan_complete)(void *event_ctx, int driver_scan_status);
};

struct edgez_umac_config
{
    char country_code[3];
    uint8_t local_mac[EDGEZ_UMAC_MAC_LEN];
    struct edgez_umac_channel channel;
    uint16_t beacon_interval_tu;
    uint8_t dtim_period;
    uint32_t compressed_ssid;
    struct edgez_rf_beacon_template beacon_template;
    struct edgez_umac_rate_config rate_control;
    bool enable_beaconing;
};

struct edgez_umac
{
    const struct edgez_rf_backend_ops *driver;
    void *driver_ctx;
    enum edgez_umac_state state;
    uint16_t vif_id;
    int last_driver_status;
    bool prepared;
    bool radio_started;
    bool interface_added;
    bool beacon_template_set;
    bool beaconing;
    struct edgez_umac_rate_config rate_control;
    struct edgez_umac_peer peers[EDGEZ_UMAC_MAX_PEERS];
    const struct edgez_umac_event_ops *events;
    void *event_ctx;
};

int edgez_umac_bind(struct edgez_umac *umac,
                    const struct edgez_rf_backend_ops *driver,
                    void *driver_ctx);
int edgez_umac_start(struct edgez_umac *umac,
                     const struct edgez_umac_config *config,
                     struct edgez_umac_radio_info *radio_info);
int edgez_umac_stop(struct edgez_umac *umac);
int edgez_umac_set_peer_state(struct edgez_umac *umac, uint16_t aid,
                              const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
                              enum edgez_umac_peer_state state);
int edgez_umac_install_key(struct edgez_umac *umac, uint16_t aid,
                           const struct edgez_umac_key *key,
                           uint8_t *hardware_key_index);
int edgez_umac_disable_key(struct edgez_umac *umac, uint16_t aid,
                           uint8_t hardware_key_index, bool pairwise);
int edgez_umac_transmit(struct edgez_umac *umac,
                        const struct edgez_umac_tx_request *request);
int edgez_umac_enable_beaconing(
    struct edgez_umac *umac,
    const struct edgez_rf_beacon_template *beacon_template);
int edgez_umac_disable_beaconing(struct edgez_umac *umac);
int edgez_umac_set_event_ops(struct edgez_umac *umac,
                             const struct edgez_umac_event_ops *events,
                             void *event_ctx);
/**
 * Attach only the event side of the private UMAC to an externally owned radio.
 *
 * This is the safe migration state while the reference UMAC still owns radio
 * lifecycle and packet disposal. Events are borrowed and may be inspected, but
 * lifecycle, peer, key, and transmit operations remain unavailable.
 */
int edgez_umac_attach_observer(struct edgez_umac *umac,
                               const struct edgez_umac_event_ops *events,
                               void *event_ctx);
int edgez_umac_detach_observer(struct edgez_umac *umac);
int edgez_umac_dispatch_rx_frame(struct edgez_umac *umac,
                                 const struct edgez_umac_rx_frame *frame);
int edgez_umac_dispatch_tx_status(struct edgez_umac *umac,
                                  const struct edgez_umac_tx_status *status);
int edgez_umac_dispatch_tx_pause(struct edgez_umac *umac,
                                 uint16_t source_mask, bool paused);
int edgez_umac_dispatch_hardware_restart(struct edgez_umac *umac);
int edgez_umac_dispatch_scan_complete(struct edgez_umac *umac,
                                      int driver_scan_status);

int edgez_umac_peer_add(struct edgez_umac *umac, uint16_t aid,
                        const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN]);
/** Add a peer using the first free private-UMAC AID. */
int edgez_umac_peer_add_next(struct edgez_umac *umac,
                             const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
                             uint16_t *aid);
int edgez_umac_peer_transition(struct edgez_umac *umac,
                               const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN],
                               enum edgez_umac_peer_state state);
int edgez_umac_peer_remove(struct edgez_umac *umac,
                           const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN]);
const struct edgez_umac_peer *edgez_umac_peer_find(
    const struct edgez_umac *umac,
    const uint8_t peer_addr[EDGEZ_UMAC_MAC_LEN]);
size_t edgez_umac_peer_count(const struct edgez_umac *umac);

#ifdef __cplusplus
}
#endif
