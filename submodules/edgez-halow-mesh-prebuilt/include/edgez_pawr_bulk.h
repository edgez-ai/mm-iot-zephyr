/*
 * Copyright 2026 EdgeZeron AI AB
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "edgez_regulatory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EDGEZ_PAWR_BULK_MAGIC UINT32_C(0x455a4254)
#define EDGEZ_PAWR_BULK_VERSION 4U
#define EDGEZ_PAWR_BULK_HEADER_SIZE 52U
#define EDGEZ_PAWR_BULK_CONTROL_SIZE 28U
#define EDGEZ_PAWR_BULK_MAX_CHUNK_DATA 1100U
#define EDGEZ_PAWR_BULK_CHUNK_DATA_SIZE EDGEZ_PAWR_BULK_MAX_CHUNK_DATA
#define EDGEZ_PAWR_BULK_MAX_WINDOW 32U
#define EDGEZ_PAWR_BULK_MAX_TIERS 8U

#ifndef CONFIG_EDGEZ_PAWR_BULK_RING_CAPACITY
#define CONFIG_EDGEZ_PAWR_BULK_RING_CAPACITY (16U * 1024U)
#endif

#if CONFIG_EDGEZ_PAWR_BULK_RING_CAPACITY < EDGEZ_PAWR_BULK_MAX_CHUNK_DATA
#error "CONFIG_EDGEZ_PAWR_BULK_RING_CAPACITY must hold at least one maximum chunk"
#endif

#define EDGEZ_PAWR_BULK_RING_CAPACITY CONFIG_EDGEZ_PAWR_BULK_RING_CAPACITY

#define EDGEZ_PAWR_BULK_FLAG_FIRST 0x01U
#define EDGEZ_PAWR_BULK_FLAG_LAST 0x02U
#define EDGEZ_PAWR_BULK_FLAG_ACK_REQUEST 0x04U

#define EDGEZ_PAWR_BULK_REG_FLAG_REGDB_VALID 0x01U
#define EDGEZ_PAWR_BULK_REG_FLAG_CHIP_DUTY_VALID 0x02U
#define EDGEZ_PAWR_BULK_REG_FLAG_TERMINAL_NODE 0x04U

enum edgez_pawr_bulk_kind {
    EDGEZ_PAWR_BULK_KIND_DATA = 1U,
    EDGEZ_PAWR_BULK_KIND_ACK_QUERY = 2U,
    EDGEZ_PAWR_BULK_KIND_BLOCK_ACK = 3U,
};

enum edgez_pawr_bulk_result {
    EDGEZ_PAWR_BULK_PROGRESS = 0,
    EDGEZ_PAWR_BULK_WAITING = 1,
    EDGEZ_PAWR_BULK_COMPLETE = 2,
    EDGEZ_PAWR_BULK_FAILED = -1,
    EDGEZ_PAWR_BULK_INVALID = -2,
    EDGEZ_PAWR_BULK_BACKPRESSURE = -3,
};

struct edgez_pawr_bulk_regulatory {
    char country_code[3];
    uint32_t frequency_khz;
    uint16_t duty_cycle_centi_percent;
    int8_t max_eirp_dbm;
    uint8_t bandwidth_mhz;
    uint8_t duty_cycle_mode;
    uint8_t flags;
};

struct edgez_pawr_bulk_chunk {
    uint32_t compressed_ssid;
    uint32_t session_id;
    uint32_t total_length;
    uint32_t offset;
    uint32_t expected_digest;
    uint16_t chunk_index;
    uint16_t chunk_count;
    uint16_t data_length;
    uint16_t window_id;
    uint16_t window_base_chunk;
    uint8_t window_count;
    uint8_t test_index;
    uint8_t flags;
    struct edgez_pawr_bulk_regulatory regulatory;
    const uint8_t *data;
};

struct edgez_pawr_bulk_control {
    enum edgez_pawr_bulk_kind kind;
    uint32_t compressed_ssid;
    uint32_t session_id;
    uint32_t bitmap;
    uint16_t window_id;
    uint16_t base_chunk;
    uint8_t chunk_count;
    uint8_t test_index;
};

struct edgez_pawr_bulk_ring {
    uint8_t storage[EDGEZ_PAWR_BULK_RING_CAPACITY];
    size_t head;
    size_t used;
};

void edgez_pawr_bulk_ring_init(struct edgez_pawr_bulk_ring *ring);
size_t edgez_pawr_bulk_ring_size(const struct edgez_pawr_bulk_ring *ring);
size_t edgez_pawr_bulk_ring_space(const struct edgez_pawr_bulk_ring *ring);
size_t edgez_pawr_bulk_ring_write(struct edgez_pawr_bulk_ring *ring,
                                  const uint8_t *data, size_t length);
size_t edgez_pawr_bulk_ring_read(struct edgez_pawr_bulk_ring *ring,
                                 uint8_t *data, size_t length);

size_t edgez_pawr_bulk_encode(uint8_t *output, size_t capacity,
                              const struct edgez_pawr_bulk_chunk *chunk);
bool edgez_pawr_bulk_decode(const uint8_t *input, size_t length,
                            struct edgez_pawr_bulk_chunk *chunk);
size_t edgez_pawr_bulk_control_encode(
    uint8_t *output, size_t capacity,
    const struct edgez_pawr_bulk_control *control);
bool edgez_pawr_bulk_control_decode(
    const uint8_t *input, size_t length,
    struct edgez_pawr_bulk_control *control);
bool edgez_pawr_bulk_control_matches(
    const struct edgez_pawr_bulk_control *control, uint32_t compressed_ssid,
    uint32_t session_id,
    uint8_t test_index, uint16_t window_id, uint16_t base_chunk,
    uint8_t chunk_count);

uint32_t edgez_pawr_bulk_ack_timeout_ms(uint16_t chunk_size,
                                        uint8_t window_count);

struct edgez_pawr_bulk_tier {
    uint16_t chunk_size;
    uint8_t window_size;
};

extern const struct edgez_pawr_bulk_tier edgez_pawr_bulk_default_tiers[5];

typedef size_t (*edgez_pawr_bulk_read_fn)(void *ctx, uint32_t offset,
                                          uint8_t *output, size_t capacity);
typedef bool (*edgez_pawr_bulk_send_fn)(void *ctx, const uint8_t *payload,
                                        size_t length);
typedef void (*edgez_pawr_bulk_sender_done_fn)(void *ctx, bool success);

struct edgez_pawr_bulk_sender_config {
    const struct edgez_pawr_bulk_tier *tiers;
    uint8_t tier_count;
    uint8_t initial_tier;
    uint8_t maximum_tier;
    uint8_t max_attempts;
    edgez_pawr_bulk_read_fn read;
    edgez_pawr_bulk_send_fn send;
    edgez_pawr_bulk_sender_done_fn done;
    void *ctx;
};

struct edgez_pawr_bulk_transfer {
    uint32_t compressed_ssid;
    uint32_t session_id;
    uint32_t total_length;
    uint32_t expected_digest;
    uint8_t test_index;
    struct edgez_pawr_bulk_regulatory regulatory;
};

/** Attach an already-resolved regulatory rule to wire metadata. Channel,
 * power, CCA, duty-cycle, and MPSW enforcement remain lower-layer duties. */
bool edgez_pawr_bulk_transfer_apply_policy(
    struct edgez_pawr_bulk_transfer *transfer,
    const struct edgez_regulatory_policy *policy,
    uint32_t frequency_khz, uint8_t bandwidth_mhz);

struct edgez_pawr_bulk_sender_stats {
    uint32_t transmissions;
    uint32_t selective_retries;
    uint32_t ack_queries;
    uint32_t block_acks;
    uint32_t bytes_acked;
    uint16_t chunks_acked;
    uint16_t windows_acked;
};

struct edgez_pawr_bulk_sender_slot {
    size_t ring_offset;
    uint16_t data_length;
};

struct edgez_pawr_bulk_sender {
    struct edgez_pawr_bulk_sender_config config;
    struct edgez_pawr_bulk_tier tiers[EDGEZ_PAWR_BULK_MAX_TIERS];
    struct edgez_pawr_bulk_transfer transfer;
    struct edgez_pawr_bulk_ring ring;
    struct edgez_pawr_bulk_sender_slot slots[EDGEZ_PAWR_BULK_MAX_WINDOW];
    struct edgez_pawr_bulk_sender_stats stats;
    uint32_t offset;
    uint32_t producer_offset;
    uint32_t window_end_offset;
    uint32_t ack_bitmap;
    uint32_t deadline_ms;
    uint16_t chunk_index;
    uint16_t window_end_chunk;
    uint16_t window_id;
    uint8_t window_count;
    uint8_t tier;
    uint8_t clean_windows;
    uint8_t attempts;
    uint8_t phase;
    bool active;
    bool callback_fired;
};

bool edgez_pawr_bulk_sender_init(
    struct edgez_pawr_bulk_sender *sender,
    const struct edgez_pawr_bulk_sender_config *config);
bool edgez_pawr_bulk_sender_start(
    struct edgez_pawr_bulk_sender *sender,
    const struct edgez_pawr_bulk_transfer *transfer);
/** Return writable producer capacity. This is zero for read-callback mode. */
size_t edgez_pawr_bulk_sender_space(
    const struct edgez_pawr_bulk_sender *sender);
/** Queue source bytes for push-stream mode. A short write is backpressure. */
size_t edgez_pawr_bulk_sender_write(
    struct edgez_pawr_bulk_sender *sender, const uint8_t *data, size_t length);
enum edgez_pawr_bulk_result edgez_pawr_bulk_sender_poll(
    struct edgez_pawr_bulk_sender *sender, uint32_t now_ms);
bool edgez_pawr_bulk_sender_feed(struct edgez_pawr_bulk_sender *sender,
                                 const uint8_t *payload, size_t length);
uint32_t edgez_pawr_bulk_sender_next_deadline(
    const struct edgez_pawr_bulk_sender *sender);

typedef bool (*edgez_pawr_bulk_receiver_send_fn)(
    void *ctx, const uint8_t destination[6], const uint8_t *payload,
    size_t length);
typedef bool (*edgez_pawr_bulk_data_fn)(
    void *ctx, const struct edgez_pawr_bulk_chunk *chunk);
typedef void (*edgez_pawr_bulk_receiver_done_fn)(
    void *ctx, const struct edgez_pawr_bulk_transfer *transfer, bool success);

struct edgez_pawr_bulk_receiver_config {
    uint32_t compressed_ssid;
    edgez_pawr_bulk_receiver_send_fn send;
    edgez_pawr_bulk_data_fn data;
    edgez_pawr_bulk_receiver_done_fn done;
    void *ctx;
};

struct edgez_pawr_bulk_receiver_stats {
    uint32_t ssid_mismatches;
    uint32_t frames;
    uint32_t duplicates;
    uint32_t stale;
    uint32_t block_acks;
    uint32_t ack_queries;
    uint32_t bytes_received;
    uint16_t chunks_received;
};

struct edgez_pawr_bulk_receiver {
    struct edgez_pawr_bulk_receiver_config config;
    struct edgez_pawr_bulk_transfer transfer;
    struct edgez_pawr_bulk_receiver_stats stats;
    uint8_t peer[6];
    uint32_t previous_session_id;
    uint32_t bitmap;
    uint16_t window_id;
    uint16_t base_chunk;
    uint8_t window_count;
    bool active;
    bool has_previous_session;
    bool saw_last;
    bool complete;
};

bool edgez_pawr_bulk_receiver_init(
    struct edgez_pawr_bulk_receiver *receiver,
    const struct edgez_pawr_bulk_receiver_config *config);
bool edgez_pawr_bulk_receiver_feed(
    struct edgez_pawr_bulk_receiver *receiver, const uint8_t source[6],
    const uint8_t *payload, size_t length);

#ifdef __cplusplus
}
#endif
