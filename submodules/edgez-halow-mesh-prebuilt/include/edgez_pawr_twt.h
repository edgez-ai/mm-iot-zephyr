/* SPDX-License-Identifier: Apache-2.0
 * Experimental factory PAwR negotiation, not an authenticated association. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define EDGEZ_PAWR_TWT_LENGTH 60U
#define EDGEZ_PAWR_TWT_INTERVAL_5S_US UINT32_C(5000064)
#define EDGEZ_PAWR_TWT_TRAILER_LENGTH (4U + EDGEZ_PAWR_TWT_LENGTH)
struct edgez_pawr_twt;
/* Factory negotiated extension on an existing PAwR request/ACK. No extra
 * calibration frame is scheduled. lease_ms=0 retains state until cancellation. */
bool edgez_pawr_twt_append(uint8_t *packet, size_t capacity, size_t *length,
                         const struct edgez_pawr_twt *msg);
bool edgez_pawr_twt_unwrap(const uint8_t *packet, size_t length, size_t *base_length,
                         struct edgez_pawr_twt *msg);
enum edgez_pawr_twt_kind {
    /* Session seed on a normal PAwR ACK; no standalone discovery traffic. */
    EDGEZ_PAWR_TWT_HELLO = 1,
    EDGEZ_PAWR_TWT_OFFER,
    EDGEZ_PAWR_TWT_ACCEPT,
    EDGEZ_PAWR_TWT_COMMIT,
    EDGEZ_PAWR_TWT_READY,
    EDGEZ_PAWR_TWT_PROBE,
    EDGEZ_PAWR_TWT_HIT,
    EDGEZ_PAWR_TWT_CANCEL,
};
struct edgez_pawr_twt {
    uint8_t kind, flow;
    uint32_t session, interval_us, duration_us, lease_ms, round_trip_us;
    /* Receiver radio TSF, never MCU uptime. */
    uint64_t reference_tsf, target_tsf;
    /* PROBE/HIT: slot*2 + outside bit, bit31 marks a USER wake. */
    uint32_t sequence;
    int32_t phase_error_us;
    uint32_t processing_us;
    uint64_t echo_host_us;
};

#define EDGEZ_PAWR_TWT_CLOCK_SAMPLES 8U
struct edgez_pawr_twt_clock {
    struct { int32_t correction; uint32_t rtt; } samples[EDGEZ_PAWR_TWT_CLOCK_SAMPLES];
    unsigned count, next, good, updates;
    int32_t phase_adjust_us;
    uint32_t min_rtt_us, jitter_us;
    bool reliable;
};
/* Latest eight samples, low-RTT subset median, median absolute deviation,
 * maximum 1 ms correction per update. Zero-initialize for each agreement.
 * Caller validates session/sequence and passes the correction used for TX. */
bool edgez_pawr_twt_clock_update(struct edgez_pawr_twt_clock *clock,
    int32_t sent_adjust_us, int32_t phase_error_us, uint32_t rtt_us);
bool edgez_pawr_twt_encode(uint8_t *out, size_t capacity,
                           const struct edgez_pawr_twt *msg);
bool edgez_pawr_twt_decode(const uint8_t *data, size_t length,
                           struct edgez_pawr_twt *msg);
bool edgez_pawr_twt_same_schedule(const struct edgez_pawr_twt *a,
                                  const struct edgez_pawr_twt *b);
/* Map an OFFER received at local RX time into a guarded sender deadline.
 * RTT bounds transport/queue uncertainty; assumes symmetric delay for the
 * estimate, but reserves half the full RTT on either side of window centre. */
bool edgez_pawr_twt_sender_start(const struct edgez_pawr_twt *msg,
                                 uint64_t offer_rx_us, uint64_t *start_us);
