/*
 * Copyright 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#ifndef EDGEZ_MESH_ZEPHYR_H
#define EDGEZ_MESH_ZEPHYR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef size_t (*edgez_nrf_mesh_peers_fn)(void *ctx, uint8_t (*peers)[6],
					  size_t capacity);
typedef int (*edgez_nrf_mesh_tx_fn)(void *ctx, const uint8_t *frame,
				    size_t frame_len, const uint8_t receiver[6]);
typedef int (*edgez_nrf_mesh_pawr_tx_fn)(void *ctx,
					 const uint8_t destination[6],
					 const uint8_t *frame, size_t frame_len);
typedef uint32_t (*edgez_nrf_mesh_clock_fn)(void *ctx);
typedef uint32_t (*edgez_nrf_mesh_random_fn)(void *ctx);
typedef void (*edgez_nrf_mesh_lock_fn)(void *ctx);
typedef void (*edgez_nrf_mesh_payload_fn)(const uint8_t originator[6],
					  const uint8_t *frame, size_t frame_len,
					  void *ctx);

struct edgez_nrf_mesh_transport {
	edgez_nrf_mesh_peers_fn peers;
	edgez_nrf_mesh_tx_fn transmit;
	edgez_nrf_mesh_pawr_tx_fn transmit_pawr;
	edgez_nrf_mesh_clock_fn clock_ms;
	edgez_nrf_mesh_random_fn random;
	edgez_nrf_mesh_lock_fn lock;
	edgez_nrf_mesh_lock_fn unlock;
	void *ctx;
};

int edgez_nrf_mesh_init(const uint8_t local_mac[6],
			const struct edgez_nrf_mesh_transport *transport,
			uint32_t originator_interval_ms);
void edgez_nrf_mesh_register_payload(edgez_nrf_mesh_payload_fn callback, void *ctx);
bool edgez_nrf_mesh_receive_ethernet(const uint8_t *frame, size_t frame_len,
				     const uint8_t transmitter[6]);
bool edgez_nrf_mesh_receive_pawr(const uint8_t *frame, size_t frame_len,
				 const uint8_t transmitter[6]);
void edgez_nrf_mesh_tick(void);
int edgez_nrf_mesh_send_broadcast(const uint8_t *frame, size_t frame_len);
int edgez_nrf_mesh_send_unicast(const uint8_t destination[6],
				const uint8_t *frame, size_t frame_len);
int edgez_nrf_mesh_reset_and_pause(void);
void edgez_nrf_mesh_resume(void);
size_t edgez_nrf_mesh_route_count(void);

#ifdef __cplusplus
}
#endif

#endif
