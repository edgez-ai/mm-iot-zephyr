/*
 * Copyright 2024-2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morse_log.h"
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/net/conn_mgr/connectivity_wifi_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/pm/device.h>

#include "morse.h"
#include "mmosal.h"
#include "mmpkt.h"
#include "mmwlan.h"
#include "mmwlan_stats.h"
#include "mmregdb.h"
#include "mmutils.h"
#include "mmhal.h"
#include "mmhal_wlan.h"

#if CONFIG_DT_HAS_MORSE_MM8108_ENABLED
#define DT_DRV_COMPAT morse_mm8108
#else
#define DT_DRV_COMPAT morse_mm6108
#endif

#define SPI_FRAME_BITS 8
#define ETH_HDR_LEN 14
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV6 0x86dd
#define ETH_TYPE_MESHTASTIC_HALOW 0x88b5
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17
#define MM_MESH_LOG_PREFIX "MM_MESH"
#define MM_MESH_ETH_HEADER_LEN 14
#define HALOW_MESH_HEADER_LEN 16

static const uint8_t mm_mesh_broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
typedef void (*morse_mesh_rx_cb_t)(const uint8_t *radio_buf, size_t radio_len, int8_t rssi,
				   void *user_data);

struct morse_data morse_data0;
const struct device *morse_dev;
static morse_mesh_rx_cb_t mesh_rx_cb;
static void *mesh_rx_user_data;
static uint32_t raw_tx_seq;

extern void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern void morse_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern uint32_t mmhal_get_deep_sleep_veto(void);
extern volatile uint32_t mmhal_spi_irq_poll_interval;

static void mmnetif_rx(uint8_t *header, unsigned header_len, uint8_t *payload,
		       unsigned payload_len, void *arg);
static void mmnetif_link_state(enum mmwlan_link_state link_state, void *arg);
static void mmnetif_vif_state(const struct mmwlan_vif_state *state, void *arg);

static uint16_t get_be16(const uint8_t *buf)
{
	return ((uint16_t)buf[0] << 8) | buf[1];
}

#if defined(CONFIG_WIFI_MORSE_MESH_TRAFFIC_LOG)
enum {
	MORSE_MESH_TRAFFIC_DUMP_BYTES =
		CONFIG_WIFI_MORSE_MESH_TRAFFIC_HEXDUMP_BYTES > 0 ?
			CONFIG_WIFI_MORSE_MESH_TRAFFIC_HEXDUMP_BYTES : 1,
};

static const char *ethertype_name(uint16_t ethertype)
{
	switch (ethertype) {
	case ETH_TYPE_IPV4:
		return "ipv4";
	case ETH_TYPE_ARP:
		return "arp";
	case ETH_TYPE_IPV6:
		return "ipv6";
	case ETH_TYPE_MESHTASTIC_HALOW:
		return "meshtastic";
	default:
		return "other";
	}
}

static const char *ip_proto_name(uint8_t proto)
{
	switch (proto) {
	case IP_PROTO_ICMP:
		return "icmp";
	case IP_PROTO_TCP:
		return "tcp";
	case IP_PROTO_UDP:
		return "udp";
	default:
		return "other";
	}
}

static uint32_t read_le_u32(const uint8_t *buf)
{
	return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) |
	       ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

static void log_halow_radio_frame(const char *dir, const uint8_t *radio_buf, size_t radio_len)
{
	if (!radio_buf || radio_len < HALOW_MESH_HEADER_LEN) {
		LOG_WRN("%s radio %s short_len=%u", MM_MESH_LOG_PREFIX, dir,
			(unsigned int)radio_len);
		return;
	}

	uint32_t to = read_le_u32(&radio_buf[0]);
	uint32_t from = read_le_u32(&radio_buf[4]);
	uint32_t id = read_le_u32(&radio_buf[8]);
	uint8_t flags = radio_buf[12];
	uint8_t channel = radio_buf[13];
	uint8_t next_hop = radio_buf[14];
	uint8_t relay_node = radio_buf[15];

	LOG_INF("%s radio %s to=0x%08x from=0x%08x id=0x%08x flags=0x%02x channel=%u next_hop=%u relay_node=%u payload=%u",
		MM_MESH_LOG_PREFIX, dir, to, from, id, flags, channel,
		next_hop, relay_node, (unsigned int)(radio_len - HALOW_MESH_HEADER_LEN));
	LOG_HEXDUMP_INF(&radio_buf[0], MIN(radio_len, (size_t)32),
		"MM_MESH radio preview");
}

static const char *link_state_name(enum mmwlan_link_state link_state)
{
	switch (link_state) {
	case MMWLAN_LINK_UP:
		return "up";
	case MMWLAN_LINK_DOWN:
		return "down";
	default:
		return "unknown";
	}
}

static atomic_t tx_flow_state = ATOMIC_INIT(MMWLAN_TX_READY);
static atomic_t mac_link_state_events = ATOMIC_INIT(0);
static atomic_t mac_vif_state_events = ATOMIC_INIT(0);
static atomic_t mac_tx_flow_events = ATOMIC_INIT(0);
static atomic_t mac_last_link_state = ATOMIC_INIT(MMWLAN_LINK_DOWN);
static atomic_t mac_last_vif_link_state_sta = ATOMIC_INIT(MMWLAN_LINK_DOWN);
static atomic_t mac_last_vif_link_state_ap = ATOMIC_INIT(MMWLAN_LINK_DOWN);

static const char *sta_state_name(enum mmwlan_sta_state sta_state)
{
	switch (sta_state) {
	case MMWLAN_STA_DISABLED:
		return "disabled";
	case MMWLAN_STA_CONNECTING:
		return "connecting";
	case MMWLAN_STA_CONNECTED:
		return "connected";
	default:
		return "unknown";
	}
}

static const char *tx_flow_control_state_name(enum mmwlan_tx_flow_control_state tx_state)
{
	switch (tx_state) {
	case MMWLAN_TX_READY:
		return "ready";
	case MMWLAN_TX_PAUSED:
		return "paused";
	default:
		return "unknown";
	}
}

static enum wifi_iface_state morse_sta_to_wifi_state(enum mmwlan_sta_state sta_state)
{
	switch (sta_state) {
	case MMWLAN_STA_DISABLED:
		return WIFI_STATE_DISCONNECTED;
	case MMWLAN_STA_CONNECTING:
		return WIFI_STATE_SCANNING;
	case MMWLAN_STA_CONNECTED:
		return WIFI_STATE_COMPLETED;
	default:
		return WIFI_STATE_INACTIVE;
	}
}

static const char *mmwlan_status_name(enum mmwlan_status status)
{
	switch (status) {
	case MMWLAN_SUCCESS:
		return "success";
	case MMWLAN_INVALID_ARGUMENT:
		return "invalid_argument";
	case MMWLAN_UNAVAILABLE:
		return "unavailable";
	case MMWLAN_CHANNEL_LIST_NOT_SET:
		return "channel_list_not_set";
	case MMWLAN_CHANNEL_INVALID:
		return "channel_invalid";
	case MMWLAN_NO_MEM:
		return "no_mem";
	case MMWLAN_TIMED_OUT:
		return "timed_out";
	case MMWLAN_NOT_FOUND:
		return "not_found";
	case MMWLAN_NOT_RUNNING:
		return "not_running";
	case MMWLAN_ERROR:
		return "error";
	case MMWLAN_VIF_ERROR:
		return "vif_error";
	case MMWLAN_SHUTDOWN_BLOCKED:
		return "shutdown_blocked";
	default:
		return "unknown";
	}
}

static const char *mmwlan_vif_name(enum mmwlan_vif vif)
{
	switch (vif) {
	case MMWLAN_VIF_STA:
		return "sta";
	case MMWLAN_VIF_AP:
		return "ap";
	case MMWLAN_VIF_UNSPECIFIED:
		return "unspecified";
	default:
		return "unknown";
	}
}

static void log_mmwlan_state_snapshot(const char *reason)
{
	const char *reason_text = reason ? reason : "unknown";
	enum mmwlan_status sta_mac_status;
	enum mmwlan_status ap_mac_status;
	uint8_t sta_mac[MMWLAN_MAC_ADDR_LEN];
	uint8_t ap_mac[MMWLAN_MAC_ADDR_LEN];
	struct mmwlan_stats_umac_data stats;
	enum mmwlan_status stats_status;
	int sta_state = mmwlan_get_sta_state();
	int rssi = mmwlan_get_rssi();
	int tx_flow = (int)atomic_get(&tx_flow_state);
	enum mmwlan_link_state sta_link = (enum mmwlan_link_state)atomic_get(&mac_last_vif_link_state_sta);
	enum mmwlan_link_state ap_link = (enum mmwlan_link_state)atomic_get(&mac_last_vif_link_state_ap);

	sta_mac_status = mmwlan_get_vif_mac_addr(MMWLAN_VIF_STA, sta_mac);
	ap_mac_status = mmwlan_get_vif_mac_addr(MMWLAN_VIF_AP, ap_mac);

	LOG_INF(
		"%s state[%s] sta_state=%s(%d) tx_flow=%s(%d) link_sta=%s(%d) link_ap=%s(%d) rssi=%d tx_pool=%u/%u mac_sta=%d mac_ap=%d",
		MM_MESH_LOG_PREFIX, reason_text, sta_state_name((enum mmwlan_sta_state)sta_state),
		sta_state, tx_flow_control_state_name((enum mmwlan_tx_flow_control_state)tx_flow),
		(int)tx_flow, link_state_name(sta_link), sta_link, link_state_name(ap_link), ap_link,
		rssi, (unsigned int)mmhal_wlan_pktmem_tx_free_count(),
		(unsigned int)mmhal_wlan_pktmem_tx_total_count(), (int)sta_mac_status, (int)ap_mac_status);

	stats_status = mmwlan_get_umac_stats(&stats);
	if (stats_status == MMWLAN_SUCCESS) {
		LOG_INF(
			"%s state[%s] umac last_tx=%u txq_drop=%u rxq_drop=%u tx_hwm=%u hw_restart=%u scans=%u",
			MM_MESH_LOG_PREFIX, reason_text, stats.last_tx_time,
			stats.datapath_txq_frames_dropped, stats.datapath_rxq_frames_dropped,
			stats.datapath_txq_high_water_mark, stats.hw_restart_counter,
			stats.num_scans_complete);
	} else {
		LOG_WRN("%s state[%s] umac_stats_failed=%d", MM_MESH_LOG_PREFIX,
			reason_text, (int)stats_status);
	}

	ARG_UNUSED(sta_mac_status);
	ARG_UNUSED(ap_mac_status);
	ARG_UNUSED(sta_mac);
	ARG_UNUSED(ap_mac);
}

static void log_mesh_frame_summary(const char *dir, const uint8_t *frame, size_t len)
{
	if (len < ETH_HDR_LEN) {
		LOG_INF("%s %s short_frame len=%u", MM_MESH_LOG_PREFIX, dir, (unsigned int)len);
		return;
	}

	uint16_t ethertype = get_be16(&frame[12]);

	LOG_INF("%s %s eth len=%u dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x(%s)",
		MM_MESH_LOG_PREFIX, dir, (unsigned int)len,
		frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
		frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
		ethertype, ethertype_name(ethertype));

	if (ethertype == ETH_TYPE_IPV4 && len >= ETH_HDR_LEN + 20) {
		const uint8_t *ip = &frame[ETH_HDR_LEN];
		size_t ip_hdr_len = (ip[0] & 0x0f) * 4U;
		uint8_t proto = ip[9];

		LOG_INF("%s %s ipv4 %u.%u.%u.%u -> %u.%u.%u.%u proto=%u(%s) ttl=%u",
			MM_MESH_LOG_PREFIX, dir, ip[12], ip[13], ip[14], ip[15],
			ip[16], ip[17], ip[18], ip[19],
			proto, ip_proto_name(proto), ip[8]);

		if ((proto == IP_PROTO_UDP || proto == IP_PROTO_TCP) &&
		    ip_hdr_len >= 20 && len >= ETH_HDR_LEN + ip_hdr_len + 4) {
			const uint8_t *l4 = &ip[ip_hdr_len];

			LOG_INF("%s %s %s sport=%u dport=%u",
				MM_MESH_LOG_PREFIX, dir, ip_proto_name(proto),
				get_be16(&l4[0]), get_be16(&l4[2]));
		}
	}

	size_t dump_len = MIN(len, (size_t)MORSE_MESH_TRAFFIC_DUMP_BYTES);
	if (dump_len > 0) {
		LOG_HEXDUMP_INF(frame, dump_len, "MM_MESH frame");
	}
}

static void log_mesh_rx_frame(const uint8_t *header, unsigned header_len,
			      const uint8_t *payload, unsigned payload_len)
{
	uint8_t frame[MORSE_MESH_TRAFFIC_DUMP_BYTES];
	size_t copy_len = MIN((size_t)header_len + payload_len, sizeof(frame));
	size_t header_copy_len = MIN((size_t)header_len, copy_len);
	size_t payload_copy_len = copy_len - header_copy_len;

	if (header_copy_len > 0) {
		memcpy(frame, header, header_copy_len);
	}
	if (payload_copy_len > 0) {
		memcpy(&frame[header_copy_len], payload, payload_copy_len);
	}

	LOG_INF("%s RX callback header_len=%u payload_len=%u total_len=%u",
		MM_MESH_LOG_PREFIX, header_len, payload_len, header_len + payload_len);
	log_mesh_frame_summary("RX", frame, copy_len);
}
#endif /* defined(CONFIG_WIFI_MORSE_MESH_TRAFFIC_LOG) */

static void mmnetif_tx_flow_control(enum mmwlan_tx_flow_control_state state, void *arg)
{
	ARG_UNUSED(arg);
	atomic_inc(&mac_tx_flow_events);
	int64_t seq = (int64_t)atomic_get(&mac_tx_flow_events);
	enum mmwlan_tx_flow_control_state previous =
		(enum mmwlan_tx_flow_control_state)atomic_set(&tx_flow_state, (atomic_val_t)state);
	LOG_INF("%s tx_flow_control state=%s(%d)", MM_MESH_LOG_PREFIX,
		tx_flow_control_state_name(state), (int)state);
	LOG_INF("%s tx_flow_control transition seq=%lld prev=%s(%d) tx_pool_free=%u/%u",
		MM_MESH_LOG_PREFIX, seq, tx_flow_control_state_name(previous), (int)previous,
		(unsigned int)mmhal_wlan_pktmem_tx_free_count(),
		(unsigned int)mmhal_wlan_pktmem_tx_total_count());
}

static int morse_mesh_send_ethernet_frame(const uint8_t *eth_frame, size_t eth_len, uint32_t tx_seq)
{
	struct mmwlan_tx_metadata metadata = MMWLAN_TX_METADATA_INIT;
	struct mmpkt *mmpkt;
	struct mmpktview *pktview;
	enum mmwlan_status status;
	int sta_state = mmwlan_get_sta_state();
	int32_t rssi = mmwlan_get_rssi();
	uint8_t vif_sta[MMWLAN_MAC_ADDR_LEN];
	uint8_t vif_ap[MMWLAN_MAC_ADDR_LEN];
	enum mmwlan_status sta_mac_status = mmwlan_get_vif_mac_addr(MMWLAN_VIF_STA, vif_sta);
	enum mmwlan_status ap_mac_status = mmwlan_get_vif_mac_addr(MMWLAN_VIF_AP, vif_ap);

	if (!eth_frame || eth_len == 0 || eth_len > NET_ETH_MAX_FRAME_SIZE) {
		LOG_ERR("%s raw_tx invalid eth_len=%u", MM_MESH_LOG_PREFIX, (unsigned int)eth_len);
		return -EINVAL;
	}

#if defined(CONFIG_WIFI_MORSE_MESH_TRAFFIC_LOG)
	log_mesh_frame_summary("RAW_TX", eth_frame, eth_len);
#endif

	LOG_INF("%s raw_tx entry seq=%u eth_len=%u", MM_MESH_LOG_PREFIX, tx_seq, (unsigned int)eth_len);
	log_mmwlan_state_snapshot("raw_tx_pre");
	LOG_INF("%s raw_tx path_pre sta=%s(%d) rssi=%d tx_flow=%s(%d)", MM_MESH_LOG_PREFIX,
		sta_state_name(sta_state), sta_state, (int)rssi,
		tx_flow_control_state_name((enum mmwlan_tx_flow_control_state)atomic_get(&tx_flow_state)),
		(int)atomic_get(&tx_flow_state));
	LOG_INF("%s raw_tx tx_pool_free=%u/%u", MM_MESH_LOG_PREFIX,
		(unsigned int)mmhal_wlan_pktmem_tx_free_count(),
		(unsigned int)mmhal_wlan_pktmem_tx_total_count());
	LOG_INF("%s raw_tx vif_mac_status sta=%d ap=%d", MM_MESH_LOG_PREFIX,
		sta_mac_status, ap_mac_status);
	if (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
		metadata.vif = MMWLAN_VIF_STA;
	} else {
		if (sta_mac_status == MMWLAN_SUCCESS) {
			metadata.vif = MMWLAN_VIF_STA;
		} else if (ap_mac_status == MMWLAN_SUCCESS) {
			metadata.vif = MMWLAN_VIF_AP;
		}
		if (metadata.vif == MMWLAN_VIF_UNSPECIFIED) {
			LOG_ERR("%s raw_tx missing_vif status=%d/%d", MM_MESH_LOG_PREFIX, sta_mac_status, ap_mac_status);
			return mmwlan_err_to_errno(MMWLAN_VIF_ERROR);
		}
	}
	LOG_INF("%s raw_tx selected vif=%d", MM_MESH_LOG_PREFIX, metadata.vif);
	if (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
		/*
		 * Mesh broadcast packets must be allowed while the STA-style mesh state machine
		 * is scanning/connecting. The generic wait_ready() waits on every UMAC pause
		 * source, including scan/traffic-control pauses, which can permanently block
		 * mesh beacons even when packet memory is fully available.
		 */
		LOG_INF("%s raw_tx wait_ready skipped mesh_broadcast tx_flow=%s(%d)",
			MM_MESH_LOG_PREFIX,
			tx_flow_control_state_name((enum mmwlan_tx_flow_control_state)atomic_get(&tx_flow_state)),
			(int)atomic_get(&tx_flow_state));
	} else {
		status = mmwlan_tx_wait_until_ready(MMWLAN_TX_DEFAULT_TIMEOUT_MS);
		LOG_INF("%s raw_tx wait_ready rc=%s(%d)", MM_MESH_LOG_PREFIX,
			mmwlan_status_name(status), (int)status);
		if (status != MMWLAN_SUCCESS) {
			LOG_ERR("%s raw_tx not_ready status=%d errno=%d", MM_MESH_LOG_PREFIX,
				status, mmwlan_err_to_errno(status));
			return mmwlan_err_to_errno(status);
		}
	}

	mmpkt = mmwlan_alloc_mmpkt_for_tx(eth_len, metadata.tid);
	if (!mmpkt) {
		LOG_ERR("%s raw_tx alloc_failed eth_len=%u", MM_MESH_LOG_PREFIX,
			(unsigned int)eth_len);
		return -ENOMEM;
	}

	pktview = mmpkt_open(mmpkt);
	mmpkt_append_data(pktview, eth_frame, eth_len);
	mmpkt_close(&pktview);

	status = mmwlan_tx_pkt(mmpkt, &metadata);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s raw_tx send_failed status=%d(%s) errno=%d", MM_MESH_LOG_PREFIX,
			status, mmwlan_status_name(status), mmwlan_err_to_errno(status));
		log_mmwlan_state_snapshot("raw_tx_tx_failed");
		return mmwlan_err_to_errno(status);
	}

	LOG_INF("%s raw_tx queued seq=%u eth_len=%u radio_len=%u vif=%d tid=%u",
		MM_MESH_LOG_PREFIX, tx_seq, (unsigned int)eth_len,
		(unsigned int)(eth_len > MM_MESH_ETH_HEADER_LEN ?
			eth_len - MM_MESH_ETH_HEADER_LEN : 0),
		metadata.vif, metadata.tid);
	log_mmwlan_state_snapshot("raw_tx_post");
	return 0;
}

int morse_mesh_send_radio_buffer(const uint8_t *radio_buf, size_t radio_len)
{
	uint8_t eth_frame[NET_ETH_MAX_FRAME_SIZE];

	if (!radio_buf || radio_len == 0 ||
	    radio_len > sizeof(eth_frame) - MM_MESH_ETH_HEADER_LEN) {
		LOG_ERR("%s raw_tx invalid radio_len=%u", MM_MESH_LOG_PREFIX,
			(unsigned int)radio_len);
		return -EINVAL;
	}
	log_halow_radio_frame("TX", radio_buf, radio_len);

	uint32_t seq = ++raw_tx_seq;
	memcpy(eth_frame, mm_mesh_broadcast_mac, sizeof(mm_mesh_broadcast_mac));
	if (mmwlan_get_mac_addr(&eth_frame[6]) != MMWLAN_SUCCESS) {
		memcpy(&eth_frame[6], morse_data0.mac_addr, sizeof(morse_data0.mac_addr));
	}
	eth_frame[12] = (uint8_t)(ETH_TYPE_MESHTASTIC_HALOW >> 8);
	eth_frame[13] = (uint8_t)(ETH_TYPE_MESHTASTIC_HALOW & 0xff);
	memcpy(&eth_frame[MM_MESH_ETH_HEADER_LEN], radio_buf, radio_len);

	LOG_INF(
		"%s raw_tx enter seq=%u radio_len=%u ethertype=0x%04x dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x",
		MM_MESH_LOG_PREFIX, seq, (unsigned int)radio_len, ETH_TYPE_MESHTASTIC_HALOW,
		eth_frame[0], eth_frame[1], eth_frame[2], eth_frame[3], eth_frame[4], eth_frame[5],
		eth_frame[6], eth_frame[7], eth_frame[8], eth_frame[9], eth_frame[10], eth_frame[11]);

	int rc = morse_mesh_send_ethernet_frame(eth_frame, radio_len + MM_MESH_ETH_HEADER_LEN, seq);
	if (rc == 0) {
		LOG_INF("%s raw_tx accept seq=%u", MM_MESH_LOG_PREFIX, seq);
	} else {
		LOG_ERR("%s raw_tx accept_failed seq=%u rc=%d", MM_MESH_LOG_PREFIX, seq, rc);
	}
	return rc;
}

void morse_mesh_register_rx_cb(morse_mesh_rx_cb_t cb, void *user_data)
{
	mesh_rx_cb = cb;
	mesh_rx_user_data = user_data;
	LOG_INF("%s raw_rx_cb %s", MM_MESH_LOG_PREFIX, cb ? "registered" : "cleared");
}

static void scan_callback(const struct mmwlan_scan_result *result, void *arg)
{
	struct morse_data *morse = arg;
	struct wifi_scan_result scan;
	struct mm_rsn_information rsn_info;
	struct mm_s1g_operation s1g_operation;
	int ii;

	memset(&scan, 0, sizeof(scan));

	if (morse->channel_list == NULL) {
		LOG_DBG("channel list hasn't been set...");
		LOG_ERR("%s failed %d", __func__, MMWLAN_ERROR);
		return;
	}

	scan.ssid_length = result->ssid_len < (WIFI_SSID_MAX_LEN - 1) ? result->ssid_len
								      : WIFI_SSID_MAX_LEN - 1;
	memcpy(scan.ssid, result->ssid, scan.ssid_length);
	scan.ssid[WIFI_SSID_MAX_LEN - 1] = '\0';

	memcpy(scan.mac, result->bssid, WIFI_MAC_ADDR_LEN);
	scan.mac_length = WIFI_MAC_ADDR_LEN;
	scan.band = WIFI_FREQ_BAND_UNKNOWN;
	scan.channel = 0;
	scan.rssi = (int8_t)result->rssi;

	int ret = mm_parse_s1g_operation(result->ies, result->ies_len, &s1g_operation);
	if (ret != 0) {
		LOG_ERR("Failed to parse S1G Operation Element");
		return;
	}
	scan.channel = s1g_operation.primary_channel_number;

	ret = mm_parse_rsn_information(result->ies, result->ies_len, &rsn_info);
	if (ret == -2) {
		LOG_ERR("Failed to parse RSN IE for ssid: %s", scan.ssid);
		return;
	}

	/* Parse the RSN Information to get the MFP requirements */
	if (rsn_info.rsn_capabilities & RSN_MFPC) {
		scan.mfp = WIFI_MFP_OPTIONAL;
		if (rsn_info.rsn_capabilities & RSN_MFPR) {
			scan.mfp = WIFI_MFP_REQUIRED;
		}
	}

	scan.security = WIFI_SECURITY_TYPE_NONE;
	if (ret == -1 || rsn_info.num_akm_suites == 0) {
		goto scan_cb_end;
	}

	/* working with the API at the moment. Technically to be HaLow, a device SHALL
	 * be using WPA3. However, it can be handy for debugging, to use something other than WPA3
	 * There also isn't an OWE definition in Zephyr yet - fake being SAE.
	 */
	for (ii = 0; ii < rsn_info.num_akm_suites; ii++) {
		switch (rsn_info.akm_suites[ii]) {
		case MM_AKM_SUITE_NONE:
			LOG_DBG("ssid: %s has cipher suite NONE", scan.ssid);
			scan.security = MM_MAX(scan.security, WIFI_SECURITY_TYPE_NONE);
			break;

		case MM_AKM_SUITE_PSK:
			LOG_DBG("ssid: %s has cipher suite WPA2-PSK", scan.ssid);
			scan.security = MM_MAX(scan.security, WIFI_SECURITY_TYPE_PSK);
			break;

		case MM_AKM_SUITE_SAE:
			LOG_DBG("ssid: %s has cipher suite WPA3-SAE", scan.ssid);
			scan.security = MM_MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;

		case MM_AKM_SUITE_OWE:
			LOG_DBG("ssid: %s has cipher suite WPA3-OWE -"
				" currently unsupported by Zephyr",
				scan.ssid);
			scan.security = MM_MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;

		case MM_AKM_SUITE_OTHER:
		default:
			LOG_DBG("ssid: %s has an unknown cipher suite - assuming WPA3", scan.ssid);
			scan.security = MM_MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;
		}
	}

scan_cb_end:
	morse->scan_cb(morse->iface, 0, &scan);
	k_yield();
	return;
}

static void scan_complete_callback(enum mmwlan_scan_state state, void *arg)
{
	struct morse_data *morse = arg;
	morse->status = morse->scan_prev_state;
	LOG_DBG("Scanning completed.");
	morse->scan_cb(morse->iface, 0, NULL);
}

static int morse_wlan_boot(struct morse_data *morse)
{
	enum mmwlan_status status;
	const struct mmwlan_s1g_channel_list *channel_list;
	struct mmwlan_boot_args boot_args = MMWLAN_BOOT_ARGS_INIT;

	if (morse->booted) {
		return 0;
	}

	channel_list =
		mmwlan_lookup_regulatory_domain(get_regulatory_db(), CONFIG_WIFI_MORSE_REGION);
	if (channel_list == NULL) {
		LOG_ERR("Could not find specified regulatory domain matching country code %s\n",
			CONFIG_WIFI_MORSE_REGION);
		return -EINVAL;
	}

	LOG_INF("%s lazy_boot_begin", MM_MESH_LOG_PREFIX);
	mmwlan_init();
	status = mmwlan_set_channel_list(channel_list);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s set_channel_list_failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	morse->channel_list = channel_list;
	morse->country_code = CONFIG_WIFI_MORSE_REGION;

	status = mmwlan_boot(&boot_args);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s boot_failed status=%d errno=%d", MM_MESH_LOG_PREFIX,
			status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("%s boot_ok", MM_MESH_LOG_PREFIX);

	status = mmwlan_get_mac_addr(morse->mac_addr);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s get_mac_failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("%s mac=%02x:%02x:%02x:%02x:%02x:%02x",
		MM_MESH_LOG_PREFIX, morse->mac_addr[0], morse->mac_addr[1],
		morse->mac_addr[2], morse->mac_addr[3], morse->mac_addr[4],
		morse->mac_addr[5]);

	status = mmwlan_register_rx_cb(mmnetif_rx, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s register_rx_cb_failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("%s register_rx_cb_ok", MM_MESH_LOG_PREFIX);

	status = mmwlan_register_link_state_cb(mmnetif_link_state, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s register_link_state_cb_failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("%s register_link_state_cb_ok", MM_MESH_LOG_PREFIX);

	status = mmwlan_register_vif_state_cb(MMWLAN_VIF_UNSPECIFIED, mmnetif_vif_state, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s register_vif_state_cb failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
	} else {
		LOG_INF("%s register_vif_state_cb_ok", MM_MESH_LOG_PREFIX);
	}

	status = mmwlan_register_tx_flow_control_cb(mmnetif_tx_flow_control, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s register_tx_flow_control_cb_failed status=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
	} else {
		LOG_INF("%s register_tx_flow_control_cb_ok", MM_MESH_LOG_PREFIX);
	}

	status = mmwlan_get_version(&morse->version);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s get_version_failed status=%d errno=%d", MM_MESH_LOG_PREFIX,
			status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("%s version fw=\"%s\" morselib=\"%s\" chip_id=0x%04x",
		MM_MESH_LOG_PREFIX, morse->version.morse_fw_version,
		morse->version.morselib_version, morse->version.morse_chip_id);

	morse->booted = true;
	morse->status = WIFI_STATE_INACTIVE;
	LOG_INF("%s lazy_boot_ok", MM_MESH_LOG_PREFIX);
	return 0;
}

int morse_mesh_ensure_booted(void)
{
	return morse_wlan_boot(&morse_data0);
}

static int morse_mgmt_scan(const struct device *dev, struct wifi_scan_params *params,
			   scan_result_cb_t cb)
{
	struct morse_data *morse = dev->data;

	enum mmwlan_status status;
	struct mmwlan_scan_req scan_req = MMWLAN_SCAN_REQ_INIT;
	int rc;

	rc = morse_wlan_boot(morse);
	if (rc) {
		return rc;
	}

	morse->scan_cb = cb;
	scan_req.scan_rx_cb = scan_callback;
	scan_req.scan_complete_cb = scan_complete_callback;
	scan_req.scan_cb_arg = morse;
	status = mmwlan_scan_request(&scan_req);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to start scanning");
		return mmwlan_err_to_errno(status);
	}

	morse->scan_prev_state = morse->status;
	morse->status = WIFI_STATE_SCANNING;
	LOG_DBG("Scan started, waiting for results...");
	return 0;
}

static int morse_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct morse_data *morse = dev->data;
	struct mmwlan_sta_args *sta_args = &morse->sta_args;
	enum mmwlan_status status;
	size_t psk_len = 0;
	int rc;

	rc = morse_wlan_boot(morse);
	if (rc) {
		return rc;
	}

	memset(sta_args->passphrase, 0, sizeof(sta_args->passphrase));
	size_t ssid_len = MIN(sizeof(sta_args->ssid), params->ssid_length);
	memcpy((char *)sta_args->ssid, params->ssid, ssid_len);
	sta_args->ssid_len = ssid_len;
	if (!IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) && params->psk && params->psk_length > 0) {
		psk_len = MIN(sizeof(sta_args->passphrase) - 1, params->psk_length);
		memcpy(sta_args->passphrase, params->psk, psk_len);
		sta_args->passphrase[psk_len] = '\0';
	}
	sta_args->passphrase_len = psk_len;

	if (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
		sta_args->security_type = MMWLAN_OPEN;
	} else if (params->security == WIFI_SECURITY_TYPE_SAE) {
		sta_args->security_type = MMWLAN_SAE;
	} else if (params->security == WIFI_SECURITY_TYPE_NONE) {
		sta_args->security_type = MMWLAN_OPEN;
	} else {
		LOG_ERR("Authentication method not supported");
		return -EINVAL;
	}

	switch (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? WIFI_MFP_DISABLE : params->mfp) {
	case WIFI_MFP_DISABLE: {
		sta_args->pmf_mode = MMWLAN_PMF_DISABLED;
		break;
	}
	case WIFI_MFP_OPTIONAL:
	case WIFI_MFP_REQUIRED: {
		sta_args->pmf_mode = MMWLAN_PMF_REQUIRED;
		break;
	}
	default: {
		LOG_WRN("Invalid MFP option");
	}
	}

	LOG_INF("Morse Zephyr %s request %s=\"%.*s\" zephyr_sec=%d zephyr_mfp=%d morse_sec=%d morse_pmf=%d wifi_passphrase_len=%u mesh_cfg=%d",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh" : "connect",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh_id" : "ssid",
		sta_args->ssid_len, sta_args->ssid, params->security, params->mfp,
		sta_args->security_type, sta_args->pmf_mode,
		(unsigned int)sta_args->passphrase_len,
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? 1 : 0);
	LOG_DBG("This may take some time (~30 seconds)");
	LOG_INF("Morse HaLow connect mode=%s ssid=\"%.*s\" security=%d wifi_passphrase_len=%u",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh-open" : "sta",
		sta_args->ssid_len, sta_args->ssid,
		sta_args->security_type, (unsigned int)sta_args->passphrase_len);
	sta_args->mesh_mode = IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE);
	LOG_INF("%s %s %s=\"%.*s\" bearer=%s sec=%d pmf=%d",
		MM_MESH_LOG_PREFIX,
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh_start" : "connect_start",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh_id" : "ssid",
		sta_args->ssid_len, sta_args->ssid,
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "open" : "sta",
		sta_args->security_type, sta_args->pmf_mode);
	LOG_INF("%s sta_args mesh_mode=%u scan_retry=%u..%us bgscan=%u/%u",
		MM_MESH_LOG_PREFIX, sta_args->mesh_mode ? 1U : 0U,
		sta_args->scan_interval_base_s, sta_args->scan_interval_limit_s,
		sta_args->bgscan_short_interval_s, sta_args->bgscan_long_interval_s);

	status = mmwlan_sta_enable(sta_args, NULL);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s connect_rejected mmwlan_sta_enable=%d errno=%d",
			MM_MESH_LOG_PREFIX, status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}
	LOG_INF("Morse Zephyr mmwlan_sta_enable accepted mode=%s",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh-open" : "sta");
	LOG_INF("%s connect_accepted", MM_MESH_LOG_PREFIX);

	return 0;
}

static int morse_mgmt_disconnect(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	enum mmwlan_status status;

	if (!morse->booted) {
		wifi_mgmt_raise_disconnect_result_event(morse->iface, WIFI_REASON_DISCONN_SUCCESS);
		return 0;
	}

	status = mmwlan_sta_disable();

	if (status != MMWLAN_SUCCESS && status != MMWLAN_SHUTDOWN_BLOCKED) {
		LOG_ERR("Failed to stop %s", IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? "mesh" : "STA");
		return mmwlan_err_to_errno(status);
	}

	wifi_mgmt_raise_disconnect_result_event(morse->iface, WIFI_REASON_DISCONN_SUCCESS);
	return 0;
}

static int morse_mgmt_iface_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct morse_data *morse = dev->data;
	enum mmwlan_sta_state sta_state;

	if (!morse->booted) {
		status->state = morse->status;
		goto fill_cached_status;
	}

	if (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
		sta_state = mmwlan_get_sta_state();
		status->state = morse_sta_to_wifi_state(sta_state);
		LOG_INF("%s iface_status mesh_sta=%s(%d)", MM_MESH_LOG_PREFIX,
			sta_state_name(sta_state), (int)sta_state);
	} else {
		status->state = morse->status;
	}

fill_cached_status:
	strncpy(status->ssid, morse->sta_args.ssid, WIFI_SSID_MAX_LEN);
	status->ssid_len = morse->sta_args.ssid_len;
	status->iface_mode = WIFI_MODE_INFRA;
	status->band = WIFI_FREQ_BAND_UNKNOWN;
	status->link_mode = WIFI_LINK_MODE_UNKNOWN;
	status->mfp = morse->sta_args.pmf_mode == MMWLAN_PMF_DISABLED ? WIFI_MFP_DISABLE
								      : WIFI_MFP_REQUIRED;

	switch (morse->sta_args.security_type) {
	case MMWLAN_OPEN:
		status->security = WIFI_SECURITY_TYPE_NONE;
		break;
	case MMWLAN_SAE:
		status->security = WIFI_SECURITY_TYPE_SAE;
		break;
	default:
		status->security = WIFI_SECURITY_TYPE_UNKNOWN;
	}

	if (morse->status == WIFI_STATE_COMPLETED) {
		status->rssi = mmwlan_get_rssi();
		if (mmwlan_get_bssid(status->bssid) != MMWLAN_SUCCESS) {
			LOG_ERR("Could not get AP BSSID");
		}
		status->link_mode = WIFI_LINK_MODE_UNKNOWN;

		/* Currently no simple way to get this information from the mmwlan APIs. */
		status->channel = 0;
		status->beacon_interval = 0;
	}

	return 0;
}

static int morse_mgmt_get_version(const struct device *dev, struct wifi_version *params)
{
	struct morse_data *morse = dev->data;
	int rc;

	rc = morse_wlan_boot(morse);
	if (rc) {
		return rc;
	}

	params->drv_version = morse->version.morselib_version;
	params->fw_version = morse->version.morse_fw_version;
	return 0;
}

static int mmnetif_tx(const struct device *dev, struct net_pkt *pkt)
{
	struct morse_data *morse = dev->data;
	int rc;

	rc = morse_wlan_boot(morse);
	if (rc) {
		return rc;
	}

	LOG_INF("%s TX entry len=%u iface=%p", MM_MESH_LOG_PREFIX,
		(unsigned int)net_pkt_get_len(pkt), morse->iface);

	if (net_pkt_get_len(pkt) > NET_ETH_MAX_FRAME_SIZE) {
		LOG_ERR("%s TX drop too_large len=%u", MM_MESH_LOG_PREFIX,
			(unsigned int)net_pkt_get_len(pkt));
		return -ENOMEM;
	}

	const int pkt_len = net_pkt_get_len(pkt);
	struct mmwlan_tx_metadata metadata = MMWLAN_TX_METADATA_INIT;
	struct mmpkt *mmpkt;
	struct mmpktview *pktview;

	int ret = net_pkt_read(pkt, morse->frame_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("Failed to read packet buffer");
		return ret;
	}

#if defined(CONFIG_WIFI_MORSE_MESH_TRAFFIC_LOG)
	log_mesh_frame_summary("TX", morse->frame_buf, pkt_len);
#endif

	enum mmwlan_status status = mmwlan_tx_wait_until_ready(MMWLAN_TX_DEFAULT_TIMEOUT_MS);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s TX not_ready status=%d errno=%d", MM_MESH_LOG_PREFIX,
			status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}

	mmpkt = mmwlan_alloc_mmpkt_for_tx(pkt_len, metadata.tid);
	if (mmpkt == NULL) {
		LOG_ERR("%s TX drop alloc_failed len=%d", MM_MESH_LOG_PREFIX, pkt_len);
		return -ENOMEM;
	}

	pktview = mmpkt_open(mmpkt);
	mmpkt_append_data(pktview, morse->frame_buf, pkt_len);
	mmpkt_close(&pktview);

	metadata.vif = MMWLAN_VIF_UNSPECIFIED;
	status = mmwlan_tx_pkt(mmpkt, &metadata);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s TX send_failed status=%d errno=%d", MM_MESH_LOG_PREFIX,
			status, mmwlan_err_to_errno(status));
		return mmwlan_err_to_errno(status);
	}

	LOG_INF("Morse Zephyr TX queued len=%d vif=%d", pkt_len, metadata.vif);
	LOG_INF("%s TX queued len=%d vif=%d", MM_MESH_LOG_PREFIX, pkt_len, metadata.vif);

	return 0;
};

static void mmnetif_rx(uint8_t *header, unsigned header_len, uint8_t *payload, unsigned payload_len,
		       void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	struct net_pkt *pkt;

	NET_ASSERT(morse != NULL);
	LOG_INF("%s RX raw_callback iface=%p header_len=%u payload_len=%u",
		MM_MESH_LOG_PREFIX, morse->iface, header_len, payload_len);
	if (morse->iface == NULL) {
		LOG_ERR("%s RX drop no_iface", MM_MESH_LOG_PREFIX);
		return;
	}

#if defined(CONFIG_WIFI_MORSE_MESH_TRAFFIC_LOG)
	log_mesh_rx_frame(header, header_len, payload, payload_len);
#endif

	if (header_len >= MM_MESH_ETH_HEADER_LEN &&
	    get_be16(&header[12]) == ETH_TYPE_MESHTASTIC_HALOW) {
		LOG_INF("%s raw_rx ethertype=0x%04x radio_len=%u cb=%u",
			MM_MESH_LOG_PREFIX, ETH_TYPE_MESHTASTIC_HALOW, payload_len,
			mesh_rx_cb ? 1U : 0U);
		if (mesh_rx_cb) {
			int32_t rssi = mmwlan_get_rssi();
			log_halow_radio_frame("RX", payload, payload_len);

			mesh_rx_cb(payload, payload_len,
				   rssi == INT32_MIN ? 0 : (int8_t)rssi,
				   mesh_rx_user_data);
		}
		return;
	}

	pkt = net_pkt_rx_alloc_with_buffer(morse->iface, header_len + payload_len, AF_UNSPEC, 0,
					   K_MSEC(200));
	if (!pkt) {
		LOG_ERR("%s RX drop alloc_failed total_len=%u",
			MM_MESH_LOG_PREFIX, header_len + payload_len);
		return;
	}

	if (net_pkt_write(pkt, header, header_len) < 0) {
		LOG_ERR("Failed to write packet header");
		goto pkt_unref;
	}

	if (net_pkt_write(pkt, payload, payload_len) < 0) {
		LOG_ERR("Failed to write packet data");
		goto pkt_unref;
	}

	if (net_recv_data(morse->iface, pkt) < 0) {
		LOG_ERR("%s RX drop net_recv_failed", MM_MESH_LOG_PREFIX);
		goto pkt_unref;
	}

	LOG_INF("%s RX delivered total_len=%u", MM_MESH_LOG_PREFIX, header_len + payload_len);
	return;

pkt_unref:
	net_pkt_unref(pkt);
	return;
}

static void mmnetif_link_state(enum mmwlan_link_state link_state, void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	atomic_inc(&mac_link_state_events);
	int64_t seq = (int64_t)atomic_get(&mac_link_state_events);
	enum mmwlan_link_state previous =
		(enum mmwlan_link_state)atomic_set(&mac_last_link_state, (atomic_val_t)link_state);

	NET_ASSERT(morse != NULL);
	if (!morse->iface) {
		LOG_WRN("%s link_state=%s iface not ready", MM_MESH_LOG_PREFIX,
			link_state_name(link_state));
		morse->status = (link_state == MMWLAN_LINK_UP) ? WIFI_STATE_COMPLETED : WIFI_STATE_INACTIVE;
		return;
	}
	LOG_INF("%s link_state seq=%lld state=%s(%d) previous=%s(%d) prev_wifi_state=%d iface=%p",
		MM_MESH_LOG_PREFIX,
		seq,
		link_state == MMWLAN_LINK_DOWN ? "down" : "up",
		link_state, link_state_name(previous), (int)previous, morse->status, morse->iface);

	if (link_state == MMWLAN_LINK_DOWN) {
		net_if_dormant_on(morse->iface);
		if (IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
			LOG_INF("%s mesh_link_down awaiting mesh traffic/peer", MM_MESH_LOG_PREFIX);
		} else if (morse->status == WIFI_STATE_INACTIVE) {
			wifi_mgmt_raise_connect_result_event(morse->iface, WIFI_STATUS_CONN_FAIL);
		}
		morse->status = WIFI_STATE_INACTIVE;
	} else {
		net_if_dormant_off(morse->iface);
#if defined(CONFIG_NET_DHCPV4)
		if (!IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE)) {
			net_dhcpv4_restart(morse->iface);
		}
#endif /* defined(CONFIG_NET_DHCPV4) */
		wifi_mgmt_raise_connect_result_event(morse->iface, WIFI_STATUS_CONN_SUCCESS);
		morse->status = WIFI_STATE_COMPLETED;
	}
}

static void mmnetif_vif_state(const struct mmwlan_vif_state *state, void *arg)
{
	if (!state) {
		return;
	}
	atomic_inc(&mac_vif_state_events);
	int64_t seq = (int64_t)atomic_get(&mac_vif_state_events);
	enum mmwlan_link_state previous;
	if (state->vif == MMWLAN_VIF_STA) {
		previous = (enum mmwlan_link_state)atomic_set(&mac_last_vif_link_state_sta,
			(atomic_val_t)state->link_state);
	} else if (state->vif == MMWLAN_VIF_AP) {
		previous = (enum mmwlan_link_state)atomic_set(&mac_last_vif_link_state_ap,
			(atomic_val_t)state->link_state);
	} else {
		previous = MMWLAN_LINK_DOWN;
	}

	LOG_INF("%s vif_state seq=%lld vif=%s(%d) link=%s(%d) prev_link=%s(%d)",
		MM_MESH_LOG_PREFIX, seq, mmwlan_vif_name(state->vif), (int)state->vif,
		link_state_name(state->link_state),
		(int)state->link_state, link_state_name(previous), (int)previous);
	LOG_INF("%s vif_state last sta=%s(%d) ap=%s(%d)",
		MM_MESH_LOG_PREFIX,
		link_state_name((enum mmwlan_link_state)atomic_get(&mac_last_vif_link_state_sta)),
		(int)atomic_get(&mac_last_vif_link_state_sta),
		link_state_name((enum mmwlan_link_state)atomic_get(&mac_last_vif_link_state_ap)),
		(int)atomic_get(&mac_last_vif_link_state_ap));
	mmnetif_link_state(state->link_state, arg);
}

static void morse_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct morse_data *morse = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	if (morse->iface) {
		return;
	}

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	morse->iface = iface;

	morse->status = WIFI_STATE_INTERFACE_DISABLED;

	LOG_DBG("%s: initialising morse interface\n", __func__);

	morse->mac_addr[0] = 0x02;
	morse->mac_addr[1] = 0x00;
	morse->mac_addr[2] = 0x00;
	morse->mac_addr[3] = 0x00;
	morse->mac_addr[4] = 0x00;
	morse->mac_addr[5] = 0x00;

	if (net_if_set_link_addr(iface, morse->mac_addr, MMWLAN_MAC_ADDR_LEN, NET_LINK_ETHERNET)) {
		LOG_ERR("Failed to set link address");
	}

	/* Initialize Ethernet L2 stack */
	ethernet_init(morse->iface);

	/* Not currently connected to a network */
	net_if_dormant_on(morse->iface);

	/* L1 network layer (physical layer) is up */
	net_if_carrier_on(morse->iface);

	morse->status = WIFI_STATE_INACTIVE;
	struct mmwlan_sta_args init_args = MMWLAN_STA_ARGS_INIT;
	memcpy(&morse->sta_args, &init_args, sizeof(struct mmwlan_sta_args));
	LOG_INF("Morse Zephyr iface init lazy_boot=1 mesh_cfg=%d net_if=%p",
		IS_ENABLED(CONFIG_WIFI_MORSE_MESH_MODE) ? 1 : 0, morse->iface);
}

static int morse_pm_action(const struct device *dev, enum pm_device_action action)
{
	ARG_UNUSED(dev);
	switch (action) {
	case PM_DEVICE_ACTION_SUSPEND:
		if (mmhal_get_deep_sleep_veto() != 0) {
			return -EBUSY;
		}
		break;
	case PM_DEVICE_ACTION_RESUME:
	case PM_DEVICE_ACTION_TURN_OFF:
	case PM_DEVICE_ACTION_TURN_ON:
		break;
	}
	return 0;
}

static int morse_init(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	const struct morse_config *cfg = dev->config;

	morse_dev = dev;

	morse->status = WIFI_STATE_DISCONNECTED;
	LOG_DBG("");

	if (!spi_is_ready_dt(&cfg->spi)) {
		LOG_ERR("SPI bus %s not ready", cfg->spi.bus->name);
		return -ENODEV;
	}

	if (!gpio_is_ready_dt(&cfg->resetn)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->resetn.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->resetn, GPIO_OUTPUT_INACTIVE);

	if (!gpio_is_ready_dt(&cfg->wakeup)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->wakeup.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->wakeup, GPIO_OUTPUT_ACTIVE);

	if (!gpio_is_ready_dt(&cfg->busy)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->busy.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->busy, GPIO_INPUT);

	if (!gpio_is_ready_dt(&cfg->spi_irq)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->spi_irq.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->spi_irq, GPIO_INPUT | GPIO_PULL_UP);

	gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_DISABLE);

	gpio_init_callback(&morse->busy_cb, morse_busy_cb, BIT(cfg->busy.pin));
	gpio_add_callback(cfg->busy.port, &morse->busy_cb);

	gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_DISABLE);

	gpio_init_callback(&morse->spi_irq_cb, morse_spi_irq_cb, BIT(cfg->spi_irq.pin));
	gpio_add_callback(cfg->spi_irq.port, &morse->spi_irq_cb);

	return 0;
}

static const struct wifi_mgmt_ops morse_mgmt_api = {
	.scan = morse_mgmt_scan,
	.connect = morse_mgmt_connect,
	.disconnect = morse_mgmt_disconnect,
	.iface_status = morse_mgmt_iface_status,
	.get_version = morse_mgmt_get_version,
};

static const struct net_wifi_mgmt_offload morse_api = {
	.wifi_iface.iface_api.init = morse_iface_init,
	.wifi_iface.send = mmnetif_tx,
	.wifi_mgmt_api = &morse_mgmt_api,
};

const struct morse_config conf = {
	.spi = SPI_DT_SPEC_INST_GET(0,
				    (SPI_LOCK_ON | SPI_OP_MODE_MASTER | SPI_TRANSFER_MSB |
				     SPI_WORD_SET(SPI_FRAME_BITS)),
				    0),
	.resetn = GPIO_DT_SPEC_INST_GET(0, resetn_gpios),
	.wakeup = GPIO_DT_SPEC_INST_GET(0, wakeup_gpios),
	.busy = GPIO_DT_SPEC_INST_GET(0, busy_gpios),
	.spi_irq = GPIO_DT_SPEC_INST_GET(0, spi_irq_gpios),
};

#ifndef CONFIG_WIFI_MORSE_TEST

PM_DEVICE_DT_INST_DEFINE(0, morse_pm_action);
NET_DEVICE_DT_INST_DEFINE(0, morse_init, PM_DEVICE_DT_INST_GET(0), &morse_data0, &conf,
			  CONFIG_WIFI_INIT_PRIORITY, &morse_api, ETHERNET_L2,
			  NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

CONNECTIVITY_WIFI_MGMT_BIND(Z_DEVICE_DT_DEV_ID(DT_DRV_INST(0)));

#else

DEVICE_DT_INST_DEFINE(0, morse_init, NULL, &morse_data0, &conf, POST_KERNEL,
		      CONFIG_WIFI_INIT_PRIORITY, NULL);

#endif /* CONFIG_WIFI_MORSE_TEST */

const struct morse_config *morse_config0 = &conf;
