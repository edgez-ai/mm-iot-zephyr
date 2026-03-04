/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT morse_spi
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
#include <zephyr/net/net_if.h>
#include <zephyr/net/dhcpv4.h>
#include <zephyr/sys/byteorder.h>

#include "morse.h"
#include "mmosal.h"
#include "mmwlan.h"
#include "regdb.h"
#include "mmutils.h"

/* 8-bit frames */
#define SPI_FRAME_BITS 8

const struct morse_config morse_config0 = {
	.spi = SPI_DT_SPEC_INST_GET(0,
                                    (SPI_LOCK_ON | SPI_OP_MODE_MASTER | SPI_TRANSFER_MSB |
                                     SPI_WORD_SET(SPI_FRAME_BITS)),
                                    0),
	.resetn = GPIO_DT_SPEC_INST_GET(0, resetn_gpios),
	.wakeup = GPIO_DT_SPEC_INST_GET(0, wakeup_gpios),
	.busy = GPIO_DT_SPEC_INST_GET(0, busy_gpios),
	.spi_irq = GPIO_DT_SPEC_INST_GET(0, spi_irq_gpios),
};

struct morse_data morse_data0;

extern void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern void morse_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern volatile uint32_t mmhal_spi_irq_poll_interval;

static uint32_t dhcp_tx_count;
static uint32_t dhcp_rx_count;

static bool is_private_ipv4(uint32_t net_order_ip)
{
	uint8_t a = (uint8_t)(net_order_ip >> 24);
	uint8_t b = (uint8_t)(net_order_ip >> 16);

	if (a == 10U) {
		return true;
	}
	if (a == 172U && b >= 16U && b <= 31U) {
		return true;
	}
	if (a == 192U && b == 168U) {
		return true;
	}

	return false;
}

static uint32_t select_net_order_ipv4(uint32_t raw)
{
	uint32_t direct = raw;
	uint32_t swapped = sys_cpu_to_be32(raw);

	if (is_private_ipv4(direct) && !is_private_ipv4(swapped)) {
		return direct;
	}
	if (is_private_ipv4(swapped) && !is_private_ipv4(direct)) {
		return swapped;
	}

	return direct;
}

static struct in_addr to_in_addr(uint32_t raw)
{
	struct in_addr addr = {0};
	uint32_t net_ip = select_net_order_ipv4(raw);

	sys_put_be32(net_ip, &addr.s4_addr[0]);
	return addr;
}

static void morse_apply_dhcp_lease_work(struct k_work *work)
{
	struct morse_data *morse = CONTAINER_OF(work, struct morse_data, dhcp_lease_work);
	struct net_if *iface = morse->iface;

	if (!iface) {
		LOG_WRN("DHCP offload lease received but iface is NULL");
		return;
	}

	struct in_addr ip = to_in_addr(morse->dhcp_lease.ip4_addr);
	struct in_addr mask = to_in_addr(morse->dhcp_lease.mask4_addr);
	struct in_addr gw = to_in_addr(morse->dhcp_lease.gw4_addr);

	net_dhcpv4_stop(iface);

	if (!net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED) &&
	    !net_if_ipv4_addr_add(iface, &ip, NET_ADDR_DHCP, 0)) {
		LOG_ERR("DHCP offload: failed to apply IPv4 lease");
		return;
	}

	if (!net_if_ipv4_set_netmask_by_addr(iface, &ip, &mask)) {
		LOG_WRN("DHCP offload: failed to set netmask");
	}

	net_if_ipv4_set_gw(iface, &gw);

	LOG_INF("DHCP offload lease applied: %u.%u.%u.%u gw %u.%u.%u.%u",
		ip.s4_addr[0], ip.s4_addr[1], ip.s4_addr[2], ip.s4_addr[3],
		gw.s4_addr[0], gw.s4_addr[1], gw.s4_addr[2], gw.s4_addr[3]);
}

static void morse_dhcp_lease_update_cb(const struct mmwlan_dhcp_lease_info *lease_info, void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;

	if (!morse || !lease_info) {
		return;
	}

	morse->dhcp_lease = *lease_info;
	LOG_INF("DHCP offload lease update received");
	k_work_submit(&morse->dhcp_lease_work);
}

static const char *dhcp_type_str(uint8_t type)
{
	switch (type) {
	case 1:
		return "DISCOVER";
	case 2:
		return "OFFER";
	case 3:
		return "REQUEST";
	case 4:
		return "DECLINE";
	case 5:
		return "ACK";
	case 6:
		return "NAK";
	case 7:
		return "RELEASE";
	case 8:
		return "INFORM";
	default:
		return "UNKNOWN";
	}
}

static void morse_trace_dhcp_frame(const char *dir, const uint8_t *frame, size_t len)
{
	if (!frame || len < 14U) {
		return;
	}

	uint16_t eth_type = sys_get_be16(&frame[12]);
	if (eth_type != 0x0800U) {
		return;
	}

	if (len < 34U) {
		return;
	}

	uint8_t ihl = (frame[14] & 0x0fU) * 4U;
	if (ihl < 20U || (14U + ihl + 8U) > len) {
		return;
	}

	uint8_t proto = frame[23];
	if (proto != 17U) {
		return;
	}

	const uint8_t *udp = &frame[14 + ihl];
	uint16_t src_port = sys_get_be16(&udp[0]);
	uint16_t dst_port = sys_get_be16(&udp[2]);

	if (!((src_port == 67U && dst_port == 68U) ||
	      (src_port == 68U && dst_port == 67U))) {
		return;
	}

	if (dir[0] == 'T') {
		dhcp_tx_count++;
	} else {
		dhcp_rx_count++;
	}

	const uint8_t *dhcp = &udp[8];
	size_t dhcp_len = len - (14U + ihl + 8U);
	uint32_t xid = 0U;
	uint8_t msg_type = 0U;
	uint8_t yi0 = 0U, yi1 = 0U, yi2 = 0U, yi3 = 0U;

	if (dhcp_len >= 20U) {
		xid = sys_get_be32(&dhcp[4]);
		yi0 = dhcp[16];
		yi1 = dhcp[17];
		yi2 = dhcp[18];
		yi3 = dhcp[19];
	}

	if (dhcp_len >= 244U && dhcp[236] == 99U && dhcp[237] == 130U &&
	    dhcp[238] == 83U && dhcp[239] == 99U) {
		size_t idx = 240U;
		while (idx < dhcp_len) {
			uint8_t opt = dhcp[idx++];
			if (opt == 0U) {
				continue;
			}
			if (opt == 255U) {
				break;
			}
			if (idx >= dhcp_len) {
				break;
			}
			uint8_t opt_len = dhcp[idx++];
			if ((idx + opt_len) > dhcp_len) {
				break;
			}
			if (opt == 53U && opt_len >= 1U) {
				msg_type = dhcp[idx];
				break;
			}
			idx += opt_len;
		}
	}

	LOG_INF("DHCP %s #%u %s xid=0x%08x yiaddr=%u.%u.%u.%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u len=%u",
		dir,
		dir[0] == 'T' ? dhcp_tx_count : dhcp_rx_count,
		dhcp_type_str(msg_type),
		(unsigned)xid,
		yi0, yi1, yi2, yi3,
		frame[26], frame[27], frame[28], frame[29], src_port,
		frame[30], frame[31], frame[32], frame[33], dst_port,
		(unsigned)len);
}

/**
 * Scan rx callback.
 *
 * @param result        Pointer to the scan result.
 * @param arg           Opaque argument.
 */
static void scan_callback(const struct mmwlan_scan_result *result, void *arg)
{
	struct morse_data *morse = arg;
	struct wifi_scan_result scan;
	struct mm_rsn_information rsn_info;
	struct mm_s1g_operation s1g_operation;
	int ii;

	LOG_DBG("scan_callback: received result for BSSID %02x:%02x:%02x:%02x:%02x:%02x SSID=%.*s rssi=%d",
	        result->bssid[0], result->bssid[1], result->bssid[2],
	        result->bssid[3], result->bssid[4], result->bssid[5],
	        result->ssid_len, result->ssid, result->rssi);

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

	switch (scan.mfp) {
	case WIFI_MFP_REQUIRED:
		morse->sta_args.pmf_mode = MMWLAN_PMF_REQUIRED;
		break;
	default:
		morse->sta_args.pmf_mode = MMWLAN_PMF_DISABLED;
		break;
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

/**
 * Scan complete callback.
 *
 * @param state         Scan complete status.
 * @param arg           Opaque argument.
 */
static void scan_complete_callback(enum mmwlan_scan_state state, void *arg)
{
	struct morse_data *morse = arg;
	morse->scanning = false;
	LOG_DBG("Scanning completed.");
	morse->scan_cb(morse->iface, 0, NULL);
}

static int morse_mgmt_scan(const struct device *dev, struct wifi_scan_params *params,
                           scan_result_cb_t cb)
{
	struct morse_data *morse = dev->data;

	enum mmwlan_status status;
	struct mmwlan_scan_req scan_req = MMWLAN_SCAN_REQ_INIT;

	if (params) {
		LOG_ERR("wifi_scan_params not supported");
	}

	LOG_DBG("Starting scan with region %s, %d channels available",
	        morse->country_code, morse->channel_list ? morse->channel_list->num_channels : 0);

	morse->scan_cb = cb;
	scan_req.scan_rx_cb = scan_callback;
	scan_req.scan_complete_cb = scan_complete_callback;
	scan_req.scan_cb_arg = morse;
	status = mmwlan_scan_request(&scan_req);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to start scanning: status=%d", status);
		return -EIO;
	}

	morse->scanning = true;
	LOG_DBG("Scan started, waiting for results...");
	return 0;
}

static int morse_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct morse_data *morse = dev->data;
	struct mmwlan_sta_args *sta_args = &morse->sta_args;
	enum mmwlan_status status;

	memcpy((char *)sta_args->ssid, params->ssid, params->ssid_length);
	sta_args->ssid_len = params->ssid_length;

	if (params->security == WIFI_SECURITY_TYPE_SAE) {
		memcpy(sta_args->passphrase, params->psk, params->psk_length);
		sta_args->passphrase_len = params->psk_length;
		sta_args->security_type = MMWLAN_SAE;
	} else if (params->security == WIFI_SECURITY_TYPE_NONE) {
		sta_args->security_type = MMWLAN_OPEN;
	} else {
		LOG_ERR("Authentication method not supported");
		return -EIO;
	}

	LOG_DBG("Attempting to connect to %s with passphrase %s", sta_args->ssid,
	        sta_args->passphrase);
	LOG_DBG("This may take some time (~30 seconds)");

	status = mmwlan_sta_enable(sta_args, NULL);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s: mmwlan_sta_enable returned %d", __func__, status);
		return -EAGAIN;
	}

	return 0;
}

static int morse_mgmt_disconnect(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	int ret = mmwlan_sta_disable();

	if (ret != MMWLAN_SUCCESS && ret != MMWLAN_SHUTDOWN_BLOCKED) {
		LOG_ERR("Failed to disconnect from AP");
		return -EAGAIN;
	}

	wifi_mgmt_raise_disconnect_result_event(morse->iface, WIFI_REASON_DISCONN_SUCCESS);
	return 0;
}

static int morse_mgmt_iface_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct morse_data *morse = dev->data;

	status->state = morse->status;
	if (morse->scanning) {
		status->state = WIFI_STATE_SCANNING;
	}

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

		// Currently no simple way to get this information from the mmwlan
		// APIs.
		status->channel = 0;
		status->beacon_interval = 0;
	}

	return 0;
}

static int mmnetif_tx(const struct device *dev, struct net_pkt *pkt)
{
	struct morse_data *morse = dev->data;
	const int pkt_len = net_pkt_get_len(pkt);

	if (net_pkt_read(pkt, morse->frame_buf, pkt_len) < 0) {
		LOG_ERR("Failed to read packet buffer");
		return -EIO;
	}

	morse_trace_dhcp_frame("TX", morse->frame_buf, pkt_len);

	enum mmwlan_status status = mmwlan_tx(morse->frame_buf, pkt_len);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to send packet - %d", status);
		return -EIO;
	}

	LOG_DBG("Packet sent");

	return 0; // pkt_len;
};

static void mmnetif_rx(uint8_t *header, unsigned header_len, uint8_t *payload, unsigned payload_len,
                       void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	struct net_pkt *pkt;
	uint8_t frame_preview[384];
	unsigned frame_len = header_len + payload_len;

	NET_ASSERT(morse != NULL);
	if (morse->iface == NULL) {
		LOG_ERR("Unhandled packet, network interface unavailable");
		return;
	}

	if (frame_len > 0U) {
		unsigned copy_h = header_len > sizeof(frame_preview) ? sizeof(frame_preview) : header_len;
		unsigned copy_p = 0U;

		memcpy(frame_preview, header, copy_h);
		if (copy_h < sizeof(frame_preview) && payload_len > 0U) {
			copy_p = payload_len > (sizeof(frame_preview) - copy_h)
				? (sizeof(frame_preview) - copy_h)
				: payload_len;
			memcpy(&frame_preview[copy_h], payload, copy_p);
		}

		morse_trace_dhcp_frame("RX", frame_preview, copy_h + copy_p);
	}

	pkt = net_pkt_rx_alloc_with_buffer(morse->iface, header_len + payload_len, AF_UNSPEC, 0,
	                                   K_MSEC(200));
	if (!pkt) {
		LOG_ERR("Failed to allocate packet buffer");
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
		LOG_ERR("Failed to propagate packet");
		goto pkt_unref;
	}

	return;

pkt_unref:
	net_pkt_unref(pkt);
	return;
}

static void mmnetif_link_state(enum mmwlan_link_state link_state, void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	NET_ASSERT(morse != NULL);

	LOG_INF("Morse link state event: %s", link_state == MMWLAN_LINK_DOWN ? "DOWN" : "UP");

	if (link_state == MMWLAN_LINK_DOWN) {
		net_if_dormant_on(morse->iface);
		if (morse->status == WIFI_STATE_INACTIVE) {
			wifi_mgmt_raise_connect_result_event(morse->iface, WIFI_STATUS_CONN_FAIL);
		}
		morse->status = WIFI_STATE_INACTIVE;
	} else {
		net_if_dormant_off(morse->iface);

		#if !IS_ENABLED(CONFIG_NET_DHCPV4)
		if (!morse->dhcp_offload_enabled) {
			enum mmwlan_status status =
				mmwlan_enable_dhcp_offload(morse_dhcp_lease_update_cb, morse);
			if (status == MMWLAN_SUCCESS) {
				morse->dhcp_offload_enabled = true;
				LOG_INF("Morse DHCP offload enabled (link up)");
			} else {
				LOG_WRN("Failed to enable Morse DHCP offload on link up: %d", status);
			}
		}
		#else
		LOG_DBG("Zephyr DHCPv4 enabled; skipping Morse DHCP offload");
		#endif

		wifi_mgmt_raise_connect_result_event(morse->iface, WIFI_STATUS_CONN_SUCCESS);
		morse->status = WIFI_STATE_COMPLETED;
	}
}

static void morse_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct morse_data *morse = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	morse->iface = iface;

	enum mmwlan_status status;
	struct mmwlan_version version;
	const struct mmwlan_s1g_channel_list *channel_list;

	if (morse->status > WIFI_STATE_DISCONNECTED) {
		return;
	}

	// mmhal_spi_irq_poll_interval = 300;

	LOG_DBG("%s: initialising morse interface\n", __func__);

	channel_list =
		mmwlan_lookup_regulatory_domain(get_regulatory_db(), CONFIG_WIFI_MORSE_REGION);

	if (channel_list == NULL) {
		LOG_ERR("Could not find specified regulatory domain matching country code %s\n",
		        CONFIG_WIFI_MORSE_REGION);
		NET_ASSERT(false);
	}

	LOG_INF("Using region %s with %d channels", 
	        channel_list->country_code, channel_list->num_channels);

	/* Initialize MMWLAN interface */
	mmwlan_init();
	#if !IS_ENABLED(CONFIG_NET_DHCPV4)
	k_work_init(&morse->dhcp_lease_work, morse_apply_dhcp_lease_work);
	#endif
	mmwlan_set_channel_list(channel_list);
	morse->channel_list = channel_list;
	morse->country_code = CONFIG_WIFI_MORSE_REGION;

	/* Boot the transceiver so that we can read the MAC address. */
	struct mmwlan_boot_args boot_args = MMWLAN_BOOT_ARGS_INIT;
	status = mmwlan_boot(&boot_args);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_boot failed with code %d\n", status);
	}
	NET_ASSERT(status == MMWLAN_SUCCESS);

	/* Set MAC hardware address */
	status = mmwlan_get_mac_addr(morse->mac_addr);
	NET_ASSERT(status == MMWLAN_SUCCESS);

	/* Assign link local address. */
	if (net_if_set_link_addr(iface, morse->mac_addr, MMWLAN_MAC_ADDR_LEN, NET_LINK_ETHERNET)) {
		LOG_ERR("Failed to set link addr");
	}

	status = mmwlan_register_rx_cb(mmnetif_rx, morse);
	NET_ASSERT(status == MMWLAN_SUCCESS);
	status = mmwlan_register_link_state_cb(mmnetif_link_state, morse);
	NET_ASSERT(status == MMWLAN_SUCCESS);

	#if !IS_ENABLED(CONFIG_NET_DHCPV4)
	if (!morse->dhcp_offload_enabled) {
		status = mmwlan_enable_dhcp_offload(morse_dhcp_lease_update_cb, morse);
		if (status == MMWLAN_SUCCESS) {
			morse->dhcp_offload_enabled = true;
			LOG_INF("Morse DHCP offload enabled");
		} else {
			LOG_WRN("Failed to enable Morse DHCP offload: %d", status);
		}
	}
	#endif

	/* Disable power save mode to ensure firmware responds to scan/connect requests */
	status = mmwlan_set_power_save_mode(MMWLAN_PS_DISABLED);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to disable power save mode: %d", status);
	} else {
		LOG_INF("Power save mode disabled");
	}


	LOG_ERR("Morse LwIP interface initialised. MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
	        morse->mac_addr[0], morse->mac_addr[1], morse->mac_addr[2], morse->mac_addr[3],
	        morse->mac_addr[4], morse->mac_addr[5]);

	status = mmwlan_get_version(&version);
	NET_ASSERT(status == MMWLAN_SUCCESS);
	LOG_ERR("Morse firmware version %s, morselib version %s, Morse chip ID 0x%04x\n\n",
	        version.morse_fw_version, version.morselib_version, version.morse_chip_id);

	/* Print BCF metadata for debugging */
	struct mmwlan_bcf_metadata bcf_meta;
	status = mmwlan_get_bcf_metadata(&bcf_meta);
	if (status == MMWLAN_SUCCESS) {
		LOG_INF("BCF version %u.%u.%u, board: %s, build: %s",
		        bcf_meta.version.major, bcf_meta.version.minor, bcf_meta.version.patch,
		        bcf_meta.board_desc, bcf_meta.build_version);
	} else {
		LOG_WRN("Failed to read BCF metadata: %d", status);
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
}

static int morse_init(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	const struct morse_config *cfg = dev->config;

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
	gpio_pin_configure_dt(&cfg->resetn, GPIO_OUTPUT_INACTIVE | cfg->resetn.dt_flags);

	if (!gpio_is_ready_dt(&cfg->wakeup)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->wakeup.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->wakeup, GPIO_OUTPUT_ACTIVE | cfg->wakeup.dt_flags);

	if (!gpio_is_ready_dt(&cfg->busy)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->busy.port->name);
		return -ENODEV;
	}
	/* Honor DT flags (e.g., active_low and pulls) so logic matches board wiring. */
	gpio_pin_configure_dt(&cfg->busy, GPIO_INPUT | cfg->busy.dt_flags);

	if (!gpio_is_ready_dt(&cfg->spi_irq)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->spi_irq.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->spi_irq, GPIO_INPUT | cfg->spi_irq.dt_flags);

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
};

static const struct net_wifi_mgmt_offload morse_api = {
	.wifi_iface.iface_api.init = morse_iface_init,
	.wifi_iface.send = mmnetif_tx,
	.wifi_mgmt_api = &morse_mgmt_api,
};

#ifndef CONFIG_WIFI_MORSE_TEST

NET_DEVICE_DT_INST_DEFINE(0, morse_init, NULL, &morse_data0, &morse_config0,
                          CONFIG_WIFI_INIT_PRIORITY, &morse_api, ETHERNET_L2,
                          NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

CONNECTIVITY_WIFI_MGMT_BIND(Z_DEVICE_DT_DEV_ID(DT_DRV_INST(0)));

#else

DEVICE_DT_INST_DEFINE(0, morse_init, NULL, &morse_data0, &morse_config0, POST_KERNEL,
                      CONFIG_WIFI_INIT_PRIORITY, NULL);

#endif /* CONFIG_WIFI_MORSE_TEST */
