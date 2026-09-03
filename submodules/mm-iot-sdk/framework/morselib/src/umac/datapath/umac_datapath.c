/*
 * Copyright 2022-2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */

#include "dot11/dot11_ies.h"
#include "mmdrv.h"
#include "mmpkt_list.h"
#include "mmpkt.h"
#include "mmwlan.h"
#include "mmwlan_internal.h"
#include "umac/datapath/umac_datapath.h"
#include "umac/datapath/umac_datapath_private.h"
#include "umac/data/umac_data.h"
#include "umac/datapath/datapath_defrag.h"
#include "umac/regdb/umac_regdb.h"
#include "umac/supplicant_shim/umac_supp_shim.h"
#include "dot11/dot11.h"
#include "dot11/dot11_utils.h"
#include "umac/umac.h"
#include "umac/config/umac_config.h"
#include "umac/core/umac_core.h"
#include "common/mac_address.h"
#include "umac/ps/umac_ps.h"
#include "umac/stats/umac_stats.h"
#include "umac/interface/umac_interface.h"
#include "umac/connection/umac_connection.h"
#include "umac/rc/umac_rc.h"
#include "umac/ba/umac_ba.h"
#include "umac/twt/umac_twt.h"
#include "umac/ies/mmie.h"
#include "umac/ies/ssid.h"
#include "umac/ies/s1g_capabilities.h"
#include "umac/frames/disassociation.h"
#include "umac/frames/deauthentication.h"
#include "umac/frames/frames_common.h"
#include "umac/scan/umac_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/sys/printk.h>

#define MMWLAN_DYNAMIC_MESH_BEACON_IES_MAX_LEN 512U

/* Applications may override this to provide up-to-date mesh beacon IEs. */
__attribute__((weak)) size_t mmwlan_mesh_beacon_dynamic_ies(uint8_t *out, size_t out_cap)
{
    (void)out;
    (void)out_cap;
    return 0;
}

/* Mesh debug trace gate – controlled by CONFIG_MM_MESH_DEBUG_LOG in menuconfig */
#ifndef MESH_DBG_PRINTF
#ifdef CONFIG_MM_MESH_DEBUG_LOG
#define MESH_DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define MESH_DBG_PRINTF(...) do {} while(0)
#endif
#endif

/* Set to 1 to enable verbose per-frame [dp_mesh*] printf logging.
 * WARNING: at 115200 baud the hex dumps add ~250 ms per ping round-trip. */
#define DP_MESH_VERBOSE 0

#if DP_MESH_VERBOSE
#define dp_mesh_dbg(...) printf(__VA_ARGS__)
#else
#define dp_mesh_dbg(...) ((void)0)
#endif

/* Forward declaration for software CCMP decrypt (from wpa_supplicant crypto) */
int aes_ccm_ad(const uint8_t *key, size_t key_len, const uint8_t *nonce,
               size_t M, const uint8_t *crypt, size_t crypt_len,
               const uint8_t *aad, size_t aad_len, const uint8_t *auth,
               uint8_t *plain);

/* Forward declaration for software CCMP encrypt (from wpa_supplicant crypto) */
int aes_ccm_ae(const uint8_t *key, size_t key_len, const uint8_t *nonce,
               size_t M, const uint8_t *plain, size_t plain_len,
               const uint8_t *aad, size_t aad_len, uint8_t *crypt,
               uint8_t *auth);

#define UMAC_802_1_HEADER_LEN 8
static const uint8_t snap_802_1h[] = { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 };


#define MESH_CTRL_BASE_LEN 6   /* flags(1) + TTL(1) + seq(4) */
#define MESH_CTRL_MAX_LEN  18  /* AE=2: base(6) + Addr5(6) + Addr6(6) */

#define MAX_QOS_DATA_MAC_HEADER_LEN (sizeof(struct dot11_data_hdr) + sizeof(struct dot11_qos_ctrl) + MESH_CTRL_MAX_LEN)

/* ---------------------------------------------------------------------------
 * Mesh proxy table: maps proxied Ethernet MAC → mesh STA that proxies it.
 *
 * Learned from incoming AE=2 frames:
 *   Addr6 (proxied SA) → A4 (mesh SA, i.e. the mesh STA originating/proxying)
 *
 * Used on TX to set A3 (mesh DA) to the correct mesh STA that can deliver
 * to the final Ethernet destination, rather than always using the peer addr.
 * ---------------------------------------------------------------------------
 */
#define MESH_PROXY_TABLE_SIZE 16

struct mesh_proxy_entry {
    uint8_t eth_addr[DOT11_MAC_ADDR_LEN];   /* proxied host MAC */
    uint8_t mesh_sta[DOT11_MAC_ADDR_LEN];   /* mesh STA that proxies it */
    bool    valid;
};

static struct mesh_proxy_entry s_mesh_proxy_table[MESH_PROXY_TABLE_SIZE];

static void mesh_proxy_table_update(const uint8_t *eth_addr,
                                    const uint8_t *mesh_sta)
{
    if (mm_mac_addr_is_multicast(eth_addr))
        return;

    /* Update existing entry */
    for (int i = 0; i < MESH_PROXY_TABLE_SIZE; i++)
    {
        if (s_mesh_proxy_table[i].valid &&
            memcmp(s_mesh_proxy_table[i].eth_addr, eth_addr, DOT11_MAC_ADDR_LEN) == 0)
        {
            memcpy(s_mesh_proxy_table[i].mesh_sta, mesh_sta, DOT11_MAC_ADDR_LEN);
            return;
        }
    }

    /* Find empty slot */
    for (int i = 0; i < MESH_PROXY_TABLE_SIZE; i++)
    {
        if (!s_mesh_proxy_table[i].valid)
        {
            memcpy(s_mesh_proxy_table[i].eth_addr, eth_addr, DOT11_MAC_ADDR_LEN);
            memcpy(s_mesh_proxy_table[i].mesh_sta, mesh_sta, DOT11_MAC_ADDR_LEN);
            s_mesh_proxy_table[i].valid = true;
            dp_mesh_dbg("[dp_mesh] proxy learned: %02x:%02x:%02x:%02x:%02x:%02x -> mesh %02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth_addr[0], eth_addr[1], eth_addr[2],
                   eth_addr[3], eth_addr[4], eth_addr[5],
                   mesh_sta[0], mesh_sta[1], mesh_sta[2],
                   mesh_sta[3], mesh_sta[4], mesh_sta[5]);
            return;
        }
    }

    /* Table full — overwrite oldest (slot 0, simple eviction) */
    memcpy(s_mesh_proxy_table[0].eth_addr, eth_addr, DOT11_MAC_ADDR_LEN);
    memcpy(s_mesh_proxy_table[0].mesh_sta, mesh_sta, DOT11_MAC_ADDR_LEN);
    s_mesh_proxy_table[0].valid = true;
}

static const uint8_t *mesh_proxy_table_lookup(const uint8_t *eth_addr)
{
    for (int i = 0; i < MESH_PROXY_TABLE_SIZE; i++)
    {
        if (s_mesh_proxy_table[i].valid &&
            memcmp(s_mesh_proxy_table[i].eth_addr, eth_addr, DOT11_MAC_ADDR_LEN) == 0)
        {
            return s_mesh_proxy_table[i].mesh_sta;
        }
    }
    return NULL;
}


#define ETHERTYPE_THRESHOLD 1536


#define MAX_RX_PROCESS_PER_LOOP (5)


#define MAX_TX_PROCESS_PER_LOOP (5)


#define RX_REORDER_TIMEOUT_MS (100)


#define RX_REORDER_TIMER_PERIOD_MS (RX_REORDER_TIMEOUT_MS / 4)

static uint32_t scan_dbg_raw_mgmt_sta_seen;
static uint32_t scan_dbg_raw_probe_rsp_seen;
static uint32_t scan_dbg_raw_s1g_beacon_seen;
static uint32_t mesh_dbg_mgmt_from_peer_seen;
static uint32_t mesh_dbg_rx_mgmt_gate_seen;
static uint32_t mesh_dbg_probe_req_rx_seen;
static uint32_t mac_mgmt_rx_entry_count;
static uint32_t mac_mgmt_rx_dispatch_count;
static uint32_t mac_s1g_beacon_rx_count;
static uint32_t mac_mgmt_tx_count;

static bool mac_mgmt_trace_sample(uint16_t subtype, uint32_t count)
{
    MM_UNUSED(subtype);
    MM_UNUSED(count);
    /* Temporary RX-path diagnostic: log every management frame. */
    return true;
}

static uint32_t mesh_dbg_fnv1a32(const uint8_t *buf, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++)
    {
        hash ^= buf[i];
        hash *= 16777619u;
    }
    return hash;
}

#define DOT11_IE_SUPPORTED_RATES (1U)
#define DOT11_IE_EXT_SUPPORTED_RATES (50U)
#define DOT11_IE_RSN (48U)
#define DOT11_IE_MESH_CONFIG (113U)
#define DOT11_IE_MESH_ID (114U)

/* HWMP (Hybrid Wireless Mesh Protocol) constants */
#define HWMP_ACTION_CODE_PATH_SELECTION 1
#define WLAN_EID_RANN  126
#define WLAN_EID_PREQ  130
#define WLAN_EID_PREP  131
#define WLAN_EID_PERR  132
#define HWMP_PREQ_IE_LEN 37
#define HWMP_PREP_IE_LEN 31
#define HWMP_DEFAULT_TTL 31
#define HWMP_DEFAULT_LIFETIME 0x1388  /* ~5120 TU = ~5.24 sec */

#ifndef MESH_PREQ_INTERVAL_MS
#define MESH_PREQ_INTERVAL_MS 0  /* 0 = disabled; set via Kconfig */
#endif

static uint32_t hwmp_own_sn;  /* Our HWMP sequence number */

struct mesh_probe_rsp_builder_args
{
    uint8_t frame_subtype;
    const uint8_t *destination_address;
    uint8_t bssid[DOT11_MAC_ADDR_LEN];
    const uint8_t *ssid;
    uint8_t ssid_len;
    uint16_t beacon_interval;
    uint16_t capability_info;
    struct ie_s1g_operation channel_cfg;
};

static void umac_datapath_append_raw_ie(struct consbuf *buf,
                                        uint8_t id,
                                        const uint8_t *data,
                                        uint8_t len)
{
    consbuf_append(buf, &id, sizeof(id));
    consbuf_append(buf, &len, sizeof(len));
    if (len > 0 && data != NULL)
    {
        consbuf_append(buf, data, len);
    }
}

static void umac_datapath_build_s1g_operation_ie(struct consbuf *buf,
                                                 const struct ie_s1g_operation *channel_cfg)
{
    struct dot11_ie_s1g_operation *op_ie =
        (struct dot11_ie_s1g_operation *)consbuf_reserve(buf, sizeof(*op_ie));
    if (op_ie == NULL)
    {
        return;
    }

    memset(op_ie, 0, sizeof(*op_ie));
    op_ie->header.element_id = DOT11_IE_S1G_OPERATION;
    op_ie->header.length = sizeof(*op_ie) - sizeof(op_ie->header);

    uint8_t s1g_op_channel_width = 0;
    DOT11_S1G_OP_CHAN_WIDTH_SET_PRI_CHAN_WIDTH(
        s1g_op_channel_width,
        (channel_cfg->primary_channel_width_mhz <= 1) ? 1 : 0);
    DOT11_S1G_OP_CHAN_WIDTH_SET_OP_CHAN_WIDTH(
        s1g_op_channel_width,
        (channel_cfg->operation_channel_width_mhz > 0) ?
            (channel_cfg->operation_channel_width_mhz - 1) :
            0);
    DOT11_S1G_OP_CHAN_WIDTH_SET_PRI_CHAN_LOC(
        s1g_op_channel_width,
        channel_cfg->primary_1mhz_channel_loc);
    DOT11_S1G_OP_CHAN_WIDTH_SET_NO_MCS10(
        s1g_op_channel_width,
        channel_cfg->recommend_no_mcs10 ? 1 : 0);

    op_ie->channel_width = s1g_op_channel_width;
    op_ie->operating_class = channel_cfg->operating_class;
    op_ie->primary_channel_number = channel_cfg->primary_channel_number;
    op_ie->channel_center_freq = channel_cfg->operating_channel_index;
}

static void umac_datapath_mesh_probe_response_build(struct umac_data *umacd,
                                                    struct consbuf *buf,
                                                    void *params)
{
    const struct mesh_probe_rsp_builder_args *args =
        (const struct mesh_probe_rsp_builder_args *)params;
    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr != NULL)
    {
        dot11_build_pv0_mgmt_header(hdr,
                                    args->frame_subtype,
                                    0,
                                    args->destination_address,
                                    args->bssid,
                                    args->bssid);
    }

    {
        const uint8_t zero_timestamp[8] = { 0 };
        consbuf_append(buf, zero_timestamp, sizeof(zero_timestamp));
    }

    {
        uint16_t beacon_interval = htole16(args->beacon_interval);
        consbuf_append(buf, (const uint8_t *)&beacon_interval, sizeof(beacon_interval));
    }

    {
        uint16_t capability_info = htole16(args->capability_info);
        consbuf_append(buf, (const uint8_t *)&capability_info, sizeof(capability_info));
    }

    {
        static const uint8_t fallback_supp_rates[] = {
            0x02, 0x04, 0x0b, 0x8c, 0x16, 0x98, 0x24, 0xb0
        };
        static const uint8_t fallback_ext_supp_rates[] = {
            0x09, 0x0d, 0x0e, 0x11, 0x12, 0x19, 0x1b, 0x1e
        };
        static const uint8_t fallback_mesh_config[] = {
            0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
            0x09 /* MESH_CAP_ACCEPT_ADDITIONAL_PEER | MESH_CAP_FORWARDING */
        };
        static const uint8_t fallback_rsn_sae[] = {
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00,
            0x00, 0x0f, 0xac, 0x08,
            0xc0, 0x00
        };

        umac_datapath_append_raw_ie(buf,
                                    DOT11_IE_SUPPORTED_RATES,
                                    fallback_supp_rates,
                                    (uint8_t)sizeof(fallback_supp_rates));
        umac_datapath_append_raw_ie(buf,
                                    DOT11_IE_EXT_SUPPORTED_RATES,
                                    fallback_ext_supp_rates,
                                    (uint8_t)sizeof(fallback_ext_supp_rates));

        if (args->capability_info & DOT11_MASK_CAPINFO_PRIVACY)
        {
            umac_datapath_append_raw_ie(buf,
                                        DOT11_IE_RSN,
                                        fallback_rsn_sae,
                                        (uint8_t)sizeof(fallback_rsn_sae));
        }

        umac_datapath_append_raw_ie(buf,
                                    DOT11_IE_MESH_ID,
                                    args->ssid,
                                    args->ssid_len);
        umac_datapath_append_raw_ie(buf,
                                    DOT11_IE_MESH_CONFIG,
                                    fallback_mesh_config,
                                    (uint8_t)sizeof(fallback_mesh_config));
    }

    ie_ssid_build(buf, args->ssid, args->ssid_len);
    ie_s1g_capabilities_build(umacd, buf);
    umac_datapath_build_s1g_operation_ie(buf, &args->channel_cfg);

    {
        const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
        uint8_t dynamic_ies[MMWLAN_DYNAMIC_MESH_BEACON_IES_MAX_LEN];
        size_t dynamic_ies_len =
            mmwlan_mesh_beacon_dynamic_ies(dynamic_ies, sizeof(dynamic_ies));

        if (dynamic_ies_len > 0U && dynamic_ies_len <= sizeof(dynamic_ies))
        {
            consbuf_append(buf, dynamic_ies, dynamic_ies_len);
        }
        else if (sta_args != NULL && sta_args->extra_assoc_ies != NULL &&
                 sta_args->extra_assoc_ies_len > 0U)
        {
            consbuf_append(buf, sta_args->extra_assoc_ies, sta_args->extra_assoc_ies_len);
        }
    }
}

static void umac_datapath_try_mesh_probe_rsp(struct umac_data *umacd,
                                             struct mmpktview *rxbufview)
{
    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
    const struct umac_connection_bss_cfg *bss_cfg = umac_connection_get_bss_cfg(umacd);
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    const struct dot11_hdr *probe_req_hdr =
        (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    struct mesh_probe_rsp_builder_args rsp_args;
    struct mmpkt *probe_rsp;

    if (sta_args == NULL || !sta_args->mesh_mode || bss_cfg == NULL || stad == NULL)
    {
        return;
    }

    mesh_dbg_probe_req_rx_seen++;
    printf("[mesh_rx] probe_req_rx count=%lu src=" MM_MAC_ADDR_FMT " dst=" MM_MAC_ADDR_FMT
           " bssid=" MM_MAC_ADDR_FMT "\n",
           (unsigned long)mesh_dbg_probe_req_rx_seen,
           MM_MAC_ADDR_VAL(dot11_get_sa(probe_req_hdr)),
           MM_MAC_ADDR_VAL(dot11_get_da(probe_req_hdr)),
           MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(probe_req_hdr)));

    memset(&rsp_args, 0, sizeof(rsp_args));
    rsp_args.frame_subtype = DOT11_FC_SUBTYPE_PROBE_RSP;
    rsp_args.destination_address = dot11_get_sa(probe_req_hdr);
    rsp_args.ssid = sta_args->ssid;
    rsp_args.ssid_len = sta_args->ssid_len;
    rsp_args.beacon_interval = (bss_cfg->beacon_interval != 0) ? bss_cfg->beacon_interval : 100;
    rsp_args.capability_info =
        (sta_args->security_type == MMWLAN_OPEN) ? 0 : DOT11_MASK_CAPINFO_PRIVACY;
    rsp_args.channel_cfg = bss_cfg->channel_cfg;

    if (!mm_mac_addr_is_zero(sta_args->bssid))
    {
        memcpy(rsp_args.bssid, sta_args->bssid, sizeof(rsp_args.bssid));
    }
    else
    {
        const uint8_t *cur_bssid = umac_sta_data_peek_bssid(stad);
        if (cur_bssid != NULL && !mm_mac_addr_is_zero(cur_bssid))
        {
            memcpy(rsp_args.bssid, cur_bssid, sizeof(rsp_args.bssid));
        }
        else if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, rsp_args.bssid) !=
                 MMWLAN_SUCCESS)
        {
            if (umac_interface_get_device_mac_addr(umacd, rsp_args.bssid) != MMWLAN_SUCCESS)
            {
                return;
            }
        }
    }

    probe_rsp =
        build_mgmt_frame(umacd, umac_datapath_mesh_probe_response_build, &rsp_args);
    if (probe_rsp == NULL)
    {
        return;
    }

    enum mmwlan_status tx_status = umac_datapath_tx_mgmt_frame(stad, probe_rsp);
    printf("[mesh_tx_path] mesh_probe_rsp_tx status=%d dst=" MM_MAC_ADDR_FMT " bssid="
           MM_MAC_ADDR_FMT "\n",
           (int)tx_status,
           MM_MAC_ADDR_VAL(rsp_args.destination_address),
           MM_MAC_ADDR_VAL(rsp_args.bssid));
}

struct mmpkt *umac_datapath_get_mesh_beacon(struct umac_data *umacd)
{
    static const uint8_t broadcast_addr[DOT11_MAC_ADDR_LEN] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static uint32_t beacon_build_count;
    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
    const struct umac_connection_bss_cfg *bss_cfg = umac_connection_get_bss_cfg(umacd);
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    struct mesh_probe_rsp_builder_args beacon_args;
    struct mmpkt *beacon;

    if (sta_args == NULL || !sta_args->mesh_mode || bss_cfg == NULL || stad == NULL ||
        bss_cfg->beacon_interval == 0)
    {
        return NULL;
    }

    memset(&beacon_args, 0, sizeof(beacon_args));
    beacon_args.frame_subtype = DOT11_FC_SUBTYPE_BEACON;
    beacon_args.destination_address = broadcast_addr;
    beacon_args.ssid = sta_args->ssid;
    beacon_args.ssid_len = sta_args->ssid_len;
    beacon_args.beacon_interval = bss_cfg->beacon_interval;
    beacon_args.capability_info =
        (sta_args->security_type == MMWLAN_OPEN) ? 0 : DOT11_MASK_CAPINFO_PRIVACY;
    beacon_args.channel_cfg = bss_cfg->channel_cfg;

    const uint8_t *cur_bssid = umac_sta_data_peek_bssid(stad);
    if (cur_bssid != NULL && !mm_mac_addr_is_zero(cur_bssid))
    {
        memcpy(beacon_args.bssid, cur_bssid, sizeof(beacon_args.bssid));
    }
    else if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, beacon_args.bssid) !=
             MMWLAN_SUCCESS &&
             umac_interface_get_device_mac_addr(umacd, beacon_args.bssid) != MMWLAN_SUCCESS)
    {
        return NULL;
    }

    beacon = build_mgmt_frame(umacd, umac_datapath_mesh_probe_response_build, &beacon_args);
    if (beacon == NULL)
    {
        return NULL;
    }

    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(beacon);
    tx_metadata->flags = MMDRV_TX_FLAG_IMMEDIATE_REPORT;
    tx_metadata->tid = MMWLAN_MAX_QOS_TID;
    tx_metadata->vif_id = umac_connection_get_vif_id(umacd);
    umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);

    beacon_build_count++;
    if (beacon_build_count == 1 || (beacon_build_count % 600U) == 0)
    {
        printf("[mesh_beacon] management template built count=%lu vif=%u chan=%u interval=%u "
               "edgez_ies=%u bssid=" MM_MAC_ADDR_FMT "\n",
               (unsigned long)beacon_build_count,
               (unsigned)tx_metadata->vif_id,
               (unsigned)bss_cfg->channel_cfg.operating_channel_index,
               (unsigned)bss_cfg->beacon_interval,
               (unsigned)sta_args->extra_assoc_ies_len,
               MM_MAC_ADDR_VAL(beacon_args.bssid));
    }

    return beacon;
}

static void umac_datapath_log_rx_frame_lowlevel(struct mmpkt *rxbuf, struct mmpktview *rxbufview)
{
    const struct mmdrv_rx_metadata *rx_metadata = mmdrv_get_rx_metadata(rxbuf);
    size_t len = mmpkt_get_data_length(rxbufview);

    if (len < sizeof(struct dot11_hdr))
    {
        dp_mesh_dbg("[rx_ll] short len=%u rssi=%d freq_100khz=%u bw_mhz=%u\n",
               (unsigned)len,
               rx_metadata ? rx_metadata->rssi : 0,
               rx_metadata ? rx_metadata->freq_100khz : 0,
               rx_metadata ? rx_metadata->bw_mhz : 0);
        return;
    }

    const struct dot11_hdr *header = (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t fc = header->frame_control;
    uint16_t frame_type = dot11_frame_control_get_type(fc);
    uint16_t frame_subtype = dot11_frame_control_get_subtype(fc);
    uint16_t frame_ver_type_subtype = dot11_frame_control_get_ver_type_subtype(fc);

    if (frame_ver_type_subtype == DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON))
    {
        const struct dot11_s1g_beacon_hdr *beacon =
            (const struct dot11_s1g_beacon_hdr *)header;
        mac_s1g_beacon_rx_count++;
        printk("[MAC_BEACON] RX count=%lu len=%u fc=0x%04x rssi=%d noise=%d "
               "freq_100khz=%u bw=%u vif=%u sa=" MM_MAC_ADDR_FMT "\n",
               (unsigned long)mac_s1g_beacon_rx_count,
               (unsigned)len,
               (unsigned)le16toh(fc),
               rx_metadata ? rx_metadata->rssi : 0,
               rx_metadata ? rx_metadata->noise_dbm : 0,
               rx_metadata ? rx_metadata->freq_100khz : 0,
               rx_metadata ? rx_metadata->bw_mhz : 0,
               rx_metadata ? rx_metadata->vif_id : 0,
               MM_MAC_ADDR_VAL(beacon->source_addr));
        return;
    }

    if (frame_type == DOT11_FC_TYPE_MGMT &&
        frame_subtype == DOT11_FC_SUBTYPE_ACTION &&
        len >= sizeof(struct dot11_action))
    {
        const struct dot11_action *action =
            (const struct dot11_action *)mmpkt_get_data_start(rxbufview);
        const uint8_t *action_var = (const uint8_t *)action + sizeof(*action);
        const size_t action_var_len = len - sizeof(*action);
        const uint32_t action_var_hash = mesh_dbg_fnv1a32(action_var, action_var_len);
        const unsigned action_code =
            (action_var_len > 0U) ? (unsigned)action->field.action_details[0] : 0xffU;
         const uint8_t *ie_payload = (action_var_len > 0U) ? (action_var + 1U) : action_var;
         const size_t ie_payload_len = (action_var_len > 0U) ? (action_var_len - 1U) : 0U;
         const uint32_t ie_payload_hash = mesh_dbg_fnv1a32(ie_payload, ie_payload_len);

                 MESH_DBG_PRINTF("[rx_ll_action] len=%u cat=%u action=%u var_len=%u var_hash=0x%08lx ie_len=%u ie_hash=0x%08lx\n",
                                                 (unsigned)len,
                                                 (unsigned)action->field.category,
                                                 action_code,
                                                 (unsigned)action_var_len,
                                                 (unsigned long)action_var_hash,
                                                 (unsigned)ie_payload_len,
                                                 (unsigned long)ie_payload_hash);

        if (action->field.category == DOT11_ACTION_CATEGORY_SELF_PROTECTED)
        {
            const size_t head_len = (action_var_len > 96U) ? 96U : action_var_len;
            const size_t tail_len = (action_var_len > 32U) ? 32U : action_var_len;

            MMLOG_DUMP_INF("[rx_ll_action] var_head",
                           action_var,
                           head_len);
            if (action_var_len > tail_len)
            {
                MMLOG_DUMP_INF("[rx_ll_action] var_tail",
                               action_var + (action_var_len - tail_len),
                               tail_len);
            }
        }
    }

    dp_mesh_dbg("[rx_ll] len=%u fc=0x%04x type=%u subtype=0x%x ta=" MM_MAC_ADDR_FMT
           " ra=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT
           " rssi=%d freq_100khz=%u bw_mhz=%u\n",
           (unsigned)len,
           (unsigned)fc,
           (unsigned)frame_type,
           (unsigned)frame_subtype,
           MM_MAC_ADDR_VAL(dot11_get_ta(header)),
           MM_MAC_ADDR_VAL(dot11_get_ra(header)),
           MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)),
           rx_metadata ? rx_metadata->rssi : 0,
           rx_metadata ? rx_metadata->freq_100khz : 0,
           rx_metadata ? rx_metadata->bw_mhz : 0);
}

#ifdef ENABLE_DATAPATH_TRACE
#include "mmtrace.h"
static mmtrace_channel datapath_channel_handle;
#define DATAPATH_TRACE_INIT()     datapath_channel_handle = mmtrace_register_channel("datapath")
#define DATAPATH_TRACE(_fmt, ...) mmtrace_printf(datapath_channel_handle, _fmt, ##__VA_ARGS__)
#else
#define DATAPATH_TRACE_INIT() \
    do {                      \
    } while (0)
#define DATAPATH_TRACE(_fmt, ...) \
    do {                          \
    } while (0)
#endif


static bool umac_datapath_tx_is_paused(struct umac_datapath_data *data, uint16_t mask)
{
    return (data->tx_paused & mask) != 0;
}

enum mmwlan_status umac_datapath_wait_for_tx_ready_(struct umac_datapath_data *data,
                                                    uint32_t timeout_ms,
                                                    uint16_t mask)
{
    if (timeout_ms == UINT32_MAX)
    {
        while (umac_datapath_tx_is_paused(data, mask))
        {
            mmosal_semb_wait(data->tx_flowcontrol_sem, UINT32_MAX);
        }
    }
    else
    {
        uint32_t timeout_at = mmosal_get_time_ms() + timeout_ms;

        while (umac_datapath_tx_is_paused(data, mask))
        {
            int32_t sleep_time_ms = timeout_at - mmosal_get_time_ms();
            if (sleep_time_ms <= 0)
            {
                return MMWLAN_TIMED_OUT;
            }

            mmosal_semb_wait(data->tx_flowcontrol_sem, sleep_time_ms);
        }
    }

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_datapath_wait_for_tx_ready(struct umac_data *umacd, uint32_t timeout_ms)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    return umac_datapath_wait_for_tx_ready_(data, timeout_ms, UINT16_MAX);
}


static bool umac_datapath_validate_buf_len(struct mmpktview *view, uint32_t min_length)
{
    if (mmpkt_get_data_length(view) < min_length)
    {
        MMLOG_WRN("Data length too short. Received: %lu; Expected: %lu\n",
                  mmpkt_get_data_length(view),
                  min_length);
        return false;
    }

    return true;
}


static void umac_datapath_handle_signal_monitor(struct umac_data *umacd, int16_t new_rssi)
{
    enum umac_connection_signal_change status =
        umac_connection_check_signal_change(umacd, new_rssi);
    if (status != UMAC_CONNECTION_SIGNAL_CHANGE_NO_CHANGE)
    {
        umac_supp_notify_signal_change(umacd,
                                       new_rssi,
                                       (status == UMAC_CONNECTION_SIGNAL_CHANGE_ABOVE_THRESHOLD));
    }
}


static void umac_datapath_process_s1g_beacon(struct umac_data *umacd, struct mmpktview *rxbufview)
{
    struct mmpkt *rxbuf = mmpkt_from_view(rxbufview);
    const struct mmdrv_rx_metadata *rx_metadata = mmdrv_get_rx_metadata(rxbuf);

    if (umac_scan_has_scan_req(umacd))
    {
        scan_dbg_raw_s1g_beacon_seen++;
        if ((scan_dbg_raw_s1g_beacon_seen % 16U) == 1U)
        {
            printf("[scan_raw] s1g_beacon_seen=%lu\n", (unsigned long)scan_dbg_raw_s1g_beacon_seen);
        }
    }

    const struct dot11_s1g_beacon_hdr *s1g_header =
        (struct dot11_s1g_beacon_hdr *)mmpkt_remove_from_start(rxbufview, sizeof(*s1g_header));
    if (s1g_header == NULL)
    {
        MMLOG_WRN("S1G Beacon too short (%lu, expect at least %u)\n",
                  mmpkt_get_data_length(rxbufview),
                  sizeof(*s1g_header));
        return;
    }

    if (dot11_frame_control_get_next_tbtt_present(s1g_header->frame_control))
    {
        (void)mmpkt_remove_from_start(rxbufview, DOT11_NEXT_TBTT_LEN);
    }

    if (dot11_frame_control_get_cssid_present(s1g_header->frame_control))
    {
        (void)mmpkt_remove_from_start(rxbufview, DOT11_CSSID_LEN);
    }

    if (dot11_frame_control_get_ano_present(s1g_header->frame_control))
    {
        (void)mmpkt_remove_from_start(rxbufview, DOT11_ANO_LEN);
    }


    umac_scan_process_s1g_beacon(umacd, rxbufview, s1g_header->source_addr);

    if (!umac_connection_addr_matches_bssid(umacd, s1g_header->source_addr))
    {
        MMLOG_DBG("Beacon received from another AP.\n");
        return;
    }

    int16_t new_rssi = rx_metadata->rssi;
    umac_stats_set_rssi(umacd, new_rssi);
    umac_datapath_handle_signal_monitor(umacd, new_rssi);

    umac_connection_process_beacon_ies(umacd,
                                       mmpkt_get_data_start(rxbufview),
                                       mmpkt_get_data_length(rxbufview));
}


static void umac_datapath_process_rx_extension_frame(struct umac_data *umacd,
                                                     struct umac_datapath_data *data,
                                                     struct mmpktview *rxbufview,
                                                     uint16_t frame_control)
{
    uint16_t subtype = dot11_frame_control_get_subtype(frame_control);
    MM_UNUSED(data);

    switch (subtype)
    {
        case DOT11_FC_SUBTYPE_S1G_BEACON:
            umac_datapath_process_s1g_beacon(umacd, rxbufview);
            break;

        default:
            MMLOG_WRN("Recieved unsupported EXT frame: frame_control=0x%04x\n",
                      le16toh(frame_control));
            break;
    }
}

/* ---- HWMP (802.11s path selection) support ---- */

struct hwmp_prep_builder_args
{
    const uint8_t *da;           /* Next hop toward originator (SA of PREQ) */
    uint8_t our_addr[DOT11_MAC_ADDR_LEN];
    uint32_t target_sn;          /* Our SN */
    uint32_t lifetime;           /* Copied from PREQ */
    uint8_t orig_addr[DOT11_MAC_ADDR_LEN];  /* Originator from PREQ */
    uint32_t orig_sn;            /* Originator SN from PREQ */
};

static void hwmp_prep_frame_build(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    MM_UNUSED(umacd);
    const struct hwmp_prep_builder_args *args = (const struct hwmp_prep_builder_args *)params;

    /* 802.11 management header */
    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr != NULL)
    {
        dot11_build_pv0_mgmt_header(hdr,
                                    DOT11_FC_SUBTYPE_ACTION,
                                    0,
                                    args->da,
                                    args->our_addr,
                                    args->our_addr);
    }

    /* Category (13 = Mesh) + Action code (1 = HWMP Path Selection) */
    uint8_t cat_action[2] = { DOT11_ACTION_CATEGORY_MESH, HWMP_ACTION_CODE_PATH_SELECTION };
    consbuf_append(buf, cat_action, sizeof(cat_action));

    /* PREP IE: EID=131, len=31 */
    uint8_t prep[2 + HWMP_PREP_IE_LEN];
    prep[0] = WLAN_EID_PREP;
    prep[1] = HWMP_PREP_IE_LEN;
    prep[2] = 0;                    /* flags */
    prep[3] = 0;                    /* hop count (we are the target) */
    prep[4] = HWMP_DEFAULT_TTL;     /* TTL */
    /* Target Address = our MAC (6 bytes) */
    memcpy(&prep[5], args->our_addr, DOT11_MAC_ADDR_LEN);
    /* Target SN (4 bytes LE) */
    prep[11] = (uint8_t)(args->target_sn);
    prep[12] = (uint8_t)(args->target_sn >> 8);
    prep[13] = (uint8_t)(args->target_sn >> 16);
    prep[14] = (uint8_t)(args->target_sn >> 24);
    /* Lifetime (4 bytes LE) */
    prep[15] = (uint8_t)(args->lifetime);
    prep[16] = (uint8_t)(args->lifetime >> 8);
    prep[17] = (uint8_t)(args->lifetime >> 16);
    prep[18] = (uint8_t)(args->lifetime >> 24);
    /* Metric (4 bytes LE) = 0 (direct target, no extra cost) */
    memset(&prep[19], 0, 4);
    /* Originator Address (6 bytes) */
    memcpy(&prep[23], args->orig_addr, DOT11_MAC_ADDR_LEN);
    /* Originator SN (4 bytes LE) */
    prep[29] = (uint8_t)(args->orig_sn);
    prep[30] = (uint8_t)(args->orig_sn >> 8);
    prep[31] = (uint8_t)(args->orig_sn >> 16);
    prep[32] = (uint8_t)(args->orig_sn >> 24);

    consbuf_append(buf, prep, sizeof(prep));
}

/* ---- HWMP proactive PREQ broadcast ---- */

struct hwmp_preq_builder_args
{
    uint8_t our_addr[DOT11_MAC_ADDR_LEN];
    uint32_t preq_id;
    uint32_t orig_sn;
};

static const uint8_t broadcast_addr[DOT11_MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void hwmp_preq_frame_build(struct umac_data *umacd, struct consbuf *buf, void *params)
{
    MM_UNUSED(umacd);
    const struct hwmp_preq_builder_args *args = (const struct hwmp_preq_builder_args *)params;

    /* 802.11 management header: broadcast DA, SA=BSSID=our_addr */
    struct dot11_hdr *hdr = (struct dot11_hdr *)consbuf_reserve(buf, sizeof(*hdr));
    if (hdr != NULL)
    {
        dot11_build_pv0_mgmt_header(hdr,
                                    DOT11_FC_SUBTYPE_ACTION,
                                    0,
                                    broadcast_addr,
                                    args->our_addr,
                                    args->our_addr);
    }

    /* Category (13 = Mesh) + Action code (1 = HWMP Path Selection) */
    uint8_t cat_action[2] = { DOT11_ACTION_CATEGORY_MESH, HWMP_ACTION_CODE_PATH_SELECTION };
    consbuf_append(buf, cat_action, sizeof(cat_action));

    /* PREQ IE: EID=130, len=37  (1 target, no AE) */
    uint8_t preq[2 + HWMP_PREQ_IE_LEN];
    preq[0] = WLAN_EID_PREQ;
    preq[1] = HWMP_PREQ_IE_LEN;
    preq[2] = 0;                    /* flags (no AE, no proactive PREP) */
    preq[3] = 0;                    /* hop count */
    preq[4] = HWMP_DEFAULT_TTL;     /* TTL */
    /* PREQ ID (4 bytes LE) */
    preq[5] = (uint8_t)(args->preq_id);
    preq[6] = (uint8_t)(args->preq_id >> 8);
    preq[7] = (uint8_t)(args->preq_id >> 16);
    preq[8] = (uint8_t)(args->preq_id >> 24);
    /* Originator Address (6 bytes) = our MAC */
    memcpy(&preq[9], args->our_addr, DOT11_MAC_ADDR_LEN);
    /* Originator SN (4 bytes LE) */
    preq[15] = (uint8_t)(args->orig_sn);
    preq[16] = (uint8_t)(args->orig_sn >> 8);
    preq[17] = (uint8_t)(args->orig_sn >> 16);
    preq[18] = (uint8_t)(args->orig_sn >> 24);
    /* Lifetime (4 bytes LE) */
    preq[19] = (uint8_t)(HWMP_DEFAULT_LIFETIME);
    preq[20] = (uint8_t)(HWMP_DEFAULT_LIFETIME >> 8);
    preq[21] = (uint8_t)(HWMP_DEFAULT_LIFETIME >> 16);
    preq[22] = (uint8_t)(HWMP_DEFAULT_LIFETIME >> 24);
    /* Metric (4 bytes LE) = 0 (originator) */
    memset(&preq[23], 0, 4);
    /* Target Count = 1 */
    preq[27] = 1;
    /* Target Flags = 0 */
    preq[28] = 0;
    /* Target Address = 00:00:00:00:00:00 (proactive / broadcast discovery) */
    memset(&preq[29], 0, DOT11_MAC_ADDR_LEN);
    /* Target SN = 0 */
    memset(&preq[35], 0, 4);

    consbuf_append(buf, preq, sizeof(preq));
}

static void umac_datapath_tx_hwmp_preq(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if (stad == NULL)
    {
        return;
    }

    /* Need the group key to be installed for broadcast encryption */
    int gk = umac_keys_get_active_key_id(stad, UMAC_KEY_TYPE_GROUP);
    if (gk < 0)
    {
        return;
    }

    uint8_t our_addr[DOT11_MAC_ADDR_LEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, our_addr) != MMWLAN_SUCCESS)
    {
        if (umac_interface_get_device_mac_addr(umacd, our_addr) != MMWLAN_SUCCESS)
        {
            return;
        }
    }

    ++hwmp_own_sn;
    ++data->hwmp_preq_id;

    struct hwmp_preq_builder_args args;
    memcpy(args.our_addr, our_addr, DOT11_MAC_ADDR_LEN);
    args.preq_id = data->hwmp_preq_id;
    args.orig_sn = hwmp_own_sn;

    struct mmpkt *preq_pkt = build_mgmt_frame(umacd, hwmp_preq_frame_build, &args);
    if (preq_pkt != NULL)
    {
        enum mmwlan_status tx_status = umac_datapath_tx_mgmt_frame(stad, preq_pkt);
        MESH_DBG_PRINTF("[hwmp] PREQ tx: preq_id=%u sn=%u status=%d\n",
                (unsigned)data->hwmp_preq_id, (unsigned)hwmp_own_sn, (int)tx_status);
    }
    else
    {
        MESH_DBG_PRINTF("[hwmp] PREQ alloc failed\n");
    }
}

static inline uint32_t hwmp_le32_at(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void umac_datapath_process_rx_hwmp(struct umac_data *umacd,
                                          struct umac_sta_data *stad,
                                          struct mmpktview *rxbufview)
{
    const uint8_t *frame_raw = (const uint8_t *)mmpkt_get_data_start(rxbufview);
    size_t frame_len = mmpkt_get_data_length(rxbufview);

    /* Minimum: 24 (hdr) + 1 (category) + 1 (action_code) = 26 */
    if (frame_len < 26)
    {
        return;
    }

    uint8_t action_code = frame_raw[25];
    if (action_code != HWMP_ACTION_CODE_PATH_SELECTION)
    {
        MESH_DBG_PRINTF("[hwmp] unsupported mesh action code %u\n", action_code);
        return;
    }

    /* Get our own MAC address */
    uint8_t our_addr[DOT11_MAC_ADDR_LEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, our_addr) != MMWLAN_SUCCESS)
    {
        if (umac_interface_get_device_mac_addr(umacd, our_addr) != MMWLAN_SUCCESS)
        {
            MESH_DBG_PRINTF("[hwmp] cannot get own MAC\n");
            return;
        }
    }

    const uint8_t *preq_sa = &frame_raw[10]; /* addr2 = SA/TA of PREQ sender */

    /* Parse IEs starting at offset 26 */
    size_t pos = 26;
    while (pos + 2 <= frame_len)
    {
        uint8_t eid = frame_raw[pos];
        uint8_t elen = frame_raw[pos + 1];
        if (pos + 2 + elen > frame_len)
        {
            break;
        }

        const uint8_t *ie = &frame_raw[pos + 2]; /* IE value */

        if (eid == WLAN_EID_PREQ && elen == HWMP_PREQ_IE_LEN)
        {
            /* PREQ IE fields (no AE, single target):
             *  [0]     flags
             *  [1]     hop count
             *  [2]     TTL
             *  [3..6]  PREQ ID (LE32)
             *  [7..12] Originator Address
             *  [13..16] Originator SN (LE32)
             *  [17..20] Lifetime (LE32)
             *  [21..24] Metric (LE32)
             *  [25]    Target Count
             *  [26]    Target Flags
             *  [27..32] Target Address
             *  [33..36] Target SN (LE32)
             */
            const uint8_t *orig_addr   = ie + 7;
            uint32_t orig_sn           = hwmp_le32_at(ie + 13);
            uint32_t lifetime          = hwmp_le32_at(ie + 17);
            const uint8_t *target_addr = ie + 27;
            uint32_t target_sn_in      = hwmp_le32_at(ie + 33);

                 MESH_DBG_PRINTF("[hwmp] PREQ rx: orig=" MM_MAC_ADDR_FMT " orig_sn=%u target="
                        MM_MAC_ADDR_FMT " target_sn=%u lifetime=%u ttl=%u hopcount=%u\n",
                        MM_MAC_ADDR_VAL(orig_addr), (unsigned)orig_sn,
                        MM_MAC_ADDR_VAL(target_addr), (unsigned)target_sn_in,
                        (unsigned)lifetime, (unsigned)ie[2], (unsigned)ie[1]);

            /* Is this PREQ looking for us? */
            if (memcmp(target_addr, our_addr, DOT11_MAC_ADDR_LEN) == 0)
            {
                /* Bump our SN if the target SN in the PREQ is >= ours */
                if (target_sn_in >= hwmp_own_sn)
                {
                    hwmp_own_sn = target_sn_in;
                }
                ++hwmp_own_sn;

                  MESH_DBG_PRINTF("[hwmp] PREQ is for us, sending PREP sn=%u -> " MM_MAC_ADDR_FMT "\n",
                            (unsigned)hwmp_own_sn, MM_MAC_ADDR_VAL(preq_sa));

                struct hwmp_prep_builder_args prep_args;
                memset(&prep_args, 0, sizeof(prep_args));
                prep_args.da = preq_sa;
                memcpy(prep_args.our_addr, our_addr, DOT11_MAC_ADDR_LEN);
                prep_args.target_sn = hwmp_own_sn;
                prep_args.lifetime = (lifetime != 0) ? lifetime : HWMP_DEFAULT_LIFETIME;
                memcpy(prep_args.orig_addr, orig_addr, DOT11_MAC_ADDR_LEN);
                prep_args.orig_sn = orig_sn;

                struct mmpkt *prep_pkt = build_mgmt_frame(umacd,
                                                          hwmp_prep_frame_build,
                                                          &prep_args);
                if (prep_pkt != NULL)
                {
                    enum mmwlan_status tx_status = umac_datapath_tx_mgmt_frame(stad, prep_pkt);
                    MESH_DBG_PRINTF("[hwmp] PREP tx status=%d\n", (int)tx_status);
                }
                else
                {
                    MESH_DBG_PRINTF("[hwmp] PREP alloc failed\n");
                }
            }
            else
            {
                  MESH_DBG_PRINTF("[hwmp] PREQ not for us (target=" MM_MAC_ADDR_FMT ")\n",
                            MM_MAC_ADDR_VAL(target_addr));
            }
        }
        else if (eid == WLAN_EID_PREP && elen == HWMP_PREP_IE_LEN)
        {
                 MESH_DBG_PRINTF("[hwmp] PREP rx: target=" MM_MAC_ADDR_FMT " orig=" MM_MAC_ADDR_FMT "\n",
                        MM_MAC_ADDR_VAL(ie + 3), MM_MAC_ADDR_VAL(ie + 21));
        }
        else if (eid == WLAN_EID_RANN)
        {
                 MESH_DBG_PRINTF("[hwmp] RANN rx from " MM_MAC_ADDR_FMT "\n",
                        MM_MAC_ADDR_VAL(ie + 3));
        }
        else if (eid == WLAN_EID_PERR)
        {
            MESH_DBG_PRINTF("[hwmp] PERR rx\n");
        }

        pos += 2 + elen;
    }
}

void umac_datapath_process_rx_action_frame(struct umac_data *umacd,
                                           struct umac_sta_data *stad,
                                           struct mmpktview *rxbufview)
{
    const struct dot11_action *frame = (struct dot11_action *)mmpkt_get_data_start(rxbufview);
    size_t rx_frame_len = mmpkt_get_data_length(rxbufview);
    const uint8_t *rx_raw = (const uint8_t *)frame;

    /* Diagnostic: dump received action frames for comparison with TX */
    if (frame->field.category == DOT11_ACTION_CATEGORY_SELF_PROTECTED)
    {
        const struct dot11_hdr *rxhdr = &frame->hdr;
        dp_mesh_dbg("[frame_diag] RX_ACTION: fc=0x%04x len=%u da=%02x:%02x:%02x:%02x:%02x:%02x"
               " sa=%02x:%02x:%02x:%02x:%02x:%02x bssid=%02x:%02x:%02x:%02x:%02x:%02x"
               " cat=%u act=%u\n",
               (unsigned)le16toh(rxhdr->frame_control),
               (unsigned)rx_frame_len,
               rxhdr->addr1[0], rxhdr->addr1[1], rxhdr->addr1[2],
               rxhdr->addr1[3], rxhdr->addr1[4], rxhdr->addr1[5],
               rxhdr->addr2[0], rxhdr->addr2[1], rxhdr->addr2[2],
               rxhdr->addr2[3], rxhdr->addr2[4], rxhdr->addr2[5],
               rxhdr->addr3[0], rxhdr->addr3[1], rxhdr->addr3[2],
               rxhdr->addr3[3], rxhdr->addr3[4], rxhdr->addr3[5],
               frame->field.category, rx_raw[25]);
        size_t rx_dump = rx_frame_len < 300 ? rx_frame_len : 300;
        dp_mesh_dbg("[frame_diag] hex: ");
        for (size_t i = 0; i < rx_dump; i++)
            dp_mesh_dbg("%02x ", rx_raw[i]);
        if (rx_frame_len > rx_dump)
            dp_mesh_dbg("...(+%u)", (unsigned)(rx_frame_len - rx_dump));
        dp_mesh_dbg("\n");
        /* Dump IEs */
        uint8_t rx_act = rx_raw[25];
        size_t rx_ie_start = 28 + (rx_act == 2 ? 2 : 0);
        if (rx_ie_start < rx_frame_len)
        {
            dp_mesh_dbg("[frame_diag] RX_ACTION_IES(offset=%u): ", (unsigned)rx_ie_start);
            size_t ie_pos = rx_ie_start;
            while (ie_pos + 1 < rx_frame_len)
            {
                uint8_t eid = rx_raw[ie_pos];
                uint8_t elen = rx_raw[ie_pos + 1];
                dp_mesh_dbg("eid=%u,len=%u ", eid, elen);
                if (ie_pos + 2 + elen > rx_frame_len) { dp_mesh_dbg("[TRUNCATED]"); break; }
                ie_pos += 2 + elen;
            }
            dp_mesh_dbg("\n");
        }
    }

    MMLOG_DBG("Action Category recieved: %u\n", frame->field.category);
    switch (frame->field.category)
    {
        case DOT11_ACTION_CATEGORY_BLOCK_ACK:
            umac_ba_process_rx_frame(stad,
                                     mmpkt_get_data_start(rxbufview),
                                     mmpkt_get_data_length(rxbufview));
            break;

        case DOT11_ACTION_CATEGORY_PUBLIC:
        case DOT11_ACTION_CATEGORY_SA_QUERY:
        case DOT11_ACTION_CATEGORY_WNM:
        case DOT11_ACTION_CATEGORY_SELF_PROTECTED:
            umac_supp_process_mgmt_frame(umacd, rxbufview);
            break;

        case DOT11_ACTION_CATEGORY_MESH:
            umac_datapath_process_rx_hwmp(umacd, stad, rxbufview);
            break;

        default:
            MMLOG_WRN("Unsupported Action Category: %u\n", frame->field.category);
            break;
    }
}


static void umac_datapath_process_unprotected_robust_mgmt_frame(struct umac_data *umacd,
                                                                struct mmpktview *rxbufview)
{
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);

    MMOSAL_ASSERT(umac_datapath_validate_buf_len(rxbufview, sizeof(*header)));

    if (frame_is_deauthentication(header))
    {
        const struct dot11_deauth *deauth = (struct dot11_deauth *)mmpkt_get_data_start(rxbufview);
        if (!umac_datapath_validate_buf_len(rxbufview, sizeof(*deauth)))
        {
            return;
        }

        MMLOG_DBG("Recieved unprotected deauth frame.\n");
        umac_supp_process_unprotected_deauth(umacd,
                                             le16toh(deauth->reason_code),
                                             dot11_get_sa(&deauth->hdr),
                                             dot11_get_da(&deauth->hdr));
    }
    else if (frame_is_disassociation(header))
    {
        const struct dot11_disassoc *disassoc =
            (struct dot11_disassoc *)mmpkt_get_data_start(rxbufview);
        if (!umac_datapath_validate_buf_len(rxbufview, sizeof(*disassoc)))
        {
            return;
        }

        MMLOG_DBG("Recieved unprotected disassoc frame.\n");
        umac_supp_process_unprotected_disassoc(umacd,
                                               le16toh(disassoc->reason_code),
                                               dot11_get_sa(&disassoc->hdr),
                                               dot11_get_da(&disassoc->hdr));
    }
    else
    {
        MMLOG_DBG("Recieved unexpected unprotected robust management frame.\n");
    }
}


static void umac_datapath_process_rx_mgmt_frame(struct umac_data *umacd,
                                                struct umac_sta_data *stad,
                                                struct umac_datapath_data *data,
                                                struct mmpktview *rxbufview)
{
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);

    MMOSAL_ASSERT(umac_datapath_validate_buf_len(rxbufview, sizeof(*header)));

    uint16_t frame_control_le = header->frame_control;

    if (frame_is_robust_mgmt(rxbufview))
    {
        if (stad == NULL)
        {

            return;
        }

        if (!dot11_frame_control_get_protected(frame_control_le) &&
            umac_sta_data_pmf_is_required(stad))
        {
            const uint8_t *frame_data = mmpkt_get_data_start(rxbufview) + sizeof(*header);
            size_t frame_data_len = mmpkt_get_data_length(rxbufview) - sizeof(*header);


            if (mm_mac_addr_is_multicast(dot11_get_da(header)) &&
                (ie_mmie_find(frame_data, frame_data_len) != NULL))
            {
                if (!bip_is_valid(stad, header, frame_data, frame_data_len))
                {
                    MMLOG_INF("Invalid frame security, dropping.\n");
                    return;
                }
            }
            else
            {
                umac_datapath_process_unprotected_robust_mgmt_frame(umacd, rxbufview);
                return;
            }
        }
    }

    MMOSAL_DEV_ASSERT(data->ops != NULL);
    data->ops->process_rx_mgmt_frame(umacd, stad, rxbufview);
}

static void umac_datapath_process_rx_mgmt_frame_sta(struct umac_data *umacd,
                                                    struct umac_sta_data *stad,
                                                    struct mmpktview *rxbufview)
{
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t frame_control_le = header->frame_control;
    uint16_t subtype = dot11_frame_control_get_subtype(frame_control_le);
    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);

    if (umac_scan_has_scan_req(umacd))
    {
        scan_dbg_raw_mgmt_sta_seen++;
        if ((scan_dbg_raw_mgmt_sta_seen % 32U) == 1U)
        {
            printf("[scan_raw] mgmt_sta_seen=%lu last_subtype=0x%x\n",
                   (unsigned long)scan_dbg_raw_mgmt_sta_seen,
                   subtype);
        }
    }

    if (sta_args != NULL && sta_args->mesh_mode && stad != NULL)
    {
        const uint8_t *peer_bssid = umac_sta_data_peek_bssid(stad);
        const uint8_t *peer_addr = umac_sta_data_peek_peer_addr(stad);
        enum connection_fsm_state conn_state = umac_connection_get_conn_fsm_state(umacd);

        if ((conn_state == CONNECTION_FSM_STATE_AUTHENTICATING ||
             conn_state == CONNECTION_FSM_STATE_CONNECTING))
        {
            mesh_dbg_mgmt_from_peer_seen++;
            if ((mesh_dbg_mgmt_from_peer_seen % 8U) == 1U)
            {
                MESH_DBG_PRINTF("[mesh_trace] MESH_RX_PEER_MGMT: count=%lu subtype=0x%x da=" MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT " peer=" MM_MAC_ADDR_FMT " cfg_bssid=" MM_MAC_ADDR_FMT " state=%s\n",
                       (unsigned long)mesh_dbg_mgmt_from_peer_seen,
                       subtype,
                       MM_MAC_ADDR_VAL(dot11_get_da(header)),
                       MM_MAC_ADDR_VAL(dot11_get_sa(header)),
                       MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)),
                       MM_MAC_ADDR_VAL(peer_addr),
                       MM_MAC_ADDR_VAL(peer_bssid),
                       umac_connection_conn_fsm_state_tostr(conn_state));
            }
        }
    }

    switch (subtype)
    {
        case DOT11_FC_SUBTYPE_ASSOC_RSP:
        case DOT11_FC_SUBTYPE_REASSOC_RSP:
            umac_connection_process_assoc_reassoc_rsp(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_PROBE_RSP:
            if (umac_scan_has_scan_req(umacd))
            {
                scan_dbg_raw_probe_rsp_seen++;
                if ((scan_dbg_raw_probe_rsp_seen % 8U) == 1U)
                {
                    printf("[scan_raw] probe_rsp_seen=%lu\n",
                           (unsigned long)scan_dbg_raw_probe_rsp_seen);
                }
            }
            umac_scan_process_probe_resp(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_PROBE_REQ:
            umac_datapath_try_mesh_probe_rsp(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_DISASSOC:
            umac_connection_process_disassoc_req(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_AUTH:
        {
            const struct dot11_hdr *auth_hdr =
                (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
            const uint8_t *auth_frame = (const uint8_t *)auth_hdr;
            const size_t auth_frame_len = mmpkt_get_data_length(rxbufview);
            uint16_t diag_alg = 0xffffU;
            uint16_t diag_seq = 0xffffU;
            uint16_t diag_status = 0xffffU;

            if (auth_frame_len >= sizeof(struct dot11_hdr) + 6U)
            {
                const uint8_t *body = auth_frame + sizeof(struct dot11_hdr);
                diag_alg = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
                diag_seq = (uint16_t)body[2] | ((uint16_t)body[3] << 8);
                diag_status = (uint16_t)body[4] | ((uint16_t)body[5] << 8);
            }

            printk("[MAC_MGMT] AUTH_RX len=%u stad=%p alg=%u seq=%u status=%u da="
                   MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                   (unsigned)auth_frame_len,
                   (void *)stad,
                   (unsigned)diag_alg,
                   (unsigned)diag_seq,
                   (unsigned)diag_status,
                   MM_MAC_ADDR_VAL(dot11_get_da(auth_hdr)),
                   MM_MAC_ADDR_VAL(dot11_get_sa(auth_hdr)),
                   MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(auth_hdr)));

            if (sta_args != NULL && sta_args->mesh_mode)
            {
                /*
                 * The first SAE commit arrives before UMAC has a station
                 * record for the mesh peer. Route it to mesh_mpm even when
                 * stad is NULL; apply the configured-peer check only once a
                 * station record exists.
                 */
                if (stad != NULL)
                {
                    const uint8_t *cfg_peer = umac_sta_data_peek_peer_addr(stad);
                    const uint8_t *cfg_bssid = umac_sta_data_peek_bssid(stad);
                    const uint8_t *rx_sa = dot11_get_sa(auth_hdr);
                    const uint8_t *rx_bssid = dot11_mgmt_get_bssid(auth_hdr);
                    bool peer_set = (cfg_peer != NULL) && !mm_mac_addr_is_zero(cfg_peer);
                    bool bssid_set = (cfg_bssid != NULL) && !mm_mac_addr_is_zero(cfg_bssid);

                    if ((peer_set && !mm_mac_addr_is_equal(rx_sa, cfg_peer)) ||
                        (bssid_set && !mm_mac_addr_is_equal(rx_bssid, cfg_bssid)))
                    {
                        MESH_DBG_PRINTF("[mesh_trace] MESH_AUTH_RX_DROP: foreign auth sa=" MM_MAC_ADDR_FMT
                               " bssid=" MM_MAC_ADDR_FMT " expected_peer=" MM_MAC_ADDR_FMT
                               " expected_bssid=" MM_MAC_ADDR_FMT "\n",
                               MM_MAC_ADDR_VAL(rx_sa),
                               MM_MAC_ADDR_VAL(rx_bssid),
                               MM_MAC_ADDR_VAL(cfg_peer),
                               MM_MAC_ADDR_VAL(cfg_bssid));
                        break;
                    }
                }

                /*
                 * In mesh mode, let mesh_mpm/SAE exclusively own AUTH frame
                 * progression via EVENT_RX_MGMT. Running connection auth
                 * response handling here can race/perturb SAE state.
                 */

                const uint8_t *frame = (const uint8_t *)auth_hdr;
                const size_t frame_len = mmpkt_get_data_length(rxbufview);
                uint16_t auth_alg = 0xffff;
                uint16_t auth_seq = 0xffff;
                uint16_t auth_status = 0xffff;
                uint16_t sae_group = 0;

                if (frame_len >= sizeof(struct dot11_hdr) + 6U)
                {
                    const uint8_t *body = frame + sizeof(struct dot11_hdr);
                    auth_alg = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
                    auth_seq = (uint16_t)body[2] | ((uint16_t)body[3] << 8);
                    auth_status = (uint16_t)body[4] | ((uint16_t)body[5] << 8);
                    if (frame_len >= sizeof(struct dot11_hdr) + 8U)
                    {
                        sae_group = (uint16_t)body[6] | ((uint16_t)body[7] << 8);
                    }
                }

                MESH_DBG_PRINTF("[mesh_trace] MESH_AUTH_RX: subtype=0x%x len=%u da=" MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT " alg=%u seq=%u status=%u group=%u\n",
                       subtype,
                       (unsigned)frame_len,
                       MM_MAC_ADDR_VAL(dot11_get_da(auth_hdr)),
                       MM_MAC_ADDR_VAL(dot11_get_sa(auth_hdr)),
                       MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(auth_hdr)),
                       (unsigned)auth_alg,
                       (unsigned)auth_seq,
                       (unsigned)auth_status,
                       (unsigned)sae_group);

                /* Mesh SAE auth is handled in mesh_mpm via EVENT_RX_MGMT. */
                  MESH_DBG_PRINTF("[mesh_trace] MESH_AUTH_RX_ROUTE: calling umac_supp_process_mgmt_frame len=%u seq=%u\n",
                      (unsigned)frame_len,
                      (unsigned)auth_seq);
                umac_supp_process_mgmt_frame(umacd, rxbufview);
                  MESH_DBG_PRINTF("[mesh_trace] MESH_AUTH_RX_ROUTE: returned from umac_supp_process_mgmt_frame seq=%u\n",
                      (unsigned)auth_seq);
            }
            else
            {
                umac_connection_process_auth_resp(umacd, rxbufview);
            }
            break;
        }

        case DOT11_FC_SUBTYPE_DEAUTH:
            umac_connection_process_deauth_rx(umacd, rxbufview);
            break;

        case DOT11_FC_SUBTYPE_ACTION:
            umac_datapath_process_rx_action_frame(umacd, stad, rxbufview);
            break;

        default:
            MMLOG_WRN("Recieved unsupported MGMT frame: frame_control=0x%04x\n",
                      le16toh(frame_control_le));
            break;
    }
}


static void umac_datapath_generate_8023_header(const uint8_t *dest_addr,
                                               const uint8_t *src_addr,
                                               uint16_t ethertype,
                                               struct umac_8023_hdr *header)
{
    mac_addr_copy(header->src_addr, src_addr);
    mac_addr_copy(header->dest_addr, dest_addr);
    header->ethertype_be = htobe16(ethertype);
}


static uint16_t umac_datapath_get_llc_ethertype(struct mmpktview *view)
{
    if (!umac_datapath_validate_buf_len(view, UMAC_802_1_HEADER_LEN))
    {
        MMLOG_INF("Packet too short for LLC/SNAP header\n");
        return 0;
    }
    uint8_t *header = mmpkt_get_data_start(view);

    if (memcmp(snap_802_1h, header, sizeof(snap_802_1h)) != 0)
    {
        MMLOG_DUMP_INF("Unable to find matching LLC/SNAP in buffer:\n    ",
                       header,
                       sizeof(snap_802_1h));
        return 0;
    }

    uint16_t ethertype;
    PACK_BE16(ethertype, (header + sizeof(snap_802_1h)));

    return ethertype;
}


static bool umac_datapath_is_eapol_frame(struct mmpktview *rxbufview)
{
    return (umac_datapath_get_llc_ethertype(rxbufview) == ETHERTYPE_EAPOL);
}

static const char *mesh_dhcp_msg_type_to_str(uint8_t msg_type)
{
    switch (msg_type)
    {
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

static void mesh_log_dhcp_ipv4_payload(struct mmpktview *rxbufview)
{
    const uint8_t *ip = (const uint8_t *)mmpkt_get_data_start(rxbufview);
    size_t len = mmpkt_get_data_length(rxbufview);

    if (len < 20)
    {
        return;
    }
    if ((ip[0] >> 4) != 4)
    {
        return;
    }

    size_t ihl = (size_t)(ip[0] & 0x0f) * 4U;
    if (ihl < 20 || len < ihl + 8)
    {
        return;
    }
    if (ip[9] != 17)
    {
        return;
    }

    const uint8_t *udp = ip + ihl;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
    if (!((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67)))
    {
        return;
    }

    if (len < ihl + 8 + 240)
    {
        return;
    }

    const uint8_t *dhcp = udp + 8;
    uint8_t op = dhcp[0];
    uint32_t xid = ((uint32_t)dhcp[4] << 24) | ((uint32_t)dhcp[5] << 16) |
                   ((uint32_t)dhcp[6] << 8) | dhcp[7];

    uint8_t msg_type = 0;
    if (dhcp[236] == 0x63 && dhcp[237] == 0x82 && dhcp[238] == 0x53 && dhcp[239] == 0x63)
    {
        size_t i = 240;
        while (i < (len - ihl - 8))
        {
            uint8_t opt = dhcp[i];
            if (opt == 0xff)
            {
                break;
            }
            if (opt == 0)
            {
                i++;
                continue;
            }
            if (i + 1 >= (len - ihl - 8))
            {
                break;
            }
            uint8_t opt_len = dhcp[i + 1];
            if (i + 2 + opt_len > (len - ihl - 8))
            {
                break;
            }
            if (opt == 53 && opt_len == 1)
            {
                msg_type = dhcp[i + 2];
                break;
            }
            i += 2 + opt_len;
        }
    }

    dp_mesh_dbg("[dp_mesh_dhcp] udp=%u->%u op=%u msg=%s(%u) xid=0x%08lx ci=%u.%u.%u.%u yi=%u.%u.%u.%u si=%u.%u.%u.%u chaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
           src_port,
           dst_port,
           op,
           mesh_dhcp_msg_type_to_str(msg_type),
           msg_type,
           (unsigned long)xid,
           dhcp[12], dhcp[13], dhcp[14], dhcp[15],
           dhcp[16], dhcp[17], dhcp[18], dhcp[19],
           dhcp[20], dhcp[21], dhcp[22], dhcp[23],
           dhcp[28], dhcp[29], dhcp[30], dhcp[31], dhcp[32], dhcp[33]);
}

/**
 * Set the BOOTP broadcast flag on outgoing DHCP client requests in mesh mode.
 * This forces the DHCP server to broadcast replies (OFFER/ACK), which is needed
 * because 802.11s mesh unicast delivery requires HWMP path resolution that the
 * ESP32 mesh implementation does not support.
 *
 * @param txbufview  TX buffer containing full ethernet frame
 * @param ethertype  Ethertype from the ethernet header
 */
static void mesh_set_dhcp_broadcast_flag(struct mmpktview *txbufview, uint16_t ethertype)
{
    if (ethertype != 0x0800)
    {
        return;
    }

    uint8_t *pkt = (uint8_t *)mmpkt_get_data_start(txbufview);
    size_t pkt_len = mmpkt_get_data_length(txbufview);

    /* Minimum: 14(ether) + 20(IP) + 8(UDP) + 12(BOOTP through flags) = 54 */
    if (pkt_len < 54)
    {
        return;
    }

    /* IP header starts after 14-byte ethernet header */
    const uint8_t *ip = pkt + 14;
    if ((ip[0] >> 4) != 4)
    {
        return;
    }
    size_t ihl = (size_t)(ip[0] & 0x0F) * 4U;
    if (ihl < 20 || pkt_len < 14 + ihl + 8 + 12)
    {
        return;
    }
    /* Must be UDP (proto 17) */
    if (ip[9] != 17)
    {
        return;
    }

    const uint8_t *udp = ip + ihl;
    uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];

    /* DHCP client request: src=68 (bootpc), dst=67 (bootps) */
    if (src_port != 68 || dst_port != 67)
    {
        return;
    }

    /* BOOTP starts after 8-byte UDP header */
    uint8_t *bootp = pkt + 14 + ihl + 8;
    uint16_t old_flags = ((uint16_t)bootp[10] << 8) | bootp[11];

    if (!(old_flags & 0x8000))
    {
        /* Set broadcast flag (0x8000 in network byte order) */
        bootp[10] = 0x80;
        bootp[11] = 0x00;

        /* Zero the UDP checksum — optional for IPv4 (RFC 768) */
        uint8_t *udp_w = pkt + 14 + ihl;
        udp_w[6] = 0;
        udp_w[7] = 0;

        dp_mesh_dbg("[dp_mesh_tx] Set BOOTP broadcast flag (was 0x%04x)\n", old_flags);
    }
}


static void umac_datapath_process_rx_eapol_frame(struct umac_data *umacd,
                                                 struct umac_datapath_data *data,
                                                 struct mmpktview *rxbufview,
                                                 const struct dot11_hdr *header)
{
    MMOSAL_DEV_ASSERT(data->ops != NULL);



    MMOSAL_ASSERT(mmpkt_remove_from_start(rxbufview, UMAC_802_1_HEADER_LEN) != NULL);

    umac_supp_l2_sock_receive(umacd,
                              mmpkt_get_data_start(rxbufview),
                              mmpkt_get_data_length(rxbufview),
                              dot11_get_sa(header));
}

/**
 * Software CCMP encrypt for mesh TX.
 *
 * The chip's HW CCMP may compute AAD incorrectly for 4-address mesh frames
 * (observed: chip clears ToDS bit, producing 3-addr AAD instead of 4-addr).
 * This function performs SW CCMP encrypt with correct 4-addr AAD.
 *
 * Called AFTER all headers are prepended: [MAC_hdr 30B][QoS 2B][body...]
 * On success, replaces body with [CCMP_hdr 8B][ciphertext][MIC 8B].
 *
 * @param stad      STA data (for key lookup)
 * @param key_id    key index to use
 * @param data_hdr  pointer to constructed dot11_data_hdr (for AAD)
 * @param qos_ctrl  QoS control field value (for AAD)
 * @param qos_tid   TID from QoS control (for nonce priority octet)
 * @param txbufview view of the full frame [MAC_hdr][QoS][body]
 * @return true on success, false on failure
 */
static bool mesh_sw_ccmp_encrypt(struct umac_sta_data *stad,
                                 int key_id,
                                 const struct dot11_data_hdr *data_hdr,
                                 uint16_t qos_field,
                                 uint8_t qos_tid,
                                 struct mmpktview *txbufview)
{
    const size_t mic_len = DOT11_CCMP_128_MIC_LEN; /* 8 */
    const struct dot11_hdr *header = &data_hdr->base;

    /* Get the temporal key */
    const uint8_t *tk = umac_keys_get_key_data(stad, key_id);
    size_t tk_len = umac_keys_get_key_len(stad, key_id);
    if (tk == NULL || tk_len != 16)
    {
        printf("[dp_mesh_tx] sw_ccmp: no key id=%d len=%lu\n", key_id, (unsigned long)tk_len);
        return false;
    }

    /* Get current TX PN and increment */
    uint64_t pn = umac_keys_get_tx_seq_by_id(stad, key_id);
    umac_keys_increment_tx_seq(stad, key_id);

    /* Identify the body (everything after MAC header + QoS = offset 32) */
    const uint8_t *frame_start = (const uint8_t *)mmpkt_get_data_start(txbufview);
    size_t frame_len = mmpkt_get_data_length(txbufview);
    size_t hdr_plus_qos = sizeof(struct dot11_data_hdr) + sizeof(struct dot11_qos_ctrl); /* 32 */
    if (frame_len <= hdr_plus_qos)
    {
        printf("[dp_mesh_tx] sw_ccmp: frame too short %lu\n", (unsigned long)frame_len);
        return false;
    }
    const uint8_t *plaintext = frame_start + hdr_plus_qos;
    size_t plain_len = frame_len - hdr_plus_qos;

    /* Build CCMP nonce (13 bytes): Priority | A2 | PN5..PN0 */
    uint8_t nonce[13];
    nonce[0] = qos_tid & 0x0f;
    memcpy(&nonce[1], header->addr2, 6);
    nonce[7]  = (pn >> 40) & 0xff;
    nonce[8]  = (pn >> 32) & 0xff;
    nonce[9]  = (pn >> 24) & 0xff;
    nonce[10] = (pn >> 16) & 0xff;
    nonce[11] = (pn >> 8) & 0xff;
    nonce[12] = pn & 0xff;

    /* Build AAD (30 bytes for 4-address QoS Data frame) */
    uint8_t aad[30];
    uint8_t *pos = aad;
    uint16_t fc = le16toh(header->frame_control);
    /* Mask FC per CCMP spec: clear Retry, PwrMgt, MoreData, +HTC bits; set Protected */
    fc &= ~(DOT11_MASK_FC_RETRY | DOT11_MASK_FC_MORE_DATA | (1 << 12) | (1 << 15));
    fc |= DOT11_MASK_FC_PROTECTED;
    *pos++ = fc & 0xff;
    *pos++ = (fc >> 8) & 0xff;
    memcpy(pos, header->addr1, 6); pos += 6;
    memcpy(pos, header->addr2, 6); pos += 6;
    memcpy(pos, header->addr3, 6); pos += 6;
    /* Sequence control: mask sequence number, keep fragment number */
    *pos++ = 0; *pos++ = 0;
    memcpy(pos, data_hdr->addr4, 6); pos += 6;
    /* QoS: mask to just TID (bits 0-3) */
    *pos++ = qos_tid & 0x0f;
    *pos++ = 0;
    size_t aad_len = (size_t)(pos - aad); /* should be 30 */

    /* Build CCMP header (8 bytes) from PN */
    uint8_t ccmp_hdr[DOT11_CCMP_HEADER_LEN]; /* 8 */
    ccmp_hdr[0] = pn & 0xff;         /* PN0 */
    ccmp_hdr[1] = (pn >> 8) & 0xff;  /* PN1 */
    ccmp_hdr[2] = 0;                  /* Reserved */
    ccmp_hdr[3] = (key_id << 6) | 0x20; /* KeyID | ExtIV=1 */
    ccmp_hdr[4] = (pn >> 16) & 0xff; /* PN2 */
    ccmp_hdr[5] = (pn >> 24) & 0xff; /* PN3 */
    ccmp_hdr[6] = (pn >> 32) & 0xff; /* PN4 */
    ccmp_hdr[7] = (pn >> 40) & 0xff; /* PN5 */

    /* Allocate temp buffers for ciphertext + MIC */
    uint8_t *ciphertext = (uint8_t *)malloc(plain_len);
    uint8_t mic[8];
    if (ciphertext == NULL)
    {
        printf("[dp_mesh_tx] sw_ccmp: malloc failed\n");
        return false;
    }

    /* Encrypt */
    int ret = aes_ccm_ae(tk, tk_len, nonce, mic_len,
                         plaintext, plain_len,
                         aad, aad_len, ciphertext, mic);
    if (ret != 0)
    {
        printf("[dp_mesh_tx] sw_ccmp: encrypt FAILED ret=%d\n", ret);
        free(ciphertext);
        return false;
    }

    /* Replace body: remove plaintext, append CCMP_hdr + ciphertext + MIC */
    mmpkt_remove_from_end(txbufview, plain_len);
    mmpkt_append_data(txbufview, ccmp_hdr, sizeof(ccmp_hdr));
    mmpkt_append_data(txbufview, ciphertext, plain_len);
    mmpkt_append_data(txbufview, mic, sizeof(mic));

    dp_mesh_dbg("[dp_mesh_tx] sw_ccmp OK pn=%llu plain_len=%lu aad_len=%lu\n",
           (unsigned long long)pn, (unsigned long)plain_len, (unsigned long)aad_len);

    free(ciphertext);
    return true;
}

/**
 * The Morse Micro chip's HW crypto cannot decrypt mesh frames from peers
 * because each peer has its own BSSID and the chip's key lookup is tied to
 * the local VIF's BSSID. This function performs software CCMP decrypt for
 * both broadcast (using peer's MGTK, key_id>=1) and unicast (using the
 * pairwise TK, key_id=0) mesh frames.
 *
 * @param stad      STA data (for key lookup)
 * @param header    pointer to the 802.11 header (already consumed from rxbufview)
 * @param rxbufview view starting at CCMP header (8B) | ciphertext | MIC (8B)
 * @param qos_tid   TID from QoS control (for nonce priority octet)
 * @return true on success (rxbufview updated to plaintext), false on failure
 */
static bool mesh_sw_ccmp_decrypt(struct umac_data *umacd,
                                 struct umac_sta_data *stad,
                                 struct umac_datapath_data *data,
                                 const struct dot11_hdr *header,
                                 struct mmpktview *rxbufview,
                                 uint8_t qos_tid)
{
    MM_UNUSED(umacd);
    const size_t ccmp_hdr_len = DOT11_CCMP_HEADER_LEN; /* 8 */
    const size_t mic_len = DOT11_CCMP_128_MIC_LEN;     /* 8 */
    size_t total_len = mmpkt_get_data_length(rxbufview);

    if (total_len < ccmp_hdr_len + mic_len)
    {
        MESH_DBG_PRINTF("[dp_mesh_rx] sw_ccmp: frame too short %lu\n", (unsigned long)total_len);
        return false;
    }

    const uint8_t *buf = (const uint8_t *)mmpkt_get_data_start(rxbufview);

    /* Parse CCMP header: PN and KeyID */
    uint8_t key_id = (buf[3] >> 6) & 0x03;
    uint8_t pn[6];
    pn[0] = buf[0]; /* PN0 */
    pn[1] = buf[1]; /* PN1 */
    pn[2] = buf[4]; /* PN2 */
    pn[3] = buf[5]; /* PN3 */
    pn[4] = buf[6]; /* PN4 */
    pn[5] = buf[7]; /* PN5 */

    /* Prefer cached peer RX-only MGTK for mesh multicast SW decrypt. */
    const uint8_t *tk = NULL;
    size_t tk_len = 0;
    if (data->mesh_peer_group_key_valid && data->mesh_peer_group_key_id == key_id)
    {
        tk = data->mesh_peer_group_key;
        tk_len = data->mesh_peer_group_key_len;
    }
    else
    {
        tk = umac_keys_get_key_data(stad, key_id);
        tk_len = umac_keys_get_key_len(stad, key_id);
    }
    if (tk == NULL || tk_len != 16)
    {
        MESH_DBG_PRINTF("[dp_mesh_rx] sw_ccmp: no key for id=%u len=%lu\n",
                key_id, (unsigned long)tk_len);
        return false;
    }

    /* Build CCMP nonce (13 bytes):
     * nonce[0]    = Priority (QoS TID & 0x0f)
     * nonce[1..6] = A2 (TA / transmitter address)
     * nonce[7..12]= PN5..PN0 */
    uint8_t nonce[13];
    nonce[0] = qos_tid & 0x0f;
    memcpy(&nonce[1], header->addr2, 6);
    nonce[7]  = pn[5];
    nonce[8]  = pn[4];
    nonce[9]  = pn[3];
    nonce[10] = pn[2];
    nonce[11] = pn[1];
    nonce[12] = pn[0];

    /* Build AAD from 802.11 header.
     * For 3-addr QoS Data: FC(2) + addr1(6) + addr2(6) + addr3(6) + SC(2) + QoS(2) = 24 bytes
     * For 4-addr QoS Data: + addr4(6) = 30 bytes */
    uint8_t aad[30];
    size_t aad_len;
    uint16_t fc = le16toh(header->frame_control);
    bool addr4 = (fc & (DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS)) ==
                 (DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS);

    /* Mask FC: clear Retry, PwrMgt, MoreData, SubType bits 4-6; set Protected */
    fc &= ~(DOT11_MASK_FC_RETRY | DOT11_MASK_FC_MORE_DATA);
    /* Also clear power management bit (bit 12) */
    fc &= ~(1 << 12);
    /* Mask subtype bits (bits 4-6 of subtype, which are bits 7-9 of FC) — not needed per spec,
     * but zero the HTC order bit (bit 15) */
    fc &= ~(1 << 15);
    fc |= DOT11_MASK_FC_PROTECTED;

    uint8_t *pos = aad;
    *pos++ = fc & 0xff;
    *pos++ = (fc >> 8) & 0xff;
    memcpy(pos, header->addr1, 6); pos += 6;
    memcpy(pos, header->addr2, 6); pos += 6;
    memcpy(pos, header->addr3, 6); pos += 6;
    /* Sequence control: mask sequence number (bits 4-15), keep fragment number (bits 0-3) */
    uint16_t sc = le16toh(header->sequence_control);
    *pos++ = sc & 0x0f;
    *pos++ = 0;
    if (addr4)
    {
        const struct dot11_data_hdr *dhdr = (const struct dot11_data_hdr *)header;
        memcpy(pos, dhdr->addr4, 6);
        pos += 6;
    }
    /* QoS control: mask bits 4-6 (Ack Policy) and bit 7 (A-MSDU present) to 0 */
    *pos++ = qos_tid & 0x0f;
    *pos++ = 0;
    aad_len = pos - aad;

    /* Pointers into the encrypted payload */
    const uint8_t *crypt = buf + ccmp_hdr_len;
    size_t crypt_len = total_len - ccmp_hdr_len - mic_len;
    const uint8_t *auth_tag = buf + ccmp_hdr_len + crypt_len;

    /* Allocate temp buffer for plaintext */
    uint8_t *plain = (uint8_t *)malloc(crypt_len);
    if (plain == NULL)
    {
        MESH_DBG_PRINTF("[dp_mesh_rx] sw_ccmp: malloc failed\n");
        return false;
    }

    int ret = aes_ccm_ad(tk, tk_len, nonce, mic_len,
                         crypt, crypt_len,
                         aad, aad_len, auth_tag, plain);
    if (ret != 0)
    {
         MESH_DBG_PRINTF("[dp_mesh_rx] sw_ccmp: decrypt FAILED key_id=%u crypt_len=%lu aad_len=%lu\n",
                   key_id, (unsigned long)crypt_len, (unsigned long)aad_len);
         MESH_DBG_PRINTF("[dp_mesh_rx] sw_ccmp: nonce=");
         for (int i = 0; i < 13; i++) MESH_DBG_PRINTF("%02x", nonce[i]);
         MESH_DBG_PRINTF("\n[dp_mesh_rx] sw_ccmp: aad=");
         for (size_t i = 0; i < aad_len; i++) MESH_DBG_PRINTF("%02x", aad[i]);
         MESH_DBG_PRINTF("\n");
        free(plain);
        return false;
    }

    dp_mesh_dbg("[dp_mesh_rx] sw_ccmp OK key_id=%u plain_len=%lu\n",
           key_id, (unsigned long)crypt_len);

    /* Strip CCMP header from front */
    mmpkt_remove_from_start(rxbufview, ccmp_hdr_len);
    /* Strip MIC from end */
    mmpkt_remove_from_end(rxbufview, mic_len);
    /* Overwrite encrypted data with plaintext */
    uint8_t *data_start = (uint8_t *)mmpkt_get_data_start(rxbufview);
    memcpy(data_start, plain, crypt_len);

    free(plain);
    return true;
}


/**
 * SW CCMP decrypt for broadcast/multicast management frames (e.g. HWMP PREQs).
 * HW cannot decrypt mesh multicast management frames because the peer BSSID
 * differs from our VIF's BSSID. This mirrors mesh_sw_ccmp_decrypt() but uses
 * management-frame AAD format (no QoS, no addr4) and priority=0 nonce.
 *
 * On entry rxbufview = [dot11_hdr][CCMP_HDR][encrypted][MIC].
 * On success rxbufview = [dot11_hdr][plaintext] (CCMP hdr + MIC stripped).
 */
static bool mesh_sw_ccmp_decrypt_mgmt(struct umac_data *umacd,
                                      struct umac_sta_data *stad,
                                      struct umac_datapath_data *dpdata,
                                      struct mmpktview *rxbufview)
{
    const size_t hdr_len = sizeof(struct dot11_hdr);
    const size_t ccmp_hdr_len = DOT11_CCMP_HEADER_LEN; /* 8 */
    const size_t mic_len = DOT11_CCMP_128_MIC_LEN;     /* 8 */
    size_t total_len = mmpkt_get_data_length(rxbufview);

    if (total_len < hdr_len + ccmp_hdr_len + mic_len + 1)
    {
        MESH_DBG_PRINTF("[mesh_mgmt_rx] sw_ccmp: frame too short %lu\n", (unsigned long)total_len);
        return false;
    }

    /* Save header copy — pointer will be invalidated by view modifications */
    const uint8_t *raw = (const uint8_t *)mmpkt_get_data_start(rxbufview);
    struct dot11_hdr hdr_copy;
    memcpy(&hdr_copy, raw, sizeof(hdr_copy));

    /* Locate CCMP header right after the dot11 header */
    const uint8_t *ccmp_start = raw + hdr_len;

    /* Parse CCMP header: KeyID and PN */
    uint8_t key_id = (ccmp_start[3] >> 6) & 0x03;
    uint8_t pn[6];
    pn[0] = ccmp_start[0]; pn[1] = ccmp_start[1];
    pn[2] = ccmp_start[4]; pn[3] = ccmp_start[5];
    pn[4] = ccmp_start[6]; pn[5] = ccmp_start[7];

    /* Validate replay counter (same counter space as HW mgmt path).
     * For non-peer broadcast frames (e.g. HWMP PREQs from non-adjacent nodes),
     * the stad is a fallback (primary peer) whose PN counters belong to a
     * different sender.  Skip replay check in that case — the AES-CCM
     * authentication tag still guarantees integrity and authenticity. */
    mmpkt_remove_from_start(rxbufview, hdr_len);
    bool ta_is_known_peer = (dpdata->ops != NULL &&
                             dpdata->ops->lookup_stad_by_peer_addr(umacd, hdr_copy.addr2) != NULL);
    if (ta_is_known_peer)
    {
        if (!ccmp_is_valid(stad, (uint8_t *)mmpkt_get_data_start(rxbufview),
                           UMAC_KEY_RX_COUNTER_SPACE_IND_ROBUST_MGMT))
        {
            MESH_DBG_PRINTF("[mesh_mgmt_rx] sw_ccmp: replay check failed\n");
            umac_stats_increment_datapath_rx_ccmp_failures(umacd);
            uint8_t *hdr_dest = mmpkt_prepend(rxbufview, hdr_len);
            memmove(hdr_dest, &hdr_copy, hdr_len);
            return false;
        }
    }
    else
    {
        dp_mesh_dbg("[mesh_mgmt_rx] sw_ccmp: skip replay for non-peer ta="
               MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(hdr_copy.addr2));
    }

    /* Look up MGTK */
    const uint8_t *tk = NULL;
    size_t tk_len = 0;
    if (dpdata->mesh_peer_group_key_valid && dpdata->mesh_peer_group_key_id == key_id)
    {
        tk = dpdata->mesh_peer_group_key;
        tk_len = dpdata->mesh_peer_group_key_len;
    }
    else
    {
        tk = umac_keys_get_key_data(stad, key_id);
        tk_len = umac_keys_get_key_len(stad, key_id);
    }
    if (tk == NULL || tk_len != 16)
    {
        MESH_DBG_PRINTF("[mesh_mgmt_rx] sw_ccmp: no key id=%u len=%lu\n",
                key_id, (unsigned long)tk_len);
        uint8_t *hdr_dest = mmpkt_prepend(rxbufview, hdr_len);
        memmove(hdr_dest, &hdr_copy, hdr_len);
        return false;
    }

    /* Build CCMP nonce (13 bytes): management bit (0x10) set per
     * IEEE 802.11-2020 sec 12.5.3.3.3 and hostap wlantest/ccmp.c */
    uint8_t nonce[13];
    nonce[0] = 0x10; /* management frame: bit 4 set, TID=0 */
    memcpy(&nonce[1], hdr_copy.addr2, 6);
    nonce[7]  = pn[5]; nonce[8]  = pn[4]; nonce[9]  = pn[3];
    nonce[10] = pn[2]; nonce[11] = pn[1]; nonce[12] = pn[0];

    /* Build AAD for management frames:
     * FC(2) + A1(6) + A2(6) + A3(6) + SC(2) = 22 bytes
     * FC masked per IEEE 802.11-2020 / hostap ccmp_aad_nonce():
     *   Retry=0, PwrMgmt=0, MoreData=0, Protected=1
     *   Subtype bits are NOT masked for management frames */
    uint8_t aad[22];
    uint16_t fc = le16toh(hdr_copy.frame_control);
    fc &= ~(DOT11_MASK_FC_RETRY | DOT11_MASK_FC_MORE_DATA |
             (1u << 12) /* PwrMgmt */ | (1u << 15) /* Order/HTC */);
    fc |= DOT11_MASK_FC_PROTECTED;
    uint8_t *apos = aad;
    *apos++ = fc & 0xff; *apos++ = (fc >> 8) & 0xff;
    memcpy(apos, hdr_copy.addr1, 6); apos += 6;
    memcpy(apos, hdr_copy.addr2, 6); apos += 6;
    memcpy(apos, hdr_copy.addr3, 6); apos += 6;
    uint16_t sc = le16toh(hdr_copy.sequence_control);
    *apos++ = sc & 0x0f; *apos++ = 0;

    /* rxbufview now starts at CCMP header: [CCMP_HDR(8)][encrypted][MIC(8)] */
    const uint8_t *buf = (const uint8_t *)mmpkt_get_data_start(rxbufview);
    size_t payload_len = mmpkt_get_data_length(rxbufview) - ccmp_hdr_len - mic_len;
    const uint8_t *crypt = buf + ccmp_hdr_len;
    const uint8_t *auth_tag = crypt + payload_len;

    uint8_t *plain = (uint8_t *)malloc(payload_len);
    if (plain == NULL)
    {
        MESH_DBG_PRINTF("[mesh_mgmt_rx] sw_ccmp: malloc failed\n");
        uint8_t *hdr_dest = mmpkt_prepend(rxbufview, hdr_len);
        memmove(hdr_dest, &hdr_copy, hdr_len);
        return false;
    }

    int ret = aes_ccm_ad(tk, tk_len, nonce, mic_len,
                         crypt, payload_len,
                         aad, 22, auth_tag, plain);
    if (ret != 0)
    {
         MESH_DBG_PRINTF("[mesh_mgmt_rx] sw_ccmp FAIL key_id=%u enc_len=%lu sa="
                   MM_MAC_ADDR_FMT "\n",
                   key_id, (unsigned long)payload_len,
                   MM_MAC_ADDR_VAL(hdr_copy.addr2));
         MESH_DBG_PRINTF("[mesh_mgmt_rx] nonce=");
         for (int i = 0; i < 13; i++) MESH_DBG_PRINTF("%02x", nonce[i]);
         MESH_DBG_PRINTF("\n[mesh_mgmt_rx] aad=");
         for (int i = 0; i < 22; i++) MESH_DBG_PRINTF("%02x", aad[i]);
         MESH_DBG_PRINTF("\n[mesh_mgmt_rx] pn=%02x%02x%02x%02x%02x%02x key_src=%s\n",
                   pn[5], pn[4], pn[3], pn[2], pn[1], pn[0],
                   (dpdata->mesh_peer_group_key_valid &&
                    dpdata->mesh_peer_group_key_id == key_id)
                    ? "peer_cache" : "stad_hw");
        free(plain);
        uint8_t *hdr_dest = mmpkt_prepend(rxbufview, hdr_len);
        memmove(hdr_dest, &hdr_copy, hdr_len);
        return false;
    }

    dp_mesh_dbg("[mesh_mgmt_rx] sw_ccmp OK key_id=%u plain_len=%lu cat=%u\n",
           key_id, (unsigned long)payload_len,
           payload_len > 0 ? plain[0] : 0xff);

    /* Strip CCMP header */
    mmpkt_remove_from_start(rxbufview, ccmp_hdr_len);
    /* Strip MIC from end */
    mmpkt_remove_from_end(rxbufview, mic_len);
    /* Overwrite encrypted payload with plaintext */
    memcpy((uint8_t *)mmpkt_get_data_start(rxbufview), plain, payload_len);
    free(plain);

    /* Re-insert the dot11 header (preserving original FC with Protected bit) */
    uint8_t *hdr_dest = mmpkt_prepend(rxbufview, hdr_len);
    memmove(hdr_dest, &hdr_copy, hdr_len);

    return true;
}


/**
 * SW CCMP encrypt for broadcast/multicast management frames (mesh RMF).
 * HW crypto constructs CCMP nonce/AAD using data-frame format even for
 * management frames, causing a mismatch with the peer's SW mgmt-frame
 * decrypt path.  Software encrypt ensures matching AAD/nonce construction.
 *
 * Because management-frame mmpkt buffers are allocated without tailroom for
 * the 16 extra bytes (8-byte CCMP header + 8-byte MIC), we allocate a new
 * heap mmpkt, build the encrypted frame in it, and return it.  The caller
 * is responsible for releasing the original txbuf.
 *
 * @param stad   STA data (for key lookup — uses the local group MGTK)
 * @param key_id group key index to use
 * @param orig_view opened view of the original frame [dot11_hdr(24)][body]
 * @return new mmpkt containing the encrypted frame, or NULL on failure
 */
static struct mmpkt *mesh_sw_ccmp_encrypt_mgmt(struct umac_sta_data *stad,
                                                int key_id,
                                                struct mmpktview *orig_view)
{
    const size_t hdr_len = sizeof(struct dot11_hdr); /* 24 */
    const size_t ccmp_hdr_len = DOT11_CCMP_HEADER_LEN; /* 8 */
    const size_t mic_len = DOT11_CCMP_128_MIC_LEN;  /* 8 */

    /* Get the temporal key (our own MGTK) */
    const uint8_t *tk = umac_keys_get_key_data(stad, key_id);
    size_t tk_len = umac_keys_get_key_len(stad, key_id);
    if (tk == NULL || tk_len != 16)
    {
        printf("[dp_mesh] BC RMF sw_enc: no key id=%d len=%lu\n",
               key_id, (unsigned long)tk_len);
        return NULL;
    }

    /* Get current TX PN and increment */
    uint64_t pn = umac_keys_get_tx_seq_by_id(stad, key_id);
    umac_keys_increment_tx_seq(stad, key_id);

    /* Read original frame */
    const uint8_t *frame_start = (const uint8_t *)mmpkt_get_data_start(orig_view);
    size_t frame_len = mmpkt_get_data_length(orig_view);
    if (frame_len <= hdr_len)
    {
        printf("[dp_mesh] BC RMF sw_enc: frame too short %lu\n",
               (unsigned long)frame_len);
        return NULL;
    }

    struct dot11_hdr hdr_copy;
    memcpy(&hdr_copy, frame_start, sizeof(hdr_copy));
    size_t plain_len = frame_len - hdr_len;

    /* Copy plaintext body to temp buffer (original may be released) */
    uint8_t *plain_copy = (uint8_t *)malloc(plain_len);
    if (plain_copy == NULL)
    {
        printf("[dp_mesh] BC RMF sw_enc: malloc plain failed\n");
        return NULL;
    }
    memcpy(plain_copy, frame_start + hdr_len, plain_len);

    /* Build CCMP nonce (13 bytes): management bit (0x10) set per
     * IEEE 802.11-2020 sec 12.5.3.3.3 and hostap wlantest/ccmp.c */
    uint8_t nonce[13];
    nonce[0] = 0x10; /* management frame: bit 4 set, TID=0 */
    memcpy(&nonce[1], hdr_copy.addr2, 6);
    nonce[7]  = (pn >> 40) & 0xff;
    nonce[8]  = (pn >> 32) & 0xff;
    nonce[9]  = (pn >> 24) & 0xff;
    nonce[10] = (pn >> 16) & 0xff;
    nonce[11] = (pn >> 8) & 0xff;
    nonce[12] = pn & 0xff;

    /* Build AAD for management frames (22 bytes):
     * FC(2) + A1(6) + A2(6) + A3(6) + SC(2)
     * FC masked per IEEE 802.11-2020 / hostap ccmp_aad_nonce():
     *   Retry=0, PwrMgmt=0, MoreData=0, Protected=1
     *   Subtype bits are NOT masked for management frames */
    uint8_t aad[22];
    uint16_t fc = le16toh(hdr_copy.frame_control);
    fc &= ~(DOT11_MASK_FC_RETRY | DOT11_MASK_FC_MORE_DATA |
             (1u << 12) /* PwrMgmt */ | (1u << 15) /* Order/HTC */);
    fc |= DOT11_MASK_FC_PROTECTED;
    uint8_t *pos = aad;
    *pos++ = fc & 0xff; *pos++ = (fc >> 8) & 0xff;
    memcpy(pos, hdr_copy.addr1, 6); pos += 6;
    memcpy(pos, hdr_copy.addr2, 6); pos += 6;
    memcpy(pos, hdr_copy.addr3, 6); pos += 6;
    uint16_t sc = le16toh(hdr_copy.sequence_control);
    *pos++ = sc & 0x0f; *pos++ = 0;

    /* Build CCMP header (8 bytes) from PN */
    uint8_t ccmp_hdr[DOT11_CCMP_HEADER_LEN]; /* 8 */
    ccmp_hdr[0] = pn & 0xff;                    /* PN0 */
    ccmp_hdr[1] = (pn >> 8) & 0xff;             /* PN1 */
    ccmp_hdr[2] = 0;                            /* Reserved */
    ccmp_hdr[3] = ((uint8_t)key_id << 6) | 0x20; /* KeyID | ExtIV=1 */
    ccmp_hdr[4] = (pn >> 16) & 0xff;            /* PN2 */
    ccmp_hdr[5] = (pn >> 24) & 0xff;            /* PN3 */
    ccmp_hdr[6] = (pn >> 32) & 0xff;            /* PN4 */
    ccmp_hdr[7] = (pn >> 40) & 0xff;            /* PN5 */

    /* Encrypt */
    uint8_t *ciphertext = (uint8_t *)malloc(plain_len);
    uint8_t mic[8];
    if (ciphertext == NULL)
    {
        printf("[dp_mesh] BC RMF sw_enc: malloc cipher failed\n");
        free(plain_copy);
        return NULL;
    }

    int ret = aes_ccm_ae(tk, tk_len, nonce, mic_len,
                         plain_copy, plain_len,
                         aad, 22, ciphertext, mic);
    free(plain_copy);
    if (ret != 0)
    {
        printf("[dp_mesh] BC RMF sw_enc: encrypt FAILED ret=%d\n", ret);
        free(ciphertext);
        return NULL;
    }

    /* Allocate new TX mmpkt with enough room for the encrypted frame.
     * Uses mmdrv_alloc_mmpkt_for_tx to get proper headroom for SPI framing.
     * Total: hdr(24) + ccmp_hdr(8) + ciphertext(plain_len) + mic(8)
     * space_at_start = hdr_len so prepend can place header.
     * space_at_end = ccmp_hdr + ciphertext + mic. */
    size_t enc_body = ccmp_hdr_len + plain_len + mic_len;
    struct mmpkt *enc_pkt = mmdrv_alloc_mmpkt_for_tx(MMDRV_PKT_CLASS_MGMT,
                                                      hdr_len, enc_body);
    if (enc_pkt == NULL)
    {
        dp_mesh_dbg("[dp_mesh] BC RMF sw_enc: mmpkt alloc failed\n");
        free(ciphertext);
        return NULL;
    }

    struct mmpktview *enc_view = mmpkt_open(enc_pkt);
    /* Prepend header (moves start_offset back by hdr_len) */
    uint8_t *hdr_dest = mmpkt_prepend(enc_view, hdr_len);
    memcpy(hdr_dest, &hdr_copy, hdr_len);
    /* Append CCMP header + ciphertext + MIC */
    mmpkt_append_data(enc_view, ccmp_hdr, sizeof(ccmp_hdr));
    mmpkt_append_data(enc_view, ciphertext, plain_len);
    mmpkt_append_data(enc_view, mic, sizeof(mic));
    mmpkt_close(&enc_view);

    dp_mesh_dbg("[dp_mesh] BC RMF sw_enc OK pn=%llu plain_len=%lu\n",
           (unsigned long long)pn, (unsigned long)plain_len);

    free(ciphertext);
    return enc_pkt;
}


static void umac_datapath_process_rx_data_frame_after_reorder(
    struct umac_sta_data *stad,
    struct umac_datapath_sta_data *sta_data,
    struct mmpkt *rxbuf,
    struct mmpktview *rxbufview)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);


    const struct dot11_data_hdr *data_hdr =
        (const struct dot11_data_hdr *)mmpkt_get_data_start(rxbufview);
    const size_t data_hdr_len = dot11_data_hdr_get_len(data_hdr);

    /* Mesh RX diagnostic: hex dump first 80 bytes of received frame */
    if (data->mesh_mode)
    {
        const uint8_t *raw = (const uint8_t *)mmpkt_get_data_start(rxbufview);
        size_t raw_len = mmpkt_get_data_length(rxbufview);
        size_t dump_len = raw_len < 80 ? raw_len : 80;
        dp_mesh_dbg("[dp_mesh_rx] frame len=%zu hdr_len=%zu FC=0x%04x\n",
               raw_len, data_hdr_len, le16toh(data_hdr->base.frame_control));
        dp_mesh_dbg("[dp_mesh_rx] ");
        for (size_t i = 0; i < dump_len; i++)
            dp_mesh_dbg("%02x ", raw[i]);
        dp_mesh_dbg("\n");
    }

    data_hdr = (const struct dot11_data_hdr *)mmpkt_remove_from_start(rxbufview, data_hdr_len);

    MMOSAL_ASSERT(data_hdr);

    const struct dot11_hdr *header = &data_hdr->base;

    uint16_t llc_ethertype;
    uint8_t tid_index = MMDRV_SEQ_NUM_BASELINE;
    const struct mmdrv_rx_metadata *rx_metadata = mmdrv_get_rx_metadata(rxbuf);
    struct umac_8023_hdr header_8023 = { 0 };

    /* Mesh AE=2: save proxied DA/SA from mesh header address extensions.
     * When AE>0, the real ethernet addresses are in the mesh header, not A3/A4. */
    uint8_t mesh_rx_ae = 0;
    uint8_t mesh_rx_proxied_da[DOT11_MAC_ADDR_LEN];
    uint8_t mesh_rx_proxied_sa[DOT11_MAC_ADDR_LEN];

    bool rx_mesh_ctrl_present = false;
    uint8_t rx_qos_tid = 0; /* actual QoS TID for CCMP nonce (not seq_num space index) */
    if (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_DATA)
    {
        const struct dot11_qos_ctrl *qos_control =
            (struct dot11_qos_ctrl *)mmpkt_remove_from_start(rxbufview, sizeof(*qos_control));

        MMOSAL_ASSERT(qos_control);

        rx_qos_tid = dot11_qos_control_get_tid(qos_control->field);
        if (!mm_mac_addr_is_multicast(dot11_get_ra(header)))
        {
            tid_index = rx_qos_tid;
        }
        /* Check mesh control present bit (bit 8 of QoS field) */
        rx_mesh_ctrl_present = (le16toh(qos_control->field) >> 8) & 1;
        if (data->mesh_mode)
        {
            dp_mesh_dbg("[dp_mesh_rx] qos=0x%04x tid=%u mesh_ctrl_present=%d\n",
                   le16toh(qos_control->field), tid_index, rx_mesh_ctrl_present);
        }
    }


    if ((umac_sta_data_get_security_type(stad) != MMWLAN_OPEN) &&
        !dot11_frame_control_get_protected(header->frame_control) &&
        !umac_datapath_is_eapol_frame(rxbufview))
    {
        MMLOG_INF("Received NON EAPOL frame in plain text.\n");
        goto drop;
    }

    if (dot11_frame_control_get_protected(header->frame_control))
    {
        if (!(rx_metadata->flags & MMDRV_RX_FLAG_DECRYPTED))
        {
            /* Mesh mode: chip can't HW-decrypt because peer BSSID differs
             * from our VIF's BSSID. Use software CCMP decrypt for both
             * broadcast/multicast AND unicast mesh frames. Broadcast uses
             * group key (MGTK, key_id>=1), unicast uses pairwise key
             * (PTK, key_id=0). */
            if (data->mesh_mode)
            {
                /* Mesh: do NOT run stad-based ccmp_is_valid() replay check.
                 *
                 * The stad keeps a single PN counter per key_id space
                 * (UMAC_KEY_RX_COUNTER_SPACE_DEFAULT), but every mesh peer
                 * encrypts under its own PTK with its own independent PN
                 * sequence (key_id=0 unicast) — these cannot be linearised
                 * into one counter. Worst case: a peer reboot resets its
                 * TX PN to 1 while our cached "last seen" PN is still high,
                 * causing every subsequent frame from that peer to be
                 * rejected as a replay (TCP/OTA stalls forever).
                 *
                 * AES-CCM MIC still guarantees per-frame integrity, and
                 * mesh_sw_ccmp_decrypt() picks the correct per-peer key
                 * from s_mesh_peer_group_key_cache, so frames forged or
                 * replayed under another peer's key fail MIC.
                 *
                 * See /memories/repo/mesh-rx-replay-check-disabled.md.
                 */
                if (!mesh_sw_ccmp_decrypt(umacd, stad, data, header, rxbufview, rx_qos_tid))
                {
                    MESH_DBG_PRINTF("[dp_mesh_rx] DROP: sw ccmp decrypt failed\n");
                    umac_stats_increment_datapath_rx_ccmp_failures(umacd);
                    goto drop;
                }
                /* SW decrypt succeeded — skip the normal HW decrypt path */
                goto ccmp_done;
            }
            MMLOG_WRN("Received frame without HW Decryption (FC: 0x%04x, SEQ: 0x%04x).\n",
                      le16toh(header->frame_control),
                      le16toh(header->sequence_control));
            goto drop;
        }

        uint8_t *ccmp_header = mmpkt_remove_from_start(rxbufview, DOT11_CCMP_HEADER_LEN);
        if (ccmp_header == NULL ||
            !ccmp_is_valid(stad, ccmp_header, UMAC_KEY_RX_COUNTER_SPACE_DEFAULT))
        {
            if (data->mesh_mode)
            {
                MESH_DBG_PRINTF("[dp_mesh_rx] DROP: ccmp invalid/missing\n");
            }
            umac_stats_increment_datapath_rx_ccmp_failures(umacd);
            goto drop;
        }
        if (data->mesh_mode)
        {
            dp_mesh_dbg("[dp_mesh_rx] ccmp ok, remaining=%lu\n",
                   (unsigned long)mmpkt_get_data_length(rxbufview));
        }


        if (mmpkt_remove_from_end(rxbufview, DOT11_CCMP_128_MIC_LEN) == NULL)
        {
            MMLOG_WRN("Drop frame as rxbuf was shorter than expected");
            goto drop;
        }
    }
ccmp_done:

    /* Mesh mode: strip mesh control field (6 bytes) + Address Extension before LLC/SNAP.
     * Use QoS mesh_ctrl_present bit — broadcast uses 3-addr, unicast uses 4-addr,
     * but both have mesh control when this bit is set.
     * Address Extension (AE) in flags[1:0]: 0=none, 1=+6B proxy, 2=+12B proxy */
    if (data->mesh_mode && rx_mesh_ctrl_present)
    {
        uint8_t *mesh_ctrl = mmpkt_remove_from_start(rxbufview, MESH_CTRL_BASE_LEN);
        if (mesh_ctrl == NULL)
        {
            MMLOG_WRN("Drop mesh frame: mesh control field missing\n");
            goto drop;
        }
        uint8_t mesh_ae = mesh_ctrl[0] & 0x03;
        dp_mesh_dbg("[dp_mesh_rx] mesh_ctrl: flags=0x%02x ae=%u ttl=%u seq=%lu remaining=%lu\n",
               mesh_ctrl[0], mesh_ae, mesh_ctrl[1],
               (unsigned long)((uint32_t)mesh_ctrl[2] | ((uint32_t)mesh_ctrl[3] << 8) |
                         ((uint32_t)mesh_ctrl[4] << 16) |
                         ((uint32_t)mesh_ctrl[5] << 24)),
               (unsigned long)mmpkt_get_data_length(rxbufview));
        /* Strip Address Extension proxy addresses (6 bytes each) */
        if (mesh_ae > 0)
        {
            size_t ae_len = (size_t)mesh_ae * 6;
            uint8_t *ae_addrs = mmpkt_remove_from_start(rxbufview, ae_len);
            if (ae_addrs == NULL)
            {
                MMLOG_WRN("Drop mesh frame: AE addresses missing (ae=%u)\n", mesh_ae);
                goto drop;
            }
            /* Save proxied addresses for 802.3 header reconstruction.
             * AE=1: Addr5 = proxied SA (mesh SA is in A4)
             * AE=2: Addr5 = proxied DA, Addr6 = proxied SA */
            mesh_rx_ae = mesh_ae;
            if (mesh_ae == 2)
            {
                memcpy(mesh_rx_proxied_da, ae_addrs, DOT11_MAC_ADDR_LEN);
                memcpy(mesh_rx_proxied_sa, ae_addrs + DOT11_MAC_ADDR_LEN, DOT11_MAC_ADDR_LEN);
                /* Learn reverse proxy mapping: to reach this source host,
                 * send via the mesh STA in A4 (the originating mesh node). */
                mesh_proxy_table_update(mesh_rx_proxied_sa, data_hdr->addr4);
            }
            else if (mesh_ae == 1)
            {
                memcpy(mesh_rx_proxied_sa, ae_addrs, DOT11_MAC_ADDR_LEN);
                /* Learn reverse proxy mapping: to reach this proxied source
                 * host, send via the mesh STA in addr3.  For broadcast 3-addr
                 * mesh frames addr3 = SA = the originating mesh gate. */
                mesh_proxy_table_update(mesh_rx_proxied_sa, data_hdr->base.addr3);
            }
            dp_mesh_dbg("[dp_mesh_rx] mesh_ae: stripped %lu bytes\n", (unsigned long)ae_len);
        }
        /* Dump first 16 bytes after mesh_ctrl+AE strip (should be LLC/SNAP) */
        {
            const uint8_t *p = (const uint8_t *)mmpkt_get_data_start(rxbufview);
            size_t plen = mmpkt_get_data_length(rxbufview);
            size_t dlen = plen < 16 ? plen : 16;
            dp_mesh_dbg("[dp_mesh_rx] post_mesh_ctrl: ");
            for (size_t i = 0; i < dlen; i++)
                dp_mesh_dbg("%02x ", p[i]);
            dp_mesh_dbg("\n");
        }
    }

    if (tid_index <= MMWLAN_MAX_QOS_TID &&
        (dot11_frame_control_get_protected(header->frame_control) ||
         umac_sta_data_get_security_type(stad) == MMWLAN_OPEN))
    {
        umac_ba_set_expected_rx_seq_num(stad, tid_index, dot11_get_next_sequence_control(header));
    }




    if (mm_mac_addr_is_broadcast(dot11_get_da(header)) ||
        mm_mac_addr_is_multicast(dot11_get_da(header)))
    {
        if (dot11_frame_control_get_more_fragments(header->frame_control))
        {
            MMLOG_INF("Drop Mcast/Bcast frame with fragment bit on\n");
            goto drop;
        }


        if (!data->mesh_mode &&
            dot11_frame_control_get_from_ds(header->frame_control) &&
            umac_interface_addr_matches_mac_addr(stad, dot11_get_sa_data(data_hdr)))
        {
            MESH_DBG_PRINTF("[dp_mesh_rx] DROP: filter out bcast relayed for us\n");
            MMLOG_DBG("Filter out Bcast frame which AP relayed for us\n");
            goto drop;
        }
        if (data->mesh_mode)
            dp_mesh_dbg("[dp_mesh_rx] bcast filter passed\n");
    }
    else
    {

        MMOSAL_DEV_ASSERT(mmpkt_contains_ptr(rxbufview, (const void *)data_hdr));
        rx_metadata = NULL;
        rxbuf =
            datapath_defrag(umacd, &sta_data->defrag_data, &data_hdr, &rxbufview, rxbuf, tid_index);
        if (rxbuf == NULL)
        {

            MMOSAL_DEV_ASSERT(rxbufview == NULL);
            return;
        }
        else
        {
            header = &data_hdr->base;
            MMOSAL_DEV_ASSERT(mmpkt_from_view(rxbufview) == rxbuf);
            MMOSAL_DEV_ASSERT(mmpkt_contains_ptr(rxbufview, (const void *)data_hdr));
        }
    }

    if (umac_datapath_is_eapol_frame(rxbufview))
    {
        if (dot11_is_4addr_hdr(header->frame_control))
        {
            MMLOG_INF("Received 4-address EAPOL frame. Not supported\n");
            goto drop;
        }
        umac_datapath_process_rx_eapol_frame(umacd, data, rxbufview, header);
        goto drop;
    }

    MMOSAL_DEV_ASSERT(data->ops != NULL);
    if (data->ops->get_sta_state(stad) != MMWLAN_STA_CONNECTED)
    {
        if (data->mesh_mode)
                 MESH_DBG_PRINTF("[dp_mesh_rx] DROP: controlled port closed, sta_state=%d\n",
                        data->ops->get_sta_state(stad));
        MMLOG_DBG("Controlled Port is currently closed.\n");
        goto drop;
    }
    if (data->mesh_mode)
        dp_mesh_dbg("[dp_mesh_rx] controlled port open\n");


    llc_ethertype = umac_datapath_get_llc_ethertype(rxbufview);
    if (!llc_ethertype)
    {
        if (data->mesh_mode)
        {
            const uint8_t *p = (const uint8_t *)mmpkt_get_data_start(rxbufview);
            size_t plen = mmpkt_get_data_length(rxbufview);
            size_t dlen = plen < 16 ? plen : 16;
            MESH_DBG_PRINTF("[dp_mesh_rx] DROP: llc_ethertype=0 len=%lu data: ", (unsigned long)plen);
            for (size_t i = 0; i < dlen; i++)
                MESH_DBG_PRINTF("%02x ", p[i]);
            MESH_DBG_PRINTF("\n");
        }
        goto drop;
    }
    if (data->mesh_mode)
    {
        dp_mesh_dbg("[dp_mesh_rx] llc ok ethertype=0x%04x\n", llc_ethertype);
    }

    /* For mesh AE=2 frames, use proxied DA/SA from mesh header extensions.
     * For AE=1, use proxied SA from Addr5, DA from A3.
     * For AE=0 or non-mesh, use A3/A4 as DA/SA (standard behavior). */
    if (data->mesh_mode && mesh_rx_ae == 2)
    {
        umac_datapath_generate_8023_header(mesh_rx_proxied_da,
                                           mesh_rx_proxied_sa,
                                           llc_ethertype,
                                           &header_8023);
    }
    else if (data->mesh_mode && mesh_rx_ae == 1)
    {
        umac_datapath_generate_8023_header(dot11_get_da(header),
                                           mesh_rx_proxied_sa,
                                           llc_ethertype,
                                           &header_8023);
    }
    else
    {
        umac_datapath_generate_8023_header(dot11_get_da(header),
                                           dot11_get_sa_data(data_hdr),
                                           llc_ethertype,
                                           &header_8023);
    }


    mmpkt_remove_from_start(rxbufview, UMAC_802_1_HEADER_LEN);

    if (data->mesh_mode && llc_ethertype == 0x0800)
    {
        mesh_log_dhcp_ipv4_payload(rxbufview);
    }


    enum mmwlan_vif vif = MMWLAN_VIF_UNSPECIFIED;
    if (umac_interface_get_vif_id(umacd, UMAC_INTERFACE_STA) != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        vif = MMWLAN_VIF_STA;
    }
    else if (umac_interface_get_vif_id(umacd, UMAC_INTERFACE_AP) != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        vif = MMWLAN_VIF_AP;
    }
    else if (umac_interface_get_vif_id(umacd, UMAC_INTERFACE_MESH) != UMAC_INTERFACE_VIF_ID_INVALID)
    {
        /* Mesh uses the STA VIF slot for RX callbacks */
        vif = MMWLAN_VIF_STA;
    }
    else
    {
        MMLOG_WRN("Invalid RX VIF\n");
        goto drop;
    }

    mmwlan_rx_pkt_ext_cb_t rx_pkt_cb;
    void *arg = NULL;

    rx_pkt_cb = umac_interface_get_rx_pkt_ext_cb(umacd, vif, &arg);
    if (rx_pkt_cb != NULL)
    {
        if (data->mesh_mode)
        {
                 dp_mesh_dbg("[dp_mesh_rx] delivering to upper layer: ethertype=0x%04x vif=%d len=%lu\n",
                     llc_ethertype, vif, (unsigned long)mmpkt_get_data_length(rxbufview));
        }
        struct mmwlan_rx_metadata metadata = {
            .vif = vif,
            .tid = tid_index,
            .ta = dot11_get_ta(&data_hdr->base),
        };

        mmpkt_prepend_data(rxbufview, (const uint8_t *)&header_8023, sizeof(header_8023));
        mmpkt_close(&rxbufview);
        rx_pkt_cb(rxbuf, &metadata, arg);

        return;
    }
    if (data->rx_pkt_callback != NULL)
    {
        if (data->mesh_mode)
        {
            dp_mesh_dbg("[dp_mesh_rx] rx_pkt_callback: ethertype=0x%04x len=%lu\n",
                   llc_ethertype, (unsigned long)mmpkt_get_data_length(rxbufview));
        }
        mmpkt_prepend_data(rxbufview, (const uint8_t *)&header_8023, sizeof(header_8023));
        mmpkt_close(&rxbufview);
        data->rx_pkt_callback(rxbuf, data->rx_arg);

        return;
    }
    if (data->rx_callback != NULL)
    {
        data->rx_callback((uint8_t *)&header_8023,
                          sizeof(header_8023),
                          mmpkt_get_data_start(rxbufview),
                          mmpkt_get_data_length(rxbufview),
                          data->rx_arg);
        goto drop;
    }
    MMLOG_WRN("No RX callback registered by the network stack.\n");
    goto drop;

drop:
    mmpkt_close(&rxbufview);
    mmpkt_release(rxbuf);
}


static void umac_datapath_flush_rx_reorder_list(struct umac_sta_data *stad,
                                                struct umac_datapath_sta_data *sta_data)
{
    struct mmpkt *pkt;
    while ((pkt = mmpkt_list_dequeue(&sta_data->rx_reorder_list)) != NULL)
    {
        struct mmpktview *view = mmpkt_open(pkt);
        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, pkt, view);
    }
}

void umac_datapath_flush_rx_reorder_list_for_tid(struct umac_sta_data *stad, uint16_t tid)
{
    struct mmpkt *pkt;
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);

    if (sta_data->rx_reorder_tid != tid)
    {
        return;
    }

    umac_datapath_flush_rx_reorder_list(stad, sta_data);

    while ((pkt = mmpkt_list_dequeue(&sta_data->rx_reorder_list)) != NULL)
    {
        struct mmpktview *view = mmpkt_open(pkt);
        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, pkt, view);
    }
}


static void umac_datapath_evaluate_rx_reorder_list(struct umac_data *umacd,
                                                   struct umac_sta_data *stad,
                                                   struct umac_datapath_sta_data *sta_data)
{
    while (!mmpkt_list_is_empty(&sta_data->rx_reorder_list))
    {
        bool dequeue = false;
        struct mmpkt *pkt = mmpkt_list_peek(&sta_data->rx_reorder_list);
        struct mmpktview *view = mmpkt_open(pkt);
        const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(view);
        uint16_t seq_ctrl = le16toh(header->sequence_control);
        int32_t ret;

        ret = umac_ba_get_expected_rx_seq_num(stad, sta_data->rx_reorder_tid);
        if (ret < 0 || seq_ctrl == (uint16_t)ret)
        {
            dequeue = true;
        }
        else if (mmosal_time_has_passed(
                     mmpkt_get_metadata(pkt).rx->read_timestamp_ms + RX_REORDER_TIMEOUT_MS))
        {
            umac_stats_increment_datapath_rx_reorder_timedout(umacd);
            dequeue = true;
        }

        if (dequeue)
        {
            mmpkt_list_remove(&sta_data->rx_reorder_list, pkt);
            umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, pkt, view);
        }
        else
        {
            mmpkt_close(&view);
            return;
        }
    }
}

static void umac_datapath_rx_reorder_timeout_handler(void *arg1, void *arg2)
{
    struct umac_data *umacd = (struct umac_data *)arg1;
    struct umac_sta_data *stad = (struct umac_sta_data *)arg2;
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);

    umac_datapath_evaluate_rx_reorder_list(umacd, stad, sta_data);
    if (!mmpkt_list_is_empty(&sta_data->rx_reorder_list))
    {
        bool ok = umac_core_register_timeout(umacd,
                                             RX_REORDER_TIMER_PERIOD_MS,
                                             umac_datapath_rx_reorder_timeout_handler,
                                             umacd,
                                             stad);
        if (!ok)
        {
            MMLOG_WRN("Failed to schedule RX reorder timeout\n");
        }
    }
}


static void umac_datapath_add_rx_mpdu_to_reorder_list(struct umac_data *umacd,
                                                      struct umac_sta_data *stad,
                                                      struct umac_datapath_sta_data *sta_data,
                                                      struct mmpkt *rxbuf,
                                                      uint16_t seq_ctrl,
                                                      uint8_t reorder_list_maxlen)
{
    struct mmpkt *walk = NULL;
    struct mmpkt *next;
    struct mmpkt *head;
    struct mmpktview *headview;
    const struct dot11_hdr *head_header;
    uint16_t head_seq_ctrl;
    bool reorder_list_full;

    if (mmpkt_list_is_empty(&sta_data->rx_reorder_list))
    {
        bool ok = umac_core_register_timeout(umacd,
                                             RX_REORDER_TIMER_PERIOD_MS,
                                             umac_datapath_rx_reorder_timeout_handler,
                                             umacd,
                                             stad);
        if (!ok)
        {
            MMLOG_WRN("Failed to schedule RX reorder timeout\n");
        }

        mmpkt_list_append(&sta_data->rx_reorder_list, rxbuf);
        umac_stats_increment_datapath_rx_reorder_total(umacd);
        umac_stats_update_datapath_rx_reorder_list_high_water_mark(
            umacd,
            mmpkt_list_length(&sta_data->rx_reorder_list));
        return;
    }

    head = mmpkt_list_peek(&sta_data->rx_reorder_list);
    headview = mmpkt_open(head);
    head_header = (struct dot11_hdr *)mmpkt_get_data_start(headview);
    head_seq_ctrl = le16toh(head_header->sequence_control);
    head_header = NULL;
    mmpkt_close(&headview);
    head = NULL;

    if (head_seq_ctrl == seq_ctrl)
    {
        mmpkt_release(rxbuf);
        umac_stats_increment_datapath_rx_reorder_retransmit_drops(umacd);
        return;
    }

    reorder_list_full = mmpkt_list_length(&sta_data->rx_reorder_list) >= reorder_list_maxlen;


    if (dot11_sequence_control_lt(seq_ctrl, head_seq_ctrl))
    {
        if (reorder_list_full)
        {

            mmpkt_release(rxbuf);
            umac_stats_increment_datapath_rx_reorder_overflow(umacd);
        }
        else
        {
            mmpkt_list_prepend(&sta_data->rx_reorder_list, rxbuf);
            umac_stats_increment_datapath_rx_reorder_total(umacd);
            umac_stats_update_datapath_rx_reorder_list_high_water_mark(
                umacd,
                mmpkt_list_length(&sta_data->rx_reorder_list));
        }
        return;
    }

    if (reorder_list_full)
    {
        struct mmpkt *deq;
        struct mmpktview *deqview;


        deq = mmpkt_list_dequeue(&sta_data->rx_reorder_list);
        deqview = mmpkt_open(deq);
        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, deq, deqview);
        umac_stats_increment_datapath_rx_reorder_overflow(umacd);
    }



    MMPKT_LIST_WALK(&sta_data->rx_reorder_list, walk, next)
    {
        struct mmpktview *nextview;
        const struct dot11_hdr *next_header;
        uint16_t next_seq_ctrl;

        if (next == NULL)
        {

            break;
        }

        nextview = mmpkt_open(next);
        next_header = (struct dot11_hdr *)mmpkt_get_data_start(nextview);
        next_seq_ctrl = le16toh(next_header->sequence_control);
        mmpkt_close(&nextview);

        if (next_seq_ctrl == seq_ctrl)
        {
            mmpkt_release(rxbuf);
            umac_stats_increment_datapath_rx_reorder_retransmit_drops(umacd);
            return;
        }

        if (dot11_sequence_control_lt(seq_ctrl, next_seq_ctrl))
        {

            break;
        }
    }

    MMOSAL_ASSERT(walk != NULL);
    mmpkt_list_insert_after(&sta_data->rx_reorder_list, walk, rxbuf);
    umac_stats_increment_datapath_rx_reorder_total(umacd);
    umac_stats_update_datapath_rx_reorder_list_high_water_mark(
        umacd,
        mmpkt_list_length(&sta_data->rx_reorder_list));


    umac_datapath_evaluate_rx_reorder_list(umacd, stad, sta_data);
}


static void umac_datapath_process_rx_data_frame(struct umac_data *umacd,
                                                struct umac_sta_data *stad,
                                                struct mmpkt *rxbuf,
                                                struct mmpktview *rxbufview)
{
    int32_t ret;
    uint16_t seq_ctrl;
    uint16_t expected_seq_ctrl;
    uint8_t tid_index = MMDRV_SEQ_NUM_BASELINE;
    const struct dot11_data_hdr *data_hdr =
        (const struct dot11_data_hdr *)mmpkt_get_data_start(rxbufview);
    const struct dot11_hdr *const header = &data_hdr->base;
    const size_t data_hdr_len = dot11_data_hdr_get_len(data_hdr);
    uint8_t reorder_buf_size;

    if (stad == NULL)
    {
        MMLOG_DBG("Dropping frame, not transmitted from our AP.\n");
        goto drop;
    }

    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);

    if ((dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_NULL_DATA) ||
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_NULL))
    {
        MMLOG_DBG("Dropping NULL data frame.\n");
        goto drop;
    }

    if (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_DATA)
    {
        MMLOG_VRB("Remove extra QOS CNTL bytes (%p)\n", rxbuf);

        const struct dot11_qos_ctrl *qos_control =
            (const struct dot11_qos_ctrl *)((const uint8_t *)data_hdr + data_hdr_len);

        if (!mm_mac_addr_is_multicast(dot11_get_ra(header)))
        {
            tid_index = dot11_qos_control_get_tid(qos_control->field);
        }
    }

    reorder_buf_size = umac_ba_get_reorder_buffer_size(stad, tid_index);

    if (tid_index > MMWLAN_MAX_QOS_TID || reorder_buf_size == 0)
    {
        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, rxbuf, rxbufview);
        return;
    }


    if (sta_data->rx_reorder_tid != tid_index)
    {
        umac_datapath_flush_rx_reorder_list(stad, sta_data);
        sta_data->rx_reorder_tid = tid_index;
    }

    ret = umac_ba_get_expected_rx_seq_num(stad, tid_index);
    if (ret < 0)
    {

        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, rxbuf, rxbufview);
        return;
    }


    expected_seq_ctrl = (uint16_t)ret;

    seq_ctrl = le16toh(header->sequence_control);
    if (seq_ctrl == expected_seq_ctrl)
    {

        umac_datapath_process_rx_data_frame_after_reorder(stad, sta_data, rxbuf, rxbufview);
        rxbuf = NULL;
        rxbufview = NULL;
        umac_datapath_evaluate_rx_reorder_list(umacd, stad, sta_data);
        return;
    }
    else
    {
        if (dot11_sequence_control_lt(seq_ctrl, expected_seq_ctrl))
        {

            umac_stats_increment_datapath_rx_reorder_outdated_drops(umacd);
            MMLOG_DBG("Dropping outdated frame (SEQ: 0x%x, EXP: 0x%x)\n",
                      seq_ctrl,
                      expected_seq_ctrl);
            goto drop;
        }
        else
        {

            mmpkt_close(&rxbufview);
            umac_datapath_add_rx_mpdu_to_reorder_list(umacd,
                                                      stad,
                                                      sta_data,
                                                      rxbuf,
                                                      seq_ctrl,
                                                      reorder_buf_size);
            rxbuf = NULL;
            return;
        }
    }

drop:
    mmpkt_close(&rxbufview);
    mmpkt_release(rxbuf);
}


static bool umac_datapath_process_mgmt_frame_ccmp_header(struct umac_data *umacd,
                                                         struct umac_sta_data *stad,
                                                         struct mmpktview *rxbufview)
{
    const struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t frame_control_le = header->frame_control;

    if (!dot11_frame_control_get_protected(frame_control_le))
    {
        return true;
    }

    struct mmpkt *rxbuf = mmpkt_from_view(rxbufview);
    const struct mmdrv_rx_metadata *rx_metadata = mmdrv_get_rx_metadata(rxbuf);
    if (!(rx_metadata->flags & MMDRV_RX_FLAG_DECRYPTED))
    {
        /* Mesh broadcast: HW can't decrypt multicast mgmt frames (e.g. HWMP).
         * Fall back to SW CCMP decrypt using the cached MGTK. */
        struct umac_datapath_data *dpdata = umac_data_get_datapath(umacd);
        if (dpdata->mesh_mode && mm_mac_addr_is_multicast(dot11_get_ra(header)))
        {
            /*
             * A protected mesh action frame cannot be authenticated or
             * decrypted until its transmitter has a station/key context.
             * In particular, periodic protected HWMP broadcasts can arrive
             * while SAE is still creating the peer.  Do not pass a NULL stad
             * into the CCMP/key path.
             */
            if (stad == NULL)
            {
                printk("[MAC_MGMT] protected multicast pre-peer drop subtype=0x%x ta="
                       MM_MAC_ADDR_FMT "\n",
                       (unsigned)dot11_frame_control_get_subtype(frame_control_le),
                       MM_MAC_ADDR_VAL(dot11_get_ta(header)));
                return false;
            }
            return mesh_sw_ccmp_decrypt_mgmt(umacd, stad, dpdata, rxbufview);
        }

        MMLOG_WRN("Received frame without HW Decryption (FC: 0x%04x).\n",
                  le16toh(frame_control_le));
        return false;
    }


    mmpkt_remove_from_start(rxbufview, sizeof(*header));


    uint8_t *ccmp_header = mmpkt_remove_from_start(rxbufview, DOT11_CCMP_HEADER_LEN);
    if (!ccmp_is_valid(stad, ccmp_header, UMAC_KEY_RX_COUNTER_SPACE_IND_ROBUST_MGMT))
    {
        MMLOG_WRN("Unable to validate frame security, dropping.\n");
        umac_stats_increment_datapath_rx_ccmp_failures(umacd);
        return false;
    }


    uint8_t *hdr_dest = mmpkt_prepend(rxbufview, sizeof(*header));
    memmove(hdr_dest, header, sizeof(*header));

    return true;
}


static enum mmwlan_frame_filter_flag umac_datapath_rx_frame_filter_matches(struct umac_data *umacd,
                                                                           enum dot11_fc_type type,
                                                                           uint16_t subtype)
{
    const struct umac_datapath_data *datapath = umac_data_get_datapath(umacd);

    if (type == DOT11_FC_TYPE_MGMT)
    {
        return (enum mmwlan_frame_filter_flag)(datapath->rx_frame_filter & (1u << subtype));
    }
    return MMWLAN_FRAME_NO_MATCH;
}


static void umac_datapath_process_rx_other_frame(struct umac_data *umacd,
                                                 struct umac_sta_data *stad,
                                                 struct umac_datapath_data *data,
                                                 struct mmpkt *rxbuf,
                                                 struct mmpktview *rxbufview)
{
    struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);

    MMOSAL_ASSERT(!dot11_is_4addr_hdr(header->frame_control));

    const enum dot11_fc_type frame_type =
        (enum dot11_fc_type)dot11_frame_control_get_type(header->frame_control);
    const uint16_t frame_subtype = dot11_frame_control_get_subtype(header->frame_control);
    const enum mmwlan_frame_filter_flag frame_filter_flag =
        umac_datapath_rx_frame_filter_matches(umacd, frame_type, frame_subtype);

    if (frame_type == DOT11_FC_TYPE_MGMT)
    {
        const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
        if (sta_args != NULL && sta_args->mesh_mode)
        {
            mesh_dbg_rx_mgmt_gate_seen++;
            if ((mesh_dbg_rx_mgmt_gate_seen % 16U) == 1U)
            {
                MESH_DBG_PRINTF("[mesh_trace] MESH_RX_MGMT_GATE: count=%lu subtype=0x%x stad=%u ta=" MM_MAC_ADDR_FMT " ra=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                       (unsigned long)mesh_dbg_rx_mgmt_gate_seen,
                       frame_subtype,
                       stad ? 1U : 0U,
                       MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                       MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                       MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)));
            }
        }
    }

    if (frame_type == DOT11_FC_TYPE_MGMT &&
        !umac_datapath_process_mgmt_frame_ccmp_header(umacd, stad, rxbufview))
    {
        MMLOG_WRN("Dropping management frame due to CCMP header (aid=%u)\n",
                  stad ? umac_sta_data_get_aid(stad) : -1);
        goto drop;
    }

    if (frame_filter_flag != MMWLAN_FRAME_NO_MATCH && data->rx_frame_cb != NULL)
    {
        struct mmdrv_rx_metadata *rx_metadata = mmdrv_get_rx_metadata(rxbuf);
        struct mmwlan_rx_frame_info frame_info = {
            .frame_filter_flag = frame_filter_flag,
            .buf = mmpkt_get_data_start(rxbufview),
            .buf_len = mmpkt_get_data_length(rxbufview),
            .freq_100khz = rx_metadata->freq_100khz,
            .rssi_dbm = rx_metadata->rssi,
            .bw_mhz = rx_metadata->bw_mhz,
        };
        data->rx_frame_cb(&frame_info, data->rx_frame_cb_arg);
    }

    switch (frame_type)
    {
        case DOT11_FC_TYPE_MGMT:
            umac_datapath_process_rx_mgmt_frame(umacd, stad, data, rxbufview);
            break;

        case DOT11_FC_TYPE_EXT:
            umac_datapath_process_rx_extension_frame(umacd, data, rxbufview, header->frame_control);
            break;

        case DOT11_FC_TYPE_CTRL:
            MMLOG_INF("Control frame ignored.\n");
            break;

        case DOT11_FC_TYPE_DATA:

            MMOSAL_ASSERT(false);
            break;

        default:
            MMLOG_ERR("Unexpected frame type received.\n");
            break;
    }

drop:
    mmpkt_close(&rxbufview);
    mmpkt_release(rxbuf);
}


static bool umac_datapath_is_rx_frame_duplicate(struct umac_datapath_sta_data *sta_data,
                                                struct mmpktview *rxbufview,
                                                bool mesh_mode)
{
    uint8_t tid_index;
    struct dot11_data_hdr *data_hdr = (struct dot11_data_hdr *)mmpkt_get_data_start(rxbufview);
    struct dot11_hdr *header = &data_hdr->base;
    const uint32_t data_hdr_len = dot11_data_hdr_get_len(data_hdr);
    uint16_t last_seq_ctrl;


    if (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_EXT)
    {
        return false;
    }


    MMOSAL_ASSERT(umac_datapath_validate_buf_len(rxbufview, data_hdr_len));


    if (mm_mac_addr_is_broadcast(dot11_get_da(header)) ||
        mm_mac_addr_is_multicast(dot11_get_da(header)))
    {
        return false;
    }


    if (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_CTRL)
    {
        return false;
    }


    if ((dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_DATA) &&
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_NULL))
    {
        return false;
    }

    if ((dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_DATA) &&
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_DATA))
    {
        const struct dot11_qos_ctrl *qos_control =
            (struct dot11_qos_ctrl *)(mmpkt_get_data_start(rxbufview) + data_hdr_len);
        if (!umac_datapath_validate_buf_len(rxbufview, data_hdr_len + sizeof(*qos_control)))
        {

            return true;
        }
        tid_index = dot11_qos_control_get_tid(qos_control->field);
    }
    else
    {
        tid_index = MMDRV_SEQ_NUM_BASELINE;
    }

    if (tid_index >= MMDRV_SEQ_NUM_SPACES)
    {
        MMLOG_WRN("Received out of range TID: %d.\n", tid_index);

        return true;
    }

    last_seq_ctrl = sta_data->rx_seq_num_spaces[tid_index];

    if (dot11_frame_control_get_retry(header->frame_control) &&
        last_seq_ctrl == header->sequence_control)
    {
        if (mesh_mode &&
            dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_DATA &&
            dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_QOS_DATA &&
            dot11_frame_control_get_protected(header->frame_control))
        {
            printf("[rx_dup] BYPASS mesh_qos_duplicate tid=%u seq_ctrl=0x%04x ta=" MM_MAC_ADDR_FMT
                   " ra=" MM_MAC_ADDR_FMT "\n",
                   (unsigned)tid_index,
                   (unsigned)header->sequence_control,
                   MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                   MM_MAC_ADDR_VAL(dot11_get_ra(header)));
            return false;
        }

        printf("[rx_dup] DROP tid=%u retry=%u seq_ctrl=0x%04x last_seq_ctrl=0x%04x ta=" MM_MAC_ADDR_FMT
               " ra=" MM_MAC_ADDR_FMT "\n",
               (unsigned)tid_index,
               (unsigned)dot11_frame_control_get_retry(header->frame_control),
               (unsigned)header->sequence_control,
               (unsigned)last_seq_ctrl,
               MM_MAC_ADDR_VAL(dot11_get_ta(header)),
               MM_MAC_ADDR_VAL(dot11_get_ra(header)));
        return true;
    }


    sta_data->rx_seq_num_spaces[tid_index] = header->sequence_control;
    return false;
}


static bool umac_datapath_rx_frame_allowed_pre_association(struct umac_datapath_data *data,
                                                           uint16_t frame_ver_type_subtype,
                                                           uint16_t frame_control_le)
{
    MMOSAL_DEV_ASSERT(data != NULL);
    MMOSAL_DEV_ASSERT(data->ops != NULL);
    MMOSAL_DEV_ASSERT(data->ops->frames_allowed_pre_association != NULL);


    if (frame_ver_type_subtype != DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON) &&
        dot11_frame_control_get_protected(frame_control_le))
    {
        return false;
    }

    for (const uint16_t *iter = data->ops->frames_allowed_pre_association; *iter != UINT16_MAX;
         iter++)
    {
        if (frame_ver_type_subtype == *iter)
        {
            return true;
        }
    }
    return false;
}

static bool umac_datapath_filter_all_beacons(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    return data->filter_beacons;
}

void umac_datapath_set_filter_all_beacons(struct umac_data *umacd, bool filter)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    data->filter_beacons = filter;
}

void umac_datapath_set_mesh_peer_group_key(struct umac_data *umacd,
                                           uint8_t key_id,
                                           const uint8_t *key,
                                           size_t key_len)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    if (key == NULL || key_len == 0)
    {
        data->mesh_peer_group_key_valid = false;
        data->mesh_peer_group_key_id = 0;
        data->mesh_peer_group_key_len = 0;
        memset(data->mesh_peer_group_key, 0, sizeof(data->mesh_peer_group_key));
        MESH_DBG_PRINTF("[mesh_key] cleared peer group key cache\n");
        return;
    }

    if (key_len > sizeof(data->mesh_peer_group_key))
    {
        MESH_DBG_PRINTF("[mesh_key] ignore peer key cache: key too long=%lu\n", (unsigned long)key_len);
        return;
    }

    data->mesh_peer_group_key_valid = true;
    data->mesh_peer_group_key_id = key_id;
    data->mesh_peer_group_key_len = key_len;
    memset(data->mesh_peer_group_key, 0, sizeof(data->mesh_peer_group_key));
    memcpy(data->mesh_peer_group_key, key, key_len);
    MESH_DBG_PRINTF("[mesh_key] cached peer group key id=%u len=%lu\n",
           key_id,
           (unsigned long)key_len);
}


static bool umac_datapath_rx_frame_filter(struct umac_data *umacd, struct mmpktview *rxbufview)
{
    bool drop_frame = false;
    uint16_t frame_ver_type_subtype;
    uint16_t frame_type = UINT16_MAX;
    const char *drop_reason = "unspecified";
    bool preassoc_allowed = false;


    const struct dot11_data_hdr *data_hdr =
        (const struct dot11_data_hdr *)mmpkt_get_data_start(rxbufview);
    const struct dot11_hdr *header = &data_hdr->base;
    uint32_t header_len = dot11_data_hdr_get_len(data_hdr);

    if (!umac_datapath_validate_buf_len(rxbufview, sizeof(header->frame_control)))
    {
        drop_reason = "short_fc";
        drop_frame = true;
        goto exit;
    }

    frame_ver_type_subtype = dot11_frame_control_get_ver_type_subtype(header->frame_control);
    frame_type = dot11_frame_control_get_type(header->frame_control);

    if (frame_ver_type_subtype == DOT11_VER_TYPE_SUBTYPE(0, CTRL, RTS))
    {

        MMLOG_INF("Dropping RTS frame.\n");
        drop_reason = "rts";
        drop_frame = true;
        goto exit;
    }

    if (frame_ver_type_subtype == DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON))
    {
        if (umac_datapath_filter_all_beacons(umacd))
        {
            MMLOG_VRB("Dropping beacon.\n");
            drop_reason = "beacon_filtered";
            drop_frame = true;
            goto exit;
        }

        header_len = sizeof(struct dot11_s1g_beacon_hdr);
    }


    if (!umac_datapath_validate_buf_len(rxbufview, header_len))
    {
        MMLOG_INF("Frame too short, drop.\n");
        drop_reason = "short_header";
        drop_frame = true;
        goto exit;
    }

    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    if (data->ops == NULL)
    {
        MMLOG_WRN("Frame received before datapath configured. Dropping.\n");
        drop_reason = "ops_null";
        drop_frame = true;
        goto exit;
    }

    preassoc_allowed = umac_datapath_rx_frame_allowed_pre_association(data,
                                                                       frame_ver_type_subtype,
                                                                       header->frame_control);

    if (!preassoc_allowed)
    {
        const uint8_t *ta = dot11_get_ta(header);
        MMOSAL_DEV_ASSERT(data->ops != NULL);
        struct umac_sta_data *stad = data->ops->lookup_stad_by_peer_addr(umacd, ta);
        if (stad == NULL)
        {
            /* In mesh mode, allow broadcast/multicast frames from non-peer TAs.
             * These include HWMP PREQs from non-adjacent mesh nodes (e.g. gateway)
             * that we must process and reply to for route maintenance. */
            if (data->mesh_mode && mm_mac_addr_is_multicast(dot11_get_ra(header)))
            {
                dp_mesh_dbg("[rx_filter] ALLOW mesh bcast from non-peer ta="
                       MM_MAC_ADDR_FMT " ftype=%04x\n",
                       MM_MAC_ADDR_VAL(ta), frame_ver_type_subtype);
                goto exit;
            }
            MMLOG_INF("Dropping packet from unknown sender " MM_MAC_ADDR_FMT " (%04x)\n",
                      MM_MAC_ADDR_VAL(ta),
                      frame_ver_type_subtype);
            MESH_DBG_PRINTF("[rx_filter] DROP unknown_sender ta=" MM_MAC_ADDR_FMT " ftype=%04x\n",
                   MM_MAC_ADDR_VAL(ta), frame_ver_type_subtype);
                 drop_reason = "unknown_sender";
            drop_frame = true;
            goto exit;
        }

        if (umac_interface_addr_matches_mac_addr(stad, dot11_get_sa_data(data_hdr)))
        {
            const uint8_t *ta = dot11_get_ta(header);
            bool ta_is_ours = umac_interface_addr_matches_mac_addr(stad, ta);

            /*
             * In mesh forwarding paths we have observed valid peer-originated data
             * where derived SA may alias to local address while TA is still peer.
             * Keep loopback protection for true self-originated frames (TA == ours),
             * but don't drop peer TA traffic in mesh mode.
             */
            if (!data->mesh_mode || ta_is_ours)
            {
                MMLOG_INF("Source address matches our MAC address, dropping received frame.\n");
                drop_reason = "loopback_sa";
                drop_frame = true;
                goto exit;
            }

            dp_mesh_dbg("[rx_ll] mesh_allow_sa_local ta=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   ta[0], ta[1], ta[2], ta[3], ta[4], ta[5]);
        }

        struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);
        if (umac_datapath_is_rx_frame_duplicate(sta_data, rxbufview, data->mesh_mode))
        {
            MMLOG_INF("Dropping duplicate frame. Type %u, Subtype %u.\n",
                      dot11_frame_control_get_type(header->frame_control),
                      dot11_frame_control_get_subtype(header->frame_control));
            drop_reason = "duplicate";
            drop_frame = true;
            goto exit;
        }
    }

exit:
    if (drop_frame &&
        frame_type == DOT11_FC_TYPE_DATA &&
        umac_datapath_validate_buf_len(rxbufview, sizeof(struct dot11_hdr)))
    {
        const struct dot11_hdr *h = (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
        printf("[rx_filter] DATA_DROP reason=%s ta=" MM_MAC_ADDR_FMT
               " ra=" MM_MAC_ADDR_FMT " fc=0x%04x type=%u subtype=%u protected=%u preassoc_allowed=%u\n",
               drop_reason,
               MM_MAC_ADDR_VAL(dot11_get_ta(h)),
               MM_MAC_ADDR_VAL(dot11_get_ra(h)),
               (unsigned)h->frame_control,
               (unsigned)dot11_frame_control_get_type(h->frame_control),
               (unsigned)dot11_frame_control_get_subtype(h->frame_control),
               (unsigned)dot11_frame_control_get_protected(h->frame_control),
               (unsigned)preassoc_allowed);
    }

    return drop_frame;
}

void umac_datapath_init(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    DATAPATH_TRACE_INIT();

    memset(data, 0, sizeof(*data));

    data->tx_flowcontrol_sem = mmosal_semb_create("txfc");
    MMOSAL_ASSERT(data->tx_flowcontrol_sem != NULL);
}

void umac_datapath_stad_init(struct umac_sta_data *stad)
{
    MMOSAL_ASSERT(stad != NULL);

    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);


    memset(sta_data->rx_seq_num_spaces, 0xff, sizeof(sta_data->rx_seq_num_spaces));
}

void umac_datapath_stad_flush_txq(struct umac_data *umacd, struct umac_sta_data *stad)
{
    MMOSAL_ASSERT(stad != NULL);
    const uint16_t aid = umac_sta_data_get_aid(stad);
    MMLOG_DBG("Flushing %d frames for STA AID=%d\n", umac_sta_data_get_queued_len(stad), aid);
    while (umac_sta_data_get_queued_len(stad))
    {
        struct mmpkt *mmpkt = umac_sta_data_pop_pkt(stad);
        MMOSAL_DEV_ASSERT(mmpkt);
        mmpkt_release(mmpkt);
        umac_stats_increment_datapath_txq_frames_dropped(umacd);
        MMLOG_VRB("Popped and dropped packet for stad AID=%d\n", aid);
    }
}

void umac_datapath_stad_flush(struct umac_data *umacd, struct umac_sta_data *stad)
{
    MMOSAL_ASSERT(stad != NULL);
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);
    umac_datapath_flush_rx_reorder_list(stad, sta_data);
    datapath_defrag_deinit(umacd, &sta_data->defrag_data);
    umac_datapath_stad_flush_txq(umacd, stad);
}

static void umac_datapath_flush_txq(struct umac_data *umacd);


static void umac_datapath_flush(struct umac_data *umacd)
{
    bool more = true;
    do {

        more = umac_datapath_process(umacd);
    } while (more);

    umac_stats_clear_datapath_rxq_high_water_mark(umacd);
    umac_stats_clear_datapath_rx_mgmt_q_high_water_mark(umacd);
    umac_stats_clear_datapath_rxq_frames_dropped(umacd);
    umac_datapath_flush_txq(umacd);
    umac_stats_clear_datapath_rx_reorder_overflow(umacd);
    umac_stats_clear_datapath_rx_reorder_outdated_drops(umacd);
    umac_stats_clear_datapath_rx_reorder_total(umacd);
}

void umac_datapath_deinit(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    umac_datapath_flush(umacd);

    mmosal_semb_delete(data->tx_flowcontrol_sem);

    memset(data, 0, sizeof(*data));
}

enum mmwlan_status umac_datapath_register_tx_flow_control_cb(struct umac_data *umacd,
                                                             mmwlan_tx_flow_control_cb_t callback,
                                                             void *arg)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    data->tx_flow_control_callback = callback;
    data->tx_flow_control_arg = arg;
    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_datapath_register_rx_cb(struct umac_data *umacd,
                                                mmwlan_rx_cb_t callback,
                                                void *arg)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    data->rx_pkt_callback = NULL;
    umac_interface_register_rx_pkt_ext_cb(umacd, MMWLAN_VIF_UNSPECIFIED, NULL, NULL);
    data->rx_callback = callback;
    data->rx_arg = arg;
    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_datapath_register_rx_pkt_cb(struct umac_data *umacd,
                                                    mmwlan_rx_pkt_cb_t callback,
                                                    void *arg)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    data->rx_callback = NULL;
    umac_interface_register_rx_pkt_ext_cb(umacd, MMWLAN_VIF_UNSPECIFIED, NULL, NULL);
    data->rx_pkt_callback = callback;
    data->rx_arg = arg;
    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_datapath_register_rx_pkt_ext_cb(struct umac_data *umacd,
                                                        enum mmwlan_vif vif,
                                                        mmwlan_rx_pkt_ext_cb_t callback,
                                                        void *arg)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    data->rx_callback = NULL;
    data->rx_pkt_callback = NULL;
    data->rx_arg = NULL;

    return umac_interface_register_rx_pkt_ext_cb(umacd, vif, callback, arg);
}


static void umac_datapath_process_rx_frame(struct umac_data *umacd,
                                           struct umac_datapath_data *data,
                                           struct mmpkt *rxbuf)
{
    struct mmpktview *rxbufview = mmpkt_open(rxbuf);


    struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    uint16_t frame_control_le = header->frame_control;
    uint16_t frame_ver_type_subtype = dot11_frame_control_get_ver_type_subtype(frame_control_le);
    uint16_t frame_type = dot11_frame_control_get_type(frame_control_le);
    uint16_t frame_subtype = dot11_frame_control_get_subtype(frame_control_le);
    MMLOG_VRB("RX frame. Type: %d, Subtype: %d.\n", frame_type, frame_subtype);


    const uint8_t *ta = NULL;
    struct umac_sta_data *stad = NULL;
    bool fallback_stad = false;
    if (frame_ver_type_subtype != DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON))
    {
        ta = dot11_get_ta(header);
        MMOSAL_DEV_ASSERT(data->ops != NULL);
        MMOSAL_DEV_ASSERT(mm_mac_addr_is_multicast(ta) == false);
        stad = data->ops->lookup_stad_by_peer_addr(umacd, ta);
    }

    if (frame_type == DOT11_FC_TYPE_MGMT)
    {
        mac_mgmt_rx_dispatch_count++;
        if (mac_mgmt_trace_sample(frame_subtype, mac_mgmt_rx_dispatch_count))
        {
            printk("[MAC_MGMT] RX_DISPATCH count=%lu subtype=0x%x len=%u stad=%p ta="
                   MM_MAC_ADDR_FMT " ra=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                   (unsigned long)mac_mgmt_rx_dispatch_count,
                   (unsigned)frame_subtype,
                   (unsigned)mmpkt_get_data_length(rxbufview),
                   (void *)stad,
                   MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                   MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                   MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)));
        }
    }


    if (stad == NULL && !umac_datapath_rx_frame_allowed_pre_association(data,
                                                                        frame_ver_type_subtype,
                                                                        frame_control_le))
    {
        const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);

        /* Mesh mode: for broadcast frames from non-peer TAs (e.g. HWMP PREQs
         * from gateway), use primary connected peer's stad for key material
         * so the frame can be decrypted and processed. */
        if (sta_args != NULL && sta_args->mesh_mode &&
            mm_mac_addr_is_multicast(dot11_get_ra(header)))
        {
            stad = umac_connection_get_stad(umacd);
            if (stad != NULL)
            {
                fallback_stad = true;
                if (ta != NULL)
                {
                    dp_mesh_dbg("[rx_mac] mesh_fallback_stad for non-peer bcast ta="
                           MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(ta));
                }
            }
        }

        if (stad == NULL)
        {
            if (sta_args != NULL && sta_args->mesh_mode)
            {
                if (frame_type == DOT11_FC_TYPE_MGMT)
                {
                    printk("[MAC_MGMT] RX_DROP reason=no_sta_not_preassoc subtype=0x%x ta="
                           MM_MAC_ADDR_FMT " ra=" MM_MAC_ADDR_FMT " bssid="
                           MM_MAC_ADDR_FMT "\n",
                           (unsigned)frame_subtype,
                           MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                           MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                           MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)));
                    MESH_DBG_PRINTF("[mesh_trace] MESH_RX_PREASSOC_DROP: subtype=0x%x ta=" MM_MAC_ADDR_FMT " ra=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                           frame_subtype,
                           MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                           MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                           MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)));
                }
                else if (frame_type == DOT11_FC_TYPE_DATA)
                {
                    printf("[rx_mac] DATA PREASSOC_DROP: stad=NULL ta=" MM_MAC_ADDR_FMT
                           " ra=" MM_MAC_ADDR_FMT " fc=0x%04x\n",
                           MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                           MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                           (unsigned)frame_control_le);
                }
            }

            if (ta != NULL)
            {
                MMLOG_WRN("Unable to find STA record for " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(ta));
            }
            mmpkt_close(&rxbufview);
            mmpkt_release(rxbuf);
            return;
        }
    }


    /* Don't update sleep state from non-peer frames (fallback stad is our
     * primary peer, not the actual sender). */
    if (stad && !fallback_stad && (frame_type == DOT11_FC_TYPE_DATA || frame_type == DOT11_FC_TYPE_MGMT))
    {
        uint16_t pwr_mgt = dot11_frame_control_get_power_mgmt(frame_control_le);
        bool ok = data->ops->set_stad_sleep_state(stad, pwr_mgt);
        MMOSAL_DEV_ASSERT(ok);
    }

    if (frame_type == DOT11_FC_TYPE_DATA)
    {
#if DP_MESH_VERBOSE
        if (data->mesh_mode)
        {
            printf("[rx_mac] DATA dispatch ta=" MM_MAC_ADDR_FMT " subtype=0x%x stad=%p\n",
                   MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                   (unsigned)frame_subtype, (void *)stad);
        }
#endif
        umac_datapath_process_rx_data_frame(umacd, stad, rxbuf, rxbufview);
    }
    else
    {
        umac_datapath_process_rx_other_frame(umacd, stad, data, rxbuf, rxbufview);
    }

}


static inline bool umac_datapath_process_rx(struct umac_data *umacd,
                                            struct umac_datapath_data *data)
{
    unsigned ii;
    for (ii = 0; ii < MAX_RX_PROCESS_PER_LOOP; ii++)
    {
        struct mmpkt *mmpkt;
        MMOSAL_TASK_ENTER_CRITICAL();
        mmpkt = data->rx_mgmt_q.len ? mmpkt_list_dequeue(&data->rx_mgmt_q) :
                                      mmpkt_list_dequeue(&data->rxq);
        MMOSAL_TASK_EXIT_CRITICAL();

        if (mmpkt == NULL)
        {
            return false;
        }

        DATAPATH_TRACE("rx deq %x", (uint32_t)mmpkt);

        MMLOG_VRB("RX dequeue %p\n", mmpkt);
        umac_datapath_process_rx_frame(umacd, data, mmpkt);
    }

    return true;
}


static void umac_datapath_rx_queue_frame(struct umac_data *umacd,
                                         struct umac_datapath_data *data,
                                         struct mmpkt *rxbuf,
                                         struct mmpktview *rxbufview)
{
    MMLOG_VRB("RX queue %p\n", rxbuf);
    DATAPATH_TRACE("rx q %x", (uint32_t)rxbuf);

    struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
    bool is_mgmt = dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_MGMT;
    mmpkt_close(&rxbufview);

    MMOSAL_TASK_ENTER_CRITICAL();
    if (is_mgmt)
    {
        mmpkt_list_append(&data->rx_mgmt_q, rxbuf);
        umac_stats_update_datapath_rx_mgmt_q_high_water_mark(umacd, data->rx_mgmt_q.len);
    }
    else
    {
        mmpkt_list_append(&data->rxq, rxbuf);
        umac_stats_update_datapath_rxq_high_water_mark(umacd, data->rxq.len);
    }
    MMOSAL_TASK_EXIT_CRITICAL();
}

void umac_datapath_rx_frame(struct umac_data *umacd, struct mmpkt *rxbuf)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    struct mmpktview *rxbufview = mmpkt_open(rxbuf);
    bool trace_mgmt = false;
    uint16_t trace_mgmt_subtype = 0;

    if (mmpkt_get_data_length(rxbufview) >= sizeof(struct dot11_hdr))
    {
        const struct dot11_hdr *header =
            (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
        if (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_MGMT)
        {
            const struct mmdrv_rx_metadata *rxm = mmdrv_get_rx_metadata(rxbuf);
            trace_mgmt_subtype = dot11_frame_control_get_subtype(header->frame_control);
            mac_mgmt_rx_entry_count++;
            trace_mgmt = mac_mgmt_trace_sample(trace_mgmt_subtype, mac_mgmt_rx_entry_count);
            if (trace_mgmt)
            {
                printk("[MAC_MGMT] RX_ENTRY count=%lu subtype=0x%x fc=0x%04x len=%u "
                       "vif=%u rssi=%d freq_100khz=%u bw=%u flags=0x%x ta="
                       MM_MAC_ADDR_FMT " ra=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                       (unsigned long)mac_mgmt_rx_entry_count,
                       (unsigned)trace_mgmt_subtype,
                       (unsigned)le16toh(header->frame_control),
                       (unsigned)mmpkt_get_data_length(rxbufview),
                       rxm ? (unsigned)rxm->vif_id : 0U,
                       rxm ? (int)rxm->rssi : 0,
                       rxm ? (unsigned)rxm->freq_100khz : 0U,
                       rxm ? (unsigned)rxm->bw_mhz : 0U,
                       rxm ? (unsigned)rxm->flags : 0U,
                       MM_MAC_ADDR_VAL(dot11_get_ta(header)),
                       MM_MAC_ADDR_VAL(dot11_get_ra(header)),
                       MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(header)));
            }
        }
    }

#if DP_MESH_VERBOSE
    /* Verbose data frame receipt logging at radio/UMAC entry */
    {
        size_t flen = mmpkt_get_data_length(rxbufview);
        if (flen >= sizeof(struct dot11_hdr))
        {
            const struct dot11_hdr *h = (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
            uint16_t ft = dot11_frame_control_get_type(h->frame_control);
            if (ft == DOT11_FC_TYPE_DATA)
            {
                const struct mmdrv_rx_metadata *rxm = mmdrv_get_rx_metadata(rxbuf);
                printf("[rx_mac] DATA frame len=%u fc=0x%04x ta=" MM_MAC_ADDR_FMT
                       " ra=" MM_MAC_ADDR_FMT " rssi=%d flags=0x%x\n",
                       (unsigned)flen,
                       (unsigned)h->frame_control,
                       MM_MAC_ADDR_VAL(dot11_get_ta(h)),
                       MM_MAC_ADDR_VAL(dot11_get_ra(h)),
                       rxm ? rxm->rssi : 0,
                       rxm ? rxm->flags : 0);
            }
        }
    }
#endif

    umac_datapath_log_rx_frame_lowlevel(rxbuf, rxbufview);

    if (umac_datapath_rx_frame_filter(umacd, rxbufview))
    {
        if (trace_mgmt)
        {
            printk("[MAC_MGMT] RX_FILTER result=DROP count=%lu subtype=0x%x\n",
                   (unsigned long)mac_mgmt_rx_entry_count,
                   (unsigned)trace_mgmt_subtype);
        }
        /* Log data frame drops at filter stage (always on) */
        {
            size_t flen = mmpkt_get_data_length(rxbufview);
            if (flen >= sizeof(struct dot11_hdr))
            {
                const struct dot11_hdr *h = (const struct dot11_hdr *)mmpkt_get_data_start(rxbufview);
                uint16_t ft = dot11_frame_control_get_type(h->frame_control);
                if (ft == DOT11_FC_TYPE_DATA)
                {
                    printf("[rx_mac] DATA FILTERED_DROP ta=" MM_MAC_ADDR_FMT "\n",
                           MM_MAC_ADDR_VAL(dot11_get_ta(h)));
                }
            }
        }
        dp_mesh_dbg("[rx_ll] filtered_drop\n");
        mmpkt_close(&rxbufview);
        mmpkt_release(rxbuf);
        return;
    }

    if (trace_mgmt)
    {
        printk("[MAC_MGMT] RX_FILTER result=PASS count=%lu subtype=0x%x\n",
               (unsigned long)mac_mgmt_rx_entry_count,
               (unsigned)trace_mgmt_subtype);
    }

    umac_datapath_rx_queue_frame(umacd, data, rxbuf, rxbufview);

    umac_core_evt_wake(umacd);
}

struct mmpkt *umac_datapath_alloc_mmpkt_for_qos_data_tx(uint32_t payload_len, uint8_t pkt_class)
{
    /* Add tailroom for mesh SW CCMP: CCMP header (8) + MIC (8) = 16 bytes */
    return umac_datapath_alloc_raw_tx_mmpkt(pkt_class, MAX_QOS_DATA_MAC_HEADER_LEN,
                                            payload_len + DOT11_CCMP_HEADER_LEN + DOT11_CCMP_128_MIC_LEN);
}

struct mmpkt *mmwlan_alloc_mmpkt_for_tx(uint32_t payload_len, uint8_t tid)
{
    if (tid > MMWLAN_MAX_QOS_TID)
    {
        MMLOG_ERR("Invalid TID %u\n", tid);
        return NULL;
    }
    return umac_datapath_alloc_mmpkt_for_qos_data_tx(payload_len, MMDRV_PKT_CLASS_DATA_TID0 + tid);
}

struct mmpkt *umac_datapath_alloc_raw_tx_mmpkt(uint8_t pkt_class,
                                               uint32_t space_at_start,
                                               uint32_t space_at_end)
{
    return mmdrv_alloc_mmpkt_for_tx(pkt_class, space_at_start, space_at_end);
}

struct mmpkt *umac_datapath_copy_tx_mmpkt(struct mmpkt *pkt, uint8_t pkt_class)
{
    uint32_t length;
    struct mmpkt *copy;
    struct mmpktview *view_src;
    struct mmpktview *view_dst;

    MMOSAL_DEV_ASSERT(pkt != NULL);

    view_src = mmpkt_open(pkt);
    length = mmpkt_get_data_length(view_src);

    copy = umac_datapath_alloc_mmpkt_for_qos_data_tx(length, pkt_class);
    if (copy == NULL)
    {
        mmpkt_close(&view_src);
        return NULL;
    }

    view_dst = mmpkt_open(copy);
    mmpkt_append_data(view_dst, mmpkt_get_data_start(view_src), length);
    *(mmpkt_get_metadata(copy).tx) = *(mmpkt_get_metadata(pkt).tx);

    mmpkt_close(&view_src);
    mmpkt_close(&view_dst);

    return copy;
}


static void umac_datapath_construct_80211_data_header_sta(struct umac_sta_data *stad,
                                                          const struct umac_8023_hdr *hdr_8023,
                                                          struct dot11_data_hdr *data_hdr)
{
    uint16_t frame_control = DOT11_MASK_FC_TO_DS |
                             DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE |
                             DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE;

    umac_sta_data_get_bssid(stad, data_hdr->base.addr1);
    umac_interface_get_mac_addr(stad, data_hdr->base.addr2);
    mac_addr_copy(data_hdr->base.addr3, hdr_8023->dest_addr);
    if (!umac_interface_addr_matches_mac_addr(stad, hdr_8023->src_addr))
    {

        frame_control |= DOT11_MASK_FC_FROM_DS;
        mac_addr_copy(data_hdr->addr4, hdr_8023->src_addr);
    }
    data_hdr->base.frame_control = htole16(frame_control);
}

/** Mesh mode: 4-address header with ToDS=1, FromDS=1 per 802.11s */
static void umac_datapath_construct_80211_data_header_mesh(struct umac_sta_data *stad,
                                                           const struct umac_8023_hdr *hdr_8023,
                                                           struct dot11_data_hdr *data_hdr)
{
    bool is_group_da = mm_mac_addr_is_multicast(hdr_8023->dest_addr);

    if (is_group_da)
    {
        /* 802.11s: group-addressed frames use 3-address (ToDS=0, FromDS=1)
         *   addr1 = DA (broadcast/multicast)
         *   addr2 = TA (own MAC, also serves as BSSID)
         *   addr3 = SA (own MAC) */
        uint16_t frame_control = DOT11_MASK_FC_FROM_DS |
                                 DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE |
                                 DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE;

        mac_addr_copy(data_hdr->base.addr1, hdr_8023->dest_addr);
        umac_interface_get_mac_addr(stad, data_hdr->base.addr2);
        mac_addr_copy(data_hdr->base.addr3, hdr_8023->src_addr);

        data_hdr->base.frame_control = htole16(frame_control);
    }
    else
    {
        /* 802.11s: individually-addressed frames use 4-address (ToDS=1, FromDS=1)
         * with AE=2 (address extension) per IEEE 802.11-2020 Table 9-36:
         *   addr1 = RA (next-hop mesh peer)
         *   addr2 = TA (own MAC)
         *   addr3 = mesh DA (mesh peer serving the destination)
         *   addr4 = mesh SA (own MAC)
         * The real ethernet DA/SA are carried in mesh header Addr5/Addr6 (AE=2). */
        uint16_t frame_control = DOT11_MASK_FC_TO_DS | DOT11_MASK_FC_FROM_DS |
                                 DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE |
                                 DOT11_FC_SUBTYPE_QOS_DATA << DOT11_SHIFT_FC_SUBTYPE;

        umac_sta_data_get_peer_addr(stad, data_hdr->base.addr1);
        umac_interface_get_mac_addr(stad, data_hdr->base.addr2);
        /* A3 = mesh DA: the mesh STA that will deliver to the final
         * destination.  Look up the proxy table first (learned from
         * incoming AE=1/AE=2 frames); fall back to the ethernet DA
         * itself, which is correct when the DA is a mesh STA (single
         * or multi-hop). */
        const uint8_t *proxy_da = mesh_proxy_table_lookup(hdr_8023->dest_addr);
        if (proxy_da)
        {
            mac_addr_copy(data_hdr->base.addr3, proxy_da);
        }
        else
        {
            mac_addr_copy(data_hdr->base.addr3, hdr_8023->dest_addr);
        }
        /* A4 = mesh SA: us (the originating mesh STA) */
        umac_interface_get_mac_addr(stad, data_hdr->addr4);

        data_hdr->base.frame_control = htole16(frame_control);
    }
}

static void umac_datapath_aggr_check(struct umac_data *umacd,
                                     struct umac_sta_data *stad,
                                     uint8_t tid,
                                     uint16_t ssc)
{
    if (tid > UMAC_BA_MAX_AGGR_TID)
    {
        return;
    }

    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    MMOSAL_DEV_ASSERT(data->ops != NULL);
    if (data->ops->get_sta_state(stad) != MMWLAN_STA_CONNECTED)
    {
        return;
    }

    if (!umac_config_is_ampdu_enabled(umacd) ||
        !MORSE_CAP_SUPPORTED(umac_interface_get_capabilities(umacd), AMPDU))
    {
        return;
    }

    umac_ba_session_init(stad, tid, ssc, DOT11_BLOCK_ACK_TIMEOUT_DISABLED);
}

enum mmwlan_status umac_datapath_process_tx_frame(struct umac_data *umacd,
                                                  struct umac_sta_data *stad,
                                                  struct mmpktview *txbufview)
{
    struct mmpkt *txbuf = mmpkt_from_view(txbufview);
    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(txbuf);
    uint16_t tid = tx_metadata->tid;
    uint8_t enc = tx_metadata->enc;
    const struct umac_8023_hdr *header_8023 =
        (const struct umac_8023_hdr *)mmpkt_get_data_start(txbufview);
    const uint16_t ethertype = be16toh(header_8023->ethertype_be);
    /* Save original ethernet DA/SA before they are consumed by 802.11 header construction.
     * Needed for mesh AE=2 address extensions (proxied DA/SA). */
    uint8_t eth_da[DOT11_MAC_ADDR_LEN], eth_sa[DOT11_MAC_ADDR_LEN];
    memcpy(eth_da, header_8023->dest_addr, DOT11_MAC_ADDR_LEN);
    memcpy(eth_sa, header_8023->src_addr, DOT11_MAC_ADDR_LEN);
    struct dot11_data_hdr data_hdr = { 0 };
    struct dot11_hdr *header = &data_hdr.base;
    int key_id = -1;
    int key_len = 0;
    int ccmp_len = 0;
    uint32_t rts_threshold = 0;
    bool rts_required = false;
    struct dot11_qos_ctrl qos_ctrl = {};
    enum mmwlan_status status = MMWLAN_ERROR;

    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);


    bool is_eapol = (ethertype == ETHERTYPE_EAPOL);

    dp_mesh_dbg("[dp_tx] process_tx_frame: ethertype=0x%04x tid=%u enc=%u da=%02x:%02x:%02x:%02x:%02x:%02x\n",
           ethertype, tid, enc,
           header_8023->dest_addr[0], header_8023->dest_addr[1], header_8023->dest_addr[2],
           header_8023->dest_addr[3], header_8023->dest_addr[4], header_8023->dest_addr[5]);

    MMLOG_DBG("Dequeued frame for TX (%p, ethertype=0x%04x, tid=%u, %s port)\n",
              txbuf,
              ethertype,
              tid,
              is_eapol ? "uncontrolled" : "controlled");

    MMOSAL_DEV_ASSERT(data->ops != NULL);

    data->ops->construct_80211_data_header(stad, header_8023, &data_hdr);
    const uint32_t data_hdr_len = dot11_data_hdr_get_len(&data_hdr);

    /* Log TX Ethernet source for mesh mode to diagnose zero-MAC issues */
    if (data->mesh_mode && ethertype == 0x0800)
    {
        dp_mesh_dbg("[dp_mesh_tx] eth_src=%02x:%02x:%02x:%02x:%02x:%02x eth_dst=%02x:%02x:%02x:%02x:%02x:%02x ethertype=0x%04x\n",
               header_8023->src_addr[0], header_8023->src_addr[1], header_8023->src_addr[2],
               header_8023->src_addr[3], header_8023->src_addr[4], header_8023->src_addr[5],
               header_8023->dest_addr[0], header_8023->dest_addr[1], header_8023->dest_addr[2],
               header_8023->dest_addr[3], header_8023->dest_addr[4], header_8023->dest_addr[5],
               ethertype);
    }

    /* Mesh mode: set DHCP broadcast flag so server broadcasts replies.
     * Required because ESP32 mesh does not implement HWMP path resolution,
     * so unicast replies from the server would be dropped by the mesh peer. */
    if (data->mesh_mode)
    {
        mesh_set_dhcp_broadcast_flag(txbufview, ethertype);
    }

    mmpkt_remove_from_start(txbufview, 2 * DOT11_MAC_ADDR_LEN);
    MM_STATIC_ASSERT(2 * DOT11_MAC_ADDR_LEN == offsetof(struct umac_8023_hdr, ethertype_be), "");

    if (ethertype >= ETHERTYPE_THRESHOLD)
    {

        mmpkt_prepend_data(txbufview, snap_802_1h, sizeof(snap_802_1h));
    }

    const uint8_t *ra = dot11_get_ra(&(data_hdr.base));
    if (mm_mac_addr_is_zero(ra))
    {
        printf("[dp_tx] DROPPED: zero RA\n");
        MMLOG_WRN("Dropping tx data frame with zero RA.\n");
        status = MMWLAN_ERROR;
        goto error;
    }
    /* Key selection based on RA (addr1):
     * - 4-addr unicast: RA = peer addr → pairwise key (PTK)
     * - 3-addr broadcast/multicast: RA = DA (broadcast) → group key (MGTK) */
    bool is_multicast = mm_mac_addr_is_multicast(ra);


    MMOSAL_DEV_ASSERT(is_eapol || enc == ENCRYPTION_ENABLED);

    if (umac_sta_data_get_security_type(stad) != MMWLAN_OPEN && enc != ENCRYPTION_DISABLED)
    {
        enum umac_key_type key_type = is_multicast ? UMAC_KEY_TYPE_GROUP : UMAC_KEY_TYPE_PAIRWISE;

        key_id = umac_keys_get_active_key_id(stad, key_type);
        if (key_id >= 0)
        {
            key_len = umac_keys_get_key_len(stad, key_id);
            header->frame_control |= htole16(DOT11_MASK_FC_PROTECTED);
        }
        else if (enc == ENCRYPTION_ENABLED)
        {
            printf("[dp_tx] DROPPED: no key for type %u (multicast=%d)\n", key_type, is_multicast);
            MMLOG_WRN("Could not find key for type %u.\n", key_type);
            status = MMWLAN_ERROR;
            goto error;
        }
        MMLOG_DBG("Using %s key index %d\n",
                  (key_type == UMAC_KEY_TYPE_GROUP)    ? "GROUP" :
                  (key_type == UMAC_KEY_TYPE_PAIRWISE) ? "PAIR" :
                                                         "??",
                  key_id);
    }

    size_t seq_num_idx = is_multicast ? MMDRV_SEQ_NUM_BASELINE : tid;
    DOT11_SEQUENCE_CONTROL_SET_SEQUENCE_NUMBER(header->sequence_control,
                                               sta_data->tx_seq_num_spaces[seq_num_idx]++);


    if (!is_multicast && !is_eapol)
    {
        umac_datapath_aggr_check(umacd, stad, tid, header->sequence_control);
    }

    rts_threshold = umac_config_get_rts_threshold(umacd);


    qos_ctrl.field = (uint16_t)(tid & DOT11_MASK_QC_TID);

    /* Mesh mode: set Mesh Control Present bit in QoS Control */
    if (data->mesh_mode)
    {
        qos_ctrl.field |= htole16(1 << 8);
    }

    if (key_len == UMAC_KEY_AES_256_LEN)
    {
        ccmp_len = DOT11_CCMP_HEADER_LEN + DOT11_CCMP_256_MIC_LEN;
    }
    else if (key_len == UMAC_KEY_AES_128_LEN)
    {
        ccmp_len = DOT11_CCMP_HEADER_LEN + DOT11_CCMP_128_MIC_LEN;
    }

    /* Mesh control field size: AE=0 (broadcast) = 6 bytes, AE=2 (unicast) = 18 bytes */
    size_t mesh_ctrl_len = 0;
    if (data->mesh_mode)
    {
        mesh_ctrl_len = is_multicast ? 6 : 18;  /* AE=0: 6B, AE=2: 6B + 12B addrs */
    }

    rts_required = (rts_threshold && ((mmpkt_get_data_length(txbufview) +
                                       data_hdr_len +
                                       sizeof(qos_ctrl) +
                                       mesh_ctrl_len +
                                       DOT11_FCS_FIELD_LEN +
                                       ccmp_len) > rts_threshold));

    /* Mesh mode: prepend mesh control header.
     * Broadcast (AE=0): 6 bytes (flags + TTL + mesh_seq)
     * Unicast  (AE=2): 18 bytes (flags + TTL + mesh_seq + Addr5 + Addr6)
     *   Addr5 = proxied DA (original ethernet destination)
     *   Addr6 = proxied SA (original ethernet source) */
    if (data->mesh_mode)
    {
        uint32_t mesh_seq_val = data->mesh_seq_num++;
        if (!is_multicast)
        {
            /* Unicast: AE=2 with proxied DA/SA in mesh header extensions */
            uint8_t mesh_hdr[18];
            mesh_hdr[0] = 0x02;  /* flags: AE=2 (two address extensions) */
            mesh_hdr[1] = 31;    /* TTL */
            uint32_t seq = htole32(mesh_seq_val);
            memcpy(&mesh_hdr[2], &seq, sizeof(seq));
            memcpy(&mesh_hdr[6], eth_da, DOT11_MAC_ADDR_LEN);   /* Addr5 = proxied DA */
            memcpy(&mesh_hdr[12], eth_sa, DOT11_MAC_ADDR_LEN);  /* Addr6 = proxied SA */
            mmpkt_prepend_data(txbufview, mesh_hdr, sizeof(mesh_hdr));
        }
        else
        {
            /* Broadcast/multicast: AE=0 (no address extension) */
            uint8_t mesh_hdr[6];
            mesh_hdr[0] = 0x00;  /* flags: no address extension */
            mesh_hdr[1] = 31;    /* TTL */
            uint32_t seq = htole32(mesh_seq_val);
            memcpy(&mesh_hdr[2], &seq, sizeof(seq));
            mmpkt_prepend_data(txbufview, mesh_hdr, sizeof(mesh_hdr));
        }
        dp_mesh_dbg("[dp_mesh] mesh_ctrl prepended seq=%lu fc=0x%04x hdr_len=%lu a1=%02x:%02x:%02x:%02x:%02x:%02x a2=%02x:%02x:%02x:%02x:%02x:%02x a3=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned long)mesh_seq_val, le16toh(header->frame_control), (unsigned long)data_hdr_len,
               data_hdr.base.addr1[0], data_hdr.base.addr1[1], data_hdr.base.addr1[2],
               data_hdr.base.addr1[3], data_hdr.base.addr1[4], data_hdr.base.addr1[5],
               data_hdr.base.addr2[0], data_hdr.base.addr2[1], data_hdr.base.addr2[2],
               data_hdr.base.addr2[3], data_hdr.base.addr2[4], data_hdr.base.addr2[5],
               data_hdr.base.addr3[0], data_hdr.base.addr3[1], data_hdr.base.addr3[2],
               data_hdr.base.addr3[3], data_hdr.base.addr3[4], data_hdr.base.addr3[5]);
    }

    MMLOG_VRB("Add QOS CNTL bytes\n");
    mmpkt_prepend_data(txbufview, (uint8_t *)&qos_ctrl.field, sizeof(qos_ctrl));
    mmpkt_prepend_data(txbufview, (uint8_t *)&data_hdr, data_hdr_len);

    tx_metadata->flags = 0;
    if (key_id >= 0)
    {
        /* Mesh unicast (4-addr): use SW CCMP because the chip's HW CCMP computes
         * AAD with ToDS=0 (3-addr) instead of ToDS=1 (4-addr), causing MIC mismatch
         * on the receiver. SW CCMP builds the correct 4-addr AAD. */
        if (data->mesh_mode && !is_multicast)
        {
            if (!mesh_sw_ccmp_encrypt(stad, key_id, &data_hdr, qos_ctrl.field, tid, txbufview))
            {
                printf("[dp_tx] DROPPED: SW CCMP encrypt failed\n");
                status = MMWLAN_ERROR;
                goto error;
            }
            /* Don't set HW_ENC - frame is already encrypted by SW */
        }
        else
        {
            tx_metadata->flags |= MMDRV_TX_FLAG_HW_ENC;
            umac_keys_increment_tx_seq(stad, key_id);
        }
    }

    tx_metadata->key_idx = key_id;

    if (!is_multicast)
    {
        tx_metadata->tid_max_reorder_buf_size = umac_ba_get_reorder_buffer_size(stad, tid);
        if (umac_ba_is_ampdu_permitted(stad, tid))
        {
            tx_metadata->flags |= MMDRV_TX_FLAG_AMPDU_ENABLED;
        }
    }

    umac_connection_populate_tx_metadata(umacd, tx_metadata);

    tx_metadata->aid = umac_sta_data_get_aid(stad);


    if (is_eapol)
    {
        umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);
    }
    else if (is_multicast)
    {

        tx_metadata->flags |= MMDRV_TX_FLAG_NO_ACK;
        umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);
    }
    else
    {
        MMOSAL_DEV_ASSERT(stad != NULL);
        umac_rc_init_rate_table_data(stad,
                                     &tx_metadata->rc_data,
                                     rts_required,
                                     mmpkt_get_data_length(txbufview));
    }

    MMLOG_DBG("Transmitting frame %p\n", txbuf);

    umac_stats_update_last_tx_time(umacd);

    /* Hex dump first 48 bytes of frame before TX (hdr+qos+meshctrl+snap) */
    if (data->mesh_mode)
    {
        struct mmpktview *dbgview = mmpkt_open(txbuf);
        const uint8_t *p = mmpkt_get_data_start(dbgview);
        uint32_t dlen = mmpkt_get_data_length(dbgview);
        uint32_t dump_len = dlen < 48 ? dlen : 48;
        dp_mesh_dbg("[dp_mesh] tx_hex len=%lu: ", (unsigned long)dlen);
        for (uint32_t i = 0; i < dump_len; i++)
            dp_mesh_dbg("%02x ", p[i]);
        dp_mesh_dbg("\n");
        dp_mesh_dbg("[dp_mesh] key_idx=%d flags=0x%02x is_mcast=%d\n",
               key_id, tx_metadata->flags, is_multicast);
        mmpkt_close(&dbgview);
    }

	mmpkt_close(&txbufview);
	printf("[dp_tx] mmdrv_tx_frame call ethertype=0x%04x mesh=%d mcast=%d flags=0x%02x key=%d\n",
	       ethertype, data->mesh_mode, is_multicast, tx_metadata->flags, key_id);
	int ret = mmdrv_tx_frame(txbuf, false);
	if (ret)
	{
        printf("[dp_tx] mmdrv_tx_frame FAILED ret=%d\n", ret);
        MMLOG_WRN("mmdrv_tx_frame failed with retcode %d\n", ret);
    }
    else
    {
        dp_mesh_dbg("[dp_tx] mmdrv_tx_frame OK ethertype=0x%04x ra=%02x:%02x:%02x:%02x:%02x:%02x\n",
               ethertype, ra[0], ra[1], ra[2], ra[3], ra[4], ra[5]);
    }
    return (ret == 0 ? MMWLAN_SUCCESS : MMWLAN_ERROR);

error:
    mmpkt_close(&txbufview);
    mmpkt_release(txbuf);
    umac_stats_increment_datapath_txq_frames_dropped(umacd);
    return status;
}

static uint32_t umac_datapath_calculate_tx_timeout_ms(struct umac_data *umacd, bool blocking)
{
    if (blocking)
    {
        const struct mmwlan_twt_config_args *twt_config = umac_twt_get_config(umacd);
        if (twt_config->twt_mode == MMWLAN_TWT_REQUESTER)
        {
            return (twt_config->twt_wake_interval_us / 1000);
        }
        else
        {
            return MMWLAN_TX_DEFAULT_TIMEOUT_MS;
        }
    }
    else
    {
        return 0;
    }
}

enum mmwlan_status umac_datapath_tx_frame(struct umac_data *umacd,
                                          struct mmpkt *txbuf,
                                          enum umac_datapath_frame_encryption enc,
                                          const uint8_t *ra)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    enum mmwlan_status status = MMWLAN_ERROR;
    struct mmpktview *txbufview = mmpkt_open(txbuf);
    const struct umac_8023_hdr *header_8023 =
        (const struct umac_8023_hdr *)mmpkt_get_data_start(txbufview);

    if (mmpkt_get_data_length(txbufview) < sizeof(*header_8023))
    {
        MMLOG_WRN("Tx len is too small %lu\n", mmpkt_get_data_length(txbufview));
        status = MMWLAN_ERROR;
        goto exit;
    }

    MMOSAL_DEV_ASSERT(data->ops != NULL);
    struct umac_sta_data *stad = NULL;
    const char *addr_type;
    const uint8_t *addr;
    if (ra == NULL)
    {
        stad = data->ops->lookup_stad_by_tx_dest_addr(umacd, header_8023->dest_addr);
        addr_type = "DA";
        addr = header_8023->dest_addr;
    }
    else
    {
        stad = data->ops->lookup_stad_by_peer_addr(umacd, ra);
        addr_type = "RA";
        addr = ra;
    }

    if (stad == NULL)
    {
        MMLOG_WRN("No STA record for %s " MM_MAC_ADDR_FMT "\n", addr_type, MM_MAC_ADDR_VAL(addr));
        status = MMWLAN_NOT_FOUND;
        goto exit;
    }

	const uint16_t ethertype = be16toh(header_8023->ethertype_be);
	const bool is_eapol = (ethertype == ETHERTYPE_EAPOL);
	const bool is_mesh_multicast = data->mesh_mode && mm_mac_addr_is_multicast(header_8023->dest_addr);
	if (enc == ENCRYPTION_DISABLED && !is_eapol)
	{
		MMLOG_WRN(
            "Dropping request to TX non-EAPOL frame with encryption disabled (ethertype=0x%04x)\n",
            ethertype);
        status = MMWLAN_INVALID_ARGUMENT;
        goto exit;
    }

	struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(txbuf);
	tx_metadata->enc = is_eapol ? enc : ENCRYPTION_ENABLED;

	if ((is_eapol && !data->ops->is_stad_tx_paused(stad)) || is_mesh_multicast)
	{
		if (is_mesh_multicast)
		{
			printf("[dp_mesh_tx] immediate multicast ethertype=0x%04x\n", ethertype);
		}

		return umac_datapath_process_tx_frame(umacd, stad, txbufview);
	}

    mmpkt_close(&txbufview);

    data->ops->enqueue_tx_frame(umacd, stad, txbuf);
    MMLOG_DBG("Queued frame for TX (%p, ethertype=0x%04x, enc=0x%x)\n", txbuf, ethertype, enc);
    umac_core_evt_wake(umacd);
    return MMWLAN_SUCCESS;

exit:
    mmpkt_close(&txbufview);
    mmpkt_release(txbuf);
    return status;
}


static inline bool umac_datapath_process_tx(struct umac_data *umacd,
                                            struct umac_datapath_data *data)
{
    if (data->ops == NULL)
    {
        MMLOG_DBG("No datapath ops loaded, skipping TX work.\n");
        return false;
    }
    bool has_more = false;
    for (unsigned ii = 0; ii < MAX_TX_PROCESS_PER_LOOP; ii++)
    {

        if (umac_datapath_tx_is_paused(data, ~MMDRV_PAUSE_SOURCE_MASK_PKTMEM))
        {
            dp_mesh_dbg("[dp_tx] dequeue BLOCKED tx_paused=0x%04x\n", data->tx_paused);
            MMLOG_DBG("TX datapath blocked.\n");
            return false;
        }

        struct mmpkt *mmpkt = NULL;
        struct umac_sta_data *stad = NULL;
        has_more = data->ops->dequeue_tx_frame(umacd, &stad, &mmpkt);

        if (mmpkt == NULL)
        {
            return false;
        }
        MMOSAL_ASSERT(stad != NULL);
        DATAPATH_TRACE("tx deq %x", (uint32_t)mmpkt);

        const struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(mmpkt);

        MMLOG_VRB("TX dequeue %p for AID %u, VIF %u\n",
                  mmpkt,
                  umac_sta_data_get_aid(stad),
                  tx_metadata->vif_id);

        umac_datapath_process_tx_frame(umacd, stad, mmpkt_open(mmpkt));
    }
    return has_more;
}

static void umac_datapath_flush_txq(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    bool more = true;
    do {

        more = umac_datapath_process_tx(umacd, data);
    } while (more);

    umac_stats_clear_datapath_txq_high_water_mark(umacd);
    umac_stats_clear_datapath_txq_frames_dropped(umacd);
}

enum mmwlan_status umac_datapath_tx_mgmt_frame(struct umac_sta_data *stad, struct mmpkt *txbuf)
{
    enum mmwlan_status status;
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);
    struct mmpktview *txbufview = mmpkt_open(txbuf);
    struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(txbufview);
    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(txbuf);
    uint32_t timeout_ms;
    uint16_t pause_mask;

    uint8_t seq_num_space = MMDRV_SEQ_NUM_BASELINE;

    MMOSAL_DEV_ASSERT(stad != NULL);

    bool is_probe_request =
        (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_MGMT) &&
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_PROBE_REQ);
    bool is_authentication =
        (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_MGMT) &&
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_AUTH);
    bool is_mesh_action =
        (dot11_frame_control_get_type(header->frame_control) == DOT11_FC_TYPE_MGMT) &&
        (dot11_frame_control_get_subtype(header->frame_control) == DOT11_FC_SUBTYPE_ACTION);
    DOT11_SEQUENCE_CONTROL_SET_SEQUENCE_NUMBER(header->sequence_control,
                                               sta_data->tx_seq_num_spaces[seq_num_space]++);

    int key_id = -1;
    MMOSAL_DEV_ASSERT(data->ops != NULL);
    if ((data->ops->get_sta_state(stad) == MMWLAN_STA_CONNECTED))
    {

        if (umac_sta_data_pmf_is_required(stad) && frame_is_robust_mgmt(txbufview))
        {
            if (mm_mac_addr_is_multicast(dot11_get_da(header)))
            {
                if (data->mesh_mode)
                {
                    /* Mesh broadcast RMF: use SOFTWARE CCMP with mgmt-frame
                     * AAD format (22 bytes, no QoS/addr4).  HW crypto builds
                     * data-frame AAD even for mgmt frames, causing a mismatch
                     * with the peer's SW mgmt-frame decrypt path.
                     * Allocates a new mmpkt with room for CCMP overhead.
                     * key_id stays -1 so MMDRV_TX_FLAG_HW_ENC is NOT set. */
                    int grp_key_id = umac_keys_get_active_key_id(
                        stad, UMAC_KEY_TYPE_GROUP);
                    if (grp_key_id >= 0)
                    {
                        header->frame_control |=
                            htole16(DOT11_MASK_FC_PROTECTED);
                        struct mmpkt *enc_pkt =
                            mesh_sw_ccmp_encrypt_mgmt(stad, grp_key_id,
                                                      txbufview);
                        if (enc_pkt == NULL)
                        {
                            printf("[dp_mesh] BC RMF dropped: sw encrypt "
                                   "failed\n");
                            mmpkt_close(&txbufview);
                            mmpkt_release(txbuf);
                            return MMWLAN_ERROR;
                        }
                        /* Swap to the new encrypted packet */
                        mmpkt_close(&txbufview);
                        mmpkt_release(txbuf);
                        txbuf = enc_pkt;
                        txbufview = mmpkt_open(txbuf);
                        header = (struct dot11_hdr *)
                            mmpkt_get_data_start(txbufview);
                        tx_metadata = mmdrv_get_tx_metadata(txbuf);
                    }
                    else
                    {
                        printf("[dp_mesh] BC RMF dropped: no group key\n");
                        mmpkt_close(&txbufview);
                        mmpkt_release(txbuf);
                        return MMWLAN_ERROR;
                    }
                }
                else
                {
                    MMLOG_WRN("Unsupported attempt to TX a BC/MC RMF, frame dropped.\n");
                    mmpkt_close(&txbufview);
                    mmpkt_release(txbuf);
                    return MMWLAN_ERROR;
                }
            }
            else
            {
                header->frame_control |= htole16(DOT11_MASK_FC_PROTECTED);
                key_id = umac_keys_get_active_key_id(stad, UMAC_KEY_TYPE_PAIRWISE);
                if (key_id >= 0)
                {
                    umac_keys_increment_tx_seq(stad, key_id);
                }
                else
                {
                    MMLOG_WRN("Dropping frame, no key to encrypt protected management frame\n");
                    mmpkt_close(&txbufview);
                    mmpkt_release(txbuf);
                    return MMWLAN_ERROR;
                }
            }
        }
    }

    tx_metadata->flags = MMDRV_TX_FLAG_IMMEDIATE_REPORT;
    if (key_id >= 0)
    {
        tx_metadata->flags |= MMDRV_TX_FLAG_HW_ENC;
        tx_metadata->key_idx = key_id;
    }

    tx_metadata->tid = MMWLAN_MAX_QOS_TID;
    tx_metadata->aid = umac_sta_data_get_aid(stad);

    umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);


    pause_mask = ~MMDRV_PAUSE_SOURCE_MASK_PKTMEM;
    if (is_authentication)
    {
        /*
         * SAE auth commit must not be starved by scan/standby/etc pauses;
         * only block on pktmem flow control.
         */
        pause_mask = MMDRV_PAUSE_SOURCE_MASK_PKTMEM;
    }
    else if (is_mesh_action)
    {
        /*
         * Mesh peering action frames (OPEN/CONFIRM/CLOSE) follow immediately
         * after SAE auth and must not be blocked by scan/standby pauses.
         * Use the same permissive pause mask as auth frames.
         */
        pause_mask = MMDRV_PAUSE_SOURCE_MASK_PKTMEM;
    }
    else if (is_probe_request)
    {
        pause_mask &= ~UMAC_DATAPATH_PAUSE_SOURCE_SCAN;
    }

    timeout_ms = umac_datapath_calculate_tx_timeout_ms(umacd, true);
    status = umac_datapath_wait_for_tx_ready_(data, timeout_ms, pause_mask);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_WRN("Tx Datapath Blocked (probe=%d auth=%d pause_mask=0x%04x tx_paused=0x%04x)\n",
              is_probe_request,
              is_authentication,
              pause_mask,
              data->tx_paused);
        mmpkt_close(&txbufview);
        mmpkt_release(txbuf);
        umac_stats_increment_datapath_txq_frames_dropped(umacd);
        return status;
    }

    umac_stats_update_last_tx_time(umacd);

    /* Diagnostic: hex dump action and auth frames before they go to firmware */
    {
        struct mmpktview *diag_view = mmpkt_open(txbuf);
        const uint8_t *frame_data = (const uint8_t *)mmpkt_get_data_start(diag_view);
        size_t frame_len = mmpkt_get_data_length(diag_view);
        const struct dot11_hdr *diag_hdr = (const struct dot11_hdr *)frame_data;
        uint8_t subtype = dot11_frame_control_get_subtype(diag_hdr->frame_control);

        if (subtype == DOT11_FC_SUBTYPE_ACTION || subtype == DOT11_FC_SUBTYPE_AUTH)
        {
            const char *type_str = (subtype == DOT11_FC_SUBTYPE_ACTION) ? "ACTION" : "AUTH";
            mac_mgmt_tx_count++;
            printk("[MAC_MGMT] TX count=%lu kind=%s subtype=0x%x fc=0x%04x len=%u "
                   "da=" MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                   (unsigned long)mac_mgmt_tx_count,
                   type_str,
                   (unsigned)subtype,
                   (unsigned)le16toh(diag_hdr->frame_control),
                   (unsigned)frame_len,
                   MM_MAC_ADDR_VAL(diag_hdr->addr1),
                   MM_MAC_ADDR_VAL(diag_hdr->addr2),
                   MM_MAC_ADDR_VAL(diag_hdr->addr3));
            dp_mesh_dbg("[frame_diag] TX_%s: fc=0x%04x len=%u da=%02x:%02x:%02x:%02x:%02x:%02x"
                   " sa=%02x:%02x:%02x:%02x:%02x:%02x bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   type_str,
                   (unsigned)le16toh(diag_hdr->frame_control),
                   (unsigned)frame_len,
                   diag_hdr->addr1[0], diag_hdr->addr1[1], diag_hdr->addr1[2],
                   diag_hdr->addr1[3], diag_hdr->addr1[4], diag_hdr->addr1[5],
                   diag_hdr->addr2[0], diag_hdr->addr2[1], diag_hdr->addr2[2],
                   diag_hdr->addr2[3], diag_hdr->addr2[4], diag_hdr->addr2[5],
                   diag_hdr->addr3[0], diag_hdr->addr3[1], diag_hdr->addr3[2],
                   diag_hdr->addr3[3], diag_hdr->addr3[4], diag_hdr->addr3[5]);

            /* hex dump full frame (up to 300 bytes) for test_openwrt_rx_compat.py */
            size_t dump_len = frame_len < 300 ? frame_len : 300;
            dp_mesh_dbg("[frame_diag] hex: ");
            for (size_t i = 0; i < dump_len; i++)
                dp_mesh_dbg("%02x ", frame_data[i]);
            if (frame_len > dump_len)
                dp_mesh_dbg("...(+%u)", (unsigned)(frame_len - dump_len));
            dp_mesh_dbg("\n");

            /* Also dump IEs separately for quick inspection */
            if (subtype == DOT11_FC_SUBTYPE_ACTION && frame_len > 28)
            {
                /* action frame: hdr(24) + cat(1) + action(1) + cap(2) = 28 */
                uint8_t act_code = frame_data[25];
                size_t ie_start = 28 + (act_code == 2 ? 2 : 0); /* +2 AID for CONFIRM */
                if (ie_start < frame_len)
                {
                    dp_mesh_dbg("[frame_diag] TX_%s_IES(offset=%u): ", type_str, (unsigned)ie_start);
                    size_t ie_pos = ie_start;
                    while (ie_pos + 1 < frame_len)
                    {
                        uint8_t eid = frame_data[ie_pos];
                        uint8_t elen = frame_data[ie_pos + 1];
                        dp_mesh_dbg("eid=%u,len=%u ", eid, elen);
                        if (ie_pos + 2 + elen > frame_len) { dp_mesh_dbg("[TRUNCATED]"); break; }
                        ie_pos += 2 + elen;
                    }
                    dp_mesh_dbg("\n");
                }
            }
        }
        mmpkt_close(&diag_view);
    }

    mmpkt_close(&txbufview);
    if (mmdrv_tx_frame(txbuf, true) < 0)
    {
        return MMWLAN_ERROR;
    }

    return MMWLAN_SUCCESS;
}

void umac_datapath_handle_tx_status(struct umac_data *umacd, struct mmpkt *mmpkt)
{
    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(mmpkt);
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    if (tx_metadata->attempts != 0)
    {
        MMOSAL_TASK_ENTER_CRITICAL();
        mmpkt_list_append(&data->tx_status_q, mmpkt);
        MMOSAL_TASK_EXIT_CRITICAL();
        umac_core_evt_wake(umacd);
    }
    else
    {
        mmpkt_release(mmpkt);
    }
    DATAPATH_TRACE("tx_status q %x", (uint32_t)mmpkt);
}


static inline void umac_datapath_process_tx_status_queue(struct umac_data *umacd,
                                                         struct umac_datapath_data *data)
{
    struct mmpkt *mmpkt;
    MMOSAL_TASK_ENTER_CRITICAL();
    mmpkt = mmpkt_list_dequeue_all(&data->tx_status_q);
    MMOSAL_TASK_EXIT_CRITICAL();

    struct mmpkt *next = NULL;
    for (; mmpkt != NULL; mmpkt = next)
    {
        next = mmpkt_get_next(mmpkt);

        DATAPATH_TRACE("tx_status deq %x", (uint32_t)mmpkt);

        struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(mmpkt);


        struct umac_sta_data *stad = data->ops->lookup_stad_by_aid(umacd, tx_metadata->aid);
        if (stad != NULL)
        {
            bool frame_acked = (tx_metadata->status_flags & MMDRV_TX_STATUS_FLAG_NO_ACK) == 0;
            bool valid_ack_status =
                !(tx_metadata->status_flags &
                  (MMDRV_TX_STATUS_FLAG_PS_FILTERED | MMDRV_TX_STATUS_DUTY_CYCLE_CANT_SEND));

            struct mmpktview *tx_view = mmpkt_open(mmpkt);
            if (tx_view != NULL)
            {
                struct dot11_hdr *hdr = (struct dot11_hdr *)mmpkt_get_data_start(tx_view);
                if (hdr != NULL &&
                    dot11_frame_control_get_type(hdr->frame_control) == DOT11_FC_TYPE_MGMT &&
                    dot11_frame_control_get_subtype(hdr->frame_control) == DOT11_FC_SUBTYPE_AUTH)
                {
                          MESH_DBG_PRINTF("[mesh_trace] MESH_AUTH_TX_STATUS_DP: ack=%u valid=%u flags=0x%02x da=" MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                              frame_acked ? 1U : 0U,
                              valid_ack_status ? 1U : 0U,
                              tx_metadata->status_flags,
                              MM_MAC_ADDR_VAL(dot11_get_da(hdr)),
                              MM_MAC_ADDR_VAL(dot11_get_sa(hdr)),
                              MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(hdr)));
                }
                if (hdr != NULL &&
                    dot11_frame_control_get_type(hdr->frame_control) == DOT11_FC_TYPE_MGMT &&
                    dot11_frame_control_get_subtype(hdr->frame_control) == DOT11_FC_SUBTYPE_ACTION)
                {
                    /* Report TX status for action frames (mesh peering OPEN/CONFIRM/CLOSE) */
                    const uint8_t *body = (const uint8_t *)(hdr + 1);
                    size_t body_len = mmpkt_get_data_length(tx_view);
                    uint8_t cat = (body_len > sizeof(*hdr)) ? body[0] : 0xFF;
                    uint8_t act = (body_len > sizeof(*hdr) + 1) ? body[1] : 0xFF;
                    MESH_DBG_PRINTF("[mesh_trace] MESH_ACTION_TX_STATUS_DP: ack=%u valid=%u flags=0x%02x cat=%u action=%u da=" MM_MAC_ADDR_FMT " sa=" MM_MAC_ADDR_FMT " bssid=" MM_MAC_ADDR_FMT "\n",
                           frame_acked ? 1U : 0U,
                           valid_ack_status ? 1U : 0U,
                           tx_metadata->status_flags,
                           cat, act,
                           MM_MAC_ADDR_VAL(dot11_get_da(hdr)),
                           MM_MAC_ADDR_VAL(dot11_get_sa(hdr)),
                           MM_MAC_ADDR_VAL(dot11_mgmt_get_bssid(hdr)));
                }
                /* Log TX status for data frames in mesh mode */
                if (hdr != NULL &&
                    dot11_frame_control_get_type(hdr->frame_control) == DOT11_FC_TYPE_DATA &&
                    data->mesh_mode)
                {
                    dp_mesh_dbg("[dp_mesh] tx_status: ack=%u flags=0x%02x attempts=%u fc=0x%04x\n",
                           frame_acked ? 1U : 0U,
                           tx_metadata->status_flags,
                           tx_metadata->attempts,
                           le16toh(hdr->frame_control));
                }
                mmpkt_close(&tx_view);
            }

            MMLOG_VRB("TX status (0x%02x) indicates %s.\n",
                      tx_metadata->status_flags,
                      valid_ack_status ? (frame_acked ? "acked" : "unacked") : "unsent");

            if (tx_metadata->aid != 0)
            {
                umac_rc_feedback(stad, tx_metadata);
            }

            if (valid_ack_status)
            {
                umac_connection_handle_ack_status(mmpkt, umacd, frame_acked);
            }


            umac_supp_tx_status(umacd, mmpkt, (valid_ack_status ? frame_acked : false));

            if (tx_metadata->status_flags & MMDRV_TX_STATUS_FLAGS_FAIL_MASK)
            {
                MMLOG_WRN("TX status indicates failure with flags 0x%02x\n",
                          tx_metadata->status_flags & MMDRV_TX_STATUS_FLAGS_FAIL_MASK);
            }
        }
        else
        {
            MMLOG_INF("No STA data - link down\n");
        }

        mmpkt_release(mmpkt);
    }
}

static struct mmpkt *umac_datapath_build_3addr_to_ds_qos_null(struct umac_sta_data *stad)
{
    struct consbuf cbuf = CONSBUF_INIT_WITHOUT_BUF;
    consbuf_reserve(&cbuf, sizeof(struct dot11_hdr));
    consbuf_reserve(&cbuf, sizeof(struct dot11_qos_ctrl));

    struct mmpkt *mmpkt =
        umac_datapath_alloc_raw_tx_mmpkt(MMDRV_PKT_CLASS_DATA_TID7, 0, cbuf.offset);
    if (mmpkt == NULL)
    {
        MMLOG_INF("Failed to allocate mgmt frame (len %lu)\n", cbuf.offset);
        return NULL;
    }
    struct mmpktview *view = mmpkt_open(mmpkt);
    consbuf_reinit_from_mmpkt(&cbuf, view);

    struct dot11_hdr *header = (struct dot11_hdr *)consbuf_reserve(&cbuf, sizeof(struct dot11_hdr));
    memset(header, 0, sizeof(*header));
    umac_sta_data_get_bssid(stad, header->addr1);
    umac_interface_get_mac_addr(stad, header->addr2);
    umac_sta_data_get_bssid(stad, header->addr3);
    header->frame_control = htole16(DOT11_MASK_FC_TO_DS |
                                    (DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE) |
                                    (DOT11_FC_SUBTYPE_QOS_NULL << DOT11_SHIFT_FC_SUBTYPE));

    struct dot11_qos_ctrl *qos_ctrl =
        (struct dot11_qos_ctrl *)consbuf_reserve(&cbuf, sizeof(struct dot11_qos_ctrl));
    qos_ctrl->field = (DOT11_MASK_QC_TID & MMWLAN_MAX_QOS_TID);

    uint8_t *ret = mmpkt_append(view, cbuf.offset);
    MMOSAL_ASSERT(ret != NULL);

    mmpkt_close(&view);

    return mmpkt;
}

static struct mmpkt *umac_datapath_build_4addr_qos_null(struct umac_sta_data *stad)
{
    struct consbuf cbuf = CONSBUF_INIT_WITHOUT_BUF;
    consbuf_reserve(&cbuf, sizeof(struct dot11_data_hdr));
    consbuf_reserve(&cbuf, sizeof(struct dot11_qos_ctrl));

    struct mmpkt *mmpkt =
        umac_datapath_alloc_raw_tx_mmpkt(MMDRV_PKT_CLASS_DATA_TID7, 0, cbuf.offset);
    if (mmpkt == NULL)
    {
        MMLOG_INF("Failed to allocate mgmt frame (len %lu)\n", cbuf.offset);
        return NULL;
    }
    struct mmpktview *view = mmpkt_open(mmpkt);
    consbuf_reinit_from_mmpkt(&cbuf, view);

    struct dot11_data_hdr *header =
        (struct dot11_data_hdr *)consbuf_reserve(&cbuf, sizeof(struct dot11_data_hdr));
    memset(header, 0, sizeof(*header));
    umac_sta_data_get_peer_addr(stad, header->base.addr1);
    umac_interface_get_mac_addr(stad, header->base.addr2);
    umac_sta_data_get_peer_addr(stad, header->base.addr3);
    umac_interface_get_mac_addr(stad, header->addr4);
    header->base.frame_control = htole16(DOT11_MASK_FC_TO_DS |
                                         DOT11_MASK_FC_FROM_DS |
                                         (DOT11_FC_TYPE_DATA << DOT11_SHIFT_FC_TYPE) |
                                         (DOT11_FC_SUBTYPE_QOS_NULL << DOT11_SHIFT_FC_SUBTYPE));

    struct dot11_qos_ctrl *qos_ctrl =
        (struct dot11_qos_ctrl *)consbuf_reserve(&cbuf, sizeof(struct dot11_qos_ctrl));
    qos_ctrl->field = (DOT11_MASK_QC_TID & MMWLAN_MAX_QOS_TID);

    uint8_t *ret = mmpkt_append(view, cbuf.offset);
    MMOSAL_ASSERT(ret != NULL);

    mmpkt_close(&view);

    return mmpkt;
}

static enum mmwlan_status umac_datapath_tx_qos_null_frame(struct umac_data *umacd,
                                                          struct umac_sta_data *stad,
                                                          struct mmpkt *mmpkt)
{
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);
    struct mmpktview *view = mmpkt_open(mmpkt);
    struct dot11_hdr *header = (struct dot11_hdr *)mmpkt_get_data_start(view);


    DOT11_SEQUENCE_CONTROL_SET_SEQUENCE_NUMBER(
        header->sequence_control,
        sta_data->tx_seq_num_spaces[MMDRV_SEQ_NUM_QOS_NULL]++);


    struct mmdrv_tx_metadata *tx_metadata = mmdrv_get_tx_metadata(mmpkt);
    tx_metadata->flags = MMDRV_TX_FLAG_IMMEDIATE_REPORT;
    tx_metadata->tid = MMWLAN_MAX_QOS_TID;
    tx_metadata->aid = umac_sta_data_get_aid(stad);

    umac_rc_init_rate_table_mgmt(umacd, &tx_metadata->rc_data, false);

    umac_stats_update_last_tx_time(umacd);

    mmpkt_close(&view);
    if (mmdrv_tx_frame(mmpkt, false))
    {
        return MMWLAN_ERROR;
    }

    return MMWLAN_SUCCESS;
}

enum mmwlan_status umac_datapath_build_and_tx_to_ds_qos_null_frame(struct umac_sta_data *stad)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);


    uint32_t timeout_ms = umac_datapath_calculate_tx_timeout_ms(umacd, true);
    enum mmwlan_status status = umac_datapath_wait_for_tx_ready_(data, timeout_ms, UINT16_MAX);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_DBG("TX datapath blocked.\n");
        umac_stats_increment_datapath_txq_frames_dropped(umacd);
        return status;
    }

    struct mmpkt *mmpkt = umac_datapath_build_3addr_to_ds_qos_null(stad);
    if (mmpkt == NULL)
    {
        return MMWLAN_ERROR;
    }
    return umac_datapath_tx_qos_null_frame(umacd, stad, mmpkt);
}

enum mmwlan_status umac_datapath_build_and_tx_4addr_qos_null_frame(struct umac_sta_data *stad)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);


    uint32_t timeout_ms = umac_datapath_calculate_tx_timeout_ms(umacd, true);
    enum mmwlan_status status = umac_datapath_wait_for_tx_ready_(data, timeout_ms, UINT16_MAX);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_DBG("TX datapath blocked.\n");
        umac_stats_increment_datapath_txq_frames_dropped(umacd);
        return status;
    }

    struct mmpkt *mmpkt = umac_datapath_build_4addr_qos_null(stad);
    if (mmpkt == NULL)
    {
        return MMWLAN_ERROR;
    }
    return umac_datapath_tx_qos_null_frame(umacd, stad, mmpkt);
}

enum mmwlan_status umac_datapath_build_and_tx_mgmt_frame(struct umac_sta_data *stad,
                                                         mgmt_frame_builder_t builder,
                                                         void *params)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct mmpkt *txbuf = build_mgmt_frame(umacd, builder, params);
    if (txbuf == NULL)
    {
        return MMWLAN_NO_MEM;
    }

    return umac_datapath_tx_mgmt_frame(stad, txbuf);
}

enum mmwlan_status umac_datapath_build_copy_and_queue_mgmt_frame_tx(struct umac_sta_data *stad,
                                                                    mgmt_frame_builder_t builder,
                                                                    void *params,
                                                                    struct mmpkt **copy)
{
    struct umac_data *umacd = umac_sta_data_get_umacd(stad);
    struct mmpkt *txbuf = build_mgmt_frame(umacd, builder, params);
    if (txbuf == NULL)
    {
        return MMWLAN_NO_MEM;
    }

    *copy = umac_datapath_copy_tx_mmpkt(txbuf, MMDRV_PKT_CLASS_MGMT);
    if (*copy == NULL)
    {
        mmpkt_release(txbuf);
        return MMWLAN_NO_MEM;
    }

    return umac_datapath_tx_mgmt_frame(stad, txbuf);
}


#ifndef UNIT_TESTS
bool umac_datapath_process(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    umac_datapath_process_tx_status_queue(umacd, data);
    bool more_rx = umac_datapath_process_rx(umacd, data);
    bool more_tx = umac_datapath_process_tx(umacd, data);

#if MESH_PREQ_INTERVAL_MS > 0
    /* Periodic HWMP PREQ broadcast for mesh visibility */
    if (data->mesh_mode)
    {
        uint32_t now = mmosal_get_time_ms();
        if ((now - data->hwmp_preq_last_ms) >= MESH_PREQ_INTERVAL_MS)
        {
            data->hwmp_preq_last_ms = now;
            umac_datapath_tx_hwmp_preq(umacd);
        }
    }
#endif

    return more_rx || more_tx;
}

#else
bool umac_datapath_process(struct umac_data *umacd)
{
    MM_UNUSED(umacd);
    return false;
}

#endif

static bool umac_datapath_pause_protected(struct umac_datapath_data *data, uint16_t source_mask)
{
    uint16_t old_pause = data->tx_paused;
    data->tx_paused |= source_mask;
    return old_pause == 0;
}

static bool umac_datapath_unpause_protected(struct umac_datapath_data *data, uint16_t source_mask)
{
    uint16_t old_pause = data->tx_paused;
    data->tx_paused &= ~(source_mask);
    return old_pause != 0 && data->tx_paused == 0;
}

static const char *umac_datapath_pause_source_name(uint16_t source_mask)
{
    switch (source_mask)
    {
        case MMDRV_PAUSE_SOURCE_MASK_PKTMEM:
            return "pktmem";
        case MMDRV_PAUSE_SOURCE_MASK_TRAFFIC_CTRL:
            return "traffic_ctrl";
        case MMDRV_PAUSE_SOURCE_MASK_HW_RESTART:
            return "hw_restart";
        case UMAC_DATAPATH_PAUSE_SOURCE_SCAN:
            return "scan";
        case UMAC_DATAPATH_PAUSE_SOURCE_WNM_SLEEP:
            return "wnm_sleep";
        case UMAC_DATAPATH_PAUSE_SOURCE_STANDBY:
            return "standby";
        case UMAC_DATAPATH_PAUSE_SOURCE_ECSA:
            return "ecsa";
        default:
            return "mixed_or_unknown";
    }
}

static void umac_datapath_invoke_tx_fc_callback_handler(struct umac_data *umacd,
                                                        const struct umac_evt *evt)
{
    MM_UNUSED(evt);

    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    if (data->tx_flow_control_callback != NULL)
    {
        data->tx_flow_control_callback(data->tx_paused ? MMWLAN_TX_PAUSED : MMWLAN_TX_READY,
                                       data->tx_flow_control_arg);
    }
}

void umac_datapath_update_tx_paused(struct umac_data *umacd,
                                    uint16_t source_mask,
                                    mmdrv_host_update_tx_paused_cb_t cb)
{
    bool pause_state_changed;
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);


    MMOSAL_TASK_ENTER_CRITICAL();
    bool is_paused = cb();
    if (is_paused)
    {
        pause_state_changed = umac_datapath_pause_protected(data, source_mask);
    }
    else
    {
        pause_state_changed = umac_datapath_unpause_protected(data, source_mask);
    }
    MMOSAL_TASK_EXIT_CRITICAL();

    if (pause_state_changed)
    {
        printf("[dp_tx_flow] %s source=%s source_mask=0x%04x tx_paused=0x%04x\n",
               is_paused ? "paused" : "ready",
               umac_datapath_pause_source_name(source_mask),
               source_mask,
               data->tx_paused);
    }
    else
    {
        MMLOG_DBG("Datapath paused (|= %08x): %d\n", source_mask, data->tx_paused);
    }
    DATAPATH_TRACE("pause %x %x %u", data->tx_paused, source_mask, pause_state_changed);

    if (pause_state_changed && !is_paused)
    {

        umac_core_evt_wake(umacd);
        mmosal_semb_give(data->tx_flowcontrol_sem);
    }

    if (pause_state_changed && data->tx_flow_control_callback != NULL)
    {
        if (umac_core_evtloop_is_active(umacd))
        {
            data->tx_flow_control_callback(is_paused ? MMWLAN_TX_PAUSED : MMWLAN_TX_READY,
                                           data->tx_flow_control_arg);
        }
        else
        {
            bool ok;
            const struct umac_evt evt = UMAC_EVT_INIT(umac_datapath_invoke_tx_fc_callback_handler);

            ok = umac_core_evt_queue(umacd, &evt);
            if (!ok)
            {
                MMLOG_WRN("Failed to queue INVOKE_TX_FC_CALLBACK event\n");
            }
        }
    }
}

static bool return_true(void)
{
    return true;
}

static bool return_false(void)
{
    return false;
}

void umac_datapath_pause(struct umac_data *umacd, uint16_t source_mask)
{
    umac_datapath_update_tx_paused(umacd, source_mask, return_true);
}

void umac_datapath_unpause(struct umac_data *umacd, uint16_t source_mask)
{
    umac_datapath_update_tx_paused(umacd, source_mask, return_false);
}

void umac_datapath_handle_hw_restarted(struct umac_data *umacd, struct umac_sta_data *stad)
{
    struct umac_datapath_sta_data *sta_data = umac_sta_data_get_datapath(stad);

    const uint8_t *peer_addr = umac_sta_data_peek_peer_addr(stad);

    (void)mmdrv_set_seq_num_spaces(umac_interface_get_vif_id(umacd, UMAC_INTERFACE_STA),
                                   sta_data->tx_seq_num_spaces,
                                   peer_addr);
}

enum mmwlan_status umac_datapath_register_rx_frame_cb(struct umac_data *umacd,
                                                      uint32_t filter,
                                                      mmwlan_rx_frame_cb_t callback,
                                                      void *arg)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    data->rx_frame_filter = filter;
    data->rx_frame_cb = callback;
    data->rx_frame_cb_arg = arg;
    return MMWLAN_SUCCESS;
}


static struct umac_sta_data *umac_datapath_lookup_stad_by_peer_addr_sta_mode(
    struct umac_data *umacd,
    const uint8_t *addr)
{
    MMLOG_DBG("Lookup peer " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(addr));

    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if (stad == NULL)
    {
        return NULL;
    }

    if (mm_mac_addr_is_multicast(addr) || umac_sta_data_matches_peer_addr(stad, addr))
    {
        return stad;
    }
    else
    {
        return NULL;
    }
}

static struct umac_sta_data *umac_datapath_lookup_stad_by_tx_dest_addr_sta_mode(
    struct umac_data *umacd,
    const uint8_t *dest_addr)
{
    MMLOG_DBG("Lookup dest addr " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(dest_addr));


    return umac_connection_get_stad(umacd);
}

static struct umac_sta_data *umac_datapath_lookup_stad_by_aid_sta(struct umac_data *umacd,
                                                                  uint16_t aid)
{
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if (stad == NULL)
    {
        return NULL;
    }
    if (umac_sta_data_get_aid(stad) != aid)
    {
        MMLOG_WRN("AID mismatch (%u != %u)\n", umac_sta_data_get_aid(stad), aid);
        return NULL;
    }
    return stad;
}


static enum mmwlan_sta_state umac_datapath_get_state_sta(struct umac_sta_data *stad)
{
    MMOSAL_DEV_ASSERT(stad != NULL);
    return umac_connection_get_state(umac_sta_data_get_umacd(stad));
}

/* Mesh peers only exist after SAE/AMPE key exchange completes, so if
 * we have a stad the controlled port is effectively open. The normal
 * STA connection FSM never reaches CONNECTED for mesh because it
 * skips the AUTH→ASSOC→CONNECTING path. */
static enum mmwlan_sta_state umac_datapath_get_state_mesh(struct umac_sta_data *stad)
{
    if (stad == NULL)
        return MMWLAN_STA_DISABLED;
    return MMWLAN_STA_CONNECTED;
}


const uint16_t frames_allowed_pre_association_sta_mode[] = {
    DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, PROBE_REQ),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, PROBE_RSP),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, ACTION),
    UINT16_MAX,
};

/* A mesh peer must be able to start SAE before it has a UMAC station entry.
 * Keep ordinary STA admission unchanged and additionally allow only AUTH for
 * mesh. Unknown data frames remain blocked.
 */
const uint16_t frames_allowed_pre_association_mesh_mode[] = {
    DOT11_VER_TYPE_SUBTYPE(0, EXT, S1G_BEACON),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, PROBE_REQ),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, PROBE_RSP),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, ACTION),
    DOT11_VER_TYPE_SUBTYPE(0, MGMT, AUTH),
    UINT16_MAX,
};

static bool nullop_set_stad_sleep_state_sta_mode(struct umac_sta_data *stad, bool asleep)
{
    MM_UNUSED(asleep);
    return stad != NULL;
}

static void umac_datapath_tx_queue_frame_sta(struct umac_data *umacd,
                                             struct umac_sta_data *stad,
                                             struct mmpkt *txbuf)
{
    MMOSAL_TASK_ENTER_CRITICAL();
    umac_sta_data_queue_pkt(stad, txbuf);
    umac_stats_update_datapath_txq_high_water_mark(umacd, umac_sta_data_get_queued_len(stad));
    MMOSAL_TASK_EXIT_CRITICAL();
}

static bool umac_datapath_tx_dequeue_frame_sta(struct umac_data *umacd,
                                               struct umac_sta_data **stad_ptr,
                                               struct mmpkt **txbuf_ptr)
{
    MMOSAL_ASSERT(umacd && stad_ptr && txbuf_ptr);
    *stad_ptr = NULL;
    *txbuf_ptr = NULL;

    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    bool has_more = false;

    if (stad == NULL || umac_sta_data_is_paused(stad))
    {
        return false;
    }
    MMOSAL_TASK_ENTER_CRITICAL();
    *txbuf_ptr = umac_sta_data_pop_pkt(stad);
    has_more = umac_sta_data_get_queued_len(stad);
    MMOSAL_TASK_EXIT_CRITICAL();
    if (*txbuf_ptr != NULL)
    {
        *stad_ptr = stad;
    }
    return has_more;
}


static const struct umac_datapath_ops datapath_ops_sta = {
    .process_rx_mgmt_frame = umac_datapath_process_rx_mgmt_frame_sta,
    .lookup_stad_by_peer_addr = umac_datapath_lookup_stad_by_peer_addr_sta_mode,
    .lookup_stad_by_tx_dest_addr = umac_datapath_lookup_stad_by_tx_dest_addr_sta_mode,
    .lookup_stad_by_aid = umac_datapath_lookup_stad_by_aid_sta,
    .set_stad_sleep_state = nullop_set_stad_sleep_state_sta_mode,
    .is_stad_tx_paused = umac_sta_data_is_paused,
    .enqueue_tx_frame = umac_datapath_tx_queue_frame_sta,
    .dequeue_tx_frame = umac_datapath_tx_dequeue_frame_sta,
    .construct_80211_data_header = umac_datapath_construct_80211_data_header_sta,
    .get_sta_state = umac_datapath_get_state_sta,
    .frames_allowed_pre_association = frames_allowed_pre_association_sta_mode,
};

void umac_datapath_configure_sta_mode(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    data->ops = &datapath_ops_sta;
    data->mesh_mode = false;
    MMLOG_INF("Datapath configured for STA mode\n");
}

static const struct umac_datapath_ops datapath_ops_mesh = {
    .process_rx_mgmt_frame = umac_datapath_process_rx_mgmt_frame_sta,
    .lookup_stad_by_peer_addr = umac_datapath_lookup_stad_by_peer_addr_sta_mode,
    .lookup_stad_by_tx_dest_addr = umac_datapath_lookup_stad_by_tx_dest_addr_sta_mode,
    .lookup_stad_by_aid = umac_datapath_lookup_stad_by_aid_sta,
    .set_stad_sleep_state = nullop_set_stad_sleep_state_sta_mode,
    .is_stad_tx_paused = umac_sta_data_is_paused,
    .enqueue_tx_frame = umac_datapath_tx_queue_frame_sta,
    .dequeue_tx_frame = umac_datapath_tx_dequeue_frame_sta,
    .construct_80211_data_header = umac_datapath_construct_80211_data_header_mesh,
    .get_sta_state = umac_datapath_get_state_mesh,
    .frames_allowed_pre_association = frames_allowed_pre_association_mesh_mode,
};

void umac_datapath_configure_mesh_mode(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);
    data->ops = &datapath_ops_mesh;
    data->mesh_mode = true;
    data->mesh_seq_num = 0;
    data->hwmp_preq_last_ms = 0;
    data->hwmp_preq_id = 0;
    dp_mesh_dbg("[dp_mesh] Datapath configured for MESH mode (preq_interval=%d ms)\n",
           MESH_PREQ_INTERVAL_MS);
    MMLOG_INF("Datapath configured for mesh mode\n");
}

void umac_datapath_configure_scan_mode(struct umac_data *umacd)
{
    struct umac_datapath_data *data = umac_data_get_datapath(umacd);

    if (data->ops == NULL)
    {
        data->ops = &datapath_ops_sta;
    }
}
