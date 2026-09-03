/*
 * Copyright 2021-2025 Morse Micro
 * SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-MorseMicroCommercial
 */
#include "mmlog.h"
#include "mmosal.h"
#include "mmutils.h"
#include "mmwlan.h"
#include "umac/regdb/umac_regdb.h"
#include "umac_supp_shim_private.h"

#include "common/common.h"
#include "common/consbuf.h"
#include "common/ieee802_11_defs.h"
#include "common/mac_address.h"
#include "common/ieee802_11_common.h"
#include "bss.h"
#include "mesh.h"
#include "mesh_mpm.h"
#include "dot11/dot11.h"
#include "umac/data/umac_data.h"
#include "umac/config/umac_config.h"
#include "umac/core/umac_core.h"
#include "umac/datapath/umac_datapath.h"
#include "umac/ps/umac_ps.h"
#include "umac/scan/umac_scan.h"
#include "umac/interface/umac_interface.h"
#include "umac/connection/umac_connection.h"
#include "umac/ap/umac_ap.h"
#include "umac/frames/association.h"
#include "umac/frames/authentication.h"
#include "umac/frames/deauthentication.h"
#include "umac/frames/action.h"
#include "umac/ies/s1g_operation.h"
#include "umac/ies/ssid.h"
#include "umac/interface/umac_interface.h"
#include "umac/stats/umac_stats.h"
#include "umac/wnm_sleep/umac_wnm_sleep.h"
#include "umac/ies/s1g_capabilities.h"

/* Mesh debug trace gate – controlled by CONFIG_MM_MESH_DEBUG_LOG in menuconfig */
#ifndef MESH_DBG_PRINTF
#ifdef CONFIG_MM_MESH_DEBUG_LOG
#define MESH_DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define MESH_DBG_PRINTF(...) do {} while(0)
#endif
#endif


#define HZ_TO_KHZ(x) ((x) / 1000)

#define KHZ_TO_HZ(x) ((x) * 1000)


#define DEV_ASSERT_IN_S1G_RANGE(x) MMOSAL_DEV_ASSERT((x) > 800000)


static enum mmwlan_pmf_mode translate_supp_to_mmwlan_pmf_mode(enum mfp_options mfp_option)
{
    switch (mfp_option)
    {
        case NO_MGMT_FRAME_PROTECTION:
            return MMWLAN_PMF_DISABLED;

        case MGMT_FRAME_PROTECTION_OPTIONAL:
        case MGMT_FRAME_PROTECTION_REQUIRED:
            return MMWLAN_PMF_REQUIRED;

        default:
            MMOSAL_ASSERT(false);
    }


    MMOSAL_ASSERT(false);
    return MMWLAN_PMF_REQUIRED;
}


static enum mmwlan_security_type translate_supp_to_mmwlan_security(unsigned int key_mgmt_suite)
{
    MMLOG_DBG("Key Management 0x%x\n", key_mgmt_suite);

    if (key_mgmt_suite == 0 || (key_mgmt_suite & (key_mgmt_suite - 1)) != 0)
    {
        MMLOG_WRN("Invalid or multiple key_mgmt bits set: 0x%x\n", key_mgmt_suite);
        MMOSAL_DEV_ASSERT(false);
    }

    if (key_mgmt_suite & WPA_KEY_MGMT_SAE)
    {
        return MMWLAN_SAE;
    }
    else if (key_mgmt_suite & WPA_KEY_MGMT_OWE)
    {
        return MMWLAN_OWE;
    }
    else if (key_mgmt_suite & WPA_KEY_MGMT_NONE)
    {
        return MMWLAN_OPEN;
    }

    MMLOG_WRN("Unsupport key_mgmt_suite 0x%x\n", key_mgmt_suite);
    MMOSAL_ASSERT(false);

    return MMWLAN_SAE;
}

static enum morse_sta_state wpa_sta_flags_to_sta_state(uint32_t flags)
{
    if (flags & WPA_STA_AUTHORIZED)
    {
        return MORSE_STA_AUTHORIZED;
    }
    if (flags & WPA_STA_ASSOCIATED)
    {
        return MORSE_STA_ASSOCIATED;
    }
    if (flags & WPA_STA_AUTHENTICATED)
    {
        return MORSE_STA_AUTHENTICATED;
    }
    return MORSE_STA_NONE;
}

static int mmwpas_sta_add(void *priv, struct hostapd_sta_add_params *params)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    uint16_t vif_id = umac_interface_get_vif_id(umacd, UMAC_INTERFACE_MESH);
    enum morse_sta_state sta_state = wpa_sta_flags_to_sta_state(params->flags);
    int ret;

    if (vif_id == UMAC_INTERFACE_VIF_ID_INVALID)
    {
        vif_id = umac_interface_get_vif_id(umacd, UMAC_INTERFACE_STA);
    }

    if (vif_id == UMAC_INTERFACE_VIF_ID_INVALID)
    {
        MMLOG_WRN("Mesh/STA add peer: no active mesh/sta vif for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(params->addr));
        return -1;
    }

    MMLOG_INF("Mesh/STA add peer " MM_MAC_ADDR_FMT ": aid=%u flags=%08lx flags_mask=%08lx\n",
              MM_MAC_ADDR_VAL(params->addr),
              params->aid,
              params->flags,
              params->flags_mask);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_sta_add: vif_id=%u peer=%02x:%02x:%02x:%02x:%02x:%02x aid=%u flags=0x%lx\n",
            (unsigned)vif_id,
            params->addr[0], params->addr[1], params->addr[2],
            params->addr[3], params->addr[4], params->addr[5],
            (unsigned)params->aid,
            params->flags);

    ret = mmdrv_update_sta_state(vif_id, params->aid, params->addr, sta_state);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_sta_add: mmdrv_update_sta_state ret=%d state=%u\n",
            ret,
            (unsigned)sta_state);
    return ret == 0 ? 0 : -1;
}

static int mmwpas_sta_remove(void *priv, const u8 *addr)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    uint16_t vif_id = umac_interface_get_vif_id(umacd, UMAC_INTERFACE_MESH);
    int ret;

    if (vif_id == UMAC_INTERFACE_VIF_ID_INVALID)
    {
        vif_id = umac_interface_get_vif_id(umacd, UMAC_INTERFACE_STA);
    }

    if (vif_id == UMAC_INTERFACE_VIF_ID_INVALID)
    {
        MMLOG_WRN("Mesh/STA remove peer: no active mesh/sta vif for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(addr));
        return -1;
    }

    MMLOG_INF("Mesh/STA remove peer " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(addr));
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_sta_remove: vif_id=%u peer=%02x:%02x:%02x:%02x:%02x:%02x\n",
           (unsigned)vif_id,
           addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    ret = mmdrv_update_sta_state(vif_id, 0, addr, MORSE_STA_NONE);
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_sta_remove: mmdrv_update_sta_state ret=%d\n", ret);
    return ret == 0 ? 0 : -1;
}

static void *mmwpas_init(void *ctx, const char *ifname)
{
    MM_UNUSED(ifname);
    struct umac_data *umacd = umac_data_get_umacd();
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    data->sta_driver_ctx = ctx;

    return umacd;
}

static void mmwpas_deinit(void *priv)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);

    mmosal_free(data->bss_cache);
    data->bss_cache = NULL;

    data->sta_driver_ctx = NULL;
}

static int mmwpas_get_capa(void *priv, struct wpa_driver_capa *capa)
{
    MM_UNUSED(priv);
    memset(capa, 0x0, sizeof(*capa));


    static const uint8_t extended_capa[] = {
        DOT11_MASK_S1G_EXT_CAP0_ECSA_SUPPORTED,
    };

    static const uint8_t extended_capa_mask[] = {
        DOT11_MASK_S1G_EXT_CAP0_ECSA_SUPPORTED,
    };

    capa->extended_capa = extended_capa;
    capa->extended_capa_mask = extended_capa_mask;
    capa->extended_capa_len = sizeof(extended_capa);
    MM_STATIC_ASSERT(sizeof(extended_capa) == sizeof(extended_capa_mask),
                     "extended_capa vs extended_capa_mask size mismatch");

    capa->flags = WPA_DRIVER_FLAGS_SME |
              WPA_DRIVER_FLAGS_SAE |
              WPA_DRIVER_FLAGS_MESH;
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_get_capa flags=0x%llx (mesh=%u sme=%u sae=%u)\n",
           (unsigned long long)capa->flags,
           (capa->flags & WPA_DRIVER_FLAGS_MESH) ? 1U : 0U,
           (capa->flags & WPA_DRIVER_FLAGS_SME) ? 1U : 0U,
           (capa->flags & WPA_DRIVER_FLAGS_SAE) ? 1U : 0U);
    return 0;
}

static const u8 *mmwpas_get_mac_addr(void *priv)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    const u8 *mac_addr;


    if (umac_interface_borrow_vif_mac_addr(umacd, MMWLAN_VIF_STA, &mac_addr) != MMWLAN_SUCCESS)
    {
        return mac_addr_zero;
    }

    return mac_addr;
}


struct mmwpas_minsnr_bitrate_entry
{
    int32_t minsnr;
    uint32_t bitrate;
};


static const struct mmwpas_minsnr_bitrate_entry mmwpas_s1g8mhz_table[] = {
    { 3, 2925 },
    { 5, 5850 },
    { 7, 8775 },
    { 10, 11700 },
    { 13, 17550 },
    { 18, 23400 },
    { 19, 26325 },
    { 21, 29250 },
    { 26, 35100 },
    { 27, 39000 },
    { -1, 39000 }
};

static uint32_t mmwpas_interpolate_rate(int32_t snr,
                                        int32_t snr0,
                                        int32_t snr1,
                                        int32_t rate0,
                                        int32_t rate1)
{
    return rate0 + (snr - snr0) * (rate1 - rate0) / (snr1 - snr0);
}


static int32_t mmwpas_max_s1g_bitrate(int32_t snr)
{
    const struct mmwpas_minsnr_bitrate_entry *prev, *entry = mmwpas_s1g8mhz_table;

    while ((entry->minsnr != -1) && (snr >= entry->minsnr))
    {
        entry++;
    }
    if (entry == mmwpas_s1g8mhz_table)
    {
        return entry->bitrate;
    }
    prev = entry - 1;
    if (entry->minsnr == -1)
    {
        return prev->bitrate;
    }
    return mmwpas_interpolate_rate(snr, prev->minsnr, entry->minsnr, prev->bitrate, entry->bitrate);
}

static struct wpa_scan_res *mmwpas_alloc_and_fill_scan_result(const struct umac_scan_response *rsp)
{
    struct wpa_scan_res *res;
    size_t res_len = sizeof(*res) + rsp->frame.ies_len;

    res = (struct wpa_scan_res *)os_malloc(res_len);
    if (res == NULL)
    {
        MMLOG_WRN("Failed to allocate wpa_scan_res\n");
        return NULL;
    }

    memset(res, 0, sizeof(*res));

    res->flags = WPA_SCAN_QUAL_INVALID | WPA_SCAN_LEVEL_DBM;
    PACK_LE64(res->tsf, rsp->frame.timestamp);
    mac_addr_copy(res->bssid, rsp->frame.bssid);
    res->freq = KHZ_TO_MHZ(HZ_TO_KHZ(rsp->channel_freq_hz));
    res->freq_offset = KHZ_TO_S1G_OFFSET(HZ_TO_KHZ(rsp->channel_freq_hz));
    res->beacon_int = rsp->frame.beacon_interval;
    res->caps = rsp->frame.capability_info;
    res->level = rsp->rssi;
    res->ie_len = rsp->frame.ies_len;
    res->noise = rsp->noise_dbm;
    res->est_throughput = mmwpas_max_s1g_bitrate(rsp->rssi - rsp->noise_dbm);

    uint8_t *ies = (uint8_t *)(res + 1);
    memcpy(ies, rsp->frame.ies, res->ie_len);

#if MMLOG_LEVEL >= MMLOG_LEVEL_VRB
    char ssid[33] = { 0 };
    MMOSAL_ASSERT(rsp->frame.ssid_len < sizeof(ssid) - 1);
    memcpy(ssid, rsp->frame.ssid, rsp->frame.ssid_len);
    MMLOG_VRB("> '%s' " MM_MAC_ADDR_FMT ", %d dBm, %d kHz\n",
              ssid,
              MM_MAC_ADDR_VAL(rsp->frame.bssid),
              rsp->rssi,
              HZ_TO_KHZ(rsp->channel_freq_hz));
#endif

    return res;
}

static void mmwpas_scan_rx_handler(struct umac_data *umacd, const struct umac_scan_response *rsp)
{
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    MMOSAL_ASSERT(data->in_progress_scan_results != NULL);

    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
    if (sta_args != NULL && sta_args->scan_rx_cb != NULL)
    {
        struct mmwlan_scan_result scan_result;
        umac_scan_fill_result(&scan_result, rsp);
        sta_args->scan_rx_cb(&scan_result, sta_args->scan_rx_cb_arg);
    }


    if (data->in_progress_scan_results->num == 0)
    {
        MMLOG_VRB("Inserting scan result " MM_MAC_ADDR_FMT " @ idx 0 (num, %u)\n",
                  MM_MAC_ADDR_VAL(rsp->frame.bssid),
                  data->in_progress_scan_results->num);

        MMOSAL_ASSERT(data->in_progress_scan_results->res[0] == NULL);
        data->in_progress_scan_results->res[0] = mmwpas_alloc_and_fill_scan_result(rsp);

        if (data->in_progress_scan_results->res[0] != NULL)
        {
            data->in_progress_scan_results->num = 1;
        }
        return;
    }


    int ii;
    int insert_at_idx = 0;
    int old_entry_idx = -1;
    for (ii = 0; ii < (int)data->in_progress_scan_results->num; ii++)
    {
        struct wpa_scan_res *res = data->in_progress_scan_results->res[ii];
        MMOSAL_ASSERT(res != NULL);
        if (res->level >= rsp->rssi)
        {
            insert_at_idx = ii + 1;
        }

        if (mm_mac_addr_is_equal(rsp->frame.bssid, res->bssid))
        {
            MMOSAL_ASSERT(old_entry_idx == -1);
            old_entry_idx = ii;
        }
    }

    if (insert_at_idx >= data->max_scan_results)
    {
        MMLOG_VRB("Scan result too quiet to add to results list (" MM_MAC_ADDR_FMT
                  ") num=%u, max=%u\n",
                  MM_MAC_ADDR_VAL(rsp->frame.bssid),
                  data->in_progress_scan_results->num,
                  data->max_scan_results);
        return;
    }


    if (old_entry_idx >= 0)
    {
        struct wpa_scan_res *old_entry_res = data->in_progress_scan_results->res[old_entry_idx];

        MMLOG_VRB("Found an existing entry for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(rsp->frame.bssid));
        MMLOG_VRB("    Old entry @ %d, RSSI %d dBm\n", old_entry_idx, old_entry_res->level);
        MMLOG_VRB("    New entry @ %d, RSSI %d dBm\n", insert_at_idx, rsp->rssi);
        if (old_entry_idx <= insert_at_idx)
        {
            MMLOG_VRB("Old entry has better RSSI than new entry. Dropping new entry\n");
            return;
        }

        MMLOG_VRB("Removing old entry with lower RSSI\n");

        os_free(old_entry_res);
        data->in_progress_scan_results->num--;
        for (ii = old_entry_idx; ii < (int)data->in_progress_scan_results->num; ii++)
        {
            data->in_progress_scan_results->res[ii] = data->in_progress_scan_results->res[ii + 1];
        }
    }

    MMLOG_VRB("Inserting scan result " MM_MAC_ADDR_FMT " @ idx %d (num %u)\n",
              MM_MAC_ADDR_VAL(rsp->frame.bssid),
              insert_at_idx,
              data->in_progress_scan_results->num);

    struct wpa_scan_res *res = mmwpas_alloc_and_fill_scan_result(rsp);
    if (res == NULL)
    {
        return;
    }


    MMOSAL_ASSERT(data->in_progress_scan_results->num <= data->max_scan_results);
    if (data->in_progress_scan_results->num == data->max_scan_results)
    {
        size_t idx = data->max_scan_results - 1;
        MMLOG_VRB("Discarding scan result " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(data->in_progress_scan_results->res[idx]->bssid));
        os_free(data->in_progress_scan_results->res[idx]);
        data->in_progress_scan_results->res[idx] = NULL;
        data->in_progress_scan_results->num--;
    }

    for (ii = (int)data->in_progress_scan_results->num; ii > insert_at_idx; ii--)
    {
        data->in_progress_scan_results->res[ii] = data->in_progress_scan_results->res[ii - 1];
    }
    data->in_progress_scan_results->res[insert_at_idx] = res;
    data->in_progress_scan_results->num++;
}

static void mmwpas_clean_up_scan_data(struct umac_supp_shim_data *data)
{
    mmosal_free(data->scan_req.args.extra_ies);
    data->scan_req.args.extra_ies = NULL;
    wpa_scan_results_free(data->in_progress_scan_results);
    data->in_progress_scan_results = NULL;
    mmosal_free(data->bss_cache);
    data->bss_cache = NULL;
}


static bool mmwpas_bss_cache_build(struct umac_supp_shim_data *data,
                                   struct wpa_scan_results *scan_results)
{
    MMOSAL_ASSERT(data->bss_cache == NULL);

    data->bss_cache = (struct bss_cache *)mmosal_malloc(BSS_CACHE_SIZE(scan_results->num));
    if (data->bss_cache == NULL)
    {
        return false;
    }
    data->bss_cache->num_entries = scan_results->num;

    unsigned ii;
    for (ii = 0; ii < scan_results->num; ii++)
    {
        struct bss_cache_entry *entry = &data->bss_cache->entries[ii];
        struct wpa_scan_res *res = scan_results->res[ii];

        MMOSAL_ASSERT(res != NULL);
        memcpy(entry->bssid, res->bssid, sizeof(entry->bssid));

        const uint8_t *ie =
            ie_find((const uint8_t *)(res + 1), res->ie_len, DOT11_IE_S1G_OPERATION, NULL);

        MMOSAL_ASSERT(ie != NULL);

        MMOSAL_ASSERT(((const struct dot11_ie_s1g_operation *)ie)->header.length ==
                      sizeof(entry->s1g_operation_ie) - sizeof(struct dot11_ie_hdr));

        memcpy(entry->s1g_operation_ie, ie, sizeof(entry->s1g_operation_ie));

        entry->beacon_interval = res->beacon_int;
    }
    return true;
}


static bool mmwpas_bss_cache_lookup(struct umac_supp_shim_data *data,
                                    const uint8_t *bssid,
                                    struct umac_connection_bss_cfg *config)
{
    if (data->bss_cache == NULL)
    {
        return false;
    }

    unsigned ii;
    for (ii = 0; ii < data->bss_cache->num_entries; ii++)
    {
        struct bss_cache_entry *entry = &data->bss_cache->entries[ii];
        if (mm_mac_addr_is_equal(entry->bssid, bssid))
        {
            bool ok =
                ie_s1g_operation_parse((struct dot11_ie_s1g_operation *)entry->s1g_operation_ie,
                                       &config->channel_cfg);
            if (!ok)
            {
                MMLOG_WRN("S1G IE unparseable for " MM_MAC_ADDR_FMT "\n",
                          MM_MAC_ADDR_VAL(entry->bssid));
                return false;
            }
            config->beacon_interval = entry->beacon_interval;
            return true;
        }
    }

    return false;
}

static bool mmwpas_build_mesh_bootstrap_bss_cfg(struct umac_data *umacd,
                                                const struct wpa_driver_mesh_join_params *params,
                                                struct umac_connection_bss_cfg *config,
                                                uint8_t bootstrap_bssid[DOT11_MAC_ADDR_LEN])
{
    uint64_t freq_hz = 0;
    uint32_t freq_hz_u32 = 0;
    const struct mmwlan_s1g_channel *channel = NULL;
    const struct ie_s1g_operation *current_s1g = NULL;

    if (params == NULL || config == NULL || bootstrap_bssid == NULL)
    {
        return false;
    }

    /* S1G center frequencies can be on 500 kHz boundaries, so the integer
     * MHz field is lossy. Prefer the exact kHz value and requested bandwidth. */
    if (params->freq.freq_khz > 0)
    {
        uint8_t bw_mask = (params->freq.bandwidth > 0 && params->freq.bandwidth <= UINT8_MAX) ?
            (uint8_t)params->freq.bandwidth : (1 | 2);

        channel = umac_regdb_get_channel_from_freq_and_bw(
            umacd, ((uint32_t)params->freq.freq_khz) * 1000U, bw_mask);
        if (channel != NULL)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap using exact freq_khz=%d bandwidth=%u op_class=%u chan=%u\n",
                   params->freq.freq_khz,
                   (unsigned)channel->bw_mhz,
                   (unsigned)channel->global_operating_class,
                   (unsigned)channel->s1g_chan_num);
        }
    }

    /* A valid profile-derived channel is authoritative during runtime
     * reconfiguration. The interface's current S1G operation still contains
     * the old channel until the new BSS configuration is applied. */
    if (channel == NULL && params->freq.channel > 0)
    {
        channel = umac_regdb_get_channel(umacd, (uint8_t)params->freq.channel);
        if (channel != NULL)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap using freq.channel hint=%d op_class=%u chan=%u\n",
                   params->freq.channel,
                   (unsigned)channel->global_operating_class,
                   (unsigned)channel->s1g_chan_num);
        }
        else
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap freq.channel hint=%d not found in regdb\n",
                   params->freq.channel);
        }
    }

    if (channel == NULL && params->freq.freq > 0)
    {
        /*
         * Hostap join freq may arrive as MHz, kHz, or Hz depending on path.
         * Normalize safely and avoid truncation on 32-bit conversion.
         */
        if (params->freq.freq < 10000)
        {
            freq_hz = ((uint64_t)params->freq.freq) * 1000000ULL; /* MHz -> Hz */
        }
        else if (params->freq.freq < 100000000)
        {
            freq_hz = ((uint64_t)params->freq.freq) * 1000ULL; /* kHz -> Hz */
        }
        else
        {
            freq_hz = (uint64_t)params->freq.freq; /* already Hz */
        }

        if (freq_hz <= UINT32_MAX)
        {
            freq_hz_u32 = (uint32_t)freq_hz;
            channel = umac_regdb_get_channel_from_freq_and_bw(umacd, freq_hz_u32, (1 | 2));
        }
        else
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap freq overflow freq=%d (hz=%lu)\n",
                   params->freq.freq,
                   (unsigned long)freq_hz);
        }

        if (channel == NULL)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap freq lookup miss freq=%d (hz=%lu), trying fallbacks\n",
                   params->freq.freq,
                   (unsigned long)freq_hz);
        }
    }

    if (channel == NULL)
    {
        current_s1g = umac_interface_get_current_s1g_operation_info(umacd);
        if (current_s1g != NULL && current_s1g->operating_channel_index != 0)
        {
            channel = umac_regdb_get_channel(umacd, current_s1g->operating_channel_index);
            if (channel != NULL)
            {
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap using current channel op_class=%u chan=%u\n",
                       (unsigned)current_s1g->operating_class,
                       (unsigned)current_s1g->operating_channel_index);
            }
        }
    }

    if (channel == NULL)
    {
#if defined(CONFIG_MM_EXPERIMENTAL_MESH_CHAN)
        channel = umac_regdb_get_channel(umacd, CONFIG_MM_EXPERIMENTAL_MESH_CHAN);
        if (channel != NULL)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap using configured mesh channel=%u\n",
                   (unsigned)CONFIG_MM_EXPERIMENTAL_MESH_CHAN);
        }
#endif
    }

#if defined(CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY) && CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY
    if (channel == NULL)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: BLE-provisioned channel is required\n");
        return false;
    }
#endif

    if (channel == NULL && umac_regdb_get_num_channels(umacd) > 0)
    {
        channel = umac_regdb_get_channel_at_index(umacd, 0);
        if (channel != NULL)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap falling back to first regdb channel=%u\n",
                   (unsigned)channel->s1g_chan_num);
        }
    }

    if (channel == NULL)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap channel lookup failed for freq=%d (hz=%lu) after fallbacks\n",
               params->freq.freq,
               (unsigned long)freq_hz);
        return false;
    }

    config->channel_cfg.primary_channel_width_mhz = (channel->bw_mhz > 1) ? 2 : 1;
    config->channel_cfg.operation_channel_width_mhz = channel->bw_mhz;
    config->channel_cfg.primary_1mhz_channel_loc = 0;
    config->channel_cfg.recommend_no_mcs10 = false;
    config->channel_cfg.operating_class = channel->global_operating_class;
    config->channel_cfg.primary_channel_number = channel->s1g_chan_num;
    config->channel_cfg.operating_channel_index = channel->s1g_chan_num;
    config->beacon_interval = (params->beacon_int > 0) ? (uint16_t)params->beacon_int : 100;

    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, bootstrap_bssid) != MMWLAN_SUCCESS)
    {
        if (umac_interface_get_device_mac_addr(umacd, bootstrap_bssid) != MMWLAN_SUCCESS)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap failed to resolve local MAC\n");
            return false;
        }
    }

    return true;
}

static void mmwpas_scan_complete_handler(struct umac_data *umacd,
                                         enum mmwlan_scan_state result_code)
{
    MM_UNUSED(result_code);
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    MMOSAL_ASSERT(data->in_progress_scan_results != NULL);
    data->completed_scan_results = data->in_progress_scan_results;
    data->in_progress_scan_results = NULL;
    mmwpas_clean_up_scan_data(data);
    mmwpas_bss_cache_build(data, data->completed_scan_results);

    MMLOG_INF("%u scan results\n", data->completed_scan_results->num);
#if MMLOG_LEVEL >= MMLOG_LEVEL_DBG
    unsigned ii;
    for (ii = 0; ii < data->completed_scan_results->num; ii++)
    {
        char ssid[33] = { 0 };
        const struct dot11_ie_ssid *ssid_ie =
            ie_ssid_find((const uint8_t *)(data->completed_scan_results->res[ii] + 1),
                         data->completed_scan_results->res[ii]->ie_len);
        MMOSAL_ASSERT(ssid_ie != NULL);
        MMOSAL_ASSERT(ssid_ie->header.length < sizeof(ssid) - 1);
        memcpy(ssid, ssid_ie->ssid, ssid_ie->header.length);
        MMLOG_DBG("  - " MM_MAC_ADDR_FMT "(%ddBm): %s\n",
                  MM_MAC_ADDR_VAL(data->completed_scan_results->res[ii]->bssid),
                  data->completed_scan_results->res[ii]->level,
                  ssid);
    }
#endif

    umac_stats_update_connect_timestamp(umacd, MMWLAN_STATS_CONNECT_TIMESTAMP_SCAN_COMPLETE);


    umac_supp_event(data->sta_driver_ctx, EVENT_SCAN_RESULTS, NULL);

    umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_SCAN_COMPLETE);
}

static int mmwpas_initialise_scan_data(struct umac_data *umacd,
                                       struct umac_supp_shim_data *data,
                                       struct wpa_driver_scan_params *params)
{
    struct mmwlan_scan_args *args = &data->scan_req.args;
    bool dwell_on_home;
    size_t alloc_size;

    if (data->in_progress_scan_results != NULL)
    {

        MMLOG_WRN("Unable to start scan: already in progress\n");
        return -1;
    }


    MMOSAL_ASSERT(args->extra_ies == NULL);


    mmwpas_clean_up_scan_data(data);

    if (params->num_ssids == 1 && params->ssids[0].ssid_len != 0)
    {
        args->ssid_len = params->ssids[0].ssid_len;
        MMOSAL_ASSERT(args->ssid_len <= sizeof(args->ssid));
        memcpy(args->ssid, params->ssids[0].ssid, params->ssids[0].ssid_len);
    }
    else
    {
        memset(args->ssid, 0, MMWLAN_SSID_MAXLEN);
        args->ssid_len = 0;
    }


    if ((args->ssid_len == 0) && umac_config_is_ndp_probe_supported(umacd))
    {
        const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
        if (sta_args != NULL)
        {
            args->ssid_len = sta_args->ssid_len;
            MMOSAL_ASSERT(args->ssid_len <= sizeof(args->ssid));
            memcpy(args->ssid, sta_args->ssid, args->ssid_len);
            MMLOG_INF("Using SSID from STA args (len=%u)\n", args->ssid_len);
        }
    }


    args->dwell_time_ms = umac_config_get_supp_scan_dwell_time(umacd);
    dwell_on_home = mmwlan_get_sta_state() == MMWLAN_STA_CONNECTED && !data->sta_wpa_s->reassociate;
    args->dwell_on_home_ms = dwell_on_home ? umac_config_get_supp_scan_home_dwell_time(umacd) : 0;

    if (params->extra_ies_len)
    {
        args->extra_ies = (uint8_t *)mmosal_malloc(params->extra_ies_len);
        if (args->extra_ies)
        {
            memcpy(args->extra_ies, params->extra_ies, params->extra_ies_len);
            args->extra_ies_len = params->extra_ies_len;
        }
    }

    MMLOG_INF("SUPP_SCAN_REQ: num_ssids=%u ssid_len=%u extra_ies_len=%u dwell=%lu home_dwell=%lu\n",
              (unsigned)params->num_ssids,
              (unsigned)args->ssid_len,
              (unsigned)args->extra_ies_len,
              (unsigned long)args->dwell_time_ms,
              (unsigned long)args->dwell_on_home_ms);
    if (args->ssid_len > 0)
    {
        MMLOG_INF("SUPP_SCAN_REQ: ssid=%.*s\n", (int)args->ssid_len, (const char *)args->ssid);
    }
    if (args->extra_ies != NULL && args->extra_ies_len > 0)
    {
        MMLOG_INF("SUPP_SCAN_REQ: extra_ies[0..3]=%02x %02x %02x %02x\n",
                  args->extra_ies[0],
                  (args->extra_ies_len > 1) ? args->extra_ies[1] : 0,
                  (args->extra_ies_len > 2) ? args->extra_ies[2] : 0,
                  (args->extra_ies_len > 3) ? args->extra_ies[3] : 0);
    }

    data->scan_req.rx_cb = mmwpas_scan_rx_handler;
    data->scan_req.complete_cb = mmwpas_scan_complete_handler;

    data->in_progress_scan_results =
        (struct wpa_scan_results *)os_malloc(sizeof(*(data->in_progress_scan_results)));
    if (data->in_progress_scan_results == NULL)
    {
        goto error;
    }

    memset(data->in_progress_scan_results, 0, sizeof(*(data->in_progress_scan_results)));
    data->max_scan_results = umac_config_get_max_supp_scan_results(umacd);
    alloc_size = sizeof(struct wpa_scan_res *) * data->max_scan_results;
    data->in_progress_scan_results->res = (struct wpa_scan_res **)(os_malloc(alloc_size));
    if (data->in_progress_scan_results->res == NULL)
    {
        goto error;
    }
    memset(data->in_progress_scan_results->res, 0, alloc_size);

    return 0;

error:
    mmwpas_clean_up_scan_data(data);
    return -1;
}

static int mmwpas_scan2(void *priv, struct wpa_driver_scan_params *params)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    struct wpa_supplicant *wpa_s = data ? data->sta_wpa_s : NULL;

    if ((umac_connection_get_state(umacd) == MMWLAN_STA_CONNECTING) &&
        wpa_s != NULL &&
        wpa_s->current_ssid != NULL &&
        wpa_s->current_ssid->mode == WPAS_MODE_MESH &&
        wpa_s->current_bss != NULL)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_scan2: suppressed scan while CONNECTING (mesh current_bss set)\n");
        return -1;
    }

    int ret = mmwpas_initialise_scan_data(umacd, data, params);
    if (ret != 0)
    {
        return ret;
    }

    umac_stats_update_connect_timestamp(umacd, MMWLAN_STATS_CONNECT_TIMESTAMP_SCAN_REQUESTED);


    umac_scan_queue_request(umacd, &data->scan_req);

    umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_SCAN_REQUEST);

    return 0;
}

struct wpa_scan_results *mmwpas_get_scan_results2(void *priv)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    struct wpa_scan_results *results = data->completed_scan_results;
    data->completed_scan_results = NULL;
    return results;
}

static int mmwpas_abort_scan(void *priv, u64 scan_cookie)
{
    struct umac_data *umacd = (struct umac_data *)priv;

    MM_UNUSED(scan_cookie);

    umac_scan_abort(umacd, NULL);

    umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_SCAN_ABORT);

    return 0;
}

static int mmwpas_authenticate(void *priv, struct wpa_driver_auth_params *params)
{
    enum mmwlan_status status;
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);

    if (params->auth_alg != WPA_AUTH_ALG_OPEN && params->auth_alg != WPA_AUTH_ALG_SAE)
    {
        MMLOG_WRN("Failed to send an Auth frame: unsupported auth_alg: %d\n", params->auth_alg);
        return -1;
    }

    uint8_t own_addr[DOT11_MAC_ADDR_LEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) != MMWLAN_SUCCESS)
    {
        return -1;
    }

    struct umac_connection_bss_cfg config = { 0 };
    bool ok = mmwpas_bss_cache_lookup(data, params->bssid, &config);
    if (!ok)
    {
        MMLOG_WRN("Failed to find entry in BSS cache for " MM_MAC_ADDR_FMT "\n",
                  MM_MAC_ADDR_VAL(params->bssid));
        return -1;
    }

    MMLOG_VRB("Found BSS cache entry for " MM_MAC_ADDR_FMT "\n", MM_MAC_ADDR_VAL(params->bssid));

    struct frame_data_auth auth_params = { .auth_alg = (params->auth_alg == WPA_AUTH_ALG_OPEN) ?
                                                           DOT11_AUTH_ALG_OPEN :
                                                           DOT11_AUTH_ALG_SAE,
                                           .bssid = params->bssid,
                                           .sta_address = own_addr,
                                           .auth_data_len = params->auth_data_len,
                                           .auth_data = params->auth_data };

    MMLOG_INF("SUPP_AUTH_REQ: alg=%u bssid=" MM_MAC_ADDR_FMT " auth_data_len=%u\n",
              (unsigned)params->auth_alg,
              MM_MAC_ADDR_VAL(params->bssid),
              (unsigned)params->auth_data_len);
    if (params->auth_data != NULL && params->auth_data_len > 0)
    {
        MMLOG_INF("SUPP_AUTH_REQ: auth_data[0..3]=%02x %02x %02x %02x\n",
                  params->auth_data[0],
                  (params->auth_data_len > 1) ? params->auth_data[1] : 0,
                  (params->auth_data_len > 2) ? params->auth_data[2] : 0,
                  (params->auth_data_len > 3) ? params->auth_data[3] : 0);
    }

    status = umac_connection_set_bss_cfg(umacd, params->bssid, &config);
    if (status != MMWLAN_SUCCESS)
    {
        MMLOG_WRN("Failed to set BSS for connection.\n");
        return -1;
    }

    status = umac_connection_process_auth_req(umacd, &auth_params);

    if (status == MMWLAN_SUCCESS)
    {
        umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_AUTH_REQUEST);
        return 0;
    }

    return -1;
}

int mmwpas_associate(void *priv, struct wpa_driver_associate_params *params)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if (stad == NULL)
    {
        MMOSAL_DEV_ASSERT(false);
        return -1;
    }

    MMLOG_DBG("WPAS: Assoc\n");

    uint8_t own_addr[DOT11_MAC_ADDR_LEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) != MMWLAN_SUCCESS)
    {
        return -1;
    }

    struct frame_data_assoc_req assoc_req_params = { .bssid = params->bssid,
                                                     .prev_bssid = params->prev_bssid,
                                                     .sta_address = own_addr,
                                                     .ssid_len = params->ssid_len,
                                                     .ssid = params->ssid,
                                                     .wpa_ie_len = params->wpa_ie_len,
                                                     .wpa_ie = params->wpa_ie,
                                                     .extra_assoc_ies = sta_args->extra_assoc_ies,
                                                     .extra_assoc_ies_len =
                                                         sta_args->extra_assoc_ies_len };

    MMLOG_INF("SUPP_ASSOC_REQ: bssid=" MM_MAC_ADDR_FMT " ssid_len=%u wpa_ie_len=%u extra_assoc_ies_len=%u\n",
              MM_MAC_ADDR_VAL(params->bssid),
              (unsigned)params->ssid_len,
              (unsigned)params->wpa_ie_len,
              (unsigned)sta_args->extra_assoc_ies_len);
    if (params->ssid != NULL && params->ssid_len > 0)
    {
        MMLOG_INF("SUPP_ASSOC_REQ: ssid=%.*s\n", (int)params->ssid_len, (const char *)params->ssid);
    }
    if (params->wpa_ie != NULL && params->wpa_ie_len > 0)
    {
        MMLOG_INF("SUPP_ASSOC_REQ: wpa_ie[0..3]=%02x %02x %02x %02x\n",
                  params->wpa_ie[0],
                  (params->wpa_ie_len > 1) ? params->wpa_ie[1] : 0,
                  (params->wpa_ie_len > 2) ? params->wpa_ie[2] : 0,
                  (params->wpa_ie_len > 3) ? params->wpa_ie[3] : 0);
    }

    enum mmwlan_status status = umac_connection_process_assoc_req(umacd, &assoc_req_params);
    if (status != MMWLAN_SUCCESS)
    {
        return -1;
    }

    umac_sta_data_set_security(stad,
                               translate_supp_to_mmwlan_security(params->key_mgmt_suite),
                               translate_supp_to_mmwlan_pmf_mode(params->mgmt_frame_protection));
    umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_ASSOC_REQUEST);

    return 0;
}

struct hostapd_hw_modes *mmwpas_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags, u8 *dfs)
{
    MM_UNUSED(flags);
    MM_UNUSED(dfs);

    struct umac_data *umacd = (struct umac_data *)priv;

    struct hostapd_hw_modes *hw_mode = (struct hostapd_hw_modes *)os_calloc(1, sizeof(*hw_mode));
    if (hw_mode == NULL)
    {
        goto failure;
    }

    const struct mmwlan_s1g_channel_list *channel_list = umac_config_get_channel_list(umacd);
    MMOSAL_ASSERT(channel_list != NULL);

    hw_mode->mode = HOSTAPD_MODE_IEEE80211AH;
    hw_mode->num_channels = channel_list->num_channels;
    hw_mode->channels =
        (struct hostapd_channel_data *)os_calloc(hw_mode->num_channels, sizeof(*hw_mode->channels));
    if (hw_mode->channels == NULL)
    {
        goto failure;
    }

    for (unsigned ii = 0; ii < channel_list->num_channels; ii++)
    {
        hw_mode->channels[ii].chan = channel_list->channels[ii].s1g_chan_num;
        hw_mode->channels[ii].freq = 0;
        hw_mode->channels[ii].freq_khz = HZ_TO_KHZ(channel_list->channels[ii].centre_freq_hz);
        switch (channel_list->channels[ii].bw_mhz)
        {
            case 16:
                hw_mode->channels[ii].allowed_bw |= HOSTAPD_CHAN_WIDTH_16;
                MM_FALLTHROUGH;

            case 8:
                hw_mode->channels[ii].allowed_bw |= HOSTAPD_CHAN_WIDTH_8;
                MM_FALLTHROUGH;

            case 4:
                hw_mode->channels[ii].allowed_bw |= HOSTAPD_CHAN_WIDTH_4;
                MM_FALLTHROUGH;

            case 2:
                hw_mode->channels[ii].allowed_bw |= HOSTAPD_CHAN_WIDTH_2;
                MM_FALLTHROUGH;

            case 1:
                hw_mode->channels[ii].allowed_bw |= HOSTAPD_CHAN_WIDTH_1;
                break;

            default:
                MMLOG_WRN("Invalid channel BW MHz\n");
                MMOSAL_DEV_ASSERT(false);
                break;
        }
        hw_mode->channels[ii].max_tx_power = channel_list->channels[ii].max_tx_eirp_dbm;
    }

    struct dot11_ie_s1g_capabilities s1g_cap_ie;
    struct consbuf buf = CONSBUF_INIT_WITH_BUF((uint8_t *)&s1g_cap_ie, sizeof(s1g_cap_ie));
    ie_s1g_capabilities_build(umacd, &buf);
    MM_STATIC_ASSERT(sizeof(s1g_cap_ie.s1g_capabilities_information) == sizeof(hw_mode->s1g_capab),
                     "Size of S1G Capabilities Element in Driver and Supplicant do not match");
    MM_STATIC_ASSERT(sizeof(s1g_cap_ie.supported_s1g_mcs_nss_set) == sizeof(hw_mode->s1g_mcs),
                     "Size of S1G MCS_NSS Element in Driver and Supplicant do not match");

    memcpy(hw_mode->s1g_capab, s1g_cap_ie.s1g_capabilities_information, sizeof(hw_mode->s1g_capab));
    memcpy(hw_mode->s1g_mcs, s1g_cap_ie.supported_s1g_mcs_nss_set, sizeof(hw_mode->s1g_mcs));

    hw_mode->band = NL80211_BAND_S1GHZ;

    /* S1G rates matching the fallback beacon (in 100 kbps units).
     * These feed hostapd_prepare_rates() so that mesh action frames
     * include Supported Rates / Extended Supported Rates IEs. */
    static const int s1g_rates[] = {
        10, 20, 55, 60, 110, 120, 180, 240,  /* supp_rates */
        45, 65, 70, 85, 90, 125, 135, 150    /* ext_supp_rates */
    };
    hw_mode->num_rates = (int)(sizeof(s1g_rates) / sizeof(s1g_rates[0]));
    hw_mode->rates = os_malloc(sizeof(s1g_rates));
    if (hw_mode->rates == NULL)
    {
        goto failure;
    }
    os_memcpy(hw_mode->rates, s1g_rates, sizeof(s1g_rates));

    *num_modes = 1;
    return hw_mode;

failure:
    if (hw_mode != NULL)
    {
        os_free(hw_mode->channels);
        os_free(hw_mode->rates);
    }
    os_free(hw_mode);
    return NULL;
}


int mmwpas_get_bssid(void *priv, u8 *bssid)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    return (umac_connection_get_bssid(umacd, bssid) == MMWLAN_SUCCESS ? 0 : -1);
}

int mmwpas_set_supp_port(void *priv, int authorized)
{
    struct umac_data *umacd = (struct umac_data *)priv;

    MMLOG_DBG("WPAS: Set controlled port %d\n", authorized);

#if defined(CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY) && CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY
    MMLOG_INF("WPAS: Meshtastic raw bearer ignores controlled port authorized=%d\n", authorized);
    return 0;
#endif

    umac_connection_handle_port_state(umacd, (authorized != 0));

    return 0;
}

int mmwpas_deauthenticate(void *priv, const u8 *addr, u16 reason_code)
{
    struct umac_data *umacd = (struct umac_data *)priv;

    MMLOG_DBG("WPAS: Deauth\n");

    uint8_t own_addr[ETH_ALEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) != MMWLAN_SUCCESS)
    {
        return -1;
    }

    struct frame_data_deauth deauth_params = { .bssid = addr,
                                               .sta_address = own_addr,
                                               .reason_code = reason_code };

    enum mmwlan_status status = umac_connection_process_deauth_tx(umacd, &deauth_params);

    if (status == MMWLAN_SUCCESS)
    {
        umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_DEAUTH_TX);
        return 0;
    }

    return -1;
}

int mmwpas_get_ssid(void *priv, u8 *ssid)
{
    struct umac_data *umacd = (struct umac_data *)priv;

    return umac_connection_get_ssid(umacd, ssid);
}

int mmwpas_set_key(void *priv, struct wpa_driver_set_key_params *params)
{
    enum mmwlan_status status = MMWLAN_ERROR;
    struct umac_data *umacd = (struct umac_data *)priv;

    printf("[set_key] alg=%d key_flag=0x%x key_idx=%d key_len=%u addr=%p\n",
           params->alg, params->key_flag, params->key_idx,
           (unsigned)params->key_len, params->addr);

    uint16_t vif_id = umac_connection_get_vif_id(umacd);
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if (stad == NULL)
    {
        if (params->alg == WPA_ALG_NONE)
        {
            MMLOG_DBG("Ignoring key removal before STA is fully initialized\n");
            return 0;
        }
        else
        {
            MMLOG_WRN("Setkey STA not initialized\n");
            MMOSAL_DEV_ASSERT(false);
            return -1;
        }
    }

    if (params->alg == WPA_ALG_NONE)
    {
        if (params->key_idx == 1)
        {
            umac_datapath_set_mesh_peer_group_key(umacd, 0, NULL, 0);
        }
        status = umac_keys_uninstall_key(stad, vif_id, params->key_idx);
        if (status != MMWLAN_SUCCESS)
        {
            return -1;
        }
    }
    else if ((params->key_flag & (KEY_FLAG_PAIRWISE | KEY_FLAG_GROUP)) &&
             ((params->alg == WPA_ALG_CCMP) || (params->alg == WPA_ALG_BIP_CMAC_128)))
    {
        struct umac_key key = { 0 };

        if (params->key_flag == KEY_FLAG_PAIRWISE_RX_TX)
        {
            key.key_type = UMAC_KEY_TYPE_PAIRWISE;
        }
        else if (params->key_flag == KEY_FLAG_GROUP_RX ||
                 params->key_flag == KEY_FLAG_GROUP_TX_DEFAULT ||
                 params->key_flag == KEY_FLAG_GROUP_RX_TX_DEFAULT)
        {
            if (params->alg == WPA_ALG_CCMP && params->key_flag == KEY_FLAG_GROUP_RX)
            {
                /* Mesh peer RX-only MGTK: cache for SW decrypt and keep active TX group key untouched. */
                if (params->key_len > 0 && params->key != NULL)
                {
                    umac_datapath_set_mesh_peer_group_key(
                        umacd, params->key_idx, params->key, params->key_len);
                    printf("[set_key] cached peer GROUP_RX key_idx=%d key_len=%u\n",
                           params->key_idx,
                           (unsigned)params->key_len);
                    return 0;
                }
            }

            if (params->alg == WPA_ALG_BIP_CMAC_128)
            {
                key.key_type = UMAC_KEY_TYPE_IGTK;
            }
            else
            {
                key.key_type = UMAC_KEY_TYPE_GROUP;
            }
        }
        else
        {
            MMLOG_WRN(
                "morse_set_key - unsupported combination with key_flag: %u, alg: %u, key_index: %d",
                params->key_flag,
                params->alg,
                params->key_idx);
            return -1;
        }

        key.key_id = params->key_idx;

        if (params->key_len > sizeof(key.key_data))
        {
            MMLOG_WRN("set_key: too long %u", params->key_len);
            return -1;
        }

        key.key_len = params->key_len;
        memcpy(key.key_data, params->key, params->key_len);

        if (params->seq != NULL)
        {
            unsigned ii;
            for (ii = 0; ii < params->seq_len; ii++)
            {
                key.rx_seq[UMAC_KEY_RX_COUNTER_SPACE_DEFAULT] |= ((uint64_t)(params->seq[ii]))
                                                                 << (ii * 8);
            }
        }

        status = umac_keys_install_key(stad, vif_id, &key);
        if (status != MMWLAN_SUCCESS)
        {
            MMLOG_WRN("Failed to install key (status=%d)\n", status);
            return -1;
        }
        printf("[set_key] installed key_type=%d key_id=%d key_len=%u\n",
               key.key_type, key.key_id, key.key_len);
    }
    else
    {
        MMLOG_WRN(
            "morse_set_key - unsupported combination with key_flag: %u, alg: %u, key_index: %d",
            params->key_flag,
            params->alg,
            params->key_idx);
        return -1;
    }

    return 0;
}

static int mmwpas_send_action(void *priv,
                              unsigned int freq,
                              unsigned int wait_time,
                              const u8 *dst,
                              const u8 *src,
                              const u8 *bssid,
                              const u8 *data,
                              size_t data_len,
                              int no_cck)
{

    MM_UNUSED(freq);
    MM_UNUSED(wait_time);

    MM_UNUSED(no_cck);

    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *supp_data = umac_data_get_supp_shim(umacd);

    /*
     * In mesh mode, peering action frames (OPEN/CONFIRM/CLOSE) must be sent
     * before the connection FSM reaches CONNECTED state.  Allow action frames
     * when a mesh VIF is active even if not yet fully connected.
     */
    bool mesh_vif_active = (umac_interface_get_vif_id(umacd, UMAC_INTERFACE_MESH)
                            != UMAC_INTERFACE_VIF_ID_INVALID);

    MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: enter state=%d roc=%d mesh_vif=%d len=%u dst=" MM_MAC_ADDR_FMT " src=%02x:%02x:%02x:%02x:%02x:%02x\n",
           umac_connection_get_state(umacd),
           supp_data->in_progress_roc ? 1 : 0,
           mesh_vif_active ? 1 : 0,
           (unsigned int)data_len,
           MM_MAC_ADDR_VAL(dst),
           src[0], src[1], src[2], src[3], src[4], src[5]);

    if ((umac_connection_get_state(umacd) != MMWLAN_STA_CONNECTED) &&
        !supp_data->in_progress_roc &&
        !mesh_vif_active)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: drop (state gate) state=%d roc=%d mesh_vif=%d\n",
               umac_connection_get_state(umacd),
               supp_data->in_progress_roc ? 1 : 0,
               mesh_vif_active ? 1 : 0);
        return -1;
    }

    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    if ((stad == NULL) && mesh_vif_active)
    {
        stad = umac_ap_lookup_sta_by_addr(umacd, dst);
        if (stad == NULL)
        {
            stad = umac_ap_lookup_sta_by_addr(umacd, NULL);
        }
    }

    if (stad == NULL)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: drop (no stad)\n");
        return -1;
    }

    uint8_t own_addr[ETH_ALEN];
    if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) != MMWLAN_SUCCESS)
    {
        if (!mesh_vif_active)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: drop (get own addr failed)\n");
            return -1;
        }

        /* Mesh path can run without STA vif-id ownership; trust src from caller. */
        os_memcpy(own_addr, src, ETH_ALEN);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: own addr fallback to src for mesh\n");
    }

    if (!mm_mac_addr_is_equal(own_addr, src))
    {
        if (mesh_vif_active)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: mesh src override own=" MM_MAC_ADDR_FMT
                   " src=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   MM_MAC_ADDR_VAL(own_addr),
                   src[0], src[1], src[2], src[3], src[4], src[5]);
        }
        else
        {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: src addr mismatch own=" MM_MAC_ADDR_FMT
               " src=%02x:%02x:%02x:%02x:%02x:%02x\n",
               MM_MAC_ADDR_VAL(own_addr),
               src[0], src[1], src[2], src[3], src[4], src[5]);
        return -1;
        }
    }

    const uint8_t *tx_src = mesh_vif_active ? src : own_addr;
    const uint8_t *tx_bssid = bssid;

    MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: fmt cat=%u action=%u da=" MM_MAC_ADDR_FMT
           " sa=%02x:%02x:%02x:%02x:%02x:%02x bssid=%02x:%02x:%02x:%02x:%02x:%02x len=%u\n",
           (data_len > 0U) ? (unsigned)data[0] : 0U,
           (data_len > 1U) ? (unsigned)data[1] : 0U,
           MM_MAC_ADDR_VAL(dst),
           tx_src[0], tx_src[1], tx_src[2], tx_src[3], tx_src[4], tx_src[5],
           tx_bssid[0], tx_bssid[1], tx_bssid[2], tx_bssid[3], tx_bssid[4], tx_bssid[5],
           (unsigned int)data_len);

    struct frame_data_action params = { .bssid = tx_bssid,
                                        .dst_address = dst,
                                        .src_address = tx_src,
                                        .action_field = data,
                                        .action_field_len = data_len };

    enum mmwlan_status status =
        umac_datapath_build_and_tx_mgmt_frame(stad, frame_action_build, &params);

    if (status != MMWLAN_SUCCESS)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: tx failed status=%d\n", status);
    }
    else
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_action: tx queued ok len=%u\n", (unsigned int)data_len);
    }

    return (status == MMWLAN_SUCCESS) ? 0 : -1;
}

static void signal_remain_on_channel_evt(struct umac_data *umacd, const struct umac_evt *evt)
{
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);


    data->in_progress_roc = true;

    union wpa_event_data wpa_event_data = { 0 };

    MMLOG_DBG("Signal remain on channel event\n");

    wpa_event_data.remain_on_channel.freq = evt->args.remain_on_channel.freq_khz;
    wpa_event_data.remain_on_channel.duration = evt->args.remain_on_channel.duration_ms;
    umac_supp_event(data->sta_driver_ctx, EVENT_REMAIN_ON_CHANNEL, &wpa_event_data);
}

static int mmwpas_remain_on_channel(void *priv, unsigned int freq, unsigned int duration)
{
    enum mmwlan_status status = MMWLAN_ERROR;
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);


    MMOSAL_DEV_ASSERT(os_strcmp(data->sta_wpa_s->confname, UMAC_SUPP_DPP_CONFIG_NAME) == 0);

    if (umac_connection_bss_is_configured(umacd))
    {
        MMLOG_WRN("ROC requested with BSS configured\n");
        return -1;
    }

    DEV_ASSERT_IN_S1G_RANGE(freq);
    const struct mmwlan_s1g_channel *channel =
        umac_regdb_get_channel_from_freq_and_bw(umacd, KHZ_TO_HZ(freq), (1 | 2));
    if (channel == NULL)
    {
        status = MMWLAN_CHANNEL_INVALID;
        goto exit;
    }

    status = umac_interface_set_channel_from_regdb(umacd, channel, true);
    if (status != MMWLAN_SUCCESS)
    {
        goto exit;
    }


    struct umac_evt evt = UMAC_EVT_INIT_ARGS(signal_remain_on_channel_evt,
                                             remain_on_channel,
                                             .freq_khz = freq,
                                             .duration_ms = duration);
    bool ok = umac_core_evt_queue(umacd, &evt);
    if (!ok)
    {
        status = MMWLAN_ERROR;
    }

    MMLOG_DBG("Remain on channel %d kHz %d ms\n", freq, duration);

exit:
    return (status == MMWLAN_SUCCESS) ? 0 : -1;
}

int mmwpas_cancel_remain_on_channel(void *priv)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);

    data->in_progress_roc = false;

    MMLOG_DBG("Cancel remain on channel\n");

    return 0;
}

static int mmwpas_wnm_oper(void *priv, enum wnm_oper oper, const u8 *peer, u8 *buf, u16 *buf_len)
{
    MM_UNUSED(peer);
    MM_UNUSED(buf);
    MM_UNUSED(buf_len);

    struct umac_data *umacd = (struct umac_data *)priv;

    enum umac_wnm_sleep_event event;

    switch (oper)
    {
        case WNM_SLEEP_ENTER_CONFIRM:
            event = UMAC_WNM_SLEEP_EVENT_ENTRY_CONFIRMED;
            break;

        case WNM_SLEEP_EXIT_CONFIRM:
            event = UMAC_WNM_SLEEP_EVENT_EXIT_CONFIRMED;
            break;

        case WNM_SLEEP_ENTER_FAIL:
        case WNM_SLEEP_EXIT_FAIL:

            MMLOG_WRN("WNM Sleep enter/exit request failed.\n");
            return 0;
            break;

        default:
            MMLOG_DBG("Unsupported WNM operation recieved %d.\n", oper);
            return -1;
    }

    umac_wnm_sleep_report_event(umacd, event);

    return 0;
}

static int mmwpas_signal_monitor(void *priv, int threshold, int hysteresis)
{
    struct umac_data *umacd = (struct umac_data *)priv;

    umac_connection_set_signal_monitor(umacd, threshold, hysteresis);

    return 0;
}

static int mmwpas_init_mesh(void *priv)
{
    MM_UNUSED(priv);
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_init_mesh: ready\n");
    return 0;
}

static bool mmwpas_append_bss_ie(const struct wpa_bss *bss,
                                 uint8_t eid,
                                 uint8_t *dst,
                                 size_t dst_size,
                                 size_t *dst_len)
{
    const uint8_t *ie = wpa_bss_get_ie(bss, eid);
    size_t ie_total_len;

    if (ie == NULL)
    {
        return true;
    }

    ie_total_len = 2 + ie[1];
    if (*dst_len + ie_total_len > dst_size)
    {
        return false;
    }

    memcpy(dst + *dst_len, ie, ie_total_len);
    *dst_len += ie_total_len;
    return true;
}

static bool mmwpas_append_raw_ie(uint8_t eid,
                                 const uint8_t *payload,
                                 size_t payload_len,
                                 uint8_t *dst,
                                 size_t dst_size,
                                 size_t *dst_len)
{
    if ((payload_len > 255) || (*dst_len + 2 + payload_len > dst_size))
    {
        return false;
    }

    dst[*dst_len] = eid;
    dst[*dst_len + 1] = (uint8_t)payload_len;
    if (payload_len > 0)
    {
        memcpy(dst + *dst_len + 2, payload, payload_len);
    }
    *dst_len += 2 + payload_len;
    return true;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int mmwpas_send_mlme(void *priv,
                            const u8 *data,
                            size_t data_len,
                            int noack,
                            unsigned int freq,
                            const u16 *csa_offs,
                            size_t csa_offs_len,
                            int no_encrypt,
                            unsigned int wait,
                            int link_id)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_sta_data *stad = umac_connection_get_stad(umacd);
    const struct dot11_hdr *hdr = (const struct dot11_hdr *)data;

    if ((stad == NULL) || (data == NULL) || (data_len < sizeof(struct dot11_hdr)))
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: invalid input stad=%p data=%p len=%u\n",
               (void *)stad,
               (const void *)data,
               (unsigned)data_len);
        return -1;
    }

    if ((dot11_frame_control_get_type(hdr->frame_control) == DOT11_FC_TYPE_MGMT) &&
        (dot11_frame_control_get_subtype(hdr->frame_control) == DOT11_FC_SUBTYPE_AUTH) &&
        (data_len >= sizeof(struct ieee80211_mgmt)))
    {
        const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)data;
        const uint8_t *auth_body = (const uint8_t *)&mgmt->u.auth.auth_transaction;
        size_t fixed_auth_hdr_len = (size_t)(auth_body - data);
        uint8_t own_addr[DOT11_MAC_ADDR_LEN] = { 0 };
        static const uint8_t zero_addr[DOT11_MAC_ADDR_LEN] = { 0 };
        const uint8_t *target = mgmt->da;

        if ((memcmp(mgmt->sa, zero_addr, sizeof(own_addr)) != 0) &&
            ((mgmt->sa[0] & 0x01) == 0))
        {
            memcpy(own_addr, mgmt->sa, sizeof(own_addr));
        }

        if (memcmp(own_addr, zero_addr, sizeof(own_addr)) == 0 &&
            umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) != MMWLAN_SUCCESS)
        {
            if (umac_interface_get_mac_addr(stad, own_addr) != MMWLAN_SUCCESS)
            {
                if (umac_interface_get_device_mac_addr(umacd, own_addr) != MMWLAN_SUCCESS)
                {
                    MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: failed to get STA MAC for auth\n");
                    return -1;
                }
            }
        }

        if (memcmp(own_addr, zero_addr, sizeof(own_addr)) == 0)
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: resolved zero STA MAC for auth\n");
            return -1;
        }

        struct frame_data_auth auth_params = {
            .auth_alg = le_to_host16(mgmt->u.auth.auth_alg),
            .dest_address = target,
            .bssid = target,
            .sta_address = own_addr,
            .seq = le_to_host16(mgmt->u.auth.auth_transaction),
            .status_code = le_to_host16(mgmt->u.auth.status_code),
            .auth_data_len = (data_len > fixed_auth_hdr_len) ? (uint16_t)(data_len - fixed_auth_hdr_len) : 0,
            .auth_data = (data_len > fixed_auth_hdr_len) ? auth_body : NULL,
        };

        enum mmwlan_status auth_status = umac_connection_process_auth_req(umacd, &auth_params);
                                 MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: auth via conn path da=%02x:%02x:%02x:%02x:%02x:%02x sa=%02x:%02x:%02x:%02x:%02x:%02x bssid=%02x:%02x:%02x:%02x:%02x:%02x alg=%u seq=%u sc=%u ret=%d len=%u\n",
             target[0], target[1], target[2], target[3], target[4], target[5],
             own_addr[0], own_addr[1], own_addr[2], own_addr[3], own_addr[4], own_addr[5],
                                                                                                 target[0], target[1], target[2], target[3], target[4], target[5],
             (unsigned)auth_params.auth_alg,
               (unsigned)auth_params.seq,
             (unsigned)auth_params.status_code,
             (int)auth_status,
               (unsigned)data_len);
        return (auth_status == MMWLAN_SUCCESS) ? 0 : -1;
    }

    struct mmpkt *tx_pkt = umac_datapath_alloc_raw_tx_mmpkt(MMDRV_PKT_CLASS_MGMT, 0, data_len);
    if (tx_pkt == NULL)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: alloc failed len=%u\n", (unsigned)data_len);
        return -1;
    }

    struct mmpktview *tx_pktview = mmpkt_open(tx_pkt);
    mmpkt_append_data(tx_pktview, data, data_len);
    mmpkt_close(&tx_pktview);

    enum mmwlan_status status = umac_datapath_tx_mgmt_frame(stad, tx_pkt);
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_send_mlme: tx status=%d len=%u\n",
           (int)status,
           (unsigned)data_len);

    return (status == MMWLAN_SUCCESS) ? 0 : -1;
}

#pragma GCC diagnostic pop

static int mmwpas_join_mesh(void *priv, struct wpa_driver_mesh_join_params *params)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    struct umac_supp_shim_data *data = umac_data_get_supp_shim(umacd);
    struct wpa_supplicant *wpa_s = data ? data->sta_wpa_s : NULL;
    const struct mmwlan_sta_args *sta_args = umac_connection_get_sta_args(umacd);
    struct umac_connection_bss_cfg bss_cfg = { 0 };
    uint8_t target_bssid[DOT11_MAC_ADDR_LEN] = { 0 };
    bool bootstrap_mode = false;
    struct wpa_bss *mesh_peer_bss = NULL;
    bool have_target_bssid = false;
    enum mmwlan_status status;
    enum connection_fsm_state conn_state;

    if (params == NULL)
    {

        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: invalid params (NULL)\n");
        printf("[MM_INIT_MESH] mmwpas_join_mesh invalid params NULL\n");
        return -1;
    }

    printf("[MM_INIT_MESH] mmwpas_join_mesh begin meshid_len=%u freq=%d freq_khz=%u chan=%d beacon_int=%u dtim=%u flags=0x%x wpa_s=%p current_bss=%p current_ssid=%p bss_cache=%p\n",
           (unsigned)params->meshid_len,
           params->freq.freq,
           params->freq.freq_khz,
           params->freq.channel,
           params->beacon_int,
           params->dtim_period,
           params->flags,
           (void *)wpa_s,
           wpa_s ? (void *)wpa_s->current_bss : NULL,
           wpa_s ? (void *)wpa_s->current_ssid : NULL,
           data ? (void *)data->bss_cache : NULL);
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: meshid_len=%u freq=%d beacon_int=%u dtim=%u flags=0x%x\n",
           (unsigned)params->meshid_len,
           params->freq.freq,
           params->beacon_int,
           params->dtim_period,
           params->flags);

#if defined(CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY) && CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY
    MESH_DBG_PRINTF("[mesh_meshtastic] discovery-only: forcing bootstrap advertiser path; peer join disabled\n");
    printf("[MM_INIT_MESH] mmwpas_join_mesh discovery_only forcing bootstrap advertiser path\n");
#else
    if (wpa_s != NULL && wpa_s->current_bss != NULL)
    {
        memcpy(target_bssid, wpa_s->current_bss->bssid, sizeof(target_bssid));
        have_target_bssid = true;
        printf("[MM_INIT_MESH] mmwpas_join_mesh target=current_bss %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5]);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: using current_bss %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5]);
    }

    if (!have_target_bssid && wpa_s != NULL && wpa_s->current_ssid != NULL && wpa_s->current_ssid->bssid_set)
    {
        memcpy(target_bssid, wpa_s->current_ssid->bssid, sizeof(target_bssid));
        have_target_bssid = true;
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: using current_ssid bssid %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5]);
    }

    if (!have_target_bssid && sta_args != NULL &&
        !mm_mac_addr_is_equal(sta_args->bssid, mac_addr_zero))
    {
        memcpy(target_bssid, sta_args->bssid, sizeof(target_bssid));
        have_target_bssid = true;
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: using sta_args bssid %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5]);
    }

    if (!have_target_bssid)
    {
        if (data != NULL && data->bss_cache != NULL && data->bss_cache->num_entries > 0)
        {
            struct bss_cache_entry *entry = &data->bss_cache->entries[0];
            memcpy(target_bssid, entry->bssid, sizeof(target_bssid));
            have_target_bssid = true;
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: using first BSS cache entry %02x:%02x:%02x:%02x:%02x:%02x\n",
                            target_bssid[0], target_bssid[1], target_bssid[2],
                            target_bssid[3], target_bssid[4], target_bssid[5]);
        }
    }
#endif

    if (!have_target_bssid)
    {
        printf("[MM_INIT_MESH] mmwpas_join_mesh no target BSS; trying bootstrap wpa_s=%p current_bss=%p current_ssid=%p bssid_set=%u cache_entries=%u\n",
               (void *)wpa_s,
               wpa_s ? (void *)wpa_s->current_bss : NULL,
               wpa_s ? (void *)wpa_s->current_ssid : NULL,
               (wpa_s && wpa_s->current_ssid) ? (unsigned)wpa_s->current_ssid->bssid_set : 0U,
               (data && data->bss_cache) ? (unsigned)data->bss_cache->num_entries : 0U);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: missing selected BSS (wpa_s=%p current_bss=%p current_ssid=%p bssid_set=%u)\n",
               (void *)wpa_s,
               wpa_s ? (void *)wpa_s->current_bss : NULL,
               wpa_s ? (void *)wpa_s->current_ssid : NULL,
               (wpa_s && wpa_s->current_ssid) ? (unsigned)wpa_s->current_ssid->bssid_set : 0U);

        if (wpa_s != NULL)
        {
            const struct wpa_ssid *configured_ssid =
                (wpa_s->conf != NULL) ? wpa_s->conf->ssid : NULL;
            const struct wpa_ssid *current_ssid = wpa_s->current_ssid;
            int desired_channel = 0;
            int desired_op_class = 0;
            const struct mmwlan_s1g_channel *profile_channel = NULL;
            const struct mmwlan_s1g_channel *param_channel = NULL;

            if (current_ssid != NULL || configured_ssid != NULL)
            {
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: profile candidates current(chan=%d op_class=%d s1g_prim=%d) conf(chan=%d op_class=%d s1g_prim=%d)\n",
                       current_ssid ? current_ssid->channel : -1,
                       current_ssid ? current_ssid->op_class : -1,
                       current_ssid ? current_ssid->s1g_prim_channel : -1,
                       configured_ssid ? configured_ssid->channel : -1,
                       configured_ssid ? configured_ssid->op_class : -1,
                       configured_ssid ? configured_ssid->s1g_prim_channel : -1);
            }

            if (current_ssid != NULL && current_ssid->s1g_prim_channel > 0)
            {
                desired_channel = current_ssid->s1g_prim_channel;
                desired_op_class = current_ssid->op_class;
            }
            else if (current_ssid != NULL && current_ssid->channel > 0)
            {
                desired_channel = current_ssid->channel;
                desired_op_class = current_ssid->op_class;
            }
            else if (configured_ssid != NULL && configured_ssid->s1g_prim_channel > 0)
            {
                desired_channel = configured_ssid->s1g_prim_channel;
                desired_op_class = configured_ssid->op_class;
            }
            else if (configured_ssid != NULL && configured_ssid->channel > 0)
            {
                desired_channel = configured_ssid->channel;
                desired_op_class = configured_ssid->op_class;
            }

            if (current_ssid != NULL && configured_ssid != NULL &&
                (current_ssid->channel != configured_ssid->channel ||
                 current_ssid->op_class != configured_ssid->op_class))
            {
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: profile mismatch current(op_class=%d chan=%d) conf(op_class=%d chan=%d)\n",
                       current_ssid->op_class,
                       current_ssid->channel,
                       configured_ssid->op_class,
                       configured_ssid->channel);
            }

            if (desired_channel > 0)
            {
                profile_channel = umac_regdb_get_channel(umacd, (uint8_t)desired_channel);
            }

            if (params->freq.channel > 0)
            {
                param_channel = umac_regdb_get_channel(umacd, (uint8_t)params->freq.channel);
            }

            if (profile_channel != NULL && param_channel == NULL)
            {
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: overriding bootstrap freq.channel hint=%d with profile S1G channel=%d op_class=%d\n",
                       params->freq.channel,
                       desired_channel,
                       desired_op_class);
                params->freq.channel = desired_channel;
            }
        }

        if (!mmwpas_build_mesh_bootstrap_bss_cfg(umacd, params, &bss_cfg, target_bssid))
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap BSS setup failed; mesh advertising cannot start without peer context\n");
            printf("[MM_INIT_MESH] mmwpas_join_mesh bootstrap_cfg_failed freq=%d freq_khz=%u chan=%d\n",
                   params->freq.freq, params->freq.freq_khz, params->freq.channel);
            return -1;
        }

        have_target_bssid = true;
        bootstrap_mode = true;
        printf("[MM_INIT_MESH] mmwpas_join_mesh bootstrap_cfg_ok bssid=%02x:%02x:%02x:%02x:%02x:%02x op_class=%u chan=%u bw=%u beacon_int=%u\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5],
               (unsigned)bss_cfg.channel_cfg.operating_class,
               (unsigned)bss_cfg.channel_cfg.operating_channel_index,
               (unsigned)bss_cfg.channel_cfg.operation_channel_width_mhz,
               (unsigned)bss_cfg.beacon_interval);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: bootstrap advertiser mode enabled bssid=%02x:%02x:%02x:%02x:%02x:%02x op_class=%u chan=%u bw=%u beacon_int=%u\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5],
               (unsigned)bss_cfg.channel_cfg.operating_class,
               (unsigned)bss_cfg.channel_cfg.operating_channel_index,
               (unsigned)bss_cfg.channel_cfg.operation_channel_width_mhz,
               (unsigned)bss_cfg.beacon_interval);
    }

    if (!bootstrap_mode && !mmwpas_bss_cache_lookup(data, target_bssid, &bss_cfg))
    {
        printf("[MM_INIT_MESH] mmwpas_join_mesh bss_cache_lookup_failed target=%02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1], target_bssid[2],
               target_bssid[3], target_bssid[4], target_bssid[5]);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: BSS cache lookup failed for %02x:%02x:%02x:%02x:%02x:%02x\n",
               target_bssid[0], target_bssid[1],
               target_bssid[2], target_bssid[3],
               target_bssid[4], target_bssid[5]);
        return -1;
    }

    if (sta_args != NULL && sta_args->mesh_mode)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: mesh_mode active, keeping beacon_int=%u\n",
               (unsigned)bss_cfg.beacon_interval);
    }

    conn_state = umac_connection_get_conn_fsm_state(umacd);
    printf("[MM_INIT_MESH] mmwpas_join_mesh set_bss begin mode=%s conn_fsm=%u(%s) target=%02x:%02x:%02x:%02x:%02x:%02x beacon_int=%u op_class=%u chan=%u bw=%u\n",
           bootstrap_mode ? "bootstrap" : "peer",
           (unsigned)conn_state,
           umac_connection_conn_fsm_state_tostr(conn_state),
           target_bssid[0], target_bssid[1], target_bssid[2],
           target_bssid[3], target_bssid[4], target_bssid[5],
           (unsigned)bss_cfg.beacon_interval,
           (unsigned)bss_cfg.channel_cfg.operating_class,
           (unsigned)bss_cfg.channel_cfg.operating_channel_index,
           (unsigned)bss_cfg.channel_cfg.operation_channel_width_mhz);
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: conn_fsm before set_bss_cfg=%u (%s)\n",
           (unsigned)conn_state,
           umac_connection_conn_fsm_state_tostr(conn_state));

    status = umac_connection_set_bss_cfg(umacd, target_bssid, &bss_cfg);
    if (status != MMWLAN_SUCCESS)
    {
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: umac_connection_set_bss_cfg failed status=%d\n", status);
        printf("[MM_INIT_MESH] mmwpas_join_mesh set_bss failed status=%d\n", status);
        return -1;
    }

    conn_state = umac_connection_get_conn_fsm_state(umacd);
    printf("[MM_INIT_MESH] mmwpas_join_mesh set_bss ok conn_fsm=%u(%s)\n",
           (unsigned)conn_state,
           umac_connection_conn_fsm_state_tostr(conn_state));
    MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: conn_fsm after set_bss_cfg=%u (%s)\n",
           (unsigned)conn_state,
           umac_connection_conn_fsm_state_tostr(conn_state));

    if (wpa_s != NULL)
    {
        if (wpa_s->current_bss != NULL &&
            mm_mac_addr_is_equal(wpa_s->current_bss->bssid, target_bssid))
        {
            mesh_peer_bss = wpa_s->current_bss;
        }

        if (mesh_peer_bss == NULL)
        {
            mesh_peer_bss = wpa_bss_get_bssid_latest(wpa_s, target_bssid);
        }

        if (mesh_peer_bss == NULL)
        {
            mesh_peer_bss = wpa_bss_get_bssid(wpa_s, target_bssid);
        }

        if (mesh_peer_bss != NULL)
        {
            const u8 *peer_ies = NULL;
            size_t peer_ie_len = 0;
            uint8_t sanitized_ies[256] = { 0 };
            size_t sanitized_ie_len = 0;

            if (mesh_peer_bss->ie_len > 0)
            {
                peer_ies = wpa_bss_ie_ptr(mesh_peer_bss);
                peer_ie_len = mesh_peer_bss->ie_len;
            }
            else if (mesh_peer_bss->beacon_ie_len > 0)
            {
                peer_ies = wpa_bss_ie_ptr(mesh_peer_bss) + mesh_peer_bss->ie_len;
                peer_ie_len = mesh_peer_bss->beacon_ie_len;
            }

            if (peer_ies == NULL || peer_ie_len == 0)
            {
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: peer-candidate injection skipped (bss=%p ie_len=%u beacon_ie_len=%u)\n",
                       (void *)mesh_peer_bss,
                       (unsigned)mesh_peer_bss->ie_len,
                       (unsigned)mesh_peer_bss->beacon_ie_len);
            }
            else
            {
                 struct ieee802_11_elems elems = { 0 };
                 ParseRes pres;
                pres = ieee802_11_parse_elems(peer_ies, peer_ie_len, &elems, 0);
                if (pres != ParseFailed)
                {
                    MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: peer IE summary (initial) parse=%d len=%u mesh_id=%u mesh_cfg=%u rsn=%u supp=%u ext_supp=%u\n",
                           (int)pres,
                           (unsigned)peer_ie_len,
                           (unsigned)elems.mesh_id_len,
                           (unsigned)elems.mesh_config_len,
                           (unsigned)elems.rsn_ie_len,
                           (unsigned)elems.supp_rates_len,
                           (unsigned)elems.ext_supp_rates_len);
                }
                if (pres == ParseFailed && mesh_peer_bss->beacon_ie_len > 0 &&
                    peer_ies == wpa_bss_ie_ptr(mesh_peer_bss))
                {
                    const u8 *beacon_ies = wpa_bss_ie_ptr(mesh_peer_bss) + mesh_peer_bss->ie_len;
                    size_t beacon_ie_len = mesh_peer_bss->beacon_ie_len;
                    struct ieee802_11_elems beacon_elems = { 0 };
                    ParseRes beacon_pres = ieee802_11_parse_elems(beacon_ies, beacon_ie_len,
                                                                  &beacon_elems, 0);
                    if (beacon_pres != ParseFailed)
                    {
                        peer_ies = beacon_ies;
                        peer_ie_len = beacon_ie_len;
                        elems = beacon_elems;
                        pres = beacon_pres;
                        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: switched peer IE source to beacon IEs (probe parse failed, beacon parse=%d len=%u)\n",
                               (int)beacon_pres,
                               (unsigned)beacon_ie_len);
                    }
                    else
                    {
                        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: both probe and beacon IE parse failed (probe_len=%u beacon_len=%u)\n",
                               (unsigned)mesh_peer_bss->ie_len,
                               (unsigned)mesh_peer_bss->beacon_ie_len);
                    }
                }

                /*
                 * Some probe responses carry insufficient mesh peer context
                 * (e.g. missing mesh config or supported rates). Prefer beacon
                 * IEs when available in that case.
                 */
                if (pres != ParseFailed &&
                    ((elems.mesh_config_len == 0) ||
                     ((elems.supp_rates_len == 0) && (elems.ext_supp_rates_len == 0))) &&
                    mesh_peer_bss->beacon_ie_len > 0 &&
                    peer_ies == wpa_bss_ie_ptr(mesh_peer_bss))
                {
                    const u8 *beacon_ies = wpa_bss_ie_ptr(mesh_peer_bss) + mesh_peer_bss->ie_len;
                    size_t beacon_ie_len = mesh_peer_bss->beacon_ie_len;
                    struct ieee802_11_elems beacon_elems = { 0 };
                    ParseRes beacon_pres = ieee802_11_parse_elems(beacon_ies, beacon_ie_len,
                                                                  &beacon_elems, 0);
                    if (beacon_pres != ParseFailed &&
                        (beacon_elems.mesh_config_len > elems.mesh_config_len ||
                         beacon_elems.supp_rates_len > elems.supp_rates_len ||
                         beacon_elems.ext_supp_rates_len > elems.ext_supp_rates_len))
                    {
                        peer_ies = beacon_ies;
                        peer_ie_len = beacon_ie_len;
                        elems = beacon_elems;
                        pres = beacon_pres;
                        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: switched peer IE source to beacon IEs (probe missing mesh fields, beacon parse=%d len=%u mesh_cfg=%u supp=%u ext_supp=%u)\n",
                               (int)beacon_pres,
                               (unsigned)beacon_ie_len,
                               (unsigned)beacon_elems.mesh_config_len,
                               (unsigned)beacon_elems.supp_rates_len,
                               (unsigned)beacon_elems.ext_supp_rates_len);
                    }
                }

                if (pres == ParseFailed ||
                    elems.mesh_config_len == 0 ||
                    (elems.supp_rates_len == 0 && elems.ext_supp_rates_len == 0))
                {
                    bool ok = true;
                    const uint8_t *supp_rates_ie = wpa_bss_get_ie(mesh_peer_bss, WLAN_EID_SUPP_RATES);
                    const uint8_t *ext_supp_rates_ie = wpa_bss_get_ie(mesh_peer_bss, WLAN_EID_EXT_SUPP_RATES);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_SUPP_RATES,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_EXT_SUPP_RATES,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_MESH_ID,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_MESH_CONFIG,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_RSN,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_RSNX,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_HT_CAP,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_HT_OPERATION,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_VHT_CAP,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);
                    ok &= mmwpas_append_bss_ie(mesh_peer_bss,
                                               WLAN_EID_VHT_OPERATION,
                                               sanitized_ies,
                                               sizeof(sanitized_ies),
                                               &sanitized_ie_len);

                    if (ok &&
                        ((supp_rates_ie == NULL || supp_rates_ie[1] == 0) &&
                         (ext_supp_rates_ie == NULL || ext_supp_rates_ie[1] == 0)))
                    {
                        static const uint8_t fallback_supp_rates[] = {
                            0x02, 0x04, 0x0b, 0x8c, 0x16, 0x98, 0x24, 0xb0
                        };
                        static const uint8_t fallback_ext_supp_rates[] = {
                            0x09, 0x0d, 0x0e, 0x11, 0x12, 0x19, 0x1b, 0x1e
                        };
                        ok &= mmwpas_append_raw_ie(WLAN_EID_SUPP_RATES,
                                                   fallback_supp_rates,
                                                   sizeof(fallback_supp_rates),
                                                   sanitized_ies,
                                                   sizeof(sanitized_ies),
                                                   &sanitized_ie_len);
                        ok &= mmwpas_append_raw_ie(WLAN_EID_EXT_SUPP_RATES,
                                                   fallback_ext_supp_rates,
                                                   sizeof(fallback_ext_supp_rates),
                                                   sanitized_ies,
                                                   sizeof(sanitized_ies),
                                                   &sanitized_ie_len);
                        if (ok)
                        {
                            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: injected fallback Supported/Extended Rates IEs for mesh peer\n");
                        }
                    }

                    if (!ok || sanitized_ie_len == 0)
                    {
                        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: sanitized IE build failed (ok=%u len=%u)\n",
                               ok ? 1U : 0U,
                               (unsigned)sanitized_ie_len);
                    }
                    else
                    {
                        struct ieee802_11_elems sanitized_elems = { 0 };
                        ParseRes sanitized_pres = ieee802_11_parse_elems(sanitized_ies,
                                                                         sanitized_ie_len,
                                                                         &sanitized_elems,
                                                                         0);
                        if (sanitized_pres != ParseFailed)
                        {
                            peer_ies = sanitized_ies;
                            peer_ie_len = sanitized_ie_len;
                            elems = sanitized_elems;
                            pres = sanitized_pres;
                            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: using sanitized peer IEs (parse=%d len=%u mesh_id=%u mesh_cfg=%u rsn=%u supp=%u ext_supp=%u)\n",
                                   (int)sanitized_pres,
                                   (unsigned)sanitized_ie_len,
                                   (unsigned)sanitized_elems.mesh_id_len,
                                   (unsigned)sanitized_elems.mesh_config_len,
                                   (unsigned)sanitized_elems.rsn_ie_len,
                                   (unsigned)sanitized_elems.supp_rates_len,
                                   (unsigned)sanitized_elems.ext_supp_rates_len);
                        }
                        else
                        {
                            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: sanitized IE parse failed (len=%u)\n",
                                   (unsigned)sanitized_ie_len);
                        }
                    }
                }

                if (pres == ParseFailed)
                 {
                  MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: direct wpa_mesh_new_mesh_peer skipped (IE parse failed, len=%u)\n",
                      (unsigned)peer_ie_len);
                 }
                 else
                 {
                  if (elems.mesh_config_len == 0 ||
                      (elems.supp_rates_len == 0 && elems.ext_supp_rates_len == 0))
                  {
                      MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: WARN peer IEs still incomplete before new_peer (mesh_cfg=%u supp=%u ext_supp=%u)\n",
                             (unsigned)elems.mesh_config_len,
                             (unsigned)elems.supp_rates_len,
                             (unsigned)elems.ext_supp_rates_len);
                  }
#if defined(CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY) && CONFIG_MM_MESHTASTIC_DISCOVERY_ONLY
                  MESH_DBG_PRINTF("[mesh_meshtastic] discovery-only: suppress wpa_mesh_new_mesh_peer for %02x:%02x:%02x:%02x:%02x:%02x\n",
                      target_bssid[0], target_bssid[1],
                      target_bssid[2], target_bssid[3],
                      target_bssid[4], target_bssid[5]);
#elif defined(CONFIG_MM_EXPERIMENTAL_MESH_BEACON_TEST_ONLY) && CONFIG_MM_EXPERIMENTAL_MESH_BEACON_TEST_ONLY
                  MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: direct wpa_mesh_new_mesh_peer suppressed (BEACON_TEST_ONLY=1)\n");
#else
                  wpa_mesh_new_mesh_peer(wpa_s, target_bssid, &elems);
                  MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: direct wpa_mesh_new_mesh_peer invoked for %02x:%02x:%02x:%02x:%02x:%02x (parse=%d)\n",
                      target_bssid[0], target_bssid[1],
                      target_bssid[2], target_bssid[3],
                      target_bssid[4], target_bssid[5],
                      (int)pres);
#endif
                 }
                 MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: mesh peer trigger payload ready for %02x:%02x:%02x:%02x:%02x:%02x (ie_len=%u)\n",
                   target_bssid[0], target_bssid[1],
                   target_bssid[2], target_bssid[3],
                   target_bssid[4], target_bssid[5],
                   (unsigned)peer_ie_len);
            }
        }
        else
        {
            MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: peer-candidate injection skipped (current_bss=%p lookup_bss=%p target_match=%u)\n",
                   (void *)wpa_s->current_bss,
                   (void *)mesh_peer_bss,
                   (wpa_s->current_bss && mm_mac_addr_is_equal(wpa_s->current_bss->bssid, target_bssid)) ? 1U : 0U);
        }
    }

        printf("[MM_INIT_MESH] mmwpas_join_mesh done mode=%s target=%02x:%02x:%02x:%02x:%02x:%02x peer_bss=%p\n",
           bootstrap_mode ? "bootstrap-advertiser" : "peer-join",
           target_bssid[0], target_bssid[1],
           target_bssid[2], target_bssid[3],
           target_bssid[4], target_bssid[5],
           (void *)mesh_peer_bss);
        MESH_DBG_PRINTF("[mesh_trace] mmwpas_join_mesh: BSS configured for %02x:%02x:%02x:%02x:%02x:%02x mode=%s; waiting for mesh peering/auth state machine\n",
           target_bssid[0], target_bssid[1],
           target_bssid[2], target_bssid[3],
            target_bssid[4], target_bssid[5],
            bootstrap_mode ? "bootstrap-advertiser" : "peer-join");

    return 0;
}

static int mmwpas_leave_mesh(void *priv)
{
    struct umac_data *umacd = (struct umac_data *)priv;
    uint8_t bssid[DOT11_MAC_ADDR_LEN] = { 0 };

    if (umac_connection_get_bssid(umacd, bssid) == MMWLAN_SUCCESS)
    {
        uint8_t own_addr[DOT11_MAC_ADDR_LEN] = { 0 };
        struct frame_data_deauth deauth_params = {
            .bssid = bssid,
            .sta_address = own_addr,
            .reason_code = DOT11_REASON_UNSPECIFIED,
        };

        if (umac_interface_get_vif_mac_addr(umacd, MMWLAN_VIF_STA, own_addr) == MMWLAN_SUCCESS)
        {
            if (umac_connection_process_deauth_tx(umacd, &deauth_params) == MMWLAN_SUCCESS)
            {
                umac_connection_signal_sta_event(umacd, MMWLAN_STA_EVT_DEAUTH_TX);
                MESH_DBG_PRINTF("[mesh_trace] mmwpas_leave_mesh: deauth queued for %02x:%02x:%02x:%02x:%02x:%02x\n",
                       bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                return 0;
            }
        }
    }

    MESH_DBG_PRINTF("[mesh_trace] mmwpas_leave_mesh: no active mesh bssid to deauth\n");
    return 0;
}

const struct wpa_driver_ops mmwlan_wpas_ops = {
    .name = UMAC_SUPP_STA_DRIVER_NAME,
    .desc = "",
    .init = mmwpas_init,
    .deinit = mmwpas_deinit,
    .get_capa = mmwpas_get_capa,
    .get_hw_feature_data = mmwpas_get_hw_feature_data,
    .get_mac_addr = mmwpas_get_mac_addr,
    .scan2 = mmwpas_scan2,
    .get_scan_results2 = mmwpas_get_scan_results2,
    .abort_scan = mmwpas_abort_scan,
    .authenticate = mmwpas_authenticate,
    .associate = mmwpas_associate,
    .get_bssid = mmwpas_get_bssid,
    .get_ssid = mmwpas_get_ssid,
    .set_supp_port = mmwpas_set_supp_port,
    .sta_add = mmwpas_sta_add,
    .sta_remove = mmwpas_sta_remove,
    .deauthenticate = mmwpas_deauthenticate,
    .set_key = mmwpas_set_key,
    .send_mlme = mmwpas_send_mlme,
    .send_action = mmwpas_send_action,
    .remain_on_channel = mmwpas_remain_on_channel,
    .cancel_remain_on_channel = mmwpas_cancel_remain_on_channel,
    .wnm_oper = mmwpas_wnm_oper,
    .signal_monitor = mmwpas_signal_monitor,
    .init_mesh = mmwpas_init_mesh,
    .join_mesh = mmwpas_join_mesh,
    .leave_mesh = mmwpas_leave_mesh,
};
