#include "utils/morse.h"
#include "mmosal.h"

#ifdef MM_IOT

static bool g_mesh_probe_checked;
static bool g_mesh_probe_ok;

static int morse_mesh_backend_ready(void)
{
    if (g_mesh_probe_checked) {
        return g_mesh_probe_ok ? 0 : -1;
    }

    g_mesh_probe_checked = true;
    g_mesh_probe_ok = true;
    mmosal_printf("morse_mesh_backend_mm_iot: mesh backend accepted\n");
    return 0;
}

int morse_set_mesh_config(const char *ifname, u8 *mesh_id, u8 mesh_id_len, u8 beaconless_mode,
                          u8 max_plinks)
{
    if (morse_mesh_backend_ready() != 0) {
        return -1;
    }

    if (!ifname || !mesh_id || mesh_id_len == 0 || mesh_id_len > SSID_MAX_LEN) {
        mmosal_printf("morse_set_mesh_config: invalid params ifname=%p mesh_id=%p len=%u\n",
                      (const void *) ifname, (const void *) mesh_id, (unsigned) mesh_id_len);
        return -1;
    }

    mmosal_printf("morse_set_mesh_config: accepted if=%s mesh_id_len=%u beaconless=%u max_plinks=%u\n",
                  ifname, (unsigned) mesh_id_len, (unsigned) beaconless_mode, (unsigned) max_plinks);
    return 0;
}

int morse_mbca_conf(const char *ifname, u8 mbca_config, u8 min_beacon_gap, u8 tbtt_adj_interval,
                    u8 beacon_timing_report_interval, u16 mbss_start_scan_duration)
{
    if (morse_mesh_backend_ready() != 0) {
        return -1;
    }

    if (!ifname) {
        mmosal_printf("morse_mbca_conf: invalid ifname\n");
        return -1;
    }

    mmosal_printf("morse_mbca_conf: accepted if=%s cfg=0x%02x gap=%u tbtt_adj=%u btr=%u scan_dur=%u\n",
                  ifname,
                  (unsigned) mbca_config,
                  (unsigned) min_beacon_gap,
                  (unsigned) tbtt_adj_interval,
                  (unsigned) beacon_timing_report_interval,
                  (unsigned) mbss_start_scan_duration);
    return 0;
}

int morse_set_mesh_dynamic_peering(const char *ifname, bool enabled, u8 rssi_margin,
                                   u32 blacklist_timeout)
{
    if (morse_mesh_backend_ready() != 0) {
        return -1;
    }

    if (!ifname) {
        mmosal_printf("morse_set_mesh_dynamic_peering: invalid ifname\n");
        return -1;
    }

    mmosal_printf("morse_set_mesh_dynamic_peering: accepted if=%s enabled=%u rssi_margin=%u blacklist_timeout=%u\n",
                  ifname,
                  (unsigned) enabled,
                  (unsigned) rssi_margin,
                  (unsigned) blacklist_timeout);
    return 0;
}

#endif /* MM_IOT */
