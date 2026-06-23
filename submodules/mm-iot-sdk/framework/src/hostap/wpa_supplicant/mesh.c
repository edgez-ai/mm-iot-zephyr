/*
 * Minimal mesh-mode glue for the Morse Micro Meshtastic raw bearer.
 *
 * The full hostap mesh implementation depends on the AP/authenticator stack.
 * This target uses the driver-backed raw bearer path instead: configure mesh
 * join parameters, call the Morse driver shim, and let morselib handle the
 * raw 802.11s data path.
 */

#include "includes.h"

#include "common.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "config_ssid.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "notify.h"
#include "mesh.h"

#ifndef MESH_DBG_PRINTF
#ifdef CONFIG_MM_MESH_DEBUG_LOG
#define MESH_DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define MESH_DBG_PRINTF(...) do {} while (0)
#endif
#endif

void wpa_supplicant_mesh_iface_deinit(struct wpa_supplicant *wpa_s,
				      struct hostapd_iface *ifmsh,
				      bool also_clear_hostapd)
{
	(void) ifmsh;
	(void) also_clear_hostapd;

	if (!wpa_s)
		return;

	os_free(wpa_s->mesh_params);
	wpa_s->mesh_params = NULL;
	wpa_s->ifmsh = NULL;
	wpa_s->current_ssid = NULL;
}

int wpa_supplicant_join_mesh(struct wpa_supplicant *wpa_s,
			     struct wpa_ssid *ssid)
{
	struct wpa_driver_mesh_join_params *params;
	int ret;

	if (!wpa_s || !ssid || !ssid->ssid || !ssid->ssid_len)
		return -ENOENT;

	params = os_zalloc(sizeof(*params));
	if (!params)
		return -ENOMEM;

	wpa_supplicant_mesh_iface_deinit(wpa_s, wpa_s->ifmsh, true);

	params->meshid = ssid->ssid;
	params->meshid_len = ssid->ssid_len;
	params->freq.freq = ssid->frequency;
	params->freq.freq_khz = ssid->frequency_khz;
	params->freq.channel = ssid->channel;
	params->beacon_int = ssid->beacon_int ? ssid->beacon_int : 100;
	params->dtim_period = ssid->dtim_period ? ssid->dtim_period : 1;
	params->flags |= WPA_DRIVER_MESH_FLAG_DRIVER_MPM;
	params->conf.auto_plinks = 1;
	params->conf.peer_link_timeout = 0;
	params->conf.flags |= WPA_DRIVER_MESH_CONF_FLAG_FORWARDING;
	params->conf.forwarding = ssid->mesh_fwding;

	wpa_s->current_ssid = ssid;
	wpa_s->mesh_params = params;

	printf("[MM_INIT_MESH] hostap_join_mesh begin meshid=\"%s\" len=%u freq=%d freq_khz=%u chan=%d beacon_int=%u dtim=%u no_auto_peer=%d beaconless=%d fwd=%d flags=0x%x\n",
	       wpa_ssid_txt(ssid->ssid, ssid->ssid_len),
	       (unsigned)ssid->ssid_len,
	       ssid->frequency,
	       ssid->frequency_khz,
	       ssid->channel,
	       (unsigned)params->beacon_int,
	       (unsigned)params->dtim_period,
	       ssid->no_auto_peer,
	       ssid->mesh_beaconless_mode,
	       ssid->mesh_fwding,
	       params->flags);
	wpa_msg(wpa_s, MSG_INFO,
		"[mesh_meshtastic] raw bearer join meshid=\"%s\" len=%u channel=%d freq=%d freq_khz=%u",
		wpa_ssid_txt(ssid->ssid, ssid->ssid_len),
		(unsigned) ssid->ssid_len,
		ssid->channel,
		ssid->frequency,
		ssid->frequency_khz);
	MESH_DBG_PRINTF("[mesh_meshtastic] raw bearer join channel=%d freq=%d freq_khz=%u\n",
			ssid->channel, ssid->frequency, ssid->frequency_khz);

	ret = wpa_drv_join_mesh(wpa_s, params);
	printf("[MM_INIT_MESH] hostap_join_mesh driver_ret=%d current_bss=%p current_ssid=%p mesh_params=%p\n",
	       ret, (void *)wpa_s->current_bss, (void *)wpa_s->current_ssid,
	       (void *)wpa_s->mesh_params);
	if (ret) {
		wpa_msg(wpa_s, MSG_ERROR, "[mesh_meshtastic] raw bearer join failed");
		wpa_supplicant_mesh_iface_deinit(wpa_s, NULL, true);
		return ret;
	}

	wpa_s->reassociate = 0;
	wpa_s->disconnected = 0;
	wpa_supplicant_set_state(wpa_s, WPA_ASSOCIATED);
	wpas_notify_mesh_group_started(wpa_s, ssid);
	printf("[MM_INIT_MESH] hostap_join_mesh associated state=%d reassociate=%d disconnected=%d\n",
	       wpa_s->wpa_state, wpa_s->reassociate, wpa_s->disconnected);
	return 0;
}

int wpa_supplicant_leave_mesh(struct wpa_supplicant *wpa_s, bool need_deinit)
{
	if (!wpa_s)
		return -1;

	wpa_drv_leave_mesh(wpa_s);
	wpa_supplicant_set_state(wpa_s, WPA_DISCONNECTED);
	if (need_deinit)
		wpa_supplicant_mesh_iface_deinit(wpa_s, wpa_s->ifmsh, true);
	return 0;
}

void wpa_mesh_notify_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  const u8 *ies, size_t ie_len)
{
	(void) wpa_s;
	(void) addr;
	(void) ies;
	(void) ie_len;
}

void wpa_supplicant_mesh_add_scan_ie(struct wpa_supplicant *wpa_s,
				     struct wpabuf **extra_ie)
{
	(void) wpa_s;
	(void) extra_ie;
}

int mesh_iface_wpa_get_status(struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	(void) wpa_s;
	if (!buf || buflen == 0)
		return 0;
	buf[0] = '\0';
	return 0;
}

int wpas_mesh_scan_result_text(const u8 *ies, size_t ies_len, char *buf,
			       char *end)
{
	struct ieee802_11_elems elems;
	char *pos = buf;
	int ret;

	if (!buf || !end || buf >= end)
		return 0;

	if (ieee802_11_parse_elems(ies, ies_len, &elems, 0) == ParseFailed ||
	    !elems.mesh_id || elems.mesh_id_len == 0)
		return 0;

	ret = os_snprintf(pos, end - pos, "mesh_id=%s\n",
			  wpa_ssid_txt(elems.mesh_id, elems.mesh_id_len));
	if (os_snprintf_error(end - pos, ret))
		return pos - buf;
	pos += ret;

	return pos - buf;
}

int wpas_mesh_add_interface(struct wpa_supplicant *wpa_s, char *ifname,
			    size_t len)
{
	(void) wpa_s;
	(void) ifname;
	(void) len;
	return -1;
}

int wpas_mesh_peer_remove(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	(void) wpa_s;
	(void) addr;
	return -1;
}

int wpas_mesh_peer_add(struct wpa_supplicant *wpa_s, const u8 *addr,
		       int duration)
{
	(void) wpa_s;
	(void) addr;
	(void) duration;
	return -1;
}
