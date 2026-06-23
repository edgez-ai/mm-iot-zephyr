/*
 * Raw-bearer mesh stubs for the MM-IoT Zephyr Meshtastic profile.
 *
 * The Morse driver owns peer handling for this target.  These no-op symbols
 * keep CONFIG_MESH event hooks linkable without pulling in hostapd AP/RSN.
 */

#include "includes.h"

#include "common.h"
#include "common/defs.h"
#include "common/ieee802_11_defs.h"
#include "drivers/driver.h"

struct hostapd_data;
struct hostapd_iface;
struct ieee802_11_elems;
struct sta_info;
struct wpa_supplicant;

void wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			    struct ieee802_11_elems *elems)
{
	(void) wpa_s;
	(void) addr;
	(void) elems;
}

void mesh_mpm_deinit(struct wpa_supplicant *wpa_s, struct hostapd_iface *ifmsh)
{
	(void) wpa_s;
	(void) ifmsh;
}

void mesh_mpm_auth_peer(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	(void) wpa_s;
	(void) addr;
}

void mesh_mpm_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	(void) hapd;
	(void) sta;
}

void wpa_mesh_set_plink_state(struct wpa_supplicant *wpa_s,
			      struct sta_info *sta,
			      enum mesh_plink_state state)
{
	(void) wpa_s;
	(void) sta;
	(void) state;
}

int mesh_mpm_close_peer(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	(void) wpa_s;
	(void) addr;
	return -1;
}

int mesh_mpm_connect_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  int duration)
{
	(void) wpa_s;
	(void) addr;
	(void) duration;
	return -1;
}

void mesh_mpm_action_rx(struct wpa_supplicant *wpa_s,
			const struct ieee80211_mgmt *mgmt, size_t len)
{
	(void) wpa_s;
	(void) mgmt;
	(void) len;
}

void mesh_mpm_mgmt_rx(struct wpa_supplicant *wpa_s, struct rx_mgmt *rx_mgmt)
{
	(void) wpa_s;
	(void) rx_mgmt;
}

#ifdef CONFIG_IEEE80211AH
void mesh_mpm_kickout_peer(struct hostapd_data *hapd)
{
	(void) hapd;
}
#endif /* CONFIG_IEEE80211AH */
