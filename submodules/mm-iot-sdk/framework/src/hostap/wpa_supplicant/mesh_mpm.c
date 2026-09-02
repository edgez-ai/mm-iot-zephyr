/*
 * WPA Supplicant - Basic mesh peer management
 * Copyright (c) 2013-2014, cozybit, Inc.  All rights reserved.
 * Copyright 2023 Morse Micro
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/hw_features_common.h"
#include "common/ocv.h"
#include "ap/hostapd.h"
#include "ap/sta_info.h"
#include "ap/ieee802_11.h"
#include "ap/beacon.h"
#include "ap/wpa_auth.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "mesh_mpm.h"
#include "mesh_rsn.h"
#include "notify.h"

#ifdef ESP_PLATFORM
#include "esp_log.h"
#define PEER_DIAG_LOGI(...) do {} while (0)
#else
#define PEER_DIAG_LOGI(...) wpa_printf(MSG_INFO, __VA_ARGS__)
#endif

/* Mesh debug trace gate – controlled by CONFIG_MM_MESH_DEBUG_LOG in menuconfig */
#ifndef MESH_DBG_PRINTF
#ifdef CONFIG_MM_MESH_DEBUG_LOG
#define MESH_DBG_PRINTF(...) printf(__VA_ARGS__)
#else
#define MESH_DBG_PRINTF(...) do {} while(0)
#endif
#endif

struct mesh_peer_mgmt_ie {
	const u8 *proto_id; /* Mesh Peering Protocol Identifier (2 octets) */
	const u8 *llid; /* Local Link ID (2 octets) */
	const u8 *plid; /* Peer Link ID (conditional, 2 octets) */
	const u8 *reason; /* Reason Code (conditional, 2 octets) */
	const u8 *chosen_pmk; /* Chosen PMK (optional, 16 octets) */
};

static u32 mesh_dbg_fnv1a32(const u8 *buf, size_t len)
{
	u32 hash = 2166136261u;
	size_t i;

	for (i = 0; i < len; i++) {
		hash ^= buf[i];
		hash *= 16777619u;
	}

	return hash;
}

static void plink_timer(void *eloop_ctx, void *user_data);


enum plink_event {
	PLINK_UNDEFINED,
	OPN_ACPT,
	OPN_RJCT,
	CNF_ACPT,
	CNF_RJCT,
	CLS_ACPT,
	REQ_RJCT
};

static const char * const mplstate[] = {
	[0] = "UNINITIALIZED",
	[PLINK_IDLE] = "IDLE",
	[PLINK_OPN_SNT] = "OPN_SNT",
	[PLINK_OPN_RCVD] = "OPN_RCVD",
	[PLINK_CNF_RCVD] = "CNF_RCVD",
	[PLINK_ESTAB] = "ESTAB",
	[PLINK_HOLDING] = "HOLDING",
	[PLINK_BLOCKED] = "BLOCKED"
};

/* Failed SAE/MPM attempts can consume the small firmware management packet
 * pool faster than it is replenished. Keep this table deliberately tiny: it
 * only has to suppress immediate re-admission churn, not act as a persistent
 * blacklist. */
#define MESH_PEER_BACKOFF_SLOTS 8
#define MESH_PEER_BACKOFF_SECONDS 5

struct mesh_peer_backoff_entry {
	int valid;
	u8 addr[ETH_ALEN];
	struct os_reltime started;
};

static struct mesh_peer_backoff_entry
	mesh_peer_backoff[MESH_PEER_BACKOFF_SLOTS];
static unsigned int mesh_peer_backoff_replace_index;

static int mesh_peer_backoff_active(const u8 *addr)
{
	struct os_reltime now;
	size_t i;

	os_get_reltime(&now);
	for (i = 0; i < ARRAY_SIZE(mesh_peer_backoff); i++) {
		struct mesh_peer_backoff_entry *entry = &mesh_peer_backoff[i];

		if (!entry->valid || !ether_addr_equal(entry->addr, addr))
			continue;
		if (os_reltime_expired(&now, &entry->started,
					MESH_PEER_BACKOFF_SECONDS)) {
			entry->valid = 0;
			return 0;
		}
		return 1;
	}

	return 0;
}

static void mesh_peer_backoff_start(const u8 *addr)
{
	struct mesh_peer_backoff_entry *entry = NULL;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mesh_peer_backoff); i++) {
		if (mesh_peer_backoff[i].valid &&
		    ether_addr_equal(mesh_peer_backoff[i].addr, addr)) {
			entry = &mesh_peer_backoff[i];
			break;
		}
		if (!entry && !mesh_peer_backoff[i].valid)
			entry = &mesh_peer_backoff[i];
	}
	if (!entry) {
		entry = &mesh_peer_backoff[mesh_peer_backoff_replace_index];
		mesh_peer_backoff_replace_index =
			(mesh_peer_backoff_replace_index + 1) %
			ARRAY_SIZE(mesh_peer_backoff);
	}

	entry->valid = 1;
	os_memcpy(entry->addr, addr, ETH_ALEN);
	os_get_reltime(&entry->started);
}

static const char * const mplevent[] = {
	[PLINK_UNDEFINED] = "UNDEFINED",
	[OPN_ACPT] = "OPN_ACPT",
	[OPN_RJCT] = "OPN_RJCT",
	[CNF_ACPT] = "CNF_ACPT",
	[CNF_RJCT] = "CNF_RJCT",
	[CLS_ACPT] = "CLS_ACPT",
	[REQ_RJCT] = "REQ_RJCT",
};


static int mesh_mpm_parse_peer_mgmt(struct wpa_supplicant *wpa_s,
				    u8 action_field,
				    const u8 *ie, size_t len,
				    struct mesh_peer_mgmt_ie *mpm_ie)
{
	os_memset(mpm_ie, 0, sizeof(*mpm_ie));

	/* Remove optional Chosen PMK field at end */
	if (len >= SAE_PMKID_LEN) {
		mpm_ie->chosen_pmk = ie + len - SAE_PMKID_LEN;
		len -= SAE_PMKID_LEN;
	}

	if ((action_field == PLINK_OPEN && len != 4) ||
	    (action_field == PLINK_CONFIRM && len != 6) ||
	    (action_field == PLINK_CLOSE && len != 6 && len != 8)) {
		wpa_msg(wpa_s, MSG_DEBUG, "MPM: Invalid peer mgmt ie");
		return -1;
	}

	/* required fields */
	if (len < 4)
		return -1;
	mpm_ie->proto_id = ie;
	mpm_ie->llid = ie + 2;
	ie += 4;
	len -= 4;

	/* close reason is always present at end for close */
	if (action_field == PLINK_CLOSE) {
		if (len < 2)
			return -1;
		mpm_ie->reason = ie + len - 2;
		len -= 2;
	}

	/* Peer Link ID, present for confirm, and possibly close */
	if (len >= 2)
		mpm_ie->plid = ie;

	return 0;
}


static int plink_free_count(struct hostapd_data *hapd)
{
	if (hapd->max_plinks > hapd->num_plinks)
		return hapd->max_plinks - hapd->num_plinks;
	return 0;
}


static u16 copy_supp_rates(struct wpa_supplicant *wpa_s,
			   struct sta_info *sta,
			   struct ieee802_11_elems *elems)
{
	if ((elems->supp_rates_len + elems->ext_supp_rates_len) == 0) {
		/*
		 * Some S1G peers may omit legacy Supported Rates IEs in scan-derived
		 * elements. Keep onboarding alive so SAE/auth can proceed.
		 */
		wpa_msg(wpa_s, MSG_INFO,
			"mesh: no supported rates from " MACSTR " (continuing)",
			MAC2STR(sta->addr));
		sta->supported_rates_len = 0;
		return WLAN_STATUS_SUCCESS;
	}

	if (elems->supp_rates_len + elems->ext_supp_rates_len >
	    sizeof(sta->supported_rates)) {
		wpa_msg(wpa_s, MSG_ERROR,
			"Invalid supported rates element length " MACSTR
			" %d+%d", MAC2STR(sta->addr), elems->supp_rates_len,
			elems->ext_supp_rates_len);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->supported_rates_len = merge_byte_arrays(
		sta->supported_rates, sizeof(sta->supported_rates),
		elems->supp_rates, elems->supp_rates_len,
		elems->ext_supp_rates, elems->ext_supp_rates_len);

	return WLAN_STATUS_SUCCESS;
}


/* return true if elems from a neighbor match this MBSS */
static bool matches_local(struct wpa_supplicant *wpa_s,
			  struct ieee802_11_elems *elems)
{
	struct mesh_conf *mconf = wpa_s->ifmsh->mconf;

	if (elems->mesh_config_len < 5)
		return false;

	return (mconf->meshid_len == elems->mesh_id_len &&
		os_memcmp(mconf->meshid, elems->mesh_id,
			  elems->mesh_id_len) == 0 &&
		mconf->mesh_pp_id == elems->mesh_config[0] &&
		mconf->mesh_pm_id == elems->mesh_config[1] &&
		mconf->mesh_cc_id == elems->mesh_config[2] &&
		mconf->mesh_sp_id == elems->mesh_config[3] &&
		mconf->mesh_auth_id == elems->mesh_config[4]);
}


/* check if local link id is already used with another peer */
static bool llid_in_use(struct wpa_supplicant *wpa_s, u16 llid)
{
	struct sta_info *sta;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];

	for (sta = hapd->sta_list; sta; sta = sta->next) {
		if (sta->my_lid == llid)
			return true;
	}

	return false;
}


/* generate an llid for a link and set to initial state */
static void mesh_mpm_init_link(struct wpa_supplicant *wpa_s,
			       struct sta_info *sta)
{
	u16 llid;

	do {
		if (os_get_random((u8 *) &llid, sizeof(llid)) < 0)
			llid = 0; /* continue */
	} while (!llid || llid_in_use(wpa_s, llid));

	sta->my_lid = llid;
	sta->peer_lid = 0;
	sta->peer_aid = 0;

	/*
	 * We do not use wpa_mesh_set_plink_state() here because there is no
	 * entry in kernel yet.
	 */
	sta->plink_state = PLINK_IDLE;
}


static void mesh_mpm_send_plink_action(struct wpa_supplicant *wpa_s,
				       struct sta_info *sta,
				       enum plink_action_field type,
				       u16 close_reason)
{
	struct wpabuf *buf;
	struct hostapd_iface *ifmsh = wpa_s->ifmsh;
	struct hostapd_data *bss = ifmsh->bss[0];
	struct mesh_conf *conf = ifmsh->mconf;
	u8 supp_rates[2 + 2 + 32];
	u8 *pos, *cat;
	u8 ie_len, add_plid = 0;
	int ret;
	int ampe = conf->security & MESH_CONF_SEC_AMPE;
	size_t buf_len;
	size_t i;
	u32 tx_hash = 0;
	struct sae_data *confirm_sae = NULL;
	u16 confirm_my_lid = 0;
	u16 confirm_peer_lid = 0;
	u8 confirm_aek[8];
	u8 confirm_my_nonce[8];
	u8 confirm_peer_nonce[8];
	u8 confirm_pmkid[8];
	bool confirm_context_valid = false;
	const char *type_name = "UNKNOWN";

	if (!sta)
		return;

	buf_len = 2 +      /* Category and Action */
		  2 +      /* capability info */
		  2 +      /* AID */
		  2 + 8 +  /* supported rates */
		  2 + (32 - 8) +
		  2 + 32 + /* mesh ID */
		  2 + 7 +  /* mesh config */
		  2 + 24 + /* peering management */
		  2 + 96 + 32 + 32 + /* AMPE (96 + max GTKlen + max IGTKlen) */
		  2 + 16;  /* MIC */
#ifdef CONFIG_IEEE80211AH
	if (type != PLINK_CLOSE && bss->iconf->ieee80211ah) {
		buf_len += 2 + sizeof(struct ieee80211_s1g_capabilities) +
			   2 + sizeof(struct ieee80211_s1g_operation);
	}
#endif /* CONFIG_IEEE80211AH */
	if (type != PLINK_CLOSE && wpa_s->mesh_ht_enabled) {
		buf_len += 2 + 26 + /* HT capabilities */
			   2 + 22;  /* HT operation */
	}
#ifdef CONFIG_IEEE80211AC
	if (type != PLINK_CLOSE && wpa_s->mesh_vht_enabled) {
		buf_len += 2 + 12 + /* VHT Capabilities */
			   2 + 5;  /* VHT Operation */
	}
#endif /* CONFIG_IEEE80211AC */
#ifdef CONFIG_IEEE80211AX
	if (type != PLINK_CLOSE && wpa_s->mesh_he_enabled) {
		buf_len += 3 +
			   HE_MAX_MAC_CAPAB_SIZE +
			   HE_MAX_PHY_CAPAB_SIZE +
			   HE_MAX_MCS_CAPAB_SIZE +
			   HE_MAX_PPET_CAPAB_SIZE;
		buf_len += 3 + sizeof(struct ieee80211_he_operation);
		if (is_6ghz_op_class(bss->iconf->op_class))
			buf_len += sizeof(struct ieee80211_he_6ghz_oper_info) +
				3 + sizeof(struct ieee80211_he_6ghz_band_cap);
	}
#endif /* CONFIG_IEEE80211AX */
	if (type != PLINK_CLOSE)
		buf_len += conf->rsn_ie_len; /* RSN IE */
#ifdef CONFIG_OCV
	/* OCI is included even when the other STA doesn't support OCV */
	if (type != PLINK_CLOSE && conf->ocv)
		buf_len += OCV_OCI_EXTENDED_LEN;
#endif /* CONFIG_OCV */
#ifdef CONFIG_IEEE80211BE
	if (type != PLINK_CLOSE && wpa_s->mesh_eht_enabled) {
		buf_len += 3 + 2 + EHT_PHY_CAPAB_LEN + EHT_MCS_NSS_CAPAB_LEN +
			EHT_PPE_THRESH_CAPAB_LEN;
		buf_len += 3 + sizeof(struct ieee80211_eht_operation);
}
#endif /* CONFIG_IEEE80211BE */

	buf = wpabuf_alloc(buf_len);
	if (!buf)
		return;

	cat = wpabuf_mhead_u8(buf);
	wpabuf_put_u8(buf, WLAN_ACTION_SELF_PROTECTED);
	wpabuf_put_u8(buf, type);

	if (type != PLINK_CLOSE) {
		u8 info;

		/* capability info */
		wpabuf_put_le16(buf, ampe ? IEEE80211_CAP_PRIVACY : 0);

		/* aid */
		if (type == PLINK_CONFIRM)
			wpabuf_put_le16(buf, sta->aid);

		/* IE: supp + ext. supp rates — must be present even for S1G
		 * because AMPE AAD3 = first 6 bytes of the action frame body,
		 * which includes the supp_rates IE header at bytes [4..5].
		 * The receiver's Morse driver inserts supp_rates during
		 * S1G→11n conversion, so the TX side must include them too
		 * to keep AAD3 consistent for AES-SIV encrypt/decrypt. */
		pos = hostapd_eid_supp_rates(bss, supp_rates);
		pos = hostapd_eid_ext_supp_rates(bss, pos);
		wpabuf_put_data(buf, supp_rates, pos - supp_rates);

		/* IE: RSN IE */
		wpabuf_put_data(buf, conf->rsn_ie, conf->rsn_ie_len);

		/* IE: Mesh ID */
		wpabuf_put_u8(buf, WLAN_EID_MESH_ID);
		wpabuf_put_u8(buf, conf->meshid_len);
		wpabuf_put_data(buf, conf->meshid, conf->meshid_len);

		/* IE: mesh conf */
		wpabuf_put_u8(buf, WLAN_EID_MESH_CONFIG);
		wpabuf_put_u8(buf, 7);
		wpabuf_put_u8(buf, conf->mesh_pp_id);
		wpabuf_put_u8(buf, conf->mesh_pm_id);
		wpabuf_put_u8(buf, conf->mesh_cc_id);
		wpabuf_put_u8(buf, conf->mesh_sp_id);
		wpabuf_put_u8(buf, conf->mesh_auth_id);
		info = (bss->num_plinks > 63 ? 63 : bss->num_plinks) << 1;
		/* TODO: Add Connected to Mesh Gate/AS subfields */
		wpabuf_put_u8(buf, info);
		/* Set forwarding based on configuration and always accept
		 * plinks for now */
		wpabuf_put_u8(buf, MESH_CAP_ACCEPT_ADDITIONAL_PEER |
			      (conf->mesh_fwding ? MESH_CAP_FORWARDING : 0));
	} else {	/* Peer closing frame */
		/* IE: Mesh ID */
		wpabuf_put_u8(buf, WLAN_EID_MESH_ID);
		wpabuf_put_u8(buf, conf->meshid_len);
		wpabuf_put_data(buf, conf->meshid, conf->meshid_len);
	}

	/* IE: Mesh Peering Management element */
	ie_len = 4;
	if (ampe)
		ie_len += PMKID_LEN;
	switch (type) {
	case PLINK_OPEN:
		type_name = "OPEN";
		break;
	case PLINK_CONFIRM:
		type_name = "CONFIRM";
		ie_len += 2;
		add_plid = 1;
		break;
	case PLINK_CLOSE:
		type_name = "CLOSE";
		ie_len += 2;
		add_plid = 1;
		ie_len += 2; /* reason code */
		break;
	}

	wpabuf_put_u8(buf, WLAN_EID_PEER_MGMT);
	wpabuf_put_u8(buf, ie_len);
	/* peering protocol */
	if (ampe)
		wpabuf_put_le16(buf, 1);
	else
		wpabuf_put_le16(buf, 0);
	wpabuf_put_le16(buf, sta->my_lid);
	if (add_plid)
		wpabuf_put_le16(buf, sta->peer_lid);
	if (type == PLINK_CLOSE)
		wpabuf_put_le16(buf, close_reason);
	if (ampe) {
		if (sta->sae == NULL) {
			wpa_msg(wpa_s, MSG_INFO, "Mesh MPM: no SAE session");
			goto fail;
		}
		mesh_rsn_get_pmkid(wpa_s->mesh_rsn, sta,
				   wpabuf_put(buf, PMKID_LEN));
	}

	if (type == PLINK_CONFIRM && sta->sae) {
		confirm_sae = sta->sae;
		confirm_my_lid = sta->my_lid;
		confirm_peer_lid = sta->peer_lid;
		os_memcpy(confirm_aek, sta->aek, sizeof(confirm_aek));
		os_memcpy(confirm_my_nonce, sta->my_nonce,
			  sizeof(confirm_my_nonce));
		os_memcpy(confirm_peer_nonce, sta->peer_nonce,
			  sizeof(confirm_peer_nonce));
		os_memcpy(confirm_pmkid, sta->sae->pmkid,
			  sizeof(confirm_pmkid));
		confirm_context_valid = true;
		MESH_DBG_PRINTF("[mesh_confirm_ctx] stage=before peer=" MACSTR
				 " phase=%d sae=%p sae_state=%d lids=%04x/%04x"
				 " pmkid=%02x%02x%02x%02x%02x%02x%02x%02x"
				 " aek=%02x%02x%02x%02x%02x%02x%02x%02x"
				 " my_nonce=%02x%02x%02x%02x%02x%02x%02x%02x"
				 " peer_nonce=%02x%02x%02x%02x%02x%02x%02x%02x"
				 " aad3=%02x%02x%02x%02x%02x%02x plain_len=%u\n",
				 MAC2STR(sta->addr), sta->plink_state,
				 sta->sae, sta->sae->state, sta->my_lid, sta->peer_lid,
				 confirm_pmkid[0], confirm_pmkid[1],
				 confirm_pmkid[2], confirm_pmkid[3],
				 confirm_pmkid[4], confirm_pmkid[5],
				 confirm_pmkid[6], confirm_pmkid[7],
				 confirm_aek[0], confirm_aek[1], confirm_aek[2],
				 confirm_aek[3], confirm_aek[4], confirm_aek[5],
				 confirm_aek[6], confirm_aek[7],
				 confirm_my_nonce[0], confirm_my_nonce[1],
				 confirm_my_nonce[2], confirm_my_nonce[3],
				 confirm_my_nonce[4], confirm_my_nonce[5],
				 confirm_my_nonce[6], confirm_my_nonce[7],
				 confirm_peer_nonce[0], confirm_peer_nonce[1],
				 confirm_peer_nonce[2], confirm_peer_nonce[3],
				 confirm_peer_nonce[4], confirm_peer_nonce[5],
				 confirm_peer_nonce[6], confirm_peer_nonce[7],
				 cat[0], cat[1], cat[2], cat[3], cat[4], cat[5],
				 (unsigned) wpabuf_len(buf));
	}

#ifdef CONFIG_IEEE80211AH
	if (type != PLINK_CLOSE && bss->iconf->ieee80211ah) {
		/* S1G: add S1G_CAPABILITIES + S1G_OPERATION instead of
		 * HT/VHT — the receiving morse_driver converts these
		 * back to HT/VHT for its hostapd.  Also satisfies
		 * morse_mac_capabilities_validate() which requires
		 * S1G_CAPABILITIES on CONFIRM frames. */
		u8 s1g_ies[2 + sizeof(struct ieee80211_s1g_capabilities) +
			   2 + sizeof(struct ieee80211_s1g_operation)];
		pos = hostapd_eid_s1g_capab(bss, s1g_ies);
		pos = hostapd_eid_s1g_oper(bss, pos);
		wpabuf_put_data(buf, s1g_ies, pos - s1g_ies);
	} else
#endif /* CONFIG_IEEE80211AH */
	{
		if (type != PLINK_CLOSE && wpa_s->mesh_ht_enabled) {
			u8 ht_capa_oper[2 + 26 + 2 + 22];

			pos = hostapd_eid_ht_capabilities(bss, ht_capa_oper);
			pos = hostapd_eid_ht_operation(bss, pos);
			wpabuf_put_data(buf, ht_capa_oper, pos - ht_capa_oper);
		}
#ifdef CONFIG_IEEE80211AC
		if (type != PLINK_CLOSE && wpa_s->mesh_vht_enabled) {
			u8 vht_capa_oper[2 + 12 + 2 + 5];

			pos = hostapd_eid_vht_capabilities(bss, vht_capa_oper, 0);
			pos = hostapd_eid_vht_operation(bss, pos);
			wpabuf_put_data(buf, vht_capa_oper, pos - vht_capa_oper);
		}
#endif /* CONFIG_IEEE80211AC */
	}
#ifdef CONFIG_IEEE80211AX
	if (type != PLINK_CLOSE && wpa_s->mesh_he_enabled) {
		u8 he_capa_oper[3 +
				HE_MAX_MAC_CAPAB_SIZE +
				HE_MAX_PHY_CAPAB_SIZE +
				HE_MAX_MCS_CAPAB_SIZE +
				HE_MAX_PPET_CAPAB_SIZE +
				3 + sizeof(struct ieee80211_he_operation) +
				sizeof(struct ieee80211_he_6ghz_oper_info) +
				3 + sizeof(struct ieee80211_he_6ghz_band_cap)];

		pos = hostapd_eid_he_capab(bss, he_capa_oper,
					   IEEE80211_MODE_MESH);
		pos = hostapd_eid_he_operation(bss, pos);
		pos = hostapd_eid_he_6ghz_band_cap(bss, pos);
		wpabuf_put_data(buf, he_capa_oper, pos - he_capa_oper);
	}
#endif /* CONFIG_IEEE80211AX */
#ifdef CONFIG_OCV
	if (type != PLINK_CLOSE && conf->ocv) {
		struct wpa_channel_info ci;

		if (wpa_drv_channel_info(wpa_s, &ci) != 0) {
			wpa_printf(MSG_WARNING,
				   "Mesh MPM: Failed to get channel info for OCI element");
			goto fail;
		}

		pos = wpabuf_put(buf, OCV_OCI_EXTENDED_LEN);
		if (ocv_insert_extended_oci(&ci, pos) < 0)
			goto fail;
	}
#endif /* CONFIG_OCV */

#ifdef CONFIG_IEEE80211BE
	if (type != PLINK_CLOSE && wpa_s->mesh_eht_enabled) {
		u8 eht_capa_oper[3 +
				 2 +
				 EHT_PHY_CAPAB_LEN +
				 EHT_MCS_NSS_CAPAB_LEN +
				 EHT_PPE_THRESH_CAPAB_LEN +
				 3 + sizeof(struct ieee80211_eht_operation)];
		pos = hostapd_eid_eht_capab(bss, eht_capa_oper,
					    IEEE80211_MODE_MESH);
		pos = hostapd_eid_eht_operation(bss, pos);
		wpabuf_put_data(buf, eht_capa_oper, pos - eht_capa_oper);
	}
#endif /* CONFIG_IEEE80211BE */

	if (ampe && mesh_rsn_protect_frame(wpa_s->mesh_rsn, sta, cat, buf)) {
		wpa_msg(wpa_s, MSG_INFO,
			"Mesh MPM: failed to add AMPE and MIC IE");
		goto fail;
	}

	if (type == PLINK_CONFIRM && confirm_context_valid) {
		bool changed = sta->sae != confirm_sae ||
			sta->my_lid != confirm_my_lid ||
			sta->peer_lid != confirm_peer_lid ||
			os_memcmp(confirm_aek, sta->aek, sizeof(confirm_aek)) != 0 ||
			os_memcmp(confirm_my_nonce, sta->my_nonce,
				  sizeof(confirm_my_nonce)) != 0 ||
			os_memcmp(confirm_peer_nonce, sta->peer_nonce,
				  sizeof(confirm_peer_nonce)) != 0 ||
			!sta->sae ||
			os_memcmp(confirm_pmkid, sta->sae->pmkid,
				  sizeof(confirm_pmkid)) != 0;

		MESH_DBG_PRINTF("[mesh_confirm_ctx] stage=after peer=" MACSTR
				 " phase=%d lids=%04x/%04x changed=%u"
				 " protected_len=%u protected_hash=0x%08x\n",
				 MAC2STR(sta->addr), sta->plink_state,
				 sta->my_lid, sta->peer_lid, changed ? 1U : 0U,
				 (unsigned) wpabuf_len(buf),
				 mesh_dbg_fnv1a32(wpabuf_head(buf), wpabuf_len(buf)));
	}

	wpa_msg(wpa_s, MSG_DEBUG, "Mesh MPM: Sending peering frame %s(%d) to "
		MACSTR " state=%s my_lid=0x%x peer_lid=0x%x add_plid=%u close_reason=%u ampe=%u",
		type_name,
		type,
		MAC2STR(sta->addr),
		mplstate[sta->plink_state],
		sta->my_lid,
		sta->peer_lid,
		add_plid,
		(type == PLINK_CLOSE) ? close_reason : 0,
		ampe ? 1 : 0);
	MESH_DBG_PRINTF("[mesh_trace] MPM_TX action=%s(%d) peer=" MACSTR " state=%s my_lid=0x%x peer_lid=0x%x add_plid=%u close_reason=%u\n",
	       type_name,
	       type,
	       MAC2STR(sta->addr),
	       mplstate[sta->plink_state],
	       sta->my_lid,
	       sta->peer_lid,
	       add_plid,
	       (type == PLINK_CLOSE) ? close_reason : 0);

	/* Debug: dump first 40 bytes of CONFIRM frame body for wire-format verification */
#ifdef CONFIG_MM_MESH_DEBUG_LOG
	if (type == PLINK_CONFIRM) {
		const u8 *fbody = wpabuf_head_u8(buf);
		size_t flen = wpabuf_len(buf);
		size_t dlen = flen < 40 ? flen : 40;
		size_t di;
		MESH_DBG_PRINTF("[mesh_confirm_body] total_len=%u first_%u_bytes=",
		       (unsigned int) flen, (unsigned int) dlen);
		for (di = 0; di < dlen; di++)
			printf("%02x", fbody[di]);
		printf("\n");
		/* Parse and print key fields for easy verification */
		if (flen >= 6) {
			u16 cap_info = fbody[2] | (fbody[3] << 8);
			u16 aid = fbody[4] | (fbody[5] << 8);
			MESH_DBG_PRINTF("[mesh_confirm_body] cat=%u action=%u cap_info=0x%04x aid=0x%04x(%u)\n",
			       fbody[0], fbody[1], cap_info, aid, aid);
		}
		/* Find peering management IE (id=117=0x75) and dump link IDs */
		for (di = 6; di + 1 < flen; ) {
			u8 eid = fbody[di];
			u8 elen = fbody[di + 1];
			if (eid == 117 && di + 2 + elen <= flen && elen >= 6) {
				u16 proto = fbody[di+2] | (fbody[di+3] << 8);
				u16 tx_llid = fbody[di+4] | (fbody[di+5] << 8);
				u16 tx_plid = fbody[di+6] | (fbody[di+7] << 8);
				MESH_DBG_PRINTF("[mesh_confirm_body] peering_mgmt: proto=0x%04x llid=0x%04x plid=0x%04x ie_len=%u offset=%u\n",
				       proto, tx_llid, tx_plid, elen, (unsigned int)di);
				if (elen >= 6 + 16) {
					MESH_DBG_PRINTF("[mesh_confirm_body] pmkid(first8)=%02x%02x%02x%02x%02x%02x%02x%02x\n",
					       fbody[di+8], fbody[di+9], fbody[di+10], fbody[di+11],
					       fbody[di+12], fbody[di+13], fbody[di+14], fbody[di+15]);
				}
				break;
			}
			di += 2 + elen;
		}
	}
#endif

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0,
				  sta->addr, wpa_s->own_addr, wpa_s->own_addr,
				  wpabuf_head(buf), wpabuf_len(buf), 0);
	MESH_DBG_PRINTF("[mesh_trace] MPM_TX_RESULT action=%s(%d) ret=%d peer=" MACSTR "\n",
	       type_name,
	       type,
	       ret,
	       MAC2STR(sta->addr));
	if (ret < 0)
		wpa_msg(wpa_s, MSG_INFO,
			"Mesh MPM: failed to send peering frame");

	for (i = 0; i < wpabuf_len(buf); i++)
		tx_hash = (tx_hash * 33) ^ wpabuf_head_u8(buf)[i];
	MESH_DBG_PRINTF("[mesh_trace] MPM_TX_FRAME action=%s(%d) len=%u hash=0x%08x peer=" MACSTR
	       " my_lid=0x%x peer_lid=0x%x\n",
	       type_name,
	       type,
	       (unsigned int) wpabuf_len(buf),
	       tx_hash,
	       MAC2STR(sta->addr),
	       sta->my_lid,
	       sta->peer_lid);

fail:
	wpabuf_free(buf);
}


/* configure peering state in ours and driver's station entry */
void wpa_mesh_set_plink_state(struct wpa_supplicant *wpa_s,
			      struct sta_info *sta,
			      enum mesh_plink_state state)
{
	struct hostapd_sta_add_params params;
	int ret;

	wpa_msg(wpa_s, MSG_DEBUG, "MPM set " MACSTR " from %s into %s",
		MAC2STR(sta->addr), mplstate[sta->plink_state],
		mplstate[state]);
	sta->plink_state = state;

	os_memset(&params, 0, sizeof(params));
	params.addr = sta->addr;
	params.plink_state = state;
	params.peer_aid = sta->peer_aid;
	params.set = 1;
	params.mld_link_id = -1;
	/* The Morse shim is built without CONFIG_MESH, so plink_state is not
	 * present in its view of hostapd_sta_add_params. Encode the controlled
	 * port transition in the standard authorization mask: only PLINK_ESTAB
	 * makes this peer available to the mesh data plane. */
	params.flags_mask = WPA_STA_AUTHORIZED;
	if (state == PLINK_ESTAB)
		params.flags = WPA_STA_AUTHORIZED;

	ret = wpa_drv_sta_add(wpa_s, &params);
	if (ret) {
		wpa_msg(wpa_s, MSG_ERROR, "Driver failed to set " MACSTR
			": %d", MAC2STR(sta->addr), ret);
	}
}


/*
 * Recover from an asymmetric peer-link restart. A different SAE scalar proves
 * that the remote peer started a new authentication generation, even if our
 * previous peer link never reached PLINK_ESTAB. Keep the STA/driver allocation,
 * but retire the old link identifiers, nonces, and keys before the
 * authentication handler adopts the new SAE generation.
 */
int mesh_mpm_reset_peer_generation(struct hostapd_data *hapd,
				   struct sta_info *sta)
{
	struct wpa_supplicant *wpa_s;
	struct mesh_conf *conf;
	bool was_established;

	if (!hapd || !sta || !hapd->iface || !hapd->iface->owner)
		return -1;

	wpa_s = hapd->iface->owner;
	if (!wpa_s->ifmsh || !wpa_s->ifmsh->mconf)
		return -1;
	conf = wpa_s->ifmsh->mconf;
	was_established = sta->plink_state == PLINK_ESTAB;

	MESH_DBG_PRINTF("[mesh_peer_state] peer=" MACSTR
			 " event=RESET_MPM_GENERATION state=%d"
			 " lids=%04x/%04x aid=%u\n",
		 MAC2STR(sta->addr), sta->plink_state,
		 sta->my_lid, sta->peer_lid,
		 sta->peer_aid);

	eloop_cancel_timeout(plink_timer, wpa_s, sta);
	eloop_cancel_timeout(mesh_auth_timer, wpa_s, sta);

	/* Retire every part of the previous peer-link generation before the new
	 * SAE scalar is processed. This is required even when the old MPM did not
	 * reach ESTAB: delayed OPEN/CONFIRM/CLOSE frames otherwise reuse its link
	 * IDs and AMPE nonces and can tear down the new exchange. */
	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_IDLE);
	sta->flags &= ~(WLAN_STA_ASSOC | WLAN_STA_AUTH |
			WLAN_STA_AUTHORIZED);
	if (was_established && hapd->num_plinks > 0)
		hapd->num_plinks--;
	if (was_established)
		wpas_notify_mesh_peer_disconnected(wpa_s, sta->addr,
						   WLAN_REASON_UNSPECIFIED);

	if (conf->security & MESH_CONF_SEC_AMPE) {
		wpa_drv_set_key(wpa_s, -1, WPA_ALG_NONE, sta->addr, 0, 0,
				NULL, 0, NULL, 0, KEY_FLAG_PAIRWISE);
		if (sta->mgtk_len)
			wpa_drv_set_key(wpa_s, -1, WPA_ALG_NONE, sta->addr,
					sta->mgtk_key_id, 0, NULL, 0, NULL, 0,
					KEY_FLAG_GROUP_RX);
		if (sta->igtk_len)
			wpa_drv_set_key(wpa_s, -1, WPA_ALG_NONE, sta->addr,
					sta->igtk_key_id, 0, NULL, 0, NULL, 0,
					KEY_FLAG_GROUP_RX);
	}

	os_memset(sta->aek, 0, sizeof(sta->aek));
	os_memset(sta->mtk, 0, sizeof(sta->mtk));
	sta->mtk_len = 0;
	os_memset(sta->mgtk, 0, sizeof(sta->mgtk));
	sta->mgtk_len = 0;
	os_memset(sta->mgtk_rsc, 0, sizeof(sta->mgtk_rsc));
	os_memset(sta->igtk, 0, sizeof(sta->igtk));
	sta->igtk_len = 0;
	os_memset(sta->igtk_rsc, 0, sizeof(sta->igtk_rsc));
	os_memset(sta->my_nonce, 0, sizeof(sta->my_nonce));
	os_memset(sta->peer_nonce, 0, sizeof(sta->peer_nonce));
	sta->my_lid = 0;
	sta->peer_lid = 0;
	sta->peer_aid = 0;
	sta->mpm_retries = 0;
	sta->mpm_close_reason = 0;
	sta->mesh_sae_pmksa_caching = 0;
	wpa_auth_pmksa_remove(hapd->wpa_auth, sta->addr);

	return 0;
}


static void mesh_mpm_fsm_restart(struct wpa_supplicant *wpa_s,
				 struct sta_info *sta)
{
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct sta_info *s;
	int sta_found = 0;

	if (!wpa_s || !wpa_s->ifmsh || !wpa_s->ifmsh->bss || !wpa_s->ifmsh->bss[0] ||
	    !sta)
		return;

	for (s = hapd->sta_list; s; s = s->next) {
		if (s == sta) {
			sta_found = 1;
			break;
		}
	}
	if (!sta_found) {
		wpa_printf(MSG_DEBUG,
			   "MPM: restart skipped for stale STA context");
		return;
	}

	eloop_cancel_timeout(plink_timer, wpa_s, sta);

	/* A failed provisional link must release both the supplicant STA and the
	 * UMAC mesh-peer slot. Keeping the record and merely resetting its fields
	 * leaves the controlled port closed while received data continues to bind
	 * to that stale record. A later OPEN will allocate a clean peer and run the
	 * full SAE/AMPE joining flow again. */
	if (sta->plink_state != PLINK_ESTAB) {
		wpa_printf(MSG_WARNING,
			   "[mesh_fix] remove failed non-ESTAB peer=" MACSTR " state=%s",
			   MAC2STR(sta->addr),
			   mplstate[sta->plink_state]);
		mesh_peer_backoff_start(sta->addr);
		ap_free_sta(hapd, sta);
		return;
	}

	ap_free_sta(hapd, sta);
}


static void plink_timer(void *eloop_ctx, void *user_data)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct sta_info *sta = user_data;
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct sta_info *s;
	int sta_found = 0;

	if (!wpa_s || !wpa_s->ifmsh || !wpa_s->ifmsh->bss || !wpa_s->ifmsh->bss[0] ||
	    !sta)
		return;

	for (s = hapd->sta_list; s; s = s->next) {
		if (s == sta) {
			sta_found = 1;
			break;
		}
	}
	if (!sta_found) {
		wpa_printf(MSG_DEBUG,
			   "MPM: plink timer dropped for stale STA context");
		return;
	}

	MESH_DBG_PRINTF("[mesh_peer_timer] event=FIRE owner=" MACSTR
			 " state=%d sae=%d aid=%u retries=%d lids=%04x/%04x\n",
			 MAC2STR(sta->addr), sta->plink_state,
			 sta->sae ? sta->sae->state : -1, sta->peer_aid,
			 sta->mpm_retries, sta->my_lid, sta->peer_lid);
	for (s = hapd->sta_list; s; s = s->next) {
		MESH_DBG_PRINTF("[mesh_peer_snapshot] trigger=" MACSTR
				 " peer=" MACSTR " state=%d sae=%d aid=%u"
				 " retries=%d lids=%04x/%04x flags=0x%x\n",
				 MAC2STR(sta->addr), MAC2STR(s->addr),
				 s->plink_state, s->sae ? s->sae->state : -1,
				 s->peer_aid, s->mpm_retries, s->my_lid,
				 s->peer_lid, s->flags);
	}

	switch (sta->plink_state) {
	case PLINK_OPN_RCVD:
		/*
		 * The peer may have received our CONFIRM while our original OPEN was
		 * lost, leaving it in CNF_RCVD. Retransmit the complete pair so that
		 * either missing half can converge. Sending only CONFIRM keeps the two
		 * sides stuck in the complementary OPN_RCVD/CNF_RCVD states.
		 */
		if (sta->mpm_retries < conf->dot11MeshMaxRetries) {
			eloop_register_timeout(
				conf->dot11MeshRetryTimeout / 1000,
				(conf->dot11MeshRetryTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			sta->mpm_retries++;
			break;
		}

		/*
		 * Do a soft restart instead of sending CLOSE(56) from OPN_RCVD.
		 * This avoids repeatedly resetting peers that are still converging
		 * through SAE/MPM timing races.
		 */
		MESH_DBG_PRINTF("[mesh_fix] plink_timer OPN_RCVD soft-restart after max retries peer=" MACSTR "\n",
		       MAC2STR(sta->addr));
		mesh_mpm_fsm_restart(wpa_s, sta);
		break;

	case PLINK_OPN_SNT:
		/* retry timer */
		if (sta->mpm_retries < conf->dot11MeshMaxRetries) {
			eloop_register_timeout(
				conf->dot11MeshRetryTimeout / 1000,
				(conf->dot11MeshRetryTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
			sta->mpm_retries++;
			break;
		}
		MESH_DBG_PRINTF("[mesh_fix] plink_timer OPN_SNT soft-restart after max retries peer=" MACSTR "\n",
		       MAC2STR(sta->addr));
		mesh_mpm_fsm_restart(wpa_s, sta);
		break;

	case PLINK_CNF_RCVD:
		/*
		 * We have the peer's CONFIRM but are still waiting for its OPEN. Do
		 * not close on the first confirm timeout: on HaLow the two timers can
		 * fire before the peer's recovery frames cross the host boundary.
		 * Keep the negotiation alive with the complete local pair.
		 */
		if (sta->mpm_retries < conf->dot11MeshMaxRetries) {
			eloop_register_timeout(
				conf->dot11MeshConfirmTimeout / 1000,
				(conf->dot11MeshConfirmTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			sta->mpm_retries++;
			break;
		}

		MESH_DBG_PRINTF("[mesh_fix] plink_timer CNF_RCVD soft-restart after max retries peer=" MACSTR "\n",
		       MAC2STR(sta->addr));
		mesh_mpm_fsm_restart(wpa_s, sta);
		break;
	case PLINK_HOLDING:
		/* holding timer */

		if (sta->mesh_sae_pmksa_caching) {
			wpa_printf(MSG_DEBUG, "MPM: Peer " MACSTR
				   " looks like it does not support mesh SAE PMKSA caching, so remove the cached entry for it",
				   MAC2STR(sta->addr));
			wpa_auth_pmksa_remove(hapd->wpa_auth, sta->addr);
		}
		mesh_mpm_fsm_restart(wpa_s, sta);
		break;
	default:
		break;
	}
}


/* initiate peering with station */
static void
mesh_mpm_plink_open(struct wpa_supplicant *wpa_s, struct sta_info *sta,
		    enum mesh_plink_state next_state)
{
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;

	eloop_cancel_timeout(plink_timer, wpa_s, sta);
	eloop_register_timeout(conf->dot11MeshRetryTimeout / 1000,
			       (conf->dot11MeshRetryTimeout % 1000) * 1000,
			       plink_timer, wpa_s, sta);
	mesh_mpm_send_plink_action(wpa_s, sta, PLINK_OPEN, 0);
	wpa_mesh_set_plink_state(wpa_s, sta, next_state);
}


static int mesh_mpm_plink_close(struct hostapd_data *hapd, struct sta_info *sta,
				void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;
	int reason = WLAN_REASON_MESH_PEERING_CANCELLED;

	if (sta) {
		if (sta->plink_state == PLINK_ESTAB) {
			hapd->num_plinks--;
			wpas_notify_mesh_peer_disconnected(
				wpa_s, sta->addr, WLAN_REASON_UNSPECIFIED);
		}
		wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
		mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
		wpa_printf(MSG_DEBUG, "MPM closing plink sta=" MACSTR,
			   MAC2STR(sta->addr));
		eloop_cancel_timeout(plink_timer, wpa_s, sta);
		eloop_cancel_timeout(mesh_auth_timer, wpa_s, sta);
		return 0;
	}

	return 1;
}


int mesh_mpm_close_peer(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	struct hostapd_data *hapd;
	struct sta_info *sta;

	if (!wpa_s->ifmsh) {
		wpa_msg(wpa_s, MSG_INFO, "Mesh is not prepared yet");
		return -1;
	}

	hapd = wpa_s->ifmsh->bss[0];
	sta = ap_get_sta(hapd, addr);
	if (!sta) {
		wpa_msg(wpa_s, MSG_INFO, "No such mesh peer");
		return -1;
	}

	return mesh_mpm_plink_close(hapd, sta, wpa_s) == 0 ? 0 : -1;
}


static void peer_add_timer(void *eloop_ctx, void *user_data)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];

	os_memset(hapd->mesh_required_peer, 0, ETH_ALEN);
}


int mesh_mpm_connect_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			  int duration)
{
	struct wpa_ssid *ssid = wpa_s->current_ssid;
	struct hostapd_data *hapd;
	struct sta_info *sta;
	struct mesh_conf *conf;

	if (!wpa_s->ifmsh) {
		wpa_msg(wpa_s, MSG_INFO, "Mesh is not prepared yet");
		return -1;
	}

	if (!ssid || !ssid->no_auto_peer) {
		wpa_msg(wpa_s, MSG_INFO,
			"This command is available only with no_auto_peer mesh network");
		return -1;
	}

	hapd = wpa_s->ifmsh->bss[0];
	conf = wpa_s->ifmsh->mconf;

	sta = ap_get_sta(hapd, addr);
	if (!sta) {
		wpa_msg(wpa_s, MSG_INFO, "No such mesh peer");
		return -1;
	}

	if ((PLINK_OPN_SNT <= sta->plink_state &&
	    sta->plink_state <= PLINK_ESTAB) ||
	    (sta->sae && sta->sae->state > SAE_NOTHING)) {
		wpa_msg(wpa_s, MSG_INFO,
			"Specified peer is connecting/connected");
		return -1;
	}

	if (conf->security == MESH_CONF_SEC_NONE) {
		mesh_mpm_plink_open(wpa_s, sta, PLINK_OPN_SNT);
	} else {
		mesh_rsn_auth_sae_sta(wpa_s, sta);
		os_memcpy(hapd->mesh_required_peer, addr, ETH_ALEN);
		eloop_register_timeout(duration == -1 ? 10 : duration, 0,
				       peer_add_timer, wpa_s, NULL);
	}

	return 0;
}


void mesh_mpm_deinit(struct wpa_supplicant *wpa_s, struct hostapd_iface *ifmsh)
{
	struct hostapd_data *hapd = ifmsh->bss[0];

	/* notify peers we're leaving */
	ap_for_each_sta(hapd, mesh_mpm_plink_close, wpa_s);

	hapd->num_plinks = 0;
	hostapd_free_stas(hapd);
	eloop_cancel_timeout(peer_add_timer, wpa_s, NULL);
}


/* for mesh_rsn to indicate this peer has completed authentication, and we're
 * ready to start AMPE */
void mesh_mpm_auth_peer(struct wpa_supplicant *wpa_s, const u8 *addr)
{
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct hostapd_sta_add_params params;
	struct sta_info *sta;
	int ret;
	u8 null_nonce[WPA_NONCE_LEN] = {};

	sta = ap_get_sta(data, addr);
	if (!sta) {
		wpa_msg(wpa_s, MSG_DEBUG, "no such mesh peer");
		return;
	}

	/* WPA_AUTH can be reported again when a final SAE Confirm is duplicated.
	 * Preserve the active AMPE generation in that case. Regenerating my_nonce
	 * here makes the peer's already protected CONFIRM fail nonce validation. */
	if (os_memcmp(sta->my_nonce, null_nonce, WPA_NONCE_LEN) != 0 &&
	    sta->my_lid != 0 &&
	    sta->plink_state >= PLINK_OPN_SNT &&
	    sta->plink_state <= PLINK_ESTAB) {
		MESH_DBG_PRINTF("[mesh_peer_state] peer=" MACSTR
				 " event=KEEP_ACTIVE_AMPE_ON_DUP_AUTH state=%s"
				 " lids=%04x/%04x\n",
				 MAC2STR(sta->addr), mplstate[sta->plink_state],
				 sta->my_lid, sta->peer_lid);
		return;
	}

	sta->flags |= WLAN_STA_AUTH;

	mesh_rsn_init_ampe_sta(wpa_s, sta);

	os_memset(&params, 0, sizeof(params));
	params.addr = sta->addr;
	params.flags = WPA_STA_AUTHENTICATED | WPA_STA_AUTHORIZED;
	params.set = 1;
	params.mld_link_id = -1;

	wpa_msg(wpa_s, MSG_DEBUG, "MPM authenticating " MACSTR,
		MAC2STR(sta->addr));
	ret = wpa_drv_sta_add(wpa_s, &params);
	if (ret) {
		wpa_msg(wpa_s, MSG_ERROR,
			"Driver failed to set " MACSTR ": %d",
			MAC2STR(sta->addr), ret);
	}

	if (!sta->my_lid)
		mesh_mpm_init_link(wpa_s, sta);

	mesh_mpm_plink_open(wpa_s, sta, PLINK_OPN_SNT);
}

/*
 * Initialize a sta_info structure for a peer and upload it into the driver
 * in preparation for beginning authentication or peering. This is done when a
 * Beacon (secure or open mesh) or a peering open frame (for open mesh) is
 * received from the peer for the first time.
 */
static struct sta_info * mesh_mpm_add_peer(struct wpa_supplicant *wpa_s,
					   const u8 *addr,
					   struct ieee802_11_elems *elems)
{
	struct hostapd_sta_add_params params;
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct sta_info *sta;
	struct ieee80211_ht_operation *oper;
	int ret;

	if (mesh_peer_backoff_active(addr)) {
		wpa_msg(wpa_s, MSG_DEBUG,
			"mesh: defer failed peer during retry backoff " MACSTR,
			MAC2STR(addr));
		return NULL;
	}

	if (elems->mesh_config_len >= 7 &&
	    !(elems->mesh_config[6] & MESH_CAP_ACCEPT_ADDITIONAL_PEER)) {
		wpa_msg(wpa_s, MSG_DEBUG,
			"mesh: Ignore a crowded peer " MACSTR,
			MAC2STR(addr));
		return NULL;
	}

	sta = ap_get_sta(data, addr);
	if (sta) {
		wpa_msg(wpa_s, MSG_INFO,
			"mesh: peer already exists in STA table " MACSTR,
			MAC2STR(addr));
		return NULL;
	}

	sta = ap_sta_add(data, addr);
	if (!sta) {
		wpa_msg(wpa_s, MSG_INFO,
			"mesh: ap_sta_add failed for peer " MACSTR,
			MAC2STR(addr));
		return NULL;
	}

	/* Set WMM by default since Mesh STAs are QoS STAs */
	sta->flags |= WLAN_STA_WMM;

	/* initialize sta */
	if (copy_supp_rates(wpa_s, sta, elems)) {
		wpa_msg(wpa_s, MSG_INFO,
			"mesh: copy_supp_rates failed for peer " MACSTR,
			MAC2STR(addr));
		ap_free_sta(data, sta);
		return NULL;
	}

	if (!sta->my_lid)
		mesh_mpm_init_link(wpa_s, sta);

	copy_sta_ht_capab(data, sta, elems->ht_capabilities);

	oper = (struct ieee80211_ht_operation *) elems->ht_operation;
	if (oper &&
	    !(oper->ht_param & HT_INFO_HT_PARAM_STA_CHNL_WIDTH) &&
	    sta->ht_capabilities) {
		wpa_msg(wpa_s, MSG_DEBUG, MACSTR
			" does not support 40 MHz bandwidth",
			MAC2STR(sta->addr));
		set_disable_ht40(sta->ht_capabilities, 1);
	}

	if (update_ht_state(data, sta) > 0)
		ieee802_11_update_beacons(data->iface);

#ifdef CONFIG_IEEE80211AC
	copy_sta_vht_capab(data, sta, elems->vht_capabilities);
	copy_sta_vht_oper(data, sta, elems->vht_operation);
	set_sta_vht_opmode(data, sta, elems->opmode_notif);
#endif /* CONFIG_IEEE80211AC */

#ifdef CONFIG_IEEE80211AX
	copy_sta_he_capab(data, sta, IEEE80211_MODE_MESH,
			  elems->he_capabilities, elems->he_capabilities_len);
	copy_sta_he_6ghz_capab(data, sta, elems->he_6ghz_band_cap);
#endif /* CONFIG_IEEE80211AX */
#ifdef CONFIG_IEEE80211BE
	copy_sta_eht_capab(data, sta, IEEE80211_MODE_MESH,
			   elems->he_capabilities,
			   elems->he_capabilities_len,
			   elems->eht_capabilities,
			   elems->eht_capabilities_len);
#endif /*CONFIG_IEEE80211BE */

	if (hostapd_get_aid(data, sta) < 0) {
		wpa_msg(wpa_s, MSG_ERROR, "No AIDs available");
		ap_free_sta(data, sta);
		return NULL;
	}

	/* insert into driver */
	os_memset(&params, 0, sizeof(params));
	params.supp_rates = sta->supported_rates;
	params.supp_rates_len = sta->supported_rates_len;
	params.addr = addr;
	params.plink_state = sta->plink_state;
	params.aid = sta->aid;
	params.peer_aid = sta->peer_aid;
	params.listen_interval = 100;
	params.ht_capabilities = sta->ht_capabilities;
	params.vht_capabilities = sta->vht_capabilities;
	params.he_capab = sta->he_capab;
	params.he_capab_len = sta->he_capab_len;
	params.he_6ghz_capab = sta->he_6ghz_capab;
	params.eht_capab = sta->eht_capab;
	params.eht_capab_len = sta->eht_capab_len;
	params.flags |= WPA_STA_WMM;
	params.flags_mask |= WPA_STA_AUTHENTICATED;
	params.mld_link_id = -1;
	if (conf->security == MESH_CONF_SEC_NONE) {
		params.flags |= WPA_STA_AUTHORIZED;
		params.flags |= WPA_STA_AUTHENTICATED;
	} else {
		if (conf->ieee80211w != NO_MGMT_FRAME_PROTECTION) {
			sta->flags |= WLAN_STA_MFP;
			params.flags |= WPA_STA_MFP;
			wpa_msg(wpa_s, MSG_DEBUG, "mesh: Enabling MFP ieee80211w:%d flags:%x",
					conf->ieee80211w, sta->flags);
		} else {
			wpa_msg(wpa_s, MSG_DEBUG, "mesh: Disabling MFP ieee80211w:%d flags:%x",
					conf->ieee80211w, sta->flags);
		}
	}

	ret = wpa_drv_sta_add(wpa_s, &params);
	if (ret) {
		wpa_msg(wpa_s, MSG_ERROR,
			"Driver failed to insert " MACSTR ": %d",
			MAC2STR(addr), ret);
		ap_free_sta(data, sta);
		return NULL;
	}

	wpa_msg(wpa_s, MSG_INFO,
		"mesh: peer inserted into driver " MACSTR " aid=%u",
		MAC2STR(addr), sta->aid);

	return sta;
}


/*
 * ieee802_11.c cannot authenticate a secure mesh peer until its sta_info and
 * driver peer have been created from a beacon. It therefore stores an AUTH
 * frame received slightly ahead of peer admission in mesh_pending_auth.
 *
 * The upstream no_auto_peer path used to replay that frame, but this port
 * allows independent peer links and no longer takes that path. Leaving the
 * frame queued makes a listening relay acknowledge the SAE Commit at the MAC
 * layer without ever answering it. Replay it as soon as the matching peer has
 * been installed. Detach the buffer first because ieee802_11_mgmt() may enter
 * authentication processing recursively.
 */
static bool mesh_mpm_replay_pending_auth(struct hostapd_data *hapd,
					 const u8 *addr)
{
	struct wpabuf *pending;
	const struct ieee80211_mgmt *mgmt;
	struct os_reltime age;
	struct hostapd_frame_info fi;

	if (!hapd || !addr || !hapd->mesh_pending_auth)
		return false;

	mgmt = wpabuf_head(hapd->mesh_pending_auth);
	os_reltime_age(&hapd->mesh_pending_auth_time, &age);
	if (!ether_addr_equal(mgmt->sa, addr)) {
		/* Do not discard another peer's Commit while peers are admitted in
		 * parallel. Its own beacon/admission callback can still replay it. */
		if (age.sec >= 2) {
			wpabuf_free(hapd->mesh_pending_auth);
			hapd->mesh_pending_auth = NULL;
		}
		return false;
	}

	pending = hapd->mesh_pending_auth;
	hapd->mesh_pending_auth = NULL;
	if (age.sec >= 2) {
		MESH_DBG_PRINTF("[mesh_auth_replay] peer=" MACSTR
				 " result=expired age=%u.%06u\n",
				 MAC2STR(addr), (unsigned int) age.sec,
				 (unsigned int) age.usec);
		wpabuf_free(pending);
		return false;
	}

	MESH_DBG_PRINTF("[mesh_auth_replay] peer=" MACSTR
			 " result=dispatch age=%u.%06u\n",
			 MAC2STR(addr), (unsigned int) age.sec,
			 (unsigned int) age.usec);
	os_memset(&fi, 0, sizeof(fi));
	ieee802_11_mgmt(hapd, wpabuf_head(pending), wpabuf_len(pending), &fi);
	wpabuf_free(pending);
	return true;
}


void wpa_mesh_new_mesh_peer(struct wpa_supplicant *wpa_s, const u8 *addr,
			    struct ieee802_11_elems *elems)
{
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	struct hostapd_data *data = wpa_s->ifmsh->bss[0];
	struct sta_info *sta;
	struct wpa_ssid *ssid = wpa_s->current_ssid;

	PEER_DIAG_LOGI(
		"[4 MPM_ENTRY] peer=" MACSTR
		" local_channel=%d local_op_class=%d local_freq=%d local_freq_khz=%u mesh_config_len=%u",
		MAC2STR(addr),
		ssid ? ssid->channel : -1,
		ssid ? ssid->op_class : -1,
		ssid ? ssid->frequency : -1,
		ssid ? ssid->frequency_khz : 0U,
		elems ? (unsigned)elems->mesh_config_len : 0U);

	wpa_printf(MSG_ERROR,
		"mesh_dbg: new_peer start " MACSTR " no_auto_peer=%d security=0x%x mesh_config_len=%u supp_rates_len=%u ext_supp_rates_len=%u",
		MAC2STR(addr),
		ssid ? ssid->no_auto_peer : -1,
		conf ? conf->security : 0,
		elems ? (unsigned)elems->mesh_config_len : 0,
		elems ? (unsigned)elems->supp_rates_len : 0,
		elems ? (unsigned)elems->ext_supp_rates_len : 0);

	sta = ap_get_sta(data, addr);
	if (sta) {
		if (sta->plink_state == PLINK_ESTAB) {
			MESH_DBG_PRINTF("[mesh_peer_scan] ignore established peer="
					MACSTR "\n", MAC2STR(addr));
			return;
		}
		if (sta->plink_state == PLINK_BLOCKED) {
			/* A fresh application beacon proves that this peer is still
			 * present. Clear the failed peering/SAE attempt before handling
			 * the beacon so the existing STA entry cannot permanently suppress
			 * a new join. mesh_mpm_fsm_restart() removes the stale driver and
			 * supplicant peer state before the retry cooldown begins. */
			MESH_DBG_PRINTF("[mesh_peer_beacon] restart blocked peer="
					MACSTR "\n", MAC2STR(addr));
			mesh_mpm_fsm_restart(wpa_s, sta);
			/* restart frees the failed provisional STA. A later beacon,
			 * after the short cooldown, starts with a fresh context. */
			return;
		}
	} else {
		sta = mesh_mpm_add_peer(wpa_s, addr, elems);
	}
	if (!sta) {
		wpa_printf(MSG_ERROR,
			"mesh_dbg: new_peer aborted before auth start " MACSTR,
			MAC2STR(addr));
		return;
	}

	/* A pending Commit makes this peer the SAE initiator. Let the queued
	 * authentication handler answer it instead of starting a competing local
	 * Commit in the same call. */
	if (mesh_mpm_replay_pending_auth(data, addr))
		return;

	/* Each mesh peer owns an independent sta_info, SAE exchange and firmware
	 * peer slot. Do not serialize admission through mesh_required_peer. */
	if (ssid && ssid->no_auto_peer) {
		MESH_DBG_PRINTF("[mesh_peer_admission] peer=" MACSTR
				 " mode=independent no_auto_peer_override=1\n",
				 MAC2STR(addr));
	}

	if (conf->security == MESH_CONF_SEC_NONE) {
		if (sta->plink_state < PLINK_OPN_SNT ||
		    sta->plink_state > PLINK_ESTAB)
			mesh_mpm_plink_open(wpa_s, sta, PLINK_OPN_SNT);
		wpa_printf(MSG_ERROR,
			"mesh_dbg: open mesh plink_open for " MACSTR,
			MAC2STR(addr));
	} else {
		if (sta->sae && sta->sae->state > SAE_NOTHING) {
			wpa_printf(MSG_ERROR,
				"mesh_dbg: skip mesh_rsn_auth_sae_sta(" MACSTR
				") existing_sae_state=%d",
				MAC2STR(addr), sta->sae->state);
		} else {
			int ret = mesh_rsn_auth_sae_sta(wpa_s, sta);
			wpa_printf(MSG_ERROR,
				"mesh_dbg: mesh_rsn_auth_sae_sta(" MACSTR ") ret=%d",
				MAC2STR(addr), ret);
		}
	}
}


void mesh_mpm_mgmt_rx(struct wpa_supplicant *wpa_s, struct rx_mgmt *rx_mgmt)
{
	struct hostapd_frame_info fi;

	os_memset(&fi, 0, sizeof(fi));
	fi.datarate = rx_mgmt->datarate;
	fi.ssi_signal = rx_mgmt->ssi_signal;
	ieee802_11_mgmt(wpa_s->ifmsh->bss[0], rx_mgmt->frame,
			rx_mgmt->frame_len, &fi);
}


int mesh_mpm_mgmt_rx_if_ready(struct wpa_supplicant *wpa_s,
			      struct rx_mgmt *rx_mgmt)
{
	struct wpa_supplicant *target = wpa_s;

	if (!wpa_s || !rx_mgmt)
		return -1;

	if (!target->ifmsh && target->global) {
		struct wpa_supplicant *it;

		for (it = target->global->ifaces; it; it = it->next) {
			if (it->ifmsh) {
				target = it;
				wpa_printf(MSG_INFO,
					   "[mesh_trace] MESH_RX_READY: using global mesh iface owner=%p ifmsh=%p (requested=%p)",
					   (void *) target,
					   (void *) target->ifmsh,
					   (void *) wpa_s);
				MESH_DBG_PRINTF("[mesh_trace] MESH_RX_READY: using global mesh iface owner=%p ifmsh=%p (requested=%p)\n",
				       (void *) target,
				       (void *) target->ifmsh,
				       (void *) wpa_s);
				break;
			}
		}
	}

	if (!target->ifmsh) {
		wpa_printf(MSG_INFO,
			   "[mesh_trace] MESH_RX_NOT_READY: wpa_s=%p ifmsh=%p state=%d current_ssid=%p mode=%d",
			   (void *) target,
			   (void *) target->ifmsh,
			   target->wpa_state,
			   (void *) target->current_ssid,
			   target->current_ssid ? target->current_ssid->mode : -1);
		MESH_DBG_PRINTF("[mesh_trace] MESH_RX_NOT_READY: wpa_s=%p ifmsh=%p state=%d current_ssid=%p mode=%d\n",
		       (void *) target,
		       (void *) target->ifmsh,
		       target->wpa_state,
		       (void *) target->current_ssid,
		       target->current_ssid ? target->current_ssid->mode : -1);
		return -1;
	}

	mesh_mpm_mgmt_rx(target, rx_mgmt);
	return 0;
}


static void mesh_mpm_plink_estab(struct wpa_supplicant *wpa_s,
				 struct sta_info *sta)
{
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	u8 seq[6] = {};

	wpa_msg(wpa_s, MSG_INFO, "mesh plink with " MACSTR " established",
		MAC2STR(sta->addr));
	MESH_DBG_PRINTF("[mesh_flow] STEP4_ESTABLISHED peer=" MACSTR " state=%s my_lid=0x%x peer_lid=0x%x\n",
	       MAC2STR(sta->addr),
	       mplstate[sta->plink_state],
	       sta->my_lid,
	       sta->peer_lid);

	if (conf->security & MESH_CONF_SEC_AMPE) {
		wpa_hexdump_key(MSG_DEBUG, "mesh: MTK", sta->mtk, sta->mtk_len);
		wpa_drv_set_key(wpa_s, -1,
				wpa_cipher_to_alg(conf->pairwise_cipher),
				sta->addr, 0, 0, seq, sizeof(seq),
				sta->mtk, sta->mtk_len,
				KEY_FLAG_PAIRWISE_RX_TX);

		wpa_hexdump_key(MSG_DEBUG, "mesh: RX MGTK Key RSC",
				sta->mgtk_rsc, sizeof(sta->mgtk_rsc));
		wpa_hexdump_key(MSG_DEBUG, "mesh: RX MGTK",
				sta->mgtk, sta->mgtk_len);
		wpa_drv_set_key(wpa_s, -1,
				wpa_cipher_to_alg(conf->group_cipher),
				sta->addr, sta->mgtk_key_id, 0,
				sta->mgtk_rsc, sizeof(sta->mgtk_rsc),
				sta->mgtk, sta->mgtk_len,
				KEY_FLAG_GROUP_RX);

		if (sta->igtk_len) {
			wpa_hexdump_key(MSG_DEBUG, "mesh: RX IGTK Key RSC",
					sta->igtk_rsc, sizeof(sta->igtk_rsc));
			wpa_hexdump_key(MSG_DEBUG, "mesh: RX IGTK",
					sta->igtk, sta->igtk_len);
			wpa_drv_set_key(
				wpa_s, -1,
				wpa_cipher_to_alg(conf->mgmt_group_cipher),
				sta->addr, sta->igtk_key_id, 0,
				sta->igtk_rsc, sizeof(sta->igtk_rsc),
				sta->igtk, sta->igtk_len,
				KEY_FLAG_GROUP_RX);
		}
	}

	wpa_mesh_set_plink_state(wpa_s, sta, PLINK_ESTAB);
	hapd->num_plinks++;

	sta->flags |= WLAN_STA_ASSOC;
	sta->mesh_sae_pmksa_caching = 0;

	/* Open the controlled port on first mesh peer so the IP stack
	 * (DHCP) is triggered.  The Morse Micro driver uses set_supp_port
	 * to signal MMWLAN_LINK_UP → netif_set_link_up → DHCP. */
	if (hapd->num_plinks == 1) {
		wpa_msg(wpa_s, MSG_INFO,
			"mesh: first peer established, opening controlled port");
		wpa_drv_set_supp_port(wpa_s, 1);
	}

	eloop_cancel_timeout(peer_add_timer, wpa_s, NULL);
	peer_add_timer(wpa_s, NULL);
	eloop_cancel_timeout(plink_timer, wpa_s, sta);

	wpas_notify_mesh_peer_connected(wpa_s, sta->addr);
}


static void mesh_mpm_fsm(struct wpa_supplicant *wpa_s, struct sta_info *sta,
			 enum plink_event event, u16 reason)
{
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct mesh_conf *conf = wpa_s->ifmsh->mconf;
	enum mesh_plink_state prev_state = sta->plink_state;

	wpa_msg(wpa_s, MSG_DEBUG, "MPM " MACSTR " state %s event %s",
		MAC2STR(sta->addr), mplstate[sta->plink_state],
		mplevent[event]);

	MESH_DBG_PRINTF("[mesh_fsm] MPM " MACSTR " state=%s event=%s reason=%u\n",
		MAC2STR(sta->addr), mplstate[sta->plink_state],
		mplevent[event], reason);

	switch (sta->plink_state) {
	case PLINK_IDLE:
		switch (event) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			return;
		case OPN_ACPT:
			mesh_mpm_plink_open(wpa_s, sta, PLINK_OPN_RCVD);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM,
						   0);
			break;
		case REQ_RJCT:
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		default:
			break;
		}
		break;
	case PLINK_OPN_SNT:
		switch (event) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			return;
		case OPN_RJCT:
		case CNF_RJCT:
			if (!reason)
				reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(
				conf->dot11MeshHoldingTimeout / 1000,
				(conf->dot11MeshHoldingTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			/* retry timer is left untouched */
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_OPN_RCVD);
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_CNF_RCVD);
			eloop_cancel_timeout(plink_timer, wpa_s, sta);
			eloop_register_timeout(
				conf->dot11MeshConfirmTimeout / 1000,
				(conf->dot11MeshConfirmTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			break;
		default:
			break;
		}
		break;
	case PLINK_OPN_RCVD:
		switch (event) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			return;
		case OPN_RJCT:
		case CNF_RJCT:
			if (!reason)
				reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(
				conf->dot11MeshHoldingTimeout / 1000,
				(conf->dot11MeshHoldingTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			sta->mpm_close_reason = reason;
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CONFIRM, 0);
			break;
		case CNF_ACPT:
			if (conf->security & MESH_CONF_SEC_AMPE)
				mesh_rsn_derive_mtk(wpa_s, sta);
			mesh_mpm_plink_estab(wpa_s, sta);
			break;
		default:
			break;
		}
		break;
	case PLINK_CNF_RCVD:
		switch (event) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			return;
		case OPN_RJCT:
		case CNF_RJCT:
			if (!reason)
				reason = WLAN_REASON_MESH_CONFIG_POLICY_VIOLATION;
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;
			eloop_register_timeout(
				conf->dot11MeshHoldingTimeout / 1000,
				(conf->dot11MeshHoldingTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			sta->mpm_close_reason = reason;
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			if (conf->security & MESH_CONF_SEC_AMPE)
				mesh_rsn_derive_mtk(wpa_s, sta);
			mesh_mpm_plink_estab(wpa_s, sta);
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;
	case PLINK_ESTAB:
		switch (event) {
		case OPN_RJCT:
		case CNF_RJCT:
		case CLS_ACPT:
			wpa_mesh_set_plink_state(wpa_s, sta, PLINK_HOLDING);
			if (!reason)
				reason = WLAN_REASON_MESH_CLOSE_RCVD;

			eloop_register_timeout(
				conf->dot11MeshHoldingTimeout / 1000,
				(conf->dot11MeshHoldingTimeout % 1000) * 1000,
				plink_timer, wpa_s, sta);
			sta->mpm_close_reason = reason;

			wpa_msg(wpa_s, MSG_INFO, "mesh plink with " MACSTR
				" closed with reason %d",
				MAC2STR(sta->addr), reason);

			wpas_notify_mesh_peer_disconnected(wpa_s, sta->addr,
							   reason);

			hapd->num_plinks--;

			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		case OPN_ACPT:
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CONFIRM, 0);
			break;
		default:
			break;
		}
		break;
	case PLINK_HOLDING:
		switch (event) {
		case CLS_ACPT:
			mesh_mpm_fsm_restart(wpa_s, sta);
			return;
		case OPN_ACPT:
		case CNF_ACPT:
		case OPN_RJCT:
		case CNF_RJCT:
			reason = sta->mpm_close_reason;
			mesh_mpm_send_plink_action(wpa_s, sta,
						   PLINK_CLOSE, reason);
			break;
		default:
			break;
		}
		break;
	default:
		wpa_msg(wpa_s, MSG_DEBUG,
			"Unsupported MPM event %s for state %s",
			mplevent[event], mplstate[sta->plink_state]);
		break;
	}

	wpa_msg(wpa_s, MSG_INFO,
		"[mesh_trace] MPM_FSM_TRANSITION: peer=" MACSTR
		" prev=%s event=%s new=%s reason=%u",
		MAC2STR(sta->addr),
		mplstate[prev_state],
		mplevent[event],
		mplstate[sta->plink_state],
		reason);
}


void mesh_mpm_action_rx(struct wpa_supplicant *wpa_s,
			const struct ieee80211_mgmt *mgmt, size_t len)
{
	u8 action_field;
	struct hostapd_data *hapd = wpa_s->ifmsh->bss[0];
	struct mesh_conf *mconf = wpa_s->ifmsh->mconf;
	struct sta_info *sta;
	u16 plid = 0, llid = 0, aid = 0;
	enum plink_event event;
	struct ieee802_11_elems elems;
	struct mesh_peer_mgmt_ie peer_mgmt_ie;
	const u8 *ies;
	const u8 *raw_ies;
	size_t ie_len;
	size_t raw_ie_len;
	int ret;
	u16 reason = 0;
	u16 close_reason = 0;

	if (mgmt->u.action.category != WLAN_ACTION_SELF_PROTECTED)
	{
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=non_self_protected category=%u sa=" MACSTR,
			   mgmt->u.action.category,
			   MAC2STR(mgmt->sa));
		return;
	}

	action_field = mgmt->u.action.u.slf_prot_action.action;
	if (action_field != PLINK_OPEN &&
	    action_field != PLINK_CONFIRM &&
	    action_field != PLINK_CLOSE)
	{
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=unsupported_action action=%u sa=" MACSTR,
			   action_field,
			   MAC2STR(mgmt->sa));
		return;
	}

	ies = mgmt->u.action.u.slf_prot_action.variable;
	ie_len = (const u8 *) mgmt + len -
		mgmt->u.action.u.slf_prot_action.variable;
	raw_ies = ies;
	raw_ie_len = ie_len;
#ifdef CONFIG_MM_MESH_DEBUG_LOG
	{
		u32 raw_ie_hash = mesh_dbg_fnv1a32(raw_ies, raw_ie_len);
		wpa_printf(MSG_ERROR,
		   "Mesh MPM[rx-open-v2]: rx_len=%u action=%u raw_ie_len=%u raw_ie_hash=0x%08x sa=" MACSTR " da=" MACSTR,
		   (unsigned int) len,
		   action_field,
		   (unsigned int) raw_ie_len,
		   raw_ie_hash,
		   MAC2STR(mgmt->sa),
		   MAC2STR(mgmt->da));
	}
	wpa_hexdump(MSG_ERROR,
		    "Mesh MPM[rx-open-v2]: raw variable IEs",
		    raw_ies, raw_ie_len);
#endif

	/* at least expect mesh id and peering mgmt */
	if (ie_len < 2 + 2) {
		wpa_printf(MSG_DEBUG,
			   "MPM: Ignore too short action frame %u ie_len %u",
			   action_field, (unsigned int) ie_len);
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=too_short action=%u ie_len=%u sa=" MACSTR,
			   action_field,
			   (unsigned int) ie_len,
			   MAC2STR(mgmt->sa));
		return;
	}
	wpa_printf(MSG_DEBUG, "MPM: Received PLINK action %u", action_field);

	if (action_field == PLINK_OPEN || action_field == PLINK_CONFIRM) {
		wpa_printf(MSG_DEBUG, "MPM: Capability 0x%x",
			   WPA_GET_LE16(ies));
		ies += 2;	/* capability */
		ie_len -= 2;
	}
	if (action_field == PLINK_CONFIRM) {
		aid = WPA_GET_LE16(ies);
		wpa_printf(MSG_DEBUG, "MPM: AID 0x%x", aid);
		ies += 2;	/* aid */
		ie_len -= 2;
	}

	/* check for mesh peering, mesh id and mesh config IEs */
	if (ieee802_11_parse_elems(ies, ie_len, &elems, 0) == ParseFailed) {
		wpa_printf(MSG_DEBUG, "MPM: Failed to parse PLINK IEs");
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=parse_failed action=%u ie_len=%u sa=" MACSTR,
			   action_field,
			   (unsigned int) ie_len,
			   MAC2STR(mgmt->sa));
		return;
	}
	if (elems.mic && elems.mic >= &mgmt->u.action.category + 2) {
		size_t cat_to_mic = (size_t) ((elems.mic - 2) -
					 &mgmt->u.action.category);
		MESH_DBG_PRINTF("Mesh MPM[rx-open-v2]: parsed_ie_len=%u cat_to_mic=%u mic_len=%u peer_mgmt_len=%u rsn_len=%u\n",
		   (unsigned int) ie_len,
		   (unsigned int) cat_to_mic,
		   (unsigned int) elems.mic_len,
		   (unsigned int) elems.peer_mgmt_len,
		   (unsigned int) elems.rsn_ie_len);
	}
	if (!elems.peer_mgmt) {
		wpa_printf(MSG_DEBUG,
			   "MPM: No Mesh Peering Management element");
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=no_peer_mgmt action=%u sa=" MACSTR,
			   action_field,
			   MAC2STR(mgmt->sa));
		return;
	}
	if (action_field != PLINK_CLOSE) {
		if (!elems.mesh_id || !elems.mesh_config) {
			wpa_printf(MSG_DEBUG,
				   "MPM: No Mesh ID or Mesh Configuration element");
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=missing_mesh_fields action=%u mesh_id=%u mesh_cfg=%u sa=" MACSTR,
				   action_field,
				   elems.mesh_id ? 1 : 0,
				   elems.mesh_config ? 1 : 0,
				   MAC2STR(mgmt->sa));
			return;
		}

		if (!matches_local(wpa_s, &elems)) {
			wpa_printf(MSG_DEBUG,
				   "MPM: Mesh ID or Mesh Configuration element do not match local MBSS");
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=mesh_mismatch action=%u sa=" MACSTR,
				   action_field,
				   MAC2STR(mgmt->sa));
			return;
		}
	}

	ret = mesh_mpm_parse_peer_mgmt(wpa_s, action_field,
				       elems.peer_mgmt,
				       elems.peer_mgmt_len,
				       &peer_mgmt_ie);
	if (ret) {
		wpa_printf(MSG_DEBUG, "MPM: Mesh parsing rejected frame");
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=peer_mgmt_parse_reject action=%u sa=" MACSTR,
			   action_field,
			   MAC2STR(mgmt->sa));
		return;
	}

	/* the sender's llid is our plid and vice-versa */
	plid = WPA_GET_LE16(peer_mgmt_ie.llid);
	if (peer_mgmt_ie.plid)
		llid = WPA_GET_LE16(peer_mgmt_ie.plid);
	wpa_printf(MSG_DEBUG, "MPM: plid=0x%x llid=0x%x", plid, llid);

	if (action_field == PLINK_CLOSE) {
		close_reason = WPA_GET_LE16(peer_mgmt_ie.reason);
		wpa_printf(MSG_DEBUG, "MPM: close reason=%u", close_reason);
	}

	sta = ap_get_sta(hapd, mgmt->sa);

	/*
	 * If this is an open frame from an unknown STA, and this is an
	 * open mesh, then go ahead and add the peer before proceeding.
	 */
	if (!sta && action_field == PLINK_OPEN &&
	    (!(mconf->security & MESH_CONF_SEC_AMPE) ||
	     wpa_auth_pmksa_get(hapd->wpa_auth, mgmt->sa, NULL)))
		sta = mesh_mpm_add_peer(wpa_s, mgmt->sa, &elems);

	if (!sta) {
		wpa_printf(MSG_DEBUG, "MPM: No STA entry for peer");
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=no_sta_entry action=%u sa=" MACSTR,
			   action_field,
			   MAC2STR(mgmt->sa));
		return;
	}

	MESH_DBG_PRINTF("[mesh_flow] STEP1_SAE_GATE peer=" MACSTR " action=%u sae_ptr=%p sae_state=%d plink_state=%s\n",
	       MAC2STR(mgmt->sa),
	       action_field,
	       (void *) sta->sae,
	       sta->sae ? sta->sae->state : -1,
	       mplstate[sta->plink_state]);

	wpa_printf(MSG_DEBUG,
		   "[mesh_trace] MPM_ACTION_STA_CTX: action=%u state=%s my_lid=0x%x peer_lid=0x%x rx_plid=0x%x rx_llid=0x%x sa=" MACSTR,
		   action_field,
		   mplstate[sta->plink_state],
		   sta->my_lid,
		   sta->peer_lid,
		   plid,
		   llid,
		   MAC2STR(mgmt->sa));

#ifdef CONFIG_SAE
	/* peer is in sae_accepted? */
	if (sta->sae && sta->sae->state != SAE_ACCEPTED &&
	    action_field != PLINK_CLOSE) {
		/* Do not use AMPE to promote a pending SAE exchange. At this point
		 * the AEK/nonces may still belong to the previous generation, and
		 * sae_accept_sta() would reinitialize AMPE after this OPEN was
		 * decrypted, discarding the peer nonce just learned from it. SAE
		 * retransmission must complete first; only then may MPM consume OPEN. */
		wpa_printf(MSG_DEBUG, "MPM: SAE not yet accepted for peer");
		MESH_DBG_PRINTF("[mesh_flow] STEP1_BLOCKED reason=sae_not_accepted peer=" MACSTR " action=%u sae_state=%d\n",
		       MAC2STR(mgmt->sa), action_field, sta->sae->state);
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=sae_not_accepted action=%u sae_state=%d state=%s my_lid=0x%x peer_lid=0x%x rx_plid=0x%x rx_llid=0x%x sa=" MACSTR,
			   action_field, sta->sae->state,
			   mplstate[sta->plink_state], sta->my_lid,
			   sta->peer_lid, plid, llid, MAC2STR(mgmt->sa));
		return;
	}
	if (sta->sae && sta->sae->state != SAE_ACCEPTED &&
	    action_field == PLINK_CLOSE) {
		/* This CLOSE belongs only to this peer's earlier/stale peering
		 * generation. In multi-peer mode another peer may already be ESTAB
		 * while this peer is still running SAE. Letting the CLOSE enter MPM
		 * resets this sta->sae and repeatedly returns it to SAE_NOTHING.
		 * Preserve the peer-local SAE generation; a CLOSE received after
		 * SAE_ACCEPTED is still handled by the normal MPM state machine. */
		MESH_DBG_PRINTF("[mesh_peer_state] peer=" MACSTR
				 " event=DROP_PRE_SAE_CLOSE sae=%d state=%s"
				 " lids=%04x/%04x rx=%04x/%04x\n",
				 MAC2STR(sta->addr), sta->sae->state,
				 mplstate[sta->plink_state], sta->my_lid,
				 sta->peer_lid, plid, llid);
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=close_before_sae_accepted sae_state=%d state=%s my_lid=0x%x peer_lid=0x%x rx_plid=0x%x rx_llid=0x%x sa=" MACSTR,
			   sta->sae->state,
			   mplstate[sta->plink_state],
			   sta->my_lid,
			   sta->peer_lid,
			   plid,
			   llid,
			   MAC2STR(mgmt->sa));
		return;
	}
#endif /* CONFIG_SAE */

	if (!sta->my_lid)
		mesh_mpm_init_link(wpa_s, sta);

	if (mconf->security & MESH_CONF_SEC_AMPE) {
		int res;

		MESH_DBG_PRINTF("[mesh_flow] STEP2_AMPE_RX start peer=" MACSTR " action=%u my_lid=0x%x peer_lid=0x%x\n",
		       MAC2STR(mgmt->sa),
		       action_field,
		       sta->my_lid,
		       sta->peer_lid);

		res = mesh_rsn_process_ampe(wpa_s, sta, &elems,
					    &mgmt->u.action.category,
					    peer_mgmt_ie.chosen_pmk,
					    mgmt->da,
					    ies, ie_len);
		if (res) {
			MESH_DBG_PRINTF("[mesh_flow] STEP2_BLOCKED reason=ampe_reject peer=" MACSTR " action=%u res=%d\n",
			       MAC2STR(mgmt->sa),
			       action_field,
			       res);
			wpa_printf(MSG_DEBUG,
				   "MPM: RSN process rejected frame (res=%d)",
				   res);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=rsn_reject action=%u res=%d sa=" MACSTR,
				   action_field,
				   res,
				   MAC2STR(mgmt->sa));
			if (action_field == PLINK_OPEN && res == -2) {
				/* AES-SIV decryption failed */
				mesh_mpm_fsm(wpa_s, sta, OPN_RJCT,
					     WLAN_REASON_MESH_INVALID_GTK);
			}
			return;
		}

		MESH_DBG_PRINTF("[mesh_flow] STEP2_AMPE_RX ok peer=" MACSTR " action=%u\n",
		       MAC2STR(mgmt->sa),
		       action_field);

#ifdef CONFIG_OCV
		if (action_field == PLINK_OPEN && elems.rsn_ie) {
			struct wpa_state_machine *sm = sta->wpa_sm;
			struct wpa_ie_data data;

			res = wpa_parse_wpa_ie_rsn(elems.rsn_ie - 2,
						   elems.rsn_ie_len + 2,
						   &data);
			if (res) {
				wpa_printf(MSG_DEBUG,
					   "Failed to parse RSN IE (res=%d)",
					   res);
				wpa_hexdump(MSG_DEBUG, "RSN IE", elems.rsn_ie,
					    elems.rsn_ie_len);
				return;
			}

			wpa_auth_set_ocv(sm, mconf->ocv &&
					 (data.capabilities &
					  WPA_CAPABILITY_OCVC));
		}

		if (action_field != PLINK_CLOSE &&
		    wpa_auth_uses_ocv(sta->wpa_sm)) {
			struct wpa_channel_info ci;
			int tx_chanwidth;
			int tx_seg1_idx;

			if (wpa_drv_channel_info(wpa_s, &ci) != 0) {
				wpa_printf(MSG_WARNING,
					   "MPM: Failed to get channel info to validate received OCI in MPM Confirm");
				wpa_printf(MSG_DEBUG,
					   "[mesh_trace] MPM_ACTION_DROP: reason=ocv_channel_info_fail action=%u sa=" MACSTR,
					   action_field,
					   MAC2STR(mgmt->sa));
				return;
			}

			if (get_tx_parameters(
				    sta, channel_width_to_int(ci.chanwidth),
				    ci.seg1_idx, &tx_chanwidth,
				    &tx_seg1_idx) < 0) {
				wpa_printf(MSG_DEBUG,
					   "[mesh_trace] MPM_ACTION_DROP: reason=ocv_tx_param_fail action=%u sa=" MACSTR,
					   action_field,
					   MAC2STR(mgmt->sa));
				return;
			}

			if (ocv_verify_tx_params(elems.oci, elems.oci_len, &ci,
						 tx_chanwidth, tx_seg1_idx) !=
			    OCI_SUCCESS) {
				wpa_printf(MSG_WARNING, "MPM: OCV failed: %s",
					   ocv_errorstr);
				wpa_printf(MSG_DEBUG,
					   "[mesh_trace] MPM_ACTION_DROP: reason=ocv_verify_fail action=%u sa=" MACSTR,
					   action_field,
					   MAC2STR(mgmt->sa));
				return;
			}
		}
#endif /* CONFIG_OCV */
	}

	if (sta->plink_state == PLINK_BLOCKED) {
		wpa_printf(MSG_DEBUG, "MPM: PLINK_BLOCKED");
		wpa_printf(MSG_DEBUG,
			   "[mesh_trace] MPM_ACTION_DROP: reason=plink_blocked action=%u sa=" MACSTR,
			   action_field,
			   MAC2STR(mgmt->sa));
		return;
	}

	/* Now we will figure out the appropriate event... */
	MESH_DBG_PRINTF("[mesh_flow] STEP3_MPM_FSM_DISPATCH peer=" MACSTR " action=%u state=%s my_lid=0x%x peer_lid=0x%x rx_plid=0x%x rx_llid=0x%x\n",
	       MAC2STR(mgmt->sa),
	       action_field,
	       mplstate[sta->plink_state],
	       sta->my_lid,
	       sta->peer_lid,
	       plid,
	       llid);
	MESH_DBG_PRINTF("[mesh_upper] pre-switch action=%u state=%s my_lid=0x%x peer_lid=0x%x rx_plid=0x%x rx_llid=0x%x peer_plid_present=%u sa=" MACSTR "\n",
	       action_field,
	       mplstate[sta->plink_state],
	       sta->my_lid,
	       sta->peer_lid,
	       plid,
	       llid,
	       peer_mgmt_ie.plid ? 1 : 0,
	       MAC2STR(mgmt->sa));

	switch (action_field) {
	case PLINK_OPEN:
		MESH_DBG_PRINTF("[mesh_upper] OPEN checks free=%d peer_lid_nonzero=%u peer_lid_eq=%u\n",
		       plink_free_count(hapd),
		       sta->peer_lid ? 1 : 0,
		       (sta->peer_lid == plid) ? 1 : 0);
		if (plink_free_count(hapd) == 0) {
			event = REQ_RJCT;
			reason = WLAN_REASON_MESH_MAX_PEERS;
			wpa_printf(MSG_INFO,
				   "MPM: Peer link num over quota(%d)",
				   hapd->max_plinks);
		} else if (sta->peer_lid && sta->peer_lid != plid) {
			if (sta->plink_state != PLINK_ESTAB && plid) {
				MESH_DBG_PRINTF("[mesh_upper] OPEN taking relearn branch (non-ESTAB)\n");
				wpa_printf(MSG_DEBUG,
					   "[mesh_trace] MPM_OPEN: relearn peer_lid old=0x%x new=0x%x state=%s sa=" MACSTR,
					   sta->peer_lid,
					   plid,
					   mplstate[sta->plink_state],
					   MAC2STR(mgmt->sa));
				sta->peer_lid = plid;
				event = OPN_ACPT;
			} else {
				MESH_DBG_PRINTF("[mesh_upper] OPEN rejecting mismatch branch (state=%s plid=0x%x)\n",
				       mplstate[sta->plink_state],
				       plid);
				wpa_printf(MSG_DEBUG,
					   "MPM: peer_lid mismatch: 0x%x != 0x%x",
					   sta->peer_lid, plid);
				wpa_printf(MSG_DEBUG,
					   "[mesh_trace] MPM_ACTION_DROP: reason=open_peer_lid_mismatch action=%u expected=0x%x got=0x%x sa=" MACSTR,
					   action_field,
					   sta->peer_lid,
					   plid,
					   MAC2STR(mgmt->sa));
				return; /* no FSM event */
			}
		} else {
			sta->peer_lid = plid;
			event = OPN_ACPT;
		}
		break;
	case PLINK_CONFIRM:
		MESH_DBG_PRINTF("[mesh_upper] CONFIRM checks free=%d my_lid_eq=%u peer_lid_nonzero=%u peer_lid_eq=%u\n",
		       plink_free_count(hapd),
		       (sta->my_lid == llid) ? 1 : 0,
		       sta->peer_lid ? 1 : 0,
		       (sta->peer_lid == plid) ? 1 : 0);
		if (plink_free_count(hapd) == 0) {
			event = REQ_RJCT;
			reason = WLAN_REASON_MESH_MAX_PEERS;
			wpa_printf(MSG_INFO,
				   "MPM: Peer link num over quota(%d)",
				   hapd->max_plinks);
		} else if (sta->my_lid != llid ||
			   (sta->peer_lid && sta->peer_lid != plid)) {
			wpa_printf(MSG_DEBUG,
				   "MPM: lid mismatch: my_lid: 0x%x != 0x%x or peer_lid: 0x%x != 0x%x",
				   sta->my_lid, llid, sta->peer_lid, plid);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=confirm_lid_mismatch action=%u my_lid=0x%x rx_llid=0x%x peer_lid=0x%x rx_plid=0x%x sa=" MACSTR,
				   action_field,
				   sta->my_lid,
				   llid,
				   sta->peer_lid,
				   plid,
				   MAC2STR(mgmt->sa));
			return; /* no FSM event */
		} else {
			if (!sta->peer_lid)
				sta->peer_lid = plid;
			sta->peer_aid = aid;
			event = CNF_ACPT;
		}
		break;
	case PLINK_CLOSE:
		MESH_DBG_PRINTF("[mesh_upper] CLOSE checks estab=%u plid_nonzero=%u peer_lid_zero=%u peer_lid_eq=%u llid_eq_my=%u peer_plid_present=%u\n",
		       sta->plink_state == PLINK_ESTAB ? 1 : 0,
		       plid ? 1 : 0,
		       sta->peer_lid ? 0 : 1,
		       (sta->peer_lid == plid) ? 1 : 0,
		       (llid == sta->my_lid) ? 1 : 0,
		       peer_mgmt_ie.plid ? 1 : 0);
		MESH_DBG_PRINTF("[mesh_upper] CLOSE reason=%u state=%s my_lid=0x%x peer_lid=0x%x rx_llid=0x%x rx_plid=0x%x\n",
		       close_reason,
		       mplstate[sta->plink_state],
		       sta->my_lid,
		       sta->peer_lid,
		       llid,
		       plid);
		if (sta->plink_state == PLINK_ESTAB &&
		    peer_mgmt_ie.plid &&
		    (llid != sta->my_lid || plid != sta->peer_lid)) {
			/* Delayed CLOSE frames are common after a long HaLow TX stall.
			 * Never let an older pair of link IDs close the established
			 * generation that replaced it. */
			MESH_DBG_PRINTF("[mesh_peer_state] peer=" MACSTR
					 " event=DROP_STALE_ESTAB_CLOSE current=%04x/%04x"
					 " rx=%04x/%04x reason=%u\n",
					 MAC2STR(sta->addr), sta->my_lid,
					 sta->peer_lid, llid, plid, close_reason);
			return;
		} else if (sta->plink_state == PLINK_ESTAB)
			event = CLS_ACPT;
		else if (peer_mgmt_ie.plid && llid == 0 &&
			 plid && sta->peer_lid && sta->peer_lid == plid) {
			/*
			 * Interop guard: some peers emit CLOSE in non-ESTAB with
			 * llid=0 while still carrying the current peer_lid in plid.
			 * Ignore this transient CLOSE to keep the in-flight peering
			 * exchange from being reset.
			 */
			MESH_DBG_PRINTF("[mesh_upper] CLOSE transient ignore (state=%s my_lid=0x%x peer_lid=0x%x rx_llid=0x%x rx_plid=0x%x)\n",
			       mplstate[sta->plink_state],
			       sta->my_lid,
			       sta->peer_lid,
			       llid,
			       plid);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_IGNORE: reason=close_transient_llid_zero_non_estab action=%u state=%s my_lid=0x%x peer_lid=0x%x rx_llid=0x%x rx_plid=0x%x sa=" MACSTR,
				   action_field,
				   mplstate[sta->plink_state],
				   sta->my_lid,
				   sta->peer_lid,
				   llid,
				   plid,
				   MAC2STR(mgmt->sa));
			return; /* no FSM event */
		}
		else if (sta->plink_state == PLINK_CNF_RCVD &&
			 plid && sta->peer_lid && sta->peer_lid == plid &&
			 llid == sta->my_lid) {
			/*
			 * Interop guard: peers can emit transient CLOSE while both sides are
			 * in CNF_RCVD. If link IDs still match, keep negotiation alive by
			 * ignoring CLOSE and re-sending CONFIRM instead of dropping to HOLDING.
			 */
			MESH_DBG_PRINTF("[mesh_upper] CLOSE transient ignore in CNF_RCVD (reason=%u my_lid=0x%x peer_lid=0x%x rx_llid=0x%x rx_plid=0x%x)\n",
			       close_reason,
			       sta->my_lid,
			       sta->peer_lid,
			       llid,
			       plid);
			mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CONFIRM, 0);
			return; /* no FSM event */
		}
		else if (peer_mgmt_ie.plid && llid != sta->my_lid) {
			/*
			 * In non-ESTAB states, require the peer plid (our llid)
			 * to match my_lid before accepting CLOSE. Otherwise, a
			 * stale/mismatched CLOSE can push us to HOLDING and tear
			 * down an in-progress handshake.
			 */
			MESH_DBG_PRINTF("[mesh_upper] CLOSE rejecting llid mismatch in non-ESTAB (my_lid=0x%x rx_llid=0x%x)\n",
			       sta->my_lid,
			       llid);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=close_llid_mismatch_non_estab action=%u my_lid=0x%x rx_llid=0x%x sa=" MACSTR,
				   action_field,
				   sta->my_lid,
				   llid,
				   MAC2STR(mgmt->sa));
			return; /* no FSM event */
		}
		else if (plid && (!sta->peer_lid ||
				  (sta->peer_lid != plid && llid == sta->my_lid))) {
			/*
			 * Some peers may send CLOSE before we have learned peer_lid,
			 * or after restarting with a new link-id while referring to
			 * our current my_lid. Relearn peer_lid from CLOSE to avoid
			 * getting stuck in retry/mismatch loops.
			 */
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_CLOSE: learn peer_lid from CLOSE old=0x%x new=0x%x sa=" MACSTR,
				   sta->peer_lid,
				   plid,
				   MAC2STR(mgmt->sa));
			sta->peer_lid = plid;
			event = CLS_ACPT;
		}
		else if (sta->peer_lid != plid) {
			wpa_printf(MSG_DEBUG,
				   "MPM: peer_lid mismatch: 0x%x != 0x%x",
				   sta->peer_lid, plid);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=close_peer_lid_mismatch action=%u expected=0x%x got=0x%x sa=" MACSTR,
				   action_field,
				   sta->peer_lid,
				   plid,
				   MAC2STR(mgmt->sa));
			return; /* no FSM event */
		} else if (peer_mgmt_ie.plid && sta->my_lid != llid) {
			wpa_printf(MSG_DEBUG,
				   "MPM: my_lid mismatch: 0x%x != 0x%x",
				   sta->my_lid, llid);
			wpa_printf(MSG_DEBUG,
				   "[mesh_trace] MPM_ACTION_DROP: reason=close_my_lid_mismatch action=%u expected=0x%x got=0x%x sa=" MACSTR,
				   action_field,
				   sta->my_lid,
				   llid,
				   MAC2STR(mgmt->sa));
			return; /* no FSM event */
		} else {
			event = CLS_ACPT;
		}
		break;
	default:
		/*
		 * This cannot be hit due to the action_field check above, but
		 * compilers may not be able to figure that out and can warn
		 * about uninitialized event below.
		 */
		return;
	}
	mesh_mpm_fsm(wpa_s, sta, event, reason);
}

#if defined(CONFIG_MESH) && defined(CONFIG_IEEE80211AH)
void mesh_mpm_kickout_peer(struct hostapd_data *hapd)
{
	struct sta_info *sta = ap_get_sta(hapd, hapd->mesh_kickout_peer_addr);

	if (!sta) {
		wpa_printf(MSG_ERROR, "%s: Peer " MACSTR " not found - stas=%d, links=%d/%d\n",
				__func__,
				MAC2STR(hapd->mesh_kickout_peer_addr), hapd->num_sta,
				hapd->num_plinks, hapd->max_plinks);
		return;
	}

	wpa_printf(MSG_DEBUG, "%s: closing plink sta=" MACSTR "\n", __func__, MAC2STR(sta->addr));
	ap_free_sta(hapd, sta);
	/* Clear kickout peer addr */
	memset(hapd->mesh_kickout_peer_addr, 0, ETH_ALEN);
}
#endif /* CONFIG_MESH && CONFIG_IEEE80211AH */

/* called by ap_free_sta */
void mesh_mpm_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct wpa_supplicant *wpa_s = hapd->iface->owner;
	int reason = WLAN_REASON_MESH_PEERING_CANCELLED;

	MESH_DBG_PRINTF("[mesh_trace] MPM_FREE_STA peer=" MACSTR " state=%s assoc=%u my_lid=0x%x peer_lid=0x%x\n",
	       MAC2STR(sta->addr),
	       mplstate[sta->plink_state],
	       (sta->flags & WLAN_STA_ASSOC) ? 1 : 0,
	       sta->my_lid,
	       sta->peer_lid);

#if defined(CONFIG_MESH) && defined(CONFIG_IEEE80211AH)
	if (!memcmp(hapd->mesh_kickout_peer_addr, sta->addr, ETH_ALEN))
		reason = WLAN_REASON_MESH_MAX_PEERS;
#endif /* CONFIG_MESH && CONFIG_IEEE80211AH */

	if (sta->plink_state == PLINK_ESTAB) {
		hapd->num_plinks--;
		wpas_notify_mesh_peer_disconnected(
			wpa_s, sta->addr, WLAN_REASON_UNSPECIFIED);
	} else {
		/*
		 * For transient/non-established peers being freed, skip sending an
		 * additional CLOSE from free path to avoid close/restart churn.
		 */
		MESH_DBG_PRINTF("[mesh_fix] MPM_FREE_STA skip CLOSE non-ESTAB peer=" MACSTR " state=%s\n",
		       MAC2STR(sta->addr),
		       mplstate[sta->plink_state]);
		eloop_cancel_timeout(plink_timer, ELOOP_ALL_CTX, sta);
		eloop_cancel_timeout(mesh_auth_timer, ELOOP_ALL_CTX, sta);
		return;
	}
	mesh_mpm_send_plink_action(wpa_s, sta, PLINK_CLOSE, reason);
	wpa_printf(MSG_DEBUG, "MPM closing plink sta=" MACSTR,
			   MAC2STR(sta->addr));
	eloop_cancel_timeout(plink_timer, ELOOP_ALL_CTX, sta);
	eloop_cancel_timeout(mesh_auth_timer, ELOOP_ALL_CTX, sta);
}
