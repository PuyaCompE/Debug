/******************************************************************************
Copyright (c) 2009-2018 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_api.c
Version     : v0.1 
Description : awn wifi handler api

Author      : <dengzhong@tp-link.com.cn>
Create date : 2019/4/1

History     :
01, 2019/4/1 Deng Zhong, Created file.

*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <libubox/uloop.h>  /* for bool definition */

#include "awn_wifi_handler_api.h"



#define AWN_PLATFORM_CALL(func, ...) \
	((awn_platform_ops && awn_platform_ops->func) ? awn_platform_ops->func(__VA_ARGS__) : false)

extern AWN_PLATFORM_OPS *awn_platform_ops;

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
int awnd_init_cfg80211(void)
{
	return AWN_PLATFORM_CALL(init_cfg80211);
}

int awnd_deinit_cfg80211(void)
{
	return AWN_PLATFORM_CALL(deinit_cfg80211);
}
#endif

int awnd_get_default_mesh_channel(AWND_BAND_TYPE band, int *channel)
{
	return AWN_PLATFORM_CALL(get_default_mesh_channel, band, channel);
}

int awnd_check_block_chan_list(AWND_BAND_TYPE band, int *channel)
{
	return AWN_PLATFORM_CALL(check_block_chan_list, band, channel);
}

int awnd_get_sta_channel(AWND_BAND_TYPE band, int *channel)
{
	return AWN_PLATFORM_CALL(get_sta_channel, band, channel);
}

int awnd_get_backhaul_ap_channel(AWND_BAND_TYPE band, int *channel)
{
	return AWN_PLATFORM_CALL(get_backhaul_ap_channel, band, channel);
}

int awnd_get_phy(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth)
{
	return AWN_PLATFORM_CALL(get_phy, band, nss, phyMode, chwidth);
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#if GET_AP_RSSI
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, int *rssi, BOOL roaming_connected[])
{
	return AWN_PLATFORM_CALL(get_wds_state, band, up, rssi, roaming_connected);
}
#else
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, BOOL roaming_connected[])
{
	return AWN_PLATFORM_CALL(get_wds_state, band, up, roaming_connected);
}
#endif	/* GET_AP_RSSI	*/
#else
#if GET_AP_RSSI
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, int *rssi)
{
	return AWN_PLATFORM_CALL(get_wds_state, band, up, rssi);
}
#else
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up)
{
	return AWN_PLATFORM_CALL(get_wds_state, band, up);
}
#endif
#endif

int awnd_get_cac_state(AWND_BAND_TYPE band, int *state)
{
	return AWN_PLATFORM_CALL(get_cac_state, band, state);
}

int awnd_get_rootap_phyRate(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate)
{
	return AWN_PLATFORM_CALL(get_rootap_phyRate, band, txrate, rxrate);
}

int awnd_get_rootap_rssi(AWND_BAND_TYPE band, INT32 *rssi)
{
	return AWN_PLATFORM_CALL(get_rootap_rssi, band, rssi);
}

#ifdef SUPPORT_MESHMODE_2G
int awnd_get_chanim(AWND_BAND_TYPE band, INT32 *chanutil, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw)
{
	return AWN_PLATFORM_CALL(get_chanim, band, chanutil, intf, cur_chan, bw);
}

void awnd_do_csa(int target_chan, AWND_WIFI_BW_TYPE bw, AWND_CHAN_OFFSET_TYPE offset)
{
	return AWN_PLATFORM_CALL(do_csa, target_chan, bw, offset);
}

void awnd_disable_sta_vap(int disable, AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(disable_sta_vap, disable, band);
}
#endif

int awnd_get_rootap_info(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(get_rootap_info, pApEntry, band);
}

int awnd_get_rootap_tpie(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(get_rootap_tpie, pAwndNetInfo, band);
}

int awnd_get_tpie(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(get_tpie, pMac, entry_type, pAwndNetInfo, band);
}

int awnd_init_tpie(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType)
{
	return AWN_PLATFORM_CALL(init_tpie, pAwndNetInfo, pApMac, pLabel, weight, netType);
}

int awnd_update_wifi_tpie(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType)
{
	//return 0;
	return AWN_PLATFORM_CALL(update_wifi_tpie, pAwndNetInfo, lan_mac, uplinkMask, uplinkRate, meshType);
}

int awnd_flush_scan_table_single_band(AWND_BAND_TYPE band, BOOL force)
{
	return AWN_PLATFORM_CALL(flush_scan_table_single_band, band, force);
}

int awnd_flush_scan_table(void)
{
	return AWN_PLATFORM_CALL(flush_scan_table);
}

int awnd_do_scan(UINT8 scanBandMask)
{
	return AWN_PLATFORM_CALL(do_scan, scanBandMask);
}

int awnd_do_scan_fast(UINT8 scanBandMask)
{
	return AWN_PLATFORM_CALL(do_scan_fast, scanBandMask);
}
#ifdef CONFIG_DCMP_GLOBAL_support
int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        char* preconfig_ssid, UINT8* preconfig_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
	return AWN_PLATFORM_CALL(get_scan_result, pAwndScanResult, match_ssid, match_label, preconf_ssid, preconf_label, preconfig_ssid, preconfig_label, band, vap_type, isFast);
}
#else
int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
		char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
	return AWN_PLATFORM_CALL(get_scan_result, pAwndScanResult, match_ssid, match_label, preconf_ssid, preconf_label, band, vap_type, isFast);
}
#endif

int awnd_set_channel(AWND_BAND_TYPE band, UINT8 channel)
{
	return AWN_PLATFORM_CALL(set_channel, band, channel);
}

int awnd_get_sta_iface_in_bridge(AWND_BAND_TYPE band, UINT8* ifname)
{
	return AWN_PLATFORM_CALL(get_sta_iface_in_bridge, band, ifname);
}

int awnd_disconn_sta_pre(AWND_BAND_TYPE band, UINT* pBandMask)
{
	return AWN_PLATFORM_CALL(disconn_sta_pre, band, pBandMask);
}

int awnd_disconn_all_sta_pre(UINT* pBandMask)
{
	return AWN_PLATFORM_CALL(disconn_all_sta_pre, pBandMask);
}

int awnd_disconn_sta_post(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(disconn_sta_post, band);
}

int awnd_disconn_sta(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(disconn_sta, band);
}

int awnd_disconn_all_sta(void)
{
	return AWN_PLATFORM_CALL(disconn_all_sta);
}

int awnd_reconn_sta_pre(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp)
{
	return AWN_PLATFORM_CALL(reconn_sta_pre, band, pRootAp);
}

int awnd_reconn_sta_post(AWND_BAND_TYPE band, BOOL check_wpa_status)
{
	return AWN_PLATFORM_CALL(reconn_sta_post, band, check_wpa_status);
}

int awnd_reset_sta_connection(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(reset_sta_connection, band);
}

int awnd_set_backhaul_sta_dev(UINT32 link_state, unsigned int eth_link_state)
{
	return AWN_PLATFORM_CALL(set_backhaul_sta_dev, link_state, eth_link_state);
}

void awnd_do_band_restart(UINT8 BandMask)
{
	return AWN_PLATFORM_CALL(do_band_restart, BandMask);
}

int awnd_get_wifi_bw(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw)
{
	return AWN_PLATFORM_CALL(get_wifi_bw, band, wifi_bw);
}

void awnd_set_wifi_bw(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw)
{
	return AWN_PLATFORM_CALL(set_wifi_bw, band, channel, wifi_bw);
}

int awnd_bss_status_check(void)
{
	return AWN_PLATFORM_CALL(bss_status_check);
}

int awnd_wpa_supplicant_status_check(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(wpa_supplicant_status_check,band);
}

int awnd_get_wifi_zwdfs_support(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(get_wifi_zwdfs_support, band);
}

#ifdef CONFIG_AWN_RE_ROAMING
int awnd_proxy_l2uf(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(proxy_l2uf, band);
}

int awnd_reload_sta_conf(AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(reload_sta_conf, band);
}

int anwd_set_wireless_sta_bssid(char *bssid_str, AWND_BAND_TYPE band)
{
	return AWN_PLATFORM_CALL(set_wireless_sta_bssid, bssid_str, band);
}

int awnd_wifi_re_roam(void)
{
	return AWN_PLATFORM_CALL(wifi_re_roam);
}
#endif /* CONFIG_AWN_RE_ROAMING */