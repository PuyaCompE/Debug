/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_api.h
Version     : v0.1 
Description : awn wifi handler api definitions

Author      :  <dengzhong@tp-link.com.cn>
Create date : 2019/4/1

History     :
01, 2019/4/1 Deng Zhong, Created file.

*****************************************************************************/
#ifndef __AWN_WIFI_HANDLER_API_H__
#define __AWN_WIFI_HANDLER_API_H__


/***************************************************************************/
/*						INCLUDE_FILES					 */
/***************************************************************************/
#include <net/if_arp.h>		/* For ARPHRD_ETHER */
#include <sys/socket.h>		/* For AF_INET & struct sockaddr */
#include <netinet/in.h>         /* For struct sockaddr_in */
#if !CONFIG_BCM_USE_WL_INCLUDE_FILE
#include <net/ethernet.h>   /* struct ether_addr */
#include <netinet/if_ether.h>
#endif
#include <sys/ioctl.h>

#ifndef CONFIG_PLATFORM_RTK
#include <linux/wireless.h>
#endif
#include "tp_oui.h"

#include "auto_wifi_net.h"

#if defined(CONFIG_PLATFORM_QCA)

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
#include "qca/awn_wifi_handler_cfg80211_qca.h"
#else
#include "qca/awn_wifi_handler_qca.h"
#endif

#elif defined(CONFIG_PLATFORM_MTK)
#include "mtk/awn_wifi_handler_mtk.h"
#elif defined(CONFIG_PLATFORM_BCM)
#include "bcm/awn_wifi_handler_bcm.h"
#elif defined(CONFIG_PLATFORM_RTK)
#include "rtk/awn_wifi_handler_rtk.h"
#endif


/***************************************************************************/
/*						DEFINES						 */
/***************************************************************************/
#if 0 /* define oui in tp_oui.h */
#define IEEE80211_TP_OUI                     0x0f1d00    /* TP-LINK OUI */
#define IEEE80211_TP_NEW_OUI      				 0x923100    /* TP-LINK NEW OUI */
#define IEEE80211_TP_OUI_TYPE                    0x01
#endif

#if !defined(CONFIG_PLATFORM_QCA)

#define IEEE80211_ADDR_LEN      	6
#define IEEE80211_ELEMID_VENDOR 		221

enum {
    IEEE80211_TP_IE_IN_NODE = 0x1,
    IEEE80211_TP_IE_IN_SCAN = 0x2,
    IEEE80211_TP_IE_IN_ANY = 0x3,
};

#endif /* !CONFIG_PLATFORM_QCA */

#define WIFI_SCAN_RESULT_FILE            "/tmp/wifi_scan_result_%s"
#define TMP_WIFI_SCAN_RESULT_FILE        "/tmp/tmp_wifi_scan_result_%s"

#define STATS_BACKHAUL_STA_DEV_NAME     "/proc/net/statistics/sta_dev_name"

#define QCA_IFINDEX_5G 1
#define QCA_IFINDEX_5G_DEFAULT "1"


/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/
/**
 * @brief Enumerations for bandwidth (MHz) supported by STA
 */
typedef enum wlan_chwidth_e {
    wlan_chwidth_20,
    wlan_chwidth_40,
    wlan_chwidth_80,
    wlan_chwidth_160,
    wlan_chwidth_320,

    wlan_chwidth_invalid
} wlan_chwidth_e;

/**
 * @brief Enumerations for IEEE802.11 PHY mode
 */
typedef enum wlan_phymode_e {
	wlan_phymode_basic,
	wlan_phymode_ht,
	wlan_phymode_vht,
	wlan_phymode_he,
	wlan_phymode_eht,

	wlan_phymode_invalid
} wlan_phymode_e;

/***************************************************************************/
/*                        FUNCTIONS                                         */
/***************************************************************************/
typedef struct _AWN_PLATFORM_OPS {
#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
	int (*init_cfg80211)(void);
	int (*deinit_cfg80211)(void);
#endif
    int (*get_default_mesh_channel)(AWND_BAND_TYPE band, int *channel);
	int (*check_block_chan_list)(AWND_BAND_TYPE band, int *channel);
	int (*get_sta_channel)(AWND_BAND_TYPE band, int *channel);
	int (*get_backhaul_ap_channel)(AWND_BAND_TYPE band, int *channel);

	int (*get_phy)(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#if GET_AP_RSSI
	int (*get_wds_state)(AWND_BAND_TYPE band, int *up, int *rssi, BOOL wds_connected[]);
#else
	int (*get_wds_state)(AWND_BAND_TYPE band, int *up, BOOL wds_connected[]);
#endif	/* GET_AP_RSSI	*/
#else
#if GET_AP_RSSI
	int (*get_wds_state)(AWND_BAND_TYPE band, int *up, int *rssi);
#else
	int (*get_wds_state)(AWND_BAND_TYPE band, int *up);
#endif
#endif	/* CONFIG_AWN_MESH_OPT	*/
	int (*get_cac_state)(AWND_BAND_TYPE band, int *state);
	int (*get_rootap_phyRate)(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
	int (*get_rootap_rssi)(AWND_BAND_TYPE band, INT32 *rssi);
#ifdef SUPPORT_MESHMODE_2G
	int (*get_chanim)(AWND_BAND_TYPE band, INT32 *chanutil, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw);
	void (*do_csa)(int target_chan, AWND_WIFI_BW_TYPE bw, AWND_CHAN_OFFSET_TYPE offset);
	void (*disable_sta_vap)(int disable, AWND_BAND_TYPE band);
#endif
	int (*get_rootap_info)(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
	int (*get_rootap_tpie)(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
	int (*get_tpie)(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);

	int (*init_tpie)(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
	int (*update_wifi_tpie)(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType);


	int (*flush_scan_table_single_band)(AWND_BAND_TYPE band, BOOL force);
	int (*flush_scan_table)(void);
	int (*do_scan)(UINT8 scanBandMask);
	int (*do_scan_fast)(UINT8 scanBandMask);
	#ifdef CONFIG_DCMP_GLOBAL_support
	int (*get_scan_result)(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        char* preconfig_ssid, UINT8* preconfig_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
	#else
	int (*get_scan_result)(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
            char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
	#endif
	int (*scan)(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);

	int (*set_channel)(AWND_BAND_TYPE band, UINT8 channel);
	int (*get_sta_iface_in_bridge)(AWND_BAND_TYPE band, UINT8* ifname);

	int (*disconn_sta_pre)(AWND_BAND_TYPE band, UINT* pBandMask);
	int (*disconn_all_sta_pre)(UINT* pBandMask);
	int (*disconn_sta_post)(AWND_BAND_TYPE band);
	int (*disconn_sta)(AWND_BAND_TYPE band);
	int (*disconn_all_sta)(void);
	int (*reconn_sta_pre)(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
	int (*reconn_sta_post)(AWND_BAND_TYPE band, BOOL check_wpa_status);
	int (*reset_sta_connection)(AWND_BAND_TYPE band);
    int (*set_backhaul_sta_dev)(UINT32 link_state, unsigned int eth_link_state);
    void (*do_band_restart)(UINT8 BandMask);
    int (*get_wifi_bw)(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
    void (*set_wifi_bw)(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
    int (*bss_status_check)(void);
    int (*wpa_supplicant_status_check)(AWND_BAND_TYPE band);
    int (*get_wifi_zwdfs_support)(AWND_BAND_TYPE band);
#ifdef CONFIG_AWN_RE_ROAMING
    int (*proxy_l2uf)(AWND_BAND_TYPE band);
    int (*reload_sta_conf)(AWND_BAND_TYPE band);
    int (*set_wireless_sta_bssid)(char *bssid_str, AWND_BAND_TYPE band);
    int (*wifi_re_roam)(void);
#endif /* CONFIG_AWN_RE_ROAMING */
} AWN_PLATFORM_OPS;

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
int awnd_init_cfg80211(void);
int awnd_deinit_cfg80211(void);
int awnd_wifi_check(void);
#endif
int awnd_get_default_mesh_channel(AWND_BAND_TYPE band, int *channel);
int awnd_check_block_chan_list(AWND_BAND_TYPE band, int *channel);
int awnd_get_sta_channel(AWND_BAND_TYPE band, int *channel);
int awnd_get_backhaul_ap_channel(AWND_BAND_TYPE band, int *channel);

int awnd_get_phy(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#if GET_AP_RSSI
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, int *rssi, BOOL roaming_connected[]);
#else
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, BOOL wds_connected[]);
#endif	/* GET_AP_RSSI	*/
#else
#if GET_AP_RSSI
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up, int *rssi);
#else
int awnd_get_wds_state(AWND_BAND_TYPE band, int *up);
#endif	/* GET_AP_RSSI	*/
#endif	/*	CONFIG_AWN_MESH_OPT_SUPPORT	*/
int awnd_get_cac_state(AWND_BAND_TYPE band, int *state);
int awnd_get_rootap_phyRate(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
int awnd_get_rootap_rssi(AWND_BAND_TYPE band, INT32 *rssi);
#ifdef SUPPORT_MESHMODE_2G
int awnd_get_chanim(AWND_BAND_TYPE band, INT32 *chanutil, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw);
void awnd_do_csa(int target_chan, AWND_WIFI_BW_TYPE bw, AWND_CHAN_OFFSET_TYPE offset);
void awnd_disable_sta_vap(int disable, AWND_BAND_TYPE band);
#endif
int awnd_get_rootap_info(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
int awnd_get_rootap_tpie(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
int awnd_get_tpie(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);

int awnd_init_tpie(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
int awnd_update_wifi_tpie(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType);


int awnd_flush_scan_table_single_band(AWND_BAND_TYPE band, BOOL force);
int awnd_flush_scan_table(void);
int awnd_do_scan(UINT8 scanBandMask);
int awnd_do_scan_fast(UINT8 scanBandMask);
#ifdef CONFIG_DCMP_GLOBAL_support
int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        char* preconfig_ssid, UINT8* preconfig_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#else
int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#endif

int awnd_set_channel(AWND_BAND_TYPE band, UINT8 channel);
int awnd_get_sta_iface_in_bridge(AWND_BAND_TYPE band, UINT8* ifname);

int awnd_disconn_sta_pre(AWND_BAND_TYPE band, UINT* pBandMask);
int awnd_disconn_all_sta_pre(UINT* pBandMask);
int awnd_disconn_sta_post(AWND_BAND_TYPE band);
int awnd_disconn_sta(AWND_BAND_TYPE band);
int awnd_disconn_all_sta(void);
int awnd_reconn_sta_pre(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
int awnd_reconn_sta_post(AWND_BAND_TYPE band, BOOL check_wpa_status);
int awnd_reset_sta_connection(AWND_BAND_TYPE band);
int awnd_set_backhaul_sta_dev(UINT32 link_state, unsigned int eth_link_state);
void awnd_do_band_restart(UINT8 BandMask);
int awnd_get_wifi_bw(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
void awnd_set_wifi_bw(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
int awnd_bss_status_check(void);
int awnd_wpa_supplicant_status_check(AWND_BAND_TYPE band);
int awnd_get_wifi_zwdfs_support(AWND_BAND_TYPE band);

#ifdef CONFIG_AWN_RE_ROAMING
int awnd_proxy_l2uf(AWND_BAND_TYPE band);
int awnd_reload_sta_conf(AWND_BAND_TYPE band);
int anwd_set_wireless_sta_bssid(char *bssid_str, AWND_BAND_TYPE band);
int awnd_wifi_re_roam(void);
#endif /* CONFIG_AWN_RE_ROAMING */

#endif /* __AWN_WIFI_HANDLER_API_H__ */
