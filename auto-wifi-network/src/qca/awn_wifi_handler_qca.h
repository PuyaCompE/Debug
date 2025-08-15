/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file		auto_wifi_net.h
 *\brief	 
 *
 *\author	Weng Kaiping
 *\version	1.0.0
 *\date		12Apri16
 *
 *\history \arg 1.0.0, 12Aug16, Weng Kaiping, Create the file. 	
 */


#ifndef _AWN_WIFI_HANDLER_QCA_H_
#define _AWN_WIFI_HANDLER_QCA_H_

/***************************************************************************/
/*						INCLUDE_FILES					 */
/***************************************************************************/
#include <net/ethernet.h>	/* struct ether_addr */
#include <net/if_arp.h>		/* For ARPHRD_ETHER */
#include <sys/socket.h>		/* For AF_INET & struct sockaddr */
#include <netinet/in.h>         /* For struct sockaddr_in */
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include "ieee80211_external.h"
#include "../auto_wifi_net.h"
#include "../awn_wifi_handler_api.h"
#include "../awn_log.h"

/***************************************************************************/
/*						DEFINES						 */
/***************************************************************************/
#define __packed    __attribute__((__packed__))
#define ___packed    __attribute__((__packed__))

#define QCA_IFNAMSIZ 16

#if 0
#define QCA_IFINDEX_5G (strtoul(awnd_dynamic_marocs_value_get("QCA_IFINDEX_5G"), NULL, 10))
#define QCA_IFINDEX_5G_STA (QCA_IFINDEX_5G * 10 + 3)
#define QCA_IFINDEX_5G_AP (QCA_IFINDEX_5G * 10 + 2)
#define QCA_IFINDEX_5G_CONFIG_AP (QCA_IFINDEX_5G * 10 + 4)
#define QCA_IFINDEX_5G_DEFAULT_AP (QCA_IFINDEX_5G * 10 + 5)
#endif
#define QCA_IFINDEX_5G_DEFAULT "1"

#define QCA_USE_WIFI_VLAN_DEV    1
#define QCA_LAN_VLAN_DEV_SUFFIX "1"

#if AP_SDXPINN_SIGMA_DUT_ENABLE == 0
#define QCA_WPA_SUPPLICANT_CTRL_STA_FMT "/var/run/wpad/wpa_supplicant-%s"
#else
#define QCA_WPA_SUPPLICANT_CTRL_STA_FMT "/var/run/wpa_supplicant-%s"
#endif
#define QCA_WPA_SUPPLICANT_LOCK_STA_FMT "/var/run/wpa_supplicant-%s.lock"

#define WIFI_SCAN_RESULT_FILE            "/tmp/wifi_scan_result_%s"
#define TMP_WIFI_SCAN_RESULT_FILE        "/tmp/tmp_wifi_scan_result_%s"

#define QCA_MAX_SSID_LENGTH 32

#define QCA_MAX_SOC_STA     32
#define QCA_LIST_STATION_ALLOC_SIZE ((QCA_MAX_SOC_STA + 1) << 10)

/*
 * 802.11 protocol implementation definitions.
 */

#ifdef CONFIG_AWN_QCA_WLAN_VDEV_STATE
enum wlan_vdev_state {
	WLAN_VDEV_S_INIT = 0,
	WLAN_VDEV_S_START = 1,
	WLAN_VDEV_S_DFS_CAC_WAIT = 2,
	WLAN_VDEV_S_UP = 3,
	WLAN_VDEV_S_SUSPEND = 4,
	WLAN_VDEV_S_STOP = 5,
	WLAN_VDEV_S_MAX = 6,
	WLAN_VDEV_SS_START_START_PROGRESS = 7,
	WLAN_VDEV_SS_START_RESTART_PROGRESS = 8,
	WLAN_VDEV_SS_START_CONN_PROGRESS = 9,
	WLAN_VDEV_SS_START_DISCONN_PROGRESS = 10,
	WLAN_VDEV_SS_SUSPEND_SUSPEND_DOWN = 11,
	WLAN_VDEV_SS_SUSPEND_SUSPEND_RESTART = 12,
	WLAN_VDEV_SS_SUSPEND_HOST_RESTART = 13,
	WLAN_VDEV_SS_SUSPEND_CSA_RESTART = 14,
	WLAN_VDEV_SS_STOP_STOP_PROGRESS = 15,
	WLAN_VDEV_SS_STOP_DOWN_PROGRESS = 16,
	WLAN_VDEV_SS_IDLE = 17,
	WLAN_VDEV_SS_MAX = 18,
};
#define AWN_WDS_STATE_UP WLAN_VDEV_S_UP
#else
enum ieee80211_state {
    IEEE80211_S_INIT        = 0,    /* default state */
    IEEE80211_S_SCAN        = 1,    /* scanning */
    IEEE80211_S_JOIN        = 2,    /* join */
    IEEE80211_S_AUTH        = 3,    /* try to authenticate */
    IEEE80211_S_ASSOC       = 4,    /* try to assoc */
    IEEE80211_S_RUN         = 5,    /* associated */
    IEEE80211_S_DFS_WAIT,
    IEEE80211_S_WAIT_TXDONE,    /* waiting for pending tx before going to INI */
    IEEE80211_S_STOPPING,
    IEEE80211_S_STANDBY,        /* standby, waiting to re-start */

    IEEE80211_S_MAX /* must be last */
};
#define AWN_WDS_STATE_UP IEEE80211_S_RUN
#endif

#define	IEEE80211_RATE_VAL			0x7f
/* by wdl, 20Apr11, be careful here IEEE80211_RATE_MAXSIZE 30 -> 36 */
#define	IEEE80211_RATE_MAXSIZE		44		/* max rates we'll handle */
#define IEEE80211_WLAN_SUBTYPE_WPA 			1
#define IEEE80211_WLAN_SUBTYPE_WPA2 			2

#define IEEE80211_ELEMID_RSN			48
#define	IEEE80211_WPA_OUI							0xf25000
#define	IEEE80211_WPA_OUI_TYPE					0x01
#define	IEEE80211_WPA_VERSION						1
#define IEEE80211_IE_WPA 							1
#define IEEE80211_IE_RSN 							2
#define IEEE80211_IE_OTHER 						3
#if 0 /* define oui in tp_oui.h */
#define IEEE80211_TP_OUI                     0x0f1d00    /* TP-LINK OUI */
#define IEEE80211_TP_NEW_OUI                     0x923100    /* TP-LINK NEW OUI */
#define IEEE80211_TP_OUI_TYPE                    0x01
#endif

#define QCA_OUI                     0xf0fd8c   /* QCA OUI (in little endian) */
/* Whole Home Coverage vendor specific IEs */
#define QCA_OUI_WHC_TYPE                0x00
/* Fields and bit mask for the Whole Home Coverage AP Info Sub-type */
#define QCA_OUI_WHC_AP_INFO_SUBTYPE     0x00
#define QCA_OUI_WHC_AP_INFO_VERSION     0x01
#define QCA_OUI_WHC_AP_INFO_CAP_WDS     0x01
#define QCA_OUI_WHC_AP_INFO_CAP_SON     0x02

#define QCA_OUI_WHC_REPT_INFO_SUBTYPE   0x00
#define QCA_OUI_WHC_REPT_INFO_VERSION   0x00

#define IEEE80211_VENDORIE_INCLUDE_IN_BEACON        0x10
#define IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_REQ     0x01
#define IEEE80211_VENDORIE_INCLUDE_IN_ASSOC_RES     0x02
#define IEEE80211_VENDORIE_INCLUDE_IN_PROBE_REQ     0x04
#define IEEE80211_VENDORIE_INCLUDE_IN_PROBE_RES     0x08




/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/
#ifndef IFF_UP
#define	IFF_UP		 0x1
#endif

#ifndef IFF_RUNNING
#define	IFF_RUNNING  0x40
#endif

typedef struct _QCA_CHANNEL
{
    int channel;
    int freq;
}QCA_CHANNEL;


#define	IEEE80211_MAX_OPT_IE	512

int get_default_mesh_channel_qca(AWND_BAND_TYPE band, int *channel);
int check_block_chan_list_qca(AWND_BAND_TYPE band, int *channel);
int get_sta_channel_qca(AWND_BAND_TYPE band, int *channel);
int get_backhaul_ap_channel_qca(AWND_BAND_TYPE band, int *channel);

int get_phy_qca(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_wds_state_qca(AWND_BAND_TYPE band, int *up, BOOL roaming_connected[]);
#else
int get_wds_state_qca(AWND_BAND_TYPE band, int *up);
#endif
int get_cac_state_qca(AWND_BAND_TYPE band, int *state);
int get_rootap_phyRate_qca(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
int get_rootap_rssi_qca(AWND_BAND_TYPE band, UINT16 *rssi);
int get_rootap_info_qca(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
int get_rootap_tpie_qca(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
int get_tpie_qca(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_tpie_with_lan_mac_qca(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
#endif
int init_tpie_qca(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
int update_wifi_tpie_qca(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t* uplinkRate, u_int8_t meshType);

int flush_scan_table_single_band_qca(AWND_BAND_TYPE band, BOOL force);
int flush_scan_table_qca(void);
int do_scan_qca(UINT8 scanBandMask);
int do_scan_fast_qca(UINT8 scanBandMask);
#ifdef CONFIG_DCMP_GLOBAL_support
int get_scan_result_qca(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        char* preconfig_ssid, UINT8* preconfig_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#else
int get_scan_result_qca(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#endif

int set_channel_qca(AWND_BAND_TYPE band, UINT8 channel);
int get_sta_iface_in_bridge_qca(AWND_BAND_TYPE band, UINT8* ifname);

int disconn_sta_pre_qca(AWND_BAND_TYPE band, UINT* pBandMask);
int disconn_all_sta_pre_qca(UINT* pBandMask);
int disconn_sta_post_qca(AWND_BAND_TYPE band);
int disconn_sta_qca(AWND_BAND_TYPE band);
int disconn_all_sta_qca(void);
int reconn_sta_pre_qca(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
int reconn_sta_post_qca(AWND_BAND_TYPE band, BOOL check_wpa_status);
int reset_sta_connection_qca(AWND_BAND_TYPE band);

int set_backhaul_sta_dev_qca(UINT32 link_state, unsigned int eth_link_state);
void do_band_restart_qca(UINT8 BandMask);
int get_wifi_bw_qca(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
void set_wifi_bw_qca(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
int bss_status_check_qca();
int get_wifi_zwdfs_support_qca(AWND_BAND_TYPE band);

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_qca(AWND_BAND_TYPE band);
int reload_sta_conf_qca(AWND_BAND_TYPE band);
int set_wireless_sta_bssid_qca(char *bssid_str, AWND_BAND_TYPE band);
int wifi_re_roam_qca(void);
#endif /* CONFIG_AWN_RE_ROAMING */

#endif /* _AWN_WIFI_HANDLER_QCA_H_ */

