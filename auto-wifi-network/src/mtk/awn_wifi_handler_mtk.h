/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_mtk.h
Version     : v0.1 
Description : awn wifi handler for mtk

Author      :  <puhaowen@tp-link.com.cn>
Create date : 2019/4/28

History     :
01, 2019/4/28 Pu Haowen, Created file.

*****************************************************************************/


#ifndef _AWN_WIFI_HANDLER_MTK_H_
#define _AWN_WIFI_HANDLER_MTK_H_

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

#include "../auto_wifi_net.h"
#include "../awn_wifi_handler_api.h"
#include "../awn_log.h"
#ifdef MTK_NETLINK_SUPPORT
#include <unl.h>
#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include "mtk_vendor_nl80211.h"
#endif


/***************************************************************************/
/*						DEFINES						 */
/***************************************************************************/
/* type         5G[DBDC]      5G        24G     */
/* STA          apclix0       apclii0   apcli0  */
/* backhaul AP  rax0          rai0      ra0     */
/* AP           rax2          rai2      ra2     */
/* guest AP     rax4          rai4      ra4     */
/* config AP    rax1          rai1      ra1     */
/* default AP   rax3          rai3      ra3     */

#define MTK_IFNAMESIZE 16

#if CONFIG_HW_NAT_TRAFFIC_STATS

#define HW_NAT_DEVNAME			"hwnat0"
#define HW_NAT_SET_STA_DEV 		(0x2d)
#ifndef uint8_t
typedef unsigned char           uint8_t;  
#endif

#ifndef uint16_t
typedef unsigned short int      uint16_t;  
#endif


enum hwnat_status {
	HWNAT_SUCCESS = 0,
	HWNAT_FAIL = 1,
	HWNAT_ENTRY_NOT_FOUND = 2
};

typedef struct {
	enum hwnat_status result;
    char working_sta_name[7][MTK_IFNAMESIZE];
} hwnat_sta_dev_notify_opt;

#endif /* CONFIG_HW_NAT_TRAFFIC_STATS */

#define ifr_name	ifr_ifrn.ifrn_name	/* interface name 	*/
#define MTK_PHY_PATH                        "/proc/mtketh/phy_link_up"
#define WIRELESS_CMD_STR                 "iwconfig %s | grep \"Access Point\""
#define WIRELESS_WPAS_CMD_FMT         "wpa_cli -p /var/run/wpa_supplicant -i %s"
#define WPAS_SOCKET_PATH_FMT          "/var/run/wpa_supplicant/%s"
#define WPAS_CONFIG_PATH_FMT          "/var/run/wpa_supplicant/wpa_supplicant-%s.conf"

#define WIRELESS_HAPD_CMD_FMT         "hostapd_cli -p /var/run/hostapd -i %s"
#define HOST_SOCKET_PATH_FMT          "/var/run/hostapd/%s"
#define HOST_CONFIG_PATH_FMT          "/var/run/hostapd/hostapd-%s.conf"

#define MTK_AP_IFNAME_FMT "%s"
#define MTK_STA_IFNAME_FMT "%s"

#define MTK_MAX_SSID_LENGTH 32
#define MTK_MAX_SOC_STA     32
#define MTK_LIST_STATION_ALLOC_SIZE ((MTK_MAX_SOC_STA + 1) << 10)

#define	IEEE80211_MAX_OPT_IE	512
#define	IEEE80211_RATE_VAL			0x7f

/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN           128
#define IEEE80211_MAX_TP_IE     (TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN        3

#define MTK_RSSI_COMPENSATION 92
#define TP_RSSI_RANGE_LOW	-95
#define TP_RSSI_RANGE_HIGH	0

#define MTK_STAINFO_WIFI_ASOC_STATE 0x00000001 /* Linked */

#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32

/*iwpriv cmd must be restricted to SIOCIWFIRSTPRIV ~ SIOCIWFIRSTPRIV + 0x20,
	and SIOCIWFIRSTPRIV is completely not recommanded to set to 8BC0 
*/

#define SIOCIWFIRSTPRIV								0x8BE0

#define RT_PRIV_IOCTL							    (SIOCIWFIRSTPRIV + 0x01) /* Sync. with AP for wsc upnp daemon */
#define RTPRIV_IOCTL_GSITESURVEY                    (SIOCIWFIRSTPRIV + 0x0D)
#define RTPRIV_IOCTL_GSITESURVEY_DECO               RTPRIV_IOCTL_GSITESURVEY
//#define RTPRIV_IOCTL_SINGLE_CHANNEL_SCAN            (SIOCIWFIRSTPRIV + 0x1E)  /* not used now */

#define OID_GET_CONFIG_GENERIC				0x068D	/*generic get: phy/tpie/wds*/
#define OID_GET_STA_INFO					0x068E	/*get stainfo*/
#define OID_GSCANSTATUS						0x068F	/*check scan finish*/

#define RTPRIV_IOCTL_GET_CONFIG_GENERIC             OID_GET_CONFIG_GENERIC
#define RTPRIV_IOCTL_GET_STA_INFO                   OID_GET_STA_INFO
#define IEEE80211_IOCTL_STA_INFO                    RTPRIV_IOCTL_GET_STA_INFO
#define IEEE80211_IOCTL_CONFIG_GENERIC              RTPRIV_IOCTL_GET_CONFIG_GENERIC
#define RTPRIV_IOCTL_GSCANSTATUS                    OID_GSCANSTATUS

#else
#define SIOCIWFIRSTPRIV								0x8BC0


#define RT_PRIV_IOCTL							    (SIOCIWFIRSTPRIV + 0x01) /* Sync. with AP for wsc upnp daemon */
#define RTPRIV_IOCTL_GSITESURVEY                    (SIOCIWFIRSTPRIV + 0x0D)
#define RTPRIV_IOCTL_GET_CONFIG_GENERIC             (SIOCIWFIRSTPRIV + 0x22)
#define RTPRIV_IOCTL_GET_STA_INFO                   (SIOCIWFIRSTPRIV + 0x23)
//#define RTPRIV_IOCTL_SINGLE_CHANNEL_SCAN            (SIOCIWFIRSTPRIV + 0x1E)  /* not used now */
#define RTPRIV_IOCTL_GSITESURVEY_DECO               RTPRIV_IOCTL_GSITESURVEY
#define IEEE80211_IOCTL_STA_INFO                    RTPRIV_IOCTL_GET_STA_INFO
#define IEEE80211_IOCTL_CONFIG_GENERIC              RTPRIV_IOCTL_GET_CONFIG_GENERIC
#define RTPRIV_IOCTL_GSCANSTATUS                    (SIOCIWFIRSTPRIV + 0x25)
#endif



#define OID_VENDOR_IE_BASE			0x1200
enum vendor_ie_subcmd_oid {
	OID_SUBCMD_AP_VENDOR_IE_SET,
	OID_SUBCMD_AP_VENDOR_IE_DEL,

	NUM_OID_SUBCMD_VENDOR_IE,
	MAX_NUM_OID_SUBCMD_VENDOR_IE = NUM_OID_SUBCMD_VENDOR_IE - 1
};
#define	OID_GET_SET_TOGGLE			0x8000

#define OID_AP_VENDOR_IE_SET		(OID_VENDOR_IE_BASE | OID_SUBCMD_AP_VENDOR_IE_SET)/*0x1200*/
#define OID_AP_VENDOR_IE_DEL		(OID_VENDOR_IE_BASE | OID_SUBCMD_AP_VENDOR_IE_DEL)
#define RT_OID_AP_VENDOR_IE_SET		(OID_GET_SET_TOGGLE | OID_AP_VENDOR_IE_SET)/*0x9200*/
#define RT_OID_AP_VENDOR_IE_DEL		(OID_GET_SET_TOGGLE | OID_AP_VENDOR_IE_DEL)

#define IEEE80211_ADDR_LEN      	6

#ifndef MTK_NETLINK_SUPPORT
typedef char __s8;
#endif

#ifdef MTK_NETLINK_SUPPORT

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 6
#endif

#define MAX_LEN_OF_SSID                     32

#define CHANNEL_5G_NON_DFS_NUM	9
#define CHANNEL_6G_PSC_NUM	15

#endif


/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/
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

typedef struct _MTK_AWND_NET_INFO {
    UINT8            id;                       /* IEEE80211_ELEMID_VENDOR */
    UINT8            len;                      /* length in bytes */
    UINT8            oui[3];                   /* 0x00, 0x1d, 0x0f */
    UINT8            tpie[TP_IE_MAX_LEN];      /* OUI type */ 
} MTK_AWND_NET_INFO;

typedef struct {
    UINT16 total;
    UINT16 start;
    UINT16 valid;
    UINT16 over;
} AWND_SCAN_RANGE;


typedef struct {
    UINT8    index;
    char     ssid[AWND_MAX_SSID_LEN];
    UINT8    ssidLen;
    UINT8    bssid[AWND_MAC_LEN];
    UINT8    rssi;
    UINT16   freq;
    UINT8    channel;
    UINT16   txRate;
    UINT16   rxRate;
    UINT16   uplinkMask;
    UINT16   uplinkRate;
    UINT16   pathRate;
    UINT     notFind;
    MTK_AWND_NET_INFO netInfo;
} MTK_SCAN_AP_ENTRY;


/*
 * Retrieve the tp-link information element for an associated station.
 */
struct ieee80211_wlanconfig_tpie {
    int status;
    UINT8 entry_type;
    UINT8 tp_macaddr[IEEE80211_ADDR_LEN];
    UINT8 tp_ie[IEEE80211_MAX_TP_IE];
};


#define IEEE80211_RATE_MAXSIZE 36

struct ieee80211req_sta_info {
        UINT16          isi_len;                /* length (mult of 4) */
        UINT16          isi_freq;               /* MHz */
        UINT32          awake_time;             /* time is active mode */
        UINT32          ps_time;                /* time in power save mode */
        UINT32          isi_flags;      /* channel flags */
        UINT16          isi_state;              /* state flags */
        UINT8           isi_authmode;           /* authentication algorithm */
        UINT8            isi_rssi;
        UINT8            isi_min_rssi;
        UINT8            isi_max_rssi;
        UINT16          isi_capinfo;            /* capabilities */
        UINT8           isi_athflags;           /* Atheros capabilities */
        UINT8           isi_erp;                /* ERP element */
        UINT8           isi_ps;         /* psmode */
        UINT8           isi_macaddr[AWND_MAC_LEN];
        UINT8           isi_nrates;
                                                /* negotiated rates */
        UINT8           isi_rates[IEEE80211_RATE_MAXSIZE];
        UINT8           isi_txrate;             /* index to isi_rates[] */
        UINT32          isi_txratekbps; /* tx rate in Kbps, for 11n */
        UINT16          isi_ie_len;             /* IE length */
        UINT16          isi_associd;            /* assoc response */
        UINT16          isi_txpower;            /* current tx power */
        UINT16          isi_vlan;               /* vlan tag */
        UINT16          isi_txseqs[17];         /* seq to be transmitted */
        UINT16          isi_rxseqs[17];         /* seq previous for qos frames*/
        UINT16          isi_inact;              /* inactivity timer */
        UINT8           isi_uapsd;              /* UAPSD queues */
        UINT8           isi_opmode;             /* sta operating mode */
        UINT8           isi_cipher;
        UINT32          isi_assoc_time;         /* sta association time */
        UINT16          isi_htcap;      /* HT capabilities */
        UINT32          isi_rxratekbps; /* rx rate in Kbps */
                                /* We use this as a common variable for legacy rates
                                   and lln. We do not attempt to make it symmetrical
                                   to isi_txratekbps and isi_txrate, which seem to be
                                   separate due to legacy code. */
        /* XXX frag state? */
        /* variable length IE data */
        UINT8           isi_maxrate_per_client; /* Max rate per client */
        UINT16          isi_stamode;        /* Wireless mode for connected sta */
        UINT32          isi_ext_cap;              /* Extended capabilities */
        UINT8           isi_nss;         /* number of tx and rx chains */
        UINT8           isi_is_256qam;    /* 256 QAM support */
};


typedef enum {
    IEEE80211_WLANCONFIG_NOP,
    IEEE80211_WLANCONFIG_NAWDS_SET_MODE,
    IEEE80211_WLANCONFIG_NAWDS_SET_DEFCAPS,
    IEEE80211_WLANCONFIG_NAWDS_SET_OVERRIDE,
    IEEE80211_WLANCONFIG_NAWDS_SET_ADDR,
    IEEE80211_WLANCONFIG_NAWDS_CLR_ADDR,
    IEEE80211_WLANCONFIG_NAWDS_GET,
    IEEE80211_WLANCONFIG_WNM_SET_BSSMAX,
    IEEE80211_WLANCONFIG_WNM_GET_BSSMAX,
    IEEE80211_WLANCONFIG_WNM_TFS_ADD,
    IEEE80211_WLANCONFIG_WNM_TFS_DELETE,
    IEEE80211_WLANCONFIG_WNM_FMS_ADD_MODIFY,
    IEEE80211_WLANCONFIG_WNM_SET_TIMBCAST,
    IEEE80211_WLANCONFIG_WNM_GET_TIMBCAST,
    IEEE80211_WLANCONFIG_WDS_ADD_ADDR,
    IEEE80211_WLANCONFIG_HMMC_ADD,
    IEEE80211_WLANCONFIG_HMMC_DEL,
    IEEE80211_WLANCONFIG_HMMC_DUMP,
    IEEE80211_WLANCONFIG_HMWDS_ADD_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_RESET_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_RESET_TABLE,
    IEEE80211_WLANCONFIG_HMWDS_READ_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_READ_TABLE,
    IEEE80211_WLANCONFIG_SET_MAX_RATE,
    IEEE80211_WLANCONFIG_WDS_SET_ENTRY,
    IEEE80211_WLANCONFIG_WDS_DEL_ENTRY,
    IEEE80211_WLANCONFIG_ALD_STA_ENABLE,
    IEEE80211_WLANCONFIG_WNM_BSS_TERMINATION,
    IEEE80211_WLANCONFIG_GETCHANINFO_160,
    IEEE80211_WLANCONFIG_VENDOR_IE_ADD,
    IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE,
    IEEE80211_WLANCONFIG_VENDOR_IE_REMOVE,
    IEEE80211_WLANCONFIG_VENDOR_IE_LIST,
    IEEE80211_WLANCONFIG_NAC_ADDR_ADD,
    IEEE80211_WLANCONFIG_NAC_ADDR_DEL,
    IEEE80211_WLANCONFIG_NAC_ADDR_LIST,
    IEEE80211_PARAM_STA_ATF_STAT,
    IEEE80211_WLANCONFIG_WDS_STATE_GET,
    IEEE80211_WLANCONFIG_TP_IE_GET,
    IEEE80211_WLANCONFIG_PHY_GET,
    IEEE80211_WLANCONFIG_HMWDS_REMOVE_ADDR,
    IEEE80211_WLANCONFIG_HMWDS_DUMP_WDS_ADDR,
} IEEE80211_WLANCONFIG_CMDTYPE;

typedef enum {
    IEEE80211_WLANCONFIG_OK          = 0,
    IEEE80211_WLANCONFIG_FAIL        = 1,
} IEEE80211_WLANCONFIG_STATUS;

struct ieee80211_wlanconfig_phy{
    UINT8 nss;
    int phyMode;
    int chwidth;
};

#if GET_AP_RSSI
struct ieee80211_conn_status{
    INT32 wds_state;
    INT32 rssi;
};
#endif

struct ieee80211_wlanconfig {
    IEEE80211_WLANCONFIG_CMDTYPE cmdtype;  /* sub-command */
    IEEE80211_WLANCONFIG_STATUS status;     /* status code */
    union {
        struct ieee80211_wlanconfig_tpie tpie;
        struct ieee80211_wlanconfig_phy  phy;
#if GET_AP_RSSI
        struct ieee80211_conn_status   connStaus;
#else
        INT32 wds_state;
#endif
    } data;
};

#ifdef MTK_NETLINK_SUPPORT
typedef struct _WLAN_CONN_INFO
{
	char connected;
	char ssid[MAX_LEN_OF_SSID + 1];
	int rssi[4];
	unsigned int txrate;
	unsigned int rxrate;
	char mac[MAC_ADDR_LEN];
	int idle;
} WLAN_CONN_INFO;

#endif

typedef struct _CHAN_INFO
{
	INT32 chan_util;
	INT32 intf;
	INT32 cur_chan;
	INT32 bw;
}CHAN_INFO;

typedef struct _WLAN_CAC_STATUS
{
	unsigned char inCac;
	unsigned char inNop;
}WLAN_CAC_STATUS;

typedef enum
{
    NRD_FALSE = 0,
    NRD_TRUE = !NRD_FALSE
} NRD_BOOL;

typedef enum wlanif_chwidth_e {
    wlanif_chwidth_20,
    wlanif_chwidth_40,
    wlanif_chwidth_80,
    wlanif_chwidth_160,
    wlanif_chwidth_320,

    wlanif_chwidth_invalid
} wlanif_chwidth_e;

typedef enum wlanif_phymode_e {
    wlanif_phymode_basic,
    wlanif_phymode_ht,
    wlanif_phymode_vht,
    wlanif_phymode_he,
    wlanif_phymode_eht,

    wlanif_phymode_invalid
} wlanif_phymode_e;

typedef struct wlif_phyCapInfo_t {
    /// Flag indicating if this PHY capability entry is valid or not
    NRD_BOOL valid : 1;
    /// The maximum bandwidth supported by this STA
    wlanif_chwidth_e maxChWidth : 3;
    /// The spatial streams supported by this STA
    unsigned char numStreams : 4;
    /// The PHY mode supported by this STA
    wlanif_phymode_e phyMode : 8;
    /// The maximum MCS supported by this STA
    unsigned char maxMCS;
    /// The maximum TX power supporetd by this STA
    unsigned char maxTxPower;
} wlif_phyCapInfo_t;

typedef struct _WLAN_PHYINFO
{
	unsigned char mac[ETHER_ADDR_LEN];
	wlif_phyCapInfo_t phycap;
	
}WLAN_PHYINFO;





#define RM_LINE_END_ENTER(s)   \
    do {   \
        char *_pos = &((char *)(s))[strlen(s) - 1];   \
        while (_pos >= (s) && (*_pos == '\r' || *_pos == '\n')) {    \
            *_pos-- = '\0'; \
        }   \
    } while(0)

/***************************************************************************/
/*                        FUNCTIONS                                         */
/***************************************************************************/

int get_default_mesh_channel_mtk(AWND_BAND_TYPE band, int *channel);
int check_block_chan_list_mtk(AWND_BAND_TYPE band, int *channel);
int get_sta_channel_mtk(AWND_BAND_TYPE band, int *channel);
int get_backhaul_ap_channel_mtk(AWND_BAND_TYPE band, int *channel);

int get_phy_mtk(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
#if GET_AP_RSSI
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_wds_state_mtk(AWND_BAND_TYPE band, int *up, int *rssi, BOOL roaming_connected[]);
#else
int get_wds_state_mtk(AWND_BAND_TYPE band, int *up, int *rssi);
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#else
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_wds_state_mtk(AWND_BAND_TYPE band, int *up, BOOL roaming_connected[]);
#else
int get_wds_state_mtk(AWND_BAND_TYPE band, int *up);
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#endif
int get_rootap_phyRate_mtk(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
int get_rootap_rssi_mtk(AWND_BAND_TYPE band, INT32 *rssi);
int get_rootap_info_mtk(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
int get_rootap_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
int get_tpie_mtk(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_tpie_with_lan_mac_mtk(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
#endif

int init_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
int update_wifi_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType);


int flush_scan_table_single_band_mtk(AWND_BAND_TYPE band, BOOL force);
int flush_scan_table_mtk(void);
int do_scan_mtk(UINT8 scanBandMask);
int do_scan_fast_mtk(UINT8 scanBandMask);
int get_scan_result_mtk(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
int scan_mtk(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);

int set_channel_mtk(AWND_BAND_TYPE band, UINT8 channel);
int get_sta_iface_in_bridge_mtk(AWND_BAND_TYPE band, UINT8* ifname);

int disconn_sta_pre_mtk(AWND_BAND_TYPE band, UINT* pBandMask);
int disconn_all_sta_pre_mtk(UINT* pBandMask);
int disconn_sta_post_mtk(AWND_BAND_TYPE band);
int disconn_sta_mtk(AWND_BAND_TYPE band);
int disconn_all_sta_mtk(void);
int reconn_sta_pre_mtk(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
int reconn_sta_post_mtk(AWND_BAND_TYPE band, BOOL check_wpa_status);
int reset_sta_connection_mtk(AWND_BAND_TYPE band);
int set_backhaul_sta_dev_mtk(UINT32 link_state, unsigned int eth_link_state);
void do_band_restart_mtk(UINT8 BandMask);
int get_wifi_bw_mtk(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
void set_wifi_bw_mtk(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
int bss_status_check_mtk();
int get_wifi_zwdfs_support_mtk(AWND_BAND_TYPE band);

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_mtk(AWND_BAND_TYPE band);
int reload_sta_conf_mtk(AWND_BAND_TYPE band);
int set_wireless_sta_bssid_mtk(char *bssid_str, AWND_BAND_TYPE band);
int wifi_re_roam_mtk(void);
#endif /* CONFIG_AWN_RE_ROAMING */

#endif /* _AWN_WIFI_HANDLER_MTK_H_ */

