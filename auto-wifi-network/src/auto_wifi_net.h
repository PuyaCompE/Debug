/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file        auto_wifi_net.h
 *\brief     
 *
 *\author      Weng Kaiping
 *\version     1.0.0
 *\date        11Apri16
 *
 *\history \arg 1.0.0, 11Aug16, Weng Kaiping, Create the file.     
 */


#ifndef _AUTO_WIFI_NET_H_
#define _AUTO_WIFI_NET_H_

/***************************************************************************/
/*                        INCLUDE_FILES                     */
/***************************************************************************/
#include "tplinkType.h"
#include "eth_encap.h"
#include "awn_log.h"
/***************************************************************************/
/*                        DEFINES                         */
/***************************************************************************/
#define AWND_MAX_SCAN_BUF                 65535
#define AWND_MAX_GROUP_MEMBER             32        //Max Device (old 8)
#define CMDLINE_LENGTH                    256
#define AWND_MAX_SSID_LEN                 33        //max ssid len
#define AWND_MAX_BSSID_LEN                18        //max bssid len
#define AWND_MAX_PWD_LEN                  16
#define AWN_PLCSON_NEIGH_MAX_CNT          32
#define AWN_NEIGH_MAX_CNT                 32
#define AWN_BAND3_FIRST_CHANNEL           100
#define AWN_BAND3_LAST_CHANNEL            144
#define AWND_LABEL_LEN                    16        
#define AWND_MAC_LEN                       6
#if SCAN_OPTIMIZATION
#define AWND_MAX_MISSING_CNT               3
#endif
#define AWND_WAIT_PREFER_AP_CNT            2
#define AWND_OK                0
#define AWND_ERROR            -1
#define AWND_BUSY             -2
#define AWND_NOT_FOUND        -3
#define AWND_SCAN_SCHED       -4
#define AWND_SCAN_SCHED_FAST  -5
#define AWND_RECONNECTING     -6
#define AWND_WAIT             -7
#define AWND_WIFI_RESTART     -8
#define AWND_MODE_CHANGE      -9
#define AWND_OUT_LOOP         -10
#define AWND_REPACD_QUICK_RESTART     -11
#define AWND_SCAN_CLEAR       -12
#define AWND_MALLOC_FAIL      -13
#ifdef CONFIG_AWN_RE_ROAMING
#define AWND_RE_ROAMING       -14
#endif

#define WIFI_REPEATER 0
#define WIFI_AP       1

#define SUBMODE_STAR   0
#define SUBMODE_DAISY  1

#define TP_OUI_MAX_VERSION          1

#define IN_SAME_SUBNET_EXACT(info1, info2) \
    ((info1)->awnd_net_type == (info2)->awnd_net_type  && (memcmp((info1)->awnd_mac, (info2)->awnd_mac, AWND_MAC_LEN) == 0))

#define IN_SAME_SUBNET(info1, info2)  (memcmp((info1)->awnd_mac, (info2)->awnd_mac, AWND_MAC_LEN) == 0) 

#define ETH_NEIGH_IS_SUBNET_FAP(eth_neigh)  ((memcmp((eth_neigh)->lan_mac, (eth_neigh)->netInfo.awnd_mac, AWND_MAC_LEN) == 0) \
            && ((eth_neigh)->netInfo.awnd_net_type == AWND_NET_FAP))

#define SCAN_ENTRY_IS_SUBNET_FAP(ap_entry)  ((ap_entry)->netInfo.awnd_net_type == AWND_NET_FAP)

#define SSTR_SIZE(_STATIC_STR)              (sizeof(_STATIC_STR)-1)
#define MACFMT                              "%02X:%02X:%02X:%02X:%02X:%02X"
#define MACDAT(_macaddr)                    _macaddr[0], _macaddr[1], _macaddr[2], _macaddr[3], _macaddr[4], _macaddr[5]
#define BIT_MASK(_val, _mask, _shift)       ((_val>>_shift) & _mask)
#define IPFMT                               "%u.%u.%u.%u"
#define IPDAT(_ipaddr)                      (BIT_MASK(_ipaddr, 0xFF, 24)),(BIT_MASK(_ipaddr, 0xFF, 16)),(BIT_MASK(_ipaddr, 0xFF, 8)),(BIT_MASK(_ipaddr, 0xFF, 0))

#define CONNECT_TO_SAME_DUT 1
#if CONFIG_PLATFORM_BCM
/********************************************************************************************************
no scan entry for rootap bssid
(0, 180)   scan every 30s + wpa_supplicnat enable
[180, 300) 24G/5G/5G2/6G: scan every 120s + wpa_supplicnat enable
[300, 600) 24G/5G: no scan + wpa_supplicnat enable;  5G2/6G: scan every 120s + wpa_supplicnat enable
[600, + )  24G/5G: no scan + wpa_supplicnat disable; 5G2/6G: scan every 120s + wpa_supplicnat enable
*********************************************************************************************************/
#define NO_ENTRY_DISCONNECT_SEC      600     /* disable band connect forever if no entry after scan */
#define NO_ENTRY_NO_SCAN_SEC         300     /* not to scan if no entry after scan */
#define NO_ENTRY_LONG_SCAN_SEC       180     /* to long timer scan if no entry after scan */

#define NO_ENTRY_RESCAN_SHORT_TIMER   30     /* scan timer if no entry after scan < NO_ENTRY_LONG_SCAN_SEC */
#define NO_ENTRY_RESCAN_LONG_TIMER   120     /* scan timer if no entry after scan > NO_ENTRY_LONG_SCAN_SEC */
#define NO_ENTRY_RESCAN_BEGIN   3

#define CONNECT_POST_FAST_SEC   10
#define CONNECT_POST_SCAN_SEC   30
#define CONNECT_POST_HOSTAPD_SEC   60

#ifdef WPA_PRI_STATE_CHECK
#define CONNECT_POST_WPA_SEC   60
#endif
#else
#define NO_ENTRY_THRESOLD_SEC  180
#define NO_ENTRY_RESCAN_SHORT_TIMER  20
#define NO_ENTRY_RESCAN_LONG_TIMER  120
#define NO_ENTRY_RESCAN_BEGIN   3
#define CONNECT_POST_FAST_SEC   10
#define CONNECT_POST_SLOW_SEC   20
#define CONNECT_POST_HOSTAPD_SEC   60
#if CONFIG_OUTDOOR_CHANNELLIMIT
#define OUTDOOR_CHANLIMIT_NO_ENTRY_THRESOLD_SEC  1800
#endif
#endif /* !CONFIG_PLATFORM_BCM */

#define  AWN_CHANNEL_SWITCH_INTERVAL 30

#define WIFI_SCAN_RUNNING_FILE "/tmp/wifi_scan_running"

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#define ENABLE_PAT 0
#endif

#define SPECIALID_LEN                           8
#define SPECIALID_US                            "55530000"

#if CONFIG_OUTDOOR_CHANNELLIMIT
#define CHANNELLIMIT_LEN                        1
#define CHANLIMIT_CHANNEL_NUM_LEN               4
#define CHANNELLIMIT_PROFILE_SUPPORT            "channel_limit.radio_5g.support"
#define CHANNELLIMIT_PROFILE_START_CHANNEL      "channel_limit.radio_5g.start_channel"
#define CHANNELLIMIT_PROFILE_END_CHANNEL        "channel_limit.radio_5g.end_channel"
#endif

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/
#define IN_CONNECTING_STATE(pConnState) (! _is_in_connected_state(pConnState) && ! _is_in_disconnected_state(pConnState))

typedef enum 
{
    AWND_ROOTAP_CHANNEL_IS_NORAML = 0,  //band1&band4
    AWND_ROOTAP_CHANNEL_IS_DFS,         //band2&band3, except weather channel
    AWND_ROOTAP_CHANNEL_IS_WEATHER      //116,120,124,128
}AWND_ROOTAP_CHANNEL_TYPE;

typedef enum 
{
    AWND_LOCATION_GOOD = 0,
    AWND_LOCATION_FAR,
    AWND_LOCATION_NEAR,
    AWND_LOCATION_UNAVAIL,
    AWND_LOCATION_GETTING,
    AWND_LOCATION_MAX
}AWND_LOCATION_TYPE;

typedef enum 
{
    AWND_HOTPLUG_MODE_CHANGE_BEGIN = 0,
    AWND_HOTPLUG_MODE_CHANGE_END,
    AWND_HOTPLUG_CAP_CHANGE,            /* cap mac change */
    AWND_HOTPLUG_CAP_IP_CHANGE,         /* cap ip change */
    AWND_HOTPLUG_CAP_TYPE_CHANGE,       /* cap net type change */
    AWND_HOTPLUG_CAP_DNS_CHANGE,        /* cap dns change */
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    AWND_HOTPLUG_PARENT_CHANGE,            /* parent mac change */
    AWND_HOTPLUG_LINK_STATUS_CHANGE,            /* link status change */
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT  */
    AWND_HOTPLUG_MAX
}AWND_HOTPLUG_TYPE;

typedef enum 
{
    AWND_MODE_FAP = 0,
    AWND_MODE_HAP,
    AWND_MODE_RE,
    AWND_MODE_NONE,
    AWND_MODE_MAX
}AWND_MODE_TYPE;

#ifdef SUPPORT_MESHMODE_2G
typedef enum 
{
    AWND_MESHMODE_2G_DISCONNECT = 0,
    AWND_MESHMODE_2G_CONNECT,
    AWND_MESHMODE_2G_DYNAMIC
}AWND_MESHMODE_2G_TYPE;

typedef enum 
{
    AWND_MESHSTATE_2G_DISCONNECT = 0,
    AWND_MESHSTATE_2G_CONNECT
}AWND_MESHSTATE_2G_TYPE;
#endif

#define AWND_MODE_DEFAULT   AWND_MODE_RE

typedef enum
{
    AWND_SUBMODE_STAR = 0,
    AWND_SUBMODE_DAISY
}AWND_SUBMODE;

typedef enum 
{
    AWND_NET_FAP = 0,
    AWND_NET_HAP,
    AWND_NET_LRE,
    AWND_NET_MAX
}AWND_NET_TYPE;

typedef enum 
{
    AWND_SYSMODE_ROUTER = 0,
    AWND_SYSMODE_AP
}AWND_SYS_MODE_TYPE;

typedef enum
{
    AWND_NETINFO_ND = 0,    /* Not Defined */
    AWND_NETINFO_ETH,
    AWND_NETINFO_WIFI,
    AWND_NETINFO_PLC,
    AWND_NETINFO_MAX
}AWND_NETINFO_TYPE;

typedef enum
{
   AWND_BACKHAUL_WIFI = 1,
   AWND_BACKHAUL_PLC  = 2,
   AWND_BACKHAUL_ETH  = 4,
   AWND_BACKHAUL_WIFI_2G    = 256,
   AWND_BACKHAUL_WIFI_5G    = 512,
   AWND_BACKHAUL_WIFI_5G2   = 1024,
   AWND_BACKHAUL_WIFI_6G    = 2048,
   AWND_BACKHAUL_WIFI_6G2   = 4096
}AWND_BACKHAUL_MASK;

typedef enum
{
   LINK_STATE_MASK_2G     = 0x01,
   LINK_STATE_MASK_5G     = 0x02,
   LINK_STATE_MASK_5G2    = 0x04,
   LINK_STATE_MASK_6G     = 0x08,
   LINK_STATE_MASK_6G2    = 0x10,
   LINK_STATE_MASK_PCL    = 0x100,
}LINK_STATE_MASK;

#define LINK_STATE_BITIDX_PLC 0x8
#define LINK_STATE_BITIDX_ETH 0x9

#define PLC_BACKHAUL_ENABLE(opt) ((opt) & AWND_BACKHAUL_PLC)
#define WIFI_BACKHAUL_ENABLE(opt) ((opt) & AWND_BACKHAUL_WIFI)
#define BACKHAUL_OPT_MIN (0)
#define BACKHAUL_OPT_MAX (3)
#define CHECK_BACKHAUL_OPT(opt) ((opt) >= BACKHAUL_OPT_MIN && (opt) <= BACKHAUL_OPT_MAX)

/* band control */
typedef enum
{
    AWND_BAND_2G = 0,        
    AWND_BAND_5G,   
    AWND_BAND_3RD,
    AWND_BAND_4TH,
    AWND_BAND_5TH,
    AWND_BAND_MAX
} AWND_BAND_TYPE;

typedef enum
{
    AWND_REAL_BAND_2G = 0,
    AWND_REAL_BAND_5G,
    AWND_REAL_BAND_5G2,
    AWND_REAL_BAND_6G,
    AWND_REAL_BAND_6G2,
    AWND_REAL_BAND_MAX
} AWND_REAL_BAND_TYPE;

#define AWND_BAND_MAX_NUM   AWND_BAND_MAX
#define AWND_BAND_NUM_3		AWND_BAND_4TH
#define AWND_BAND_NUM_4		AWND_BAND_5TH
#define AWND_BAND_NUM_5		AWND_BAND_MAX

typedef enum
{
    AWND_COUNTRY_UN = 0,
    AWND_COUNTRY_US,
    AWND_COUNTRY_EU,
    AWND_COUNTRY_KR,
    AWND_COUNTRY_BR,
    AWND_COUNTRY_JP,
    AWND_COUNTRY_CA,
    AWND_COUNTRY_AU,
    AWND_COUNTRY_RU,
    AWND_COUNTRY_SW,
    AWND_COUNTRY_TW,
    AWND_COUNTRY_MAX
} AWND_COUNTRY_TYPE;

typedef enum
{
    AWND_VAP_AP = 0,        
    AWND_VAP_STA,
    AWND_VAP_MAX_NUM
} AWND_VAP_TYPE;


typedef enum
{
   AWND_INTERFACE_WIFI_2G = AWND_BAND_2G,
   AWND_INTERFACE_WIFI_5G = AWND_BAND_5G,
   AWND_INTERFACE_WIFI_3RD = AWND_BAND_3RD,
   AWND_INTERFACE_WIFI_4TH  = AWND_BAND_4TH,
   AWND_INTERFACE_WIFI_5TH = AWND_BAND_5TH,
   AWND_INTERFACE_PLC = 8,
   AWND_INTERFACE_ETH = 16   
}AWND_INTERFACE_TYPE;

typedef enum _AWND_CONN_STATUS
{
    AWND_STATUS_DISCONNECT,
    AWND_STATUS_CONNECTED,
    AWND_STATUS_CONNECTING,
    AWND_STATUS_RECONNECTING,
#ifdef CONFIG_AWN_RE_ROAMING
    AWND_STATUS_ROAMING,
#endif
    AWND_STATUS_MAX
}AWND_CONN_STATUS;

typedef enum _AWND_NET_CHANGE_TYPE{
    AWND_NET_HOLD = 0,	
    AWND_NET_BECOME_STABLE = 1,
    AWND_NET_BECOME_UNSTABLE = 2
}AWND_NET_CHANGE_TYPE;


typedef enum _AWND_PLC_NEIGH_FLAG
{
    AWND_NEIGH_CLEAR = 0,
    AWND_NEIGH_VALID,
    AWND_NEIGH_AGING,
}AWND_NEIGH_FLAG;

typedef enum _AWND_ETH_NEIGH_DIR{
	NEIGH_IN_LAN = 1,
    NEIGH_IN_WAN = 2
}AWND_ETH_NEIGH_DIR;

typedef enum _AWND_CONFIG_ROLE{
    AWND_CONFIG_RE = 0,
    AWND_CONFIG_AP = 1
}AWND_CONFIG_ROLE;

typedef enum _AWND_SERVER_DETECT_ACTION{
    SERVER_DETECT_OFF = 0,
    SERVER_DETECT_ON = 1
}AWND_SERVER_DETECT_ACTION;

typedef enum _AWND_RE_STAGE {
    AWND_RE_STAGE_NONE = 0,
    AWND_RE_STAGE_FIRST = 1,
    AWND_RE_STAGE_SECOND,
    AWND_RE_STAGE_THIRD,
    AWND_RE_STAGE_FOURTH
}AWND_RE_STAGE;

typedef enum _AWND_RE_BIND_STATUS {
    AWND_BIND_NONE,
    AWND_BIND_CONFIG_CONNECTED,          /* connected in config network with no group-info */
    AWND_BIND_START,                     /* insert group-info and connected in config network */
    AWND_BIND_BACKHUAL_CONNECTING,       /* change to connect in backhual network */
    AWND_BIND_OVER,                      /* connected in backhual network, bind over */
    AWND_BIND_MAX
}AWND_BIND_STATUS;

typedef enum _AWND_WIFI_IFACE_TYPE {
     WIFI_IFACE_BACKHUAL = 1,
     WIFI_IFACE_CONFIG,
     WIFI_IFACE_PRECONFIG,
     WIFI_IFACE_STA,
     WIFI_IFACE_ALL,
}AWND_WIFI_IFACE_TYPE;

typedef enum _AWND_MESH_TYPE {
     AWND_MESH_BACKHUAL = 1,
     AWND_MESH_CONFIG,
     AWND_MESH_PRECONFIG,
     AWND_MESH_BACKHUAL_STA,
     AWND_MESH_UNKNOW
}AWND_MESH_TYPE;

typedef enum _AWND_ONBOARDING_STATUS {
     ONBOARDING_OFF = 0,
     ONBOARDING_ON,
     ONBOARDING_NONE
}AWND_ONBOARDING_STATUS;

typedef enum _AWND_WIFI_CONFIG {
    AWND_WIFI_CONFIG_BEGIN = 16,
    AWND_WIFI_CONFIG_END,
}AWND_WIFI_CONFIG;

typedef enum _AWND_STA_TYPE {
    AWND_STA_TYPE_NORMAL = 0,
    AWND_STA_TYPE_PRE,
    AWND_STA_TYPE_PRECONFIG,
    AWND_STA_TYPE_UNKNOW,
}AWND_STA_TYPE;

typedef enum _AWND_WIFI_BW_TYPE {
    WIFI_BW_20M = 0,
    WIFI_BW_40M,
    WIFI_BW_80M,
    WIFI_BW_160M,
    WIFI_BW_MAX,
}AWND_WIFI_BW_TYPE;

#ifdef SUPPORT_MESHMODE_2G
typedef enum _AWND_CHAN_OFFSET_TYPE {
    CHAN_OFFSET_NONE = 0,
    CHAN_OFFSET_UP,
    CHAN_OFFSET_DOWN,
}AWND_CHAN_OFFSET_TYPE;
#endif

typedef enum _AWND_SILENT_PERIOD_TYPE {
    SILENT_PERIOD_NONE= 0,
    SILENT_PERIOD_START,
    SILENT_PERIOD_DONE,
    SILENT_PERIOD_MAX,
}AWND_SILENT_PERIOD_TYPE;

typedef enum _AWND_OUI_TYPE
{
    AWND_OLD_OUI = 0,
    AWND_NEW_OUI = 1,
} AWND_OUI_TYPE;

/* */
typedef enum _AWND_OUI_UPDATE_STATUS
{
    OUI_KEEP_STATE = 0,
    OUI_OLD_TO_NEW = 1,
    OUI_NEW_TO_OLD = 2,
} AWND_OUI_UPDATE_STATUS;

typedef struct _IEEE80211_TP_OUI_LIST
{
    UINT8 tp_oui[3];
}IEEE80211_TP_OUI_LIST;

typedef enum
{
    AWND_OP_FLUSH = 0,
    AWND_OP_SET_PREFER,
    AWND_OP_SET_FLAG,
    AWND_OP_CHECK_MAC,
    AWND_OP_CHECK_PREFER,
    AWND_OP_MAX
}AWND_UNABLE_TABLE_OP_TYPE;

typedef struct _AWND_HOTPLUG_CONFIG {
    AWND_MODE_TYPE srcMode;
    AWND_MODE_TYPE dstMode;
    AWND_HOTPLUG_TYPE type;
    AWND_NET_TYPE capSrcType;
    AWND_NET_TYPE capDstType;
}AWND_HOTPLUG_CONFIG;


typedef struct _AWND_CONFIG {
    int              enable;
    /* configuration about wifi */
    UINT8            mac[AWND_MAC_LEN];       /* mac of lan */    
    UINT8            weight;
	int				 band_num;
	int				 sp5G2;
	int 			 sp6G;
	int				 sp6G2;
	int				 band_5g2_type;
	int				 band_6g_type;
	int				 band_6g2_type;
	int				 band_3rd_type;
	int				 band_4th_type;
	int				 band_5th_type;
    /* interface list */
    int              plc_attached;
    int              backhaul_option;
    UINT8            plcMac[AWND_MAC_LEN];     
    char             plcIfname[IFNAMSIZ];
    char             lanDevName[IFNAMSIZ];
    char             wanDevName[IFNAMSIZ];  
    char             ethIfnames[MAX_ETH_DEV_NUM][IFNAMSIZ];  
    int              ethIfCnt;
    /* timer */
    int              tm_scan_start;
    int              tm_scan_interval;
    int              tm_scan_sched;
    int              tm_status_start;
    int              tm_status_interval;    
    int              tm_online_start;
    int              tm_online_interval;
    int              tm_connect_duration;
    int              tm_plc_inspect_start;
    int              tm_plc_inspect_interval;
    int              tm_eth_inspect_start;
    int              tm_eth_inspect_interval;
    int              tm_update_lanip_start;
    int              tm_update_lanip_interval;
    int              tm_server_detect_start;
    int              tm_server_detect_interval;
    int              tm_re_stage_inspect;
    int              tm_wait_prefer_ap;
#if CONFIG_RE_RESTORE_STA_CONFIG
    int              tm_record_sta_config_interval;
    int              tm_record_sta_config_monitoring_interval;
#endif
#ifdef SUPPORT_MESHMODE_2G
    int              tm_meshmode_2g_inspect;
#endif
    int              tm_onboarding_start;
    int              tm_onboarding_interval;
    int              tm_bind_confirm_interval;
    int              plc_report_interval;
    int              eth_report_interval;    
    int              plc_entry_aging_time;
    int              eth_entry_aging_time;    
    /* rootap selection threshold*/
    int              scaling_factor;
    int              high_rssi_threshold;
    int              low_rssi_threshold;
    int              best_effort_rssi_threshold;	
    int              best_effort_rssi_inc;
    int              best_effort_uplink_rate;    
    int              plc_rate_good;
    int              wifi_lost_rate_to_plc;
    int              wifi_pathRate_threshold_2g;
    int              wifi_pathRate_threshold_5g;
    int              limit_scan_band1;
    int              limit_scan_band4;	
#if SCAN_OPTIMIZATION
    int              normal_scan_time;
    int              normal_scan_time_6g;
    int              fast_scan_time;
    int              connect_time;	
#endif
    /* debug level */
    int              debug_level;
    AWND_COUNTRY_TYPE country;
    char             staIfnames[AWND_BAND_MAX][IFNAMSIZ];
    char             apIfnames[AWND_BAND_MAX][IFNAMSIZ];    /* backhaul ap */
    char             configIfnames[AWND_BAND_MAX][IFNAMSIZ];
    char             preconfigIfnames[AWND_BAND_MAX][IFNAMSIZ];
    char             hostIfnames[AWND_BAND_MAX][IFNAMSIZ];
#if CONFIG_BSS_STATUS_CHECK
    int              tm_bss_status_inspect;
#endif
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    int              roaming_status_revert_interval;
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#ifdef SUPPORT_MESHMODE_2G
    int              onlyForTest;
#endif
#if CONFIG_OUTDOOR_CHANNELLIMIT
    char             special_id[SPECIALID_LEN + 1];  /* special id.
                         move out from macro if needed by other feature. */
    BOOL             channellimit_support;
    char             channellimit_id[CHANNELLIMIT_LEN + 1];  /* limit channel range for outdoor 5G */
    int              channellimit_start_chan;
    int              channellimit_end_chan;
#endif
} AWND_CONFIG;


typedef struct _AWND_NET_INFO {
    UINT8            id;                       /* IEEE80211_ELEMID_VENDOR */
    UINT8            len;                      /* length in bytes */
    UINT8            oui[3];                   /* 0x00, 0x1d, 0x0f */
    UINT8            type;                     /* OUI type */    
    UINT8            awnd_net_type;            /* subnet type:FAP,HAP,RE */
    UINT8            awnd_weight;              /* weight calculated by previous mode*/    
    UINT8            awnd_level;               /* level in the subnet  */
    UINT8            awnd_mac[AWND_MAC_LEN];   /* mac of the subnet */
    UINT8            awnd_label[AWND_LABEL_LEN];    /* label of the subnet */
    UINT8            wait;                          /* wait for mode change */
    UINT32           awnd_lanip;                    /* lan ip of AP*/
    UINT16           uplink_mask ;
    UINT16           uplink_rate;    
    UINT8            server_detected;            /* server detect fail/sucess */
    UINT8            reserve1[3];
    UINT32           server_touch_time;          /* server detect success time*/
    UINT32           awnd_dns;                   /* dns address of CAP */
    UINT8            lan_mac[AWND_MAC_LEN]; 
    UINT8            reserve2[2]; 	
} AWND_NET_INFO;

typedef struct _GROUP_INFO {    
    char             ssid[AWND_MAX_SSID_LEN];
    char             pwd[AWND_MAX_PWD_LEN]; 
    UINT8            label[AWND_LABEL_LEN];
} GROUP_INFO;

typedef struct _AWND_GROUP_INFO { 
    GROUP_INFO              configGroupInfo;
    GROUP_INFO              backhualGroupInfo;
    GROUP_INFO              staGroupInfo;
    GROUP_INFO              preconfGroupInfo; /* preconf for pair in factory mode*/
    GROUP_INFO              preconfigGroupInfo; 
    AWND_CONFIG_ROLE        cfg_role;            /* AP/RE */
    UINT32                  staType;       /* sta Vap use preconfGroupInfo or staGroupInfo ssid and password to connect */
} AWND_GROUP_INFO;

typedef struct {
    UINT8    index;
    UINT8    isNew;
    UINT8    lan_mac[AWND_MAC_LEN];    
    UINT8    plc_mac[AWND_MAC_LEN];
    UINT8    plcRoot;
    AWND_NET_INFO    netInfo;
    AWND_NEIGH_FLAG  flag;  
    UINT16   txRate;
    UINT16   rxRate;
} AWND_PLC_NEIGH;

typedef struct {
    int cnt;
    int eventEnable;
    AWND_PLC_NEIGH     plcNeigh[AWN_NEIGH_MAX_CNT];   
}AWND_PLC_NEIGH_TABLE;


typedef struct {
    UINT8    index; 
    UINT8    lan_mac[AWND_MAC_LEN];
    char     dev_name[IFNAMSIZ];
    UINT16   uplink_mask;
    UINT16   uplink_rate;
    UINT8    forward_num;
    AWND_ETH_NEIGH_DIR   nh_dir;
    AWND_NET_INFO        netInfo;
    AWND_NEIGH_FLAG      flag;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    UINT32           link_speed;                      /* link_speed of eth port */
    unsigned long    tx_speed;                        /* tx_speed of eth port */
    unsigned long    rx_speed;                        /* rx_speed of eth port */
#endif
    UINT8    forwarder[AWND_MAC_LEN];
} AWND_ETH_NEIGH;

typedef struct {
    int cnt;
    AWND_ETH_NEIGH     ethNeigh[AWN_NEIGH_MAX_CNT];   
}AWND_ETH_NEIGH_TABLE;

typedef struct _AWND_STA_CONFIG {
    UINT8    enable;
    UINT8    bssid[AWND_MAC_LEN];
    UINT8    channel;
}AWND_STA_CONFIG;

typedef struct {
    UINT8    index;
    char     ssid[AWND_MAX_SSID_LEN];
    UINT8    bssid[AWND_MAC_LEN];
    UINT8    lan_mac[AWND_MAC_LEN];	
    UINT8    rssi;
#ifdef SUPPORT_MESHMODE_2G
    UINT8    chanutil;
    UINT8    intf;
#endif
    UINT8    freq;
    UINT8    channel;
    UINT16   txRate;
    UINT16   rxRate;
#ifdef SUPPORT_MESHMODE_2G
    UINT16   maxRate;
#endif
    UINT16   uplinkMask;
    UINT16   uplinkRate;
    UINT16   pathRate;
    UINT     notFind;
    UINT     isConfig;
    UINT     isPreconf;
    UINT     isPreconfig;
    AWND_NET_INFO netInfo;
#if CONFIG_PLATFORM_BCM
    UINT     postCnt;
    UINT     restartCnt;
#endif
#if SCAN_OPTIMIZATION
    UINT8    missing_cnt;
#endif
} AWND_AP_ENTRY;

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
typedef struct _AWND_ROAMING_TARGET{
    UINT8 valid;
    AWND_AP_ENTRY entry;
} AWND_ROAMING_TARGET;
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

typedef struct _AWND_GLOBAL{
    UINT8              notBind;
    AWND_BIND_STATUS   bindStatus;
    UINT8              bindFast;
    AWND_LOCATION_TYPE locate;    
    AWND_MODE_TYPE     workMode;
#ifdef SUPPORT_MESHMODE_2G
    AWND_MESHMODE_2G_TYPE  meshmode;
    AWND_MESHMODE_2G_TYPE  meshmode_last;
    AWND_MESHSTATE_2G_TYPE  meshstate;
    UINT32             ticks;
    UINT32             connected_ticks[AWND_BAND_MAX_NUM];
    UINT8              is2GCaculatedBssid;
#endif
    AWND_NET_INFO      netInfo;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    AWND_NET_INFO      ethNetInfo; /* netinfo for eth, when eth & wlan backhual support */
    //UINT8              ethRootApMac[AWND_MAC_LEN];
    UINT8              findWifiRootApFailCnt;
#endif
    AWND_SUBMODE       subMode;
    AWND_AP_ENTRY      rootAp[AWND_BAND_MAX];
    AWND_CONN_STATUS   connStatus[AWND_BAND_MAX];
#if FAST_RECONNECT_ROOTAP
    AWND_AP_ENTRY      secondAp[AWND_BAND_MAX];
    UINT8              secondApNotEmpty;
    uint8_t            last_rootap_lanmac[AWND_MAC_LEN];
#endif
#if GET_AP_RSSI
    int                rootApRtRssi[AWND_BAND_MAX];
#endif
    AWND_STA_CONFIG    staConfig[AWND_BAND_MAX];
    UINT8              unlinkcnt;
    UINT8              plcAttached;
    UINT8              isPlcRoot;   
    AWND_PLC_NEIGH     plcPeerNeigh;
    AWND_CONN_STATUS   plcStatus;
    UINT8              plcWinWifi;
    UINT16             uplinkMask;
    UINT16             uplinkRate;
    UINT8              ethLinkTry;
    AWND_CONN_STATUS   ethStatus;
	UINT8              ethNeighExist[MAX_ETH_DEV_NUM];
	UINT8              ethLinktoAP[MAX_ETH_DEV_NUM];
	int                ethHasNeigh;
    UINT8              ethRootApMac[AWND_MAC_LEN];
    UINT32             link_status;
    UINT8              sysMode; /* Router or AP */
    AWND_ROOTAP_CHANNEL_TYPE rootApChType; 
    AWND_ONBOARDING_STATUS  isOnboarding;
    AWND_ONBOARDING_STATUS  isPreOnboarding;
    UINT8               wifiToHap;          /* RE need change to HAP from wifi scan result */
    UINT8               ethToHap;           /* RE need change to HAP after eth inspect */
    UINT8               plcToHap;           /* RE need change to HAP after plc inspect */
    AWND_RE_STAGE       reStage;          /*记录RE的阶段信息*/
    UINT32              stage2Timestamp;         /* 记录RE进入第二阶段的timestamp*/
    UINT32              stage4Timestamp;         /* 记录RE进入第四阶段的timestamp*/
    UINT8               server_detected;          /* server detect fail/sucess */
    UINT32              server_touch_time;       /* server detect success time*/  
    UINT8               fapMac[AWND_MAC_LEN];    /* mac of the fap from bind device lsit */
    UINT8               capMac[AWND_MAC_LEN];       /* mac of the connected cap */
    UINT32              capLanip;                   /* lanip of the connected cap */
    UINT8               capNetType;                 /* netType of the connected cap */
    UINT32              capDns;                     /* dns of the connected cap */
#if CONFIG_PLATFORM_BCM
    UINT8              scanFailCnt[AWND_BAND_MAX];
    UINT8              disconnRecord[AWND_BAND_MAX];
#endif
#if CONFIG_5G_HT160_SUPPORT
    UINT8              ht160Enable;
    UINT8              wifiBw[AWND_BAND_MAX];
#endif
#if CONFIG_WIFI_DFS_SILENT
    UINT8              SilentPeriod[AWND_BAND_MAX];
#endif
#if CONFIG_BSS_STATUS_CHECK
    UINT8              wlDownCnt[AWND_BAND_MAX];
    UINT8              bssDownCnt[AWND_BAND_MAX];
    UINT32             reinitCnt[AWND_BAND_MAX];
    UINT8              reloadCnt;
    UINT8              bwNeqCnt[AWND_BAND_MAX];
#endif
    UINT8              enable5g2;
    UINT8              enable6g;
    UINT8              enable6g2;
#if SCAN_OPTIMIZATION
    UINT32             connet_time[AWND_BAND_MAX];
    UINT8              scan_band_success_mask;
    UINT8              scan_one_more_time;/*-1: bindStatus=AWND_BIND_BACKHUAL_CONNECTING; 1: can not find fap in 5g's scan result */
#endif
    int                zwdfs_support[AWND_BAND_MAX];
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    AWND_ROAMING_TARGET roamTarget[AWND_BAND_MAX];     /* record the RE roaming target. In case best AP reselecting */
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */
    UINT8              eth_wifi_coexist; /* 1: support wifi when eth is connecting; 0: eth or wifi */
    UINT8              wpa_supplicant_disable_mask;
}AWND_GLOBAL;



typedef struct {
    UINT8 iApNum;
    AWND_AP_ENTRY tApEntry[AWND_MAX_GROUP_MEMBER];
} AWND_SCAN_RESULT;

typedef struct {
    UINT8 scan_in_retry;
    UINT8 scan_fast;
    UINT8 scan_windows;
    UINT8 scan_band;
#if SCAN_OPTIMIZATION
    UINT8 scan_fail_mask;
#endif
    AWND_SCAN_RESULT apList[AWND_BAND_MAX];
}AWND_SCAN_TABLE;

/* developer:wangchaoran@tp-link.com.cn
 *           lizhongwen@tp-link.com.cn
*/
typedef struct ISP_DCMP_PRECONFIG
{
    UINT8 rootap_link_state;
    UINT8 rootap_link_type;
    /* whether update wifi driver filter or not */
    BOOL  is_add_md5;
    /* if athx8 is RUNNING or NOT */
    BOOL  preconfig_vap_state;
}ISP_DCMP_PRECONFIG;

extern ISP_DCMP_PRECONFIG isp_dcmp_preconfig;
typedef struct {
    UINT8 prefer_ap_level;
    UINT8 prefer_ap_mac[AWND_MAC_LEN];
    UINT8 is_failed;
}AWND_UNABLE_CONN_AP_TABLE;

extern AWND_CONFIG l_awnd_config;

extern int awnd_get_rate_estimate(UINT8 rootDist, int factor, UINT16 backhaulMask,
    UINT16 backhaulRate, UINT8 snr, int nss, int phyMode, int chwidth);
extern int awnd_rssi_estimate(int rssi, int level, int factor);

extern int awnd_config_set_plc_nmk(char* nmk);
extern void awnd_check_wifi_ssid_pwd(AWND_GROUP_INFO *pAwndConfig, AWND_WIFI_IFACE_TYPE ifaceType);
extern int awnd_config_set_stacfg_bssid(char * bssid, AWND_BAND_TYPE band);
extern int awnd_config_set_stacfg_enb(int enb, AWND_BAND_TYPE band);
extern int awnd_config_set_all_stacfg_enb(int enb);
extern int awnd_config_get_stacfg_enb(AWND_BAND_TYPE band);
extern int awnd_config_get_stacfg_type(AWND_BAND_TYPE band, char *type);
extern int awnd_config_set_cfg_mesh_enb(int enb);
extern int awnd_config_set_eth_active(int active);
extern int awnd_config_set_eth_interface(const char* ifname);
//extern int awnd_config_set_eth_neigh_interface(AWND_ETH_PORT_NUM port, UINT8 value);
extern int awnd_config_set_eth_neigh_interface(int value);
extern int awnd_config_set_plc_active(int active);
extern int awnd_config_set_plc_as_root(UINT8 isRoot);
extern int awnd_config_set_channel(UINT8 channel, AWND_BAND_TYPE band);
#if CONFIG_RE_RESTORE_STA_CONFIG
extern int awnd_config_set_sta_config(BOOL need_save_config);
extern int awnd_config_restore_sta_config();
#endif
extern UINT8 awnd_config_get_channel(AWND_BAND_TYPE band);
extern int awnd_config_set_re_submode(AWND_SUBMODE submode);
extern int awnd_config_set_re_gwmode(int gw_mode);
extern int awnd_config_set_mode(int mode, int gw_mode);
extern int awnd_config_get_mode();
extern UINT8 awnd_config_get_weight();
#if CONFIG_5G_HT160_SUPPORT
extern UINT8 awnd_config_get_enable_ht160();
#endif /* CONFIG_5G_HT160_SUPPORT */
extern UINT8 awnd_config_get_enable_5g_ht240();
UINT8 awnd_config_get_enable_5g2();
UINT8 awnd_config_get_enable_6g();
UINT8 awnd_config_get_enable_6g2();
AWND_COUNTRY_TYPE awnd_config_get_country_code();
extern int awnd_read_config(char *fpath, AWND_CONFIG *pAwndConfig);
extern int awnd_set_re_bridge(AWND_SUBMODE submode);
extern int awnd_get_group_id(AWND_GROUP_INFO * pConfig, UINT8* bind);
extern void awnd_clean_gid_detect();
extern int awnd_write_rt_info(AWND_INTERFACE_TYPE band, BOOL status, UINT8* pMac, BOOL capHasPlc);
extern int awnd_write_work_mode(AWND_MODE_TYPE workMode, int linked, UINT8* pMac, AWND_NET_TYPE netType, UINT8 level, UINT8* pParentMac);
extern BOOL awnd_check_ap_mode();
extern char* awnd_dynamic_marocs_value_get(char *marocName);

extern UINT8 awnd_config_get_cfg_mesh_enb();
#ifdef SUPPORT_MESHMODE_2G
extern int awnd_config_get_meshmode_2g();
extern int awnd_config_sta_vap_disable(int disable, AWND_BAND_TYPE band);
extern int awnd_config_get_record_channel_2g();
extern int awnd_config_get_bandwidth_2g();
extern int awnd_file_exist(char *file);
#endif
extern int awnd_config_set_cfg_mesh_enb(int enb);
extern int awnd_get_bind_fap_mac();
extern int awnd_config_set_path_rate_threshold(int pathRate2g, int pathRate5g);
extern int awnd_netinfo_update_dns(UINT32 dns);
extern size_t awnd_strlcat(char *dst, const char *src, size_t dst_sz);

#ifdef CONFIG_AWN_RE_ROAMING
extern int awnd_config_sta_bssid(char *bssid_str, const char *vap);
extern int awnd_re_roam(uint8_t *mac);
#endif

extern int check_unable_conn_ap_table(AWND_AP_ENTRY *ap_entry, AWND_UNABLE_TABLE_OP_TYPE op_type);
extern void set_prefer();
extern void awnd_start_scan_new();
extern void awnd_prefer_change_scan();
extern void awnd_set_oui_update_status_fap(int status);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
extern int awnd_update_tpie(AWND_NET_INFO *pAwndNetInfo, AWND_NETINFO_TYPE NetInfoType);
#else
extern int awnd_update_tpie(AWND_NET_INFO *pAwndNetInfo);
#endif
extern void channel_switch_state_set();
extern void channel_switch_state_clear();
extern void awnd_switch_channel(AWND_BAND_TYPE band, UINT8 channel, BOOL force);

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
extern int awnd_ai_fap_start(int alg_strategy, char *mac);
extern int awnd_ai_debug_print();
// extern int awnd_ai_network_get_scan_result_now(void);
extern void awnd_ai_network_get_scan_result();
extern int awnd_set_tipc_check_time(int n);
extern void awnd_mode_call_hotplug(AWND_HOTPLUG_CONFIG *pHotplugCfg);
void set_send_scan_info_flag(BOOL flag);
int awnd_ai_network_send_roaming(void);
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */
extern void awnd_set_oui_now_version(int version);
extern void channel_switch_state_set();
extern void channel_switch_state_clear();
extern int awnd_config_check_block_chan_list(AWND_BAND_TYPE band, int *channel);
extern void awnd_switch_channel(AWND_BAND_TYPE band, UINT8 channel, BOOL force);

#ifdef CONFIG_DCMP_GLOBAL_support
int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, 
                        char* preconf_ssid, UINT8* preconf_label, 
                        char* preconfig_ssid, UINT8* preconfig_label, 
                        AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#else

int awnd_get_scan_result(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
#endif

UINT8 awnd_config_get_precfg_mesh_enb();
int awnd_config_set_precfg_mesh_enb(int enb);
UINT32 get_rootap_link_info(ISP_DCMP_PRECONFIG *isp_dcmp_preconfig);
BOOL get_preconfig_vap_state();
void change_rootap();
void md5_make_digest(unsigned char* digest, unsigned char* input, int len);
extern void awnd_get_special_id(char* specialid);

#if CONFIG_OUTDOOR_CHANNELLIMIT
extern BOOL awnd_get_chanlimit_support();
extern int awnd_get_chanlimit_chan(const char *uci_path);
extern void awnd_get_outdoor_channellimit(char* channellimit);
#endif

typedef struct _HOTPLUG_INFO
{
    AWND_HOTPLUG_TYPE type;
    char typeName[16];
}HOTPLUG_INFO;

typedef struct _MODE_INFO
{
    AWND_MODE_TYPE type;
    char modeName[16];
}MODE_INFO;

typedef struct _NET_TYPE_INFO
{
    AWND_NET_TYPE type;
    char netTypeName[16];
}NET_TYPE_INFO;

extern MODE_INFO modeArray[AWND_MODE_MAX];
static inline char* modeToStr(AWND_MODE_TYPE type)
{
    int index = 0;
    for (index = 0; index < AWND_MODE_MAX; index++)
    {
        if (type == modeArray[index].type)
            return modeArray[index].modeName;
    }

    return "--";
}

extern NET_TYPE_INFO netTypeArray[AWND_NET_MAX];
static inline char* netTypeToStr(AWND_NET_TYPE type)
{
    int index = 0;
    for (index = 0; index < AWND_NET_MAX; index++)
    {
        if (type == netTypeArray[index].type)
            return netTypeArray[index].netTypeName;
    }

    return "--";
}

static inline void _macaddr_ntop(UINT8* mac, char* buf)
{
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline int _mac_raw_equal(UINT8 *mac1, UINT8 *mac2)
{
    return (/*(mac1[0] & 0xf0) == (mac2[0] & 0xf0) &&*/  (0 == memcmp(&mac1[1], &mac2[1], AWND_MAC_LEN - 1)));
}

static inline int _is_null_group_info(GROUP_INFO *pGroupInfo)
{
    GROUP_INFO zeroGroupInfo;

    memset(&(zeroGroupInfo), 0, sizeof(GROUP_INFO));
    return !memcmp(&(zeroGroupInfo), pGroupInfo, sizeof(GROUP_INFO));
}

static inline void _stable_sleep(unsigned int sleep_time)
{
	while(1)
	{
		sleep_time = sleep(sleep_time);
		if (sleep_time == 0)
		{
			break;
		}
	}
}

static inline AWND_REAL_BAND_TYPE _get_real_band_type(AWND_BAND_TYPE band)
{
    AWND_REAL_BAND_TYPE real_band = AWND_REAL_BAND_MAX;

    switch (band)
    {
        case AWND_BAND_2G:
            real_band = AWND_REAL_BAND_2G;
            break;
        case AWND_BAND_5G:
            real_band = AWND_REAL_BAND_5G;
            break;
        case AWND_BAND_3RD:
            real_band = l_awnd_config.band_3rd_type;
            break;
        case AWND_BAND_4TH:
            real_band = l_awnd_config.band_4th_type;
            break;
        case AWND_BAND_5TH:
            real_band = AWND_REAL_BAND_6G2;
            break;
        default:
            AWN_LOG_CRIT("invaild band type: %d", band);
            break;
    }

    return real_band;
}

static inline AWND_BAND_TYPE _get_band_type_index(AWND_REAL_BAND_TYPE real_band)
{
    AWND_BAND_TYPE band = AWND_BAND_MAX;

    switch (real_band)
    {
        case AWND_REAL_BAND_2G:
            band = AWND_BAND_2G;
            break;
        case AWND_REAL_BAND_5G:
            band = AWND_BAND_5G;
            break;
        case AWND_REAL_BAND_5G2:
            band = AWND_BAND_3RD;
            break;
        case AWND_REAL_BAND_6G:
            if(l_awnd_config.band_3rd_type == AWND_REAL_BAND_6G)
                band = AWND_BAND_3RD;
            else if(l_awnd_config.band_4th_type == AWND_REAL_BAND_6G)
                band = AWND_BAND_4TH;
            else if(l_awnd_config.band_5th_type == AWND_REAL_BAND_6G)
                band = AWND_BAND_5TH;
            else                
                AWN_LOG_CRIT("AWND_REAL_BAND_6G invaild band type!!!");
            break;
        case AWND_REAL_BAND_6G2:        
            if(l_awnd_config.band_3rd_type == AWND_REAL_BAND_6G2)
                band = AWND_BAND_3RD;
            else if(l_awnd_config.band_4th_type == AWND_REAL_BAND_6G2)
                band = AWND_BAND_4TH;
            else if(l_awnd_config.band_5th_type == AWND_REAL_BAND_6G2)
                band = AWND_BAND_5TH;
            else                
                AWN_LOG_CRIT("AWND_REAL_BAND_6G2 invaild band type!!!");
            break;
        default:
            AWN_LOG_CRIT("invaild band type: %d", band);
            break;
    }

    return band;
}

static inline int _is_both_band_connected(AWND_CONN_STATUS *pConnState)
{    
	int index = 0;
	for(index = 0;index < l_awnd_config.band_num;index++)
	{
		if( pConnState[index] != AWND_STATUS_CONNECTED)
			return 0;
	}
	return 1;
}

static inline int _is_one_band_disconnected(AWND_CONN_STATUS *pConnState)
{    
	int index = 0;
	for(index = 0;index < l_awnd_config.band_num;index++)
	{
		if( pConnState[index] == AWND_STATUS_DISCONNECT)
			return 1;
	}
	return 0;
}

static inline int _is_in_connected_state(AWND_CONN_STATUS *pConnState)
{    
	int index = 0;
	for(index = 0;index < l_awnd_config.band_num;index++)
	{
		if( pConnState[index] == AWND_STATUS_CONNECTED)
			return 1;
	}
	return 0;
}
static inline int _is_in_disconnected_state(AWND_CONN_STATUS *pConnState)
{    
	int index = 0;
	for(index = 0;index < l_awnd_config.band_num;index++)
	{
		if( pConnState[index] != AWND_STATUS_DISCONNECT)
			return 0;
	}
	return 1;
}
#ifdef CONFIG_AWN_RE_ROAMING
static inline int _is_in_roaming_state(AWND_CONN_STATUS *pConnState)
{    
	int index = 0;
	for(index = 0;index < l_awnd_config.band_num;index++)
	{
		if( pConnState[index] != AWND_STATUS_ROAMING)
			return 0;
	}
	return 1;
}
#endif

#endif

