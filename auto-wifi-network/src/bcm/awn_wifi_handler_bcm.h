/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_bcm.h
Version     : v0.1 
Description : awn wifi handler for bcm

Author      :  <dengzhong@tp-link.com.cn>
Create date : 2019/4/1

History     :
01, 2019/4/1 Deng Zhong, Created file.

*****************************************************************************/


#ifndef _AWN_WIFI_HANDLER_BCM_H_
#define _AWN_WIFI_HANDLER_BCM_H_

/***************************************************************************/
/*						INCLUDE_FILES					 */
/***************************************************************************/
#if 0
#include <net/ethernet.h>	/* struct ether_addr */
#include <net/if_arp.h>		/* For ARPHRD_ETHER */
#include <sys/socket.h>		/* For AF_INET & struct sockaddr */
#include <netinet/in.h>         /* For struct sockaddr_in */
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#endif

#include "../auto_wifi_net.h"
#include "../awn_wifi_handler_api.h"
#include "../awn_log.h"

/***************************************************************************/
/*						DEFINES						 */
/***************************************************************************/
/* type         5G      24G     5G2 */
/* STA          wl0     wl1     wl2 */
/* backhaul AP  wl01    wl11    wl21 */
/* AP           wl02    wl12    wl22 */
/* guest AP     wl03    wl13    wl23 */
/* config AP    wl04    wl14    wl24 */
/* default AP   wl05    wl15    wl25 */

#define BCM_USE_WIFI_VLAN_DEV    1
#define BCM_LAN_VLAN_DEV_SUFFIX "1"

#define	WLC_IOCTL_SMLEN			256	    /* small length ioctl buffer required */
#define WLC_IOCTL_MEDLEN        1536    /* "med" length ioctl buffer required */
#define	WLC_IOCTL_MAXLEN		8192	/* max length ioctl buffer required */

#define WIFI_SCAN_RESULT_FILE            "/tmp/wifi_scan_result_%s"

#define BCM_WPA_SUPPLICANT_CTRL_STA_FMT "/var/run/%s_wpa_supplicant"


/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN           128
#define IEEE80211_MAX_TP_IE     (TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN        3

typedef struct bcm_tpie{
    UINT8            id;                       /* IEEE80211_ELEMID_VENDOR */
    UINT8            len;                      /* length in bytes */
    UINT8            oui[VENDORIE_OUI_LEN];    /* 0x00, 0x1d, 0x0f */
    UINT8            tpie[TP_IE_MAX_LEN];      /* OUI type */
} bcm_tpie_t;

/* Structures and constants used for "vndr_ie" IOVar interface */
#define VNDR_IE_CMD_LEN		4	/**< length of the set command string: * "add", "del" (+ NUL) */

#define VNDR_IE_HD_LEN (VNDR_IE_CMD_LEN + 8) /* cmd + iecount + pktflag */
#define MAX_TP_IE_SET_BUF 1024

typedef enum
{
    BCM_SCAN_ACTIVE = 0,
    BCM_SCAN_PASSIVE,
    BCM_SCAN_LOW_PRIO,
    BCM_SCAN_PROHIBITED,
    BCM_SCAN_OFFCHAN,
    BCM_SCAN_HOTSPOT,
    BCM_SCAN_SWTCHAN
} BCM_SCAN_TYPE;


#if CONFIG_BCM_USE_WL_INCLUDE_FILE

#else

/*************************************************/
#define WLC_GET_MAGIC 				0
#define WLC_GET_VERSION				1
#define WLC_UP						2
#define WLC_DOWN					3
#define WLC_GET_RATE				12
#define WLC_GET_BSSID				23  /* Get the BSSID value, error if STA and not associated */
#define WLC_SET_BSSID				24
#define WLC_GET_SSID				25
#define WLC_SET_SSID				26

#define WLC_GET_CHANNEL             29
#define WLC_SET_CHANNEL             30

#define WLC_GET_PASSIVE_SCAN		48
#define WLC_SET_PASSIVE_SCAN		49
#define WLC_SCAN				    50
#define WLC_SCAN_RESULTS			51
#define WLC_DISASSOC				52
#define WLC_REASSOC				    53

#define WLC_GET_BSS_INFO			136     /* Print information about current network association */
/* returns a list of STAs associated with a specific bsscfg */
#define WLC_GET_ASSOCLIST			159
#define WLC_GET_UP				    162

#define WLC_GET_SCAN_CHANNEL_TIME		184
#define WLC_SET_SCAN_CHANNEL_TIME		185

#define WLC_GET_VAR		            262	    /* get value of named variable  0x106 */
#define WLC_SET_VAR		            263	    /* set named variable to value 0x107 */
#define WLC_TP_SCAN_RESULTS 		340		/* get custom results > store scan entry */
#define WLC_TP_STA_GET_CONN_STAT 	341		/* connect status with rootap */
#define WLC_TP_STA_GET_TPIE 		342		/* get rootap's tpie */
#define WLC_TP_GET_PHY				343		/* phy and chwidth */
#define WLC_TP_STORE_SCAN_RESULTS 	344		/* only get store scan entry which has tpie */
#define WLC_TP_FLUSH_SCAN_RESULTS 	345		/* flush scan tables */
/*************************************************/

//#define ifr_name ifr_ifrn.ifrn_name /* interface name */
#define ifr_addr ifr_ifru.ifru_addr /* address */
#define ifr_broadaddr ifr_ifru.ifru_broadaddr /* broadcast address */
#define ifr_netmask ifr_ifru.ifru_netmask /* interface net mask */
#define ifr_flags ifr_ifru.ifru_flags /* flags */
#define ifr_hwaddr ifr_ifru.ifru_hwaddr /* MAC address */

/**Linux network driver ioctl encoding */
typedef struct wl_ioctl {
	UINT32 cmd;	/**< common ioctl definition */
	void *buf;	/**< pointer to user buffer */
	UINT32 len;	/**< length of user buffer */
	UINT8 set;		/**< 1=set IOCTL; 0=query IOCTL */
	UINT32 used;	/**< bytes read or written (optional) */
	UINT32 needed;	/**< bytes needed (optional) */
} wl_ioctl_t;


/** channel encoding */
typedef struct channel_info {
	UINT32 hw_channel;
	UINT32 target_channel;
	UINT32 scan_channel;
} channel_info_t;

typedef struct {
	UINT32 pktflag;			/**< bitmask indicating which packet(s) contain this IE */
	bcm_tpie_t vndr_ie_data;		/**< vendor IE data */
}  vndr_ie_info_t;

typedef struct {
	UINT32 iecount;			/**< number of entries in the vndr_ie_list[] array */
	vndr_ie_info_t vndr_ie_list[1];	/**< variable size list of vndr_ie_info_t structs */
}  vndr_ie_buf_t;

typedef  struct {
	UINT8 cmd[VNDR_IE_CMD_LEN];	/**< vndr_ie IOVar set command : "add", "del" + NUL */
	vndr_ie_buf_t vndr_ie_buffer;	/**< buffer containing Vendor IE list information */
}  vndr_ie_setbuf_t;

typedef struct maclist {
   UINT32          count;            /*   number of MAC addresses */
   unsigned char ea[1];            /*   variable length array of MAC addresses */
} WLM_1905_MACLIST;


#define WL_SCAN_PARAMS_FIXED_SIZE  64
#define WL_SCAN_PARAMS_FIXED_SIZE_V1	WL_SCAN_PARAMS_FIXED_SIZE
#define WL_SCAN_PARAMS_FIXED_SIZE_V2	80
#define WL_SCAN_VERSION_MAJOR_V2		2u
#define WL_NUMCHANNELS		64
#define WL_SCAN_PARAMS_SSID_MAX 	10

#define DOT11_MAX_SSID_LEN 32

typedef struct wlc_ssid {
	UINT32		SSID_len;
	UINT8		SSID[DOT11_MAX_SSID_LEN];
} wlc_ssid_t;

static const struct ether_addr ether_bcast = {{255, 255, 255, 255, 255, 255}};

#define WLC_MAX_ASSOC_OUI_NUM 6
typedef struct {
	UINT8 count;
	UINT8 oui[WLC_MAX_ASSOC_OUI_NUM][VENDORIE_OUI_LEN];
} sta_vendor_oui_t;


#define WL_MAXRATES_IN_SET		16	/**< max # of rates in a rateset */

typedef struct wl_rateset {
	UINT32	count;				/**< # rates in this set */
	UINT8	rates[WL_MAXRATES_IN_SET];	/**< rates in 500kbps units w/hi bit set if basic */
} wl_rateset_t;

/* A chanspec holds the channel number, band, bandwidth and control sideband */
typedef INT16 chanspec_t;

#define WL_STA_ANT_MAX		4	/**< max possible rx antennas */
#define MCSSET_LEN	16	/* 16-bits per 8-bit set to give 128-bits bitmap of MCS Index */
#define WL_VHT_CAP_MCS_MAP_NSS_MAX	8
#define WL_HE_CAP_MCS_MAP_NSS_MAX	8

typedef struct wl_rateset_args_v2 {
	UINT16 version;		/**< version. */
	UINT16 len;		/**< length */
	UINT32	count;		/**< # rates in this set */
	UINT8	rates[WL_MAXRATES_IN_SET];	/**< rates in 500kbps units w/hi bit set if basic */
	UINT8   mcs[MCSSET_LEN];		/**< supported mcs index bit map */
	UINT16 vht_mcs[WL_VHT_CAP_MCS_MAP_NSS_MAX]; /**< supported mcs index bit map per nss */
	UINT16 he_mcs[WL_HE_CAP_MCS_MAP_NSS_MAX]; /**< supported he mcs index bit map per nss */
} wl_rateset_args_v2_t;

typedef struct wl_scan_version {
	UINT16	version;		/**< version of the structure */
	UINT16	length;			/**< length of the entire structure */

	/* scan interface version numbers */
	UINT16	scan_ver_major;		/**< scan interface major version number */
} wl_scan_version_t;

typedef struct wl_scan_params {
	wlc_ssid_t ssid;		/**< default: {0, ""} */
	struct ether_addr bssid;	/**< default: bcast */
	UINT8 bss_type;			/**< default: any,
					 * DOT11_BSSTYPE_ANY/INFRASTRUCTURE/INDEPENDENT
					 */
	UINT8 scan_type;		/**< flags, 0 use default */

	INT32 nprobes;			/**< -1 use default, number of probes per channel */
	INT32 active_time;		/**< -1 use default, dwell time per channel for
					 * active scanning
					 */
	INT32 passive_time;		/**< -1 use default, dwell time per channel
					 * for passive scanning
					 */
	INT32 home_time;		/**< -1 use default, dwell time for the home channel
					 * between channel scans
					 */
	INT32 channel_num;		/**< count of channels and ssids that follow
					 *
					 * low half is count of channels in channel_list, 0
					 * means default (use all available channels)
					 *
					 * high half is entries in wlc_ssid_t array that
					 * follows channel_list, aligned for int32 (4 bytes)
					 * meaning an odd channel count implies a 2-byte pad
					 * between end of channel_list and first ssid
					 *
					 * if ssid count is zero, single ssid in the fixed
					 * parameter portion is assumed, otherwise ssid in
					 * the fixed portion is ignored
					 */
	UINT16 channel_list[1];		/**< list of chanspecs */
} wl_scan_params_t;

typedef struct wl_scan_params_v2 {
	wlc_ssid_t ssid;		/**< default: {0, ""} */
	struct ether_addr bssid;	/**< default: bcast */
	INT8 bss_type;			/**< default: any,
					 * DOT11_BSSTYPE_ANY/INFRASTRUCTURE/INDEPENDENT
					 */
	UINT8 scan_type;		/**< flags, 0 use default */

	INT32 nprobes;			/**< -1 use default, number of probes per channel */
	INT32 active_time;		/**< -1 use default, dwell time per channel for
					 * active scanning
					 */
	INT32 passive_time;		/**< -1 use default, dwell time per channel
					 * for passive scanning
					 */
	INT32 home_time;		/**< -1 use default, dwell time for the home channel
					 * between channel scans
					 */
	INT32 channel_num;		/**< count of channels and ssids that follow
					 *
					 * low half is count of channels in channel_list, 0
					 * means default (use all available channels)
					 *
					 * high half is entries in wlc_ssid_t array that
					 * follows channel_list, aligned for int32 (4 bytes)
					 * meaning an odd channel count implies a 2-byte pad
					 * between end of channel_list and first ssid
					 *
					 * if ssid count is zero, single ssid in the fixed
					 * parameter portion is assumed, otherwise ssid in
					 * the fixed portion is ignored
					 */
	UINT16 version;			 /* Version of wl_scan_params, change value of
					 * WL_SCAN_PARAM_VERSION on version update
					 */
	UINT16 length;			 /* length of structure wl_scan_params_v1_t
					 * without implicit pad
					 */
	UINT32 scan_type_2;              /* flags, 0x01 for RNR SCAN , 0x02 for PSC SCAN */
	UINT32 ssid_type;		/**< ssid_type_flag ,0 use default, and flags specified
					 * WL_SCAN_SSID_FLAGS
					 */
	UINT32 n_short_ssid;
	UINT16 channel_list[1];		/**< list of chanspecs */
} wl_scan_params_v2_t;

/* sta_info_t version 7
 * sta_info_t version 6 is not compatible with all the router branches so we extended version 6
 * to support all the router branches
 */
typedef struct {
	UINT16                  ver;            /**< version of this struct */
	UINT16                  len;            /**< length in bytes of this structure */
	UINT16                  cap;            /**< sta's advertised capabilities */
	UINT16                  RSRV_0;
	UINT32                  flags;          /**< flags defined below */
	UINT32                  idle;           /**< time since data pkt rx'd from sta */
	struct ether_addr       ea;             /**< Station address */
	UINT16                  RSRV_1;
	wl_rateset_t			rateset;        /**< rateset in use */
	UINT32                  in;             /**< seconds elapsed since associated */
	UINT32                  listen_interval_inms; /**< Min Listen interval in ms for this STA */
	UINT32                  tx_pkts;        /**< # of user packets transmitted (unicast) */
	UINT32                  tx_failures;    /**< # of user packets failed */
	UINT32                  rx_ucast_pkts;  /**< # of unicast packets received */
	UINT32                  rx_mcast_pkts;  /**< # of multicast packets received */
	UINT32                  tx_rate;        /**< Rate used by last tx frame */
	UINT32                  rx_rate;        /**< Rate of last successful rx frame */
	UINT32                  rx_decrypt_succeeds;    /**< # of packet decrypted successfully */
	UINT32                  rx_decrypt_failures;    /**< # of packet decrypted unsuccessfully */
	UINT32                  tx_tot_pkts;    /**< # of user tx pkts (ucast + mcast) */
	UINT32                  rx_tot_pkts;    /**< # of data packets recvd (uni + mcast) */
	UINT32                  tx_mcast_pkts;  /**< # of mcast pkts txed */
	UINT64                  tx_tot_bytes;   /**< data bytes txed (ucast + mcast) */
	UINT64                  rx_tot_bytes;   /**< data bytes recvd (ucast + mcast) */
	UINT64                  tx_ucast_bytes; /**< data bytes txed (ucast) */
	UINT64                  tx_mcast_bytes; /**< # data bytes txed (mcast) */
	UINT64                  rx_ucast_bytes; /**< data bytes recvd (ucast) */
	UINT64                  rx_mcast_bytes; /**< data bytes recvd (mcast) */
	INT8                    rssi[WL_STA_ANT_MAX]; /**< average rssi per antenna
						       * of data frames
						       */
	INT8                    nf[WL_STA_ANT_MAX];     /**< per antenna noise floor */
	UINT16                  aid;                    /**< association ID */
	UINT16                  ht_capabilities;        /**< advertised ht caps */
	UINT16                  vht_flags;              /**< converted vht flags */
	UINT16                  RSRV_3;
	UINT32                  tx_pkts_retried;        /**< # of frames where a retry was
							 * necessary
							 */
	UINT32                  tx_pkts_retry_exhausted; /**< # of user frames where a retry
							  * was exhausted
							  */
	INT8                    rx_lastpkt_rssi[WL_STA_ANT_MAX]; /**< Per antenna RSSI of last
								  * received data frame.
								  */
	/* TX WLAN retry/failure statistics:
	 * Separated for host requested frames and WLAN locally generated frames.
	 * Include unicast frame only where the retries/failures can be counted.
	 */
	UINT32                  tx_pkts_total;          /**< # user frames sent successfully */
	UINT32                  tx_pkts_retries;        /**< # user frames retries */
	UINT32                  tx_pkts_fw_total;       /**< # FW generated sent successfully */
	UINT32                  tx_pkts_fw_retries;     /**< # retries for FW generated frames */
	UINT32                  tx_pkts_fw_retry_exhausted;     /**< # FW generated where a retry
								 * was exhausted
								 */
	UINT32                  rx_pkts_retried;        /**< # rx with retry bit set */
	UINT32                  tx_rate_fallback;       /**< lowest fallback TX rate */
	/* Fields above this line are common to sta_info_t versions 4 and 5 */

	UINT32                  rx_dur_total;   /* total user RX duration (estimated) */

	chanspec_t              chanspec;       /** chanspec this sta is on */
	UINT16                  RSRV_4;
	wl_rateset_args_v2_t    rateset_adv;    /* rateset along with mcs index bitmap */
	UINT16                  wpauth;                 /* authentication type */
	UINT8                   algo;                   /* crypto algorithm */
	UINT8					RSRV_5;
	UINT32                  tx_rspec;       /* Rate of last successful tx frame */
	UINT32                  rx_rspec;       /* Rate of last successful rx frame */
	UINT32                  wnm_cap;              /* wnm capabilities */
	UINT16                  he_flags;	/* converted he flags */
	UINT16                  RSRV_6;
	sta_vendor_oui_t        sta_vendor_oui;
} sta_info_v7_t;


/**
 * BSS info structure
 * Applications MUST CHECK ie_offset field and length field to access IEs and
 * next bss_info structure in a vector (in wl_scan_results_t)
 */
typedef struct wl_bss_info {
	UINT32		version;		/**< version field */
	UINT32		length;			/**< byte length of data in this record,
						 * starting at version and including IEs
						 */
	struct ether_addr BSSID;
	UINT16		beacon_period;		/**< units are Kusec */
	UINT16		capability;		/**< Capability information */
	UINT8		SSID_len;
	UINT8		SSID[32];
	UINT8		bcnflags;		/* additional flags w.r.t. beacon */
	struct {
		UINT32	count;			/**< # rates in this set */
		UINT8	rates[16];		/**< rates in 500kbps units w/hi bit set if basic */
	} rateset;				/**< supported rates */
	chanspec_t	chanspec;		/**< chanspec for bss */
	UINT16		atim_window;		/**< units are Kusec */
	UINT8		dtim_period;		/**< DTIM period */
	UINT8		accessnet;		/* from beacon interwork IE (if bcnflags) */
	INT16		RSSI;			/**< receive signal strength (in dBm) */
	INT8		phy_noise;		/**< noise (in dBm) */
	UINT8		n_cap;			/**< BSS is 802.11N Capable */
	UINT16		freespace1;		/* make implicit padding explicit */
	UINT32		nbss_cap;		/**< 802.11N+AC BSS Capabilities */
	UINT8		ctl_ch;			/**< 802.11N BSS control channel number */
	UINT8		padding1[3];		/**< explicit struct alignment padding */
	UINT16		vht_rxmcsmap;	/**< VHT rx mcs map (802.11ac IE, VHT_CAP_MCS_MAP_*) */
	UINT16		vht_txmcsmap;	/**< VHT tx mcs map (802.11ac IE, VHT_CAP_MCS_MAP_*) */
	UINT8		flags;			/**< flags */
	UINT8		vht_cap;		/**< BSS is vht capable */
	UINT8		reserved[2];		/**< Reserved for expansion of BSS properties */
	UINT8		basic_mcs[MCSSET_LEN];	/**< 802.11N BSS required MCS set */

	UINT16		ie_offset;		/**< offset at which IEs start, from beginning */
	UINT16		freespace2;		/* making implicit padding explicit */
	UINT32		ie_length;		/**< byte length of Information Elements */
	INT16		SNR;			/**< average SNR of during frame reception */
	UINT16		vht_mcsmap;		/**< STA's Associated vhtmcsmap */
	UINT16		vht_mcsmap_prop;	/**< STA's Associated prop vhtmcsmap */
	UINT16		vht_txmcsmap_prop;	/**< prop VHT tx mcs prop */
} wl_bss_info_v109_t;

#define	LEGACY_WL_BSS_INFO_VERSION	107		/**< older version of wl_bss_info struct */
#define	LEGACY2_WL_BSS_INFO_VERSION	108		/**< old version of wl_bss_info struct */
#define	WL_BSS_INFO_VERSION			109		/**< current version of wl_bss_info struct */

/* MLME Enumerations */
#define DOT11_BSSTYPE_INFRASTRUCTURE		0	/* d11 infrastructure */
#define DOT11_BSSTYPE_INDEPENDENT		1	/* d11 independent */
#define DOT11_BSSTYPE_ANY			2	/* d11 any BSS type */
#define DOT11_BSSTYPE_MESH			3	/* d11 Mesh */
#define DOT11_SCANTYPE_ACTIVE			0	/* d11 scan active */
#define DOT11_SCANTYPE_PASSIVE			1	/* d11 scan passive */

#define WL_SCANFLAGS_PASSIVE	0x01	/* force passive scan */
#define WL_SCANFLAGS_LOW_PRIO	0x02	/* Low priority scan */
#define WL_SCANFLAGS_PROHIBITED	0x04	/* allow scanning prohibited channels */
#define WL_SCANFLAGS_OFFCHAN	0x08	/* allow scanning/reporting off-channel APs */
#define WL_SCANFLAGS_HOTSPOT	0x10	/* automatic ANQP to hotspot APs */
#define WL_SCANFLAGS_SWTCHAN	0x20	/* Force channel switch for differerent bandwidth */

/* Flags for sta_info_t indicating properties of STA */
#define WL_STA_BRCM			0x00000001	/* Running a Broadcom driver */
#define WL_STA_WME			0x00000002	/* WMM association */
#define WL_STA_NONERP		0x00000004	/* No ERP */
#define WL_STA_AUTHE		0x00000008	/* Authenticated */
#define WL_STA_ASSOC		0x00000010	/* Associated */
#define WL_STA_AUTHO		0x00000020	/* Authorized */
#define WL_STA_WDS			0x00000040	/* Wireless Distribution System */
#define WL_STA_WDS_LINKUP	0x00000080	/* WDS traffic/probes flowing properly */
#define WL_STA_PS			0x00000100	/* STA is in power save mode from AP's viewpoint */
#define WL_STA_APSD_BE		0x00000200	/* APSD delv/trigger for AC_BE is default enabled */
#define WL_STA_APSD_BK		0x00000400	/* APSD delv/trigger for AC_BK is default enabled */
#define WL_STA_APSD_VI		0x00000800	/* APSD delv/trigger for AC_VI is default enabled */
#define WL_STA_APSD_VO		0x00001000	/* APSD delv/trigger for AC_VO is default enabled */
#define WL_STA_N_CAP		0x00002000	/* STA 802.11n capable */
#define WL_STA_SCBSTATS		0x00004000	/* Per STA debug stats */
#define WL_STA_AMPDU_CAP	0x00008000	/* STA AMPDU capable */
#define WL_STA_AMSDU_CAP	0x00010000	/* STA AMSDU capable */
#define WL_STA_MIMO_PS		0x00020000	/* mimo ps mode is enabled */
#define WL_STA_MIMO_RTS		0x00040000	/* send rts in mimo ps mode */
#define WL_STA_RIFS_CAP		0x00080000	/* rifs enabled */
#define WL_STA_VHT_CAP		0x00100000	/* STA VHT(11ac) capable */
#define WL_STA_WPS			0x00200000	/* WPS state */
#define WL_STA_HE_CAP		0x00400000	/* STA HE(11ax) capable */
#define WL_STA_GBL_RCLASS	0x00800000	/* STA supports global operatinng class */
#define WL_STA_DWDS_CAP		0x01000000	/* DWDS CAP */
#define WL_STA_DWDS			0x02000000	/* DWDS active */
#define WL_WDS_LINKUP		WL_STA_WDS_LINKUP	/* deprecated */

#define BSS_PEER_INFO_PARAM_CUR_VER	0
typedef struct {
	UINT16			version;
	struct ether_addr	ea;
	INT32			rssi;
	UINT32			tx_rate;	/**< current tx rate */
	UINT32			rx_rate;	/**< current rx rate */
	wl_rateset_t	rateset;	/**< rateset in use */
	UINT32			age;		/**< age in seconds */
} bss_peer_info_t;

typedef struct {
	UINT16			version;
	UINT16			bss_peer_info_len;	/**< length of bss_peer_info_t */
	UINT32			count;			/**< number of peer info */
	bss_peer_info_t		peer_info[1];		/**< peer info */
} bss_peer_list_info_t;

typedef struct {
	UINT16			version;
	struct	ether_addr ea;	/**< peer MAC address */
} bss_peer_info_param_t;


typedef struct bcm_scan_result_entry {
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
    bcm_tpie_t netInfo;
} bcm_scan_result_entry_t;

typedef struct _tp_scan_result {
	UINT32 status;
	UINT32 buflen;
	UINT32 count;	/* scan result entry count  */
	bcm_scan_result_entry_t scan_entry[1];
} tp_scan_result_t;
// sizeof(bcm_scan_result_entry_t) 194 byte(TP_IE_MAX_LEN=128) old 316(TP_IE_MAX_LEN=250)

typedef struct _tp_flush_scan_result {
	UINT32 cmd;
} tp_flush_scan_result_t;

#define WL_TP_FLUSH_SCAN_RESULT_SIZE (sizeof(tp_flush_scan_result_t))

typedef struct bcm_wlanconfig_tpie {
    int status;								/* 0:success */
    UINT8 conn_status;						/* 1:conencted 0:disconencted */
    UINT8 entry_type;
    UINT8 tp_macaddr[ETHER_ADDR_LEN];		/* rootap's bssid copy form usersapce */
    bcm_tpie_t netInfo;
} bcm_wlanconfig_tpie_t;

typedef struct bcm_conn_status {
    INT32 wds_state;						/* 0:conencted 1:disconencted */
    INT32 rssi;
} bcm_conn_status_t;

typedef struct bcm_wlanconfig_phy {
    int status;								/* 0:success */
    int phyMode;
    int chwidth;
    UINT8 nss;
} bcm_wlanconfig_phy_t;

#define WL_STA_GET_TPIE_BUF_SIZE 		(sizeof(bcm_wlanconfig_tpie_t))
#define WL_STA_GET_CONN_STAT_BUF_SIZE 	(sizeof(bcm_conn_status_t))
#define WL_GET_PHY_BUF_SIZE 			(sizeof(bcm_wlanconfig_phy_t))


/*********************************************************************
    DFS status
**********************************************************************/
/* cac state values */
#define WL_DFS_CACSTATE_IDLE        0    /* state for operating in non-radar channel */
#define WL_DFS_CACSTATE_PREISM_CAC  1    /* CAC in progress */
#define WL_DFS_CACSTATE_ISM         2    /* ISM in progress */
#define WL_DFS_CACSTATE_CSA         3    /* csa */
#define WL_DFS_CACSTATE_POSTISM_CAC 4    /* ISM CAC */
#define WL_DFS_CACSTATE_PREISM_OOC  5    /* PREISM OOC */
#define WL_DFS_CACSTATE_POSTISM_OOC 6    /* POSTISM OOC */
#define WL_DFS_CACSTATES            7    /* this many states exist */

/** data structure used in 'dfs_status' wl interface, which is used to query dfs status */
typedef struct {
    UINT32 state;        /**< noted by WL_DFS_CACSTATE_XX. */
    UINT32 duration;        /**< time spent in ms in state. */
    /**
     * as dfs enters ISM state, it removes the operational channel from quiet channel
     * list and notes the channel in channel_cleared. set to 0 if no channel is cleared
     */
    chanspec_t chanspec_cleared;
    /** chanspec cleared used to be a uint32, add another to uint16 to maintain size */
    UINT16 pad;
} wl_dfs_status_t;

/*
 * error codes could be added but the defined ones shouldn't be changed/deleted
 * these error codes are exposed to the user code
 * when ever a new error code is added to this list
 * please update errorstring table with the related error string and
 * update osl files with os specific errorcode map
*/

#define BCME_OK				0	/* Success */
#define BCME_ERROR			-1	/* Error generic */
#define BCME_BADARG			-2	/* Bad Argument */
#define BCME_BADOPTION			-3	/* Bad option */
#define BCME_NOTUP			-4	/* Not up */
#define BCME_NOTDOWN			-5	/* Not down */
#define BCME_NOTAP			-6	/* Not AP */
#define BCME_NOTSTA			-7	/* Not STA  */
#define BCME_BADKEYIDX			-8	/* BAD Key Index */
#define BCME_RADIOOFF			-9	/* Radio Off */
#define BCME_NOTBANDLOCKED		-10	/* Not  band locked */
#define BCME_NOCLK			-11	/* No Clock */
#define BCME_BADRATESET			-12	/* BAD Rate valueset */
#define BCME_BADBAND			-13	/* BAD Band */
#define BCME_BUFTOOSHORT		-14	/* Buffer too short */
#define BCME_BUFTOOLONG			-15	/* Buffer too long */
#define BCME_BUSY			-16	/* Busy */
#define BCME_NOTASSOCIATED		-17	/* Not Associated */
#define BCME_BADSSIDLEN			-18	/* Bad SSID len */
#define BCME_OUTOFRANGECHAN		-19	/* Out of Range Channel */
#define BCME_BADCHAN			-20	/* Bad Channel */
#define BCME_BADADDR			-21	/* Bad Address */
#define BCME_NORESOURCE			-22	/* Not Enough Resources */
#define BCME_UNSUPPORTED		-23	/* Unsupported */
#define BCME_BADLEN			-24	/* Bad length */
#define BCME_NOTREADY			-25	/* Not Ready */
#define BCME_EPERM			-26	/* Not Permitted */
#define BCME_NOMEM			-27	/* No Memory */
#define BCME_ASSOCIATED			-28	/* Associated */
#define BCME_RANGE			-29	/* Not In Range */
#define BCME_NOTFOUND			-30	/* Not Found */
#define BCME_WME_NOT_ENABLED		-31	/* WME Not Enabled */
#define BCME_TSPEC_NOTFOUND		-32	/* TSPEC Not Found */
#define BCME_ACM_NOTSUPPORTED		-33	/* ACM Not Supported */
#define BCME_NOT_WME_ASSOCIATION	-34	/* Not WME Association */
#define BCME_SDIO_ERROR			-35	/* SDIO Bus Error */
#define BCME_DONGLE_DOWN		-36	/* Dongle Not Accessible */
#define BCME_VERSION			-37	/* Incorrect version */
#define BCME_TXFAIL			-38	/* TX failure */
#define BCME_RXFAIL			-39	/* RX failure */
#define BCME_NODEVICE			-40	/* Device not present */
#define BCME_NMODE_DISABLED		-41	/* NMODE disabled */
#define BCME_HOFFLOAD_RESIDENT		-42	/* offload resident */
#define BCME_SCANREJECT			-43	/* reject scan request */
#define BCME_USAGE_ERROR		-44	/* WLCMD usage error */
#define BCME_IOCTL_ERROR		-45	/* WLCMD ioctl error */
#define BCME_SERIAL_PORT_ERR		-46	/* RWL serial port error */
#define BCME_DISABLED			-47	/* Disabled in this build */
#define BCME_DECERR			-48	/* Decrypt error */
#define BCME_ENCERR			-49	/* Encrypt error */
#define BCME_MICERR			-50	/* Integrity/MIC error */
#define BCME_REPLAY			-51	/* Replay */
#define BCME_IE_NOTFOUND		-52	/* IE not found */
#define BCME_DATA_NOTFOUND		-53	/* Complete data not found in buffer */
#define BCME_NOT_GC			-54	/* expecting a group client */
#define BCME_PRS_REQ_FAILED		-55	/* GC presence req failed to sent */
#define BCME_NO_P2P_SE			-56	/* Could not find P2P-Subelement */
#define BCME_NOA_PND			-57	/* NoA pending, CB shuld be NULL */
#define BCME_FRAG_Q_FAILED		-58	/* queueing 80211 frag failedi */
#define BCME_GET_AF_FAILED		-59	/* Get p2p AF pkt failed */
#define BCME_MSCH_NOTREADY		-60	/* scheduler not ready */
#define BCME_IOV_LAST_CMD		-61	/* last batched iov sub-command */
#define BCME_MINIPMU_CAL_FAIL		-62	/* MiniPMU cal failed */
#define BCME_RCAL_FAIL			-63	/* Rcal failed */
#define BCME_LPF_RCCAL_FAIL		-64	/* RCCAL failed */
#define BCME_DACBUF_RCCAL_FAIL		-65	/* RCCAL failed */
#define BCME_VCOCAL_FAIL		-66	/* VCOCAL failed */
#define BCME_BANDLOCKED			-67	/* interface is restricted to a band */
#define BCME_BAD_IE_DATA		-68	/* Recieved ie with invalid/bad data */
#define BCME_LAST			BCME_BAD_IE_DATA

#endif

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/

/***************************************************************************/
/*                        FUNCTIONS                                         */
/***************************************************************************/

int get_default_mesh_channel_bcm(AWND_BAND_TYPE band, int *channel);
int check_block_chan_list_bcm(AWND_BAND_TYPE band, int *channel);
int get_sta_channel_bcm(AWND_BAND_TYPE band, int *channel);
int get_backhaul_ap_channel_bcm(AWND_BAND_TYPE band, int *channel);

int get_phy_bcm(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
int get_wds_state_bcm(AWND_BAND_TYPE band, int *up);
int get_rootap_phyRate_bcm(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
int get_rootap_rssi_bcm(AWND_BAND_TYPE band, INT32 *rssi);
int get_rootap_info_bcm(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
int get_rootap_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
int get_tpie_bcm(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);

int init_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
int update_wifi_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType);


int flush_scan_table_single_band_bcm(AWND_BAND_TYPE band, BOOL force);
int flush_scan_table_bcm(void);
int do_scan_bcm(UINT8 scanBandMask);
int do_scan_fast_bcm(UINT8 scanBandMask);
int get_scan_result_bcm(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
int scan_bcm(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);

int set_channel_bcm(AWND_BAND_TYPE band, UINT8 channel);
int get_sta_iface_in_bridge_bcm(AWND_BAND_TYPE band, UINT8* ifname);

int disconn_sta_pre_bcm(AWND_BAND_TYPE band, UINT* pBandMask);
int disconn_all_sta_pre_bcm(UINT* pBandMask);
int disconn_sta_post_bcm(AWND_BAND_TYPE band);
int disconn_sta_bcm(AWND_BAND_TYPE band);
int disconn_all_sta_bcm(void);
int reconn_sta_pre_bcm(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
int reconn_sta_post_bcm(AWND_BAND_TYPE band, BOOL check_wpa_status);
int reset_sta_connection_bcm(AWND_BAND_TYPE band);

int set_backhaul_sta_dev_bcm(UINT32 link_state, unsigned int eth_link_state);
void do_band_restart_bcm(UINT8 BandMask);
int get_wifi_bw_bcm(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
void set_wifi_bw_bcm(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
int bss_status_check_bcm(void);
int get_wifi_zwdfs_support_bcm(AWND_BAND_TYPE band);

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_bcm(AWND_BAND_TYPE band);
int reload_sta_conf_bcm(AWND_BAND_TYPE band);
int set_wireless_sta_bssid_bcm(char *bssid_str, AWND_BAND_TYPE band);
int wifi_re_roam_bcm(void);
#endif /* CONFIG_AWN_RE_ROAMING */

#endif /* _AWN_WIFI_HANDLER_BCM_H_ */

