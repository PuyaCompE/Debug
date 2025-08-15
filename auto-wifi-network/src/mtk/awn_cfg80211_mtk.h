/******************************************************************************
Copyright (c) 2009-2023 TP-Link Technologies CO.,LTD.  All rights reserved.

File name	: awn_cfg80211_mtk.h
Version		: v0.1 
Description	: Netklink control API for AWN, support by Realtek

Author		: Jiang Ji <jiangji@tp-link.com.hk>
Create date	: 2023/3/23

History		:
01, 2023/3/23 Jiang Ji, create this file

*****************************************************************************/
#ifndef __AWN_CFG80211_MTK_H_
#define __AWN_CFG80211_MTK_H_

#include "../awn_wifi_handler_api.h"

/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN			128
#define IEEE80211_MAX_TP_IE		(TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN		3

#ifndef IW_ESSID_MAX_SIZE
#define IW_ESSID_MAX_SIZE 32
#endif

#ifndef TP_MAX_SCANREQ_FREQ
#define TP_MAX_SCANREQ_FREQ  59
#endif

#ifndef TP_SCAN_ENTRY_MAX_NUM
#define TP_SCAN_ENTRY_MAX_NUM 128
#endif

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 6
#endif

typedef struct tpie_t{
    unsigned char    id;                       /* IEEE80211_ELEMID_VENDOR */
    unsigned char    len;                      /* length in bytes */
    unsigned char    oui[VENDORIE_OUI_LEN];    /* 0x00, 0x1d, 0x0f */
    unsigned char    tpie[TP_IE_MAX_LEN];      /* OUI type */
} tpie_t;

typedef struct mtk_tpie_t {
    int tpie_len;
    tpie_t netInfo;
} mtk_tpie_t;

typedef struct tp_scan_param {
	size_t      ssid_len;
	uint8_t    num_channels;
	UINT32   min_channel_time; /* in TU */
	UINT32	max_channel_time; /* in TU */
	uint8_t ssid[IW_ESSID_MAX_SIZE + 1];
	uint8_t channels[TP_MAX_SCANREQ_FREQ];
	uint8_t active;
	uint8_t scan_band;
	uint8_t flush;
} TP_SCAN_PARAM;

typedef struct mtk_scan_result_entry {
	uint8_t    index;
	uint8_t    ssid[IW_ESSID_MAX_SIZE + 1];
	uint8_t    ssidLen;
	uint8_t    bssid[MAC_ADDR_LEN];
	uint8_t    rssi;
	uint16_t   freq;
	uint8_t    channel;
	uint16_t   txRate;
	uint16_t   rxRate;
	uint16_t   uplinkMask;
	uint16_t   uplinkRate;
	uint16_t   pathRate;
	u_int32_t   notFind;
	mtk_tpie_t  netInfo;
} MTK_SCAN_ENTRY;

typedef struct _mtk_scan_result {
	u_int32_t count;   /* scan result entry count  */
	MTK_SCAN_ENTRY scan_entry[TP_SCAN_ENTRY_MAX_NUM];
} MTK_SCAN_RESULT;

typedef struct tp_vap_info {
	uint8_t  mac[MAC_ADDR_LEN];
	uint8_t  channum;
	uint8_t  ssid[IW_ESSID_MAX_SIZE + 1];
	uint16_t phy_id;
} TP_VAP_INFO;

typedef struct tp_phycap_info {
	uint8_t       maxMCS;
	uint8_t       numStreams;
	wlan_chwidth_e maxChWidth;
	wlan_phymode_e phyMode;
} TP_PHYCAP_INFO;

typedef struct tp_sta_info {
	unsigned short	aid;
	unsigned char	addr[MAC_ADDR_LEN];
	unsigned int	tx_packets;
	unsigned int	rx_packets;
	unsigned long	tx_bytes;
	unsigned long	rx_bytes;
	unsigned int	tx_rate;
	unsigned int	rx_rate;
	unsigned int	expired_time;
	unsigned short	flags;
	unsigned int	rssi;
	unsigned int	state;
} TP_CFG80211_STA_INFO;

#define CFG80211_SCAN_ENTRY_MAX_NUM 128
#define CFG80211_VENDOR_IE_MAX_LEN 256

#define WLAN_EID_SSID 0
#define WLAN_EID_VENDOR_SPECIFIC 221

#define TP_OUI     "\x00\x1d\x0f" /* TP-LINK OUI */
#define TP_NEW_OUI "\x00\x31\x92" /* TP-LINK NEW OUI */
#define TP_VENDOR_CMD_OUI 0x001d0f

enum nr_cfg80211_cmd {
	AWN_CMD_GET_TPIE = 0,
	AWN_CMD_START_SCAN,
	AWN_CMD_SCAN_RESULT,
	AWN_CMD_AP_INFO,
	AWN_CMD_AP_PHYINFO,
	AWN_CMD_GET_STAINFO,  /* wlanX-vxd info */
	AWN_CMD_GET_CHANINFO,
	AWN_CMD_GET_CACNOPSTATUS,
	AWN_CMD_GET_SCAN_STATUS,
};

typedef struct tp_cfg80211_vendor_data {
	int data_len;
	uint8_t *data;
} TP_CFG80211_VENDOR_DATA;

typedef struct tp_cfg80211_scan_result_entry {
	uint8_t bssid[MAC_ADDR_LEN];
	int freq;
	uint16_t beacon_int;
	uint16_t caps;
	int noise;
	int level;
	uint64_t tsf;
	unsigned int age;
	uint8_t ssid[IW_ESSID_MAX_SIZE + 2];
	uint8_t ssid_len;
	uint8_t tpie[CFG80211_VENDOR_IE_MAX_LEN];
	uint8_t tpie_len;
} TP_CFG80211_SCAN_RESULT_ENTRY;

typedef struct tp_cfg80211_scan_results {
	size_t bss_num;
	TP_CFG80211_SCAN_RESULT_ENTRY bss_entry[CFG80211_SCAN_ENTRY_MAX_NUM];
} TP_CFG80211_SCAN_RESULTS;

typedef struct tpie_search_entry {
	uint8_t entry_type;
	uint8_t bssid[MAC_ADDR_LEN];
} TPIE_SEARCH_ENTRY;

/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN			128
#define IEEE80211_MAX_TP_IE		(TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN		3

struct nl80211_state {
	struct nl_handle *nl_sock;
	int nl80211_id;
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};
/*
enum nlmsgerr_attrs {
	NLMSGERR_ATTR_UNUSED,
	NLMSGERR_ATTR_MSG,
	NLMSGERR_ATTR_OFFS,
	NLMSGERR_ATTR_COOKIE,

	__NLMSGERR_ATTR_MAX,
	NLMSGERR_ATTR_MAX = __NLMSGERR_ATTR_MAX - 1
};*/
#ifndef NETLINK_CAP_ACK
#define NETLINK_CAP_ACK 10
#endif
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
#endif
#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NLE_DUMP_INTR
#define NLE_DUMP_INTR 33  /* copy from libnl3.5  netlink/errno.h */
#endif

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 6
#endif
#define MTK_NR_FLOOR (-92)

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

static uint8_t *tp_get_ie(const uint8_t *ies, size_t ies_len, uint8_t eid,
	uint8_t *oui, size_t oui_len, size_t *ie_len);

int awn_cfg80211_get_tpie(const char *ifname, TPIE_SEARCH_ENTRY *pSearchEntry, void *data, int *data_len);
int awn_cfg80211_scan(const char *ifname, TP_SCAN_PARAM *scan_params);
int awn_cfg80211_scan_result(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_vap_info(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_ap_phyinfo(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_sta_info(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_channel_info(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_scan_status(const char *ifname, void *data, int *data_len);

#endif
