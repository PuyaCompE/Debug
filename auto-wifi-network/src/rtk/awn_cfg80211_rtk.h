/******************************************************************************
Copyright (c) 2009-2023 TP-Link Technologies CO.,LTD.  All rights reserved.

File name	: awn_cfg80211_rtk.h
Version		: v0.1 
Description	: Netklink control API for AWN, support by Realtek

Author		: Jiang Ji <jiangji@tp-link.com.hk>
Create date	: 2023/3/23

History		:
01, 2023/3/23 Jiang Ji, create this file

*****************************************************************************/
#ifndef __AWN_CFG80211_RTK_H_
#define __AWN_CFG80211_RTK_H_

#include "../awn_wifi_handler_api.h"

/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN			128
#define IEEE80211_MAX_TP_IE		(TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN		3

#ifndef IW_ESSID_MAX_SIZE
#define IW_ESSID_MAX_SIZE 32
#endif

#ifndef TP_MAX_SCANREQ_FREQ
#define TP_MAX_SCANREQ_FREQ  16
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

typedef struct rtk_tpie_t {
    int tpie_len;
    tpie_t netInfo;
} rtk_tpie_t;

typedef struct tp_scan_param {
	size_t      ssid_len;
	u_int8_t    num_channels;
	u_int32_t   min_channel_time; /* in TU */
	u_int32_t	max_channel_time; /* in TU */
	u_int8_t ssid[IW_ESSID_MAX_SIZE + 1];
	u_int8_t channels[TP_MAX_SCANREQ_FREQ];
	u_int8_t active;
} TP_SCAN_PARAM;

typedef struct rtk_scan_result_entry {
	u_int8_t    index;
	u_int8_t    ssid[IW_ESSID_MAX_SIZE + 1];
	u_int8_t    ssidLen;
	u_int8_t    bssid[MAC_ADDR_LEN];
	u_int8_t    rssi;
	u_int16_t   freq;
	u_int8_t    channel;
	u_int16_t   txRate;
	u_int16_t   rxRate;
	u_int16_t   uplinkMask;
	u_int16_t   uplinkRate;
	u_int16_t   pathRate;
	u_int32_t   notFind;
	rtk_tpie_t  netInfo;
} RTK_SCAN_ENTRY;

typedef struct _rtk_scan_result {
	u_int32_t count;   /* scan result entry count  */
	RTK_SCAN_ENTRY scan_entry[TP_SCAN_ENTRY_MAX_NUM];
} RTK_SCAN_RESULT;

typedef struct tp_vap_info {
	u_int8_t  mac[MAC_ADDR_LEN];
	u_int8_t  channum;
	u_int8_t  ssid[IW_ESSID_MAX_SIZE + 1];
	u_int16_t phy_id;
} TP_VAP_INFO;

typedef struct tp_phycap_info {
	u_int8_t       maxMCS;
	u_int8_t       numStreams;
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

int awn_cfg80211_get_tpie(const char *ifname, void *data, int *data_len);
int awn_cfg80211_scan(const char *ifname, TP_SCAN_PARAM *scan_params);
int awn_cfg80211_scan_result(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_vap_info(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_ap_phyinfo(const char *ifname, void *data, int *data_len);
int awn_cfg80211_get_sta_info(const char *ifname, void *data, int *data_len);

#endif
