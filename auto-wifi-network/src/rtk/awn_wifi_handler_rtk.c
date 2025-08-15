/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_RTK.c
Version     : v0.1 
Description : awn wifi handler for RTK

Author      :  <puhaowen@tp-link.com.cn>
Create date : 2019/4/28

History     :
01, 2019/4/28 Pu Haowen, Created file.

*****************************************************************************/

/***************************************************************************/
/*                        CONFIGURATIONS                                   */
/***************************************************************************/


/***************************************************************************/
/*                        INCLUDE_FILES                                    */
/***************************************************************************/
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <libubox/blobmsg_json.h>
#include <json/json.h>
#include <net/if.h>

#include "tp_linux.h"

#include "../auto_wifi_net.h"
#include "../awn_log.h"
#include "../awn_wifi_handler_api.h"

#include "awn_wifi_handler_rtk.h"
#include "awn_hostapd_rtk.h"
#include "awn_cfg80211_rtk.h"
/***************************************************************************/
/*                        DEFINES                                          */
/***************************************************************************/
/* unalligned little endian access */
#define LE_READ_4(p)                    \
    ((u_int32_t)                    \
     ((((const u_int8_t *)(p))[0]      ) |        \
      (((const u_int8_t *)(p))[1] <<  8) |        \
      (((const u_int8_t *)(p))[2] << 16) |        \
      (((const u_int8_t *)(p))[3] << 24)))

#define LE_READ_2(p)                        \
    ((u_int16_t)                            \
     ((((u_int8_t *)(p))[0]      ) | (((u_int8_t *)(p))[1] <<  8)))

#define LE_WRITE_2(p, n) \
    do{\
        *p++ = (u_int16_t)n & 0xff;\
        *p++ = ((u_int16_t)n >> 8) & 0xff;\
    }while(0)

#define LE_WRITE_4(p, n) \
    do{\
        *p++ = (u_int32_t)n & 0xff;\
        *p++ = ((u_int32_t)n >> 8) & 0xff;\
        *p++ = ((u_int32_t)n >> 16) & 0xff;\
        *p++ = ((u_int32_t)n >> 24) & 0xff;\
    }while(0)

#define CMDLINE_LENGTH          256

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN AWND_MAC_LEN
#endif
#define RTK_RSSI_COMPENSATION 92
#define TP_RSSI_RANGE_LOW	0
#define TP_RSSI_RANGE_HIGH	95

#define RTK_STAINFO_WIFI_ASOC_STATE 0x00000001 /* Linked */

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/

/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/
static char *band_suffix[AWND_BAND_MAX] = {"2g", "5g", "5g2"};
static char *RTK_ifname_ap_prefix_str[AWND_BAND_MAX] = {"wlan1",
                                                        "wlan0",
                                                        "wlan2"};
static char *RTK_config_ap_postfix[AWND_BAND_MAX] = {"-vap0",
                                                     "-vap0",
                                                     "-vap0"};
static char *RTK_default_ap_postfix[AWND_BAND_MAX] = {"-vap2",
                                                      "-vap2",
                                                      "-vap2"};
static char *RTK_backhaul_ap_postfix[AWND_BAND_MAX] = {"",
                                                       "",
                                                       ""};

static char *RTK_ifname_sta_prefix_str[AWND_BAND_MAX] = {RTK_IFNAME_2G_STA_PREFIX_STR,
                                                         RTK_IFNAME_5G_STA_PREFIX_STR,
                                                         RTK_IFNAME_5G2_STA_PREFIX_STR};
static char *RTK_ifname_sta_post_str[AWND_BAND_MAX] = {RTK_IFNAME_2G_STA_POST_STR,
                                                       RTK_IFNAME_5G_STA_POST_STR,
                                                       RTK_IFNAME_5G2_STA_POST_STR};

static char *rtk_phy_name[AWND_BAND_MAX] = {"phy0", "phy1", "phy2"};

#define RTK_STA_INFO_PROC_PATH_2G "/proc"
#define RTK_STA_INFO_PROC_PATH_5G "/proc/net/rtk_wifi6"

#define RTK_STA_INFO_PROC_FILE_2G "sta_info"
#define RTK_STA_INFO_PROC_FILE_5G "sta_info"

static char *RTK_wlan_proc_file_path_prefix[AWND_BAND_MAX] = {RTK_STA_INFO_PROC_PATH_2G,
                                                          RTK_STA_INFO_PROC_PATH_5G,
                                                          RTK_STA_INFO_PROC_PATH_5G};

static char *RTK_wlan_proc_stainfo_file[AWND_BAND_MAX] = {RTK_STA_INFO_PROC_FILE_2G,
                                                          RTK_STA_INFO_PROC_FILE_5G,
                                                          RTK_STA_INFO_PROC_FILE_5G};

extern AWND_GLOBAL g_awnd;
extern AWND_CONFIG l_awnd_config;

static int _fast_scan_single_channel(AWND_BAND_TYPE band);

extern int awnd_get_network_oui();
extern void awnd_set_oui_update_status_re(int status);
extern int fap_oui_update_status;
extern int re_oui_update_status;
/***************************************************************************/
/*                        LOCAL FUNCTIONS                                  */
/***************************************************************************/

/*
    2g ch 1 -> 2412
    5g ch 36 -> 5180
    6g ch 37 -> 6135
*/
static int channel_to_freq(AWND_BAND_TYPE band, int channel)
{
    int freq;
    switch(band){
        case AWND_BAND_2G:
            freq = 2412 + (channel - 1) * 5;
            break;
        case AWND_BAND_5G:
        case AWND_BAND_5G2:
            freq = 5000 + channel * 5;
            break;
        case   AWND_BAND_6G:
            freq = 5950 + channel * 5;
            break;
    }
    return freq;
}

static int freq_to_channel(AWND_BAND_TYPE band, int freq)
{
    int channel;
    switch(band){
        case AWND_BAND_2G:
            channel = (freq - 2412)/5 + 1;
            break;
        case AWND_BAND_5G:
        case AWND_BAND_5G2:
            channel = (freq - 5000)/5;
            break;
        case   AWND_BAND_6G:
            channel = (freq - 5950)/5;
            break;
    }
    return channel;
}

static inline int _mac_compare(UINT8 *mac1, UINT8 *mac2)
{
    int macIdx;
    for (macIdx = 0; macIdx < 6; macIdx++)
    {
        if (mac1[macIdx] > mac2[macIdx])
            return 1;
        else if (mac1[macIdx] < mac2[macIdx])
            return -1;
    }
    return 0;
}

static inline int istpoui(const UINT8 *frm)
{
    return frm[1] > 3 && ((LE_READ_4(frm+2) == ((IEEE80211_TP_OUI_TYPE << 24)|IEEE80211_TP_OUI)) ||
        (LE_READ_4(frm+2) == ((IEEE80211_TP_OUI_TYPE << 24)|IEEE80211_TP_NEW_OUI)));
}

static int _copy_essid(char* buf, int bufsize, const UINT8* essid, int essid_len)
{
    size_t maxlen;

    if (essid_len > bufsize)
        maxlen = bufsize;
    else
        maxlen = essid_len;

    memcpy(buf, essid, maxlen);

    if (maxlen != essid_len)
    {
        memcpy(buf + maxlen - 3, "...", 3);
    }

    buf[maxlen] = '\0';

    return maxlen;
}

static int _wifi_exec_cmd(INT8* cmd, ...)
{
    char buf[1024] = {0};
    va_list vaList;

    va_start (vaList, cmd);
    vsprintf (buf, cmd, vaList);
    va_end (vaList);

    TP_SYSTEM(buf);
    AWN_LOG_INFO("wifi cmd(%s)", buf);

    return AWND_OK;
}

static int _get_channel(INT8 *ifname, int *channel)
{
    int ret = AWND_OK;
	TP_VAP_INFO vap_info;
	int len = 0;
	int chan = 0;

	memset(&vap_info, 0, sizeof(vap_info));

	ret = awn_cfg80211_get_vap_info(ifname, &vap_info, &len);
	if (ret)
	{
		AWN_LOG_CRIT("get vap_info fail");
		ret = AWND_ERROR;
	}
	else
	{
		if (strlen(vap_info.ssid) > 0)
		{
			chan = (int)vap_info.channum;
			ret = AWND_OK;
		}
		else
		{
			ret = AWND_ERROR;
		}
	}

	*channel = chan;

    return ret;
}

/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/
int get_default_mesh_channel_RTK(AWND_BAND_TYPE band, int *channel)
{
    char ifname[RTK_IFNAMESIZE] = {0};
    snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);
    return _get_channel(ifname, channel);
}

int get_sta_channel_RTK(AWND_BAND_TYPE band, int *channel)
{
    INT8 ifname[RTK_IFNAMESIZE] = {0};
    snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
    return _get_channel(ifname, channel);
}

int get_backhaul_ap_channel_RTK(AWND_BAND_TYPE band, int *channel)
{
    INT8 ifname[RTK_IFNAMESIZE] = {0};

    snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);

    return _get_channel(ifname, channel);
}

int get_phy_RTK(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth)
{
	int ret = AWND_OK;
	TP_PHYCAP_INFO phy_info;
	unsigned char ifname[IFNAMSIZ] = {'\0'};
	int len = 0;
	int chan = 0;

	if (band < AWND_BAND_2G || band >= AWND_BAND_MAX ||
		nss == NULL || phyMode == NULL || chwidth == NULL)
	{
		return AWND_ERROR;
	}

	memset(&phy_info, 0, sizeof(phy_info));

	snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);
	ret = awn_cfg80211_get_ap_phyinfo(ifname, &phy_info, &len);
	if (ret)
	{
		AWN_LOG_CRIT("get phy_info fail");
		*nss = 0;
		*phyMode = wlan_phymode_invalid;
		*chwidth = wlan_chwidth_invalid;
		ret = AWND_ERROR;
	}
	else
	{
		*nss = phy_info.numStreams;
		*phyMode = phy_info.phyMode;
		*chwidth = phy_info.maxChWidth;
		ret = AWND_OK;
	}

	return ret;
}

int _get_vap_status(const char *ifname, int *up)
{
	struct ifreq ifr;
	int ret = AWND_OK;
	int sock = -1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		AWN_LOG_ERR("%s: create socket fail\n", __func__);
		ret = AWND_ERROR;
		goto END;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) {
		ret = errno ? -errno : -999;
		AWN_LOG_ERR("Could not read interface %s flags: %s",
			   ifname, strerror(errno));
		ret = AWND_ERROR;
		goto END;
	}

	if (0 == (ifr.ifr_flags & IFF_UP))
	{
		*up = 0;
	}
	else
	{
		*up = 1;
	}

END:
	if (sock)
	{
		close(sock);
	}
	return ret;
}

/* get rootap's txrate/rxrate */
static int __get_rootap_general_info_RTK(AWND_BAND_TYPE band, UINT16 *pTxRate, UINT16 *pRxRate, int *pStatus, int *pRssi)
{
    int ret = AWND_OK;
    TP_CFG80211_STA_INFO sta_info;
    unsigned char ifname[IFNAMSIZ] = {0};
    int len = 0;

    snprintf(ifname, sizeof(ifname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
    if (pTxRate == NULL || pRxRate== NULL || pStatus == NULL || pRssi == NULL)
    {
        AWN_LOG_ERR("%s get rootap info fail", ifname);
        return AWND_ERROR;
    }

    memset(&sta_info, 0, sizeof(sta_info));

    ret = awn_cfg80211_get_sta_info(ifname, &sta_info, &len);
    if (ret)
    {
        ret = AWND_ERROR;
    }
    else
    {
        *pTxRate = sta_info.tx_rate;
        *pRxRate = sta_info.rx_rate;
        *pStatus = sta_info.state & RTK_STAINFO_WIFI_ASOC_STATE;

        if (sta_info.rssi < TP_RSSI_RANGE_LOW)
        {
            sta_info.rssi = TP_RSSI_RANGE_LOW;
        }
        else if (sta_info.rssi > RTK_RSSI_COMPENSATION)
        {
            sta_info.rssi = RTK_RSSI_COMPENSATION;
        }

        *pRssi = sta_info.rssi - TP_RSSI_RANGE_HIGH;

        ret = AWND_OK;
    }

    return ret;
}

int get_wds_state_RTK(AWND_BAND_TYPE band, int *up
#if GET_AP_RSSI
                    , int *rssi
#endif
                        )
{
    int linkstatus = 0;
    UINT16 txrate = 0;
    UINT16 rxrate = 0;
    int rssitmp = 0;
    unsigned char ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

    __get_rootap_general_info_RTK(band, &txrate, &rxrate, &linkstatus, &rssitmp);
    _get_vap_status(ifname, up);
#if GET_AP_RSSI
    *rssi = rssitmp;
#endif
    return linkstatus;
}

/* get rootap's txrate/rxrate */
int get_rootap_phyRate_RTK(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate)
{
    int linkstatus = 0;
    int rssi = 0;
    __get_rootap_general_info_RTK(band, txrate, rxrate, &linkstatus, &rssi);
    return AWND_OK;
}

int get_rootap_rssi_RTK(AWND_BAND_TYPE band, INT32 *rssi)
{
    int ret = AWND_OK;
    TP_CFG80211_STA_INFO sta_info;
    unsigned char ifname[IFNAMSIZ] = {0};
    int len = 0;

    snprintf(ifname, sizeof(ifname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
    if (rssi == NULL)
    {
        AWN_LOG_ERR("%s get rootap rssi fail", ifname);
        return AWND_ERROR;
    }

    memset(&sta_info, 0, sizeof(sta_info));

    ret = awn_cfg80211_get_sta_info(ifname, &sta_info, &len);
    if (ret)
    {
        *rssi = 0;
        ret = AWND_ERROR;
    }
    else
    {
        if (sta_info.rssi < TP_RSSI_RANGE_LOW)
        {
            *rssi = TP_RSSI_RANGE_LOW;
        }
        else if (sta_info.rssi > TP_RSSI_RANGE_HIGH)
        {
            *rssi = TP_RSSI_RANGE_HIGH;
        }
        else
        {
            *rssi = sta_info.rssi;
        }
        ret = AWND_OK;
    }

    return ret;
}

/* no use */
int get_rootap_info_RTK(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band)
{
    return AWND_OK;
}
/* no use */
int get_rootap_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    return AWND_OK;
}

static int _atoi(char *s, int base)
{
    int k = 0;
    int sign = 1;
    if (NULL == s){
        return 0;
    }

    k = 0;
    if (base == 10) {
        if(*s== '-') {
            sign = -1;
            s++;
        }
        while (*s != '\0' && *s >= '0' && *s <= '9') {
            k = 10 * k + (*s - '0');
            s++;
        }
        k *= sign;
    }
    else {
        while (*s != '\0') {
            int v;
            if ( *s >= '0' && *s <= '9')
                v = *s - '0';
            else if ( *s >= 'a' && *s <= 'f')
                v = *s - 'a' + 10;
            else if ( *s >= 'A' && *s <= 'F')
                v = *s - 'A' + 10;
            else {
                return k;
            }
            k = 16 * k + v;
            s++;
        }
    }
    return k;
}

/* get rootap's tpie */
int get_tpie_RTK(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    int ret = AWND_OK;
    int len = 0;
    unsigned char ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

    /* disconnected: get tpie from scan entry */
    if (IEEE80211_TP_IE_IN_SCAN == entry_type) {
        /* TBD: trigger scan and found target AP's TPIE */
        return AWND_NOT_FOUND;
    }

    /* connected: get tpie from rootap info */
    ret = awn_cfg80211_get_tpie(ifname, pAwndNetInfo, &len);
    if (ret)
    {
        AWN_LOG_ERR("%s get rootap tpie fail", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

    if (len > 0)
    {
        AWN_LOG_DEBUG("%s get tpie success", ifname);
        memset(pAwndNetInfo->lan_mac, 0, AWND_MAC_LEN);
        pAwndNetInfo->uplink_mask = 0;
        pAwndNetInfo->uplink_rate = 0;
        pAwndNetInfo->awnd_lanip = ntohl(pAwndNetInfo->awnd_lanip);
        pAwndNetInfo->server_touch_time = ntohl(pAwndNetInfo->server_touch_time);
        pAwndNetInfo->awnd_dns = ntohl(pAwndNetInfo->awnd_dns);
        pAwndNetInfo->uplink_mask = LE_READ_2(&pAwndNetInfo->uplink_mask);
        pAwndNetInfo->uplink_rate = LE_READ_2(&pAwndNetInfo->uplink_rate);
    }
    else
    {
        AWN_LOG_DEBUG("%s no tpie found", ifname);
        ret = AWND_NOT_FOUND;
        goto leave;
    }

leave:
    return ret;
}

int init_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType)
{
    if (NULL == pAwndNetInfo || NULL == pApMac)
    {
        return AWND_ERROR;
    }

    memset(pAwndNetInfo, 0, sizeof(AWND_NET_INFO));

    pAwndNetInfo->id = IEEE80211_ELEMID_VENDOR;
    pAwndNetInfo->len = sizeof(AWND_NET_INFO) -2;
#ifdef CONFIG_MERCUSYS_PRODUCT
    pAwndNetInfo->oui[0] = 0x2f;
    pAwndNetInfo->oui[1] = 0x25;
    pAwndNetInfo->oui[2] = 0xc0;
#else
    /* Init device oui by traversing bind_device_list */
    if (awnd_get_network_oui() == 1)
    {
        pAwndNetInfo->oui[0] = 0x00;
        pAwndNetInfo->oui[1] = 0x31;
        pAwndNetInfo->oui[2] = 0x92;
    }
    else
    {
        pAwndNetInfo->oui[0] = 0x00;
        pAwndNetInfo->oui[1] = 0x1d;
        pAwndNetInfo->oui[2] = 0x0f;
    }
#endif
    AWN_LOG_WARNING("Device's oui will be inited to 0x%x%x%x", pAwndNetInfo->oui[0], pAwndNetInfo->oui[1], pAwndNetInfo->oui[2]);
    pAwndNetInfo->type = 0x01;
    pAwndNetInfo->awnd_net_type = netType;
    pAwndNetInfo->awnd_weight   = weight;
    pAwndNetInfo->awnd_level = 0;
    pAwndNetInfo->awnd_lanip = 0;
    pAwndNetInfo->server_detected = 0;
    pAwndNetInfo->server_touch_time = 0;
    /* set initial dns nonzero:192.168.0.0 */
    pAwndNetInfo->awnd_dns = 0xc0a80000;
    pAwndNetInfo->wait = 0;
    memcpy(pAwndNetInfo->awnd_mac, pApMac, 6);
    memcpy(pAwndNetInfo->awnd_label, pLabel, AWND_LABEL_LEN);

    return AWND_OK;
}

int update_wifi_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType)
{
    u_int8_t ie_buf[IEEE80211_MAX_TP_IE];
    u_int8_t ie_buf_str[IEEE80211_MAX_TP_IE*2];
    INT8 ifname[RTK_IFNAMESIZE] = {0};
    AWND_NET_INFO  *ni = NULL;
    AWND_BAND_TYPE band;
    int ret = AWND_OK;
    int length = 0;
    UINT8* cp = NULL;
    char cmd[256] = {0};
    int i;

    if (NULL == pAwndNetInfo )
    {
        return AWND_ERROR;
    }

    length = (pAwndNetInfo->len + 2 > IEEE80211_MAX_TP_IE) ? IEEE80211_MAX_TP_IE : (pAwndNetInfo->len + 2);

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        /* fill up ifname */
        switch (meshType)
        {
            case AWND_MESH_BACKHUAL:
                snprintf(ifname, sizeof(ifname),  RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);
                break;
            case AWND_MESH_CONFIG:
                snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_config_ap_postfix[band]);
                break;
            default:
                AWN_LOG_ERR("Unknown mesh type:%d\n", meshType);
                break;
        }

        /* fill up configuration */
        memset(ie_buf, 0, sizeof(ie_buf));
        memcpy(ie_buf, pAwndNetInfo, sizeof(AWND_NET_INFO));
        ni = (AWND_NET_INFO*)ie_buf;
        ni->awnd_lanip = htonl(pAwndNetInfo->awnd_lanip);
        ni->server_touch_time = htonl(pAwndNetInfo->server_touch_time);
        ni->awnd_dns = htonl(pAwndNetInfo->awnd_dns);
        cp = (u_int8_t *)(&(ni->uplink_mask));
        LE_WRITE_2(cp, uplinkMask);
        LE_WRITE_2(cp, uplinkRate[band]);
        memcpy(ni->lan_mac, lan_mac, AWND_MAC_LEN);

        /* fill up oui */
        if(meshType == AWND_MESH_CONFIG)
        {    /* config interfaces should be the old oui all the time */
            ni->oui[0] = 0x00;
            ni->oui[1] = 0x1d;
            ni->oui[2] = 0x0f;
        }
        else if(meshType == AWND_MESH_BACKHUAL)
        {    /* FAP/RE's backhual interfaces woule be updated depends on fap/re_oui_update_status */
            if (fap_oui_update_status == OUI_OLD_TO_NEW || re_oui_update_status == OUI_OLD_TO_NEW)
            {
                /* first, delete current oui of backhual interfaces, to prevent two oui exist at the same time*/
                ni->oui[0] = 0x00;
                ni->oui[1] = 0x1d;
                ni->oui[2] = 0x0f;
                if (hostapd_del_tpie(ifname) != 0)
                {
                    AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s", ifname);
                }
                AWN_LOG_ERR("OUI_OLD_TO_NEW : removed %s oui 0x%x%x%x.",ifname,ni->oui[0],ni->oui[1],ni->oui[2]);

                /* second, set dst oui*/
                ni->oui[0] = 0x00;
                ni->oui[1] = 0x31;
                ni->oui[2] = 0x92;
            }
            else if(fap_oui_update_status == OUI_NEW_TO_OLD || re_oui_update_status == OUI_NEW_TO_OLD)
            {
                ni->oui[0] = 0x00;
                ni->oui[1] = 0x31;
                ni->oui[2] = 0x92;
                if (hostapd_del_tpie(ifname) != 0)
                {
                    AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s", ifname);
                }
                AWN_LOG_ERR("OUI_NEW_TO_OLD : removed %s oui 0x%x%x%x.",ifname,ni->oui[0],ni->oui[1],ni->oui[2]);

                ni->oui[0] = 0x00;
                ni->oui[1] = 0x1d;
                ni->oui[2] = 0x0f;
            }
            else
            {
                /* for other situation, just copy pAwndNetInfo->oui */
                memcpy(ni->oui, pAwndNetInfo->oui, VENDORIE_OUI_LEN);
                AWN_LOG_ERR("OUI_KEEP_STATE : copyed %s oui 0x%x%x%x.", ifname,ni->oui[0],ni->oui[1],ni->oui[2]);
            }
        }

        memset(ie_buf_str, 0, sizeof(ie_buf_str));
        for (i = 0; i < sizeof(AWND_NET_INFO); i++)
        {
            sprintf((u_int8_t*)(ie_buf_str + strlen(ie_buf_str)), "%02x", ie_buf[i]);
        }

        ret = hostapd_update_tpie(ifname, ie_buf_str);
    }

    AWN_LOG_INFO("Update tpie ret:%d", ret);

	/* update pAwndNetInfo->oui only after chang oui success. */
	if ((fap_oui_update_status == OUI_OLD_TO_NEW || re_oui_update_status == OUI_OLD_TO_NEW ) && ret == AWND_OK )
	{
		pAwndNetInfo->oui[0] = 0x00;
		pAwndNetInfo->oui[1] = 0x31;
		pAwndNetInfo->oui[2] = 0x92;
		/* reset the flag oui_update_status after updated.*/
		if(AWND_MODE_RE == g_awnd.workMode)
		{
			awnd_set_oui_update_status_fap(OUI_KEEP_STATE);
		}
		else if((AWND_MODE_FAP == g_awnd.workMode) || (AWND_MODE_HAP == g_awnd.workMode))
		{
			awnd_set_oui_update_status_re(OUI_KEEP_STATE);
		}
		AWN_LOG_CRIT("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
	}
	else if((fap_oui_update_status == OUI_NEW_TO_OLD || re_oui_update_status == OUI_NEW_TO_OLD) && ret == AWND_OK )
	{
		pAwndNetInfo->oui[0] = 0x00;
		pAwndNetInfo->oui[1] = 0x1d;
		pAwndNetInfo->oui[2] = 0x0f;
		if(AWND_MODE_RE == g_awnd.workMode)
		{
			awnd_set_oui_update_status_fap(OUI_KEEP_STATE);
		}
		else if((AWND_MODE_FAP == g_awnd.workMode) || (AWND_MODE_HAP == g_awnd.workMode))
		{
			awnd_set_oui_update_status_re(OUI_KEEP_STATE);
		}
		AWN_LOG_CRIT("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
	}

    AWN_LOG_INFO("awnd_update_wifi_tpie awnd_net_type:%-3d,awnd_level:%-2d, wait:%d, lanip:%x, dns:%x, \n \
                server_detected:%d, server_touch_time:%d awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X len=%d",
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->wait, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
            pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5], pAwndNetInfo->len);
    AWN_LOG_INFO("label: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X, uplinkMask:%x, uplinkRate:%u/%u/%u", pAwndNetInfo->awnd_label[0],
        pAwndNetInfo->awnd_label[1],pAwndNetInfo->awnd_label[2],pAwndNetInfo->awnd_label[3],pAwndNetInfo->awnd_label[4],
        pAwndNetInfo->awnd_label[5],pAwndNetInfo->awnd_label[6],pAwndNetInfo->awnd_label[7],pAwndNetInfo->awnd_label[8],
        pAwndNetInfo->awnd_label[9],pAwndNetInfo->awnd_label[10],pAwndNetInfo->awnd_label[11],pAwndNetInfo->awnd_label[12],
        pAwndNetInfo->awnd_label[13],pAwndNetInfo->awnd_label[14],pAwndNetInfo->awnd_label[15], uplinkMask,
        uplinkRate[AWND_BAND_2G],uplinkRate[AWND_BAND_5G], uplinkRate[AWND_BAND_5G2]);

    return ret;
}

int flush_scan_table_single_band_RTK(AWND_BAND_TYPE band, BOOL force)
{
    /*for RTK, the scan table will be flush at begin scanning at driver*/
    return AWND_OK;
}

int flush_scan_table_RTK(void)
{
    /*for RTK, the scan table will be flush at begin scanning at driver*/
    return AWND_OK;
}

static int _start_scan_single_band(AWND_BAND_TYPE band)
{
	int ret = AWND_OK;
	int len = 0;
	unsigned char ifname[IFNAMSIZ] = {'\0'};
	TP_SCAN_PARAM params;

	snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);

	memset(&params, 0, sizeof(params));
	params.active = FALSE; /* not used */
	params.num_channels = 0; /* not specify scan channel, iter all channels */
	params.ssid_len = 0; /* not specify scan SSID */

	ret = awn_cfg80211_scan(ifname, &params);

	return ret ? AWND_ERROR : AWND_OK;
}

int do_scan_RTK(UINT8 scanBandMask)
{
	 AWND_BAND_TYPE bi;

	for (bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
	{
		if (scanBandMask & (1 << bi)) {
			_start_scan_single_band(bi);
		}
	}

	_stable_sleep(5);
	exit(0);
}

static int _fast_scan_single_channel(AWND_BAND_TYPE band)
{
	int ret = AWND_OK;
	int channel = 0;
	unsigned char ifname[IFNAMSIZ] = {'\0'};
	TP_SCAN_PARAM params;

	snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);

	ret = _get_channel(ifname, &channel);
	if (ret == AWND_ERROR)
	{
		AWN_LOG_ERR("get working channel fail\n");
		return ret;
	}

	memset(&params, 0, sizeof(params));
	params.active = FALSE; /* not used */
	params.num_channels = 1; /* scan on current channel */
	params.channels[0] = channel;
	params.ssid_len = 0; /* not specify scan SSID */

	ret = awn_cfg80211_scan(ifname, &params);

	return ret ? AWND_ERROR : AWND_OK;
}

int do_scan_fast_RTK(UINT8 scanBandMask)
{
	AWND_BAND_TYPE bi;

	for (bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
	{
		if (scanBandMask & (1 << bi)) {
			_fast_scan_single_channel(bi);
		}
	}

	exit(0);
}

int get_scan_result_RTK(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
		char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
	int ret = AWND_OK;
	unsigned char ifname[IFNAMSIZ] = {'\0'};
	unsigned char cmdline[CMDLINE_LENGTH] = {'\0'};
	unsigned char ssid[AWND_MAX_SSID_LEN] = {'\0'};
	int nss = 0;
	int phyMode = 0;
	int chwidth = 0;
	RTK_SCAN_RESULT scan_data;
	int scan_data_len = 0;
	int entry_cnt = 0;
	RTK_SCAN_ENTRY *se = NULL;
	int i = 0;
	int idx = 0;
	unsigned char* vp = NULL;
	int ielen = 0;

	AWND_AP_ENTRY* pCurApEntry = NULL;

	if (NULL == pAwndScanResult)
	{
		AWN_LOG_ERR("pAwndScanResult is null");
		return AWND_ERROR;
	}

	if (AWND_VAP_AP == vap_type)
		snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_postfix[band]);
	else
		snprintf(ifname, sizeof(ifname), RTK_AP_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

	if (!isFast)
	{
		/* save scan result(BSSID SSID mode channel rate) */
		snprintf(cmdline, sizeof(cmdline),"iw dev %s scan dump -u > "WIFI_SCAN_RESULT_FILE" &",
			ifname, band_suffix[band]);
		_wifi_exec_cmd(cmdline);
	}

	if (AWND_OK != get_phy_RTK(band, &nss, &phyMode, &chwidth))
	{
		AWN_LOG_ERR("get_phy_RTK fail, quit awnd_get_scan_result");
		return AWND_ERROR;
	}

	memset(&scan_data, 0, sizeof(scan_data));
	ret = awn_cfg80211_scan_result(ifname, &scan_data, &scan_data_len);
	if (ret)
	{
		AWN_LOG_ERR("get scan result failed ret=%d", ret);
			return AWND_ERROR;
	}

	idx = 0;
	pAwndScanResult->iApNum = 0;
	for (i = 0; (i < scan_data.count) && (idx < AWND_MAX_GROUP_MEMBER); i++)
	{
		se = &scan_data.scan_entry[i];
		pCurApEntry = &(pAwndScanResult->tApEntry[idx]);

		memset(pCurApEntry, 0, sizeof(AWND_AP_ENTRY));

		if (se->ssidLen > 0)
		{
			_copy_essid(ssid, sizeof(ssid), se->ssid, se->ssidLen);
			memcpy(pCurApEntry->ssid, ssid, strlen(ssid));
			pCurApEntry->ssid[se->ssidLen] = 0;
		}

		if (se->bssid != NULL) {
			memcpy(pCurApEntry->bssid, se->bssid, AWND_MAC_LEN);
		}

		pCurApEntry->rssi  = se->rssi;
		pCurApEntry->freq  = se->freq;
		pCurApEntry->index = idx + 1;
		pCurApEntry->channel = se->channel;

		vp = (unsigned char *)&(se->netInfo.netInfo);
		ielen = se->netInfo.netInfo.len;
		if (ielen > 0)
		{
			if (se->netInfo.netInfo.id == IEEE80211_ELEMID_VENDOR && istpoui(vp))
			{
				memcpy(&(pCurApEntry->netInfo), vp, ((2+vp[1]) < sizeof(AWND_NET_INFO))? (2+vp[1]) : sizeof(AWND_NET_INFO));
			}
			else
			{
				continue;
			}
		}

		if (0 == memcmp(pAwndScanResult->tApEntry[idx].netInfo.awnd_label, match_label, AWND_LABEL_LEN))
		{
			pAwndScanResult->tApEntry[idx].isPreconf = 0;
		}
		else if (preconf_label && 0 == memcmp(pAwndScanResult->tApEntry[idx].netInfo.awnd_label, preconf_label, AWND_LABEL_LEN))
		{
			pAwndScanResult->tApEntry[idx].isPreconf = 1;
		}
		else
		{
			continue;
		}

		/* Transfer from network byte order to host byte order */
		pCurApEntry->netInfo.awnd_lanip = ntohl(pCurApEntry->netInfo.awnd_lanip);
		pCurApEntry->netInfo.server_touch_time = ntohl(pCurApEntry->netInfo.server_touch_time);
		pCurApEntry->netInfo.awnd_dns = ntohl(pCurApEntry->netInfo.awnd_dns);
		pCurApEntry->netInfo.uplink_mask = LE_READ_2(&pCurApEntry->netInfo.uplink_mask);
		pCurApEntry->netInfo.uplink_rate = LE_READ_2(&pCurApEntry->netInfo.uplink_rate);

		/* cp individual's unique params to AP ENTRY, and leave common params in AWND_NET_INFO */
		pCurApEntry->uplinkMask = pCurApEntry->netInfo.uplink_mask;
		pCurApEntry->netInfo.uplink_mask = 0;
		if ((!(pCurApEntry->uplinkRate) || pCurApEntry->netInfo.awnd_level >= 2) && pCurApEntry->netInfo.uplink_rate)
		{
			pCurApEntry->uplinkRate = pCurApEntry->netInfo.uplink_rate;
		}
		pCurApEntry->netInfo.uplink_rate = 0;
		memcpy(pCurApEntry->lan_mac, pCurApEntry->netInfo.lan_mac, AWND_MAC_LEN);
		memset(pCurApEntry->netInfo.lan_mac, 0, AWND_MAC_LEN);

		if (!(pCurApEntry->netInfo.awnd_level) || !(pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI))
			pCurApEntry->uplinkRate = 0;

		if ((pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI) && ((pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_2G) ||
			(pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_5G) || (pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_5G2) ||
			(pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_6G)))
		{	/* if current band disconnect with rootap, uplinkRate set to zero */
			if (!(pCurApEntry->uplinkMask & (1 << (8 + band))))
			{
				AWN_LOG_INFO("bssid:%02X:%02X:%02X:%02X:%02X:%02X %-6s disconnect with rootap, uplinkRate(%d) set to 0",
				pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
				pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],
				ifname, pCurApEntry->uplinkRate);

				pCurApEntry->uplinkRate = 0;
			}
		}
		pCurApEntry->uplinkMask &= 0x00FF;

		pCurApEntry->pathRate
					 = awnd_get_rate_estimate(pCurApEntry->netInfo.awnd_level, l_awnd_config.scaling_factor,
						pCurApEntry->uplinkMask, pCurApEntry->uplinkRate,
						pCurApEntry->rssi, nss, phyMode, chwidth);

		AWN_LOG_ERR("%-6s idx:%d, ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%-4d, channel:%-3d, uplinkMask:%-5u, uplinkrate:%-5u, pathRate:%-5u",
			ifname,idx, pCurApEntry->ssid, pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
			pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],pCurApEntry->rssi, pCurApEntry->channel,
			pCurApEntry->uplinkMask, pCurApEntry->uplinkRate,  pCurApEntry->pathRate);

		AWN_LOG_ERR("awnd_net_type:%-3d,awnd_level:%-2d, awnd_weight:%d, wait:%d, lanip:%x, dns:%x \
			server_detected:%d, server_touch_time:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
			pCurApEntry->netInfo.awnd_net_type, pCurApEntry->netInfo.awnd_level,
			pCurApEntry->netInfo.awnd_weight, pCurApEntry->netInfo.wait,
			pCurApEntry->netInfo.awnd_lanip, pCurApEntry->netInfo.awnd_dns,
			pCurApEntry->netInfo.server_detected, pCurApEntry->netInfo.server_touch_time,
			pCurApEntry->netInfo.awnd_mac[0],pCurApEntry->netInfo.awnd_mac[1],
			pCurApEntry->netInfo.awnd_mac[2],pCurApEntry->netInfo.awnd_mac[3],
			pCurApEntry->netInfo.awnd_mac[4],pCurApEntry->netInfo.awnd_mac[5]);

		pAwndScanResult->iApNum++;
		++idx;
	} /* End of for*/

	return AWND_OK;
}

int set_channel_RTK(AWND_BAND_TYPE band, UINT8 channel)
{
#if 0
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, sizeof(cmdline), "iwpriv "RTK_AP_IFNAME_FMT" set Channel=%d & ",
            RTK_ifname_ap_prefix_str[band], RTK_backhaul_ap_ifindex[band], channel);    

    return _wifi_exec_cmd(cmdline);
#endif
    return AWND_OK;
}

int get_sta_iface_in_bridge_RTK(AWND_BAND_TYPE band, UINT8* ifname)
{
    UINT8 vapname[RTK_IFNAMESIZE] = {0};

    snprintf(vapname, sizeof(vapname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

    snprintf(ifname, IFNAMSIZ, "%s", vapname);

    return AWND_OK;
}

int disconn_sta_pre_RTK(AWND_BAND_TYPE band, UINT* pBandMask)
{
    memset(&g_awnd.rootAp[band], 0, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_DISCONNECT;
    
    *pBandMask |= (1 << band);
     
    return AWND_OK;
}

int disconn_all_sta_pre_RTK(UINT* pBandMask)
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        awnd_disconn_sta_pre(band, pBandMask);
}

int disconn_sta_post_RTK(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    AWN_LOG_DEBUG("RECORD DISCONN");
   
    /*if (awnd_get_wds_state(band))*/
    {
        //snprintf(cmdline, sizeof(cmdline), "wpa_cli -g /var/run/wpa_supplicant/global interface_remove "RTK_STA_IFNAME_FMT" &",
        //  RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

        /*
            wpa_cli -i wlan1-vxd enable_networ disable_network <network_id>,
            param <network_id> can get by
                "wpa_cli -i wlan1-vxd list_networks" and match bssid,
            but we only have one fron connection, so we just use 0
        */
        snprintf(cmdline, sizeof(cmdline), "wpa_cli -i "RTK_STA_IFNAME_FMT" disable_network 0", 
          RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
        _wifi_exec_cmd(cmdline);
    }

    awnd_write_rt_info(band, FALSE, NULL, FALSE);  
    return AWND_OK;
}

int disconn_sta_RTK(AWND_BAND_TYPE band)
{
    UINT bandMask;

    awnd_disconn_sta_pre(band, &bandMask);

    return awnd_disconn_sta_post(band);
}

int disconn_all_sta_RTK(void)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        awnd_disconn_sta(band);

    return AWND_OK;
}

int reconn_sta_pre_RTK(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp)
{
    memcpy(&g_awnd.rootAp[band], pRootAp, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_CONNECTING;
     
    return AWND_OK;
}

int reconn_sta_post_RTK(AWND_BAND_TYPE band, BOOL check_wpa_status)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    awnd_config_set_stacfg_enb(1, band);

    /*
    snprintf(cmdline, sizeof(cmdline), 
        "wpa_cli -g /var/run/wpa_supplicant/global interface_add  "RTK_STA_IFNAME_FMT" /var/run/wpa_supplicant-"RTK_STA_IFNAME_FMT".conf nl80211 /var/run/wpa_supplicant-"RTK_STA_IFNAME_FMT" br-lan",
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band],
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band],
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);*/
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -i "RTK_STA_IFNAME_FMT" enable_network 0", 
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);

    _wifi_exec_cmd(cmdline);

    return AWND_OK;
}

int reset_sta_connection_RTK(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    //snprintf(cmdline, sizeof(cmdline), "wpa_cli -g /var/run/wpa_supplicant/global interface_remove "RTK_STA_IFNAME_FMT" &",
    //    RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -i "RTK_STA_IFNAME_FMT" disable_network 0",
      RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);
    _wifi_exec_cmd(cmdline);

    memset(cmdline, 0, sizeof(cmdline));
    /*snprintf(cmdline, sizeof(cmdline),
        "wpa_cli -g /var/run/wpa_supplicant/global interface_add  "RTK_STA_IFNAME_FMT" /var/run/wpa_supplicant-"RTK_STA_IFNAME_FMT".conf nl80211 /var/run/wpa_supplicant-"RTK_STA_IFNAME_FMT" br-lan",
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band],
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band],
        RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);*/
    snprintf(cmdline, sizeof(cmdline), "sleep 1 && wpa_cli -i "RTK_STA_IFNAME_FMT" enable_network 0 &", 
          RTK_ifname_sta_prefix_str[band], RTK_ifname_sta_post_str[band]);		
    _wifi_exec_cmd(cmdline);

    return AWND_OK;
}

int ubus_send_sta_to_tfs(char *dev_list)
{
    static struct blob_buf blob;
    char *str = NULL;
    char cmd[256];

    blob_buf_init(&blob, 0);

    blobmsg_add_string(&blob, "sta_dev", dev_list);
    str = blobmsg_format_json(blob.head, true);

    if (!str)
    {
        AWN_LOG_DEBUG("format json failed.\n");
        return AWND_ERROR;
    }

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "ubus call tfstats save_sta_dev '%s'", str);
    AWN_LOG_WARNING("cmd:%s", str);
    _wifi_exec_cmd(cmd);

    if (str)
        free(str);
    
    return AWND_OK;
}

#define RTK_MAX_WIRELESS_BACKHUAL_NUM (4)
int set_backhaul_sta_dev_RTK(UINT32 link_state, unsigned int eth_link_state)
{
    char dev_list[128];
    char cmd[128];
    FILE *fp;
    int index = 0;
    unsigned int flag = 0;
    int ret = 0;
    int dev_num = 0;
    char working_sta_name[6][RTK_IFNAMESIZE];
    int fd;
    int can_send_to_nat = 1;
    UINT32 all_link_state;

#if (ETH_PORT_NUM == 3)
    char sta_name[7][RTK_IFNAMESIZE] = {"", "", "","", "eth1", "eth2", "eth3"};
#else
    char sta_name[6][RTK_IFNAMESIZE] = {"", "", "","", "eth1", "eth2"};
#endif

    char tmp_ifname[RTK_IFNAMESIZE] = {0};
    
    for (index = 0; index < 3; index++)
    {
        snprintf(tmp_ifname, sizeof(tmp_ifname), RTK_STA_IFNAME_FMT, RTK_ifname_sta_prefix_str[index], RTK_ifname_sta_post_str[index]);
        strncpy(sta_name[index], tmp_ifname, RTK_IFNAMESIZE);
    }

    all_link_state = link_state | (eth_link_state << RTK_MAX_WIRELESS_BACKHUAL_NUM);

    AWN_LOG_WARNING("link_state is 0x%x, eth_link_state is 0x%x all_link_state is 0x%x", link_state, eth_link_state, all_link_state);

    memset(dev_list, 0, sizeof(dev_list));
#if (ETH_PORT_NUM == 3)
    for (index = 0; index < 7; index ++)
#else
    for (index = 0; index < 6; index ++)
#endif
    {
        flag = (0x1) << (index);
        if (all_link_state & flag)
        {
            /* get name */
            if (dev_num)
                awnd_strlcat(dev_list, ":", sizeof(dev_list));

            awnd_strlcat(dev_list, sta_name[index], sizeof(dev_list));
            dev_num ++;

        }
    }
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "echo '%s' > %s", dev_list, STATS_BACKHAUL_STA_DEV_NAME);
    AWN_LOG_WARNING("cmd:%s", cmd);

    /* get sta traffic directly from wifi/switch driver, no need to get it in PS. */
    /*if ((fp = popen(cmd, "r")) == NULL)
    {
        AWN_LOG_WARNING("popen error:%s", strerror(errno));
        return AWND_ERROR;
    }

    if ((ret = pclose(fp)) == -1)
    {
        AWN_LOG_WARNING("pclose error:%s", strerror(errno));
        return AWND_ERROR;
    }*/

    return ubus_send_sta_to_tfs(dev_list);
}
#undef RETRY_HW_NAT_TIMES

void do_band_restart_RTK(UINT8 BandMask)
{
    return;
}

int get_wifi_bw_RTK(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw)
{
    return AWND_OK;
}

void set_wifi_bw_RTK(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw)
{
    return;
}

int bss_status_check_RTK()
{
    return AWND_OK;
}

AWN_PLATFORM_OPS awn_platform_RTK = {
    .get_default_mesh_channel = get_default_mesh_channel_RTK,
    .get_sta_channel = get_sta_channel_RTK,
    .get_backhaul_ap_channel = get_backhaul_ap_channel_RTK,

    .get_phy = get_phy_RTK,
    .get_wds_state = get_wds_state_RTK,
    .get_rootap_phyRate = get_rootap_phyRate_RTK,
    .get_rootap_rssi = get_rootap_rssi_RTK,
    .get_rootap_info = get_rootap_info_RTK,
    .get_rootap_tpie = get_rootap_tpie_RTK,
    .get_tpie = get_tpie_RTK,


    .init_tpie = init_tpie_RTK,
    .update_wifi_tpie = update_wifi_tpie_RTK,

    .flush_scan_table_single_band = flush_scan_table_single_band_RTK,
    .flush_scan_table = flush_scan_table_RTK,
    .do_scan = do_scan_RTK,
    .do_scan_fast = do_scan_fast_RTK,
    .get_scan_result = get_scan_result_RTK,

    .set_channel = set_channel_RTK,
    .get_sta_iface_in_bridge = get_sta_iface_in_bridge_RTK,

    .disconn_sta_pre = disconn_sta_pre_RTK,
    .disconn_all_sta_pre = disconn_all_sta_pre_RTK,
    .disconn_sta_post = disconn_sta_post_RTK,
    .disconn_sta = disconn_sta_RTK,
    .disconn_all_sta = disconn_all_sta_RTK,
    .reconn_sta_pre = reconn_sta_pre_RTK,
    .reconn_sta_post = reconn_sta_post_RTK,
    .reset_sta_connection = reset_sta_connection_RTK,

    .set_backhaul_sta_dev = set_backhaul_sta_dev_RTK,
    .do_band_restart = do_band_restart_RTK,

    .get_wifi_bw = get_wifi_bw_RTK,
    .set_wifi_bw = set_wifi_bw_RTK,
    .bss_status_check = bss_status_check_RTK,
};

AWN_PLATFORM_OPS *awn_platform_ops = &awn_platform_RTK;

