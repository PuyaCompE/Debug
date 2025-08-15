/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_mtk.c
Version     : v0.1 
Description : awn wifi handler for mtk

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

#include "tp_linux.h"

#include "../auto_wifi_net.h"
#include "../awn_log.h"
#include "../awn_wifi_handler_api.h"

#include "awn_wifi_handler_mtk.h"
#include "awn_cfg80211_mtk.h"

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

#define LE_READ_2(p)                            \
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

#define LIST_STATION_ALLOC_SIZE 24*1024
#define CMDLINE_LENGTH          256

#define RSSI_WEIGHT 0.8
/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/



/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/

static char *band_suffix[AWND_BAND_MAX] = {"2g", "5g", "5g_2"};
static char *real_band_suffix[AWND_REAL_BAND_MAX] = {"2g", "5g", "5g_2", "6g", "6g_2"};

extern AWND_GLOBAL g_awnd;
extern AWND_CONFIG l_awnd_config;
extern int fap_oui_update_status;
extern int re_oui_update_status;
extern UINT8 l_mac_ai_roaming_target[AWND_MAC_LEN];
extern BOOL roaming_running;
/***************************************************************************/
/*                        LOCAL FUNCTIONS                                  */
/***************************************************************************/
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

static int _hexStr2Bytes (const char *str, unsigned char *buf, int buf_len)
{
    int i, j, str_len;
    unsigned char c;

    if (NULL == str || NULL == buf)
    {
        return -1;
    }

    str_len = strlen(str);

    if (buf_len < str_len / 2)
    {
        return -1;
    }

    for (i = 0, j = 0; i < buf_len; i++)
    {
        if (j >= str_len)
        {
            break;
        }

        if (*str >= '0' && *str <= '9')
        {
            c  = (unsigned char) (*str++ - '0');
        }
        else if (*str >= 'a' && *str <= 'f')
        {
            c  = (unsigned char) (*str++ - 'a') + 10;
        }
        else if (*str >= 'A' && *str <= 'F')
        {
            c  = (unsigned char) (*str++ - 'A') + 10;
        }
        else
        {
            continue;
        }

        c <<= 4;

        if (*str >= '0' && *str <= '9')
        {
            c |= (unsigned char) (*str++ - '0');
        }
        else if (*str >= 'a' && *str <= 'f')
        {
            c |= (unsigned char) (*str++ - 'a') + 10;
        }
        else
        {
            c |= (unsigned char) (*str++ - 'A') + 10;
        }

        buf[i] = c;
        j += 2;
    }

    return i;
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
    AWN_LOG_NOTICE("wifi cmd(%s)", buf);

    return AWND_OK;
}

static int
getsocket(void)
{
    static int s = -1;

    if (s < 0) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0)
        {
            AWN_LOG_CRIT("socket(SOCK_DRAGM)");
        }
    }
    return s;
}

static int
getscansocket(void)
{
    static int s_scan = -1;

    if (s_scan < 0) {
        s_scan = socket(AF_INET, SOCK_DGRAM, 0);
        if (s_scan < 0)
        {
            AWN_LOG_CRIT("socket(SOCK_DRAGM)");
        }
    }
    return s_scan;
}

static int _get_channel(INT8 *ifname, int *channel)
{
    struct iwreq iwr;
    int sock = -1;
    int res = 0;
    // i, exp = 6;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        AWN_LOG_ERR("socket fail");
        return AWND_ERROR;
    }

    memset(&iwr, 0, sizeof(struct iwreq));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    if (ioctl(sock, SIOCGIWFREQ, &iwr) < 0) {
        AWN_LOG_INFO("unable to get channel of vap(%s)", ifname);
        close(sock);
        return AWND_ERROR;
    }
	else if(iwr.u.freq.m == 0)
	{
        AWN_LOG_ERR("get invalid channel 0 of vap(%s)", ifname);
        close(sock);
        return AWND_ERROR;
	}

//    exp -= iwr.u.freq.e;
    res = iwr.u.freq.m;
    *channel = res;
    //: Need Default Channe?

    AWN_LOG_DEBUG("iface:%s, channel:%d\n", ifname, *channel);

    close(sock);
    return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
static int proxy_l2uf_single_interface(const char *ifname)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    snprintf(cmdline, sizeof(cmdline), "iwpriv %s set SendProxyL2UF=", ifname);
    _wifi_exec_cmd(cmdline);
    return AWND_OK;
}
#endif

/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/


int get_default_mesh_channel_mtk(AWND_BAND_TYPE band, int *channel)
{
    /* apIfnames = backhaul ap name, use backhaul ap channel as default channel */
    return _get_channel(l_awnd_config.apIfnames[band], channel);
}

int check_block_chan_list_mtk(AWND_BAND_TYPE band, int *channel)
{
    return AWND_ERROR;
}

int get_sta_channel_mtk(AWND_BAND_TYPE band, int *channel)
{
    return _get_channel(l_awnd_config.staIfnames[band], channel);
}

int get_backhaul_ap_channel_mtk(AWND_BAND_TYPE band, int *channel)
{
    /* apIfnames = backhaul ap, the variable is defined in auto_wifi_net.h */
    return _get_channel(l_awnd_config.apIfnames[band], channel);
}

int get_phy_mtk(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth)
{
#ifdef MTK_NETLINK_SUPPORT
    int ret = AWND_OK;
    TP_PHYCAP_INFO phy_info;
    int len = 0;
    int chan = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    if (band < AWND_BAND_2G || band >= AWND_BAND_MAX ||
        nss == NULL || phyMode == NULL || chwidth == NULL)
    {
        return AWND_ERROR;
    }

    memset(&phy_info, 0, sizeof(phy_info));
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
#else
    struct iwreq iwr; 
    struct ieee80211_wlanconfig config;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = IEEE80211_WLANCONFIG_PHY_GET;
    
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length  = sizeof(config);
#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
    iwr.u.data.flags = IEEE80211_IOCTL_CONFIG_GENERIC;
    if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0)
#endif
    {
        AWN_LOG_ERR("%s ioctl socket failed: IEEE80211_IOCTL_CONFIG_GENERIC:%x, errno %d", ifname, IEEE80211_IOCTL_CONFIG_GENERIC, errno);
        return AWND_ERROR;
    }

    
    *nss = config.data.phy.nss;
    *phyMode = config.data.phy.phyMode;
    *chwidth = config.data.phy.chwidth;
    ret = AWND_OK;
#endif
    AWN_LOG_DEBUG("[awnd_get_phy]%s nss:%d, phyMode:%d, chwidth:%d\n", ifname, *nss, *phyMode, *chwidth);

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
static int __get_rootap_general_info_mtk(AWND_BAND_TYPE band, UINT16 *pTxRate, UINT16 *pRxRate, int *pStatus, int *pRssi)
{
    int ret = AWND_OK;
    WLAN_CONN_INFO connInfo;
    int len = 0;
	int rssi;

    INT8 ifname[MTK_IFNAMESIZE] = {0};
	strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));
    if (pTxRate == NULL || pRxRate== NULL || pStatus == NULL || pRssi == NULL)
    {
        AWN_LOG_ERR("%s get rootap info fail", ifname);
        return AWND_ERROR;
    }

    memset(&connInfo, 0, sizeof(connInfo));
	AWN_LOG_DEBUG("%s get rootap info ", ifname);

    ret = awn_cfg80211_get_sta_info(ifname, &connInfo, &len);
    if (ret)
    {
        ret = AWND_ERROR;
    }
    else
    {
        *pTxRate = connInfo.txrate;
        *pRxRate = connInfo.rxrate;
        *pStatus = connInfo.connected & MTK_STAINFO_WIFI_ASOC_STATE;
		if (!connInfo.connected)
		{
			/* not connected */
			AWN_LOG_DEBUG("%s not connect", ifname);
			return AWND_ERROR;
		}
		else
		{
			/* connected. we can get rssi here */
			if (0 == connInfo.rssi[0])
			{
				connInfo.rssi[0] = -100;
			}
			if (0 == connInfo.rssi[1])
			{
				connInfo.rssi[1] = -100;
			}
			if (0 == connInfo.rssi[2])
			{
				connInfo.rssi[2] = -100;
			}
			if (0 == connInfo.rssi[3])
			{
				connInfo.rssi[3] = -100;
			}

			/* get the largest */
			rssi = connInfo.rssi[0] > connInfo.rssi[1] ? connInfo.rssi[0] : connInfo.rssi[1];
			rssi = rssi  > connInfo.rssi[2] ? rssi  : connInfo.rssi[2];
			rssi = rssi  > connInfo.rssi[3] ? rssi  : connInfo.rssi[3];

			AWN_LOG_DEBUG("%s rssi = %d", ifname, rssi);
		}

        if (rssi < TP_RSSI_RANGE_LOW)
        {
            *pRssi = 0;
        }
        else if (rssi > TP_RSSI_RANGE_HIGH)
        {
            *pRssi = 95;
        }
		else
		{
			*pRssi = rssi + 95;
		}

        ret = AWND_OK;
    }

    return ret;
}

static int __get_channal_info_mtk(AWND_BAND_TYPE band, INT32 *chan_util, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw)
{
    int ret = AWND_OK;
    CHAN_INFO chaninfo;
    int len = 0;

    INT8 ifname[MTK_IFNAMESIZE] = {0};
	strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    if (chan_util == NULL || intf== NULL || cur_chan == NULL || bw == NULL)
    {
        AWN_LOG_ERR("%s get channel info fail", ifname);
        return AWND_ERROR;
    }

    memset(&chaninfo, 0, sizeof(CHAN_INFO));
	AWN_LOG_DEBUG("%s get channel info ", ifname);

	ret = awn_cfg80211_get_channel_info(ifname, &chaninfo, &len);
	
	*chan_util = chaninfo.chan_util;
	*intf = chaninfo.intf;
	*cur_chan = chaninfo.cur_chan;
	*bw = chaninfo.bw;

    if (ret)
    {
        ret = AWND_ERROR;
    }
	else
	{
		ret = AWND_OK;
	}

	return ret;
}

int get_wds_state_mtk(AWND_BAND_TYPE band, int *up
#if GET_AP_RSSI
                    , int *rssi
#endif
                        )
{
#ifdef MTK_NETLINK_SUPPORT
    UINT16 txrate = 0;
    UINT16 rxrate = 0;
    int rssitmp = 0;
    int ret = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    __get_rootap_general_info_mtk(band, &txrate, &rxrate, &ret, &rssitmp);
    _get_vap_status(ifname, up);
#if GET_AP_RSSI
    *rssi = rssitmp;
    AWN_LOG_INFO("[awnd_get_conn_state]%s wds state:%d, rssi = %d, ret = %d\n", ifname, *up, *rssi, ret);
#endif

#else
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    struct iwreq iwr = {0};
    struct ifreq ifr = {0};
    struct ieee80211_wlanconfig config;
    int ret = 0;

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    *up = 0;

    /*sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return AWND_STATUS_CONNECTING;
    }*/

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(getsocket(),SIOCGIFFLAGS,&ifr)< 0)
    {
        AWN_LOG_DEBUG("%s ioctl socket failed: SIOCGIFFLAGS", ifname);    
        return 0;
    }
    else if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING)))
    {
        return 0;
    }

    *up = 1;

    /*To do:get connect status through IEEE80211_WLANCONFIG_STA_KEYSTATE in PSK ????*/
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = IEEE80211_WLANCONFIG_WDS_STATE_GET;
    
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length  = sizeof(config);
#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
    iwr.u.data.flags = IEEE80211_IOCTL_CONFIG_GENERIC;
    if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
    if (ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0)
#endif
    {
        AWN_LOG_ERR("ioctl socket failed: IEEE80211_IOCTL_CONFIG_GENERIC");    
        return 0;
    }

#if GET_AP_RSSI
    ret = (config.data.connStaus.wds_state == IEEE80211_S_RUN ? 1 : 0);
    *rssi = config.data.connStaus.rssi;
    AWN_LOG_INFO("[awnd_get_conn_state]%s wds state:%d rssi:%d\n", ifname, config.data.connStaus.wds_state, *rssi);
#else
    ret = (config.data.wds_state == IEEE80211_S_RUN ? 1 : 0);
    AWN_LOG_INFO("[awnd_get_conn_state]%s wds state:%d\n", ifname, config.data.connStaus.wds_state);
#endif
#endif
    return ret;
}

/* get rootap's txrate/rxrate */
int get_rootap_phyRate_mtk(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate)
{
#ifdef MTK_NETLINK_SUPPORT
    int linkstatus = 0;
    int rssi = 0;
    __get_rootap_general_info_mtk(band, txrate, rxrate, &linkstatus, &rssi);

#else
    struct iwreq iwr;
    UINT8 *cp = NULL;
    int i = 0;
    int len = 0;
    int ielen = 0;
    /*UINT32 txrate = 0, rxrate = 0; maxrate = 0;*/
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    INT8 sta_buf[MTK_LIST_STATION_ALLOC_SIZE] = {0};

    *txrate = 0;
    *rxrate = 0;

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void*)sta_buf;
    iwr.u.data.length = MTK_LIST_STATION_ALLOC_SIZE;

#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
    iwr.u.data.flags = IEEE80211_IOCTL_STA_INFO;
	if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
	if (ioctl(getsocket(), IEEE80211_IOCTL_STA_INFO, &iwr) < 0)
#endif
	{
        AWN_LOG_CRIT("%s ioctl socket failed: IEEE80211_IOCTL_STA_INFO", ifname);        
        return AWND_ERROR;
    }

    len = iwr.u.data.length;

    if (len < sizeof(struct ieee80211req_sta_info)){
        AWN_LOG_ERR("sta info len is wrong len=%d sizeof ieee80211req_sta_info:%d",
            len, sizeof(struct ieee80211req_sta_info));
        return AWND_ERROR;
    }

    cp = (UINT8*)sta_buf;

    do {
        struct ieee80211req_sta_info *si;
        uint8_t *vp;

        si = (struct ieee80211req_sta_info*)cp;
        vp = (u_int8_t*)(si + 1);


        if(si->isi_txratekbps == 0)
           *txrate = (si->isi_rates[si->isi_txrate] & IEEE80211_RATE_VAL)/2;
        else
            *txrate = si->isi_txratekbps / 1000;
        if(si->isi_rxratekbps >= 0) {
            *rxrate = si->isi_rxratekbps / 1000;
        }     

        i++;
        if (i >= 1)
        {
            break;
        }

        cp += si->isi_len, len -= si->isi_len;
    } while (len >= sizeof(struct ieee80211req_sta_info));

    AWN_LOG_DEBUG("Success to get rootAp phyRate");
#endif

    return AWND_OK;
}

/* get rootap's rssi */
int get_rootap_rssi_mtk(AWND_BAND_TYPE band, INT32 *rssi)
{	
#ifdef MTK_NETLINK_SUPPORT
	UINT16 txrate = 0;
	UINT16 rxrate = 0;
	int linkstatus = 0;
	int rssitmp = 0;
	INT8 ifname[MTK_IFNAMESIZE] = {0};

	strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

	*rssi = 0;

    __get_rootap_general_info_mtk(band, &txrate, &rxrate, &linkstatus, rssi);
    AWN_LOG_INFO("band %d, rssi %d, ifname :%s", band, *rssi, ifname);
#else
    *rssi = 0;
#if GET_AP_RSSI
    int up = 0;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    BOOL tmp[AWND_BAND_MAX_NUM];
    if (0 == get_wds_state_mtk(band, &up, rssi, tmp)) {
#else
    if (0 == get_wds_state_mtk(band, &up, rssi)) {
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
        AWN_LOG_ERR("band %d not connected to rootap", band);
        return AWND_ERROR;
    }
    AWN_LOG_DEBUG("get ap rssi :%d", *rssi);

#else
    struct iwreq iwr;
    UINT8 *cp = NULL;
    int i = 0;
    int len = 0;
    int ielen = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    INT8 sta_buf[MTK_LIST_STATION_ALLOC_SIZE] = {0};

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void*)sta_buf;
    iwr.u.data.length = MTK_LIST_STATION_ALLOC_SIZE;

#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
    iwr.u.data.flags = IEEE80211_IOCTL_STA_INFO;
	if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
	if (ioctl(getsocket(), IEEE80211_IOCTL_STA_INFO, &iwr) < 0)
#endif
	{
        AWN_LOG_CRIT("%s ioctl socket failed: IEEE80211_IOCTL_STA_INFO", ifname);
        return AWND_ERROR;
    }

    len = iwr.u.data.length;

    if (len < sizeof(struct ieee80211req_sta_info)){
        AWN_LOG_ERR("sta info len is wrong len=%d sizeof ieee80211req_sta_info:%d",
            len, sizeof(struct ieee80211req_sta_info));
        return AWND_ERROR;
    }

    cp = (UINT8*)sta_buf;

    do {
        struct ieee80211req_sta_info *si;

        si = (struct ieee80211req_sta_info*)cp;

        /* staInfo.isi_rssi = (RTMPAvgRssi(pAd, &pEntry->RssiSample) + 90), so convert to get source rssi */
        *rssi = (char)si->isi_rssi - 90;

        i++;
        if (i >= 1)
        {
            break;
        }

        cp += si->isi_len, len -= si->isi_len;
    } while (len >= sizeof(struct ieee80211req_sta_info));
#endif

    if(*rssi <= -95){
        *rssi = 0;
    }
    else if(*rssi > 0){
        *rssi = 95;
    }
    else{
        *rssi = *rssi + 95;
    }

#endif
    AWN_LOG_DEBUG("Success to get band %d rootAp rssi %d", band, *rssi);

    return AWND_OK;
}

#ifdef SUPPORT_MESHMODE_2G
int get_chanim_mtk(AWND_BAND_TYPE band, INT32 *chan_util, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw)
{
/*current channel, chan_util, bandwidth, obss_util*/
    int ret = AWND_OK;
	INT8 ifname[MTK_IFNAMESIZE] = {0};

	strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));
   	ret = __get_channal_info_mtk(band, chan_util, intf, cur_chan, bw);
	
    AWN_LOG_DEBUG("get_chanim_mtk: Ifname: %s, cur_chan: %u, chan_util: %u, intf: %u, bw: %u\r\n", 
            l_awnd_config.apIfnames[band], *cur_chan, *chan_util, *intf, *bw);

    return ret;
}

void do_csa_mtk(int target_chan, AWND_WIFI_BW_TYPE bw, AWND_CHAN_OFFSET_TYPE offset)
{
    char chan_buff[256];
	char bw_buff[256];

    switch (bw) {
    case WIFI_BW_20M:
		sprintf(chan_buff, "iwpriv ra2 set channel=%d;", target_chan);
		sprintf(bw_buff, "mwctl phy phy0 set channel bw=20;");
		strcat(chan_buff, bw_buff);
        break;
    case WIFI_BW_40M:
		sprintf(chan_buff, "iwpriv ra2 set channel=%d;", target_chan);
		sprintf(bw_buff, "mwctl phy phy0 set channel bw=40;");
		strcat(chan_buff, bw_buff);
        break;
    case WIFI_BW_80M:
		sprintf(chan_buff, "iwpriv ra2 set channel=%d;", target_chan);
		sprintf(bw_buff, "mwctl phy phy0 set channel bw=80;");
		strcat(chan_buff, bw_buff);
        break;
    case WIFI_BW_160M:
		sprintf(chan_buff, "iwpriv ra2 set channel=%d;", target_chan);
		sprintf(bw_buff, "mwctl phy phy0 set channel bw=160;");
		strcat(chan_buff, bw_buff);
        break;
    default:
		sprintf(chan_buff, "iwpriv ra2 set channel=%d;", target_chan);
		sprintf(bw_buff, "mwctl phy phy0 set channel bw=20;");
		strcat(chan_buff, bw_buff);
        break;
    }

    AWN_LOG_NOTICE("lxdebug need to csa to target_chan\n");
    system(chan_buff);
}


void disable_sta_vap_mtk(int disable, AWND_BAND_TYPE band)
{
    if (disable) {
        _wifi_exec_cmd("touch /tmp/awnd_meshmode_2g_disconnect");
        awnd_write_rt_info(band, FALSE, NULL, FALSE);
    } else {
        _wifi_exec_cmd("rm /tmp/awnd_meshmode_2g_disconnect");
    }

    awnd_config_sta_vap_disable(disable, band);

    _wifi_exec_cmd("wifi update vap %s", l_awnd_config.staIfnames[band]);
}
#endif

/* no use */
int get_rootap_info_mtk(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band)
{
    return AWND_OK;
}
/* no use */
int get_rootap_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    return AWND_OK;
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int get_tpie_with_lan_mac_mtk(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    struct iwreq iwr;
    int len = 0;
    INT8 ifname[IFNAMSIZ] = {0};
    struct ieee80211_wlanconfig config;
    int ret = 0;

    if (NULL == pMac || NULL == pAwndNetInfo)
    {
        return AWND_ERROR;
    }    

    snprintf(ifname, sizeof(ifname), MTK_STA_IFNAME_FMT, mtk_ifname_sta_prefix_str[band], mtk_backhaul_sta_ifindex[band]);

    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = IEEE80211_WLANCONFIG_TP_IE_GET;
    config.data.tpie.entry_type = entry_type;
    memcpy(config.data.tpie.tp_macaddr, pMac, IEEE80211_ADDR_LEN);


    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length  = sizeof(config);
    
    if ((ret = ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr)) < 0){
        AWN_LOG_CRIT("ioctl socket failed: IEEE80211_IOCTL_GETTPIE, ret:%d", ret);        
        return AWND_ERROR;
    }
    len = iwr.u.data.length;
    if (len < sizeof(struct ieee80211_wlanconfig)){

        return AWND_ERROR;
    }

    switch (config.data.tpie.status)
    {
        case 0:
            if(config.data.tpie.tp_ie[0] == IEEE80211_ELEMID_VENDOR && istpoui(config.data.tpie.tp_ie))
            {
                memcpy(pAwndNetInfo, config.data.tpie.tp_ie, sizeof(AWND_NET_INFO));
                //memset(pAwndNetInfo->lan_mac, 0, AWND_MAC_LEN);
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
                AWN_LOG_DEBUG("[%s]Failed to get tpie", __FUNCTION__);
                return AWND_NOT_FOUND;
            }           
            break;
        case EAGAIN:
            return AWND_BUSY;
        case ENOENT:
            return AWND_NOT_FOUND;
        case EINVAL:
        default:
            return AWND_ERROR;
    }


    AWN_LOG_DEBUG("[%s]Success to get tpie", __FUNCTION__);
    AWN_LOG_DEBUG("[(%s)%02X:%02X:%02X:%02X:%02X:%02X]awnd_net_type:%-3d,awnd_level:%-2d, awnd_lanip:%x, awnd_dns:%x \
            server_detected:%-2d, server_touch_time:%-2d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
            ifname, pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5], 
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
            pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5]);

    
    return AWND_OK;

}
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

/* get rootap's tpie */
int get_tpie_mtk(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
#ifdef MTK_NETLINK_SUPPORT
	unsigned char ifname[MTK_IFNAMESIZE] = {0};
	int ret = AWND_OK;
	int len = 0;
	TPIE_SEARCH_ENTRY search_entry;

	strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

	memset(&search_entry, 0, sizeof(TPIE_SEARCH_ENTRY));

	search_entry.entry_type = entry_type;
	memcpy(search_entry.bssid, pMac, MAC_ADDR_LEN);

	/* connected: get tpie from rootap info */
	ret = awn_cfg80211_get_tpie(ifname, &search_entry, (void *)pAwndNetInfo, &len);
	if (ret)
	{
		if (ret == AWND_NOT_FOUND) {
			AWN_LOG_DEBUG("%s no tpie found", ifname);
			return AWND_NOT_FOUND;
		} else {
			AWN_LOG_DEBUG("%s get tpie error", ifname);
			return AWND_ERROR;
		}
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
		AWN_LOG_DEBUG("%s: data_len = 0, no tpie found", ifname);
		return AWND_NOT_FOUND;
	}

#else
    struct iwreq iwr;
    int len = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    struct ieee80211_wlanconfig config;
    int ret = 0;

    if (NULL == pMac || NULL == pAwndNetInfo)
    {
        return AWND_ERROR;
    }    

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = IEEE80211_WLANCONFIG_TP_IE_GET;
    config.data.tpie.entry_type = entry_type;
    memcpy(config.data.tpie.tp_macaddr, pMac, IEEE80211_ADDR_LEN);


    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) &config;
    iwr.u.data.length  = sizeof(config);
#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
	iwr.u.data.flags = IEEE80211_IOCTL_CONFIG_GENERIC;
	if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
    if ((ret = ioctl(getsocket(), IEEE80211_IOCTL_CONFIG_GENERIC, &iwr)) < 0)
#endif
	{
        AWN_LOG_CRIT("ioctl socket failed: IEEE80211_IOCTL_GETTPIE, ret:%d", ret);
        return AWND_ERROR;
    }
    len = iwr.u.data.length;
    if (len < sizeof(struct ieee80211_wlanconfig)){
        AWN_LOG_WARNING("length error len:%d sizeof ieee80211_wlanconfig:%d", len, sizeof(struct ieee80211_wlanconfig));
        return AWND_ERROR;
    }

    switch (config.data.tpie.status)
    {
        case 0:
            memcpy(pAwndNetInfo, config.data.tpie.tp_ie, sizeof(AWND_NET_INFO));
            memset(pAwndNetInfo->lan_mac, 0, AWND_MAC_LEN);
            pAwndNetInfo->uplink_mask = 0;
            pAwndNetInfo->uplink_rate = 0;
            pAwndNetInfo->awnd_lanip = ntohl(pAwndNetInfo->awnd_lanip);
            pAwndNetInfo->server_touch_time = ntohl(pAwndNetInfo->server_touch_time);		
            pAwndNetInfo->awnd_dns = ntohl(pAwndNetInfo->awnd_dns); 
            pAwndNetInfo->uplink_mask = LE_READ_2(&pAwndNetInfo->uplink_mask);
            pAwndNetInfo->uplink_rate = LE_READ_2(&pAwndNetInfo->uplink_rate);			
            break;

        default:
            return AWND_NOT_FOUND;
    }
#endif

    AWN_LOG_DEBUG("[%s]Success to get tpie", __FUNCTION__);
    AWN_LOG_DEBUG("[(%s)%02X:%02X:%02X:%02X:%02X:%02X]awnd_net_type:%-3d,awnd_level:%-2d, awnd_lanip:%x, awnd_dns:%x \
            server_detected:%-2d, server_touch_time:%-2d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
            ifname, pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5], 
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
            pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5]);
    
    return AWND_OK;
}


int init_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType)
{
    if (NULL == pAwndNetInfo || NULL == pApMac)
    {
        return AWND_ERROR;
    }

    memset(pAwndNetInfo, 0, sizeof(AWND_NET_INFO));

    pAwndNetInfo->id = IEEE80211_ELEMID_VENDOR;
    pAwndNetInfo->len = sizeof(AWND_NET_INFO) -2;
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
    AWN_LOG_DEBUG("Device's oui will be inited to 0x%x%x%x", pAwndNetInfo->oui[0], pAwndNetInfo->oui[1], pAwndNetInfo->oui[2]);
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

int update_wifi_tpie_mtk(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType)
{
    struct iwreq iwr;
    u_int8_t ie_buf[IEEE80211_MAX_OPT_IE];
	u_int8_t ie_buf_str[IEEE80211_MAX_TP_IE*2];
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    AWND_NET_INFO  *ni = NULL;
    AWND_BAND_TYPE band;
	int remove_ret = AWND_OK;
    int ret = AWND_OK;
	UINT8 previous_oui[VENDORIE_OUI_LEN] = {0};
    int length = 0;
	UINT8* cp = NULL;
	char cmdline[CMDLINE_LENGTH] = {0};
	int i = 0;
    if (NULL == pAwndNetInfo )
    {
        return AWND_ERROR;
    }
    length = (pAwndNetInfo->len + 2 > IEEE80211_MAX_TP_IE) ? IEEE80211_MAX_TP_IE : (pAwndNetInfo->len + 2);
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {    
        /* fill up ifname */
        switch (meshType)
        {
            case AWND_MESH_BACKHUAL:
				strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
                break;
            case AWND_MESH_CONFIG:
				strncpy(ifname, l_awnd_config.configIfnames[band], sizeof(ifname));
                break;
            default:
                AWN_LOG_ERR("Unknown mesh type:%d\n", meshType);
                break;
        }
        
        memset(&iwr, 0, sizeof(struct iwreq));
        strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
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
		/* fill up oui into ie_buf */
        if(meshType == AWND_MESH_CONFIG)
        {   /* config should be the old oui all the time */
            ni->oui[0] = 0x00;
            ni->oui[1] = 0x1d;
            ni->oui[2] = 0x0f;
        }else if(meshType == AWND_MESH_BACKHUAL)
        {   /* FAP/RE's ra2/rai2 woule be updated depends on fap/re_oui_update_status */
            if (fap_oui_update_status == OUI_OLD_TO_NEW || re_oui_update_status == OUI_OLD_TO_NEW)
            {
                /* first, delete tmp_oui of ra2/rai2, to prevent two oui exist at the same time*/
				ni->oui[0] = 0x00;
				ni->oui[1] = 0x1d;
				ni->oui[2] = 0x0f;
				iwr.u.data.pointer = (void*) ie_buf;
				iwr.u.data.length = length;
				iwr.u.data.flags = RT_OID_AP_VENDOR_IE_DEL;
				AWN_LOG_INFO("legnth;%d flags:%x", length, RT_OID_AP_VENDOR_IE_DEL);
				if ((remove_ret = ioctl(getsocket(), RT_PRIV_IOCTL, &iwr)) < 0) {
					AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s[%d]", ifname, remove_ret);
				}
				AWN_LOG_DEBUG("OUI_OLD_TO_NEW : removed %s oui 0x%x%x%x.",ifname,ni->oui[0],ni->oui[1],ni->oui[2]);
                /* second, set dst ni->oui to change oui of ra2/rai2*/
				ni->oui[0] = 0x00;
				ni->oui[1] = 0x31;
				ni->oui[2] = 0x92;
			}else if(fap_oui_update_status == OUI_NEW_TO_OLD || re_oui_update_status == OUI_NEW_TO_OLD)
            {
				ni->oui[0] = 0x00;
				ni->oui[1] = 0x31;
				ni->oui[2] = 0x92;
				iwr.u.data.pointer = (void*) ie_buf;
				iwr.u.data.length = length;
				iwr.u.data.flags = RT_OID_AP_VENDOR_IE_DEL;
				AWN_LOG_INFO("legnth;%d flags:%x", length, RT_OID_AP_VENDOR_IE_DEL);
				if ((remove_ret = ioctl(getsocket(), RT_PRIV_IOCTL, &iwr)) < 0) {
					AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s[%d]", ifname, remove_ret);
				}
				AWN_LOG_DEBUG("OUI_NEW_TO_OLD : removed %s oui 0x%x%x%x.",ifname,ni->oui[0],ni->oui[1],ni->oui[2]);
				ni->oui[0] = 0x00;
				ni->oui[1] = 0x1d;
				ni->oui[2] = 0x0f;
            }else
            {
                /* for other situation, keep OUI */
                AWN_LOG_DEBUG("OUI_KEEP_STATE : oui 0x%x%x%x.",ifname,ni->oui[0],ni->oui[1],ni->oui[2]);
            }
        }
#ifdef MTK_NETLINK_SUPPORT
	    memset(ie_buf_str, 0, sizeof(ie_buf_str));
        for (i = 0; i < sizeof(AWND_NET_INFO); i++)
        {
            sprintf((u_int8_t*)(ie_buf_str + strlen(ie_buf_str)), "%02x", ie_buf[i]);
        }
		//snprintf(cmdline, sizeof(cmdline), WIRELESS_HAPD_CMD_FMT" set vendor_elements %s", 
        //ifname, ie_buf_str);
        snprintf(cmdline, sizeof(cmdline), "iwpriv %s set tp_ie=%s", 
        ifname, ie_buf_str);
		_wifi_exec_cmd(cmdline);
		ret = AWND_OK;
#else
        /* fill up request */
        iwr.u.data.pointer = (void*) ie_buf;
        iwr.u.data.length = length;
        iwr.u.data.flags = RT_OID_AP_VENDOR_IE_SET;
        AWN_LOG_INFO("legnth;%d flags:%x", length, RT_OID_AP_VENDOR_IE_SET);
        if ((ret = ioctl(getsocket(), RT_PRIV_IOCTL, &iwr)) < 0) {
            AWN_LOG_CRIT("config_generic failed awnd_update_tpie(): %s[%d]", ifname, ret);             
            ret = AWND_ERROR;
        }
#endif
    }
	/* update pAwndNetInfo->oui only after chang oui success. */
    if ((fap_oui_update_status == OUI_OLD_TO_NEW || re_oui_update_status == OUI_OLD_TO_NEW ) && ret == AWND_OK )
    {
        pAwndNetInfo->oui[0] = 0x00;
        pAwndNetInfo->oui[1] = 0x31;
        pAwndNetInfo->oui[2] = 0x92;
        /* reset the flag oui_update_status after updated.*/
        if(AWND_MODE_RE == g_awnd.workMode){
            awnd_set_oui_update_status_fap(OUI_KEEP_STATE);
        }else if((AWND_MODE_FAP == g_awnd.workMode) || (AWND_MODE_HAP == g_awnd.workMode))
        {
            awnd_set_oui_update_status_re(OUI_KEEP_STATE);
        }
        AWN_LOG_CRIT("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
    }else if((fap_oui_update_status == OUI_NEW_TO_OLD || re_oui_update_status == OUI_NEW_TO_OLD) && ret == AWND_OK )
    {
        pAwndNetInfo->oui[0] = 0x00;
        pAwndNetInfo->oui[1] = 0x1d;
        pAwndNetInfo->oui[2] = 0x0f;
        if(AWND_MODE_RE == g_awnd.workMode){
            awnd_set_oui_update_status_fap(OUI_KEEP_STATE);
        }else if((AWND_MODE_FAP == g_awnd.workMode) || (AWND_MODE_HAP == g_awnd.workMode))
        {
            awnd_set_oui_update_status_re(OUI_KEEP_STATE);
        }
        AWN_LOG_CRIT("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
    }
    
    AWN_LOG_INFO("Update tpie ret:%d", ret);
    AWN_LOG_ERR("awnd_update_wifi_tpie awnd_net_type:%-3d,awnd_level:%-2d, wait:%d, lanip:%x, dns:%x, \n \
                server_detected:%d, server_touch_time:%d awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X len=%d",
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->wait, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
            pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5], pAwndNetInfo->len); 
    AWN_LOG_ERR("label: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X, uplinkMask:%x, uplinkRate:%u/%u/%u", pAwndNetInfo->awnd_label[0],
        pAwndNetInfo->awnd_label[1],pAwndNetInfo->awnd_label[2],pAwndNetInfo->awnd_label[3],pAwndNetInfo->awnd_label[4],
        pAwndNetInfo->awnd_label[5],pAwndNetInfo->awnd_label[6],pAwndNetInfo->awnd_label[7],pAwndNetInfo->awnd_label[8],
        pAwndNetInfo->awnd_label[9],pAwndNetInfo->awnd_label[10],pAwndNetInfo->awnd_label[11],pAwndNetInfo->awnd_label[12],
        pAwndNetInfo->awnd_label[13],pAwndNetInfo->awnd_label[14],pAwndNetInfo->awnd_label[15], uplinkMask, 
        uplinkRate[AWND_BAND_2G],uplinkRate[AWND_BAND_5G], uplinkRate[l_awnd_config.band_5g2_type]);
        
    return ret;
}

int flush_scan_table_single_band_mtk(AWND_BAND_TYPE band, BOOL force)
{
    /*for mtk, the scan table will be flush at begin scanning at driver*/
    return;
}
int flush_scan_table_mtk(void)
{
    /*for mtk, the scan table will be flush at begin scanning at driver*/
    return;
}

static void _set_wifi_scan_flag()
{
    char cmdline[CMDLINE_LENGTH] = {0};

    if (access(WIFI_SCAN_RUNNING_FILE, 0))
    {
        snprintf(cmdline, sizeof(cmdline), "touch %s", WIFI_SCAN_RUNNING_FILE);
        _wifi_exec_cmd(cmdline);
    }
}

static void _clear_wifi_scan_flag()
{
    char cmdline[CMDLINE_LENGTH] = {0};

    if (0 == access(WIFI_SCAN_RUNNING_FILE, 0))
    {
        snprintf(cmdline, sizeof(cmdline), "rm %s", WIFI_SCAN_RUNNING_FILE);
        _wifi_exec_cmd(cmdline);
    }
}
#if 0
static void *_start_scan_single_band( void *arg)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    AWND_VAP_TYPE vap_type = AWND_VAP_AP;
    AWND_BAND_TYPE *band = (AWND_BAND_TYPE *)arg;

    if (AWND_VAP_AP == vap_type)
    {
#if 0
        snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_AP_IFNAME_FMT" set PartialScan=1",
            mtk_ifname_ap_prefix_str[*band], mtk_backhaul_ap_ifindex[*band]);
#endif 
        snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_AP_IFNAME_FMT" set SiteSurvey=",
            mtk_ifname_ap_prefix_str[*band], mtk_backhaul_ap_ifindex[*band]);
    }
    else
    {
#if 0
        snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_STA_IFNAME_FMT" set PartialScan=1",
            mtk_ifname_sta_prefix_str[*band], mtk_backhaul_sta_ifindex[*band]);
#endif
        snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_STA_IFNAME_FMT" set SiteSurvey=",
            mtk_ifname_sta_prefix_str[*band], mtk_backhaul_sta_ifindex[*band]);
    }

    _wifi_exec_cmd(cmdline);

}
#endif

static void _start_scan_single_band(AWND_BAND_TYPE band)
{
#ifdef MTK_NETLINK_SUPPORT
    int len = 0;
    TP_SCAN_PARAM params;
    //u_int8_t Ch5G[CHANNEL_5G_NON_DFS_NUM] = {36, 40, 44, 48, 149, 153, 157, 161, 165};
    u_int8_t PSCList[CHANNEL_6G_PSC_NUM] = {5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229};
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    memset(&params, 0, sizeof(params));
    params.active = FALSE; /* not used */
    params.ssid_len = 0; /* not specify scan SSID */
    params.flush = TRUE;

    if (AWND_BAND_2G == band || AWND_BAND_5G == band) {
        params.num_channels = 0; /* not specify scan channel, iter all channels */
    }/*
    else if (band == AWND_BAND_5G) {
        params.num_channels = CHANNEL_5G_NON_DFS_NUM;
        memcpy(params.channels, Ch5G, CHANNEL_5G_NON_DFS_NUM);
    }*/
    else if (AWND_BAND_3RD == band) {
        params.num_channels = CHANNEL_6G_PSC_NUM;
        memcpy(params.channels, PSCList, CHANNEL_6G_PSC_NUM);
    }
    params.scan_band = _get_real_band_type(band);
    AWN_LOG_INFO("_start_scan_single_band, band:%d, ifname %s, num_channels:%d", band, ifname, params.num_channels);
    awn_cfg80211_scan(ifname, &params);
#else
    char cmdline[CMDLINE_LENGTH] = {0};

     snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_AP_IFNAME_FMT" set SiteSurvey=1",
        l_awnd_config.apIfnames[band]);

     _wifi_exec_cmd(cmdline);
#endif
}

#ifdef MTK_NETLINK_SUPPORT
static int wait_scan_finish(UINT8 scanBandMask)
{
    AWND_BAND_TYPE bi;
    // 0: scanning, 1:scan done
    UINT8 scan_status = 0;
    UINT8 tmp_status = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    int count = 0;

    /* It takes approximately 400ms to scan a channel, 2/5/6 can be scan together, the max scan channel num=25, max wait 10s */
    while (0 == scan_status && count < 100)
    {
        count++;
        scan_status = 1;
        // get all band scan status
        for (bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
        {
            if (scan_status && (scanBandMask & (1 << bi))) {
                memset(ifname, 0, sizeof(ifname));
                strncpy(ifname, l_awnd_config.apIfnames[bi], sizeof(ifname));
                tmp_status = 0;
                awn_cfg80211_get_scan_status(ifname, &tmp_status, sizeof(UINT8));
                // when all band scan done, set scan finish
                scan_status = scan_status & tmp_status;
                AWN_LOG_DEBUG("[nl80211] ifname = %s, tmp_status = %u, scan_status = %u", ifname, tmp_status, scan_status);
            }
        }
        usleep(1000*100);
    }

    if (1 == scan_status)
    {
        AWN_LOG_INFO("[nl80211] wireless scan succeed!, ifname =%s, count = %d", ifname, count);
        return AWND_OK;
    }
    else
    {
        AWN_LOG_ERR("[nl80211] wireless is still scanning");
        return AWND_ERROR;
    }
}
#else
static int wait_scan_finish(AWND_BAND_TYPE band)
{
#if 0
    sleep(4);
    return AWND_OK;
#else
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    struct iwreq iwr = {0};
    INT8 scan_status = 0;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = &scan_status;
    iwr.u.data.length  = sizeof(scan_status);
    int count = 0;
    while (scan_status == 0 && count < 50)
    {
        count++;
#ifdef WEXT_SIOCIWPRIV_NUM_RESTRIC_32
		iwr.u.data.flags = RTPRIV_IOCTL_GSCANSTATUS;
		if (ioctl(getsocket(), RT_PRIV_IOCTL, &iwr) < 0)
#else
        if (ioctl(getsocket(), RTPRIV_IOCTL_GSCANSTATUS, &iwr) < 0)
#endif
        {
            AWN_LOG_ERR("ioctl socket failed: RTPRIV_IOCTL_GSCANSTATUS %x, errno %d", RTPRIV_IOCTL_GSCANSTATUS, errno);
            return AWND_ERROR;
        }
        usleep(1000*100);
    }

    if (scan_status == 1)
    {
        AWN_LOG_INFO("wireless scan succeed!, ifname =%s, count = %d", ifname, count);
        return AWND_OK;
    }
    else
    {
        AWN_LOG_ERR("wireless is still scanning");
        return AWND_ERROR;
    }
#endif
}
#endif

int do_scan_mtk(UINT8 scanBandMask)
{
#ifdef MTK_NETLINK_SUPPORT
	AWND_BAND_TYPE bi;
	AWN_LOG_INFO("start scanbandmask = %u", scanBandMask);
	_set_wifi_scan_flag();

	for (bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
	{
		if (scanBandMask & (1 << bi)) {
			_start_scan_single_band(bi);
		}
	}

	wait_scan_finish(scanBandMask);
	AWN_LOG_INFO("Finish  scan");
	_clear_wifi_scan_flag();

#else
//    pthread_t tid[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band[AWND_BAND_MAX];    
    AWND_BAND_TYPE bi;

    _set_wifi_scan_flag();

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            band[bi]=bi;
#if 0
            if (pthread_create(&tid[bi], NULL, _start_scan_single_band, (void *)(&band[bi]))) 
            {
                AWN_LOG_WARNING("Fail to create scan thread for band %s", band_suffix[bi]);
                tid[bi] = 0;
            }
#endif
            _start_scan_single_band(band[bi]);
            wait_scan_finish(band[bi]);
        }
    }
#if 0
    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (tid[bi])
        {
            if(pthread_join(tid[bi],NULL))
            {
                AWN_LOG_WARNING("Fail to join pthread:%d", tid[bi]);
            }
        }

    }
#endif   

#if 0
    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi))
        {
            band[bi]=bi;
            wait_scan_finish(band[bi]);
        }
    }
#endif

    //sleep(8);
    //_stable_sleep(8);
    AWN_LOG_INFO("Finish  scan");
    _clear_wifi_scan_flag();
#endif
    exit(0);
}

static void *_fast_scan_single_channel(void *arg)
{
#ifdef MTK_NETLINK_SUPPORT
	int ret = AWND_OK;
	int channel = 0;
	TP_SCAN_PARAM params;

	INT8 ifname[MTK_IFNAMESIZE] = {0};
	AWND_BAND_TYPE *band = (AWND_BAND_TYPE *)arg;
	strncpy(ifname, l_awnd_config.apIfnames[*band], sizeof(ifname));

	ret = _get_channel(ifname, &channel);
	if (ret == AWND_ERROR)
	{
		AWN_LOG_ERR("get working channel fail\n");
		return;
	}

	memset(&params, 0, sizeof(params));
	params.active = FALSE; /* not used */
	params.num_channels = 1; /* scan on current channel */
	params.channels[0] = channel;
	params.ssid_len = 0; /* not specify scan SSID */
	params.scan_band = _get_real_band_type(*band);
	AWN_LOG_DEBUG("scan_band:%d, ifname %s, num_channels:%u, channel=%u",
					params.scan_band, ifname, params.num_channels, params.channels[0]);

	awn_cfg80211_scan(ifname, &params);
#else
    AWND_BAND_TYPE *band = (AWND_BAND_TYPE *)arg;
    int channel = 0;
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    struct iwreq wrq;
    int scanflags = 0;                  /* Flags for scan */
    struct timeval tv;              /* Select timeout */
    //int timeout = 15000000;         /* 15s */
    char cmdline[CMDLINE_LENGTH] = {0};

    strncpy(ifname, l_awnd_config.apIfnames[*band], sizeof(ifname));
    if ((AWND_OK != _get_channel(ifname, &channel)) || (0 == channel))
    {
        AWN_LOG_WARNING("band:%s get channel:%d fail", ifname, channel);
        goto done;
    }

    /* Init timeout value -> 250ms between set and first get */
    tv.tv_sec = 0;
    tv.tv_usec = 250000;

    snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_AP_IFNAME_FMT" set SingleChSiteSurvey=%d",
        l_awnd_config.apIfnames[*band], channel);


    _wifi_exec_cmd(cmdline);

done:
    AWN_LOG_INFO("outting...\n");
#endif
}


int do_scan_fast_mtk(UINT8 scanBandMask)
{
#ifdef MTK_NETLINK_SUPPORT
	AWND_BAND_TYPE bi;
	AWN_LOG_INFO("begain fast scan");

	_set_wifi_scan_flag();

	for (bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
	{
		if (scanBandMask & (1 << bi)) {
			_fast_scan_single_channel(&bi);
		}
	}
	// fast scan just scan one channel, so only sleep 500ms
	usleep(500*1000);
	AWN_LOG_INFO("Finish fast scan");
	_clear_wifi_scan_flag();

#else
    // pthread_t tid[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band[AWND_BAND_MAX];
    AWND_BAND_TYPE bi;
	AWN_LOG_ERR("begain fast scan");

    _set_wifi_scan_flag();

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            band[bi] = bi;
#if 0
            if (pthread_create(&tid[bi], NULL, _fast_scan_single_channel, (void *)(&band[bi]))) 
            {
                AWN_LOG_WARNING("Fail to create scan thread for band %s", band_suffix[bi]);
                tid[bi] = 0;
            }
#endif
            _start_scan_single_band(band[bi]);
            wait_scan_finish(band[bi]);
        }
    }
#if 0
    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (tid[bi])
        {
            if(pthread_join(tid[bi],NULL))
            {
                AWN_LOG_WARNING("Fail to join pthread:%d", tid[bi]);
            }
        }

    }
#endif

#if 0
    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi))
        {
            band[bi]=bi;
            AWN_LOG_ERR("wait_scan_finish begin, band =%d", band[bi]);
            wait_scan_finish(band[bi]);
        }
    }
#endif

    // sleep(3);
    AWN_LOG_INFO("Finish fast scan");
    _clear_wifi_scan_flag();
#endif
    exit(0);
}
#ifdef MTK_NETLINK_SUPPORT
int get_scan_result_mtk(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
		char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
	int ret = AWND_OK;
	INT8 ifname[MTK_IFNAMESIZE] = {0};
	unsigned char cmdline[CMDLINE_LENGTH] = {'\0'};
	unsigned char ssid[AWND_MAX_SSID_LEN] = {'\0'};
	char scanfile[CMDLINE_LENGTH] = {0};
	char staconf[CMDLINE_LENGTH] = {0};
	FILE *fp_conf = NULL;
	int freq_list_exist = 0;
	char line[CMDLINE_LENGTH] = {0};
	int cur_ch_scan_num = 0;
	int nss = 0;
	int phyMode = 0;
	int chwidth = 0;
	MTK_SCAN_RESULT scan_data;
	int scan_data_len = 0;
	int entry_cnt = 0;
	MTK_SCAN_ENTRY *se = NULL;
	int i = 0;
	int idx = 0;
	unsigned char* vp = NULL;
	int ielen = 0;
	int cur_5g_channel = 0;

	AWND_AP_ENTRY* pCurApEntry = NULL;
	AWND_REAL_BAND_TYPE real_band = 0;
	char ssidNull[AWND_MAX_SSID_LEN] = {0};

	real_band = _get_real_band_type(band);

	AWN_LOG_INFO("get_scan_result_mtk start, realband is:%d", real_band);

	if (NULL == pAwndScanResult)
	{
		AWN_LOG_ERR("pAwndScanResult is null");
		return AWND_ERROR;
	}

	if (AWND_VAP_AP == vap_type)
		strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
	else
		strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));
	

	if (AWND_OK != get_phy_mtk(band, &nss, &phyMode, &chwidth))
	{
		AWN_LOG_ERR("get_phy_MTK fail, quit awnd_get_scan_result");
		return AWND_ERROR;
	}

	memset(&scan_data, 0, sizeof(scan_data));
	ret = awn_cfg80211_scan_result(ifname, &scan_data, &scan_data_len);
	if (ret)
	{
		AWN_LOG_ERR("get scan result failed ret=%d", ret);
			return AWND_ERROR;
	}
	
    snprintf(scanfile, sizeof(scanfile), TMP_WIFI_SCAN_RESULT_FILE, real_band_suffix[real_band]);
    FILE *fp = fopen(scanfile, "w+");
    if (fp != NULL)
        fprintf(fp, "Scan completed:\n");

	if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
	{
		cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
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

		if (fp != NULL)
        {
            fprintf(fp, "    MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", se->bssid[0],se->bssid[1],se->bssid[2],
                    se->bssid[3],se->bssid[4],se->bssid[5]);
            fprintf(fp, "    ESSID:\"%s\"\n", se->ssid);
            fprintf(fp, "    Channel:%d\n\n", se->channel);
        }

		pCurApEntry->rssi  = se->rssi;
		pCurApEntry->freq  = se->freq;
		pCurApEntry->index = idx + 1;
		pCurApEntry->channel = se->channel;

		if (AWND_BAND_5G == band && pCurApEntry->channel != cur_5g_channel 
			&& (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
		{
			if (!((l_awnd_config.limit_scan_band1 && pCurApEntry->channel <= 48) 
				|| (l_awnd_config.limit_scan_band4 && pCurApEntry->channel >= 149)))
			{
				AWN_LOG_DEBUG("skip entry when channel(%d) is not in band1 or band4, bssid:%02X:%02X:%02X:%02X:%02X:%02X,limitband1=%d,limitband4=%d", 
								pCurApEntry->channel, pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
								pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],
								l_awnd_config.limit_scan_band1, l_awnd_config.limit_scan_band4);
				continue;
			}
		}

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

		if (g_awnd.enable6g && AWND_REAL_BAND_6G == real_band)
		{
			if (0 != memcmp(pCurApEntry->ssid, ssidNull, AWND_MAX_SSID_LEN))
			{
				if((NULL != match_ssid  && 0 != strncmp(match_ssid, pCurApEntry->ssid, AWND_MAX_SSID_LEN))
				    && (NULL == preconf_ssid || (NULL != preconf_ssid && 0 != strncmp(preconf_ssid, pCurApEntry->ssid, AWND_MAX_SSID_LEN))))
				{
				    AWN_LOG_INFO("%-6s idx:%d,ssid not match, skip entry ssid is:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%-4d, channel:%-3d",
						ifname, idx, pCurApEntry->ssid, pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
						pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],pCurApEntry->rssi, pCurApEntry->channel);
				    continue;
				}
			}
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
			if (!(pCurApEntry->uplinkMask & (1 << (8 + real_band))))
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

		if (pCurApEntry->channel == cur_5g_channel)
		{
			cur_ch_scan_num ++;
		}

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

	AWN_LOG_INFO("Max GROUP MEMBER is:%d, scanResult Ap Num is: %d", AWND_MAX_GROUP_MEMBER, pAwndScanResult->iApNum);

	if (AWND_BAND_5G == band && cur_5g_channel > 48 && cur_5g_channel < 149 && 0 == cur_ch_scan_num)
	{
		memset(staconf, 0, sizeof(staconf));
		snprintf(staconf, sizeof(staconf), WPAS_CONFIG_PATH_FMT, l_awnd_config.staIfnames[band]);
		fp_conf = fopen(staconf, "r");
		/* If no entries are scanned and the sta interface configuration exists, delete the freq-list configuration item */
		if (NULL != fp_conf)
		{
			while (fgets(line, CMDLINE_LENGTH, fp_conf) != NULL)
			{
				if(0 == strncmp(line, "freq_list=", 10))
				{
					freq_list_exist = 1;
					break;
				}
			}
			if (freq_list_exist)
			{
				memset(cmdline, 0, sizeof(cmdline));
				snprintf(cmdline, sizeof(cmdline),"sed -i 's/freq_list=.*//g' "WPAS_CONFIG_PATH_FMT, l_awnd_config.staIfnames[band]);
				_wifi_exec_cmd(cmdline);

				memset(cmdline, 0, sizeof(cmdline));
				snprintf(cmdline, sizeof(cmdline), WIRELESS_WPAS_CMD_FMT" reconfigure &", l_awnd_config.staIfnames[band]);
				_wifi_exec_cmd(cmdline);
				AWN_LOG_DEBUG("Without an optional 5G entry, supplicant has been changed to full-channel scanning");
			}
		}
		if (fp_conf != NULL)
			fclose(fp_conf);
	}

	if (fp != NULL)
        fclose(fp);

	if (!isFast)
	{
		/* save scan result */
		memset(cmdline, 0, sizeof(cmdline));
        snprintf(cmdline, sizeof(cmdline),"cp -f "TMP_WIFI_SCAN_RESULT_FILE" "WIFI_SCAN_RESULT_FILE" &",
             real_band_suffix[real_band], real_band_suffix[real_band]);
        _wifi_exec_cmd(cmdline);
	}

	return AWND_OK;
}

#else
int get_scan_result_mtk(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
    UINT8 buf[AWND_MAX_SCAN_BUF] = {0};
    char cmdline[CMDLINE_LENGTH] = {0};
    char scanfile[CMDLINE_LENGTH] = {0};
    struct iwreq iwr;
    UINT8* cp = NULL;
    int len = 0;
    int idx = 0;
    int count = 0;
    int ielen = 0;
    INT8 ssid[MTK_MAX_SSID_LENGTH + 1] = {0};
    INT8 ifname[MTK_IFNAMESIZE] = {0};
    MTK_SCAN_AP_ENTRY* entry = NULL;
    AWND_AP_ENTRY* pCurApEntry;
    //AWND_SCAN_RANGE *range;
    UINT8* vp = NULL;
    int nss;
    int phyMode;
    int chwidth;
    int ret = -1;
    AWND_REAL_BAND_TYPE real_band = 0;
    int cur_5g_channel = 0;

    real_band = _get_real_band_type(band);

    if (NULL == pAwndScanResult)
    {
        AWN_LOG_ERR("pAwndScanResult is null");
        return AWND_ERROR;
    }

    if (AWND_VAP_AP == vap_type)
        strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    else 
        strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if (AWND_OK != awnd_get_phy(band, &nss, &phyMode, &chwidth))
    {
        AWN_LOG_ERR("awnd_get_phy fail, quit awnd_get_scan_result");
        return AWND_ERROR;
    }
    

    /* get scan result from wlan driver */
    memset(&iwr, 0, sizeof(iwr));
    strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void*)buf;
    iwr.u.data.length  = sizeof(buf);

    if ((ret = ioctl(getscansocket(), RTPRIV_IOCTL_GSITESURVEY_DECO, &iwr)) < 0)
    {
        AWN_LOG_ERR("unable to get scan result:ifname:%s, ret:%d", ifname, ret);
        return AWND_ERROR;
    }

    snprintf(scanfile, sizeof(scanfile), TMP_WIFI_SCAN_RESULT_FILE, real_band_suffix[real_band]);
    FILE *fp = fopen(scanfile, "w+");
    if (fp != NULL)
        fprintf(fp, "Scan completed:\n");

    len = iwr.u.data.length;
    if (len < sizeof(MTK_SCAN_AP_ENTRY))
    {
        AWN_LOG_ERR("scan result len is wrong");
        if (fp != NULL)
            fclose(fp);
        return AWND_ERROR;
    }
    //range = (AWND_SCAN_RANGE *)buf;
    //AWN_LOG_ERR("scan range total=%d, start=%d, valid=%d, over=%d", range->total, range->start, range->valid, range->over);

    entry = (MTK_SCAN_AP_ENTRY *)buf;

    if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
    {
        cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
    }

    /* parse scan result to data struct AWND_SCAN_RESULT */
    //while(count < range->valid && idx < AWND_MAX_GROUP_MEMBER){
    do {
        if (fp != NULL)
        {
            fprintf(fp, "    MAC:%02X:%02X:%02X:%02X:%02X:%02X\n", entry->bssid[0],entry->bssid[1],entry->bssid[2],
                    entry->bssid[3],entry->bssid[4],entry->bssid[5]);
            fprintf(fp, "    ESSID:\"%s\"\n", entry->ssid);
            fprintf(fp, "    Channel:%d\n\n", entry->channel);
        }

        if (entry->netInfo.len == 0)
        {
            entry += 1;
            //count += 1;
            len -= sizeof(MTK_SCAN_AP_ENTRY);
            continue;
        }

        pCurApEntry = &(pAwndScanResult->tApEntry[idx]);

        memset(pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
 
        _copy_essid(ssid, sizeof(ssid), entry->ssid, entry->ssidLen);

        memcpy(pCurApEntry->ssid, ssid, strlen(ssid));
        pCurApEntry->ssid[entry->ssidLen] = 0;

        memcpy(pCurApEntry->bssid, entry->bssid, IEEE80211_ADDR_LEN);
        pCurApEntry->rssi  = entry->rssi;
        pCurApEntry->freq  = entry->freq;
        pCurApEntry->index = idx + 1;
        pCurApEntry->channel = entry->channel;

        if (AWND_BAND_5G == band && pCurApEntry->channel != cur_5g_channel 
            && (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
        {
            if (!((l_awnd_config.limit_scan_band1 && pCurApEntry->channel <= 48) 
                || (l_awnd_config.limit_scan_band4 && pCurApEntry->channel >= 149)))
            {
                AWN_LOG_DEBUG("skip entry when channel(%d) is not in band1 or band4, bssid:%02X:%02X:%02X:%02X:%02X:%02X,limitband1=%d,limitband4=%d", 
                                pCurApEntry->channel, pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
                                pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],
                                l_awnd_config.limit_scan_band1, l_awnd_config.limit_scan_band4);
                continue;
            }
        }

        vp = (UINT8*)&(entry->netInfo);
        ielen = entry->netInfo.len;
        if (ielen > 0) 
        {
            if (entry->netInfo.id == IEEE80211_ELEMID_VENDOR && istpoui(vp))
            {
                memcpy(&(pCurApEntry->netInfo), vp, ((2+vp[1]) < sizeof(AWND_NET_INFO))? (2+vp[1]) : sizeof(AWND_NET_INFO));
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
            entry += 1;
            //count += 1;
            len -= sizeof(MTK_SCAN_AP_ENTRY);
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
        pCurApEntry->uplinkRate = pCurApEntry->netInfo.uplink_rate;
        pCurApEntry->netInfo.uplink_rate = 0;
        memcpy(pCurApEntry->lan_mac, pCurApEntry->netInfo.lan_mac, AWND_MAC_LEN);
        memset(pCurApEntry->netInfo.lan_mac, 0, AWND_MAC_LEN);

        if (!(pCurApEntry->netInfo.awnd_level) || !(pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI))
            pCurApEntry->uplinkRate = 0;

        if ((pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI) && ((pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_2G) ||
            (pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_5G) || (pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_5G2)))
        {   /* if current band disconnect with rootap, uplinkRate set to zero  */
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

        entry += 1;
        //count += 1;
        len -= sizeof(MTK_SCAN_AP_ENTRY);
        ++idx;
    } while(len >= sizeof(MTK_SCAN_AP_ENTRY) && idx < AWND_MAX_GROUP_MEMBER);
    pAwndScanResult->iApNum = idx;
    if (fp != NULL)
        fclose(fp);
#if !CONFIG_ROLE_SUPPORT_RE_ONLY
    /* no need to save scan result when support role is RE only */
    if (!isFast)
    {
        /* save scan result */
        snprintf(cmdline, sizeof(cmdline),"cp -f "TMP_WIFI_SCAN_RESULT_FILE" "WIFI_SCAN_RESULT_FILE" &",
             real_band_suffix[real_band], real_band_suffix[real_band]);
        _wifi_exec_cmd(cmdline);
    }
#endif  /* !CONFIG_ROLE_SUPPORT_RE_ONLY */

    return AWND_OK;
}
#endif


int set_channel_mtk(AWND_BAND_TYPE band, UINT8 channel)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_AP_IFNAME_FMT" set Channel=%d & ",
            l_awnd_config.apIfnames[band], channel);

    return _wifi_exec_cmd(cmdline);
}

int get_sta_iface_in_bridge_mtk(AWND_BAND_TYPE band, UINT8* ifname)
{
    UINT8 vapname[MTK_IFNAMESIZE] = {0};

    strncpy(vapname, l_awnd_config.staIfnames[band], sizeof(vapname));

#if QCA_USE_WIFI_VLAN_DEV
    snprintf(ifname, IFNAMSIZ, "%s.%s", vapname, QCA_LAN_VLAN_DEV_SUFFIX); 
#else
    snprintf(ifname, IFNAMSIZ, "%s", vapname);
#endif

    return AWND_OK;
}


int disconn_sta_pre_mtk(AWND_BAND_TYPE band, UINT* pBandMask)
{
    memset(&g_awnd.rootAp[band], 0, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_DISCONNECT;
    
    *pBandMask |= (1 << band);
     
    return AWND_OK;
}
int disconn_all_sta_pre_mtk(UINT* pBandMask)
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        awnd_disconn_sta_pre(band, pBandMask);
}
int disconn_sta_post_mtk(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    AWN_LOG_DEBUG("RECORD DISCONN");

#ifdef MTK_NETLINK_SUPPORT
	snprintf(cmdline, sizeof(cmdline), WIRELESS_WPAS_CMD_FMT" disconnect", 
          l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);
#else
    /*if (awnd_get_wds_state(band))*/
    {
        snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_STA_IFNAME_FMT" set ApCliEnable=0 &", 
            l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);
    }
#endif
    awnd_write_rt_info(band, FALSE, NULL, FALSE);
     
    return AWND_OK;
}
int disconn_sta_mtk(AWND_BAND_TYPE band)
{
    UINT bandMask;

    awnd_disconn_sta_pre(band, &bandMask);
     
    return awnd_disconn_sta_post(band);
}
int disconn_all_sta_mtk(void)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        awnd_disconn_sta(band);

    return AWND_OK;
}
int reconn_sta_pre_mtk(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp)
{
    memcpy(&g_awnd.rootAp[band], pRootAp, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_CONNECTING;
     
    return AWND_OK;
}
int reconn_sta_post_mtk(AWND_BAND_TYPE band, BOOL check_wpa_status)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    awnd_config_set_stacfg_enb(1, band);
#ifdef MTK_NETLINK_SUPPORT
	snprintf(cmdline, sizeof(cmdline), WIRELESS_WPAS_CMD_FMT" reconnect", 
        l_awnd_config.staIfnames[band]);
	AWN_LOG_ERR("reconn_sta_post_mtk");
#else
    snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_STA_IFNAME_FMT" set ApCliEnable=1", l_awnd_config.staIfnames[band]);
#endif
    _wifi_exec_cmd(cmdline);
	
    return AWND_OK;
}
int reset_sta_connection_mtk(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};
#ifdef MTK_NETLINK_SUPPORT
	snprintf(cmdline, sizeof(cmdline), WIRELESS_WPAS_CMD_FMT" disconnect",
      l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    memset(cmdline, 0, sizeof(cmdline));
    snprintf(cmdline, sizeof(cmdline), "sleep 1 && "WIRELESS_WPAS_CMD_FMT" reconnect &", 
          l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);
#else
    snprintf(cmdline, sizeof(cmdline), "iwpriv "MTK_STA_IFNAME_FMT" set ApCliEnable=0; sleep 1; iwpriv "MTK_STA_IFNAME_FMT" set ApCliEnable=1 &", 
            l_awnd_config.staIfnames[band], l_awnd_config.staIfnames[band]);
	_wifi_exec_cmd(cmdline);
#endif
	
    return AWND_OK;
}

#define RETRY_HW_NAT_TIMES (1)
int set_backhaul_sta_dev_mtk(UINT32 link_state, unsigned int eth_link_state)
{
    char dev_list[128];
    char cmd[128];
    FILE *fp;
    int index = 0;
    unsigned int flag = 0;
    int ret = 0;
    int dev_num = 0;
    int fd;
    int can_send_to_nat = 1;
    const int MAX_STA_NAME_LEN = 4 + l_awnd_config.ethIfCnt;
#if CONFIG_HW_NAT_TRAFFIC_STATS
    hwnat_sta_dev_notify_opt opt;
#endif
    AWND_BAND_TYPE band_index = 0;

#ifdef CONFIG_IS_MT798x
    memset(dev_list, 0, sizeof(dev_list));
    for (index = 0; index < LINK_STATE_BITIDX_ETH; index ++)
    {
        flag = (0x1) << (index);
        if (link_state & flag)
        {
            /* get name */
            if (dev_num)
                awnd_strlcat(dev_list, ":", sizeof(dev_list));            

            if (index < LINK_STATE_BITIDX_PLC) {
                band_index = _get_band_type_index(index);
                if (band_index < l_awnd_config.band_num) {
                    awnd_strlcat(dev_list, l_awnd_config.staIfnames[band_index], sizeof(dev_list));
                }
                else {
                    AWN_LOG_WARNING("Unknown sta index: %d band_index: %d", index, band_index);
                }
            }
            else {
                awnd_strlcat(dev_list, l_awnd_config.plcIfname, sizeof(dev_list));
            }

            dev_num ++;
		}
	}

    for (index = 0; index < l_awnd_config.ethIfCnt; index ++)
    {
        flag = (0x1) << (index);
        if (eth_link_state & flag)
        {
            if (dev_num)
                awnd_strlcat(dev_list, ":", sizeof(dev_list));

            awnd_strlcat(dev_list, l_awnd_config.ethIfnames[index], sizeof(dev_list));
            dev_num ++;
        }
    }
#else
    /* (bits from index 0 to 5)2.4G STA, 5G1 STA, 5G2 STA, PLC, ethX, ethY[, ethZ] */
    char sta_name[MAX_STA_NAME_LEN][MTK_IFNAMESIZE];
    for(index = 0; index < MAX_STA_NAME_LEN; ++index){
        sta_name[index][0] = '/0';
    }
    for(index = 0; index < l_awnd_config.ethIfCnt; ++index){
        _strlcpy(sta_name[index + 4], l_awnd_config.ethIfnames[index], MTK_IFNAMESIZE);
    }
#if 0
#if (ETH_PORT_NUM == 3)
    /* (bits from index 0 to 5)2.4G STA, 5G1 STA, 5G2 STA, PLC, eth0.2, eth0.3, eth0.4 */
    char sta_name[7][MTK_IFNAMESIZE] = {"", "", "","", "eth0.2", "eth0.3", "eth0.4"};
#else 
#if CONFIG_TP_SWITCH_E4V3
    /* (bits from index 0 to 5)2.4G STA, 5G1 STA, 5G2 STA, PLC, eth0.2, eth0.3 */
    char sta_name[6][MTK_IFNAMESIZE] = {"", "", "", "", "eth0.2", "eth0.3"};
#else
    /* (bits from index 0 to 5)2.4G STA, 5G1 STA, 5G2 STA, PLC, eth0, eth1 */
    char sta_name[6][MTK_IFNAMESIZE] = {"", "", "", "", "eth0", "eth1"};
#endif  //CONFIG_TP_SWITCH_E4V3
#endif  //ETH_PORT_NUM == 3
#endif
    char tmp_ifname[MTK_IFNAMESIZE] = {0};
    
    for (index = 0; index < 3; index++)
    {
		strncpy(tmp_ifname, l_awnd_config.staIfnames[index], sizeof(tmp_ifname));
        strncpy(sta_name[index], tmp_ifname, MTK_IFNAMESIZE);
    }

    #if CONFIG_HW_NAT_TRAFFIC_STATS
    /* send info to hw_nat */
    for (index = 0; index < RETRY_HW_NAT_TIMES; index++)
    {
        fd = open("/dev/"HW_NAT_DEVNAME, O_RDONLY);
        if (fd < 0)
        {
            can_send_to_nat = 0;
	        AWN_LOG_WARNING("Open %s pseudo device failed\n", "/dev/"HW_NAT_DEVNAME);
            sleep(1);
        }else
        {
            break;
        }
    }
    #endif

    memset(dev_list, 0, sizeof(dev_list));
    for (index = 0; index < MAX_STA_NAME_LEN; index ++)
    {
        flag = (0x1) << (index);
        if (link_state & flag)
        {
            /* get name */
            if (dev_num)
                awnd_strlcat(dev_list, ":", sizeof(dev_list));            

            awnd_strlcat(dev_list, sta_name[index], sizeof(dev_list));
            dev_num ++;
            
            #if CONFIG_HW_NAT_TRAFFIC_STATS
            memcpy(opt.working_sta_name[index], sta_name[index], MTK_IFNAMESIZE);
            opt.working_sta_name[index][MTK_IFNAMESIZE - 1] = '\0';
        }else{
            opt.working_sta_name[index][0] = '\0';
            #endif
        }
    }

#endif  //CONFIG_IS_MT798x
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "echo '%s' > %s", dev_list, STATS_BACKHAUL_STA_DEV_NAME);
    AWN_LOG_WARNING("cmd:%s", cmd);

    #if CONFIG_HW_NAT_TRAFFIC_STATS
    if (can_send_to_nat == 1)
    {
        if(ioctl(fd, HW_NAT_SET_STA_DEV, &opt)<0) 
        {
	        AWN_LOG_WARNING("HW_NAT_API: ioctl error\n");
        }
        close(fd);
    }
    #endif

    if ((fp = popen(cmd, "r")) == NULL)
    {
        AWN_LOG_WARNING("popen error:%s", strerror(errno));
        return AWND_ERROR;
    }

    if ((ret = pclose(fp)) == -1)
    {
        AWN_LOG_WARNING("pclose error:%s", strerror(errno));
        return AWND_ERROR;
    }
    return AWND_OK;
}

#undef RETRY_HW_NAT_TIMES
void do_band_restart_mtk(UINT8 BandMask)
{
    return;
}

int get_wifi_bw_mtk(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw)
{
    return AWND_OK;
}
void set_wifi_bw_mtk(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw)
{
    return;
}

int bss_status_check_mtk()
{
    return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_mtk(AWND_BAND_TYPE band)
{
    proxy_l2uf_single_interface(l_awnd_config.hostIfnames[band]);
    proxy_l2uf_single_interface(l_awnd_config.apIfnames[band]);

    return AWND_OK;
}

int reload_sta_conf_mtk(AWND_BAND_TYPE band)
{

    return AWND_OK;
}

int set_wireless_sta_bssid_mtk(char *bssid_str, AWND_BAND_TYPE band)
{
    /*char vap_name[IFNAMSIZ] = {0};
    strncpy(vap_name, l_awnd_config.staIfnames[band], sizeof(vap_name));
    return awnd_config_sta_bssid(bssid_str, vap_name);*/
    return AWND_OK;
}

int wifi_re_roam_mtk(void)
{
    AWND_BAND_TYPE band;
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, CMDLINE_LENGTH, "wifi update reroam ");
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) {
        if (band != AWND_BAND_2G) {
            awnd_strlcat(cmdline, ",", CMDLINE_LENGTH);
        }
        awnd_strlcat(cmdline, l_awnd_config.staIfnames[band], CMDLINE_LENGTH);
    }
    _wifi_exec_cmd(cmdline);
    return AWND_OK;
}
#endif


int get_cac_state_mtk(AWND_BAND_TYPE band, int *state)
{
    char cmdline[CMDLINE_LENGTH] = {0};
	WLAN_CAC_STATUS cacStatus;
	int len;
	memset(&cacStatus, 0, sizeof(cacStatus));
	awn_cfg80211_get_cacnopstatus(l_awnd_config.apIfnames[band], &cacStatus, &len);
	if(cacStatus.inCac || cacStatus.inNop)
		*state = 1;
	else
		*state = 0;
		
    return AWND_OK;
}


AWN_PLATFORM_OPS awn_platform_mtk = {
    .get_default_mesh_channel = get_default_mesh_channel_mtk,
    .check_block_chan_list = check_block_chan_list_mtk,
    .get_sta_channel = get_sta_channel_mtk,
    .get_backhaul_ap_channel = get_backhaul_ap_channel_mtk,

    .get_phy = get_phy_mtk,
    .get_wds_state = get_wds_state_mtk,
    .get_cac_state = get_cac_state_mtk,
    .get_rootap_phyRate = get_rootap_phyRate_mtk,
    .get_rootap_rssi = get_rootap_rssi_mtk,
#ifdef SUPPORT_MESHMODE_2G
	.get_chanim = get_chanim_mtk,
	.do_csa = do_csa_mtk,
	.disable_sta_vap = disable_sta_vap_mtk,
#endif
    .get_rootap_info = get_rootap_info_mtk,
    .get_rootap_tpie = get_rootap_tpie_mtk,
    .get_tpie = get_tpie_mtk,


    .init_tpie = init_tpie_mtk,
    .update_wifi_tpie = update_wifi_tpie_mtk,
    
    .flush_scan_table_single_band = flush_scan_table_single_band_mtk,
    .flush_scan_table = flush_scan_table_mtk,
    .do_scan = do_scan_mtk,
    .do_scan_fast = do_scan_fast_mtk,
    .get_scan_result = get_scan_result_mtk,

    .set_channel = set_channel_mtk,
    .get_sta_iface_in_bridge = get_sta_iface_in_bridge_mtk,

    .disconn_sta_pre = disconn_sta_pre_mtk,
    .disconn_all_sta_pre = disconn_all_sta_pre_mtk,
    .disconn_sta_post = disconn_sta_post_mtk,
    .disconn_sta = disconn_sta_mtk,
    .disconn_all_sta = disconn_all_sta_mtk,
    .reconn_sta_pre = reconn_sta_pre_mtk,
    .reconn_sta_post = reconn_sta_post_mtk,
    .reset_sta_connection = reset_sta_connection_mtk,

    .set_backhaul_sta_dev = set_backhaul_sta_dev_mtk,
    .do_band_restart = do_band_restart_mtk,

    .get_wifi_bw = get_wifi_bw_mtk,
    .set_wifi_bw = set_wifi_bw_mtk,
    .bss_status_check = bss_status_check_mtk,
    .wpa_supplicant_status_check = NULL,
    .get_wifi_zwdfs_support = NULL,

#ifdef CONFIG_AWN_RE_ROAMING
    .proxy_l2uf = proxy_l2uf_mtk,
    .reload_sta_conf = reload_sta_conf_mtk,
    .set_wireless_sta_bssid = set_wireless_sta_bssid_mtk,
    .wifi_re_roam = wifi_re_roam_mtk,
#endif /* CONFIG_AWN_RE_ROAMING */
};

AWN_PLATFORM_OPS *awn_platform_ops = &awn_platform_mtk;

