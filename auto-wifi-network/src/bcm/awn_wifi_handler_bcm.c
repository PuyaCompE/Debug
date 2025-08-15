/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_bcm.c
Version     : v0.1 
Description : awn wifi handler for bcm

Author      :  <dengzhong@tp-link.com.cn>
Create date : 2019/4/1

History     :
01, 2019/4/1 Deng Zhong, Created file.

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
#include <signal.h>

#include "tp_linux.h"

#if 0
#include "bcmutils.h"
#include "wlioctl.h"
#include "bcmtlv.h"
#include "802.11.h"
#endif

#include "../auto_wifi_net.h"
#include "../awn_log.h"
#include "../awn_wifi_handler_api.h"

#include "awn_wifi_handler_bcm.h"

#if CONFIG_BCM_USE_WL_INCLUDE_FILE
#include "wlioctl.h"
#include "bcmutils.h"
#endif
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
#define READLINE_LENGTH         64
/* passive scan time(for beacon listen) default 110 in drivers */
#define SCAN_PASSIVE_TIME       200
/* time for home channel processing default 45 in drivers
   test result: the time return home channel will be less than 70ms when scanning */
#define WLC_SCAN_HOME_TIME      200

#define SCAN_CHANNEL_TIME       40  /* active scan time(for probe) */
#define SCAN_BAND1_CHANNEL_NUM  4
#define SCAN_BAND2_CHANNEL_NUM  4
#define SCAN_BAND4_CHANNEL_NUM  5
#define SCAN_BAND3_CHANNEL_NUM  8
#define SCAN_BAND1_BAND4_CHANNEL_NUM  8

#define SCAN_6G_HALF_CHANNEL_NUM   8
#define SCAN_6G_CHANNEL_NUM       12
#define SCAN_6G_EU_CHANNEL_NUM     4

#define RSSI_WEIGHT 0.8
#define ENABLE 1

#define AWND_TMP_WIFI_CONFIG_WIFI   "/tmp/etc/config/wifi"
#define AWND_DHD_PATH               "/sys/module/dhd"
#define BSS_DOWN_TIMER          3
#if CONFIG_BAND_WIDTH_CHECK
#define BWRESET_TOTAL_TIME      60000
#endif
#define REINIT_CNT_THRESOLD     6
/* normaly reinit_cnt increase every 4s,
    to wl down/up if increase more than 10 in 1 minute */
#define REINIT_CNT_TIMER        10

#define SCAN_RETRY_TIMES 2

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/
/*tpie_setbuf_t is only for tp，do not used for other vendors*/
#if CONFIG_BCM_USE_WL_INCLUDE_FILE
#define sta_info_t sta_info_v8_t
#define octet_t octet
#define wl_bss_info_t wl_bss_info_v109_1_t
/*vndr_tpie_setbuf_t is defined at wlioctl.h*/
#define	tpie_setbuf_t vndr_tpie_setbuf_t
#else
#define sta_info_t sta_info_v7_t
#define octet_t ether_addr_octet
#define wl_bss_info_t wl_bss_info_v109_t
#define	tpie_setbuf_t vndr_ie_setbuf_t
#endif
/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/

static char *real_band_suffix[AWND_REAL_BAND_MAX] = {"2g", "5g", "5g_2", "6g", "6g_2"};

extern AWND_GLOBAL g_awnd;
extern AWND_CONFIG l_awnd_config;

//{48, 44, 40, 36};
static UINT16 l_band1_channel[SCAN_BAND1_CHANNEL_NUM] = {0xd030, 0xd02c, 0xd028, 0xd024};
//{52, 56, 60, 64};
static UINT16 l_band2_channel[SCAN_BAND2_CHANNEL_NUM] = {0xd034, 0xd038, 0xd03c, 0xd040};
//{100, 104, 108, 112, 116, 120, 124, 128};
static UINT16 l_band3_channel[SCAN_BAND3_CHANNEL_NUM] = {0xd064, 0xd068, 0xd06c, 0xd070, 0xd074, 0xd078, 0xd07c, 0xd080};
//{149, 153, 157, 161, 165};
static UINT16 l_band4_channel[SCAN_BAND4_CHANNEL_NUM] = {0xd095, 0xd099, 0xd09d, 0xd0a1, 0xd0a5};
//{48, 44, 40, 36, 149, 153, 157, 161};
static UINT16 l_band1_band4_channel[SCAN_BAND1_BAND4_CHANNEL_NUM] = {0xd030, 0xd02c, 0xd028, 0xd024, 0xd095, 0xd099, 0xd09d, 0xd0a1};
/****************************************************************
BW160_2 33 37 41 45 49 53 57 61
BW160_3 65 69 73 77 81 85 89 93
BW160_4 97 101 105 109 113 117 121 125
BW160_5 129 133 137 141 145 149 153 157
BW160_6 161 165 169 173 177 181 185 189
BW160_7 193 197 201 205 209 213 217 221
BW40_29 225 229
BW20    233
****************************************************************/
//{33, 65, 97, 129, 161, 193, 225, 233};
static UINT16 l_6g_80_1_channel[SCAN_6G_HALF_CHANNEL_NUM] = {0x5021, 0x5041, 0x5061, 0x5081, 0x50a1, 0x50c1, 0x50e1, 0x50e9};
//{41, 49, 81, 113, 145, 177, 209, 229};
static UINT16 l_6g_80_2_channel[SCAN_6G_HALF_CHANNEL_NUM] = {0x5029, 0x5031, 0x5051, 0x5071, 0x5091, 0x50b1, 0x50d1, 0x50e5};

//{37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213};
static UINT16 l_6g_all_channel[SCAN_6G_CHANNEL_NUM] = {0x5025, 0x5035, 0x5045, 0x5055, 0x5065, 0x5075, 0x5085, 0x5095,
                                0x50a5, 0x50b5, 0x50c5, 0x50d5};

//{37, 53, 69, 85}; 33-93
static UINT16 l_6g_eu_channel[SCAN_6G_EU_CHANNEL_NUM] = {0x5025, 0x5035, 0x5045, 0x5055};

extern int fap_oui_update_status;
extern int re_oui_update_status;

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

static int _check_invalid_bssid(struct ether_addr ea)
{
    const struct ether_addr ether_zero = {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
    const struct ether_addr ether_bcast = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }};
    const struct ether_addr ether_hack = {{ 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 }};

    if (!memcmp(&ea, &ether_zero, sizeof(struct ether_addr))) {
        return -1;
    }
    else if (!memcmp(&ea, &ether_bcast, sizeof(struct ether_addr))) {
        return -1;
    }
    else if (!memcmp(&ea, &ether_hack, sizeof(struct ether_addr))) {
        return -1;
    }

    return AWND_OK; 
}

static int _wifi_exec_cmd(INT8* cmd, ...)
{
    char buf[1024] = {0};
    va_list vaList;

    va_start (vaList, cmd);
    vsprintf (buf, cmd, vaList);
    va_end (vaList);
    
    TP_SYSTEM(buf);
    AWN_LOG_WARNING("wifi cmd(%s)", buf);

    return AWND_OK;
}

static int _wl_restart(const char* ifname)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, sizeof(cmdline), "wl -i %s down; wl -i %s up &", ifname, ifname);
    _wifi_exec_cmd(cmdline);

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

/*************************************************
 *  eth addr to string 00:11:22:33:44:55
 * ************************************************/
char *
_wl_ether_etoa(const struct ether_addr *n)
{
	static char etoa_buf[IEEE80211_ADDR_LEN * 3];
	char *c = etoa_buf;
	int i;

    memset(etoa_buf, 0, sizeof(etoa_buf));
	for (i = 0; i < IEEE80211_ADDR_LEN; i++) {
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", n->octet_t[i] & 0xff);
	}
	return etoa_buf;
}

static int _wl_driver_ioctl(void *wl, wl_ioctl_t *ioc)
{
    struct ifreq *ifr = (struct ifreq *) wl;
    int ret;

    ifr->ifr_data = (caddr_t)ioc;
    ret = ioctl(getsocket(), SIOCDEVPRIVATE, ifr);

    return ret;
}


static int _wl_ioctl(void *wl, int cmd, void *buf, int len, BOOL set)
{
    wl_ioctl_t ioc;
    int ret;

    /* do it */
    ioc.cmd = cmd;
    ioc.buf = buf;
    ioc.len = len;
    ioc.set = set;

    ret = _wl_driver_ioctl(wl, &ioc);
    if (ret < 0) {
        AWN_LOG_INFO("wl_driver_ioctl cmd(%d 0x%x) fail ret=%d", cmd, cmd, ret);
    }

    return ret;
}

int _wl_get(void *wl, int cmd, void *buf, int len)
{
    int error = 0;
    error = _wl_ioctl(wl, cmd, buf, len, FALSE);
    return error;
}

int _wl_set(void *wl, int cmd, void *buf, int len)
{
    int error = 0;
    error = _wl_ioctl(wl, cmd, buf, len, TRUE);
    return error;
}

static int _wl_get_channel(const INT8 *ifname, int *channel)
{
    int ret = AWND_OK;
    channel_info_t ci;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    int retry_cnt = 0;

    memset(&ci, 0, sizeof(ci));
    ret = _wl_get(&ifr, WLC_GET_CHANNEL, &ci, sizeof(channel_info_t));
    if (ret < 0) {
        AWN_LOG_ERR("%s get channel fail", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

    if (ci.scan_channel) {
        AWN_LOG_INFO("%s Scan in progress. current scan channel\t%d", ifname, ci.scan_channel);
        ret = AWND_BUSY;
    }
    else {
        AWN_LOG_DEBUG("%s: current mac channel\t%d. target channel\t%d",
        ifname, ci.hw_channel, ci.target_channel);
        *channel = ci.target_channel;
    }

leave:
    return ret;
}

/******************************************************************
 * channel to chanspec for 20M.
 * 24G 0x1000 + channel
 * 5G  0xd000 + channel
 * 6G  0x5000 + channel
 * ****************************************************************/
static UINT16 _channel_to_chanspec(AWND_BAND_TYPE band, int channel)
{
    UINT16 chanspec = 0;
    AWND_BAND_TYPE real_band = _get_real_band_type(band);

    if (channel <= 0) {
        return 0;
    }

    switch (real_band)
    {
        case AWND_REAL_BAND_2G:
            chanspec = 0x1000 + channel;
            break;
        case AWND_REAL_BAND_5G:
        case AWND_REAL_BAND_5G2:
            chanspec = 0xd000 + channel;
            break;
        case AWND_REAL_BAND_6G:
        case AWND_REAL_BAND_6G2:
            chanspec = 0x5000 + channel;
            break;
        default:
            chanspec = channel;
            break;
    }

    return chanspec;
}

/******************************************************************
 * set channel only will not take effect.
 * to becomme effective: wl -i wl0 down; wl channel 40; wl -i wl0 up
 * all bss for this band will be down/up
 * ****************************************************************/
static int _wl_set_channel(const char* ifname, int channel)
{
    int ret = AWND_OK;
    channel_info_t ci;
    struct ifreq ifr;
    int pre_channel = 0;

    if (AWND_OK == _wl_get_channel(ifname, &pre_channel)) {
        if (pre_channel == channel) {
            AWN_LOG_INFO("%s:no need to set channel", ifname);
            goto done;
        }
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    memset(&ci, 0, sizeof(ci));
    ci.target_channel = channel;

    _wl_set(&ifr, WLC_DOWN, NULL, 0);

    ret = _wl_set(&ifr, WLC_SET_CHANNEL, &ci.target_channel, sizeof(int));
    if (ret < 0) {
        AWN_LOG_ERR("%s:set channel fail", ifname);
    }

    _wl_set(&ifr, WLC_UP, NULL, 0);

done:
    return ret;
}


#define CHANSPEC_BUF_LEN  64
#define UPER_CHANNEL_NUM  17
#define BELOW_CHANNEL_NUM 20
static int _get_chanspec(UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw, UINT8 *chanspec)
{
    int idx = 0;
    UINT8 has_get = 0;
    UINT8 uper_channel[UPER_CHANNEL_NUM] = { 1, 2, 3, 4, 5, 36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157};
    UINT8 below_channel[BELOW_CHANNEL_NUM] = { 6, 7, 8, 9, 10, 11, 12, 13, 40, 48, 56, 64, 104, 112, 120, 128,
                     136, 144, 153, 161 };

    if (0 == channel || wifi_bw > WIFI_BW_160M ||
        (WIFI_BW_160M == wifi_bw && channel > 128)) {
        AWN_LOG_ERR("bad parameter channel:%u bw:%u to get chanspec", channel, wifi_bw);
        return AWND_ERROR;
    }

    if (165 == channel) {
        /* only has HT20 */
        snprintf(chanspec, CHANSPEC_BUF_LEN, "%u", channel);
        return AWND_OK;
    }

    switch (wifi_bw)
    {
        case WIFI_BW_160M:
            snprintf(chanspec, CHANSPEC_BUF_LEN, "%u/160", channel);
            break;
        case WIFI_BW_80M:
            snprintf(chanspec, CHANSPEC_BUF_LEN, "%u/80", channel);
            break;
        case WIFI_BW_40M:
            for (idx = 0; idx < UPER_CHANNEL_NUM; idx ++)
            {
                if (channel == uper_channel[idx]) {
                    snprintf(chanspec, CHANSPEC_BUF_LEN, "%ul", channel);
                    has_get = 1;
                    break;
                }
            }

            for (idx = 0; 0 == has_get && idx < BELOW_CHANNEL_NUM; idx ++)
            {
                if (channel == below_channel[idx]) {
                    snprintf(chanspec, CHANSPEC_BUF_LEN, "%uu", channel);
                    break;
                }
            }
            break;
        case WIFI_BW_20M:
        default:
            snprintf(chanspec, CHANSPEC_BUF_LEN, "%u", channel);
            break;
    }

    return AWND_OK;
}

/**************************
 *  set/del TPIE
 
vndr_tpie
vndr_ie_setbuf_t {
    uchar cmd[4]; add/del
    vndr_ie_buffer {
        int iecount;
        vndr_ie_list[0] {
            int pktflag;
            vndr_ie_data {
                uchar id;
                uchar len;
                uchar oui [3];
                uchar data [1];	
            }
        }
    }
}

 * ***********************/

static int _wl_vndr_tpie(void *wl, const char *command, UINT8 *buf, int len)
{
    UINT8 ie_set_buf[MAX_TP_IE_SET_BUF];
	tpie_setbuf_t *ie_buf;
    bcm_tpie_t *ie_data;
    int cmd_len = 0;
    int buf_len = 0;
	int ret = 0;

    memset(ie_set_buf, 0, MAX_TP_IE_SET_BUF);
    cmd_len = strlen("vndr_tpie") + 1;
    strncpy(ie_set_buf, "vndr_tpie", cmd_len - 1);
    buf_len += cmd_len;

    ie_buf = (tpie_setbuf_t *) &ie_set_buf[cmd_len];
	strncpy(ie_buf->cmd, command, VNDR_IE_CMD_LEN - 1);
	ie_buf->cmd[VNDR_IE_CMD_LEN - 1] = '\0';

    if (buf && len) {
        ie_buf->vndr_ie_buffer.iecount = 1;
        ie_buf->vndr_ie_buffer.vndr_ie_list[0].pktflag = 0;
        ie_data = &ie_buf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data;
        buf_len += VNDR_IE_HD_LEN;
        if (len > IEEE80211_MAX_TP_IE) {
            len = IEEE80211_MAX_TP_IE;
        }

        if (buf[1] != (len - 2)) {
            AWN_LOG_INFO("buf len error: len(%d) should be (buf len(%d) - 2), to correct it", buf[1], len);
            buf[1] = (len - 2);
        }

        memcpy((void *)ie_data, buf, len);
        buf_len += len;
        AWN_LOG_DEBUG("========add=============== buf_len = %d", buf_len);
        ret = _wl_set(wl, WLC_SET_VAR, &ie_set_buf[0], buf_len);
    }
    else if (!buf) {
        buf_len += VNDR_IE_HD_LEN;
        AWN_LOG_DEBUG("========del=============== buf_len = %d", buf_len);
        ret = _wl_set(wl, WLC_SET_VAR, &ie_set_buf[0], buf_len);
    }

	return ret;
}


static int _wl_update_tpie(const char* ifname, UINT8 *buf, int len)
{
    int ret = 0;
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = _wl_vndr_tpie(&ifr, "add", buf, len);
    if (ret < 0) {
        AWN_LOG_ERR("%s:set tpie fail", ifname);
    }

    return ret;
}

static int _wl_del_tpie(const char* ifname)
{
    int ret = 0;
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = _wl_vndr_tpie(&ifr, "del", NULL, 0);
    if (ret < 0) {
        AWN_LOG_ERR("%s:set channel fail", ifname);
    }

    return ret;
}

/**************************
 *  get connected status 
 * ***********************/

static int _wl_get_assoclist(const char* ifname)
{
    int ret = 0;
    UINT8 buf[WLC_IOCTL_MEDLEN] = {0};
    struct maclist *maclist = (struct maclist *) buf;
    uint i, max = (WLC_IOCTL_MEDLEN - sizeof(int)) / IEEE80211_ADDR_LEN;
    struct ifreq ifr;
    struct ether_addr *ea;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    maclist->count = max;
    if ((ret = _wl_get(&ifr, WLC_GET_ASSOCLIST, maclist, WLC_IOCTL_MEDLEN)) < 0) {
        AWN_LOG_ERR("%s:set channel fail", ifname);
        goto exit;
    }

    //for (i = 0, ea = maclist->ea; i < maclist->count && i < max; i++, ea++) {
    //    AWN_LOG_ERR("%s %s\n", ifname, _wl_ether_etoa(ea));
    //}

exit:
    return ret;
}

/* get bss info */
static int _wl_get_rootap_info(void *wl, struct ether_addr *bssid)
{
    int ret = AWND_ERROR;
    char *buf = NULL;
    wl_bss_info_t *bi;

    buf = malloc(WLC_IOCTL_MEDLEN);
    if(!buf)
    {
        AWN_LOG_ERR("%s,MALLOC buff failed!\n",__FUNCTION__);
        goto leave;
    }

    memset(buf, 0, WLC_IOCTL_MEDLEN);
    *(UINT32*)buf = (UINT32)(WLC_IOCTL_MEDLEN);
    if (_wl_get(wl, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MEDLEN) < 0) {
        AWN_LOG_ERR("get bss info error");
        goto leave;
    }

    memset(bssid, 0, sizeof(struct ether_addr));
    bi = (wl_bss_info_t*)(buf + 4);
    if (bi->version == WL_BSS_INFO_VERSION ||
            bi->version == LEGACY2_WL_BSS_INFO_VERSION ||
            bi->version == LEGACY_WL_BSS_INFO_VERSION) {

        AWN_LOG_DEBUG("BSSID:%02X:%02X:%02X:%02X:%02X:%02X",
            bi->BSSID.octet_t[0], bi->BSSID.octet_t[1], bi->BSSID.octet_t[2],
            bi->BSSID.octet_t[3], bi->BSSID.octet_t[4], bi->BSSID.octet_t[5]);

        if (AWND_OK == _check_invalid_bssid(bi->BSSID)) {
            memcpy(bssid, &bi->BSSID, sizeof(struct ether_addr));
            ret = AWND_OK;
        }
        else {
            AWN_LOG_INFO(":BSSID is invaild");
        }
    }

leave:
    if(buf)
        free(buf);

    return ret;
}

/* get connect status with rootap */
static int _wl_get_conn_status(const char* ifname, UINT8 *conn)
{
    int ret = AWND_ERROR;
    char *buf = NULL;
    sta_info_t sta;
    struct ifreq ifr;
    struct ether_addr  bssid;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    *conn = 0;
    if (AWND_OK != _wl_get_rootap_info(&ifr, &bssid)) {
        AWN_LOG_DEBUG("%s:get rootap bssid error", ifname);
        goto leave;
    }

    memset(&sta, 0, sizeof(sta_info_t));
    buf = (char *)(&sta);
    strcpy(buf, "sta_info");
    memcpy(buf + strlen(buf) + 1, (char*)&bssid, ETHER_ADDR_LEN);

    if ((ret = _wl_get(&ifr, WLC_GET_VAR, buf, sizeof(sta_info_t))) < 0) {
        AWN_LOG_ERR("%s:get sta_info error", ifname);
        goto leave;
    }

    ret = AWND_OK;
    AWN_LOG_DEBUG("%s:get sta info:%x", ifname, sta.flags);
    if ((sta.flags & WL_STA_ASSOC) && (sta.flags & WL_STA_AUTHE) &&
        (sta.flags & WL_STA_AUTHO)
        /* && (sta.flags & WL_STA_DWDS_CAP) && (sta.flags & WL_STA_DWDS) */) {
        AWN_LOG_DEBUG("%s:STA is assoc with rootap", ifname);
       *conn = 1;
    }

    if (sta.flags & WL_STA_DWDS_CAP) {
        AWN_LOG_DEBUG("%s:WL_STA_DWDS_CAP", ifname);
    }

    if (sta.flags & WL_STA_DWDS) {
        AWN_LOG_DEBUG("%s:WL_STA_DWDS", ifname);
	}

leave:
    return ret;
}


static int _wl_get_rate(void *wl, UINT16 *txrate, UINT16 *rxrate, INT32 *rssi)
{
    int ret = AWND_ERROR;
    bss_peer_list_info_t *info;
    bss_peer_info_t *peer_info;
    bss_peer_info_param_t param;
    int err, i, param_len;
    char *buf = NULL;

    buf = malloc(WLC_IOCTL_MEDLEN);
    if(!buf)
    {
        AWN_LOG_ERR("MALLOC buff failed!\n");
        goto leave;
    }

    param_len = sizeof(bss_peer_info_param_t);
    memset(&param, 0, param_len);
    param.version = BSS_PEER_INFO_PARAM_CUR_VER;

    memset(buf, 0, WLC_IOCTL_MEDLEN);
    strcpy(buf, "bss_peer_info");
    memcpy(buf + strlen(buf) + 1, &param, param_len);

    if ((ret = _wl_get(wl, WLC_GET_VAR, buf, WLC_IOCTL_MEDLEN)) < 0) {
        AWN_LOG_ERR("get bss_peer_info error");
        goto leave;
    }

    info = (bss_peer_list_info_t*)buf;
    AWN_LOG_DEBUG("info->count=%d", info->count);
    for (i = 0; i < info->count; i++) {
        peer_info = &info->peer_info[i];
        AWN_LOG_DEBUG("PEER%d: RSSI %d TxRate %d kbps RxRate %d kbps age : %ds\r",
            i, peer_info->rssi, peer_info->tx_rate,
            peer_info->rx_rate, peer_info->age);

        *txrate = peer_info->tx_rate/1000;
        *rxrate = peer_info->rx_rate/1000;

        if (peer_info->rssi <= -95) {
		    *rssi = 0;
	    }
	    else if (peer_info->rssi <= 0) {
		    *rssi = peer_info->rssi + 95;
	    }
	    else {
		    *rssi = 95;
	    }
        ret = AWND_OK;
    }

leave:
    if (buf)
        free(buf);
    return ret;
}


/***************************************************************
    _check_dfs_status: check scan is available
    AWND_OK: get dfs status success and state is ISM/IDLE
    AWND_ERROR: malloc/_wl_get fail or state is not ISM/IDLE
***************************************************************/
static int _check_dfs_status(AWND_BAND_TYPE band)
{
    char *buf = NULL;
    struct ifreq ifr;
    wl_dfs_status_t *dfs_status;
    UINT32 dfs_cac = 0;
    int ret = AWND_ERROR;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, l_awnd_config.apIfnames[band], IFNAMSIZ);

    buf = malloc(WLC_IOCTL_SMLEN);
    if(!buf)
    {
        AWN_LOG_ERR("MALLOC buff failed!\n");
        return ret;
    }

    /* to fix diver BUG: non dfs chanspec but dfs_status is CAC
        1) wl dfs_cac: 0 cac is doing; 1 no cac
        2) to get dfs_status if get dfs_cac fail
    */
    memset(buf, 0, WLC_IOCTL_SMLEN);
    strcpy(buf, "dfs_cac");
    if (_wl_get(&ifr, WLC_GET_VAR, buf, WLC_IOCTL_SMLEN) < 0) {
        AWN_LOG_WARNING("%s get dfs cac error; to get dfs_status", l_awnd_config.apIfnames[band]);

        memset(buf, 0, WLC_IOCTL_SMLEN);
        strcpy(buf, "dfs_status");
        if (_wl_get(&ifr, WLC_GET_VAR, buf, WLC_IOCTL_SMLEN) < 0) {
            AWN_LOG_ERR("%s get dfs status error", l_awnd_config.apIfnames[band]);
            goto leave;
        }

        dfs_status = (wl_dfs_status_t *)(buf);
        AWN_LOG_INFO("%s get dfs status: %u", l_awnd_config.apIfnames[band], dfs_status->state);
        if (WL_DFS_CACSTATE_PREISM_CAC != dfs_status->state && WL_DFS_CACSTATE_POSTISM_CAC != dfs_status->state) {
            ret = AWND_OK;
        }
    }
    else {
        dfs_cac = *(UINT32 *)(buf);
        AWN_LOG_INFO("%s get dfs cac: %u.", l_awnd_config.apIfnames[band], dfs_cac);
        if (!dfs_cac) {
            ret = AWND_OK;
        }
    }

leave:
    if(buf)
        free(buf);
    return ret;
}


/**************************
 *  scan 
 * ***********************/

static void _set_wifi_scan_flag()
{
    char cmdline[CMDLINE_LENGTH] = {0};

    if (access(WIFI_SCAN_RUNNING_FILE, 0))
    {
        snprintf(cmdline, sizeof(cmdline), "touch %s", WIFI_SCAN_RUNNING_FILE);
        system(cmdline);
    }
}

static void _clear_wifi_scan_flag()
{
    char cmdline[CMDLINE_LENGTH] = {0};

    if (0 == access(WIFI_SCAN_RUNNING_FILE, 0))
    {
        snprintf(cmdline, sizeof(cmdline), "rm %s", WIFI_SCAN_RUNNING_FILE);
        system(cmdline);
    }
}


static int
_wl_scan_prep(BCM_SCAN_TYPE scan_type, wlc_ssid_t *ssid, int channel_num, UINT16 *channel_list,
    INT32 active_time, INT32 passive_time, void *params, int *params_size, UINT16 version)
{
	int ret = 0;
	int i = 0;
    wl_scan_params_t *params_v1 = (wl_scan_params_t *)params;
    wl_scan_params_v2_t *params_v2 = NULL;
    if (version == WL_SCAN_VERSION_MAJOR_V2) {
        params_v2 = (wl_scan_params_v2_t *)params;
    }

	memset(&params_v1->ssid, 0, sizeof(wlc_ssid_t));
    if (ssid) {
        memcpy(&params_v1->ssid, ssid, sizeof(wlc_ssid_t));
    }
	memcpy(&params_v1->bssid, &ether_bcast, IEEE80211_ADDR_LEN);
	params_v1->bss_type = DOT11_BSSTYPE_ANY;
	params_v1->scan_type = 0;  /* default ACTIVE */
	params_v1->nprobes = -1;
	params_v1->active_time = active_time;  /* default 40 */
	params_v1->passive_time = passive_time;    /* default 110 */
	params_v1->home_time = WLC_SCAN_HOME_TIME; /* default 45 */

    switch(scan_type) {
        case BCM_SCAN_ACTIVE:
            //params_v1->scan_type = -1; /* default -1 */
            /* do nothing - scan_type is initialized outside of while loop */
            break;
        case BCM_SCAN_PASSIVE:
            params_v1->scan_type |= WL_SCANFLAGS_PASSIVE;
            break;
        case BCM_SCAN_PROHIBITED:
            params_v1->scan_type |= WL_SCANFLAGS_PROHIBITED;
            break;
        case BCM_SCAN_OFFCHAN:
            params_v1->scan_type |= WL_SCANFLAGS_OFFCHAN;
            break;
        case BCM_SCAN_HOTSPOT:
            params_v1->scan_type |= WL_SCANFLAGS_HOTSPOT;
            break;
        case BCM_SCAN_LOW_PRIO:
            params_v1->scan_type |= WL_SCANFLAGS_LOW_PRIO;
            break;
        default:
            AWN_LOG_CRIT("invaild scan type:%d", scan_type);       
            break;
    }

    if (g_awnd.bindStatus != AWND_BIND_OVER)
    {
        params_v1->scan_type = DOT11_SCANTYPE_ACTIVE;  /*ACTIVE */
	params_v1->nprobes = 3;
    }

    if (version == WL_SCAN_VERSION_MAJOR_V2) {
        params_v2->channel_num = channel_num;  /* default 0 */
        if (channel_num > 0) {
            memcpy(&(params_v2->channel_list[0]), channel_list, channel_num * sizeof(UINT16));
        }
        *params_size = WL_SCAN_PARAMS_FIXED_SIZE_V2 + channel_num * sizeof(UINT16);
    } else {
        params_v1->channel_num = channel_num;  /* default 0 */
        if (channel_num > 0) {
            memcpy(&(params_v1->channel_list[0]), channel_list, channel_num * sizeof(UINT16));
        }
    }

	return ret;
}


static int _wl_scan(const char* ifname, BCM_SCAN_TYPE scan_type, wlc_ssid_t *ssid, int channel_num, UINT16 *channel_list)
{
    struct ifreq ifr;
    UINT8 buf[WLC_IOCTL_MAXLEN] = {0};
	int params_size; //support WL_NUMCHANNELS channel
    wl_scan_version_t *ver;
    UINT16 version = 0;
	void *params;
	int ret = 0;
    int retry_times = 0;
    int org_scan_time = 20; /* default 20 */
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    //only support one spec ssid
	//params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);

    /* Get scan version */
    strcpy(buf, "scan_ver");

    _wl_get(&ifr, WLC_GET_VAR, buf, WLC_IOCTL_MAXLEN);
    ver = (wl_scan_version_t *)buf;
    if (ver->scan_ver_major == WL_SCAN_VERSION_MAJOR_V2) {
        params_size = WL_SCAN_PARAMS_FIXED_SIZE_V2 + WL_NUMCHANNELS * sizeof(UINT16);
        version = WL_SCAN_VERSION_MAJOR_V2;
    } else {
        params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(UINT16);
    }
	params = malloc(params_size);
	if (params == NULL) {
		AWN_LOG_ERR("Error allocating %d bytes for scan params", params_size);
		return -1;
	}
	memset(params, 0, params_size);

#if 0
    _wl_get(&ifr, WLC_GET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
    if (org_scan_time < SCAN_CHANNEL_TIME) {
        org_scan_time = SCAN_CHANNEL_TIME;
        _wl_set(&ifr, WLC_SET_SCAN_CHANNEL_TIME, &org_scan_time, sizeof(org_scan_time));
    }
#endif

	_wl_scan_prep(scan_type, ssid, channel_num, channel_list, SCAN_CHANNEL_TIME,
        SCAN_PASSIVE_TIME, params, &params_size, version);

retry:
    ret = _wl_set(&ifr, WLC_SCAN, params, params_size);
    if (ret < 0) {
        if (retry_times++ < SCAN_RETRY_TIMES) {
            AWN_LOG_INFO("%s:set WLC_SCAN(%d) error:%d retry %d", ifname, WLC_SCAN, ret, retry_times);
            usleep(300*1000);
            goto retry;
        }
    }

	free(params);
    return ret;
}

static int _wl_scan_active(const char* ifname)
{
    if (_wl_scan(ifname, BCM_SCAN_ACTIVE, NULL, 0, NULL) < 0) {
        AWN_LOG_INFO("%s:set error", ifname);
        return AWND_ERROR;
    }
    return AWND_OK;
}

static int _wl_scan_passive(const char* ifname)
{
    if (_wl_scan(ifname, BCM_SCAN_PASSIVE, NULL, 0, NULL) < 0) {
        AWN_LOG_INFO("%s:set error", ifname);
        return AWND_ERROR;
    }
    return AWND_OK;
}

/* scan spec channel */
static int _wl_scan_chanspec(const char* ifname, int channel_num, UINT16 *channel_list)
{
    if (_wl_scan(ifname, BCM_SCAN_PASSIVE, NULL, channel_num, channel_list) < 0) {
        AWN_LOG_ERR("%s: set error channel_num:%d", ifname, channel_num);
        return AWND_ERROR;
    }
    return AWND_OK;
}

/* scan spec SSID */
static int _wl_scan_SSIDspec(const char* ifname, int SSID_len, UINT8 *SSID)
{
    wlc_ssid_t ssid;
    memset(&ssid, 0, sizeof(wlc_ssid_t));

    ssid.SSID_len = SSID_len;
    memcpy(ssid.SSID, SSID, SSID_len);
    if (_wl_scan(ifname, BCM_SCAN_ACTIVE, NULL, 0, NULL) < 0) {
        AWN_LOG_ERR("%s:set error", ifname);
        return AWND_ERROR;
    }
    return AWND_OK;
}

int _start_scan_single_band(AWND_BAND_TYPE band)
{
#define SPECIFIED_CHANNEL_SCAN  1
    INT8 ifname[IFNAMSIZ] = {0};
    int ret = AWND_OK;
    AWND_BAND_TYPE real_band = _get_real_band_type(band);

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);

#if SPECIFIED_CHANNEL_SCAN

    switch (real_band)
    {
        case AWND_REAL_BAND_2G:
        ret = _wl_scan_passive(ifname);
            break;
        case AWND_REAL_BAND_5G:
        if(l_awnd_config.band_num == AWND_BAND_NUM_3 && !l_awnd_config.sp6G)
        {
            ret = _wl_scan_chanspec(ifname, SCAN_BAND1_CHANNEL_NUM, l_band1_channel);
        }
        else
        {
            /* to scan special channels according to country. EU/JP: band1; US/CA: band1/4. */
            if (AWND_COUNTRY_EU == l_awnd_config.country || AWND_COUNTRY_JP == l_awnd_config.country) {
                ret = _wl_scan_chanspec(ifname, SCAN_BAND1_CHANNEL_NUM, l_band1_channel);
            }
            else {
                ret = _wl_scan_chanspec(ifname, SCAN_BAND1_BAND4_CHANNEL_NUM, l_band1_band4_channel);
            }
        }
            break;
        case AWND_REAL_BAND_5G2:
#if CONFIG_5G2_BAND3_BAND4_SUPPORT
            ret = _wl_scan_passive(ifname);
#else
        /* to scan special channels according to country */
        if (AWND_COUNTRY_EU == l_awnd_config.country || AWND_COUNTRY_JP == l_awnd_config.country) {
                ret = _wl_scan_chanspec(ifname, SCAN_BAND3_CHANNEL_NUM, l_band3_channel);
        }
        else {
            ret = _wl_scan_chanspec(ifname, SCAN_BAND4_CHANNEL_NUM, l_band4_channel);
        }
#endif //CONFIG_5G2_BAND3_BAND4_SUPPORT
            break;

        case AWND_REAL_BAND_6G:
            if (AWND_COUNTRY_EU == l_awnd_config.country || AWND_COUNTRY_JP == l_awnd_config.country) {
                ret = _wl_scan_chanspec(ifname, SCAN_6G_EU_CHANNEL_NUM, l_6g_eu_channel);
            }
            else {
                ret = _wl_scan_chanspec(ifname, SCAN_6G_CHANNEL_NUM, l_6g_all_channel);
            }
            break;
        case AWND_REAL_BAND_6G2:
            /* to be done */
            break;
        default:
            AWN_LOG_ERR("%s:Unknown band %d", ifname, real_band);
            break;
    }

#else /* SPECIFIED_CHANNEL_SCAN */
    ret = _wl_scan_passive(ifname);
#endif /* SPECIFIED_CHANNEL_SCAN 0 */

    return ret;
}

int _fast_scan_single_channel(AWND_BAND_TYPE band)
{
    int channel = 0;
    INT8 ifname[IFNAMSIZ] = {0};
    UINT16 channel_list[10] = {0};
    int ret = AWND_OK;

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
    if ((AWND_OK != _wl_get_channel(ifname, &channel)) || (0 == channel))
    {
        AWN_LOG_WARNING("band:%s get channel:%d fail", ifname, channel);
        goto done;
    }

    AWN_LOG_DEBUG("band:%s get channel:%d success", ifname, channel);
    channel_list[0] = _channel_to_chanspec(band, channel);
    if (_wl_scan_chanspec(ifname, 1, channel_list)) {
        AWN_LOG_WARNING("%s: scan spec channel:%d fail", ifname, channel);
        ret = AWND_ERROR;
    }

done:
    AWN_LOG_DEBUG("outting...");
    return ret;
}

static int _flush_scan_table(AWND_BAND_TYPE band, BOOL force)
{
    struct ifreq ifr;
    int params_size = WL_TP_FLUSH_SCAN_RESULT_SIZE;
    tp_flush_scan_result_t *params;
    int ret = AWND_OK;
    INT8 ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
#if CONFIG_WIFI_DFS_SILENT
#if CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1
    if ((FALSE == force) && (AWND_BAND_5G == band) && (AWND_ERROR == _check_dfs_status(AWND_BAND_5G))) {
        AWN_LOG_WARNING("%s CAC not flush scan result", ifname);
        return AWND_ERROR;
    }
#endif /* CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1 */
#if CONFIG_WIFI_DFS_SILENT_5G2
    if ((l_awnd_config.band_num == AWND_BAND_NUM_3) &&(FALSE == force) && 
        (l_awnd_config.band_5g2_type == band) && 
        (AWND_ERROR == _check_dfs_status(l_awnd_config.band_5g2_type))) {
        AWN_LOG_WARNING("%s CAC not flush scan result", ifname);
        return AWND_ERROR;
    }
#endif /* CONFIG_WIFI_DFS_SILENT_5G2 */
#endif /* CONFIG_WIFI_DFS_SILENT */

#if SCAN_OPTIMIZATION
    if (0 != g_awnd.scan_band_success_mask){
        AWN_LOG_WARNING("%s is scanning. scan_band_success_mask = %d, not flush scan result", ifname, g_awnd.scan_band_success_mask);
        return AWND_BUSY;
    }
#endif
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    params = (tp_flush_scan_result_t *)malloc(params_size);
    if (params == NULL) {
        AWN_LOG_ERR("Error allocating %d bytes for scan params", params_size);
        return AWND_ERROR;
    }

    memset(params, 0, params_size);
    params->cmd = 1;
    ret = _wl_set(&ifr, WLC_TP_FLUSH_SCAN_RESULTS, params, params_size);
    if (ret < 0) {
        AWN_LOG_WARNING("%s: flush scan table error", ifname);
        ret = AWND_ERROR;
    } else {
        AWN_LOG_WARNING("%s flush scan result", ifname);
    }

    free(params);
    return ret;
}


/**************************
 *  get scan result 
 * ***********************/

#define SCAN_NOTFOUND_NUM 10
int _get_tpie_from_scan_results(void *wl, UINT8 *pMac, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band, UINT8 *rootap_rssi)
{
    UINT8 buf[WLC_IOCTL_MAXLEN] = {0};
    INT8 ssid[AWND_MAX_SSID_LEN] = {0};
    tp_scan_result_t *scan_result;
    bcm_scan_result_entry_t *sr;
    int ret = 0;
    int buf_len = 0;
    int status = 0;
    int entry_cnt = 0;
    UINT8* cp = NULL;
    int len = 0;
    AWND_AP_ENTRY pCurApEntry;
    UINT8* vp = NULL;
    int entry_found = 0;
    static UINT8 notfound_cnt[AWND_BAND_MAX] = {0};

    memset(buf, 0, WLC_IOCTL_MAXLEN);
    if ((ret = _wl_get(wl, WLC_TP_STORE_SCAN_RESULTS, buf, WLC_IOCTL_MAXLEN)) < 0) {
        AWN_LOG_DEBUG("band:%d get scan result fail ret=%d notfound_cnt=%d", band, ret, notfound_cnt[band]);

        if (BCME_NOTFOUND == ret) {
           /* results_state == WL_SCAN_RESULTS_ABORTED 
                should send scan commd to recovery */
            notfound_cnt[band] ++;
            if (notfound_cnt[band] >= SCAN_NOTFOUND_NUM) {
                notfound_cnt[band] = 0;
                AWN_LOG_ERR("band:%d get scan result BCME_NOTFOUND for %d times to set scan cmd to recovery", band, SCAN_NOTFOUND_NUM);
                _start_scan_single_band(band);
            }
        }
        else {
            notfound_cnt[band] = 0;
        }

        return AWND_ERROR;
    }

    scan_result = (tp_scan_result_t *) buf;
    buf_len = scan_result->buflen;
    entry_cnt = scan_result->count;
    status = scan_result->status;

    AWN_LOG_INFO("buf_len:%d entry_cnt:%d status:%d", buf_len, entry_cnt, status);
    if (entry_cnt < 1 || buf_len < sizeof(tp_scan_result_t)) {
        AWN_LOG_INFO("get scan entry is null");
        return AWND_NOT_FOUND;
    }

    len = buf_len - (sizeof(tp_scan_result_t) - sizeof(bcm_scan_result_entry_t));
    cp = (UINT8*) &scan_result->scan_entry[0];
    do {
        sr = (bcm_scan_result_entry_t *) cp;

        entry_found = 0;
        memset(&pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
        if (sr->bssid != NULL && 0 == memcmp(pMac, sr->bssid, IEEE80211_ADDR_LEN)) {
            entry_found = 1;
            memcpy(pCurApEntry.bssid, sr->bssid, IEEE80211_ADDR_LEN);
        }

        _copy_essid(ssid, sizeof(ssid), sr->ssid, sr->ssidLen);
        memcpy(pCurApEntry.ssid, ssid, strlen(ssid));
        pCurApEntry.ssid[sr->ssidLen] = 0; 

        if (0 == entry_found) {
            cp += sizeof(bcm_scan_result_entry_t), len -= sizeof(bcm_scan_result_entry_t);
            continue;
        }

        entry_found = 0;
        vp = (UINT8 *)&(sr->netInfo);
        if (sr->netInfo.len > 0) 
        {
            if (sr->netInfo.id == IEEE80211_ELEMID_VENDOR && istpoui(vp))
            {
                memcpy(&pCurApEntry.netInfo, vp, ((2+vp[1]) < sizeof(AWND_NET_INFO))? (2+vp[1]) : sizeof(AWND_NET_INFO));
                entry_found = 1;
            }
        }

        if (0 == entry_found) {
            AWN_LOG_DEBUG("=====right bssid but no tpie");
            return AWND_NOT_FOUND;
        }

        *rootap_rssi = sr->rssi;
        memcpy(pAwndNetInfo, &pCurApEntry.netInfo, sizeof(AWND_NET_INFO));
        memset(pAwndNetInfo->lan_mac, 0, AWND_MAC_LEN);
        pAwndNetInfo->uplink_mask = 0;
        pAwndNetInfo->uplink_rate = 0;
        pAwndNetInfo->awnd_lanip = ntohl(pAwndNetInfo->awnd_lanip);
        pAwndNetInfo->server_touch_time = ntohl(pAwndNetInfo->server_touch_time);       
        pAwndNetInfo->awnd_dns = ntohl(pAwndNetInfo->awnd_dns); 
        pAwndNetInfo->uplink_mask = LE_READ_2(&pAwndNetInfo->uplink_mask);
        pAwndNetInfo->uplink_rate = LE_READ_2(&pAwndNetInfo->uplink_rate);

        AWN_LOG_DEBUG("ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%d",
            pCurApEntry.ssid, pCurApEntry.bssid[0],pCurApEntry.bssid[1],pCurApEntry.bssid[2],
            pCurApEntry.bssid[3],pCurApEntry.bssid[4],pCurApEntry.bssid[5], sr->rssi);

        AWN_LOG_DEBUG("awnd_net_type:%-3d,awnd_level:%-2d, awnd_weight:%d, wait:%d, lanip:%x, dns:%x \
            server_detected:%d, server_touch_time:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",            
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level,
            pAwndNetInfo->awnd_weight, pAwndNetInfo->wait,
            pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],
            pAwndNetInfo->awnd_mac[2],pAwndNetInfo->awnd_mac[3],
            pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5]);

        return AWND_OK;
    } while(len >= sizeof(bcm_scan_result_entry_t));

    return AWND_NOT_FOUND;
}


/***************************************************************************
    int _wl_get_reinit_cnt(char *ifname, unsigned int *reinit)
func1
wl -i wl1 counters | grep reinit
reinit 13690
func2 wl -i wl1 reinit_cnt
***************************************************************************/
#if 0
static int _wl_get_reinit_cnt(char *ifname, unsigned int *reinit)
{
    char line[READ_LINE_LEN] = {0};
    char *s = NULL;    
    FILE *fp = NULL;
    char name[15] = {0};
    char reinit_cnt_str[24] = {0};
    char cmd[128] = {0};
    unsigned int reinit_cnt = 0;

    snprintf(cmd, sizeof(cmd),"wl -i %s counters | grep 'reinit '", ifname);
    
    fp = popen(cmd, "r");
    if (NULL == fp)
    {
        AWN_LOG_ERR("Failed to get stat info");
        return AWND_ERROR;
    }

    while (fgets(line, READ_LINE_LEN , fp) != NULL)
    {
        if (NULL != (s = strstr(line, "reinit")))
        {
            sscanf(s,"%s%s", name, reinit_cnt_str);
            sscanf(reinit_cnt_str, "%llu", &reinit_cnt);
        }
    }

    pclose(fp);

    *reinit = reinit_cnt;

    return AWND_OK;
}
#else

static int _wl_get_reinit_cnt(char *ifname, unsigned int *reinit)
{
    char *buf = NULL;
    UINT32 reinit_cnt = 0;
    struct ifreq ifr;
    int ret = AWND_OK;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    buf = malloc(WLC_IOCTL_SMLEN);
    if(!buf)
    {
        AWN_LOG_ERR("MALLOC buff failed!\n");
        return AWND_MALLOC_FAIL;
    }

    memset(buf, 0, WLC_IOCTL_SMLEN);
    strcpy(buf, "reinit_cnt");
    if (_wl_get(&ifr, WLC_GET_VAR, buf, WLC_IOCTL_SMLEN) < 0) {
        AWN_LOG_ERR("%s get reinit_cnt error", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

    reinit_cnt = (unsigned int)(*buf);
    AWN_LOG_DEBUG("%s get reinit cnt: %d", ifname, reinit_cnt);
    *reinit = reinit_cnt;

leave:
    if(buf)
        free(buf);
    return ret;
}
#endif

static int _get_wl_up_status(char *ifname, UINT8 *up)
{
    int is_up = 0;
    struct ifreq ifr;

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (_wl_get(&ifr, WLC_GET_UP, &is_up, sizeof(int)) < 0) {
        AWN_LOG_ERR("%s get up status fail");
        return AWND_ERROR;
    }

    *up = is_up;

    return AWND_OK;
}


static int _get_bss_up_status(char *ifname, UINT8 *up, AWND_BAND_TYPE band)
{
    int is_up = 0;
    char *buf = NULL;
    struct ifreq ifr;
    int ret = AWND_OK;
    int bsscfg_idx = 1; /* backhaul AP: wl01/wl21 */

    if (l_awnd_config.band_5g2_type == band || l_awnd_config.band_6g_type == band) {
        bsscfg_idx = 3; /* 6G backhaul AP: wl13 */
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    buf = malloc(WLC_IOCTL_SMLEN);
    if(!buf)
    {
        AWN_LOG_ERR("MALLOC buff failed!\n");
        return AWND_MALLOC_FAIL;
    }

    memset(buf, 0, WLC_IOCTL_SMLEN);
    strcpy(buf, "bss");
    memcpy(buf + strlen(buf) + 1, &bsscfg_idx, sizeof(int));
    if (_wl_get(&ifr, WLC_GET_VAR, buf, WLC_IOCTL_SMLEN) < 0) {
        AWN_LOG_ERR("%s get bss error", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

    is_up = *(int *)buf;
    AWN_LOG_DEBUG("%s get bss up: %d", ifname, is_up);
    *up = is_up;

leave:
    if(buf)
        free(buf);
    return ret;
}


/******************************************************************************
    restart wpa_supplicant for one band
    wpa_supplicant -i wlx -Dnl80211 -c /tmp/wlx_wpa_supplicant.conf -b br-lan
*******************************************************************************/
static int _wpa_supplicant_restart(AWND_BAND_TYPE band)
{
#define FILE_BUF_SIZE 32
    char buffer[FILE_BUF_SIZE] = {0};
    char cmd[CMDLINE_LENGTH] = {0};
    INT32 index = 0;
    INT32 sum = 0;
    pid_t pid;
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "ps | grep wpa_supplicant | grep -v grep | grep %s | awk \'{print $1}\'",
        l_awnd_config.staIfnames[band]);
    if ((fp = popen(cmd, "r")) == NULL)
    {
        perror("popen");
        AWN_LOG_ERR("Fail to popen %s.", cmd);
        return AWND_ERROR;
    }

    while (NULL != fgets(buffer, FILE_BUF_SIZE, fp))
    {
        sum = 0;
        index = 0;
        while (buffer[index] >= '0' && buffer[index] <= '9')
        {
            sum = sum*10 + buffer[index] - '0';
            index++;
        }
        pid = sum;

        kill(pid, SIGTERM);
        AWN_LOG_WARNING("kill process(%s), pid(%d).", cmd, pid);
    }
    pclose(fp);

    /* to start wpa_supplicant */
    memset(cmd, 0, CMDLINE_LENGTH);
    snprintf(cmd, sizeof(cmd), "wpa_supplicant -i %s -Dnl80211 -c /tmp/%s_wpa_supplicant.conf -b br-lan &",
                l_awnd_config.staIfnames[band], l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmd);

    return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
static int _proxy_l2uf_single_interface(const char *ifname)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    snprintf(cmdline, sizeof(cmdline), "wl -i %s iapp &", ifname);
    _wifi_exec_cmd(cmdline);
    return AWND_OK;
}
#endif

/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/


int get_default_mesh_channel_bcm(AWND_BAND_TYPE band, int *channel)
{
    INT8 ifname[IFNAMSIZ] = {0};
    char wl_filename[128] = {0};
    char acs_channel[128] = {0};

    /* backhaul is always up. default ap channel is the same with backhaul ap */
    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);


    snprintf(wl_filename, sizeof(wl_filename),"/tmp/acsd2_%s_channel", ifname);

    if(access(wl_filename, 0) == 0)
    {
        FILE *fp = NULL;
        fp = fopen(wl_filename, "r");
        if(fp != NULL)
        {
            fread(acs_channel,sizeof(acs_channel),1,fp); 
            if(acs_channel != NULL && atoi(acs_channel) != 0)
            {
                *channel = atoi(acs_channel);
                fclose(fp);
                return AWND_OK;
            }
            else
            {
                fclose(fp);
                return _wl_get_channel(ifname, channel); 
            }       
        }
    }  
    else
    {
        return _wl_get_channel(ifname, channel);
    }
}

int check_block_chan_list_bcm(AWND_BAND_TYPE band, int *channel)
{
    return AWND_ERROR;
}

int get_sta_channel_bcm(AWND_BAND_TYPE band, int *channel)
{
    INT8 ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), "%s", l_awnd_config.staIfnames[band]);

    return _wl_get_channel(ifname, channel);
}
int get_backhaul_ap_channel_bcm(AWND_BAND_TYPE band, int *channel)
{
    INT8 ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);

    return _wl_get_channel(ifname, channel);
}


int get_wifi_bw_bcm(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw)
{
#define READ_LINE_LEN 64
    FILE *fp = NULL;
    char *s = NULL;  
    char cmd[128] = {0};
    char line[READ_LINE_LEN] = {0};

    snprintf(cmd, sizeof(cmd), "wl -i %s chanspec", l_awnd_config.apIfnames[band]);
    fp = popen(cmd, "r");
    if (NULL == fp) {
        AWN_LOG_INFO("Failed to get %s chanspec", l_awnd_config.apIfnames[band]);
        return AWND_ERROR;
    }

    while (fgets(line, READ_LINE_LEN , fp) != NULL)
    {
        if (NULL != (s = strstr(line, "/160"))) {
            *wifi_bw = WIFI_BW_160M;
            break;
        }
        else if (NULL != (s = strstr(line, "/80"))) {
            *wifi_bw = WIFI_BW_80M;
            break;
        }
        else if ((NULL != (s = strstr(line, "l "))) || (NULL != (s = strstr(line, "u "))) ) {
            *wifi_bw = WIFI_BW_40M;
            break;
        }
        else{
            *wifi_bw = WIFI_BW_20M;
            break;
        }
    }
    AWN_LOG_DEBUG("%s get bw:%d", l_awnd_config.apIfnames[band], *wifi_bw);

    pclose(fp);

    return AWND_OK;
}

void set_wifi_bw_bcm(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    UINT8 chanspec[CHANSPEC_BUF_LEN] = {0};
    INT8 ifname[IFNAMSIZ] = {0};
    int cur_channel = 0;
    int idx = 0;

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
    if (0 == channel) {
        for (idx = 0; idx < 10; idx ++) {
            if (AWND_OK == _wl_get_channel(ifname, &cur_channel)) {
                channel = (UINT8) cur_channel;
                break;
            }
            usleep(200*1000);
        }
    }

    if ( AWND_ERROR == _get_chanspec(channel, wifi_bw, chanspec)) {
        return;
    }

    snprintf(cmdline, sizeof(cmdline), "wl -i %s down; wl -i %s chanspec %s; wl -i %s up &",
        ifname, ifname, chanspec, ifname);
    _wifi_exec_cmd(cmdline);
    return;
}

int get_phy_bcm(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth)
{
    INT8 ifname[IFNAMSIZ] = {0};
    struct ifreq ifr; 
    bcm_wlanconfig_phy_t config_phy;

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    memset(&config_phy, 0, sizeof(bcm_wlanconfig_phy_t));
    if (_wl_get(&ifr, WLC_TP_GET_PHY, &config_phy, sizeof(bcm_wlanconfig_phy_t))) {
        AWN_LOG_ERR("%s get phy fail", ifname);
        return AWND_ERROR;
    }

    /************************************************
        nss:1/2/3/4  cmd(wl -i wl0 txchain/rxchain)
        phyMode: 0:11g/a mode 1:11n 2:11ac
        chwidth:0/1/2/3 --> 20M/40M/80M/160M
    *************************************************/
    if (0 == config_phy.status) {
        if (15 == config_phy.nss) {
            *nss = 4;
        }
        else if (7 == config_phy.nss) {
            *nss = 3;
        }
        else if (3 == config_phy.nss) {
            *nss = 2;
        }
        else if (1 == config_phy.nss) {
            *nss = 1;
        }
        else {
            AWN_LOG_INFO("%s unexcpted nss(%d) nss set default(2)", ifname, config_phy.nss);
            *nss = 2;
        }

        if (config_phy.phyMode > wlan_phymode_he) {
           AWN_LOG_INFO("%s unexcpted phy mode:(%d) > wlan_phymode_he(%d) set default(11ax)",
            ifname, config_phy.phyMode, wlan_phymode_he); 
            *phyMode = wlan_phymode_he;
        }
        else {
            *phyMode = config_phy.phyMode;
        }

        if (15 == config_phy.chwidth) {
            *chwidth = 3;   /* 160M */
        }
        else if (7 == config_phy.chwidth) {
            *chwidth = 2;   /* 80M */
        }
        else if (3 == config_phy.chwidth) {
            *chwidth = 1;   /* 40M */
        }
        else if (1 == config_phy.chwidth) {
            *chwidth = 0;   /* 20M */
        }
        else {
            AWN_LOG_INFO("%s unexcpted chwidth(%d) ", ifname, config_phy.chwidth);
            if (band >= AWND_BAND_5G)
                *chwidth = 2;
            else
                *chwidth = 1;
        }
    }

    AWN_LOG_DEBUG("[awnd_get_phy]%s nss:%d, phyMode:%d, chwidth:%d ", ifname, *nss, *phyMode, *chwidth);
    return AWND_OK;
}

int get_wds_state_bcm(AWND_BAND_TYPE band, int *up)
{
    INT8 ifname[IFNAMSIZ] = {0};
    char type[16] = {};
    struct ifreq ifr; 
    bcm_conn_status_t conn_status;
    struct ether_addr  bssid;
    int ret = AWND_OK;
    UINT8 connect = 0;
    
    *up = 0;

    if (awnd_config_get_stacfg_type(band, type) == AWND_OK) {
        if (strcmp(type, "backup") == 0) {
            return 0;
        }
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    snprintf(ifname, sizeof(ifname), l_awnd_config.staIfnames[band]);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(getsocket(), SIOCGIFFLAGS, &ifr)< 0) {
        AWN_LOG_DEBUG("%s ioctl socket failed: SIOCGIFFLAGS", ifname);    
        return 0;
    }
    else if (!(ifr.ifr_flags & (IFF_UP | IFF_RUNNING))) {
        AWN_LOG_INFO("%s intface is not up", ifname);
        return 0;
    }

    *up = 1;

    //_wl_get_conn_status(ifname, &connect);
    if (AWND_OK != _wl_get_rootap_info(&ifr, &bssid)) {
        AWN_LOG_DEBUG("%s:get rootap bssid error means disconnected", ifname);
        ret = 0;
        goto leave;
    }

    memset(&conn_status, 0, sizeof(bcm_conn_status_t));
    if (_wl_get(&ifr, WLC_TP_STA_GET_CONN_STAT, &conn_status, sizeof(bcm_conn_status_t)) < 0) {
        AWN_LOG_DEBUG("%s get wds state failed", ifname);
        ret = 0;
        goto leave;
    }
    
    AWN_LOG_DEBUG("%s conn_status.wds_state=%d.", ifname, conn_status.wds_state);
    ret = (conn_status.wds_state == 1 ? 1 : 0);

leave:
    return ret;
}

/* get rootap's txrate/rxrate */
int get_rootap_phyRate_bcm(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate)
{
    INT8 ifname[IFNAMSIZ] = {0};
    struct ifreq ifr; 
    int ret = AWND_OK;
    INT32 rssi;

    snprintf(ifname, sizeof(ifname), l_awnd_config.staIfnames[band]);    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    *txrate = 0;
    *rxrate = 0;
    rssi = 0;
    if (AWND_OK != _wl_get_rate(&ifr, txrate, rxrate, &rssi)) {
        AWN_LOG_ERR("%s get rootap phyRate fail", ifname);
    }

    return ret;
}

int get_rootap_rssi_bcm(AWND_BAND_TYPE band, INT32 *rssi)
{
    INT8 ifname[IFNAMSIZ] = {0};
    struct ifreq ifr; 
    int ret = AWND_OK;
    UINT16 txrate, rxrate;

    snprintf(ifname, sizeof(ifname), l_awnd_config.staIfnames[band]);    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    txrate = 0;
    rxrate = 0;
    *rssi = 0;

    if (AWND_OK != _wl_get_rate(&ifr, &txrate, &rxrate, rssi)) {
        AWN_LOG_ERR("%s get rootap rssi fail", ifname);
    }

    return ret;
}

/* no use */
int get_rootap_info_bcm(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band)
{
    return AWND_OK;
}
/* no use */
int get_rootap_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    return AWND_OK;
}

/* get rootap's tpie */
int get_tpie_bcm(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    INT8 ifname[IFNAMSIZ] = {0};
    bcm_wlanconfig_tpie_t  wlanconfig_tpie;
    //struct ether_addr  bssid;
    struct ifreq ifr;
    int val = 0;
    int ret = AWND_OK;
    UINT8 rootap_rssi = 0;

    memset(&ifr, 0, sizeof(struct ifreq));
    snprintf(ifname, sizeof(ifname), l_awnd_config.staIfnames[band]);    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    /* disconnected: get tpie from scan entry */
    if (IEEE80211_TP_IE_IN_SCAN == entry_type) {
        return _get_tpie_from_scan_results(&ifr, pMac, pAwndNetInfo, band, &rootap_rssi);
    }

    /* connected: get tpie from rootap info */
#if 0
    memset(&bssid, 0, sizeof(struct ether_addr));
    if (AWND_OK != _wl_get_rootap_info(&ifr, &bssid)) {
        AWN_LOG_DEBUG("%s:get rootap bssid error means disconnected", ifname);
        ret = AWND_ERROR;
        goto leave;
    }
#endif

    memset(&wlanconfig_tpie, 0, sizeof(bcm_wlanconfig_tpie_t));
    /* set entry type and rootap's bssid:
    wlanconfig_tpie.entry_type = entry_type;
    memcpy(wlanconfig_tpie.tp_macaddr, pMac, ETHER_ADDR_LEN);
    */
    if(_wl_get(&ifr, WLC_TP_STA_GET_TPIE, &wlanconfig_tpie, sizeof(bcm_wlanconfig_tpie_t)) < 0) {
        AWN_LOG_ERR("%s get rootap tpie fail", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

    if (0 == wlanconfig_tpie.status && 1 == wlanconfig_tpie.conn_status) {
        AWN_LOG_DEBUG("%s get tpie success", ifname);
        memcpy(pAwndNetInfo, &wlanconfig_tpie.netInfo, sizeof(AWND_NET_INFO));
        memset(pAwndNetInfo->lan_mac, 0, AWND_MAC_LEN);
        pAwndNetInfo->uplink_mask = 0;
        pAwndNetInfo->uplink_rate = 0;
        pAwndNetInfo->awnd_lanip = ntohl(pAwndNetInfo->awnd_lanip);
        pAwndNetInfo->server_touch_time = ntohl(pAwndNetInfo->server_touch_time);       
        pAwndNetInfo->awnd_dns = ntohl(pAwndNetInfo->awnd_dns); 
        pAwndNetInfo->uplink_mask = LE_READ_2(&pAwndNetInfo->uplink_mask);
        pAwndNetInfo->uplink_rate = LE_READ_2(&pAwndNetInfo->uplink_rate);
    }
    else {
        AWN_LOG_DEBUG("%s disconnected with rootap", ifname);
        ret = AWND_ERROR;
        goto leave;
    }

leave:
    return ret;
}


int init_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType)
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
    AWN_LOG_ERR("Device's oui will be inited to 0x%x%x%x", pAwndNetInfo->oui[0], pAwndNetInfo->oui[1], pAwndNetInfo->oui[2]);
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

int update_wifi_tpie_bcm(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType)
{
    bcm_tpie_t *tp_net_info;
    u_int8_t ie_buf[256];
    INT8 ifname[IFNAMSIZ] = {0};
    AWND_NET_INFO  *ni = NULL;
    AWND_BAND_TYPE band;
    UINT8 len = 0;
    int ret = AWND_OK;
    UINT8* cp = NULL;
    int remove_ret = AWND_OK;

    if (NULL == pAwndNetInfo )
    {
        return AWND_ERROR;
    }

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {    
        /* fill up ifname */
        switch (meshType)
        {
            case AWND_MESH_BACKHUAL:
                snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
                break;
            case AWND_MESH_CONFIG:
                snprintf(ifname, sizeof(ifname), l_awnd_config.configIfnames[band]);
                break;
            default:
                AWN_LOG_ERR("Unknown mesh type:%d", meshType);
                break;
        }

        /* fill up configuration */
        memset(ie_buf, 0, sizeof(ie_buf));
        tp_net_info = (bcm_tpie_t *)ie_buf;

        if (pAwndNetInfo->len > (TP_IE_MAX_LEN + 3)) {
            len = TP_IE_MAX_LEN + 5;
            tp_net_info->len = TP_IE_MAX_LEN + 3;
        }
        else {
            len = pAwndNetInfo->len + 2;
            tp_net_info->len = pAwndNetInfo->len;
            /*
                for re, just to follow rootap's len( sizeof(ap's AWND_NET_INFO) - 2)
                if it is not equal mylen( sizeof(my AWND_NET_INFO) - 2 )
            */
        }

        tp_net_info->id = IEEE80211_ELEMID_VENDOR; /*default vendor ie value */
        // memcpy(tp_net_info->oui, pAwndNetInfo->oui, VENDORIE_OUI_LEN);
        // just to copy length(sizeof(AWND_NET_INFO)-2), which is the maxlen get form rootap
        memcpy(&tp_net_info->tpie[0], &(pAwndNetInfo->type), ( sizeof(AWND_NET_INFO) - 2 - VENDORIE_OUI_LEN));

        ni = (AWND_NET_INFO *)(ie_buf);
        ni->awnd_lanip = htonl(pAwndNetInfo->awnd_lanip);
        ni->server_touch_time = htonl(pAwndNetInfo->server_touch_time);		
        ni->awnd_dns = htonl(pAwndNetInfo->awnd_dns);			
        cp = (u_int8_t *)(&(ni->uplink_mask));
        LE_WRITE_2(cp, uplinkMask);
        LE_WRITE_2(cp, uplinkRate[band]);
        memcpy(ni->lan_mac, lan_mac, AWND_MAC_LEN);
        /* fill up oui */
        if(meshType == AWND_MESH_CONFIG)
        {   /* config interfaces should be the old oui all the time */
            tp_net_info->oui[0] = 0x00;
            tp_net_info->oui[1] = 0x1d;
            tp_net_info->oui[2] = 0x0f;
        }
        else if(meshType == AWND_MESH_BACKHUAL)
        {   /* FAP/RE's backhual interfaces woule be updated depends on fap/re_oui_update_status */
            if (fap_oui_update_status == OUI_OLD_TO_NEW || re_oui_update_status == OUI_OLD_TO_NEW)
            {
                /* first, delete current oui of backhual interfaces, to prevent two oui exist at the same time*/
                tp_net_info->oui[0] = 0x00;
                tp_net_info->oui[1] = 0x1d;
                tp_net_info->oui[2] = 0x0f;
                if ((remove_ret = _wl_del_tpie(ifname)) < 0)
                {
                    AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s[%d]", ifname, remove_ret);
                }
                AWN_LOG_ERR("OUI_OLD_TO_NEW : removed %s oui 0x%x%x%x.",ifname,tp_net_info->oui[0],tp_net_info->oui[1],tp_net_info->oui[2]);

                /* second, set dst oui*/
                tp_net_info->oui[0] = 0x00;
                tp_net_info->oui[1] = 0x31;
                tp_net_info->oui[2] = 0x92;

            }else if(fap_oui_update_status == OUI_NEW_TO_OLD || re_oui_update_status == OUI_NEW_TO_OLD)
            {
                tp_net_info->oui[0] = 0x00;
                tp_net_info->oui[1] = 0x31;
                tp_net_info->oui[2] = 0x92;
                if ((remove_ret = _wl_del_tpie(ifname)) < 0)
                {
                    AWN_LOG_ERR("config_generic failed awnd_remove_tpie(): %s[%d]", ifname, remove_ret);
                }
                AWN_LOG_ERR("OUI_NEW_TO_OLD : removed %s oui 0x%x%x%x.",ifname,tp_net_info->oui[0],tp_net_info->oui[1],tp_net_info->oui[2]);

                tp_net_info->oui[0] = 0x00;
                tp_net_info->oui[1] = 0x1d;
                tp_net_info->oui[2] = 0x0f;

            }else
            {
                /* for other situation, just copy pAwndNetInfo->oui */
                memcpy(tp_net_info->oui, pAwndNetInfo->oui, VENDORIE_OUI_LEN);
                AWN_LOG_ERR("OUI_KEEP_STATE : copyed oui 0x%x%x%x.",ifname,tp_net_info->oui[0],tp_net_info->oui[1],tp_net_info->oui[2]);
            }
        }

        if ((ret = _wl_update_tpie(ifname, (UINT8 *)&ie_buf, len)) < 0) {
             AWN_LOG_ERR("%s Update tpie fail:%d", ifname, ret);
        }
    }

    AWN_LOG_INFO("Update tpie ret:%d", ret);

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
        uplinkRate[AWND_BAND_2G],uplinkRate[AWND_BAND_5G], uplinkRate[l_awnd_config.band_5g2_type]);
        
    return ret;
}


int flush_scan_table_single_band_bcm(AWND_BAND_TYPE band, BOOL force)
{
    return _flush_scan_table(band, force);
}

int flush_scan_table_bcm(void)
{
    AWND_BAND_TYPE bi;
    int ret = AWND_OK;

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (AWND_ERROR == _flush_scan_table(bi, FALSE)) {
            ret = AWND_ERROR;
        }
    }
    return ret;
}

int do_scan_bcm(UINT8 scanBandMask)
{
    //pthread_t tid[AWND_BAND_MAX] = {0};
    //AWND_BAND_TYPE band[AWND_BAND_MAX];    
    AWND_BAND_TYPE bi;
    int ret = AWND_OK;
    UINT8 scanFailMask = 0;

    _set_wifi_scan_flag();

#if CONFIG_WIFI_DFS_SILENT
#if CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1
    /* notBind: acsd is running, the time of 80M update 160M is uncertain
          Bind: acsd is down  */
    if ((AWND_ERROR == _check_dfs_status(AWND_BAND_5G)) && (scanBandMask & (1 << AWND_BAND_5G))) {
        scanBandMask &= ~(1 << AWND_BAND_5G);
    }
#endif /* CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1 */

#if CONFIG_WIFI_DFS_SILENT_5G2
    if ((l_awnd_config.band_num == AWND_BAND_NUM_3) && 
        (AWND_ERROR == _check_dfs_status(l_awnd_config.band_5g2_type)) && 
        (scanBandMask & (1 << l_awnd_config.band_5g2_type))) {
        scanBandMask &= ~(1 << l_awnd_config.band_5g2_type);
    }
#endif /* CONFIG_WIFI_DFS_SILENT_5G2 */
#endif /* CONFIG_WIFI_DFS_SILENT */

    AWN_LOG_WARNING("scanBandMask: %d", scanBandMask);

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            ret = _start_scan_single_band(bi);
            if (AWND_ERROR == ret) {
                scanFailMask |= (1 << bi);
            }
        }
    }
    
#if SCAN_OPTIMIZATION
    g_awnd.scan_band_success_mask = scanBandMask ^ scanFailMask;
    AWN_LOG_WARNING("Finish  scan scanFailMask:%d, scan_band_success_mask %d", scanFailMask, g_awnd.scan_band_success_mask);
    _clear_wifi_scan_flag();
    return scanFailMask;
#else

    if(l_awnd_config.sp6G)
        sleep(5);
   else
        sleep(3);

    AWN_LOG_WARNING("Finish  scan scanFailMask:%d", scanFailMask);
    _clear_wifi_scan_flag();
    exit(scanFailMask);
#endif //SCAN_OPTIMIZATION 
}

int do_scan_fast_bcm(UINT8 scanBandMask)
{
    //pthread_t tid[AWND_BAND_MAX] = {0};
    //AWND_BAND_TYPE band[AWND_BAND_MAX];
    AWND_BAND_TYPE bi;
    int ret = AWND_OK;
    UINT8 scanFailMask = 0;

    _set_wifi_scan_flag();

#if CONFIG_WIFI_DFS_SILENT
#if CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1
    /* notBind: acsd is running, the time of 80M update 160M is uncertain
          Bind: acsd is down  */
    if ((AWND_ERROR == _check_dfs_status(AWND_BAND_5G)) && (scanBandMask & (1 << AWND_BAND_5G))) {
        scanBandMask &= ~(1 << AWND_BAND_5G);
    }
#endif /* CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1 */

#if CONFIG_WIFI_DFS_SILENT_5G2
    if ((l_awnd_config.band_num == AWND_BAND_NUM_3) && 
        (AWND_ERROR == _check_dfs_status(l_awnd_config.band_5g2_type)) && 
        (scanBandMask & (1 << l_awnd_config.band_5g2_type))) {
        scanBandMask &= ~(1 << l_awnd_config.band_5g2_type);
    }
#endif /* CONFIG_WIFI_DFS_SILENT_5G2 */
#endif /* CONFIG_WIFI_DFS_SILENT */

    AWN_LOG_WARNING("scanBandMask: %d", scanBandMask);

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            ret = _fast_scan_single_channel(bi);
            if (AWND_ERROR == ret) {
                scanFailMask |= (1 << bi);
            }
        }
    }

#if SCAN_OPTIMIZATION
    g_awnd.scan_band_success_mask = scanBandMask ^ scanFailMask;
    AWN_LOG_WARNING("Finish fast scan scanFailMask:%d", scanFailMask);
    _clear_wifi_scan_flag();

    return scanFailMask;
#else
    sleep(3);
    AWN_LOG_WARNING("Finish fast scan scanFailMask:%d", scanFailMask);
    _clear_wifi_scan_flag();

    exit(scanFailMask);
#endif //SCAN_OPTIMIZATION
}

int find_idle_idx_to_insert_sr(AWND_SCAN_RESULT *pAwndScanResult, char* tmp_bssid)
{
    int tmp_idx;
    int idx_first_idle = -1;
    int idx = -1;
    int idx_max_missing = 0;
    int max_missing = 0;
    UINT8 macZero[AWND_MAC_LEN]={0};
    AWND_AP_ENTRY* tmp_pCurApEntry;

    for(tmp_idx = 0; tmp_idx < AWND_MAX_GROUP_MEMBER; tmp_idx++)
    {
        tmp_pCurApEntry = &(pAwndScanResult->tApEntry[tmp_idx]);
        if(0 == memcmp(tmp_bssid, tmp_pCurApEntry->bssid, IEEE80211_ADDR_LEN))
        {
            tmp_pCurApEntry->missing_cnt = 0;
            AWN_LOG_DEBUG("AP entry has exit.idx %d update it", tmp_idx);
            return tmp_idx;
        }
        else if(-1 == idx_first_idle && 0 == memcmp(tmp_pCurApEntry->bssid, macZero, IEEE80211_ADDR_LEN))
        {
            idx_first_idle = tmp_idx;
        }
        else if (max_missing < tmp_pCurApEntry->missing_cnt)
        {
            idx_max_missing = tmp_idx;
            max_missing = tmp_pCurApEntry->missing_cnt;
        }

        if(tmp_idx == AWND_MAX_GROUP_MEMBER - 1)
        {
            if (-1 != idx_first_idle)
            {
                AWN_LOG_DEBUG("find idx_first_idle position to insert. %d", idx_first_idle);
                return idx_first_idle;
            }  
            else
            {
                AWN_LOG_DEBUG("find idx_max_missing position to insert. %d", idx_max_missing);
                return idx_max_missing;
            }   
        }
    }
}

int get_scan_result_bcm(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
    UINT8 buf[WLC_IOCTL_MAXLEN] = {0};
    char cmdline[CMDLINE_LENGTH] = {0};
    INT8 ifname[IFNAMSIZ] = {0};
	INT8 ssid[AWND_MAX_SSID_LEN] = {0};
    struct ifreq ifr; 
    tp_scan_result_t *scan_result;
    bcm_scan_result_entry_t *sr;
	int ret = 0;
    int buf_len = 0;
    int status = 0;
    int entry_cnt = 0;
    UINT8* cp = NULL;
    int len = 0;
    int idx = 0;
    int ielen = 0;
    AWND_AP_ENTRY* pCurApEntry;
    UINT8* vp = NULL;
    int nss;
    int phyMode;
    int chwidth;
    int cur_5g_channel = 0;
    AWND_BAND_TYPE real_band = 0;
#if SCAN_OPTIMIZATION
    UINT8 tmp_bssid[AWND_MAC_LEN];
    UINT8 macZero[AWND_MAC_LEN]={0};
    AWND_AP_ENTRY* tmp_pCurApEntry;
    int idx_tpEntry = 0;
    int count = 0;
#endif

    real_band = _get_real_band_type(band);
    if (NULL == pAwndScanResult)
    {
        AWN_LOG_ERR("pAwndScanResult is null");     
        return AWND_ERROR;        
    }

#if SCAN_OPTIMIZATION
    if (0 == (g_awnd.scan_band_success_mask & (1 << band)))
    {
        AWN_LOG_DEBUG("scan_band_success_mask:%d, band:%d, return.", g_awnd.scan_band_success_mask, band);
        return AWND_OK;
    }
#endif //SCAN_OPTIMIZATION

    if (AWND_VAP_AP == vap_type)
        snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
    else 
        snprintf(ifname, sizeof(ifname), l_awnd_config.staIfnames[band]);

	if (!isFast) {
    	/* save scan result(BSSID SSID mode channel rate) */
    	snprintf(cmdline, sizeof(cmdline),"wl -i %s getscan > "WIFI_SCAN_RESULT_FILE" &",
			ifname, real_band_suffix[real_band]);
    	_wifi_exec_cmd(cmdline);
	}

    if (AWND_OK != get_phy_bcm(band, &nss, &phyMode, &chwidth))
    {
        AWN_LOG_ERR("awnd_get_phy fail, quit awnd_get_scan_result"); 	
        return AWND_ERROR;		  
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    memset(buf, 0, WLC_IOCTL_MAXLEN);

    if ((ret = _wl_get(&ifr, WLC_TP_STORE_SCAN_RESULTS, buf, WLC_IOCTL_MAXLEN)) < 0) {
        AWN_LOG_ERR("get scan result fail ret=%d to scan again", ret);

#if 0
        _start_scan_single_band(band);
        sleep(2);
        if ((ret = _wl_get(&ifr, WLC_TP_SCAN_RESULTS, buf, WLC_IOCTL_MAXLEN)) < 0) {
            AWN_LOG_ERR("get scan result failed ret=%d", ret);
            return AWND_ERROR;
        }
#endif
    }

    scan_result = (tp_scan_result_t *) buf;
    buf_len = scan_result->buflen;
    entry_cnt = scan_result->count;
    status = scan_result->status;

    AWN_LOG_DEBUG("buf_len:%d entry_cnt:%d status:%d", buf_len, entry_cnt, status);
    if (entry_cnt < 1 || buf_len < sizeof(tp_scan_result_t)) {
        AWN_LOG_INFO("get scan entry is null");
        return AWND_ERROR;
    }

    if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
    {
        cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
    }

    len = buf_len - (sizeof(tp_scan_result_t) - sizeof(bcm_scan_result_entry_t));
    cp = (UINT8*) &scan_result->scan_entry[0];

#if SCAN_OPTIMIZATION
    for(idx_tpEntry = 0; idx_tpEntry < AWND_MAX_GROUP_MEMBER; idx_tpEntry++)
    {
        tmp_pCurApEntry = &(pAwndScanResult->tApEntry[idx_tpEntry]);
        if(0 != memcmp(tmp_pCurApEntry->bssid, macZero, IEEE80211_ADDR_LEN)){
            tmp_pCurApEntry->missing_cnt++;
        }
    }
    pCurApEntry = (AWND_AP_ENTRY *)malloc(sizeof(AWND_AP_ENTRY));
    if(!pCurApEntry)
    {
        AWN_LOG_ERR("malloc fail.byte: %d", sizeof(AWND_AP_ENTRY));
        return AWND_MALLOC_FAIL;
    }

#endif //SCAN_OPTIMIZATION

    do {

#if SCAN_OPTIMIZATION
        memset(pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
#else
		pCurApEntry = &(pAwndScanResult->tApEntry[idx]);
#endif
        sr = (bcm_scan_result_entry_t *) cp;

        memset(pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
        _copy_essid(ssid, sizeof(ssid), sr->ssid, sr->ssidLen);
        memcpy(pCurApEntry->ssid, ssid, strlen(ssid));
        pCurApEntry->ssid[sr->ssidLen] = 0; 
        
        if (sr->bssid != NULL) {
            memcpy(pCurApEntry->bssid, sr->bssid, IEEE80211_ADDR_LEN);
        }
        pCurApEntry->rssi  = sr->rssi;
        pCurApEntry->freq  = sr->freq;
        pCurApEntry->index = idx + 1;
        pCurApEntry->channel = sr->channel;

        if (AWND_BAND_5G == band && pCurApEntry->channel != cur_5g_channel
            && (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
        {
            if (!((l_awnd_config.limit_scan_band1 && pCurApEntry->channel <= 48)
                || (l_awnd_config.limit_scan_band4 && pCurApEntry->channel >= 149)))
            {
                cp += sizeof(bcm_scan_result_entry_t), len -= sizeof(bcm_scan_result_entry_t);
                AWN_LOG_DEBUG("AWND_BAND_5G: skip entry when channel(%d) is not in band1 or band4", pCurApEntry->channel);
                continue; 
            }
        }

        if (AWND_REAL_BAND_5G2 == real_band && pCurApEntry->channel <= 48)
        {
            cp += sizeof(bcm_scan_result_entry_t), len -= sizeof(bcm_scan_result_entry_t);
            AWN_LOG_DEBUG("AWND_BAND_5G2: skip entry when channel(%d) is in band1", pCurApEntry->channel);
            continue;
        }

        vp = (UINT8 *)&(sr->netInfo);
        ielen = sr->netInfo.len;
        if (ielen > 0) 
        {
            if (sr->netInfo.id == IEEE80211_ELEMID_VENDOR && istpoui(vp))
            {
                memcpy(&(pCurApEntry->netInfo), vp, ((2+vp[1]) < sizeof(AWND_NET_INFO))? (2+vp[1]) : sizeof(AWND_NET_INFO));
            }
        }

#if SCAN_OPTIMIZATION
        if (0 == memcmp(pCurApEntry->netInfo.awnd_label, match_label, AWND_LABEL_LEN))
        {
            pCurApEntry->isPreconf = 0;
        }
        else if (preconf_label && 0 == memcmp(pCurApEntry->netInfo.awnd_label, preconf_label, AWND_LABEL_LEN))
        {
            pCurApEntry->isPreconf = 1;
        }
#else
        if (0 == memcmp(pAwndScanResult->tApEntry[idx].netInfo.awnd_label, match_label, AWND_LABEL_LEN))
        {
            pAwndScanResult->tApEntry[idx].isPreconf = 0;
        }
        else if (preconf_label && 0 == memcmp(pAwndScanResult->tApEntry[idx].netInfo.awnd_label, preconf_label, AWND_LABEL_LEN))
        {
            pAwndScanResult->tApEntry[idx].isPreconf = 1;
        }
#endif //SCAN_OPTIMIZATION
        else
        {
            cp += sizeof(bcm_scan_result_entry_t), len -= sizeof(bcm_scan_result_entry_t);
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
            (pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_6G) || (pCurApEntry->uplinkMask & AWND_BACKHAUL_WIFI_6G2) ))
        {   /* if current band disconnect with rootap, uplinkRate set to zero  */
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
#if SCAN_OPTIMIZATION
        idx = find_idle_idx_to_insert_sr(pAwndScanResult, pCurApEntry->bssid);
        memset(&(pAwndScanResult->tApEntry[idx]), 0, sizeof(AWND_AP_ENTRY));
        memcpy(&(pAwndScanResult->tApEntry[idx]), pCurApEntry, sizeof(AWND_AP_ENTRY));
#else
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

#endif //SCAN_OPTIMIZATION
        cp += sizeof(bcm_scan_result_entry_t), len -= sizeof(bcm_scan_result_entry_t);

    }while(len >= sizeof(bcm_scan_result_entry_t) && idx < AWND_MAX_GROUP_MEMBER);

#if SCAN_OPTIMIZATION
    for(idx_tpEntry = 0; idx_tpEntry < AWND_MAX_GROUP_MEMBER; idx_tpEntry++)
    {
        tmp_pCurApEntry = &(pAwndScanResult->tApEntry[idx_tpEntry]);
        if(tmp_pCurApEntry->missing_cnt >= AWND_MAX_MISSING_CNT)
        {
            memset(tmp_pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
            AWN_LOG_ERR("idx %d, missing_cnt >= %d, delete it.", idx_tpEntry, AWND_MAX_MISSING_CNT);
        }
        else if(0 != memcmp(tmp_pCurApEntry->bssid, macZero, IEEE80211_ADDR_LEN))
        {
            count = idx_tpEntry;
            AWN_LOG_ERR("%-6s idx:%d, ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%-4d, channel:%-3d, uplinkMask:%-5u, uplinkrate:%-5u, pathRate:%-5u, missing_cnt:%-3d",
            ifname,idx_tpEntry, tmp_pCurApEntry->ssid, tmp_pCurApEntry->bssid[0],tmp_pCurApEntry->bssid[1],tmp_pCurApEntry->bssid[2],
            tmp_pCurApEntry->bssid[3],tmp_pCurApEntry->bssid[4],tmp_pCurApEntry->bssid[5],tmp_pCurApEntry->rssi, tmp_pCurApEntry->channel, 
            tmp_pCurApEntry->uplinkMask, tmp_pCurApEntry->uplinkRate,  tmp_pCurApEntry->pathRate, tmp_pCurApEntry->missing_cnt);

            AWN_LOG_ERR("awnd_net_type:%-3d,awnd_level:%-2d, awnd_weight:%d, wait:%d, lanip:%x, dns:%x \
            server_detected:%d, server_touch_time:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",            
            tmp_pCurApEntry->netInfo.awnd_net_type, tmp_pCurApEntry->netInfo.awnd_level,
            tmp_pCurApEntry->netInfo.awnd_weight, tmp_pCurApEntry->netInfo.wait,
            tmp_pCurApEntry->netInfo.awnd_lanip, tmp_pCurApEntry->netInfo.awnd_dns,
            tmp_pCurApEntry->netInfo.server_detected, tmp_pCurApEntry->netInfo.server_touch_time,
            tmp_pCurApEntry->netInfo.awnd_mac[0],tmp_pCurApEntry->netInfo.awnd_mac[1],
            tmp_pCurApEntry->netInfo.awnd_mac[2],tmp_pCurApEntry->netInfo.awnd_mac[3],
            tmp_pCurApEntry->netInfo.awnd_mac[4],tmp_pCurApEntry->netInfo.awnd_mac[5]);
        }
    }
    pAwndScanResult->iApNum = count + 1;
    free(pCurApEntry);
#else
    pAwndScanResult->iApNum = idx;
#endif //SCAN_OPTIMIZATION

    return AWND_OK;
}



int set_channel_bcm(AWND_BAND_TYPE band, UINT8 channel)
{
    UINT8 ifname[IFNAMSIZ] = {0};

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
    _wl_set_channel(ifname, channel);

    return AWND_OK;
}

int get_sta_iface_in_bridge_bcm(AWND_BAND_TYPE band, UINT8* ifname)
{
    UINT8 vapname[IFNAMSIZ] = {0};

    snprintf(vapname, sizeof(vapname), l_awnd_config.staIfnames[band]);
#if BCM_USE_WIFI_VLAN_DEV
    snprintf(ifname, IFNAMSIZ, "%s.%s", vapname, BCM_LAN_VLAN_DEV_SUFFIX);
#else
    snprintf(ifname, IFNAMSIZ, "%s", vapname);
#endif

    return AWND_OK;
}


int disconn_sta_pre_bcm(AWND_BAND_TYPE band, UINT* pBandMask)
{
    memset(&g_awnd.rootAp[band], 0, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_DISCONNECT;
    
    *pBandMask |= (1 << band);
     
    return AWND_OK;
}

int disconn_all_sta_pre_bcm(UINT* pBandMask)
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        disconn_sta_pre_bcm(band, pBandMask);

    return AWND_OK;
}

/*!
 *\fn           awnd_disconn_sta()
 *\brief        Disconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int disconn_sta_post_bcm(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    AWN_LOG_DEBUG("RECORD DISCONN");
#if CONFIG_WIFI_HOSTAPD_SUPPORT
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0 &", l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);

#if CONFIG_5G_HT160_SUPPORT
    if (AWND_BAND_5G == band && ENABLE == g_awnd.ht160Enable)
    {
        if (g_awnd.notBind && (AWND_BIND_START == g_awnd.bindStatus || AWND_BIND_BACKHUAL_CONNECTING == g_awnd.bindStatus))
        {
            AWND_WIFI_BW_TYPE cur_bw = 0;
            if (AWND_OK == get_wifi_bw_bcm(band, &cur_bw) && WIFI_BW_160M == cur_bw)
            {
                AWN_LOG_WARNING("HT160 to reduce bandwith to HT80 when config network change to backhaul");
                awnd_set_wifi_bw(AWND_BAND_5G, 0, WIFI_BW_80M);
            }
        }
    }
#endif /* CONFIG_5G_HT160_SUPPORT */

#else
    snprintf(cmdline, sizeof(cmdline), "wl -i %s bss down &", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

#endif /* CONFIG_WIFI_HOSTAPD_SUPPORT */

    awnd_write_rt_info(band, FALSE, NULL, FALSE);

    return AWND_OK;
}
/*!
 *\fn           disconn_sta_qca()
 *\brief        Disconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int disconn_sta_bcm(AWND_BAND_TYPE band)
{
    UINT bandMask;

    disconn_sta_pre_bcm(band, &bandMask);

    return disconn_sta_post_bcm(band);
}

int disconn_all_sta_bcm(void)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        disconn_sta_bcm(band);

    return AWND_OK;
}

/*!
 *\fn           reconn_sta_pre_qca()
 *\brief        Pepare for reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reconn_sta_pre_bcm(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp)
{
    if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band])
    {
        AWN_LOG_WARNING("record disconnect for band %s", real_band_suffix[_get_real_band_type(band)]);
        awnd_write_rt_info(band, FALSE, NULL, FALSE);
        //g_awnd.disconnRecord[band] = 3;
    }

    memcpy(&g_awnd.rootAp[band], pRootAp, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_CONNECTING;
    g_awnd.disconnRecord[band] = 3;

    return AWND_OK;
}

/*!
 *\fn           reconn_sta_post_qca()
 *\brief        Reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reconn_sta_post_bcm(AWND_BAND_TYPE band, BOOL check_wpa_status)
{
#define WPA_SUPP_RESTART_SUPPORT 0
#define HIGH_RSSI_TIMER 3
#define LOW_RSSI_TIMER 10
#define MAX_WPA_RESTART_TIMER 5

#define WPA_SUPP_DISABLE_SUPPORT 0
#define REDUCE_HT80_WHEN_POST    0
#define WL_RESTART_MAX 5
#define WPA_DISABLE_START  3  //means wpa disable in (WPA_DISABLE_START, WL_RESTART_MAX)
#define WPA_ENABLE_CNT  5

    FILE *fp = NULL;
    char *s = NULL;
    char cmdline[CMDLINE_LENGTH] = {0};
    char line[READ_LINE_LEN] = {0};
    UINT8 wl_restart = 0;
    UINT8 wpa_restart = 0;
    UINT8 wpa_disable = 0;
    UINT8 wpa_scanning = 0;
    AWND_NET_INFO     tmpNetInfo;
    struct ifreq ifr;
    int ret_tpie = 0;
    UINT8 rootap_rssi = 0;
#if WPA_SUPP_RESTART_SUPPORT
    static int high_rssi_post = 0;
    static int low_rssi_post = 0;
#endif /* WPA_SUPP_RESTART_SUPPORT */
    static UINT8 wpa_restart_cnt[AWND_BAND_MAX] = {0};
    struct ether_addr bssid;
    UINT8 wpa_inactive = 0;
    static UINT8 inactive_cnt[AWND_BAND_MAX] = {0};
    static UINT8 wpa_enable_cnt[AWND_BAND_MAX] = {0};

    awnd_config_set_stacfg_enb(1, band);

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, l_awnd_config.staIfnames[band], IFNAMSIZ);
    if (AWND_OK == _wl_get_rootap_info(&ifr, &bssid) &&
        !memcmp(g_awnd.staConfig[band].bssid, &bssid, sizeof(struct ether_addr))) {
        AWN_LOG_WARNING("%s: is in connected status; no need to wpa_cli disable/enable_network", l_awnd_config.staIfnames[band]);
        wpa_enable_cnt[band] = 0;
        return AWND_OK;
    }

    if (check_wpa_status)
    {
        snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" status", l_awnd_config.staIfnames[band]);

        fp = popen(cmdline, "r");
        if (NULL == fp)
        {
            AWN_LOG_INFO("Failed to open %s", cmdline);
        }
        else
        {
            while (fgets(line, READ_LINE_LEN, fp) != NULL)
            {
                if ( (NULL != (s = strstr(line, "wpa_state=INACTIVE"))) /* ||
                    (NULL != (s = strstr(line, "wpa_state=DISCONNECTED"))) */ )
                {
                    wpa_inactive = 1;
#if WPA_SUPP_RESTART_SUPPORT
                    high_rssi_post = 0;
                    low_rssi_post = 0;
#endif /* WPA_SUPP_RESTART_SUPPORT */
                    break;
                }
                else if (NULL != (s = strstr(line, "wpa_state=SCANNING"))) {
                    wpa_scanning = 1;
                }
            }
            pclose(fp);
        }

        if (wpa_inactive) {
            if (inactive_cnt[band] <= WL_RESTART_MAX) {
                inactive_cnt[band] ++;
            }

            if (HIGH_RSSI_TIMER == inactive_cnt[band]) {
                AWN_LOG_WARNING("%s wpa_state is INACTIVE to restart wpa_supplicant", l_awnd_config.staIfnames[band]);
                if (wpa_restart_cnt[band] <= MAX_WPA_RESTART_TIMER && AWND_OK == _wpa_supplicant_restart(band)) {
#if WPA_SUPP_RESTART_SUPPORT
                    high_rssi_post = 0;
                    low_rssi_post = 0;
#endif /* WPA_SUPP_RESTART_SUPPORT */
                    wl_restart = 1;
                    wpa_restart = 1;
                    wpa_restart_cnt[band] ++;

#if CONFIG_5G_HT160_SUPPORT
                    if (!g_awnd.notBind && AWND_BAND_5G == band && ENABLE == g_awnd.ht160Enable)
                    {
                        AWND_WIFI_BW_TYPE cur_bw = 0;
                        if (AWND_OK == get_wifi_bw_bcm(band, &cur_bw) && WIFI_BW_160M == cur_bw)
                        {
                            AWN_LOG_WARNING("HT160 to reduce bandwith to HT80 when starting");
                            awnd_set_wifi_bw(AWND_BAND_5G, 0, WIFI_BW_80M);
                        }
                    }
#endif /* CONFIG_5G_HT160_SUPPORT */
                }

            }
            else if (inactive_cnt[band] <= WL_RESTART_MAX) {
                AWN_LOG_WARNING("%s wpa_state is INACTIVE to wl down/up", l_awnd_config.staIfnames[band]);
                _wl_restart(l_awnd_config.apIfnames[band]);
                wl_restart = 1;
                if (inactive_cnt[band] >= WPA_DISABLE_START) {
                    wpa_disable = 1;
                }
            }
        }
        else {
            inactive_cnt[band] = 0;
        }

#if WPA_SUPP_RESTART_SUPPORT
        if (!wl_restart && wpa_scanning && wpa_restart_cnt[band] <= MAX_WPA_RESTART_TIMER)
        {
             /**********************************************************************************************
                to fix Bug 496770 - 【偶现两次】W6000作为RE时出现wpasupplicant异常，5G无法连接前端，重启后恢复正常
                _get_tpie_from_scan_results: if OK ==> rootap is on
                if (25 <= rssi <= 85)  连续3分钟连接失败，则重启wpa_supplicant
                if (14 <= rssi < 25)   连续10分钟连接失败，则重启wpa_supplicant
                重启wpa_supplicant的尝试最多5次。
            ************************************************************************************************/
            memset(&ifr, 0, sizeof(struct ifreq));
            strncpy(ifr.ifr_name, l_awnd_config.staIfnames[band], IFNAMSIZ);
            memset(&tmpNetInfo, 0, sizeof(AWND_NET_INFO));

            ret_tpie = _get_tpie_from_scan_results(&ifr, g_awnd.rootAp[band].bssid, &tmpNetInfo, band, &rootap_rssi);
            if (AWND_OK == ret_tpie && (rootap_rssi >= AWND_HIGH_RSSI_THRESHOLD && rootap_rssi <= 85)) {
                high_rssi_post ++;
            }
            else if (AWND_OK == ret_tpie && (rootap_rssi >= AWND_LOW_RSSI_THRESHOLD && rootap_rssi < AWND_HIGH_RSSI_THRESHOLD)) {
                low_rssi_post ++;
            }

            if (AWND_OK == ret_tpie && high_rssi_post >= HIGH_RSSI_TIMER || low_rssi_post >= LOW_RSSI_TIMER) {


                if (AWND_OK == _wpa_supplicant_restart(band)) {
                    high_rssi_post = 0;
                    low_rssi_post = 0;
                    wpa_restart = 1;
                    wpa_restart_cnt[band] ++;
#if CONFIG_5G_HT160_SUPPORT
                    if (!g_awnd.notBind && AWND_BAND_5G == band && ENABLE == g_awnd.ht160Enable)
                    {
                        AWND_WIFI_BW_TYPE cur_bw = 0;
                        if (AWND_OK == get_wifi_bw_bcm(band, &cur_bw) && WIFI_BW_160M == cur_bw )
                        {
                            AWN_LOG_WARNING("HT160 to reduce bandwith to HT80 when starting");
                            awnd_set_wifi_bw(AWND_BAND_5G, 0, WIFI_BW_80M);
                        }
                    }
#endif /* CONFIG_5G_HT160_SUPPORT */
                }

            }
        }
#endif /* WPA_SUPP_RESTART_SUPPORT */

    }
#if WPA_SUPP_RESTART_SUPPORT
    else {
        high_rssi_post = 0;
        low_rssi_post = 0;
    }
#endif /* WPA_SUPP_RESTART_SUPPORT */

    if (!wpa_restart) {

#if CONFIG_5G_HT160_SUPPORT && REDUCE_HT80_WHEN_POST
        if (!g_awnd.notBind && AWND_BAND_5G == band && ENABLE == g_awnd.ht160Enable)
        {
            AWND_WIFI_BW_TYPE cur_bw = 0;
            if (AWND_OK == get_wifi_bw_bcm(band, &cur_bw) && WIFI_BW_160M == cur_bw
                && AWND_ERROR == _check_dfs_status(AWND_BAND_5G))
            {
                AWN_LOG_WARNING("HT160 to reduce bandwith to HT80 when post connecting and dfs CAC");
                awnd_set_wifi_bw(AWND_BAND_5G, 0, WIFI_BW_80M);
            }
        }
#endif /* CONFIG_5G_HT160_SUPPORT */

#if WPA_SUPP_DISABLE_SUPPORT
        snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0", l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);
#endif /* WPA_SUPP_DISABLE_SUPPORT */

        if (!wpa_restart && wl_restart && wpa_disable)
        {
            wpa_enable_cnt[band] = 0;
            snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0", l_awnd_config.staIfnames[band]);
            _wifi_exec_cmd(cmdline);
        }
        else {
            wpa_enable_cnt[band] ++;
            if (wpa_enable_cnt[band] >= WPA_ENABLE_CNT) {
                wpa_enable_cnt[band] = 0;
                AWN_LOG_WARNING("enbale simple for %d times, do disable_network before enable_network", WPA_ENABLE_CNT);
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);
            }
        }

        snprintf(cmdline, sizeof(cmdline), "ifconfig %s up", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

        snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" reconfigure &", l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);

        snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" enable_network 0 &", l_awnd_config.staIfnames[band]);
        AWN_LOG_DEBUG("cmd: reconfigure and %s ", cmdline);
    _wifi_exec_cmd(cmdline);
    }
    else {
        wpa_enable_cnt[band] = 0;
    }

    return AWND_OK;
}

/*!
 *\fn           reset_sta_connection_qca()
 *\brief        Reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reset_sta_connection_bcm(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

#if CONFIG_WIFI_HOSTAPD_SUPPORT
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0; sleep 1;",
            l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    snprintf(cmdline, sizeof(cmdline), "ifconfig %s up;  wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" reconfigure &",
            l_awnd_config.staIfnames[band], l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" enable_network 0 &",
            l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);
#else
    snprintf(cmdline, sizeof(cmdline), "wl -i %s bss down", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    memset(cmdline, 0, sizeof(cmdline));
    //snprintf(cmdline, sizeof(cmdline), "wl -i %s bss up &", l_awnd_config.staIfnames[band]);
    snprintf(cmdline, sizeof(cmdline), "/sbin/bcm_sta_connect %s &", real_band_suffix[_get_real_band_type(band)]);
    _wifi_exec_cmd(cmdline);

#endif /* CONFIG_WIFI_HOSTAPD_SUPPORT */

    return AWND_OK;
}

/*******************************
 link_state:
 bit0-3: 2.4g 5g 5g2 6g
 bit4: plc
 bit5-7: eth0 eth1 eth2
********************************/
int set_backhaul_sta_dev_bcm(UINT32 link_state, unsigned int eth_link_state)
{
    char dev_list[128];
    char cmd[128];
    FILE *fp;
    int index = 0;
    unsigned int flag = 0;
    int ret = 0;
    int dev_num = 0;
    AWND_BAND_TYPE band_index = 0;

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

    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "echo '%s' > %s", dev_list, STATS_BACKHAUL_STA_DEV_NAME);
    AWN_LOG_WARNING("cmd:%s", cmd);
    if ((fp = popen(cmd, "r")) == NULL)
    {
        AWN_LOG_WARNING("popen error:%s", strerror(errno));
        return -1;
    }

    if ((ret = pclose(fp)) == -1)
    {
        AWN_LOG_WARNING("pclose error:%s", strerror(errno));
        return -1;
    }

    return AWND_OK;   
}

void do_band_restart_bcm(UINT8 BandMask)
{
    AWND_BAND_TYPE band;
    INT8 ifname[IFNAMSIZ] = {0};

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (BandMask & (1 << band))
        {
            snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
            _wl_restart(ifname);
        }
    }

    return;
}

#if CONFIG_BSS_STATUS_CHECK
int bss_status_check_bcm()
{
    INT8 ifname[IFNAMSIZ] = {0};
    UINT32 reinit_cnt = 0;
    UINT8 wl_up_status[AWND_BAND_MAX] = {0};
    UINT8 bss_up_status[AWND_BAND_MAX] = {0};
    UINT8 wifi_reload = 0;
    char cmdline[CMDLINE_LENGTH] = {0};
    AWND_BAND_TYPE band;
    int ret_wl = AWND_OK;
    int ret_bss = AWND_OK;
    UINT8 need_kill_hostapd = 0;

#if CONFIG_BAND_WIDTH_CHECK
    AWND_WIFI_BW_TYPE wifi_bw_dft_5g2 = WIFI_BW_80M;
    AWND_WIFI_BW_TYPE wifi_bw_5g2 = WIFI_BW_MAX;
    UINT8 channel_5g2 = 0;
#endif

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
        ret_wl = _get_wl_up_status(ifname, &wl_up_status[band]);
        if (AWND_OK == ret_wl && wl_up_status[band])
        {
            AWN_LOG_DEBUG(" get %s bss status: %u", ifname, wl_up_status[band]);
            g_awnd.wlDownCnt[band] = 0;
            ret_bss = _get_bss_up_status(ifname, &bss_up_status[band], band);

            if (AWND_OK == ret_bss && bss_up_status[band])
            {
                AWN_LOG_DEBUG(" get %s bss status: %u", ifname, bss_up_status[band]);
                g_awnd.bssDownCnt[band] = 0;
            }
            else if (AWND_ERROR == ret_bss || !bss_up_status[band])
            {
                AWN_LOG_WARNING("Failed to get %s bss status or bss is down %u", ifname, bss_up_status[band]);
                g_awnd.bssDownCnt[band] ++;
#if CONFIG_SUPPORT_WIFI_RELOAD
                if (g_awnd.bssDownCnt[band] >= (BSS_DOWN_TIMER + 1))
                {
                    AWN_LOG_ERR("%s bss down for %u times, to wifi reload", ifname, g_awnd.bssDownCnt[band]);
                    wifi_reload = 1;
                    g_awnd.wlDownCnt[band] = 0;
                }
                else
#endif /* CONFIG_SUPPORT_WIFI_RELOAD */
                {
                    if (g_awnd.bssDownCnt[band] >= BSS_DOWN_TIMER) {
                        snprintf(cmdline, sizeof(cmdline), "wl -i %s down; wl -i %s up &", ifname, ifname);
                        _wifi_exec_cmd(cmdline);
                        sleep(1);
                        snprintf(cmdline, sizeof(cmdline), "wl -i %s bss down; wl -i %s bss up &", ifname, ifname);
                        _wifi_exec_cmd(cmdline);
#if CONFIG_SUPPORT_WIFI_RELOAD

#else
                        g_awnd.bssDownCnt[band] = 0;
#endif
                    }
                    else {
                        snprintf(cmdline, sizeof(cmdline), "wl -i %s bss up &", ifname);
                        _wifi_exec_cmd(cmdline);
                    }
                }
            }
        }
        else if (AWND_ERROR == ret_wl || !wl_up_status[band])
        {
            AWN_LOG_WARNING("Failed to get %s wl status or wl is down %u", ifname, wl_up_status[band]);
            g_awnd.bssDownCnt[band] = 0;
            g_awnd.wlDownCnt[band] ++;
#if CONFIG_SUPPORT_WIFI_RELOAD
            if (g_awnd.wlDownCnt[band] >= (BSS_DOWN_TIMER + 1))
            {
                AWN_LOG_ERR("%s wl down for %u times, to wifi reload", ifname, g_awnd.wlDownCnt[band]);
                wifi_reload = 1;
                g_awnd.wlDownCnt[band] = 0;
            }
            else
#endif /* CONFIG_SUPPORT_WIFI_RELOAD */
            {
                if (g_awnd.wlDownCnt[band] >= BSS_DOWN_TIMER) {
                    snprintf(cmdline, sizeof(cmdline), "wl -i %s down; wl -i %s up &", ifname, ifname);
                    _wifi_exec_cmd(cmdline);
                    sleep(1);
                    snprintf(cmdline, sizeof(cmdline), "wl -i %s bss down; wl -i %s bss up &", ifname, ifname);
                    _wifi_exec_cmd(cmdline);
#if CONFIG_SUPPORT_WIFI_RELOAD

#else
                    g_awnd.wlDownCnt[band] = 0;
#endif
                }
                else {
                    snprintf(cmdline, sizeof(cmdline), "wl -i %s up &", ifname);
                    _wifi_exec_cmd(cmdline);
                }
            }
        }
    }

#if CONFIG_SUPPORT_WIFI_RELOAD
    if (wifi_reload)
    {
        /* rmmod wifi modules has the risk of system crashed, so reboot deco to avoid it temporarily*/
#if 0
        g_awnd.reloadCnt ++;
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            snprintf(cmdline, sizeof(cmdline), "wl -i %s down",
                l_awnd_config.apIfnames[band]);
            _wifi_exec_cmd(cmdline);
            sleep(2);

            snprintf(cmdline, sizeof(cmdline), "wlconf -i %s down",
                l_awnd_config.staIfnames[band]);
            _wifi_exec_cmd(cmdline);
            sleep(2);
        }

        if(access(AWND_TMP_WIFI_CONFIG_WIFI, 0) == 0)
        {
            unlink(AWND_TMP_WIFI_CONFIG_WIFI);
        }

        if (g_awnd.reloadCnt >= (2 * BSS_DOWN_TIMER))
        {
            g_awnd.reloadCnt = 0;
            sleep(5);
            _wifi_exec_cmd("rmmod wl &");
            /* wait for wl diriver rmmod */
            sleep(10);

            if(access(AWND_DHD_PATH, 0) == 0)
            {
                _wifi_exec_cmd("rmmod dhd &");
                sleep(5);
            }

            need_kill_hostapd = 1;
        }

        if (need_kill_hostapd || g_awnd.reloadCnt >= BSS_DOWN_TIMER)
        {
            _wifi_exec_cmd("killall hostapd &");
            sleep(10);
            _wifi_exec_cmd("killall wpa_supplicant &");
            sleep(2);
        }
#else
        //_wifi_exec_cmd("reboot");
#endif

        return AWND_WIFI_RESTART;
    }
    else
#endif /* CONFIG_SUPPORT_WIFI_RELOAD */
    {
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);

#if 0
        /******************************************************************************************************************
            监测reinit增长并进行wl down/up恢复，主要用于解决6755机型(主接口为sta模式且关闭wpa_supplicant进程)开关机5%概率持续reinit
            1 6755机型已调整实现，不会出现主接口为sta模式且关闭wpa_supplicant进程，是否需要待评估确认。
            2 6756机型，不会出现主接口为sta模式且关闭wpa_supplicant进程，驱动有相关恢复机制，不需要上层监控。
        ******************************************************************************************************************/
            if (AWND_OK == _wl_get_reinit_cnt(ifname, &reinit_cnt))
            {
                if (g_awnd.reinitCnt[band] >= REINIT_CNT_THRESOLD &&
                    (reinit_cnt - g_awnd.reinitCnt[band] >=
                        (REINIT_CNT_TIMER * l_awnd_config.tm_bss_status_inspect/60000)))
                {
                    AWN_LOG_ERR("%s reinit cnt increase from %u to %u", ifname, g_awnd.reinitCnt[band], reinit_cnt);
                    _wl_restart(ifname);
                }
                g_awnd.reinitCnt[band] = reinit_cnt;
            }
            else
            {
                AWN_LOG_ERR("%s reinit cnt get fail", ifname);
                g_awnd.reinitCnt[band] = 0;
            }
#endif

#if CONFIG_BAND_WIDTH_CHECK
            if (l_awnd_config.band_5g2_type == band && AWND_MODE_FAP == g_awnd.workMode)
            {
                if (AWND_OK == get_wifi_bw_bcm(band, &wifi_bw_5g2))
                {
                    if(wifi_bw_5g2 != wifi_bw_dft_5g2)
                    {
                        g_awnd.bwNeqCnt[band] += 1;
                        AWN_LOG_DEBUG("%s band width not equal Cnt=%d", ifname, g_awnd.bwNeqCnt[band]);
                    }
                    // reset if band width not equal to HT80 after over 1 minutes
                    if (g_awnd.bwNeqCnt[band] * l_awnd_config.tm_bss_status_inspect >= BWRESET_TOTAL_TIME)
                    {
                        if (AWND_OK == get_backhaul_ap_channel_bcm(band, &channel_5g2))
                        {
                            set_wifi_bw_bcm(band, channel_5g2 ,wifi_bw_dft_5g2);
                        }
                        else
                        {
                            AWN_LOG_WARNING("%s get channel failed", ifname);
                        }
                        g_awnd.bwNeqCnt[band] = 0;
                    }
                }
                else
                {
                    AWN_LOG_WARNING("%s get band width failed", ifname);
                    g_awnd.bwNeqCnt[band] = 0;
                }
            }
#endif
        }
    }

    return AWND_OK;
}
#else
int bss_status_check_bcm()
{
    return AWND_OK;
}
#endif /* CONFIG_BSS_STATUS_CHECK */

int wpa_supplicant_status_check_bcm(AWND_BAND_TYPE band)
{
    FILE *fp = NULL;
    char *s = NULL;
    char cmdline[CMDLINE_LENGTH] = {0};
    char line[READ_LINE_LEN] = {0};
    struct ifreq ifr;
    static UINT8 wpa_restart_cnt[AWND_BAND_MAX] = {0};
    struct ether_addr bssid;
#if WPA_PRI_STATE_CHECK
    static UINT8 abnormal_cnt[AWND_BAND_MAX] = {0};
    UINT8 wpa_abnormal = 0;
#endif /* WPA_PRI_STATE_CHECK */
    int ret = AWND_OK;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, l_awnd_config.staIfnames[band], IFNAMSIZ);
    if (AWND_OK == _wl_get_rootap_info(&ifr, &bssid) &&
        !memcmp(g_awnd.staConfig[band].bssid, &bssid, sizeof(struct ether_addr))) {
        AWN_LOG_WARNING("%s: is in connected status; no need to check wpa_supplicant", l_awnd_config.staIfnames[band]);
        return AWND_OK;
    }

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" status", l_awnd_config.staIfnames[band]);
    fp = popen(cmdline, "r");
    if (NULL == fp)
    {
        AWN_LOG_INFO("Failed to open %s", cmdline);
    }
    else
    {
	while (fgets(line, READ_LINE_LEN, fp) != NULL)
        {
#if WPA_PRI_STATE_CHECK
                if (NULL != (s = strstr(line, "wpa_tp_pri_state=ABNORMAL"))) {;
                        AWN_LOG_INFO("wpa_supplicant ABNORMAL");
			wpa_abnormal = 1;
                }
#endif /* WPA_PRI_STATE_CHECK */
        }
        pclose(fp);
    }

#if WPA_PRI_STATE_CHECK
    if (wpa_abnormal && AWND_BAND_5G != band && AWND_BAND_2G != band ) {
    /**********************************************************************************************
        to fix Bug 536906: 【PowerCycle】开关机三频backhaul桥接测试，重启FAP测试，1/50概率性RE样机6G backhaul无法正常桥接
        出现一直连接不成功显现。表现为wpa_supplicant条目一致被加入黑名单。
        在wpa_supplicant的state信息中加入wpa_tp_pri_state状态，有normal与abnormal两种。
        abnormal的条件是黑名单加入次数过多。仅重启wpa_supplicant能清除该标志。
    ************************************************************************************************/
	abnormal_cnt[band] ++;
	wpa_restart_cnt[band] ++;
        AWN_LOG_WARNING("%s wpa_tp_pri_state is ABNORMAL to restart wpa_supplicant, band %d, abnormal_cnt %d, restart_cnt %d", 
				l_awnd_config.staIfnames[band], (UINT8)band, abnormal_cnt[band], wpa_restart_cnt[band]);
        _wpa_supplicant_restart(band);

        if (4 == (wpa_restart_cnt[band] % 5)) {
            AWN_LOG_WARNING("%s band %d, restart_cnt %d to wl down/up", l_awnd_config.staIfnames[band], (UINT8)band,  wpa_restart_cnt[band]);
            sleep(1);
            _wl_restart(l_awnd_config.apIfnames[band]);
        }

	ret = AWND_ERROR;
    }
#endif /* WPA_PRI_STATE_CHECK */

    return ret;
}

int get_wifi_zwdfs_support_bcm(AWND_BAND_TYPE band)
{
    FILE * fp;
    INT8 ifname[IFNAMSIZ] = {0};
    char cmd[CMDLINE_LENGTH];
    char buffer[READLINE_LENGTH];

    snprintf(ifname, sizeof(ifname), l_awnd_config.apIfnames[band]);
    snprintf(cmd, sizeof(cmd), "wl -i %s cap | grep ' bgdfs ' | grep ' bgdfs160 ' | wc -l", ifname);
    fp = popen(cmd, "r");
    if (NULL == fp) {
        AWN_LOG_WARNING("Failed to get %s bgdfs bgdfs160", ifname);
        return AWND_ERROR;
    }
    else {
        fgets(buffer, sizeof(buffer), fp);
        pclose(fp);
        if (!strncmp(buffer, "1", 1))
            return AWND_OK;
        else
            return AWND_ERROR;
    }

    return AWND_ERROR;
}

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_bcm(AWND_BAND_TYPE band)
{
    _proxy_l2uf_single_interface(l_awnd_config.hostIfnames[band]);
    _proxy_l2uf_single_interface(l_awnd_config.apIfnames[band]);

    return AWND_OK;
}

int reload_sta_conf_bcm(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" reconfigure &", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "BCM_WPA_SUPPLICANT_CTRL_STA_FMT" enable_network 0 &", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    return AWND_OK;
}

int set_wireless_sta_bssid_bcm(char *bssid_str, AWND_BAND_TYPE band)
{
    char vap_name[IFNAMSIZ] = {0};
    snprintf(vap_name, sizeof(vap_name), l_awnd_config.staIfnames[band]);
    return awnd_config_sta_bssid(bssid_str, vap_name);
}

int wifi_re_roam_bcm(void)
{
    AWND_BAND_TYPE band;
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, CMDLINE_LENGTH, "wifi update reroam ");
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
        if (band != AWND_BAND_2G) {
            awnd_strlcat(cmdline, ",", CMDLINE_LENGTH);
        }
        awnd_strlcat(cmdline, l_awnd_config.staIfnames[band], CMDLINE_LENGTH);
    }
    _wifi_exec_cmd(cmdline);
    return AWND_OK;
}
#endif

AWN_PLATFORM_OPS awn_platform_bcm = {
    .get_default_mesh_channel = get_default_mesh_channel_bcm,
    .check_block_chan_list = check_block_chan_list_bcm,
    .get_sta_channel = get_sta_channel_bcm,
    .get_backhaul_ap_channel = get_backhaul_ap_channel_bcm,

    .get_phy = get_phy_bcm,
    .get_wds_state = get_wds_state_bcm,
    .get_rootap_phyRate = get_rootap_phyRate_bcm,
    .get_rootap_rssi = get_rootap_rssi_bcm,
    .get_rootap_info = get_rootap_info_bcm,
    .get_rootap_tpie = get_rootap_tpie_bcm,
    .get_tpie = get_tpie_bcm,


    .init_tpie = init_tpie_bcm,
    .update_wifi_tpie = update_wifi_tpie_bcm,
    
    .flush_scan_table_single_band = flush_scan_table_single_band_bcm,
    .flush_scan_table = flush_scan_table_bcm,
    .do_scan = do_scan_bcm,
    .do_scan_fast = do_scan_fast_bcm,
    .get_scan_result = get_scan_result_bcm,

    .set_channel = set_channel_bcm,
    .get_sta_iface_in_bridge = get_sta_iface_in_bridge_bcm,

    .disconn_sta_pre = disconn_sta_pre_bcm,
    .disconn_all_sta_pre = disconn_all_sta_pre_bcm,
    .disconn_sta_post = disconn_sta_post_bcm,
    .disconn_sta = disconn_sta_bcm,
    .disconn_all_sta = disconn_all_sta_bcm,
    .reconn_sta_pre = reconn_sta_pre_bcm,
    .reconn_sta_post = reconn_sta_post_bcm,
    .reset_sta_connection = reset_sta_connection_bcm,

    .set_backhaul_sta_dev = set_backhaul_sta_dev_bcm,
    .do_band_restart = do_band_restart_bcm,
    .get_wifi_bw = get_wifi_bw_bcm,
    .set_wifi_bw = set_wifi_bw_bcm,
    .bss_status_check = bss_status_check_bcm,
    .wpa_supplicant_status_check = wpa_supplicant_status_check_bcm,
    .get_wifi_zwdfs_support = get_wifi_zwdfs_support_bcm,

#ifdef CONFIG_AWN_RE_ROAMING
    .proxy_l2uf = proxy_l2uf_bcm,
    .reload_sta_conf = reload_sta_conf_bcm,
    .set_wireless_sta_bssid = set_wireless_sta_bssid_bcm,
    .wifi_re_roam = wifi_re_roam_bcm,
#endif /* CONFIG_AWN_RE_ROAMING */
};

AWN_PLATFORM_OPS *awn_platform_ops = &awn_platform_bcm;

