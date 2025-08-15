/*
 *
 *\file      awn_wifi_handler.c
 *\brief     
 *
 *\author    Weng Kaiping
 *\version   1.0.0
 *\date      12Apr16
 *
 *\history \arg 1.0.0, 12Apr16, Weng Kaiping, Create the file. 
 */

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
#include <pthread.h>
#include <unistd.h>
#include <errno.h>

#include "tp_linux.h"

#include "../auto_wifi_net.h"
#include "../awn_log.h"
#include "../awn_wifi_handler_api.h"

#include "awn_wifi_handler_cfg80211_qca.h"

#include "wlanif_cmn.h"
#include <errno.h>
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

#define MLO_INVALID_LINK_ID 255

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/



/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/
struct wlanif_config *wlanIfAwn = NULL;

static QCA_CHANNEL l_qca_channel[] = {
        {34, 5170},
        {36, 5180},
        {38, 5190},
        {40, 5200},
        {42, 5210},
        {44, 5220},
        {46, 5230},
        {48, 5240},
        {52, 5260},
        {56, 5280},
        {60, 5300},
        {64, 5320},
        {100, 5500},
        {104, 5520},
        {108, 5540},
        {112, 5560},
        {116, 5580},
        {120, 5600},
        {124, 5620},
        {128, 5640},
        {132, 5660},
        {136, 5680},
        {140, 5700},
        {149, 5745},
        {153, 5765},
        {157, 5785},
        {161, 5805},
        {165, 5825},
        
        {-1, -1} //default
};

static char *real_band_suffix[AWND_REAL_BAND_MAX] = {"2g", "5g", "5g_2", "6g", "6g_2"};

extern AWND_GLOBAL g_awnd;
extern AWND_CONFIG l_awnd_config;
extern int fap_oui_update_status;
extern int re_oui_update_status;
extern int oui_now_version;
extern int oui_old_version;
extern IEEE80211_TP_OUI_LIST tp_oui_list[TP_OUI_MAX_VERSION+1];

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

static int
isqca_whc_oui(UINT8 *frm, UINT8 whc_subtype)
{
    return ((frm[1] > 4) && (LE_READ_4(frm+2) == ((QCA_OUI_WHC_TYPE<<24)|QCA_OUI)) &&
            (*(frm+6) == whc_subtype));
}


#if 0
static void _macaddr_ntop(UINT8* mac, char* buf)
{
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
#endif


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

static int _get_5g_channel(int freq)
{
    
    int index = 0;
    
    for (index = 0; l_qca_channel[index].freq != -1; index++)
    {
        if (l_qca_channel[index].freq == freq)
        {
            return l_qca_channel[index].channel;
        }
    }

    return 36;//default channel
}

static int _wifi_exec_cmd(INT8* cmd, ...)
{
    char buf[2048] = {0};
    va_list vaList;

    va_start (vaList, cmd);
    vsprintf (buf, cmd, vaList);
    va_end (vaList);
    
    TP_SYSTEM(buf);
    AWN_LOG_WARNING("wifi cmd(%s)", buf);

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

static int awnd_config_check_mod(char *mod_name)
{
    FILE *fp = NULL;
    char cmd[128];

    snprintf(cmd, sizeof(cmd), "lsmod | grep -o '%s'", mod_name);
    AWN_LOG_NOTICE("check_mod_cmd:%s", cmd);

    fp = popen(cmd, "r");
    if(fp == NULL)
    {
        return 0;
    }else
    {
        AWN_LOG_INFO("mod exist");
        pclose(fp);
        fp = NULL;
        return 1;
    }
}

static void awnd_do_shell_task(char *command)
{
    int fd;
        
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
        
    char *argv[4];
    argv[0] = "sh";
    argv[1] = "-c";
    argv[2] = command;
    argv[3] = 0;
    execve("/bin/sh", argv, NULL);
    exit(127);

    return;
}

static int check_vap_is_up(const char *vapname)
{
	FILE* fp = NULL;
    char output[256] = {0};
    char cmd[64] = {0};
	char *json_str = NULL;
    int result = -1;
	int error_code;
	int max_rate;
	size_t buf_size = 0;

	json_object *root_obj = NULL;
    json_object *error_code_obj = NULL;
    json_object *max_rate_obj = NULL;


    snprintf(cmd, sizeof(cmd) - 1, "wifiapi -i %s max_rate", vapname);
    if ((fp = popen(cmd, "r")) == NULL)
    {
        goto cleanup;
    }

	while (fgets(output, sizeof(output), fp) != NULL) {
		char *new_ptr = realloc(json_str, buf_size + strlen(output) + 1);
		if (!new_ptr)
		{
			goto cleanup;
		}
		json_str = new_ptr;
        strncpy(json_str + buf_size, output, strlen(output) + 1);
		buf_size += strlen(output);
    }

	if (!json_str) {
		goto cleanup;
	}

	//解析json，获取error_code和max_rate
	root_obj = json_tokener_parse(json_str);
    if (root_obj == NULL) {
        AWN_LOG_DEBUG("Failed to parse JSON\n");
        goto  cleanup;
    }
	
	// 获取error_code、max_rate字段
    if (!json_object_object_get_ex(root_obj, "error_code", &error_code_obj)) {
        goto  cleanup;
    }
    if (!json_object_object_get_ex(root_obj, "max_rate", &max_rate_obj)) {
        goto  cleanup;
    }
    error_code = json_object_get_int(error_code_obj);
    max_rate = json_object_get_int(max_rate_obj);

	if (error_code == 0 && max_rate > 0)
	{
		result = 0;
	}

cleanup:
	if(fp)
		pclose(fp);
	if (root_obj)
		json_object_put(root_obj);
	free(json_str);

	return result;
}

static int check_if_mld(const char *vapname)
{
    const char *colon_pos = strstr(vapname, "mld");
    if (colon_pos == NULL)
    {
        return -1;
    }
    return 0;   
}

static int get_linkid_by_vapname(int *linkid, const char *vapname)
{
    char buf[544];
    const char *colon_pos = strchr(vapname, ':');
    if (colon_pos == NULL)
    {
        return -1;
    }
    *linkid = atoi(colon_pos + 1);

    return 0;   
}

static int get_vapname_by_ifname(const char *ifname, char *vapname, size_t vapname_size)
{
    char command[128];
    FILE *fp;

    //构建uci指令，获取vapname
    snprintf(command, sizeof(command), "uci get wireless.%s.vapname", ifname);
    fp = popen(command, "r");
    if (fp == NULL)
    {
        return -1;
    }
    //读取命令输出
    if (fgets(vapname, vapname_size, fp) != NULL)
    {
        // 去掉换行符
        vapname[strcspn(vapname, "\n")] = 0;
        pclose(fp);
        return 0;
    }

    pclose(fp);
    return -1;    
}

static int get_athsection_by_mld(const char *mldname, char *athsection, size_t athsection_size)
{
    char command[128];
    FILE *fp;

    //构建uci指令，获取athx section
    snprintf(command, sizeof(command), "uci get mld_list.%s.ath_section -c /etc/profile.d/", mldname);
    fp = popen(command, "r");
    if (fp == NULL)
    {
        return -1;
    }
    //读取命令输出
    if (fgets(athsection, athsection_size, fp) != NULL)
    {
        // 去掉换行符
        athsection[strcspn(athsection, "\n")] = 0;
        pclose(fp);
        return 0;
    }
    AWN_LOG_ERR("awn get_athsection_by_mld failed , mldname: %s\n", mldname);

    pclose(fp);
    return -1;    
}

static int _get_channel(char *ifname, int *channel) 
{
    int32_t freq = 0;
    int linkid = MLO_INVALID_LINK_ID;

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getFreq_cfg80211(wlanIfAwn->ctx, ifname, &freq, linkid) < 0) {
        AWN_LOG_INFO("getFreq failed, ifName: %s, linkid: %d", ifname, linkid);
        return AWND_ERROR;
    }

    freq = freq / 100000;
    //AWN_LOG_ERR("awn getFreq , ifName: %s, freq: %d\n", ifname, freq);

    if (freq <= 2484)
    {
        if (freq == 2484)
        {
            *channel = 14;
        }
        else
        {
            *channel = (freq - 2407) / 5;
        }
    }
    else if (freq >= 5950)
    {
        *channel = (freq - 5950) / 5;
    }
    else 
    {
        *channel = _get_5g_channel(freq);
    }

    AWN_LOG_DEBUG("awn _get_channel , ifName: %s, channel: %d\n", ifname, *channel);

    return AWND_OK;
}

static int _get_freq(char *ifname, int *freq) 
{
    int linkid = MLO_INVALID_LINK_ID;

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getFreq_cfg80211(wlanIfAwn->ctx, ifname, freq, linkid) < 0) {
        AWN_LOG_INFO("getFreq failed, ifName: %s, linkid: %d", ifname, linkid);
        return 0;
    }

    AWN_LOG_DEBUG("awn _get_freq , ifName: %s, freq: %d\n", ifname, *freq);

    return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
static int proxy_l2uf_single_interface(const char *ifname)
{
    struct ieee80211_wlanconfig config;
    int linkid = MLO_INVALID_LINK_ID;

    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (setProxyl2uf_cfg80211_tp(wlanIfAwn->ctx, ifname, &config, linkid) < 0) {
        AWN_LOG_ERR("proxy_l2uf_single_interface failed, ifName: %s", ifname);
        return 0;
    }
    return AWND_OK;
}
#endif


/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/

int init_cfg80211_qca(void)
{
    wlanIfAwn = wlanif_config_init(AWND_NL80211_CMD_SOCK,
                                    AWND_NL80211_EVENT_SOCK);
    return 0;
}

int deinit_cfg80211_qca(void)
{
	wlanif_config_deinit(wlanIfAwn);
    return 0;
}

/*!
 *\fn           get_default_mesh_channel_qca(AWND_BAND_TYPE band, int *channel)
 *\brief        Get channel of default config
 *\param[in]       band              Wireless band type 2G/5G
 *\return       int
 */
int get_default_mesh_channel_qca(AWND_BAND_TYPE band, int *channel)
{
    return _get_channel(l_awnd_config.apIfnames[band], channel);
}

/*!
 *\fn           get_sta_channel_qca(AWND_BAND_TYPE band, int *channel)
 *\brief        Get channel of sta interface
 *\param[in]       band              Wireless band type 2G/5G
 *\return       int
 */
int get_sta_channel_qca(AWND_BAND_TYPE band, int *channel)
{
    return _get_channel(l_awnd_config.staIfnames[band], channel);
}


/*!
 *\fn           get_backhaul_ap_channel_qca(AWND_BAND_TYPE band, int *channel)
 *\brief        Get channel of backhaul ap interface
 *\param[in]       band              Wireless band type 2G/5G
 *\return       int
 */
int get_backhaul_ap_channel_qca(AWND_BAND_TYPE band, int *channel)
{
    return _get_channel(l_awnd_config.apIfnames[band], channel);
}

/*!
 *\fn           get_phy_qca()
 *\brief        Get connect status of STA vap
 *\param[in]       band              Wireless band type 2G/5G
 *\return       int
 */
int get_phy_qca(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth)
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    struct ieee80211_wlanconfig config;
    int linkid = MLO_INVALID_LINK_ID;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getPhy_cfg80211_tp(wlanIfAwn->ctx, ifname, &config, linkid) < 0) {
        AWN_LOG_ERR("getphy failed, ifName: %s", ifname);
        return AWND_ERROR;
    }

    *nss = config.data.phy.nss;
    *phyMode = config.data.phy.phyMode;
    *chwidth = config.data.phy.chwidth;
    /* wifi driver 80/160(3)/80_80(4)/320(5), awnd:80/160(3)/320(4) (no 80_80)
        ==> for 320M: wifi return wlan_chwidth_320(5) should reduce to 4 */
    if (4 == config.data.phy.chwidth) {
        /* chwidth_80_80 */
        *chwidth = wlan_chwidth_160;
    }
    else if (config.data.phy.chwidth >= 5) {
        /* chwidth_320 */
        *chwidth = wlan_chwidth_320;
    }

    AWN_LOG_DEBUG("[awnd_get_phy]%s nss:%d, phyMode:%d, chwidth:%d\n", ifname, *nss, *phyMode, *chwidth);

    return AWND_OK;
}

/*!
 *\fn           get_wds_state_qca()
 *\brief        Get connect status of STA vap
 *\param[in]       band              Wireless band type 2G/5G
 *\return       int
 */
int get_wds_state_qca(AWND_BAND_TYPE band, int *up)
{
    struct ieee80211_wlanconfig config;
    int32_t wds_state = 0;
    int linkid = MLO_INVALID_LINK_ID;
    int ret;
    char type[16] = {0};
    struct ifreq ifr = {0};
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    char athsection[64] = {0};
    char vapname[64] = {0};

    *up = 0;

    if (awnd_config_get_stacfg_type(band, type) == AWND_OK) {
        if (strcmp(type, "backup") == 0) {
            return 0;
        }
    }

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    memset(&ifr, 0, sizeof(ifr));
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

    if (getWds_cfg80211_tp(wlanIfAwn->ctx, ifname, &wds_state, linkid) < 0) {
        AWN_LOG_DEBUG("getWdsState failed, ifName: %s, linkid: %d", ifname, linkid);
        return 0;
    }

    ret = (wds_state == AWN_WDS_STATE_UP ? 1 : 0);

    AWN_LOG_DEBUG("[getWdsState]%s, ret= %d wds state:%d\n", ifname, ret, wds_state);

    return ret;
}

/*!
 *\fn           get_cac_state_qca()
 *\brief        Get cac status of interface
 *\param[in]       band              Wireless band type 2G/5G/6G
 *\return       int
 */
int get_cac_state_qca(AWND_BAND_TYPE band, int *state)
{
    int32_t cac_state = 0;
    int linkid = MLO_INVALID_LINK_ID;
    INT8 ifname[QCA_IFNAMSIZ] = {0};

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getCacState_cfg80211(wlanIfAwn->ctx, ifname, &cac_state, linkid) < 0) {
        AWN_LOG_ERR("getCacState failed, ifName: %s, linkid: %d", ifname, linkid);
        return 0;
    }

   AWN_LOG_DEBUG("ifname : %s cac state : %d", ifname, cac_state);
    return AWND_OK;
}

/*!
 *\fn           get_rootap_phyRate_qca()
 *\brief        Get RootAp info
 *\param[in]       band       Wireless band type 2G/5G
 *\param[out]   pApEntry   The data struct of AWND_AP_ENTRY 
 *\return       OK/ERROR 
 */
int get_rootap_phyRate_qca(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate)
{
    u_int8_t *buf = NULL;
    int length = 0;
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;
    int ret = AWND_OK;
    int i = 0;

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, ifname);
    }

    do {
        if(getStationInfo_cfg80211(wlanIfAwn->ctx, ifname, (void **)(&buf), &length, linkid) < 0) {
            AWN_LOG_ERR("Failed to perform ioctl for iface %s", ifname);
            ret = AWND_ERROR;
            break;
        }
        if (!buf) {
            AWN_LOG_ERR("Station info is NULL for iface: %s", ifname);
            ret = AWND_ERROR;
            break;
        }

        // Loop over all of the STAs, providing a callback for each one.
        u_int8_t *currentPtr = buf;
        u_int8_t *endPtr = buf + length;

        AWN_LOG_DEBUG("Station info length %d\n", length);
        length = 0;
        while (currentPtr + sizeof(struct ieee80211req_sta_info) <= endPtr) {
            const struct ieee80211req_sta_info *staInfo =
                (const struct ieee80211req_sta_info *) currentPtr;
            if(!staInfo->isi_len) {
                AWN_LOG_ERR("Invalid STA Info \n", __func__);
                break;
            }

            if(staInfo->isi_txratekbps == 0)
                *txrate = (staInfo->isi_rates[staInfo->isi_txrate] & IEEE80211_RATE_VAL)/2;
            else
                *txrate = staInfo->isi_txratekbps / 1000;
            if(staInfo->isi_rxratekbps >= 0) {
                *rxrate = staInfo->isi_rxratekbps / 1000;
            }

            i++;
            if (i >= 1)
            {
                break;
            }

            currentPtr += staInfo->isi_len;
        }
    } while (0);

    AWN_LOG_DEBUG("ifname : %s get_rootap_phyRate txrate: %d, rxrate: %d", ifname, *txrate, *rxrate);

    if (buf)
        free(buf);
    return ret;
}

/*!
 *\fn           get_rootap_rssi_qca()
 *\brief        Get RootAp info
 *\param[in]       band       Wireless band type 2G/5G
 *\param[out]   pApEntry   The data struct of AWND_AP_ENTRY 
 *\return       OK/ERROR 
 */
int get_rootap_rssi_qca(AWND_BAND_TYPE band, UINT16 *rssi)
{
    u_int8_t *buf = NULL;
    int length = 0;
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;
    int ret = AWND_OK;
    int i = 0;

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    do {
        if(getStationInfo_cfg80211(wlanIfAwn->ctx, ifname, (void **)(&buf), &length, linkid) < 0) {
            AWN_LOG_ERR("Failed to perform ioctl for iface %s", ifname);
            ret = AWND_ERROR;
            break;
        }
        if (!buf) {
            AWN_LOG_ERR("Station info is NULL for iface: %s", ifname);
            ret = AWND_ERROR;
            break;
        }

        // Loop over all of the STAs, providing a callback for each one.
        u_int8_t *currentPtr = buf;
        u_int8_t *endPtr = buf + length;

        AWN_LOG_CRIT("Station info length %d\n", length);
        length = 0;
        while (currentPtr + sizeof(struct ieee80211req_sta_info) <= endPtr) {
            const struct ieee80211req_sta_info *staInfo =
                (const struct ieee80211req_sta_info *) currentPtr;
            if(!staInfo->isi_len) {
                AWN_LOG_ERR("Invalid STA Info \n", __func__);
                break;
            }

            *rssi = staInfo->isi_rssi;

            i++;
            if (i >= 1)
            {
                break;
            }

            currentPtr += staInfo->isi_len;
        }
    } while (0);

    AWN_LOG_CRIT("ifname : %s get_rootap_rssi rssi: %d", ifname, *rssi);

    if (buf)
        free(buf);
    return ret;
}

#ifdef SUPPORT_MESHMODE_2G
static void freq_to_channel(int *cur_chan)
{
	/* convert to channel num */
	if (*cur_chan == 2484)
	{
    	*cur_chan = 14;
	}
	else if (*cur_chan < 2484)
	{
    	*cur_chan = (*cur_chan - 2407) / 5;
	}
	else if (*cur_chan < 5000) 
	{
    	if (*cur_chan > 4900) 
		{
        	*cur_chan = (*cur_chan - 4000) / 5;
    	} 
		else
		{
        	*cur_chan = 15 + ((*cur_chan - 2512) / 20);
    	}
	}
	else if (*cur_chan < 5950)
	{
		*cur_chan = (*cur_chan - 5000) / 5;
	}
	else
	{
		*cur_chan = (*cur_chan - 5950) / 5;
	}

	return;
}

int get_chanim_qca(AWND_BAND_TYPE band, INT32 *chan_util, INT32 *intf, int *cur_chan, AWND_WIFI_BW_TYPE *bw)
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    ieee80211_rrmutil_t rrmutil;
    int linkid = MLO_INVALID_LINK_ID;
    int ChannelWidth;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    memset(&rrmutil, 0, sizeof(ieee80211_rrmutil_t));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getRrmutil_cfg80211_tp(wlanIfAwn->ctx, ifname, &rrmutil, linkid) < 0) {
        AWN_LOG_ERR("getrrmutil failed, ifName: %s", ifname);
        return AWND_ERROR;
    }

    if (getChannelWidth_cfg80211(wlanIfAwn->ctx, ifname, &ChannelWidth, linkid) < 0) {
        AWN_LOG_ERR("getrrmutil failed, ifName: %s", ifname);
        return AWND_ERROR;
    }

    *chan_util = rrmutil.chann_util + rrmutil.obss_util;
    *intf = rrmutil.obss_util;
    *cur_chan = rrmutil.channel;
    freq_to_channel(cur_chan);
    *bw = ChannelWidth;

    AWN_LOG_NOTICE("[awnd_get_chanim_qca]%s chan_util:%d, intf:%d, cur_chan:%d, bw:%d\n", ifname, *chan_util, *intf, *cur_chan, *bw);

    return AWND_OK;
}

void do_csa_qca(int target_chan, AWND_WIFI_BW_TYPE bw, AWND_CHAN_OFFSET_TYPE offset)
{
    char    buff[256];
    INT8 section_2g[QCA_IFNAMSIZ] = "ath02";
    char vapname[64];

    if(get_vapname_by_ifname(section_2g, vapname, sizeof(vapname)) < 0)
    {
        AWN_LOG_ERR("get_vapname_by_ifname failed, ifName: %s", section_2g);
    }

    if(check_if_mld(vapname) >= 0)
    {

        switch (bw) {
        case WIFI_BW_20M:
            sprintf(buff, "cfg80211tool mld02 link_id 0 doth_ch_chwidth %d 0 20",target_chan);
            break;
        case WIFI_BW_40M:
            sprintf(buff, "cfg80211tool mld02 link_id 0 doth_ch_chwidth %d 0 40",target_chan);
            break;
        case WIFI_BW_80M:
            sprintf(buff, "cfg80211tool mld02 link_id 0 doth_ch_chwidth %d 0 80",target_chan);
            break;
        case WIFI_BW_160M:
            sprintf(buff, "cfg80211tool mld02 link_id 0 doth_ch_chwidth %d 0 160",target_chan);
            break;
        default:
            sprintf(buff, "cfg80211tool mld02 link_id 0 doth_ch_chwidth %d 0 20",target_chan);
            break;
        }
    }
    else
    {
        switch (bw) {
        case WIFI_BW_20M:
            sprintf(buff, "cfg80211tool ath02 doth_ch_chwidth %d 0 20",target_chan);
            break;
        case WIFI_BW_40M:
            sprintf(buff, "cfg80211tool ath02 doth_ch_chwidth %d 0 40",target_chan);
            break;
        case WIFI_BW_80M:
            sprintf(buff, "cfg80211tool ath02 doth_ch_chwidth %d 0 80",target_chan);
            break;
        case WIFI_BW_160M:
            sprintf(buff, "cfg80211tool ath02 doth_ch_chwidth %d 0 160",target_chan);
            break;
        default:
            sprintf(buff, "cfg80211tool ath02 doth_ch_chwidth %d 0 20",target_chan);
            break;
        }
    }


    AWN_LOG_NOTICE("lxdebug need to csa to target_chan\n");
    system(buff);
}

void disable_sta_vap_qca(int disable, AWND_BAND_TYPE band)
{
    char staIfname[IFNAMSIZ] = {0};
    char athsection[64] = {0};
    char cmdline[CMDLINE_LENGTH] = {0};

    if (disable)
    {
        _wifi_exec_cmd("touch /tmp/awnd_meshmode_2g_disconnect");
        awnd_write_rt_info(band, FALSE, NULL, FALSE);
    } else {
        _wifi_exec_cmd("rm /tmp/awnd_meshmode_2g_disconnect");
    }

    strncpy(staIfname, l_awnd_config.staIfnames[band], sizeof(staIfname));
    if(check_if_mld(staIfname) >= 0)
    {
        if (disable)
        {
            snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "QCA_WPA_SUPPLICANT_CTRL_STA_FMT" disconnect",
                l_awnd_config.staIfnames[band]);
            _wifi_exec_cmd(cmdline);
            snprintf(cmdline, sizeof(cmdline), "ifconfig %s down",
                l_awnd_config.staIfnames[band]);
            _wifi_exec_cmd(cmdline);
        }
        get_athsection_by_mld(staIfname, athsection, sizeof(athsection));
        strncpy(staIfname, athsection, IFNAMSIZ);
    }

    _wifi_exec_cmd("wifi update vap %s", staIfname);
}
#endif

/*!
 *\fn           get_rootap_info_qca()
 *\brief        Get RootAp info
 *\param[in]       band       Wireless band type 2G/5G
 *\param[out]   pApEntry   The data struct of AWND_AP_ENTRY 
 *\return       OK/ERROR 
 */
int get_rootap_info_qca(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band)
{
    u_int8_t *buf = NULL;
    int length = 0;
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;
    int ret = AWND_OK;
    int i = 0;
    int ielen = 0;

    strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    do {
        if(getStationInfo_cfg80211(wlanIfAwn->ctx, ifname, (void **)(&buf), &length, linkid) < 0) {
            AWN_LOG_ERR("Failed to perform ioctl for iface %s", ifname);
            ret = AWND_ERROR;
            break;
        }
        if (!buf) {
            AWN_LOG_ERR("Station info is NULL for iface: %s", ifname);
            ret = AWND_ERROR;
            break;
        }

        // Loop over all of the STAs, providing a callback for each one.
        u_int8_t *currentPtr = buf;
        u_int8_t *endPtr = buf + length;

        AWN_LOG_CRIT("Station info length %d\n", length);
        length = 0;
        while (currentPtr + sizeof(struct ieee80211req_sta_info) <= endPtr) {
            u_int8_t *vp;
            const struct ieee80211req_sta_info *staInfo =
                (const struct ieee80211req_sta_info *) currentPtr;

            vp = (u_int8_t*)(staInfo + 1);
            if(!staInfo->isi_len) {
                AWN_LOG_ERR("Invalid STA Info \n", __func__);
                break;
            }

            memcpy(pApEntry->bssid, staInfo->isi_macaddr, IEEE80211_ADDR_LEN);

            AWN_LOG_CRIT("ie_len of rootAp:%d", staInfo->isi_ie_len);
            ielen = staInfo->isi_ie_len;
            while (ielen > 0) 
            {
                if (vp[0] == IEEE80211_ELEMID_VENDOR && istpoui(vp))
                {
                    memcpy(&pApEntry->netInfo, vp, sizeof(AWND_NET_INFO));
                    break;
                }
            
                ielen -= 2+vp[1];
                vp += 2+vp[1];
            }

            AWN_LOG_DEBUG("%-6s  bssid:%02X:%02X:%02X:%02X:%02X:%02X, isi_ie_len:%d", ifname, 
                pApEntry->bssid[0], pApEntry->bssid[1], pApEntry->bssid[2], pApEntry->bssid[3],
                pApEntry->bssid[4], pApEntry->bssid[5], staInfo->isi_ie_len);

            i++;
            if (i >= 1)
            {
                break;
            }

            currentPtr += staInfo->isi_len;
        }
    } while (0);

    AWN_LOG_DEBUG("Success to get rootAp info");

    if (buf)
        free(buf);
    return ret;
}

/*!
 *\fn           get_rootap_tpie_qca()
 *\brief        Get tp-link IE of rootAp
 *\param[in]       band           Wireless band type 2G/5G
 *\param[out]   pAwndNetInfo   The data struct of AWND_NET_INFO 
 *\return       OK/ERROR 
 */
int get_rootap_tpie_qca(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    AWND_AP_ENTRY apEntry;
    
    if (NULL == pAwndNetInfo)
    {
        return AWND_ERROR;
    }

    memset(&apEntry, 0, sizeof(AWND_AP_ENTRY));
    memset(pAwndNetInfo, 0, sizeof(AWND_NET_INFO));    
    
    if (AWND_OK == awnd_get_rootap_info(&apEntry, band))
    {
        memcpy(pAwndNetInfo, &apEntry.netInfo, sizeof(AWND_NET_INFO));

        AWN_LOG_DEBUG("Success to get rootAp tpie");
        AWN_LOG_DEBUG("[rootAp:%s]awnd_net_type:%-3d,awnd_level:%-2d, awnd_lanip:%x, awnd_dns:%x, server_detected:%d, server_touch_time:%d \
            awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
                real_band_suffix[_get_real_band_type(band)], pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
                pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
                pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
                pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5]);    
    }

    return AWND_ERROR;
}

int get_tpie_qca(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band)
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    struct ieee80211_wlanconfig config;
    int linkid = MLO_INVALID_LINK_ID;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    config.cmdtype = IEEE80211_WLANCONFIG_TP_IE_GET;
    config.data.tpie.entry_type = entry_type;
    memcpy(config.data.tpie.tp_macaddr, pMac, IEEE80211_ADDR_LEN);

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (getTpie_cfg80211_tp(wlanIfAwn->ctx, ifname, &config, linkid) < 0) {
        AWN_LOG_ERR("gettpie failed, ifName: %s", ifname);
        return AWND_ERROR;
    }

    switch (config.data.tpie.status)
    {
        case 0:
            if(config.data.tpie.tp_ie[0] == IEEE80211_ELEMID_VENDOR && istpoui(config.data.tpie.tp_ie))
            {
                memcpy(pAwndNetInfo, config.data.tpie.tp_ie, sizeof(AWND_NET_INFO));
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

/*!
 *\fn           init_tpie_qca()
 *\param[in]       pApMac         Mac of 2.4G AP VAP
 *\param[in]       netType        Wireless network type FAP/HAP/RE
 *\param[out]   pAwndNetInfo   The data struct of AWND_NET_INFO 
 *\return       OK/ERROR 
 */
int init_tpie_qca(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType)
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

#ifdef CONFIG_AWN_SET_FAPMAC_TO_DRIVER
int awnd_updtae_netmac(AWND_BAND_TYPE band, u_int8_t *mac)
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    struct ieee80211_wlanconfig config;
    int linkid = MLO_INVALID_LINK_ID;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    memset(&config, 0, sizeof(struct ieee80211_wlanconfig));
    memcpy(config.data.snm.mac, mac, AWND_MAC_LEN);

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (setNetmac_cfg80211_tp(wlanIfAwn->ctx, ifname, &config, linkid) < 0) {
        AWN_LOG_ERR("setnetmac failed, ifName: %s", ifname);
        return AWND_ERROR;
    }
	
    return AWND_OK;
}
#endif

/*!
 *\fn           update_wifi_tpie_qca()
 *\param[in]    pAwndNetInfo   The data struct of AWND_NET_INFO 
 *\return       OK/ERROR 
 */
int update_wifi_tpie_qca(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, 
                         u_int16_t* uplinkRate, u_int8_t meshType)
{
    u_int8_t ie_buf[IEEE80211_MAX_OPT_IE + 12];
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    struct ieee80211_wlanconfig_vendorie *vie = (struct ieee80211_wlanconfig_vendorie *) ie_buf;
    AWND_NET_INFO  *ni = NULL;
    AWND_BAND_TYPE band;
    int remove_ret = AWND_OK;
    int ret = AWND_OK;
    UINT8 previous_oui[VENDORIE_OUI_LEN] = {0};
    UINT8* cp = NULL;	
    int tmp_oui_ver;
    int linkid = MLO_INVALID_LINK_ID;

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
                strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
                break;
            case AWND_MESH_CONFIG:
                strncpy(ifname, l_awnd_config.configIfnames[band], sizeof(ifname));
                break;
            default:
                AWN_LOG_ERR("Unknown mesh type:%d\n", meshType);
                break;
        }
        
        if(check_if_mld(ifname) >= 0)
        {
            char athsection[64];
            char vapname[64];
            get_athsection_by_mld(ifname, athsection, sizeof(athsection));
            get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
            get_linkid_by_vapname(&linkid, vapname);
        }

        /* fill up configuration */
        memset(ie_buf, 0, IEEE80211_MAX_OPT_IE + 12);
    
        // vie->cmdtype = IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE;
        vie->ftype_map = IEEE80211_VENDORIE_INCLUDE_IN_BEACON | IEEE80211_VENDORIE_INCLUDE_IN_PROBE_RES;
        vie->ie.id = IEEE80211_ELEMID_VENDOR; /*default vendor ie value */
    
        // memcpy(vie->ie.oui, pAwndNetInfo->oui,VENDORIE_OUI_LEN);
        vie->ie.len = pAwndNetInfo->len;
        memcpy(vie->ie.cap_info, &(pAwndNetInfo->type), (sizeof(AWND_NET_INFO)- 2 - VENDORIE_OUI_LEN));
        
        ni = (AWND_NET_INFO *)(&vie->ie);
        ni->awnd_lanip = htonl(pAwndNetInfo->awnd_lanip);
        ni->server_touch_time = htonl(pAwndNetInfo->server_touch_time);		
        ni->awnd_dns = htonl(pAwndNetInfo->awnd_dns);			
        cp = (u_int8_t *)(&(ni->uplink_mask));
        LE_WRITE_2(cp, uplinkMask);
        LE_WRITE_2(cp, uplinkRate[band]);

        memcpy(ni->lan_mac, lan_mac, AWND_MAC_LEN);
        
        vie->tot_len = vie->ie.len + 12;

        /* fill up request */

        /* fill up oui into vie */
        if(meshType == AWND_MESH_CONFIG)
        {   /* ath04/14 should be the old oui all the time */
            vie->ie.oui[0] = 0x00;
            vie->ie.oui[1] = 0x1d;
            vie->ie.oui[2] = 0x0f;
        }
        else if(meshType == AWND_MESH_BACKHUAL)
        {
            tmp_oui_ver = awnd_get_network_oui();
            if(oui_now_version != tmp_oui_ver)
            {
                awnd_set_oui_now_version(tmp_oui_ver);
                AWN_LOG_ERR("[oui_check] change %s oui to version %d.", ifname, oui_now_version);
            }
            vie->ie.oui[0] = tp_oui_list[oui_now_version].tp_oui[0];
            vie->ie.oui[1] = tp_oui_list[oui_now_version].tp_oui[1];
            vie->ie.oui[2] = tp_oui_list[oui_now_version].tp_oui[2];

            AWN_LOG_DEBUG("update %s oui to 0x%02x%02x%02x.", ifname, vie->ie.oui[0], vie->ie.oui[1], vie->ie.oui[2]);
        }

        vie->cmdtype = IEEE80211_WLANCONFIG_VENDOR_IE_UPDATE;
        if (setTpie_cfg80211_tp(wlanIfAwn->ctx, ifname, vie, linkid) < 0) {
            AWN_LOG_ERR("setTpie_cfg80211_tp failed, ifName: %s, link_id:%d", ifname, linkid);
            return AWND_ERROR;
        }
        AWN_LOG_INFO("config_generic successed awnd_update_tpie() : %s[%d]", ifname, ret);   

#ifdef CONFIG_AWN_SET_FAPMAC_TO_DRIVER
        awnd_updtae_netmac(band, pAwndNetInfo->awnd_mac);
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
        AWN_LOG_INFO("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
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
        AWN_LOG_INFO("update pAwndNetInfo oui to 0x%x%x%x with ret : %d.",pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2],ret);
    }

    AWN_LOG_WARNING("awnd_update_wifi_tpie awnd_net_type:%-3d,awnd_level:%-2d, wait:%d, lanip:%x, dns:%x, \n \
                server_detected:%d, server_touch_time:%d awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X len=%d",
            pAwndNetInfo->awnd_net_type, pAwndNetInfo->awnd_level, pAwndNetInfo->wait, pAwndNetInfo->awnd_lanip, pAwndNetInfo->awnd_dns,
            pAwndNetInfo->server_detected, pAwndNetInfo->server_touch_time,
            pAwndNetInfo->awnd_mac[0],pAwndNetInfo->awnd_mac[1],pAwndNetInfo->awnd_mac[2],
            pAwndNetInfo->awnd_mac[3],pAwndNetInfo->awnd_mac[4],pAwndNetInfo->awnd_mac[5], pAwndNetInfo->len); 
    AWN_LOG_WARNING("label: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X, uplinkMask:%x, uplinkRate:%u/%u/%u/%u", pAwndNetInfo->awnd_label[0],
        pAwndNetInfo->awnd_label[1],pAwndNetInfo->awnd_label[2],pAwndNetInfo->awnd_label[3],pAwndNetInfo->awnd_label[4],
        pAwndNetInfo->awnd_label[5],pAwndNetInfo->awnd_label[6],pAwndNetInfo->awnd_label[7],pAwndNetInfo->awnd_label[8],
        pAwndNetInfo->awnd_label[9],pAwndNetInfo->awnd_label[10],pAwndNetInfo->awnd_label[11],pAwndNetInfo->awnd_label[12],
        pAwndNetInfo->awnd_label[13],pAwndNetInfo->awnd_label[14],pAwndNetInfo->awnd_label[15], uplinkMask, 
        uplinkRate[AWND_BAND_2G],uplinkRate[AWND_BAND_5G], uplinkRate[AWND_BAND_3RD], uplinkRate[AWND_BAND_4TH]);
        
    return ret;
}

int flush_scan_table_single_band_qca(AWND_BAND_TYPE band, BOOL force)
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    char cmdline[CMDLINE_LENGTH] = {0};

    if(check_if_mld(ifname) < 0)
    {
        char vapname[64];
        get_vapname_by_ifname(ifname, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, ifname);
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s s_scan_flush 0 &", ifname);
    }
    else
    {
        char athsection[64];
        char vapname[64];
        u_int8_t *buf = NULL;
        int length = 0;
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
        if(band > AWND_BAND_5G)
        {
            if (getScanresult_cfg80211_tp(wlanIfAwn->ctx, ifname, &buf, &length, linkid) < 0) {
                if(buf)
                {
                    free(buf);
                }
                return AWND_OK;
            }
            if (length == 0)
            {
                if(buf)
                {
                    free(buf);
                }
                return AWND_OK;
            }
        }
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s link_id %d s_scan_flush 0 &", ifname, linkid);
        if(buf)
        {
            free(buf);
        }
    }

    _wifi_exec_cmd(cmdline);   
    return AWND_OK;   
}

int flush_scan_table_qca()
{
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;

    char cmdline[CMDLINE_LENGTH] = {0};

    AWND_BAND_TYPE bi;

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        strncpy(ifname, l_awnd_config.apIfnames[bi], sizeof(ifname));
        if(check_if_mld(ifname) < 0)
        {
            char vapname[64];
            get_vapname_by_ifname(ifname, vapname, sizeof(vapname));
            get_linkid_by_vapname(&linkid, ifname);
            snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s s_scan_flush 0 &", ifname);
        }
        else
        {
            char athsection[64];
            char vapname[64];
            u_int8_t *buf = NULL;
            int length = 0;
            get_athsection_by_mld(ifname, athsection, sizeof(athsection));
            get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
            get_linkid_by_vapname(&linkid, vapname);
            if(bi > AWND_BAND_5G)
            {
                if (getScanresult_cfg80211_tp(wlanIfAwn->ctx, ifname, &buf, &length, linkid) < 0) {
                    if(buf)
                    {
                        free(buf);
                    }
                    return AWND_OK;
                }
                if (length == 0)
                {
                    if(buf)
                    {
                        free(buf);
                    }
                    return AWND_OK;
                }
            }
            snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s link_id %d s_scan_flush 0 &", ifname, linkid);
            if(buf)
            {
                free(buf);
            }
        }
        _wifi_exec_cmd(cmdline); 
    }
    
}

void *_start_scan_single_band( void *arg)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    AWND_VAP_TYPE vap_type = AWND_VAP_AP;
    AWND_BAND_TYPE *band = (AWND_BAND_TYPE *)arg;
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(*band);
    if (AWND_VAP_AP == vap_type)
    {
        if (g_awnd.bindStatus == AWND_BIND_OVER){
            snprintf(cmdline, sizeof(cmdline), "iw dev %s scan > "TMP_WIFI_SCAN_RESULT_FILE" ",
                l_awnd_config.apIfnames[*band], real_band_suffix[real_band]);
        }
        else{
            //snprintf(cmdline, sizeof(cmdline), "iw dev %s scan scanType tss > "TMP_WIFI_SCAN_RESULT_FILE" ",
            //    l_awnd_config.apIfnames[*band], real_band_suffix[real_band]);
            snprintf(cmdline, sizeof(cmdline), "iw dev %s scan > "TMP_WIFI_SCAN_RESULT_FILE" ",
                l_awnd_config.apIfnames[*band], real_band_suffix[real_band]);
        }
    }
    else
    {
	    //snprintf(cmdline, sizeof(cmdline), "iwlist "QCA_STA_IFNAME_FMT" scanning  >/dev/null", (*band ? QCA_IFINDEX_5G_STA : QCA_IFINDEX_2G_STA));
        snprintf(cmdline, sizeof(cmdline), "iw dev %s scan > "TMP_WIFI_SCAN_RESULT_FILE" ",
            l_awnd_config.staIfnames[*band] , real_band_suffix[real_band]);
    }

    _wifi_exec_cmd(cmdline);

}

void *_fast_scan_single_channel(void *arg)
{
    AWND_BAND_TYPE *band = (AWND_BAND_TYPE *)arg;
    int freq = 0;
    int channel = 0;
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    char cmdline[CMDLINE_LENGTH] = {0};

    struct timeval tv;              /* Select timeout */
    int timeout = 15000000;         /* 15s */

    strncpy(ifname, l_awnd_config.apIfnames[*band], sizeof(ifname));
    if ((AWND_OK != _get_freq(ifname, &freq)) || (0 == freq))
    {
        AWN_LOG_WARNING("band:%s get freq:%d fail", ifname, freq);
        goto done;
    }

    /* Init timeout value -> 250ms between set and first get */
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
 
    AWN_LOG_INFO("scan freq:%d", freq);

    snprintf(cmdline, sizeof(cmdline), "iw dev %s scan freq %d ",
        l_awnd_config.apIfnames[*band], freq);
    _wifi_exec_cmd(cmdline);

    timeout -= tv.tv_usec;
 
     /* Forever */
     while(1)
     {
         fd_set     rfds;       /* File descriptors for select */
         int        last_fd;    /* Last fd */
         int        ret;
 
         /* Guess what ? We must re-generate rfds each time */
         FD_ZERO(&rfds);
         last_fd = -1;
 
         /* In here, add the rtnetlink fd in the list */
 
         /* Wait until something happens */
         ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);
 
         /* Check if there was an error */
         if(ret < 0)
         {
             if(errno == EAGAIN || errno == EINTR)
                 continue;
            
            AWN_LOG_WARNING("Unhandled signal - exiting...\n");
            break;
         }
 
         /* Check if there was a timeout */
         if(ret == 0)
         {
            break;
         }
       /* In here, check if event and event type
        * if scan event, read results. All errors bad & no reset timeout */
     }

done:
    AWN_LOG_INFO("outting...\n");
}

/*!
 *\fn           awnd_dual_scan()
 *\brief        
 *\return       int
 */
int do_scan_qca(UINT8 scanBandMask)
{
    pthread_t tid[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band[AWND_BAND_MAX];    
    AWND_BAND_TYPE bi;

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            band[bi]=bi;
            if (pthread_create(&tid[bi], NULL, _start_scan_single_band, (void *)(&band[bi]))) 
            {
                AWN_LOG_WARNING("Fail to create scan thread for band %s", real_band_suffix[_get_real_band_type(bi)]);
                tid[bi] = 0;
            }
        }
    }

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
    
    //sleep(1);
    _stable_sleep(1);
    AWN_LOG_INFO("Finish  scan");
    
    exit(0);
}


/*!
 *\fn           do_scan_fast_qca()
 *\brief        
 *\return       int
 */
int do_scan_fast_qca(UINT8 scanBandMask)
{
    pthread_t tid[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band[AWND_BAND_MAX];
    AWND_BAND_TYPE bi;

    for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
    {
        if (scanBandMask & (1 << bi)) {
            band[bi] = bi;
#ifdef SUPPORT_MESHMODE_2G
            if(((g_awnd.meshmode == AWND_MESHMODE_2G_DYNAMIC && g_awnd.meshstate == AWND_MESHSTATE_2G_DISCONNECT) || 
                (g_awnd.meshmode == AWND_MESHMODE_2G_DISCONNECT)) && bi == AWND_BAND_2G){
                if (pthread_create(&tid[bi], NULL, _start_scan_single_band, (void *)(&band[bi]))) 
                {
                    AWN_LOG_WARNING("Fail to create scan thread for band %s", real_band_suffix[_get_real_band_type(bi)]);
                    tid[bi] = 0;
                }
            } else
#endif
            if (pthread_create(&tid[bi], NULL, _fast_scan_single_channel, (void *)(&band[bi]))) 
            {
                AWN_LOG_WARNING("Fail to create scan thread for band %s", real_band_suffix[_get_real_band_type(bi)]);
                tid[bi] = 0;
            }
        }
    }

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

    usleep(100*1000);
    exit(0);
}

/*!
 *\fn           get_scan_result_qca()
 *\brief        Get scan result
 *\param[in]       band              Wireless band type 2G/5G
 *\param[in]       vap_type          Wireless vap type STA/AP
 *\param[out]   pAwndScanResult   The data struct of scan result 
 *\return       OK/ERROR
 */
int get_scan_result_qca(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast)
{
    u_int8_t *buf = NULL;
    int length = 0;
    char cmdline[CMDLINE_LENGTH] = {0};
    UINT8* cp = NULL;
    int len = 0;
    int idx = 0;
    int ielen = 0;
    INT8 ssid[QCA_MAX_SSID_LENGTH + 1] = {0};
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    struct ieee80211req_scan_result* sr = NULL;
    AWND_AP_ENTRY* pCurApEntry;	
    UINT8* vp = NULL;
    int nss;
    int phyMode;
    int chwidth;	
    int ret = AWND_ERROR;
    AWND_REAL_BAND_TYPE real_band = 0;
    int cur_5g_channel = 0;
    int linkid = MLO_INVALID_LINK_ID;

    real_band = _get_real_band_type(band);
    if (NULL == pAwndScanResult)
    {
        AWN_LOG_ERR("pAwndScanResult is null");     
        ret = AWND_ERROR;
        goto out;
    }

    if (AWND_VAP_AP == vap_type)
        strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));
    else 
        strncpy(ifname, l_awnd_config.staIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) >= 0)
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
    }

    if (AWND_OK != get_phy_qca(band, &nss, &phyMode, &chwidth))
    {
        AWN_LOG_DEBUG("awnd_get_phy fail, quit awnd_get_scan_result"); 	
        ret = AWND_ERROR;
        goto out;
    }
    if (getScanresult_cfg80211_tp(wlanIfAwn->ctx, ifname, &buf, &length, linkid) < 0) {
        AWN_LOG_DEBUG("get_scan_result_qca failed, ifName: %s", ifname);
        ret = AWND_ERROR;
        goto out;
    }

    len = length;
    if (len == 0)
    {
        AWN_LOG_DEBUG("scan result len is zero");
        ret = AWND_OK;
        goto out;
    }
    else if (len < sizeof(struct ieee80211req_scan_result))
    {
        AWN_LOG_DEBUG("scan result len is wrong");
        ret = AWND_ERROR;
        goto out;
    }

    if (!isFast)
    {
        /* save scan result */
        snprintf(cmdline, sizeof(cmdline),"cp -f "TMP_WIFI_SCAN_RESULT_FILE" "WIFI_SCAN_RESULT_FILE" &",
             real_band_suffix[real_band], real_band_suffix[real_band]);
        _wifi_exec_cmd(cmdline);
    }

    if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
    {
        cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
    }

    /* parse scan result to data struct AWND_SCAN_RESULT */
    cp = buf;
    do {
        int ap_nss=nss;
        int ap_phyMode=phyMode;
        int ap_chwidth=chwidth;
        int min_nss,min_phyMode,min_chwidth;

        pCurApEntry = &(pAwndScanResult->tApEntry[idx]);
        sr = (struct ieee80211req_scan_result *) cp;
        vp = (u_int8_t *)(sr+1);        

        _copy_essid(ssid, sizeof(ssid), vp, sr->isr_ssid_len);

        if(sr->isr_len == 0)
        {
            AWN_LOG_ERR("Invalid Scan result Info \n");
            break;
        }      

        memset(pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
        
        memcpy(pCurApEntry->ssid, ssid, strlen(ssid));
        pCurApEntry->ssid[sr->isr_ssid_len] = 0; 
        
        if (sr->isr_bssid != NULL) {
            memcpy(pCurApEntry->bssid, sr->isr_bssid, IEEE80211_ADDR_LEN);
            /*_macaddr_ntop(sr->isr_bssid, pAwndScanResult->tApEntry[idx].bssid);*/
        }
        pCurApEntry->rssi  = sr->isr_rssi;
        pCurApEntry->freq  = sr->isr_freq;
        pCurApEntry->index = idx + 1;
        
        if (band == AWND_BAND_2G)
        {
            if (sr->isr_freq == 2484)
            {
                pCurApEntry->channel = 14;
            }
            else
            {
                pCurApEntry->channel = (sr->isr_freq - 2407) / 5;
            }
        }
        else if (sr->isr_freq > 5950 && sr->isr_freq < 7115)
        {
            //for 6G
            pCurApEntry->channel = (sr->isr_freq - 5950) / 5;
        }
        else 
        {
            /* don't used */
            pCurApEntry->channel = _get_5g_channel(sr->isr_freq);
        }
        if (AWND_BAND_5G == band && pCurApEntry->channel != cur_5g_channel
            && (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
        {
            if (!((l_awnd_config.limit_scan_band1 && pCurApEntry->channel <= 48)
                || (l_awnd_config.limit_scan_band4 && pCurApEntry->channel >= 149)))
            {
                cp += sr->isr_len, len -= sr->isr_len;
                AWN_LOG_DEBUG("AWND_BAND_5G: skip entry when channel(%d) is not in band1 or band4", pCurApEntry->channel);
                continue; 
            }
        }		

        vp = vp + sr->isr_ssid_len;
        ielen = sr->isr_ie_len;
        while (ielen > 0) 
        {
            if (vp[0] == IEEE80211_ELEMID_VENDOR && istpoui(vp))
            {
                memcpy(&(pCurApEntry->netInfo), vp, ((2+vp[1])<sizeof(AWND_NET_INFO))? (2+vp[1]) : sizeof(AWND_NET_INFO));
            }
            if (vp[0] == IEEE80211_ELEMID_VENDOR && isqca_whc_oui(vp, QCA_OUI_WHC_AP_INFO_SUBTYPE))
            {           
                struct ieee80211_ie_whc_apinfo *whcAPInfoIE = (struct ieee80211_ie_whc_apinfo *)vp;        
                pCurApEntry->uplinkRate =LE_READ_2(&whcAPInfoIE->whc_apinfo_uplink_rate);

            }
        
            ielen -= 2+vp[1];
            vp += 2+vp[1];
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
            cp += sr->isr_len, len -= sr->isr_len;
            continue;
        }

		/* get ap nss */
        ap_nss = sr->nss;
        ap_phyMode = sr->phyMode;
        ap_chwidth = sr->chwidth;
        if (4 == ap_chwidth) {
            /* chwidth_80_80 */
            ap_chwidth = wlan_chwidth_160;
        }
        else if (ap_chwidth >= 5) {
            /* chwidth_320 */
            ap_chwidth = wlan_chwidth_320;
        }
        min_nss = nss > ap_nss ? ap_nss : nss;
        min_phyMode = phyMode > ap_phyMode ? ap_phyMode : phyMode;
        min_chwidth = chwidth > ap_chwidth ? ap_chwidth : chwidth;
        /* Transfer from network byte order to host byte order */
        pCurApEntry->netInfo.awnd_lanip = ntohl(pCurApEntry->netInfo.awnd_lanip);
        pCurApEntry->netInfo.server_touch_time = ntohl(pCurApEntry->netInfo.server_touch_time);		
        pCurApEntry->netInfo.awnd_dns = ntohl(pCurApEntry->netInfo.awnd_dns); 
        pCurApEntry->netInfo.uplink_mask = LE_READ_2(&pCurApEntry->netInfo.uplink_mask);
        pCurApEntry->netInfo.uplink_rate = LE_READ_2(&pCurApEntry->netInfo.uplink_rate);		

        /* cp individual's unique params to AP ENTRY, and leave common params in AWND_NET_INFO */
        pCurApEntry->uplinkMask = pCurApEntry->netInfo.uplink_mask;	 
        pCurApEntry->netInfo.uplink_mask = 0;

        if ((!(pCurApEntry->uplinkRate) || (pCurApEntry->uplinkRate = 0xffff) || pCurApEntry->netInfo.awnd_level >= 2) && pCurApEntry->netInfo.uplink_rate)
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
                        pCurApEntry->rssi, min_nss, min_phyMode, min_chwidth);

        AWN_LOG_WARNING("%-6s idx:%d, ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%-4d, channel:%-3d, uplinkMask:%-5u, uplinkrate:%-5u, pathRate:%-5u",
            ifname,idx, pCurApEntry->ssid, pCurApEntry->bssid[0],pCurApEntry->bssid[1],pCurApEntry->bssid[2],
            pCurApEntry->bssid[3],pCurApEntry->bssid[4],pCurApEntry->bssid[5],pCurApEntry->rssi, pCurApEntry->channel, 
            pCurApEntry->uplinkMask, pCurApEntry->uplinkRate,  pCurApEntry->pathRate);

        AWN_LOG_WARNING("awnd_net_type:%-3d,awnd_level:%-2d, awnd_weight:%d, wait:%d, lanip:%x, dns:%x \
            server_detected:%d, server_touch_time:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",            
            pCurApEntry->netInfo.awnd_net_type, pCurApEntry->netInfo.awnd_level,
            pCurApEntry->netInfo.awnd_weight, pCurApEntry->netInfo.wait,
            pCurApEntry->netInfo.awnd_lanip, pCurApEntry->netInfo.awnd_dns,
            pCurApEntry->netInfo.server_detected, pCurApEntry->netInfo.server_touch_time,
            pCurApEntry->netInfo.awnd_mac[0],pCurApEntry->netInfo.awnd_mac[1],
            pCurApEntry->netInfo.awnd_mac[2],pCurApEntry->netInfo.awnd_mac[3],
            pCurApEntry->netInfo.awnd_mac[4],pCurApEntry->netInfo.awnd_mac[5]);

        pAwndScanResult->iApNum++;

        cp += sr->isr_len, len -= sr->isr_len;

        ++idx;
    }while(len >= sizeof(struct ieee80211req_scan_result) && idx < AWND_MAX_GROUP_MEMBER);
    pAwndScanResult->iApNum = idx;
    ret = AWND_OK;

out:
    if(buf)
        free(buf);
    return ret;

}

int set_channel_qca(AWND_BAND_TYPE band, UINT8 channel)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    int linkid = MLO_INVALID_LINK_ID;
    INT8 ifname[QCA_IFNAMSIZ] = {0};

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname)); 

    if(check_if_mld(ifname) < 0)
    {
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s channel %d & ",
                l_awnd_config.apIfnames[band], channel);   
    }
    else
    {
        char athsection[64];
        char vapname[64];
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s link_id %d channel %d & ",
                l_awnd_config.apIfnames[band], linkid, channel);
    }

    return _wifi_exec_cmd(cmdline);

}

int get_sta_iface_in_bridge_qca(AWND_BAND_TYPE band, UINT8* ifname) {
    UINT8 vapname[QCA_IFNAMSIZ] = {0};

    strncpy(vapname, l_awnd_config.staIfnames[band], sizeof(vapname));
#if QCA_USE_WIFI_VLAN_DEV
    snprintf(ifname, IFNAMSIZ, "%s.%s", vapname, QCA_LAN_VLAN_DEV_SUFFIX); 
#else
    snprintf(ifname, IFNAMSIZ, "%s", vapname);
#endif

    return AWND_OK;
}

/*!
 *\fn           disconn_sta_pre_qca()
 *\brief        Prepare for disconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int disconn_sta_pre_qca(AWND_BAND_TYPE band, UINT* pBandMask)
{
    memset(&g_awnd.rootAp[band], 0, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_DISCONNECT;
#ifdef SUPPORT_MESHMODE_2G
    g_awnd.connected_ticks[band] = 0;
#endif
    
    *pBandMask |= (1 << band);
     
    return AWND_OK;
}

int disconn_all_sta_pre_qca(UINT* pBandMask)
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        awnd_disconn_sta_pre(band, pBandMask);
}

/*!
 *\fn           awnd_disconn_sta()
 *\brief        Disconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int disconn_sta_post_qca(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    INT8 ifname[QCA_IFNAMSIZ] = {0};
    int linkid = MLO_INVALID_LINK_ID;

    AWN_LOG_DEBUG("RECORD DISCONN");
   
    /*if (awnd_get_wds_state(band))*/
    {
        snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "QCA_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0 &", 
            l_awnd_config.staIfnames[band]);
        _wifi_exec_cmd(cmdline);
    }

    strncpy(ifname, l_awnd_config.apIfnames[band], sizeof(ifname));

    if(check_if_mld(ifname) < 0)
    {
        char vapname[64];
        get_vapname_by_ifname(ifname, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, ifname);
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s s_scan_flush 0 &", ifname);
    }
    else
    {
        char athsection[64];
        char vapname[64];
        u_int8_t *buf = NULL;
        int length = 0;
        get_athsection_by_mld(ifname, athsection, sizeof(athsection));
        get_vapname_by_ifname(athsection, vapname, sizeof(vapname));
        get_linkid_by_vapname(&linkid, vapname);
        if(band > AWND_BAND_5G)
        {
            if (getScanresult_cfg80211_tp(wlanIfAwn->ctx, ifname, &buf, &length, linkid) < 0) {
                if(buf)
                {
                    free(buf);
                }
                return AWND_OK;
            }
            if (length == 0)
            {
                if(buf)
                {
                    free(buf);
                }
                return AWND_OK;
            }
        }
        snprintf(cmdline, sizeof(cmdline), "cfg80211tool %s link_id %d s_scan_flush 0 &", ifname, linkid);
        if(buf)
        {
            free(buf);
        }
    }
    _wifi_exec_cmd(cmdline);        

    awnd_write_rt_info(band, FALSE, NULL, FALSE);
    g_awnd.wpa_supplicant_disable_mask = g_awnd.wpa_supplicant_disable_mask | (1 << band);
     
    return AWND_OK;
}

/*!
 *\fn           disconn_sta_qca()
 *\brief        Disconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int disconn_sta_qca(AWND_BAND_TYPE band)
{
    UINT bandMask;

    awnd_disconn_sta_pre(band, &bandMask);
     
    return awnd_disconn_sta_post(band);
}

int disconn_all_sta_qca()
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        awnd_disconn_sta(band);

    return AWND_OK;
}

/*!
 *\fn           reconn_sta_pre_qca()
 *\brief        Pepare for reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reconn_sta_pre_qca(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp)
{
#if 0
    g_awnd.staStatus[band].connAttempt = 0;
    g_awnd.staStatus[band].connStatus = AWND_STATUS_CONNECTING;
    memcpy(g_awnd.staStatus[band].mac, bssid, IEEE80211_ADDR_LEN);
    memcpy(&(g_awnd.staStatus[band].netInfo), pNetInfo, sizeof(AWND_NET_INFO));    
#endif    

    memcpy(&g_awnd.rootAp[band], pRootAp, sizeof(AWND_AP_ENTRY));
    g_awnd.connStatus[band] = AWND_STATUS_CONNECTING;

#ifdef SUPPORT_MESHMODE_2G
    if(((g_awnd.meshmode == AWND_MESHMODE_2G_DYNAMIC && g_awnd.meshstate == AWND_MESHSTATE_2G_DISCONNECT) || 
        (g_awnd.meshmode == AWND_MESHMODE_2G_DISCONNECT)) && band == AWND_BAND_2G){
        _wifi_exec_cmd("touch /tmp/awnd_meshmode_2g_disconnect");
    }
    g_awnd.connected_ticks[band] = 0;
#endif
     
    return AWND_OK;
}

/*!
 *\fn           reconn_sta_post_qca()
 *\brief        Reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reconn_sta_post_qca(AWND_BAND_TYPE band, BOOL check_wpa_status)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    awnd_config_set_stacfg_enb(WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? 1 : 0, band);

    snprintf(cmdline, sizeof(cmdline), "ifconfig %s up ", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "QCA_WPA_SUPPLICANT_CTRL_STA_FMT" enable_network 0 &", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);
    g_awnd.wpa_supplicant_disable_mask = g_awnd.wpa_supplicant_disable_mask ^ (1 << band);
	
    return AWND_OK;
}

/*!
 *\fn           reset_sta_connection_qca()
 *\brief        Reconnect STA with rootAp
 *\param[in]       band              Wireless band type 2G/5G
 *\return       OK/ERROR
 */
int reset_sta_connection_qca(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};

    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p "QCA_WPA_SUPPLICANT_CTRL_STA_FMT" disable_network 0; sleep 1;  wpa_cli -p "QCA_WPA_SUPPLICANT_CTRL_STA_FMT" enable_network 0 &", 
            l_awnd_config.staIfnames[band], l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);
    g_awnd.wpa_supplicant_disable_mask = g_awnd.wpa_supplicant_disable_mask ^ (1 << band);
	
    return AWND_OK;
}

/*
    link_state:
    bit0-2 2.4g 5g 5g2
    bit3   plc
    bit4-6 eth0 eth1 eth2
*/
int set_backhaul_sta_dev_qca(UINT32 link_state, unsigned int eth_link_state) 
{
    char dev_list[128];
    char cmd[128];
    FILE *fp;
    int index = 0;
    unsigned int flag = 0;
    int ret = 0;
    int dev_num = 0;
    char plc_backhaul[10];
    char plc_guest[10];
    char plc_backhaul_vid[4];
    char plc_guest_vid[4];
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
                if (awnd_config_check_mod("rtl8367s_gsw"))
                {
                    if (awnd_config_get_plc_backhaul(plc_backhaul_vid))
                    {
                        snprintf(plc_backhaul, sizeof(plc_backhaul), "eth1.%s", plc_backhaul_vid);
                        strlcat(dev_list, plc_backhaul, sizeof(dev_list));
                    }
                    if (awnd_config_get_plc_guest(plc_guest_vid))
                    {
                        strlcat(dev_list, ":", sizeof(dev_list));
                        snprintf(plc_guest, sizeof(plc_guest), "eth1.%s", plc_guest_vid);
                        strlcat(dev_list, plc_guest, sizeof(dev_list));
                        dev_num++;
                    }
                }else{
                    strlcat(dev_list, "eth0-p2", sizeof(dev_list));
                }
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

    return 0;
}

void do_band_restart_qca(UINT8 BandMask)
{
    return;
}

int get_wifi_bw_qca(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw)
{
    return AWND_OK;
}
void set_wifi_bw_qca(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw)
{
    return;
}

int bss_status_check_qca()
{
    return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
int proxy_l2uf_qca(AWND_BAND_TYPE band)
{
    char user_section[IFNAMSIZ] = {0};
    snprintf(user_section, IFNAMSIZ, "ath%d", band);

    proxy_l2uf_single_interface(user_section);
    proxy_l2uf_single_interface(l_awnd_config.apIfnames[band]);

    return 0;
}

int reload_sta_conf_qca(AWND_BAND_TYPE band)
{
    char cmdline[CMDLINE_LENGTH] = {0};
    snprintf(cmdline, sizeof(cmdline), "wpa_cli -p " QCA_WPA_SUPPLICANT_CTRL_STA_FMT "interface_reload &", l_awnd_config.staIfnames[band]);
    _wifi_exec_cmd(cmdline);

    return AWND_OK;
}

int set_wireless_sta_bssid_qca(char *bssid_str, AWND_BAND_TYPE band)
{
    return awnd_config_sta_bssid(bssid_str, l_awnd_config.staIfnames[band]);
}

int wifi_re_roam_qca(void)
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

AWN_PLATFORM_OPS awn_platform_qca = {
    .init_cfg80211 = init_cfg80211_qca,
    .deinit_cfg80211 = deinit_cfg80211_qca,
    .get_default_mesh_channel = get_default_mesh_channel_qca,
    .get_sta_channel = get_sta_channel_qca,
    .get_backhaul_ap_channel = get_backhaul_ap_channel_qca,

    .get_phy = get_phy_qca,
    .get_wds_state = get_wds_state_qca,
    .get_cac_state = get_cac_state_qca,
    .get_rootap_phyRate = get_rootap_phyRate_qca,
    .get_rootap_rssi = get_rootap_rssi_qca,
#ifdef SUPPORT_MESHMODE_2G
    .get_chanim = get_chanim_qca,
    .do_csa = do_csa_qca,
    .disable_sta_vap = disable_sta_vap_qca,
#endif
    .get_rootap_info = get_rootap_info_qca,
    .get_rootap_tpie = get_rootap_tpie_qca,
    .get_tpie = get_tpie_qca,


    .init_tpie = init_tpie_qca,
    .update_wifi_tpie = update_wifi_tpie_qca,

    .flush_scan_table_single_band = flush_scan_table_single_band_qca,
    .flush_scan_table = flush_scan_table_qca,
    .do_scan = do_scan_qca,
    .do_scan_fast = do_scan_fast_qca,
    .get_scan_result = get_scan_result_qca,

    .set_channel = set_channel_qca,
    .get_sta_iface_in_bridge = get_sta_iface_in_bridge_qca,

    .disconn_sta_pre = disconn_sta_pre_qca,
    .disconn_all_sta_pre = disconn_all_sta_pre_qca,
    .disconn_sta_post = disconn_sta_post_qca,
    .disconn_sta = disconn_sta_qca,
    .disconn_all_sta = disconn_all_sta_qca,
    .reconn_sta_pre = reconn_sta_pre_qca,
    .reconn_sta_post = reconn_sta_post_qca,
    .reset_sta_connection = reset_sta_connection_qca,
    .set_backhaul_sta_dev = set_backhaul_sta_dev_qca,
    .do_band_restart = do_band_restart_qca,

    .get_wifi_bw = get_wifi_bw_qca,
    .set_wifi_bw = set_wifi_bw_qca,
    .bss_status_check = bss_status_check_qca,
    .wpa_supplicant_status_check = NULL,
    .get_wifi_zwdfs_support = NULL,

#ifdef CONFIG_AWN_RE_ROAMING
    .proxy_l2uf = proxy_l2uf_qca,
    .reload_sta_conf = reload_sta_conf_qca,
    .set_wireless_sta_bssid = set_wireless_sta_bssid_qca,
    .wifi_re_roam = wifi_re_roam_qca,
#endif /* CONFIG_AWN_RE_ROAMING */
};

AWN_PLATFORM_OPS *awn_platform_ops = &awn_platform_qca;
