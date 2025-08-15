/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file      awn_config.c
 *\brief     
 *
 *\author    Weng Kaiping
 *\version   1.0.0
 *\date      14Apr16
 *
 *\history \arg 1.0.0, 14Apr16, Weng Kaiping, Create the file. 
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
#include <string.h>
#include <ctype.h>

#include "uci.h"

#include "auto_wifi_net.h"
#include "awn_log.h"
#include "md5.h"
#include "awn_wifi_handler_api.h"
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include "ping.h"
#endif

#include "jsonutl.h"

/***************************************************************************/
/*                        DEFINES                                          */
/***************************************************************************/
#define MODULE_NAME  "ledctrl"
#define CONFIG_PATH  "/etc/config"
#define SAVE_PATH    "/var/state"

#define AWND_CONFIG_BUF_LEN 2048

#define UCI_STR_MAX_LEN    128
#define MAROC_MAX_LEN       32
#define STR_2G_DEFUALT "2g"
#define STR_5G_DEFUALT "5g"


#define STR_2G "2g"

#define STR_5G (awnd_dynamic_marocs_value_get("STR_5G"))
#if 0
#define UCI_STR_FMT_STABSS_ENB     "wifi%s_Cfg.settings1.staBssEnabled"
#endif

#define STR_5G2 "5g_2"
#define STR_6G "6g"
#define STR_6G2 "6g_2"
 
static char *wifi_real_radio_suffix[AWND_REAL_BAND_MAX] = {STR_2G, STR_5G_DEFUALT, STR_5G2, STR_6G, STR_6G2};
static char *wifi_defaut_name[AWND_REAL_BAND_MAX] = {"wifi0", "wifi1", "wifi2", "wifi3", "wifi4"};

/* backhual AP VAP ath02/ath12, from /tmp/group-info */
#define UCI_STR_FMT_BACKHUAL_SSID       "wifi.backhaul.ssid"
#define UCI_STR_FMT_BACKHUAL_PWD        "wifi.backhaul.password"
/* config AP VAP ath04/ath14, from /tmp/dft-group-info */
#define UCI_STR_FMT_CONFIG_SSID       "wifi.config.ssid"
#define UCI_STR_FMT_CONFIG_PWD        "wifi.config.password"
/* config AP VAP ath012/ath112, ath08/ath18 or ath06/ath16, from /tmp/preconfig-group-info */
#define UCI_STR_FMT_PRECONFIG_SSID       "wifi.preconfig.ssid"
#define UCI_STR_FMT_PRECONFIG_PWD        "wifi.preconfig.password"

/* STA VAP ath03/ath13, from /tmp/group-info or /tmp/dft-group-info */
#define UCI_STR_FMT_STA_SSID       "wifi.sta.ssid"
#define UCI_STR_FMT_STA_PWD        "wifi.sta.password"

#define UCI_STR_FMT_CONFIG_MESH_ENABLE     "wifi.config.enable"
#define UCI_STR_FMT_PRECONFIG_MESH_ENABLE     "wifi.preconfig.enable"

#define UCI_STR_FMT_RADIO_COUNTRY  "wifi.radio_5g.country"
#define UCI_STR_FMT_NET_MAC        "wifi.radio_2g.bssid"
#define UCI_STR_FMT_STA_ENABLE     "wifi.sta_%s.enable"
#define UCI_STR_FMT_ROOTAP_BSSID   "wifi.sta_%s.bssid"
#define UCI_STR_FMT_RADIO_CHANNEL  "wifi.radio_%s.channel"

#if CONFIG_RE_RESTORE_STA_CONFIG
#define UCI_STR_FMT_STA_CONFIG_ENABLE   "sta_config.sta_%s.enable"
#define UCI_STR_FMT_STA_CONFIG_BSSID    "sta_config.sta_%s.bssid"
#define UCI_STR_FMT_STA_CONFIG_CHANNEL  "sta_config.sta_%s.channel"
#endif

#define UCI_STR_FMT_EXT_STA_ENABLE     "ext_wifi.sta_%s.enable"
#define UCI_STR_FMT_EXT_ROOTAP_BSSID   "ext_wifi.sta_%s.bssid"
#define UCI_STR_FMT_EXT_RADIO_CHANNEL  "ext_wifi.radio_%s.channel"
#define UCI_STR_FMT_EXT_6G2_ENABLE     "ext_wifi.ap.enable_6g2"

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
#define UCI_STR_FMT_RADIO_5G_RCACEN  "wifi.radio_5g.rCACEn"
#endif
#define UCI_STR_FMT_ENABLE_HT160   "wifi.ap.enable_ht160"
#define UCI_STR_FMT_HOST_ENABLE      "wifi.ap.enable"
#define UCI_STR_FMT_HOST_6G_ENABLE   "wifi.ap.enable_6g"
#define UCI_STR_FMT_HOST_5G2_ENABLE  "wifi.ap.enable_5g2"
#define UCI_STR_FMT_GUEST_ENABLE     "wifi.guest.enable"
#define UCI_STR_FMT_GUEST_6G_ENABLE  "wifi.guest.enable_6g"
#define UCI_STR_FMT_GUEST_5G2_ENABLE  "wifi.guest.enable_5g2"
#define UCI_STR_FMT_ENABLE_HT240	"ext_wifi.ap.enable_ht240"
#define UCI_STR_FMT_WIFI_DEV_NAME     "interfaces.radio_%s.name"

#define UCI_STR_FMT_DEVICE_TYPE    "repacd.repacd.DeviceType"
#define UCI_STR_FMT_GW_CONN_MODE   "repacd.repacd.GatewayConnectedMode"
#define UCI_STR_FMT_RE_SUBMODE     "repacd.repacd.AssocDerivedRESubMode"
#define UCI_STR_FMT_PLC_ACTIVE     "repacd.repacd.TrafficPlcActive"
#define UCI_STR_FMT_PLC_SET_ROOT   "repacd.repacd.TrafficPlcRoot"
#define UCI_STR_FMT_ETH_ACTIVE     "repacd.repacd.TrafficEthActive"
#define UCI_STR_FMT_ETH_INTERFACE  "repacd.repacd.TrafficEthInterface"
#define UCI_STR_FMT_ETH_HAS_NEIGH  "repacd.repacd.eth_HasNeigh"
#define UCI_STR_FMT_AWN_WEIGHT     "auto_wifi_net.auto_wifi_net.awn_weight"
#define UCI_STR_FMT_AWN_DYNAMIC_MAROCS     "auto_wifi_net.dynamic_marocs_define.%s"
#define UCI_STR_FMT_PLC_NMK        "plc.config.NetworkPassWd"
#define UCI_BIND_DEVICE_LIST    "bind_device_list"

#define PLC_BACKHAUL_VID  "plc_sync.vlan.backhaul_vlan_id"
#define PLC_GUEST_VID     "plc_sync.vlan.guest_vlan_id"

#define MODULE_NAME_FMT     "wifi%s_Cfg"
#define STA_SECTION_NAME    "settings1"
#define AP_SECTION_NAME     "settings2"

#define WIFI_PARA_NAME_LEN 32
#define WIFI_RUNTIME_FILE_2G  "/tmp/wifi_runtime_info.2g"
#define WIFI_RUNTIME_FILE_5G  "/tmp/wifi_runtime_info.5g"
#define WIFI_RUNTIME_FILE_5G2 "/tmp/wifi_runtime_info.5g2"
#define WIFI_RUNTIME_FILE_6G  "/tmp/wifi_runtime_info.6g"
#define WIFI_RUNTIME_FILE_6G2 "/tmp/wifi_runtime_info.6g2"

#define PLC_RUNTIME_FILE      "/tmp/plc_runtime_info"
#define ETH_RUNTIME_FILE      "/tmp/eth_runtime_info"

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
#define ETH_WLAN_RUNTIME_FILE "/tmp/eth_wlan_runtime_info"
#define ETH_WLAN_ENABLE "eth_wlan_info.only_enable_eth.enable"
#endif

#define WIFI_LOCATION_STATUS_FILE "/tmp/wifi_location_status"

#define GID_FILE        "/tmp/group-info"
#define GID_FILE_DETECT "/tmp/gid"
#define DFT_GID_FILE    "/tmp/dft-group-info"
#define PRECONF_GID_FILE    "/tmp/preconf-group-info"
#define PRECONFIG_GID_FILE    "/tmp/preconfig-group-info"
#define SYNC_BIND_DEV_LIST "/tmp/sync-server/bind_dev_list"

#define SYSMODE_CONFIG_FILE     "sysmode"
#define SECTION_NAME_SYSMODE    "sysmode"
#define SYSMODE_OPTION_MODE     "mode"
#define MODE_VAL_AP             "AP"
#define MODE_VAL_ROUTER         "Router"
#ifdef SUPPORT_MESHMODE_2G
#define MESHMODE_2G             "backhaul_optimization.backhaul_optimization.mode"
#define RECORD_CHANNEL_2G       "record_mode.radio_2g.record_channel"
#define AUTO_BANDWIDTH_2G       "record_mode.radio_2g.auto_bandwidth"
#define HTMODE_2G               "wifi.radio_2g.htmode"
#endif

#if CONFIG_RE_RESTORE_STA_CONFIG
#define CMD_SAVE_CONFIG         "saveconfig"
#endif

static char *real_band_suffix[AWND_REAL_BAND_MAX] = {"2g", "5g", "5g2", "6g", "6g2"};

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/



/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/
static unsigned int link_state = 0;
static unsigned int eth_link_state = 0;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static unsigned int wireless_eth_state = 0;
#endif
UINT8 old_parent_mac[AWND_MAC_LEN] = {0};
#if GET_AP_RSSI
static int rootap_rssi[AWND_BAND_MAX] = {0};
#endif
static char str_5g[MAROC_MAX_LEN] = {0};
static char str_qca_ifindex_5g[MAROC_MAX_LEN] = {0};

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/
extern AWND_GLOBAL g_awnd;
extern UINT8 l_mac_prefer[AWND_MAC_LEN];
extern AWND_CONFIG l_awnd_config;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
extern UINT8 l_mac_ai_roaming_target[AWND_MAC_LEN];
#endif

/***************************************************************************/
/*                        LOCAL FUNCTIONS                                  */
/***************************************************************************/
static inline int _is_vaild_mac(UINT8 *mac)
{
    UINT8 macZero[AWND_MAC_LEN]={0};

    return memcmp(mac, macZero, AWND_MAC_LEN);
}

size_t _strlcpy(char *dst, const char *src, size_t dstsize)
{
    size_t srclen = (size_t)strlen(src);

    if (dstsize > 0) {
        size_t len = (srclen >= dstsize) ? dstsize - 1 : srclen;
        memset(dst, 0, (len + 1));
        memcpy(dst, src, len);
    }

    return srclen;
}

size_t
awnd_strlcat (char *dst, const char *src, size_t dst_sz)
{
    size_t len = strlen(dst);

    if (dst_sz < len) {
    /* the total size of dst is less than the string it contains;
           this could be considered bad input, but we might as well
           handle it */
		return len + strlen(src);
	}

    return len + _strlcpy (dst + len, src, dst_sz - len);
}



void md5_make_digest(unsigned char* digest, unsigned char* input, int len)
{
	MD5_CTX ctx;
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, input, len);
	MD5_Final(digest, &ctx);
}

static void _macaddr_ston(UINT8* mac, char* buf)
{
    UINT  ori_mac[6] = {0};
    int   i = 0;
    
    sscanf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", &ori_mac[0], &ori_mac[1], &ori_mac[2], &ori_mac[3], &ori_mac[4], &ori_mac[5]);
    for (i = 0; i < 6; i++)
    {
        mac[i] = (UINT8)ori_mac[i];
    }
}

void _macaddr_ston_(UINT8* mac, char* buf)
{
    UINT  ori_mac[6] = {0};
    int   i = 0;
    
    sscanf(buf, "%02X-%02X-%02X-%02X-%02X-%02X", &ori_mac[0], &ori_mac[1], &ori_mac[2], &ori_mac[3], &ori_mac[4], &ori_mac[5]);
    for (i = 0; i < 6; i++)
    {
        mac[i] = (UINT8)ori_mac[i];
    }
}

static void _macaddr_format_convert(UINT8* mac, const char* buf)
{
    UINT  ori_mac[6] = {0};
    int   i = 0;
    
    sscanf(buf, "%02X-%02X-%02X-%02X-%02X-%02X", &ori_mac[0], &ori_mac[1], &ori_mac[2], &ori_mac[3], &ori_mac[4], &ori_mac[5]);
    for (i = 0; i < 6; i++)
    {
        mac[i] = (UINT8)ori_mac[i];
    }
}

/**
 * Free the uci context object.
 * @param uciCtx uci context object
 */
static void _uci_context_free(struct uci_context *uciCtx)
{
    if (uciCtx)
    {
        uci_free_context(uciCtx);
    }
}

/**
 * Init the uci context object.
 * @return uci context object
 */
static struct uci_context *_uci_context_init(const char *config_path, const char *save_path)
{
    struct uci_context *uciCtx = NULL;
    uciCtx = uci_alloc_context();
    if (uciCtx)
    {
        uci_set_confdir(uciCtx, config_path);
        uci_set_savedir(uciCtx, save_path);
    }
    return uciCtx;
}

#if CONFIG_RE_RESTORE_STA_CONFIG
/*!
*\fn           _uci_set_cfg_path_value()
*\brief        Set an element's value
*\param[in]    pUciTupleStr: uci tuple string to look up
*\param[in]    pValue:       value to set 
*\return       OK/ERROR
*/
static int _uci_set_cfg_path_value(char * pUciTupleStr, char* pValue)
{
    struct uci_context *uciCtx = NULL;
    struct uci_ptr uciPtr;
    char revertTuple[UCI_STR_MAX_LEN];    
    int ret;

    if (NULL == pUciTupleStr || NULL == pValue)
    {
        AWN_LOG_ERR("pUciTupleStr or pValue is null");         
        goto error;    
    }

    AWN_LOG_DEBUG("pUciTupleStr:%s, pValue:%s", pUciTupleStr, pValue); 
    
    uciCtx = uci_alloc_context();
    if (uciCtx)
    {
        uci_set_confdir(uciCtx, CONFIG_PATH);
    }
    else
    {
        AWN_LOG_ERR("fail to init uci context:%s", pUciTupleStr);         
        goto error;
    }

    /*revert state at first*/
    strncpy(revertTuple, pUciTupleStr, UCI_STR_MAX_LEN);
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, revertTuple, true))
    {
        AWN_LOG_ERR("fail to get ptr %s ", pUciTupleStr); 
        goto error;
    }

    if (UCI_OK != (ret = uci_revert(uciCtx, &uciPtr)))
    {
        AWN_LOG_ERR("fail to revert ptr %s (ret:%d)", pUciTupleStr, ret); 
        goto error;
    }

    /*set and save in CONFIG_PATH */
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, pUciTupleStr, true))
    {
        AWN_LOG_ERR("fail to get ptr again %s ", pUciTupleStr); 
        goto error;
    }
    uciPtr.value = pValue;  

    if (UCI_OK != (ret = uci_set(uciCtx, &uciPtr)))
    {
        AWN_LOG_ERR("fail to set ptr %s (ret:%d)", pUciTupleStr, ret); 
        goto error;
    }

    if (UCI_OK != uci_commit(uciCtx, &uciPtr.p, FALSE))
    {
        AWN_LOG_ERR("fail to commit %s", pUciTupleStr); 
        goto error;
    }

    AWN_LOG_INFO("Success to set %s = %s ", pUciTupleStr, pValue);
    
    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    _uci_context_free(uciCtx);
    return AWND_ERROR;    
}
#endif

/*!
*\fn           _uci_set_value()
*\brief        Set an element's value
*\param[in]    pUciTupleStr: uci tuple string to look up
*\param[in]    pValue:       value to set 
*\return       OK/ERROR
*/
static int _uci_set_value(char * pUciTupleStr, char* pValue)
{
    struct uci_context *uciCtx = NULL;
    struct uci_ptr uciPtr;
    char revertTuple[UCI_STR_MAX_LEN];    
    int ret;

    if (NULL == pUciTupleStr || NULL == pValue)
    {
        AWN_LOG_ERR("pUciTupleStr or pValue is null");         
        goto error;    
    }

    AWN_LOG_DEBUG("pUciTupleStr:%s, pValue:%s", pUciTupleStr, pValue); 
    
    uciCtx = _uci_context_init(CONFIG_PATH, SAVE_PATH);
    if (!uciCtx)
    {
        AWN_LOG_ERR("fail to init uci context:%s", pUciTupleStr);         
        goto error;
    }

    /*revert state at first*/
    strncpy(revertTuple, pUciTupleStr,UCI_STR_MAX_LEN);
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, revertTuple, true))
    {
        AWN_LOG_ERR("fail to get ptr %s ", pUciTupleStr); 
        goto error;
    }

    if (UCI_OK != (ret = uci_revert(uciCtx, &uciPtr)))
    {
        AWN_LOG_ERR("fail to revert ptr %s (ret:%d)", pUciTupleStr, ret); 
        goto error;
    }


    /*set and save in /var/state*/
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, pUciTupleStr, true))
    {
        AWN_LOG_ERR("fail to get ptr again %s ", pUciTupleStr); 
        goto error;
    }   
    
    uciPtr.value = pValue;
    AWN_LOG_DEBUG("uciPtr.uci_type:%d", uciPtr.target);
    AWN_LOG_DEBUG("uciPtr.package:%s",  uciPtr.package);
    AWN_LOG_DEBUG("uciPtr.section:%s",  uciPtr.section);
    AWN_LOG_DEBUG("uciPtr.option:%s",   uciPtr.option);
    AWN_LOG_DEBUG("uciPtr.value:%s",    uciPtr.value);    


    if (UCI_OK != (ret = uci_set(uciCtx, &uciPtr)))
    {
        AWN_LOG_ERR("fail to set ptr %s (ret:%d)", pUciTupleStr, ret); 
        goto error;
    }

    if (UCI_OK != uci_save(uciCtx, uciPtr.p))
    {
        AWN_LOG_ERR("fail to commit %s", pUciTupleStr); 
        goto error;
    }

    AWN_LOG_INFO("Success to set %s = %s ", pUciTupleStr, pValue);
    
    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    _uci_context_free(uciCtx);
    return AWND_ERROR;    
}


/*!
*\fn           _uci_get_value()
*\brief        Get an element's value
*\param[in]    pUciTupleStr: uci tuple string to look up
*\param[out]   pValue:       value of the option 
*\return       OK/ERROR
*/
static int _uci_get_value(char * pUciTupleStr, char* pValue)
{
    struct uci_context *uciCtx = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr uciPtr;

    if (NULL == pUciTupleStr || NULL == pValue)
    {
        AWN_LOG_ERR("pUciTupleStr or pValue is null");         
        goto error;    
    }

    AWN_LOG_DEBUG("pUciTupleStr:%s, pValue:%s", pUciTupleStr, pValue); 
    uciCtx = _uci_context_init(CONFIG_PATH, SAVE_PATH);
    if (!uciCtx)
    {
        AWN_LOG_ERR("fail to init uci context:%s", pUciTupleStr);         
        goto error;
    }

    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, pUciTupleStr, true))
    {
        goto error;
    }

    e = uciPtr.last;
    if (UCI_TYPE_OPTION != e->type)
    {
        goto error;
    }

    if (UCI_TYPE_STRING != uciPtr.o->type)
    {
        goto error;
    }    

    _strlcpy(pValue, uciPtr.o->v.string, UCI_STR_MAX_LEN);
    AWN_LOG_INFO("Success to get  option value %s = %s ", pUciTupleStr,uciPtr.o->v.string);
    
    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    _uci_context_free(uciCtx);
    return AWND_ERROR;    
}

static int _uci_revert_value(char * pUciTupleStr)
{
    struct uci_context *uciCtx = NULL;
    struct uci_ptr uciPtr;
    char revertTuple[UCI_STR_MAX_LEN] = {0};
    int ret;

    if (NULL == pUciTupleStr)
    {
        AWN_LOG_ERR("pUciTupleStr is null");
        goto error;
    }

    AWN_LOG_DEBUG("pUciTupleStr:%s", pUciTupleStr);

    uciCtx = _uci_context_init(CONFIG_PATH, SAVE_PATH);
    if (!uciCtx)
    {
        AWN_LOG_ERR("fail to init uci context:%s", pUciTupleStr);
        goto error;
    }

    /*revert state at first*/
    snprintf(revertTuple, UCI_STR_MAX_LEN, "%s", pUciTupleStr);
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, revertTuple, true))
    {
        AWN_LOG_ERR("fail to get ptr %s ", pUciTupleStr);
        goto error;
    }

    if (UCI_OK != (ret = uci_revert(uciCtx, &uciPtr)))
    {
        AWN_LOG_ERR("fail to revert ptr %s (ret:%d)", pUciTupleStr, ret);
        goto error;
    }

    AWN_LOG_INFO("Success to revert %s", pUciTupleStr);

    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    _uci_context_free(uciCtx);
    return AWND_ERROR;
}

/*!
 *\fn           int _parse_config()
 *\brief        Parse config according to <name, value>
 *\param[in]       name     Key     
 *\param[in]       value    Value
 *\param[out]   data     AWND_CONFIG struct
 *\return       OK/ERROR
 */ 
static int _parse_config(char *name, char *value, void *data)
{
    AWND_CONFIG *cfg = (AWND_CONFIG *)data;
    char delims[] = ",";
    char *subValue = NULL;
    int  subIdx = 0;
	int tmpValue=0;
        
    
    if (NULL == cfg) 
        return AWND_OK;

    if(NULL == name && NULL == value)
    {
        AWN_LOG_ERR("name or value is null");    
        return AWND_ERROR;
    }
    
    if (!strcmp(name, "enable"))
        cfg->enable = strtoul(value, NULL, 10);
    else if	(!strcmp(name, "net_mac"))
        _macaddr_ston(cfg->mac, value);
    else if	(!strcmp(name, "prefer_mac"))
        _macaddr_ston_(l_mac_prefer, value);    
    //else if (!strcmp(name, "ssid"))
    //    strcpy(cfg->ssid, value);
    
    else if (!strcmp(name, "plc_attached"))
        cfg->plc_attached = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "backhaul_option"))
        cfg->backhaul_option = strtoul(value, NULL, 10);
    else if (!strcmp(name, "plc_ifname"))
        strcpy(cfg->plcIfname, value);
    else if (!strcmp(name, "lan_ifname"))
        strcpy(cfg->lanDevName, value); 
    else if (!strcmp(name, "wan_ifname"))
        strcpy(cfg->wanDevName, value);

#if 0
    else if (!strcmp(name, "sta_ifnames"))
    {
        subIdx = 0;
        subValue = strtok(value, ",");
        while(NULL != subValue)
        {
            strcpy(cfg->staIfnames[subIdx], subValue);
            subIdx++;
            subValue = strtok(NULL, ",");
        }
    }
    else if (!strcmp(name, "ap_ifnames"))
    {
        subIdx = 0;
        subValue = strtok(value, ",");
        while(NULL != subValue)
        {
            strcpy(cfg->apIfnames[subIdx], subValue);
            subIdx++;
            subValue = strtok(NULL, ",");
        }
    }
    else if (!strcmp(name, "config_ifnames"))
    {
        subIdx = 0;
        subValue = strtok(value, ",");
        while(NULL != subValue)
        {
            strcpy(cfg->configIfnames[subIdx], subValue);
            subIdx++;
            subValue = strtok(NULL, ",");
        }
    }
#endif

    else if (!strcmp(name, "tm_scan_start"))
        cfg->tm_scan_start       = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_scan_interval"))
        cfg->tm_scan_interval    = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_scan_sched"))
        cfg->tm_scan_sched       = strtoul(value, NULL, 10);	
    else if (!strcmp(name, "tm_status_start"))
        cfg->tm_status_start     = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_status_interval"))
        cfg->tm_status_interval  = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_online_start"))
        cfg->tm_online_start     = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_online_interval"))
        cfg->tm_online_interval  = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_connect_duration"))
        cfg->tm_connect_duration = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_plc_inspect_start"))
        cfg->tm_plc_inspect_start     = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_plc_inspect_interval"))
        cfg->tm_plc_inspect_interval  = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_eth_inspect_start"))
        cfg->tm_eth_inspect_start     = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tm_eth_inspect_interval"))
        cfg->tm_eth_inspect_interval  = strtoul(value, NULL, 10);
    else if (!strcmp(name, "plc_report_interval"))
        cfg->plc_report_interval      = strtoul(value, NULL, 10);
    else if (!strcmp(name, "eth_report_interval"))
        cfg->eth_report_interval      = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "plc_entry_aging_time"))
        cfg->plc_entry_aging_time     = strtoul(value, NULL, 10);
    else if (!strcmp(name, "eth_entry_aging_time"))
        cfg->eth_entry_aging_time     = strtoul(value, NULL, 10); 
    
    else if (!strcmp(name, "scaling_factor"))
        cfg->scaling_factor = strtoul(value, NULL, 10);  
    else if (!strcmp(name, "high_rssi_threshold"))
        cfg->high_rssi_threshold = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "low_rssi_threshold"))
        cfg->low_rssi_threshold = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "best_effort_rssi_threshold"))
        cfg->best_effort_rssi_threshold = strtoul(value, NULL, 10);	
    else if (!strcmp(name, "best_effort_rssi_inc"))
        cfg->best_effort_rssi_inc = strtoul(value, NULL, 10);
    else if (!strcmp(name, "best_effort_uplink_rate"))
        cfg->best_effort_uplink_rate = strtoul(value, NULL, 10);    
    else if (!strcmp(name, "plc_rate_good"))
        cfg->plc_rate_good = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "wifi_lost_rate_to_plc"))
        cfg->wifi_lost_rate_to_plc = strtoul(value, NULL, 10); 
    else if (!strcmp(name, "limit_scan_band1"))
        cfg->limit_scan_band1 = strtoul(value, NULL, 10);
    else if (!strcmp(name, "limit_scan_band4"))
        cfg->limit_scan_band4 = strtoul(value, NULL, 10);
    else if (!strcmp(name, "band_num"))
        cfg->band_num = strtoul(value, NULL, 10);
    else if (!strcmp(name, "sp_5g2"))
        cfg->sp5G2 = strtoul(value, NULL, 10);
    else if (!strcmp(name, "sp_6g"))
        cfg->sp6G = strtoul(value, NULL, 10);
    else if (!strcmp(name, "sp_6g2"))
        cfg->sp6G2 = strtoul(value, NULL, 10);
    else if (!strcmp(name, "tri_band_6g"))
    {
        tmpValue = strtoul(value, NULL, 10);
		if(tmpValue)
		{
			cfg->band_5g2_type = AWND_BAND_MAX;
			cfg->band_6g_type = AWND_BAND_3RD;
			cfg->band_6g2_type = AWND_BAND_MAX;
			cfg->band_3rd_type = AWND_REAL_BAND_6G;
			cfg->band_4th_type = AWND_REAL_BAND_MAX;
			cfg->band_5th_type = AWND_REAL_BAND_MAX;
		}
		else
		{
			cfg->band_5g2_type = AWND_BAND_3RD;
			cfg->band_6g_type = AWND_BAND_MAX;
			cfg->band_6g2_type = AWND_BAND_MAX;
			cfg->band_3rd_type = AWND_REAL_BAND_5G2;
			cfg->band_4th_type = AWND_REAL_BAND_MAX;
			cfg->band_5th_type = AWND_REAL_BAND_MAX;
		}
    }
    else if (!strcmp(name, "four_band_6g2"))
    {
        tmpValue = strtoul(value, NULL, 10);
		if(tmpValue)
		{
			cfg->band_5g2_type = AWND_BAND_MAX;
			cfg->band_6g_type = AWND_BAND_3RD;
			cfg->band_6g2_type = AWND_BAND_4TH;
			cfg->band_3rd_type = AWND_REAL_BAND_6G;
			cfg->band_4th_type = AWND_REAL_BAND_6G2;
			cfg->band_5th_type = AWND_REAL_BAND_MAX;
		}
		else
		{
			cfg->band_5g2_type = AWND_BAND_3RD;
			cfg->band_6g_type = AWND_BAND_4TH;
			cfg->band_6g2_type = AWND_BAND_MAX;
			cfg->band_3rd_type = AWND_REAL_BAND_5G2;
			cfg->band_4th_type = AWND_REAL_BAND_6G;
			cfg->band_5th_type = AWND_REAL_BAND_MAX;
		}
    }
    
    else if (!strcmp(name, "debug_level"))
        cfg->debug_level = strtoul(value, NULL, 10);    
#ifdef SUPPORT_MESHMODE_2G
    else if (!strcmp(name, "meshmode"))
        cfg->onlyForTest = 1;
#endif
    else
    {
        AWN_LOG_ERR("Unknown name: %s", name);  
    }    

    AWN_LOG_INFO("Success to parse config");
    
    return AWND_OK;
}

static const char* _get_sta_radio_suffix(AWND_BAND_TYPE band)
{
    AWND_REAL_BAND_TYPE real_band;
    switch (band)
    {
        case AWND_BAND_2G:
            return "24g";
        case AWND_BAND_5G:
            return "5g1";
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
            AWN_LOG_ERR("Unknown band: %d", band);
            return "";
    };

    switch(real_band) 
    {
        case AWND_REAL_BAND_5G2:
            return "5g2";
        case AWND_REAL_BAND_6G:
            return "6g1";
        case AWND_REAL_BAND_6G2:
            return "6g2";
        default:
            AWN_LOG_ERR("Unknown realband: %d", real_band);
            return "";
    };
}

static char* _get_wifi_radio_suffix(AWND_BAND_TYPE band)
{
	AWND_REAL_BAND_TYPE real_band;
	switch(band)
	{
	case AWND_BAND_2G:
		return STR_2G;
	case AWND_BAND_5G:
		return STR_5G_DEFUALT;
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
		AWN_LOG_ERR("Unknown band: %d", band);  
		return "";
	};

	switch(real_band)
	{
	case AWND_REAL_BAND_5G2:
		return STR_5G2;
	case AWND_REAL_BAND_6G:
		return STR_6G;
	case AWND_REAL_BAND_6G2:
		return STR_6G2;
	default:
		AWN_LOG_ERR("Unknown realband: %d", real_band); 
		return ""; 
	};
}

/*!
*\fn           awnd_default_marocs_value()
*\brief        get the default value of dynamic configuration maroc
*\param[in]    maroc name 
*\param[in]    maroc value point        
*\return       OK
*/
static int awnd_default_marocs_value(char *marocName, char* marocStr)
{
    if (!strcmp(marocName, "STR_5G"))
        strncpy(marocStr, STR_5G_DEFUALT, strlen(STR_5G_DEFUALT));
    else if (!strcmp(marocName, "QCA_IFINDEX_5G"))
        strncpy(marocStr, QCA_IFINDEX_5G_DEFAULT, strlen(QCA_IFINDEX_5G_DEFAULT));
    else        
        AWN_LOG_ERR("Unknown name: %s", marocName);  
    return AWND_OK;
}
/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/
/*!
*\fn           awnd_dynamic_marocs_value_get()
*\brief        get the value of dynamic configuration maroc
*\param[in]    maroc name    
*\return       maraoc value
*/
char* awnd_dynamic_marocs_value_get(char *marocName)
{
    char maroc_uci_str[UCI_STR_MAX_LEN] = {0};
    char maroc_str[MAROC_MAX_LEN] = {0};
    char *pmaroc = NULL;

    memset(maroc_uci_str, 0, sizeof(maroc_uci_str));
    memset(maroc_str, 0, sizeof(maroc_str));
    snprintf(maroc_uci_str, sizeof(maroc_uci_str), UCI_STR_FMT_AWN_DYNAMIC_MAROCS, marocName);

    AWN_LOG_DEBUG("To get maroc %s maroc_uci_str:%s", marocName, maroc_uci_str);
    
    if (!strcmp(marocName, "STR_5G"))
    {
        if (strlen(str_5g) == 0)
        {
            pmaroc = str_5g;
        }
        else
        {
            return str_5g;
        }
    }
    else if (!strcmp(marocName, "QCA_IFINDEX_5G"))
    {
        if (strlen(str_qca_ifindex_5g) == 0)
        {
            pmaroc= str_qca_ifindex_5g;
        }
        else
        {
            return str_qca_ifindex_5g;
        }
    }
    else        
        pmaroc = maroc_str;  
    

    if (AWND_OK != _uci_get_value(maroc_uci_str, pmaroc))
    {
        AWN_LOG_INFO("fail to get maroc  %s  marocName", marocName); 
        memset(maroc_str, 0, sizeof(maroc_str));
        awnd_default_marocs_value(marocName, pmaroc);
    }

    AWN_LOG_INFO("Success to get maroc value:%s", pmaroc);
    
    return pmaroc;    
}

/*!
*\fn           awnd_config_set_stacfg_channel()
*\brief        set channel for rootap
*\param[in]    channel    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
int awnd_config_set_channel(UINT8 channel, AWND_BAND_TYPE band)
{
    char channel_uci_str[UCI_STR_MAX_LEN];
    char channel_str[8];
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_EXT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }

    snprintf(channel_str, sizeof(channel_str), "%d", channel);
    if (AWND_OK != _uci_set_value(channel_uci_str, channel_str))
    {
        AWN_LOG_ERR("fail to set channel uci %s ", channel_str); 
        return AWND_ERROR;
    }

    g_awnd.staConfig[band].channel = channel;

    AWN_LOG_INFO("Success to set channel %s for %s rootap", channel_str, real_band_suffix[real_band]);
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_get_channel()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
UINT8 awnd_config_get_channel(AWND_BAND_TYPE band)
{
    char channel_uci_str[UCI_STR_MAX_LEN];
    char channel_str[8];
    UINT8  channel = 0;
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_EXT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }

    if (AWND_OK != _uci_get_value(channel_uci_str, channel_str))
    {
        AWN_LOG_ERR("fail to get channel %s ", channel_uci_str); 
    }
    else
    {
        channel = strtoul(channel_str, NULL, 10);
        AWN_LOG_INFO("Success to get channel %d", channel);
    }

    return channel;    
}

UINT8 awnd_config_revert_channel(AWND_BAND_TYPE band)
{
    char channel_uci_str[UCI_STR_MAX_LEN];
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_EXT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_RADIO_CHANNEL, _get_wifi_radio_suffix(band));
    }

    if (AWND_OK != _uci_revert_value(channel_uci_str))
    {
        AWN_LOG_ERR("Fail to revert channel.");
        return AWND_ERROR;
    }

    return AWND_OK;
}


/*!
*\fn           awnd_config_set_stacfg_bssid()
*\brief        set bssid for rootap
*\param[in]    bssid    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
int awnd_config_set_stacfg_bssid(char * bssid, AWND_BAND_TYPE band)
{
    char bssid_uci_str[UCI_STR_MAX_LEN];
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(bssid_uci_str, sizeof(bssid_uci_str), UCI_STR_FMT_EXT_ROOTAP_BSSID, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(bssid_uci_str, sizeof(bssid_uci_str), UCI_STR_FMT_ROOTAP_BSSID, _get_wifi_radio_suffix(band));
    }

    if (AWND_OK != _uci_set_value(bssid_uci_str, bssid))
    {
        AWN_LOG_ERR("fail to set bssid uci %s ", bssid); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set bssid %s for %s rootap", bssid, real_band_suffix[real_band]);
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_set_stacfg_enb()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
int awnd_config_set_stacfg_enb(int enb, AWND_BAND_TYPE band)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_EXT_STA_ENABLE, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_ENABLE, _get_wifi_radio_suffix(band));
    }
    
    snprintf(enb_str, sizeof(enb_str), "%d", enb);

    if (AWND_OK != _uci_set_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to set STA %s ", enb_str); 
        return AWND_ERROR;
    }

    g_awnd.staConfig[band].enable = enb;

    AWN_LOG_INFO("Success to set %s STA %s", real_band_suffix[real_band], enb_str);
    
    return AWND_OK;    
}

int awnd_config_set_all_stacfg_enb(int enb)
{
    AWND_BAND_TYPE band;
    int ret = AWND_OK;
    
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (AWND_OK != awnd_config_set_stacfg_enb(enb, band))
            ret = AWND_ERROR;
    }

    return ret;
}

#if CONFIG_RE_RESTORE_STA_CONFIG
/*!
*\fn           awnd_get_sta_config_enb()
*\brief        get value of sta_config.sta_%s.enable
*\param[in]    band     2G/5G/5G2/6G
*\return       enable 0/1
*/
UINT8 awnd_get_sta_config_enb(AWND_BAND_TYPE band)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    UINT8  enable = 0;
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_CONFIG_ENABLE, _get_sta_radio_suffix(real_band));

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get sta enable %s ", enb_uci_str);
    }
    else
    {
        enable = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get sta enable %d", enable);
    }

    return enable;
}

/*!
*\fn           awnd_set_sta_config_enb()
*\brief        set state of sta_config.sta_%s.enable
*\param[in]    enb      state of the station
*\param[in]    band     2G/5G/5G2/6G
*\return       OK/ERROR
*/

int awnd_set_sta_config_enb(int enb, AWND_BAND_TYPE band)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_CONFIG_ENABLE, _get_sta_radio_suffix(real_band));
    snprintf(enb_str, sizeof(enb_str), "%d", enb);

    if (AWND_OK != _uci_set_cfg_path_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to set STA %s ", enb_str);
        return AWND_ERROR;
    }

    //g_awnd.staConfig[band].enable = enb;

    AWN_LOG_INFO("Success to set %s STA %s", _get_sta_radio_suffix(real_band), enb_str);

    return AWND_OK;
}

/*!
*\fn           awnd_get_sta_config_bssid()
*\brief        get value of sta_config.sta_%s.bssid
*\param[in]    band     2G/5G/5G2/6G
*\return       bssid
*/
UINT8 awnd_get_sta_config_bssid(AWND_BAND_TYPE band, char *bssid_str)
{
    char bssid_uci_str[UCI_STR_MAX_LEN] = {0};
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(bssid_uci_str, sizeof(bssid_uci_str), UCI_STR_FMT_STA_CONFIG_BSSID, _get_sta_radio_suffix(real_band));

    if (AWND_OK != _uci_get_value(bssid_uci_str, bssid_str))
    {
        return AWND_ERROR;
    }

    AWN_LOG_INFO("-------Success to get sta bssid_str %s", bssid_str);
    return AWND_OK;
}

/*!
*\fn           awnd_set_sta_config_bssid()
*\brief        set state of sta_config.sta_%s.enable
*\param[in]    enb      state of the station
*\param[in]    band     2G/5G/5G2/6G
*\return       OK/ERROR
*/

int awnd_set_sta_config_bssid(AWND_BAND_TYPE band, char * bssid)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_CONFIG_BSSID, _get_sta_radio_suffix(real_band));

    if (AWND_OK != _uci_set_cfg_path_value(enb_uci_str, bssid))
    {
        AWN_LOG_ERR("fail to set STA %s ", bssid);
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s STA %s", _get_sta_radio_suffix(real_band), bssid);

    return AWND_OK;
}

/*!
*\fn           awnd_get_sta_config_channel()
*\brief        get value of sta_config.sta_%s.channel
*\param[in]    band     2G/5G/5G2/6G
*\return       bssid
*/
UINT8 awnd_get_sta_config_channel(AWND_BAND_TYPE band)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    UINT8  channel = 0;
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_CONFIG_CHANNEL, _get_sta_radio_suffix(real_band));

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get sta config channel %s ", enb_uci_str);
    }
    else
    {
        channel = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get sta config channel %d", channel);
    }

    return channel;
}

/*!
*\fn           awnd_set_sta_config_channel()
*\brief        set state of sta_config.sta_%s.channel
*\param[in]    enb      state of the station
*\param[in]    band     2G/5G/5G2/6G
*\return       OK/ERROR
*/

int awnd_set_sta_config_channel(AWND_BAND_TYPE band, UINT8 channel)
{
    char channel_uci_str[UCI_STR_MAX_LEN];
    char channel_str[8];
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
    if (AWND_BAND_5G2 == band) {
        real_band = AWND_BAND_6G;
    }
#endif /* CONFIG_WIFI_6G_SUPPORT && CONFIG_TRI_BACKHAUL_SUPPORT */

    snprintf(channel_uci_str, sizeof(channel_uci_str), UCI_STR_FMT_STA_CONFIG_CHANNEL, _get_sta_radio_suffix(real_band));
    snprintf(channel_str, sizeof(channel_str), "%d", channel);

    if (AWND_OK != _uci_set_cfg_path_value(channel_uci_str, channel_str))
    {
        AWN_LOG_ERR("fail to set STA %s ", channel_str);
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s : %s", _get_sta_radio_suffix(real_band), channel_str);

    return AWND_OK;
}

int awnd_config_set_sta_config(BOOL need_save_config)
{
    AWND_BAND_TYPE band;
    char bssid[AWND_MAX_SSID_LEN];
    char old_bssid[AWND_MAX_SSID_LEN];
    BOOL bssid_changed = false;
    UINT8 old_channel = 0;
    UINT8 old_enb = 0;

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        memset(bssid, 0, AWND_MAX_SSID_LEN);
        _macaddr_ntop(g_awnd.staConfig[band].bssid, bssid);

        memset(old_bssid, 0, AWND_MAX_SSID_LEN);
        if (AWND_OK == awnd_get_sta_config_bssid(band, old_bssid))
        {
            if (0 != strncmp(bssid, old_bssid, AWND_MAX_SSID_LEN)) {
                awnd_set_sta_config_bssid(band, bssid);
                bssid_changed = 1; /* Rootap has changed! Save config into sta_config */
            }
        }
        else
        {
            awnd_set_sta_config_bssid(band, bssid);
        }

        old_channel = awnd_get_sta_config_channel(band);
        if (g_awnd.staConfig[band].channel != old_channel) {
            awnd_set_sta_config_channel(band, g_awnd.staConfig[band].channel);
        }

        old_enb = awnd_get_sta_config_enb(band);
        if (g_awnd.staConfig[band].enable != old_enb) {
            awnd_set_sta_config_enb(g_awnd.staConfig[band].enable, band);
        }
    }

    if (need_save_config && bssid_changed)
    {
        AWN_LOG_ERR("to save sta_config ");
        system(CMD_SAVE_CONFIG);
        return AWND_OK;
    }
    return AWND_ERROR;
}

int awnd_config_restore_sta_config()
{
    AWND_BAND_TYPE band;
    char bssid[AWND_MAC_LEN] = {0};
    char bssid_str[AWND_MAX_SSID_LEN] = {0};
    int vaild_bssid = 0;
    UINT8 old_channel = 0;
    UINT8 old_enb = 0;
    int ret = AWND_ERROR;

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        vaild_bssid = 0;
        if (AWND_OK == awnd_get_sta_config_bssid(band, bssid_str))
        {
            _macaddr_ston(bssid, bssid_str);
            if ( _is_vaild_mac(bssid)) {
                vaild_bssid = 1;
            }
        }

        old_enb = awnd_get_sta_config_enb(band);
        if (1 == old_enb && vaild_bssid) {
            g_awnd.staConfig[band].enable = 1;
            memcpy(g_awnd.staConfig[band].bssid, bssid, AWND_MAC_LEN);
            memcpy(g_awnd.rootAp[band].lan_mac, bssid, AWND_MAC_LEN);
            
            old_channel = awnd_get_sta_config_channel(band);
            if (old_channel) {
                g_awnd.staConfig[band].channel = old_channel;
            }

            g_awnd.connStatus[band] = AWND_STATUS_CONNECTING;
            ret = AWND_OK;
        }
    }
    return ret;
}
#endif

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
int awnd_config_set_radio_5g_rcac_enb(int enb)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    
    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_RADIO_5G_RCACEN);    
    snprintf(enb_str, sizeof(enb_str), "%d", enb);

    if (AWND_OK != _uci_set_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to set radio_5g rCACEn %s ", enb_str); 
        return AWND_ERROR;
    }

    AWN_LOG_NOTICE("Success to set radio_5g rCACEn %s", enb_str);
    
    return AWND_OK;    
}
#endif

/*!
*\fn           awnd_config_get_stacfg_enb()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
int awnd_config_get_stacfg_enb(AWND_BAND_TYPE band)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    UINT8  enable = 0;
    AWND_REAL_BAND_TYPE real_band = 0;

    real_band = _get_real_band_type(band);
    if (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band) {
        snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_EXT_STA_ENABLE, _get_wifi_radio_suffix(band));
    }
    else {
        snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_STA_ENABLE, _get_wifi_radio_suffix(band));
    }

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get sta enable %s ", enb_uci_str); 
    }
    else
    {
        enable = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get sta enable %d", enable);
    }

    return enable;    
}

int awnd_config_get_stacfg_type(AWND_BAND_TYPE band, char *type)
{
    char tuple[UCI_STR_MAX_LEN] = {};

    snprintf(tuple, sizeof(tuple), "wifi.sta_%s.type", real_band_suffix[band]);

    if (AWND_OK != _uci_get_value(tuple, type)) {
        return AWND_ERROR;
    }

    return AWND_OK;
}

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
int awnd_config_get_radio_5g_rcac_enb()
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];
    UINT8  enable = 1;

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_RADIO_5G_RCACEN);

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get radio 5g rCACEn %s ", enb_uci_str); 
    }
    else
    {
        enable = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get radio 5g rCACEn %d", enable);
    }

    return enable;    
}
#endif

/*!
*\fn           awnd_config_set_cfg_mesh_enb()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\return       OK/ERROR
*/
int awnd_config_set_cfg_mesh_enb(int enb)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_CONFIG_MESH_ENABLE);

    snprintf(enb_str, sizeof(enb_str), "%d", enb);

    if (AWND_OK != _uci_set_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to set STA %s ", enb_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s : %s", enb_uci_str, enb_str);
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_set_precfg_mesh_enb()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\return       OK/ERROR
*/
int awnd_config_set_precfg_mesh_enb(int enb)
{
    char enb_uci_str[UCI_STR_MAX_LEN];
    char enb_str[8];

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_PRECONFIG_MESH_ENABLE);

    snprintf(enb_str, sizeof(enb_str), "%d", enb);

    if (AWND_OK != _uci_set_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to set STA %s ", enb_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s : %s", enb_uci_str, enb_str);
    
    return AWND_OK;    
}


/*!
*\fn           awnd_config_get_cfg_mesh_enb()
*\brief        get config mesh enable 
*\return       enable 0/1    
*/
UINT8 awnd_config_get_cfg_mesh_enb()
{
    char   enb_uci_str[UCI_STR_MAX_LEN];
    char   enb_str[8];
    UINT8  enable = 0;

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_CONFIG_MESH_ENABLE);

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get config mesh enable %s ", enb_uci_str); 
    }
    else
    {
        enable = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get config mesh enable %d", enable);
    }
    
    return enable;
}

#ifdef SUPPORT_MESHMODE_2G
/*!
*\fn           awnd_config_get_meshmode_2g()
*\brief        get config meshmode_2g
*\return       mode  0:keep disconnect 1: keep connect 2:dynamic   
*/
int awnd_config_get_meshmode_2g()
{
    char   mode_uci_str[UCI_STR_MAX_LEN];
    char   mode_str[30] = {0};
    int    mode = 1;

    snprintf(mode_uci_str, sizeof(mode_uci_str), "%s", MESHMODE_2G);

    if (AWND_OK != _uci_get_value(mode_uci_str, mode_str))
    {
        AWN_LOG_ERR("fail to get meshmode_2g %s ", mode_uci_str); 
    }
    else
    {
        AWN_LOG_INFO("Success to get meshmode_2g %s", mode_str);
        if (!strncmp(mode_str,"wireless_link_down",sizeof("wireless_link_down")))
        {
            mode = AWND_MESHMODE_2G_DISCONNECT;
        }
        else if (!strncmp(mode_str,"wireless_link_up",sizeof("wireless_link_up")))
        {
            mode = AWND_MESHMODE_2G_CONNECT;
        }
        else if (!strncmp(mode_str,"auto",sizeof("auto")))
        {
            mode = AWND_MESHMODE_2G_DYNAMIC;
        }
    }

    AWN_LOG_NOTICE("lxdebug uci get meshmode=%d\n",mode);
    
    return mode;
}

int awnd_config_sta_vap_disable(int disable, AWND_BAND_TYPE band)
{
    char disable_uci_str[UCI_STR_MAX_LEN];
    char disable_str[8];

    snprintf(disable_uci_str, sizeof(disable_uci_str), "wireless.%s.disabled", l_awnd_config.staIfnames[band]);
    snprintf(disable_str, sizeof(disable_str), "%d", disable);

    if (AWND_OK != _uci_set_value(disable_uci_str, disable_str))
    {
        AWN_LOG_ERR("fail to set STA disable %s ", disable_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s STA disable %s", l_awnd_config.staIfnames[band], disable_str);
    return  AWND_OK;
}

/*!
*\fn           _uci_get_record_mode_value()
*\brief        Get an element's value
*\param[in]    pUciTupleStr: uci tuple string to look up
*\param[out]   pValue:       value of the option 
*\return       OK/ERROR
*/
static int _uci_get_record_mode_value(char * pUciTupleStr, char* pValue)
{
    struct uci_context *uciCtx = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr uciPtr;

    if (NULL == pUciTupleStr || NULL == pValue)
    {
        AWN_LOG_NOTICE("pUciTupleStr or pValue is null");         
        goto error;    
    }

    AWN_LOG_NOTICE("pUciTupleStr:%s, pValue:%s", pUciTupleStr, pValue); 
    uciCtx = _uci_context_init(CONFIG_PATH, SAVE_PATH);
    if (!uciCtx)
    {
        AWN_LOG_NOTICE("fail to init uci context:%s", pUciTupleStr);         
        goto error;
    }

    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, pUciTupleStr, true))
    {
        AWN_LOG_NOTICE("fail to get ptr %s ", pUciTupleStr); 
        goto error;
    }

    e = uciPtr.last;
    if (UCI_TYPE_OPTION != e->type)
    {
        AWN_LOG_NOTICE("element type is not option:%d", e->type); 
        goto error;
    }

    if (UCI_TYPE_STRING != uciPtr.o->type)
    {
        AWN_LOG_NOTICE("option type is not string:%d", uciPtr.o->type); 
        goto error;
    }    

    _strlcpy(pValue, uciPtr.o->v.string, UCI_STR_MAX_LEN);
    AWN_LOG_NOTICE("Success to get  option value %s = %s ", pUciTupleStr,uciPtr.o->v.string);
    
    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    _uci_context_free(uciCtx);
    return AWND_ERROR;    
}

/*!
*\fn           awnd_config_get_record_channel_2g()
*\brief        get config record_channel_2g
*\return       channel
*/
int awnd_config_get_record_channel_2g()
{
    char channel_uci_str[UCI_STR_MAX_LEN];
    char channel_str[8];
    UINT8  channel = 0;

    snprintf(channel_uci_str, sizeof(channel_uci_str), "%s", RECORD_CHANNEL_2G);

    if (AWND_OK != _uci_get_record_mode_value(channel_uci_str, channel_str))
    {
        AWN_LOG_NOTICE("fail to get record_channel_2g %s ", channel_uci_str); 
    }
    else
    {
        channel = strtoul(channel_str, NULL, 10);
        AWN_LOG_INFO("Success to get channel %d", channel);
    }

    AWN_LOG_NOTICE("lxdebug uci get record_channel_2g=%d\n",channel);
    
    return channel;
}

/*!
*\fn           awnd_config_get_bandwidth_2g()
*\brief        get config bandwidth_2g
*\return       bandwidth_2g  0:ht20 1:ht40 2:auto
*/
int awnd_config_get_bandwidth_2g()
{
    char auto_bandwidth_uci_str[UCI_STR_MAX_LEN];
    char htmode_uci_str[UCI_STR_MAX_LEN];
    char auto_bandwidth_str[8];
    char htmode_str[8];
    UINT8  auto_bandwidth = 1;
    int bandwidth_2g = 2;

    snprintf(auto_bandwidth_uci_str, sizeof(auto_bandwidth_uci_str), "%s", AUTO_BANDWIDTH_2G);
    snprintf(htmode_uci_str, sizeof(htmode_uci_str), "%s", HTMODE_2G);

    if (AWND_OK != _uci_get_record_mode_value(auto_bandwidth_uci_str, auto_bandwidth_str))
    {
        AWN_LOG_NOTICE("fail to get auto_bandwidth %s ", auto_bandwidth_uci_str); 
    }
    else
    {
        auto_bandwidth = strtoul(auto_bandwidth_str, NULL, 10);
        AWN_LOG_INFO("Success to get auto_bandwidth %d", auto_bandwidth);
    }

    if (auto_bandwidth != 1)
    {
        if (AWND_OK != _uci_get_record_mode_value(htmode_uci_str, htmode_str))
        {
            AWN_LOG_NOTICE("fail to get htmode %s ", htmode_uci_str); 
        }
        else
        {
            AWN_LOG_INFO("Success to get htmode %s", htmode_str);
            if (!strncmp(htmode_str,"HT40",sizeof("HT40")))
            {
                bandwidth_2g = 1;
            }
            else if (!strncmp(htmode_str,"HT20",sizeof("HT20")))
            {
                bandwidth_2g = 0;
            }
        }
    }

    AWN_LOG_NOTICE("lxdebug uci get bandwidth_2g=%d\n",bandwidth_2g);
    
    return bandwidth_2g;
}

int awnd_file_exist(char *file)
{
    if (0 == access(file, 0)) {
        return AWND_OK;
    }

    return AWND_ERROR;
}
#endif

/*!
*\fn           awnd_config_get_precfg_mesh_enb()
*\brief        get config mesh enable 
*\return       enable 0/1    
*/
UINT8 awnd_config_get_precfg_mesh_enb()
{
    char   enb_uci_str[UCI_STR_MAX_LEN];
    char   enb_str[8];
    UINT8  enable = 0;

    snprintf(enb_uci_str, sizeof(enb_uci_str), UCI_STR_FMT_PRECONFIG_MESH_ENABLE);

    if (AWND_OK != _uci_get_value(enb_uci_str, enb_str))
    {
        AWN_LOG_ERR("fail to get preconfig mesh enable %s ", enb_uci_str); 
    }
    else
    {
        enable = strtoul(enb_str, NULL, 10);
        AWN_LOG_INFO("Success to get preconfig mesh enable %d", enable);
    }
    
    return enable;
}

int awnd_config_set_eth_active(int active)
{
    char active_uci_str[UCI_STR_MAX_LEN];
    char active_str[8];

    snprintf(active_str,     sizeof(active_str), "%d", active);
    snprintf(active_uci_str, sizeof(active_uci_str),    "%s", UCI_STR_FMT_ETH_ACTIVE);    

    if (AWND_OK != _uci_set_value(active_uci_str, active_str))
    {
        AWN_LOG_ERR("fail to set %s=%s ", active_uci_str, active_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s=%s", active_uci_str, active_str); 
    
    return AWND_OK;    
}

int awnd_config_set_eth_interface(const char* ifname)
{
    char if_uci_str[UCI_STR_MAX_LEN];
    char if_str[8];

    snprintf(if_str,     sizeof(if_str), "%s", ifname);
    snprintf(if_uci_str, sizeof(if_uci_str),    "%s", UCI_STR_FMT_ETH_INTERFACE);    

    if (AWND_OK != _uci_set_value(if_uci_str, if_str))
    {
        AWN_LOG_ERR("fail to set %s=%s ", if_uci_str, if_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s=%s", if_uci_str, if_str); 
    
    return AWND_OK;    
}

//int awnd_config_set_eth_neigh_interface(AWND_ETH_PORT_NUM port, UINT8 value)
int awnd_config_set_eth_neigh_interface(int value)
{
	char enb_uci_str[UCI_STR_MAX_LEN] = {0};
	char enb_str[8] = {0};
	snprintf(enb_uci_str, sizeof(enb_uci_str), "%s", UCI_STR_FMT_ETH_HAS_NEIGH);

	snprintf(enb_str, sizeof(enb_str), "%d", value);

	if (AWND_OK != _uci_set_value(enb_uci_str, enb_str))
	{
		AWN_LOG_ERR("fail to set STA %s = %s ", enb_uci_str, enb_str); 
		return AWND_ERROR;
	}

	AWN_LOG_INFO("Success to set %s STA %s", enb_uci_str, enb_str);

	return AWND_OK;
}

/*!
*\fn           awnd_config_set_stacfg_enb()
*\brief        set state of station 
*\param[in]    enb      state of the station    
*\param[in]    band     2G/5G
*\return       OK/ERROR
*/
int awnd_config_set_plc_active(int active)
{
    char active_uci_str[UCI_STR_MAX_LEN];
    char active_str[8];

    snprintf(active_str,     sizeof(active_str), "%d", active);
    snprintf(active_uci_str, sizeof(active_uci_str),    "%s", UCI_STR_FMT_PLC_ACTIVE);    

    if (AWND_OK != _uci_set_value(active_uci_str, active_str))
    {
        AWN_LOG_ERR("fail to set %s=%s ", active_uci_str, active_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s=%s", active_uci_str, active_str); 
    
    return AWND_OK;    
}

int awnd_config_set_plc_as_root(UINT8 isRoot)
{
    char active_uci_str[UCI_STR_MAX_LEN];
    char active_str[8];

    snprintf(active_str,     sizeof(active_str), "%d", isRoot);
    snprintf(active_uci_str, sizeof(active_uci_str),    "%s", UCI_STR_FMT_PLC_SET_ROOT);    

    if (AWND_OK != _uci_set_value(active_uci_str, active_str))
    {
        AWN_LOG_ERR("fail to set %s=%s ", active_uci_str, active_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s=%s", active_uci_str, active_str); 
    
    return AWND_OK;    
}

int awnd_config_set_re_submode(AWND_SUBMODE submode)
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    char mode_str[8];

    snprintf(mode_uci_str,    sizeof(mode_uci_str),    "%s", UCI_STR_FMT_RE_SUBMODE);
	
    if (AWND_SUBMODE_STAR == submode)
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "star");
    }
    else
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "daisy"); 
    }

    if (AWND_OK != _uci_set_value(mode_uci_str, mode_str))
    {
        AWN_LOG_ERR("fail to set re submode uci %s ", mode_str); 
        return AWND_ERROR;
    }
	

    AWN_LOG_INFO("Success to set re submode %s", mode_str);
    
    return AWND_OK; 
}

int awnd_config_set_re_gwmode(int gw_mode)
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    char mode_str[8];

    snprintf(mode_uci_str,    sizeof(mode_uci_str),    "%s", UCI_STR_FMT_GW_CONN_MODE);
	
    if (gw_mode)
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "AP");
    }
    else
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "RE"); 
    }

    if (AWND_OK != _uci_set_value(mode_uci_str, mode_str))
    {
        AWN_LOG_ERR("fail to set re submode uci %s ", mode_str); 
        return AWND_ERROR;
    }
	

    AWN_LOG_INFO("Success to set re submode %s", mode_str);
    
    return AWND_OK; 
}

/*!
*\fn           awnd_config_set_mode()
*\brief        set work mode 
*\param[in]    mode     0:repeater;1:ap    
*\return       OK/ERROR
*/
int awnd_config_set_mode(int mode, int gw_mode)
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    char gw_mode_uci_str[UCI_STR_MAX_LEN];
    char mode_str[8];
    char gw_mode_str[8];
    AWND_BAND_TYPE band;

    snprintf(mode_uci_str,    sizeof(mode_uci_str),    "%s", UCI_STR_FMT_DEVICE_TYPE);
    snprintf(gw_mode_uci_str, sizeof(gw_mode_uci_str), "%s", UCI_STR_FMT_GW_CONN_MODE);
	
    if (WIFI_AP == mode)
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "AP");
       snprintf(gw_mode_str, sizeof(mode_str), "%s", "CAP");
       for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
       {
           awnd_config_revert_channel(band);
       }
    }
    else
    {
       snprintf(mode_str,    sizeof(mode_str), "%s", "RE");
       if (gw_mode)
           snprintf(gw_mode_str, sizeof(mode_str), "%s", "AP");
       else
           snprintf(gw_mode_str, sizeof(mode_str), "%s", "RE");        
    }

    if (AWND_OK != _uci_set_value(mode_uci_str, mode_str))
    {
        AWN_LOG_ERR("fail to set device type uci %s ", mode_str); 
        return AWND_ERROR;
    }
    if (AWND_OK != _uci_set_value(gw_mode_uci_str, gw_mode_str))
    {
        AWN_LOG_ERR("fail to set GatewayConnectedMode uci %s ",gw_mode_str); 
        return AWND_ERROR;
    }	

    AWN_LOG_INFO("Success to set work mode %s", mode_str);
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_get_mode()
*\brief        get work mode 
*\return       mode     0:repeater;1:ap    
*/
int awnd_config_get_mode()
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    char mode_str[8];
    int  mode = -1;

    snprintf(mode_uci_str, sizeof(mode_uci_str), "%s", UCI_STR_FMT_DEVICE_TYPE);

    if (AWND_OK != _uci_get_value(mode_uci_str, mode_str))
    {
        AWN_LOG_ERR("fail to get mode %s ", mode_uci_str); 
    }
    else
    {
        mode = strcmp(mode_str, "AP") ? WIFI_REPEATER : WIFI_AP;   
        AWN_LOG_INFO("Success to get work mode %s", mode_str);
    }
    
    return mode;    
}

int awnd_config_set_plc_nmk(char* nmk)
{
    char nmk_uci_str[UCI_STR_MAX_LEN];

    snprintf(nmk_uci_str, sizeof(nmk_uci_str), "%s", UCI_STR_FMT_PLC_NMK);

    if (AWND_OK != _uci_set_value(nmk_uci_str, nmk))
    {
        AWN_LOG_ERR("fail to set ssid uci %s ", UCI_STR_FMT_PLC_NMK); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s = %s", UCI_STR_FMT_PLC_NMK, nmk);
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_get_ssid()
*\brief        get ssid 
*\return       char* ssid       
*/
int awnd_config_get_ssid(AWND_WIFI_IFACE_TYPE ifaceType, char *ssid_str)
{
    char ssid_uci_str[UCI_STR_MAX_LEN];
	
    if (!ssid_str)
        return AWND_ERROR;

    switch (ifaceType)
    {    
        case WIFI_IFACE_BACKHUAL:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_BACKHUAL_SSID);
            break;
        case WIFI_IFACE_CONFIG:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_CONFIG_SSID);
            break;
        case WIFI_IFACE_STA:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_STA_SSID);
            break; 
        case WIFI_IFACE_PRECONFIG:    
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_PRECONFIG_SSID);   
            break;                   
        default:
            AWN_LOG_CRIT("invaild iface type:%d", ifaceType);                 
            return AWND_ERROR;                    
    }	

    if (AWND_OK != _uci_get_value(ssid_uci_str, ssid_str))
    {
        AWN_LOG_ERR("fail to get ssid %s ", ssid_uci_str); 
        return AWND_ERROR;  		
    }
    
    return AWND_OK;
}

/*!
*\fn           awnd_config_set_ssid()
*\brief        set backhaul ssid
*\param[in]    ssid    
*\return       OK/ERROR
*/
int awnd_config_set_ssid(char* ssid, AWND_WIFI_IFACE_TYPE ifaceType)
{
    char ssid_uci_str[UCI_STR_MAX_LEN];

    switch (ifaceType)
    {    
        case WIFI_IFACE_BACKHUAL:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_BACKHUAL_SSID);
            break;
        case WIFI_IFACE_CONFIG:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_CONFIG_SSID);
            break;
        case WIFI_IFACE_PRECONFIG:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_PRECONFIG_SSID);
            break;
        case WIFI_IFACE_STA:
            snprintf(ssid_uci_str, sizeof(ssid_uci_str), "%s", UCI_STR_FMT_STA_SSID);
            break;
        default:
            AWN_LOG_CRIT("invaild iface type:%d", ifaceType);                 
            return AWND_ERROR;
    }

    if (AWND_OK != _uci_set_value(ssid_uci_str, ssid))
    {
        AWN_LOG_INFO("fail to set ssid uci %s ", ssid_uci_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s = %s", ssid_uci_str, ssid);
    
    return AWND_OK;
}

/*!
*\fn           awnd_config_get_pwd()
*\brief        get pwd 
*\return       char* pwd       
*/
int awnd_config_get_pwd(AWND_WIFI_IFACE_TYPE ifaceType, char *pwd_str)
{
    char pwd_uci_str[UCI_STR_MAX_LEN];

    if (!pwd_str)
        return AWND_ERROR;

    switch (ifaceType)
    {    
        case WIFI_IFACE_BACKHUAL:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_BACKHUAL_PWD);
            break;
        case WIFI_IFACE_CONFIG:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_CONFIG_PWD);
            break;
        case WIFI_IFACE_STA:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_STA_PWD);
            break;
        case WIFI_IFACE_PRECONFIG:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_PRECONFIG_PWD);
            break;
        default:
            AWN_LOG_CRIT("invaild iface type:%d", ifaceType);                 
            return AWND_ERROR;
    }

    if (AWND_OK != _uci_get_value(pwd_uci_str, pwd_str))
    {
        AWN_LOG_ERR("fail to get pwd %s ", pwd_uci_str); 
        return AWND_ERROR;
    }
    
    return AWND_OK;    
}

/*!
*\fn           awnd_config_set_pwd()
*\brief        set backhaul password
*\param[in]    pwd    
*\return       OK/ERROR
*/
int awnd_config_set_pwd(char* pwd, AWND_WIFI_IFACE_TYPE ifaceType)
{
    char pwd_uci_str[UCI_STR_MAX_LEN];

    switch (ifaceType)
    {    
        case WIFI_IFACE_BACKHUAL:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_BACKHUAL_PWD);
            break;
        case WIFI_IFACE_CONFIG:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_CONFIG_PWD);
            break;
        case WIFI_IFACE_PRECONFIG:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_PRECONFIG_PWD);
            break;
        case WIFI_IFACE_STA:
            snprintf(pwd_uci_str, sizeof(pwd_uci_str), "%s", UCI_STR_FMT_STA_PWD);
            break;                        
        default:
            AWN_LOG_CRIT("invaild iface type:%d", ifaceType);                 
            return AWND_ERROR;
    }

    if (AWND_OK != _uci_set_value(pwd_uci_str, pwd))
    {
        AWN_LOG_ERR("fail to set  uci %s ", pwd_uci_str); 
        return AWND_ERROR;
    }

    AWN_LOG_INFO("Success to set %s = %s", pwd_uci_str, pwd);
    
    return AWND_OK;    
}

_check_wifi_ssid_pwd_preconfig()
{
    awnd_config_set_ssid("preconfig", WIFI_IFACE_PRECONFIG);
    awnd_config_set_pwd("preconfig", WIFI_IFACE_PRECONFIG);
}
_check_wifi_ssid_pwd_preconfig_sta()
{
    awnd_config_set_ssid("preconfig", WIFI_IFACE_STA);
    awnd_config_set_pwd("preconfig", WIFI_IFACE_STA);
}

static void _check_wifi_ssid_pwd(GROUP_INFO *pGroupInfo, AWND_WIFI_IFACE_TYPE ifaceType)
{
    char ssid_str[AWND_MAX_SSID_LEN];
    char pwd_str[AWND_MAX_PWD_LEN];

    if (_is_null_group_info(pGroupInfo))
        return;

    if ( AWND_ERROR == awnd_config_get_ssid(ifaceType, ssid_str))
    {
		AWN_LOG_ERR("fail to get ssid"); 
		return;
    }
	
    if ( AWND_ERROR == awnd_config_get_pwd(ifaceType, pwd_str))
    {
		AWN_LOG_ERR("fail to get password"); 
		return;
    }


    if (strcmp(pGroupInfo->ssid,  ssid_str) || strcmp(pGroupInfo->pwd,  pwd_str))
    {    
        awnd_config_set_ssid(pGroupInfo->ssid, ifaceType);
        awnd_config_set_pwd(pGroupInfo->pwd, ifaceType);
    }
    return;
}


/*!
*\fn           awnd_check_wifi_ssid_pwd()
*\brief        check backhual wifi ssid and pwd 
*\return       v    
*/

void awnd_check_wifi_ssid_pwd(AWND_GROUP_INFO *pAwndConfig, AWND_WIFI_IFACE_TYPE ifaceType)
{

    switch (ifaceType)
    {
        case WIFI_IFACE_BACKHUAL:
            _check_wifi_ssid_pwd(&(pAwndConfig->backhualGroupInfo), WIFI_IFACE_BACKHUAL);
            break;
        case WIFI_IFACE_CONFIG:
            _check_wifi_ssid_pwd(&(pAwndConfig->configGroupInfo), WIFI_IFACE_CONFIG);
            break;
         case WIFI_IFACE_PRECONFIG:
            //_check_wifi_ssid_pwd(&(pAwndConfig->configGroupInfo), WIFI_IFACE_CONFIG);
            break;
        case WIFI_IFACE_STA:
            if(AWND_STA_TYPE_NORMAL == pAwndConfig->staType)
            {
                _check_wifi_ssid_pwd(&(pAwndConfig->staGroupInfo), WIFI_IFACE_STA);
            }
            else if(AWND_STA_TYPE_PRE == pAwndConfig->staType)
            {
                _check_wifi_ssid_pwd(&(pAwndConfig->preconfGroupInfo), WIFI_IFACE_STA);
            }
            else if(AWND_STA_TYPE_PRECONFIG == pAwndConfig->staType)
            {
                //_check_wifi_ssid_pwd_preconfig_sta();
                _check_wifi_ssid_pwd(&(pAwndConfig->preconfigGroupInfo), WIFI_IFACE_STA);
            }

            break;
        case WIFI_IFACE_ALL:
            _check_wifi_ssid_pwd(&(pAwndConfig->backhualGroupInfo), WIFI_IFACE_BACKHUAL);
            _check_wifi_ssid_pwd(&(pAwndConfig->configGroupInfo), WIFI_IFACE_CONFIG);
             _check_wifi_ssid_pwd(&(pAwndConfig->preconfigGroupInfo), WIFI_IFACE_PRECONFIG);
            if(AWND_STA_TYPE_NORMAL == pAwndConfig->staType)
            {
                _check_wifi_ssid_pwd(&(pAwndConfig->staGroupInfo), WIFI_IFACE_STA);
            }
            else if(AWND_STA_TYPE_PRE == pAwndConfig->staType)
            {
                _check_wifi_ssid_pwd(&(pAwndConfig->preconfGroupInfo), WIFI_IFACE_STA);
            }
            break;
        default:
            AWN_LOG_WARNING("invaild iface type:%d", ifaceType);
            break;
    }

    return;
}


/*!
*\fn           awnd_config_get_weight()
*\brief        get weight of the subnet 
*\return       weight    
*/
UINT8 awnd_config_get_weight()
{
    char   weight_uci_str[UCI_STR_MAX_LEN];
    char   weight_str[8];
    UINT8  weight = 0;

    snprintf(weight_uci_str, sizeof(weight_uci_str), "%s", UCI_STR_FMT_AWN_WEIGHT);

    if (AWND_OK != _uci_get_value(weight_uci_str, weight_str))
    {
        AWN_LOG_ERR("fail to get mode %s ", weight_uci_str); 
    }
    else
    {
        weight = strtoul(weight_str, NULL, 10);
        AWN_LOG_INFO("Success to get awn weight %d", weight);
    }
    
    return weight;    
}

#if CONFIG_5G_HT160_SUPPORT
UINT8 awnd_config_get_enable_ht160()
{
#if CONFIG_ZERO_WAIT_DFS_SUPPORT
    /* 支持ZERO WAIT DFS的机型，无论wifi.ap.enable_ht160为0/1，当成160M处理。*/
    return 1;
#else
    char   enable_ht160_uci_str[UCI_STR_MAX_LEN];
    char   enable_ht160_str[8];
    UINT8  enable_ht160 = 1;

    snprintf(enable_ht160_uci_str, sizeof(enable_ht160_uci_str), "%s", UCI_STR_FMT_ENABLE_HT160);

    if (AWND_OK != _uci_get_value(enable_ht160_uci_str, enable_ht160_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_ht160_uci_str); 
    }
    else
    {
        enable_ht160 = strtoul(enable_ht160_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_ht160 %d", enable_ht160);
    }
    
    return enable_ht160;    
#endif /* CONFIG_ZERO_WAIT_DFS_SUPPORT */
}
#endif /* CONFIG_5G_HT160_SUPPORT */

UINT8 awnd_config_get_enable_5g_ht240()
{
    char   enable_ht240_uci_str[UCI_STR_MAX_LEN];
    char   enable_ht240_str[8];
    UINT8  enable_ht240 = 0;

    snprintf(enable_ht240_uci_str, sizeof(enable_ht240_uci_str), "%s", UCI_STR_FMT_ENABLE_HT240);

    if (AWND_OK != _uci_get_value(enable_ht240_uci_str, enable_ht240_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_ht240_uci_str); 
    }
    else
    {
        enable_ht240 = strtoul(enable_ht240_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_ht240 %d", enable_ht240);
    }
    
    return enable_ht240;
}


UINT8 awnd_config_get_enable_5g2()
{
    char   enable_5g2_uci_str[UCI_STR_MAX_LEN];
    char   enable_5g2_str[8];
    UINT8  enable_host = 0;
    UINT8  enable_host_5g2 = 0;
    UINT8  enable_guest = 0;
    UINT8  enable_guest_5g2 = 0;

    snprintf(enable_5g2_uci_str, sizeof(enable_5g2_uci_str), "%s", UCI_STR_FMT_HOST_ENABLE);
    if (AWND_OK != _uci_get_value(enable_5g2_uci_str, enable_5g2_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_5g2_uci_str);
    }
    else
    {
        enable_host = strtoul(enable_5g2_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_host %d", enable_host);
    }

    snprintf(enable_5g2_uci_str, sizeof(enable_5g2_uci_str), "%s", UCI_STR_FMT_HOST_5G2_ENABLE);
    if (AWND_OK != _uci_get_value(enable_5g2_uci_str, enable_5g2_str))
    {
        AWN_LOG_INFO("fail to get %s ", enable_5g2_uci_str);
    }
    else
    {
        enable_host_5g2 = strtoul(enable_5g2_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_host_5g2 %d", enable_host_5g2);
    }

    snprintf(enable_5g2_uci_str, sizeof(enable_5g2_uci_str), "%s", UCI_STR_FMT_GUEST_ENABLE);
    if (AWND_OK != _uci_get_value(enable_5g2_uci_str, enable_5g2_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_5g2_uci_str);
    }
    else
    {
        enable_guest = strtoul(enable_5g2_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_guest %d", enable_guest);
    }

    snprintf(enable_5g2_uci_str, sizeof(enable_5g2_uci_str), "%s", UCI_STR_FMT_GUEST_5G2_ENABLE);
    if (AWND_OK != _uci_get_value(enable_5g2_uci_str, enable_5g2_str))
    {
        AWN_LOG_INFO("fail to get %s ", enable_5g2_uci_str);
    }
    else
    {
        enable_guest_5g2 = strtoul(enable_5g2_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_guest_5g2 %d", enable_guest_5g2);
    }

    if ((1 == enable_host && 1 == enable_host_5g2) || (1 == enable_guest && 1 == enable_guest_5g2))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

UINT8 awnd_config_get_enable_6g()
{
    char   enable_6g_uci_str[UCI_STR_MAX_LEN];
    char   enable_6g_str[8];
    UINT8  enable_host = 0;
    UINT8  enable_host_6g = 0;
    UINT8  enable_guest = 0;
    UINT8  enable_guest_6g = 0;

    snprintf(enable_6g_uci_str, sizeof(enable_6g_uci_str), "%s", UCI_STR_FMT_HOST_ENABLE);
    if (AWND_OK != _uci_get_value(enable_6g_uci_str, enable_6g_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_6g_uci_str);
    }
    else
    {
        enable_host = strtoul(enable_6g_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_host %d", enable_host);
    }

    snprintf(enable_6g_uci_str, sizeof(enable_6g_uci_str), "%s", UCI_STR_FMT_HOST_6G_ENABLE);
    if (AWND_OK != _uci_get_value(enable_6g_uci_str, enable_6g_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_6g_uci_str);
    }
    else
    {
        enable_host_6g = strtoul(enable_6g_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_host_6g %d", enable_host_6g);
    }

    snprintf(enable_6g_uci_str, sizeof(enable_6g_uci_str), "%s", UCI_STR_FMT_GUEST_ENABLE);
    if (AWND_OK != _uci_get_value(enable_6g_uci_str, enable_6g_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_6g_uci_str);
    }
    else
    {
        enable_guest = strtoul(enable_6g_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_guest %d", enable_guest);
    }

    snprintf(enable_6g_uci_str, sizeof(enable_6g_uci_str), "%s", UCI_STR_FMT_GUEST_6G_ENABLE);
    if (AWND_OK != _uci_get_value(enable_6g_uci_str, enable_6g_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_6g_uci_str);
    }
    else
    {
        enable_guest_6g = strtoul(enable_6g_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_guest_6g %d", enable_guest_6g);
    }

    if ((1 == enable_host && 1 == enable_host_6g) || (1 == enable_guest && 1 == enable_guest_6g))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

UINT8 awnd_config_get_enable_6g2()
{
    char   enable_6g2_uci_str[UCI_STR_MAX_LEN];
    char   enable_6g2_str[8];
    UINT8  enable_6g2 = 0;

    snprintf(enable_6g2_uci_str, sizeof(enable_6g2_uci_str), "%s", UCI_STR_FMT_EXT_6G2_ENABLE);
    if (AWND_OK != _uci_get_value(enable_6g2_uci_str, enable_6g2_str))
    {
        AWN_LOG_ERR("fail to get %s ", enable_6g2_uci_str);
    }
    else
    {
        enable_6g2 = strtoul(enable_6g2_str, NULL, 10);
        AWN_LOG_INFO("Success to get enable_6g2 %d", enable_6g2);
    }

    if (1 == enable_6g2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

AWND_COUNTRY_TYPE awnd_config_get_country_code()
{
    char   country_uci_str[UCI_STR_MAX_LEN] = {0};
    char   country_str[8] = {0};
    AWND_COUNTRY_TYPE  country = AWND_COUNTRY_US;

    snprintf(country_uci_str, sizeof(country_uci_str), "%s", UCI_STR_FMT_RADIO_COUNTRY);

    if (AWND_OK != _uci_get_value(country_uci_str, country_str))
    {
        AWN_LOG_ERR("fail to get %s ", country_uci_str);
    }
    else
    {
        AWN_LOG_INFO("Success to get country code %s", country_str);
        if (!strncmp(country_str, "US", 2)) {
            country = AWND_COUNTRY_US;
        }
        else if (!strncmp(country_str, "EU", 2) || !strncmp(country_str, "DE", 2)) {
            country = AWND_COUNTRY_EU;
        }
        else if (!strncmp(country_str, "KR", 2)) {
            country = AWND_COUNTRY_KR;
        }
        else if (!strncmp(country_str, "BR", 2)) {
            country = AWND_COUNTRY_BR;
        }
        else if (!strncmp(country_str, "JP", 2)) {
            country = AWND_COUNTRY_JP;
        }
        else if (!strncmp(country_str, "CA", 2)) {
            country = AWND_COUNTRY_CA;
        }
        else if (!strncmp(country_str, "AU", 2)) {
            country = AWND_COUNTRY_AU;
        }
        else if (!strncmp(country_str, "RU", 2)) {
            country = AWND_COUNTRY_RU;
        }
        else if (!strncmp(country_str, "SW", 2)) {
            country = AWND_COUNTRY_SW;
        }
        else if (!strncmp(country_str, "TW", 2)) {
            country = AWND_COUNTRY_TW;
        }
    }

    return country;
}


/*****************************************************************
    device:wifi0 wifi1 wifi2 wifi3 wifi4
    interface       mode    network     net_type
    backhaul ap     ap      backhaul    backhaul
    host ap         ap      lan         lan
    guest ap        ap      guest       guest
    config ap       ap      backhaul    config
    default ap      ap      lan         default
    sta             sta     backhaul    backhaul

    BCM wifi0 wifi1 wifi3(5G2) wifi3(6G) wifi4(6G2)
        XE75 wifi0 wifi1 wifi3(6G)
        X75  wifi0 wifi1 wifi2(5G2)
    QCA: get form interfaces.radio_%s.name
        XE200 :
        BE85/BE65 : wifi0 wifi2(5G) wifi1(6G)
        BE95 : wifi0 wifi1 wifi2(6G) wifi3(6G2)
*****************************************************************/
static int _get_wifix_name_from_profile(char * pUciTupleStr, char* pValue)
{
    struct uci_context *uciCtx = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr uciPtr;

    uciCtx = uci_alloc_context();
    if (NULL == uciCtx)
    {
        AWN_LOG_ERR("Failed to alloc uci ctx");
        goto error;
    }
    uci_set_confdir(uciCtx, "/etc/profile.d");

    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, pUciTupleStr, true))
    {
        AWN_LOG_ERR("fail to get ptr %s ", pUciTupleStr);
        goto error;
    }

    e = uciPtr.last;
    if (UCI_TYPE_OPTION != e->type)
    {
        AWN_LOG_ERR("ptr %s: element type is not option:%d", pUciTupleStr, e->type);
        goto error;
    }

    if (UCI_TYPE_STRING != uciPtr.o->type)
    {
        AWN_LOG_ERR("ptr %s: option type is not string:%d", pUciTupleStr, uciPtr.o->type);
        goto error;
    }

    _strlcpy(pValue, uciPtr.o->v.string, UCI_STR_MAX_LEN);
    AWN_LOG_INFO("Success to get  option value %s = %s ", pUciTupleStr, uciPtr.o->v.string);

    _uci_context_free(uciCtx);
    return AWND_OK;

error:
    if (uciCtx)
    {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }
    return AWND_ERROR;
}

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
static int check_if_mld(const char *vapname)
{
    const char *colon_pos = strstr(vapname, "mld");
    if (colon_pos == NULL)
    {
        AWN_LOG_DEBUG("check_if_mld vapname: %s, is not mld\n", vapname);
        return -1;
    }
    AWN_LOG_CRIT("check_if_mld vapname: %s, is mld\n", vapname);
    return 0;   
}

static int get_mlddev_by_vapname(char **mlddev, char *vapname)
{
    const char *colon_pos = strchr(vapname, ':');
    if (colon_pos == NULL)
    {
        AWN_LOG_DEBUG("get_mlddev_by_vapname failed, vapname:%s\n", vapname);
        return -1;
    }

    size_t str_length = colon_pos - vapname;

    *mlddev = (char *)malloc(str_length + 1);
    if (*mlddev == NULL)
    {
        return -1;
    }
    strncpy(*mlddev, vapname, str_length);
    (*mlddev)[str_length]='\0';
    AWN_LOG_DEBUG("get_mlddev_by_vapname success, mlddev:%s\n", *mlddev);

    return 0;
}
#endif

static int get_wireless_interface_name(AWND_CONFIG *cfg)
{
    AWND_BAND_TYPE band = AWND_BAND_2G;
    AWND_REAL_BAND_TYPE real_band = AWND_REAL_BAND_2G;
    int ret = AWND_OK;
    struct uci_context *uciCtx  = NULL;
    struct uci_package *pkg     = NULL;
    struct uci_element *element = NULL;
    struct uci_section *section = NULL;
    const char *vapname = NULL;
    const char *if_mode = NULL;
    const char *if_type = NULL;
    const char *if_dev  = NULL;
    char  wifi_name_uci_str[UCI_STR_MAX_LEN] = {0};
    UINT8  wifix_name[AWND_REAL_BAND_MAX][16] = {0};

    for (real_band = AWND_REAL_BAND_2G; real_band < AWND_REAL_BAND_MAX; real_band ++) {
#if CONFIG_PLATFORM_BCM
        strncpy(wifix_name[real_band], wifi_defaut_name[real_band], sizeof(wifix_name[real_band]));
#else
        snprintf(wifi_name_uci_str, sizeof(wifi_name_uci_str), UCI_STR_FMT_WIFI_DEV_NAME, wifi_real_radio_suffix[real_band]);
        _get_wifix_name_from_profile(wifi_name_uci_str, wifix_name[real_band]);
#endif
        AWN_LOG_DEBUG("real_band:%d wifi_name(%s) strlen(%d)", real_band, wifix_name[real_band], strlen(wifix_name[real_band]));
    }

    uciCtx = uci_alloc_context();
    if (NULL == uciCtx)
    {
        AWN_LOG_ERR("Failed to alloc uci ctx");
        ret = AWND_ERROR;
        goto err;
    }

    uci_set_confdir(uciCtx, "/etc/config");
    if (UCI_OK != uci_load(uciCtx, "wireless", &pkg))
    {
        uci_perror(uciCtx, "wireless");
        ret = AWND_ERROR;
        goto err;
    }

    uci_foreach_element(&pkg->sections, element)
    {
        section = uci_to_section(element);
        vapname = uci_lookup_option_string(uciCtx, section, "vapname");
        if (NULL != vapname)
        {
            if_mode = uci_lookup_option_string(uciCtx, section, "mode");
            if_type = uci_lookup_option_string(uciCtx, section, "type");
            if_dev  = uci_lookup_option_string(uciCtx, section, "device");

            if (if_dev && if_mode && (!strcmp(if_mode, "ap") || !strcmp(if_mode, "sta")) &&
                if_type && (!strcmp(if_type, "backhaul") || !strcmp(if_type, "config") || !strcmp(if_type, "preconfig") || !strcmp(if_type, "lan")))
            {
                band = AWND_BAND_2G;
#ifdef CONFIG_DECO_WIFIHAL_SUPPORT                
                char *mlddev = NULL;
#endif
                for (real_band = AWND_REAL_BAND_2G; real_band < AWND_REAL_BAND_MAX; real_band ++) {
                    if(!strcmp(if_dev, wifix_name[real_band]))
                    {
                        band = _get_band_type_index(real_band);
                        break;
                    }
                }
                if (AWND_REAL_BAND_MAX == real_band) {
                     AWN_LOG_CRIT("unexpected vap device:%s vapname:%s", if_dev, vapname);
                }
#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
                else {

                    AWN_LOG_CRIT("check_if_mld vapname: %s, is mld: %d\n", vapname);
                    if(check_if_mld(vapname) < 0)
                    {
                        if(!strcmp(if_type, "backhaul")) {
                            if (!strcmp(if_mode, "ap")) {
                                strncpy(cfg->apIfnames[band], vapname, IFNAMSIZ);
                            }
                            else {
                                strncpy(cfg->staIfnames[band], vapname, IFNAMSIZ);
                            }
                        }
                        else if(!strcmp(if_type, "config")) {
                            strncpy(cfg->configIfnames[band], vapname, IFNAMSIZ);
                        }
                        else if(!strcmp(if_type, "preconfig")) {
                            strncpy(cfg->preconfigIfnames[band], vapname, IFNAMSIZ);
                        }
                        else if(!strcmp(if_type, "lan")) {
                            strncpy(cfg->hostIfnames[band], vapname, IFNAMSIZ);
                        }
                    }
                    else
                    {
                        get_mlddev_by_vapname(&mlddev, vapname);
                        if(mlddev == NULL)
                        {
                            break;
                        }
                        if(!strcmp(if_type, "backhaul")) {
                            if (!strcmp(if_mode, "ap")) {
                                strncpy(cfg->apIfnames[band], mlddev, IFNAMSIZ);
                            }
                            else {
                                strncpy(cfg->staIfnames[band], mlddev, IFNAMSIZ);
                            }
                        }
                        else if(!strcmp(if_type, "config")) {
                            strncpy(cfg->configIfnames[band], mlddev, IFNAMSIZ);
                        }
                        else if(!strcmp(if_type, "preconfig")) {
                            strncpy(cfg->preconfigIfnames[band], mlddev, IFNAMSIZ);
                        }
                        else if(!strcmp(if_type, "lan")) {
                            strncpy(cfg->hostIfnames[band], mlddev, IFNAMSIZ);
                        }
                    }
                }

                if(mlddev)
                    free(mlddev);
#else
                else {
                    if(!strcmp(if_type, "backhaul")) {
                        if (!strcmp(if_mode, "ap")) {
                            strncpy(cfg->apIfnames[band], vapname, IFNAMSIZ);
                        }
                        else {
                            strncpy(cfg->staIfnames[band], vapname, IFNAMSIZ);
                        }
                    }
                    else if(!strcmp(if_type, "config")) {
                        strncpy(cfg->configIfnames[band], vapname, IFNAMSIZ);
                    }
                    else if(!strcmp(if_type, "preconfig")) {
                        strncpy(cfg->preconfigIfnames[band], vapname, IFNAMSIZ);
                    }
                    else if(!strcmp(if_type, "lan")) {
                        strncpy(cfg->hostIfnames[band], vapname, IFNAMSIZ);
                    }
                }
#endif
            }

        }
    }

    uci_unload(uciCtx, pkg);

#if 0
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
        real_band = _get_real_band_type(band);
        AWN_LOG_INFO("band:%d real_band:%d (%s) ap:%s config:%s host:%s sta:%s ", band, real_band, real_band_suffix[real_band],
            cfg->apIfnames[band], cfg->configIfnames[band], cfg->hostIfnames[band], cfg->staIfnames[band]);
    }
#endif

err:
    if (uciCtx)
    {
    uci_free_context(uciCtx);
    uciCtx = NULL;
    }
    uciCtx = NULL;
  
    return ret;
}



/*!
 *\fn           int awnd_read_config()
 *\brief        Read config from auto-wifi-network conf
 *\param[in]       fpath          Configure file path      
 *\param[out]   pAwndConfig    The data struct of config 
 *\return       OK/ERROR
 */
int awnd_read_config(char *fpath, AWND_CONFIG *pAwndConfig)
{
    char *key;
    char *value;
    int  len  = 0;
    int  ret  = AWND_OK;
    FILE *fp  = NULL;
    char line[AWND_CONFIG_BUF_LEN] = { 0 };

    fp = fopen(fpath, "r");
    
    if (fp)
    {
        while (fgets(line, sizeof(line), fp))
        {
            key = line;
            if (*key == '#')
            {
                continue;
            }

            if (*key == '\n')
            {
                continue;
            }
            
            
            value = strchr(key, '=');
            if (value)
            {
                value++;
                key[value - key - 1] = '\0';
                len = strlen(value);
                if (len < 1) goto clean;
                value[len - 1] = '\0';

                ret = _parse_config(key, value, pAwndConfig);    
                if (ret < 0)
                {
                    AWN_LOG_CRIT("fail to paser config %s ", fpath); 
                    goto clean;    
                }
            }    
        }
clean:
        fclose(fp);            
    }
    else
    {
        AWN_LOG_CRIT("Open conf file failed.");
        ret = AWND_ERROR;    
    }

    AWN_LOG_ERR("band_num:%d sp_5g_2:%d sp_6g:%d sp_6g_2:%d \
    	band5g2_type:%d band6gtype:%d band6g2type:%d band3type:%d band4type:%d band5type:%d",
    	pAwndConfig->band_num, pAwndConfig->sp5G2,pAwndConfig->sp6G,pAwndConfig->sp6G2,
    	pAwndConfig->band_5g2_type,pAwndConfig->band_6g_type,pAwndConfig->band_6g2_type,
    	pAwndConfig->band_3rd_type,pAwndConfig->band_4th_type,pAwndConfig->band_5th_type);

	if (AWND_ERROR == get_wireless_interface_name(pAwndConfig))
	{
		AWN_LOG_CRIT("get wifi interface name from wireless config failed.");
		ret = AWND_ERROR;
		goto err;
	}

err:
    return ret;
}


#define MD5_LEN 16

int awnd_read_group_id(GROUP_INFO * pConfig, char* gidFile, int * defineRole)
{
    json_object_t *root = NULL;
    json_object_t *param = NULL;
    char cmd[128];
    char groupId[64]={0};
    char key[512]={0};
    char role[16]={0};
    char srcbuf[256]={0};
    char dstbuf[16]={0};
    char base='0';
    int bufLen = 0;  
    int index = 0;
    int ret = AWND_OK;
    

    if (NULL == pConfig || NULL == gidFile || NULL == defineRole)
    {
        return AWND_ERROR;
    }
    
    root = JSON_READ_FROM_FILE(gidFile);
    if (NULL == root)
    {
        AWN_LOG_INFO("parse file %s failed.", gidFile);	
        ret = AWND_ERROR;
        goto leave;
    }

    param = JSON_GET_OBJECT(root, "gid");
    if (param && JSON_TYPE_STRING == JSON_OBJECT_GET_TYPE(param))
    {
        strncpy(groupId, JSON_OBJECT_GET_STRING(param), sizeof(groupId));
        AWN_LOG_INFO("get group id %s.", groupId);	        
    }
    else
    {
        ret = AWND_ERROR;
        goto leave;    
    }       
    
    memset(pConfig->label, 0, AWND_LABEL_LEN);
    md5_make_digest(pConfig->label, groupId, strlen(groupId));
    AWN_LOG_INFO("label: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", 
        pConfig->label[0], pConfig->label[1], pConfig->label[2], pConfig->label[3], pConfig->label[4], 
        pConfig->label[5], pConfig->label[6], pConfig->label[7], pConfig->label[8], pConfig->label[9],
        pConfig->label[10], pConfig->label[11],pConfig->label[12], pConfig->label[13],pConfig->label[14], pConfig->label[15]);	

    param = JSON_GET_OBJECT(root, "key");
    if (param && JSON_TYPE_STRING == JSON_OBJECT_GET_TYPE(param))
    {
        strncpy(key, JSON_OBJECT_GET_STRING(param), sizeof(key));
        AWN_LOG_INFO("get key %s.", key);	        
    }
    else
    {
        ret = AWND_ERROR;
        goto leave;    
    } 

    bufLen = strlen(key) / 2;
    memset(pConfig->ssid, 0, AWND_MAX_SSID_LEN);
    for (index = 0; index < 16; index ++)
    {
        if ((index+1)* 7 < bufLen)
        {
            pConfig->ssid[index] = key[(index+ 1) * 7];
        }
        else 
        {
            break;
        }
    }

    memset(pConfig->pwd, 0, AWND_MAX_PWD_LEN);
    for (index = 0; index < 8; index ++)
    {
        if ((index+1)* 11 < bufLen)
        {
            pConfig->pwd[index] = key[bufLen + (index+1) * 11];
        }
        else 
        {
            pConfig->pwd[index]=(char)(base + index + 1);
        }
    }   
    
    AWN_LOG_INFO("ssid:%s, pwd:%s", pConfig->ssid, pConfig->pwd);	

    param = JSON_GET_OBJECT(root, "role");
    if (param && JSON_TYPE_STRING == JSON_OBJECT_GET_TYPE(param))
    {
        strncpy(role, JSON_OBJECT_GET_STRING(param), sizeof(role));
        AWN_LOG_INFO("get role %s.", role);

        if (!strncmp(role, "AP", 6))
        {
            *defineRole = AWND_CONFIG_AP;
        }
        else
        {
            *defineRole = AWND_CONFIG_RE;
        }
    }
 
leave:

    if (root)
    {
        JSON_DELETE(root);
        root = NULL;
    }

    return ret;    
    
}

void awnd_clean_gid_detect()
{
    char buf[120];
    if (!access(GID_FILE_DETECT, 0))
    {
        sprintf(buf, "rm %s", GID_FILE_DETECT);
        system(buf);
    }
}

int awnd_get_group_id(AWND_GROUP_INFO * pConfig, UINT8* bind)
{
    int ret = AWND_OK;
    int define_role = AWND_CONFIG_RE;
    int tmp_role = AWND_CONFIG_RE;

    if (NULL == pConfig || NULL == bind)
    {
        return AWND_ERROR;   
    }

    *bind = 0;
    pConfig->cfg_role = AWND_CONFIG_RE;

    if (_is_null_group_info(&(pConfig->configGroupInfo)))
    {
        if (AWND_OK != awnd_read_group_id(&(pConfig->configGroupInfo), DFT_GID_FILE, &define_role))
        {
            AWN_LOG_ERR("read default group info fail");
        }    
    }

    if (_is_null_group_info(&(pConfig->preconfGroupInfo)))
    {
        if (AWND_OK != awnd_read_group_id(&(pConfig->preconfGroupInfo), PRECONF_GID_FILE, &tmp_role))
        {
            AWN_LOG_INFO("read preconf group info fail");
        }    
    }
#ifdef CONFIG_DCMP_GLOBAL_support
	if (_is_null_group_info(&(pConfig->preconfigGroupInfo)))
    {
        if (AWND_OK != awnd_read_group_id(&(pConfig->preconfigGroupInfo), PRECONFIG_GID_FILE, &tmp_role))
        {
            AWN_LOG_INFO("read preconfig group info fail");
        }
    }
#endif
    if (AWND_OK == awnd_read_group_id(&(pConfig->backhualGroupInfo), GID_FILE, &define_role))
    {
        *bind = 1;
        pConfig->cfg_role = define_role;
        //AWN_LOG_INFO("backhual ssid:%s, pwd:%s", pConfig->backhualGroupInfo.ssid, pConfig->configGroupInfo.pwd);
        memcpy(&(pConfig->staGroupInfo), &(pConfig->backhualGroupInfo), sizeof(GROUP_INFO));
    }
    else
    {
        AWN_LOG_INFO("%s is empty", GID_FILE);
        memcpy(&(pConfig->staGroupInfo), &(pConfig->configGroupInfo), sizeof(GROUP_INFO));
    }
    //pConfig->staType = AWND_STA_TYPE_NORMAL;
     
    AWN_LOG_INFO("awnd_get_group_id bind: %d", *bind);


    //AWN_LOG_INFO("config ssid:%s, pwd:%s", pConfig->configGroupInfo.ssid, pConfig->configGroupInfo.pwd);   
    //AWN_LOG_INFO("sta ssid:%s, pwd:%s", pConfig->staGroupInfo.ssid, pConfig->staGroupInfo.pwd);

    return ret;
}

#if 0
int awnd_get_bind_fap_mac()
{   
    const char *json_mac = NULL;
    const char *json_role = NULL;
    char dev_mac[AWND_MAC_LEN] = {0};
    char dev_role[10] = {0};
    int ret = AWND_ERROR;
    struct json_object *root = NULL;

    root = json_object_from_file(SYNC_BIND_DEV_LIST);
    if (NULL == root)
    {
        AWN_LOG_ERR("Failed to read json file %s", SYNC_BIND_DEV_LIST);
        goto done;
    }

    json_object_object_foreach(root, key, val)
    {
        json_mac = json_object_get_string(json_object_object_get(val, "mac"));
        json_role = json_object_get_string(json_object_object_get(val, "role"));

        if (!json_mac || !json_role)
        {
            AWN_LOG_ERR("Invalid mesh device data format.");
            continue;
        }

        snprintf(dev_mac, sizeof(dev_mac), "%s", json_mac);
        snprintf(dev_role, sizeof(dev_role), "%s", json_role);

        AWN_LOG_INFO("dev_mac:%s dev_role:%s  cap_mac:%s.", dev_mac, dev_role);

        /* get AP's ip */
        if (!strcmp(dev_role, "AP"))
        {
            AWN_LOG_ERR("Current bind device: AP's mac is (%s)", dev_mac);
            snprintf(g_awnd.fapMac, AWND_MAC_LEN, "%s", dev_mac);
            ret = AWND_OK;
            break;
        }
    }

done:

    if (root)
    {
        json_object_put(root);
        root = NULL;
    }

    return ret;
}

#else

int  awnd_get_bind_fap_mac()
{
    struct uci_context *uciCtx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    struct uci_element *e = NULL;
    const char *roleStr = NULL;
    const char *macStr = NULL;
    int ret = AWND_ERROR;
    int i = 0;

    uciCtx = uci_alloc_context();
    if (NULL == uciCtx)
    {
        AWN_LOG_ERR("Failed to alloc uci ctx");
        ret = AWND_ERROR;
        goto error;
    }
    uci_set_confdir(uciCtx, CONFIG_PATH);
    
    if (UCI_OK != uci_load(uciCtx, UCI_BIND_DEVICE_LIST, &pkg))
    {
        AWN_LOG_ERR("uci_load %s error!", UCI_BIND_DEVICE_LIST);
        uci_perror(uciCtx, UCI_BIND_DEVICE_LIST);
        ret = AWND_ERROR;
        goto error;
    }
    
    uci_foreach_element(&pkg->sections, e)
    {
        //SHN_LOG_DEBUG("element name: %s.", e->name);
        s = uci_to_section(e);
        roleStr = uci_lookup_option_string(uciCtx, s, "role");
        if (roleStr != NULL && !strncmp(roleStr, "AP", 2))
        {
            macStr = uci_lookup_option_string(uciCtx, s, "mac");
            if (NULL != macStr)
            {
                _macaddr_format_convert(g_awnd.fapMac, macStr);
                AWN_LOG_INFO("Current bind device: AP's mac is (%s) fapMac:%02X:%02X:%02X:%02X:%02X:%02X",
                    macStr, g_awnd.fapMac[0], g_awnd.fapMac[1], g_awnd.fapMac[2], g_awnd.fapMac[3], g_awnd.fapMac[4], g_awnd.fapMac[5]);
                ret = AWND_OK;
                break;
            }
        }
    }

    uci_unload(uciCtx, pkg);

error:
    if (uciCtx)
    {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }
    return ret;
}

int awnd_get_network_oui()
{
    struct uci_context *uciCtx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    struct uci_element *e = NULL;
    const char *roleStr = NULL;
    const char *ouiStr = NULL;
    int network_oui = 1;
    int ret = AWND_ERROR;
    int i = 0;

    uciCtx = uci_alloc_context();
    if (NULL == uciCtx)
    {
        AWN_LOG_ERR("Failed to alloc uci ctx");
        ret = AWND_ERROR;
        goto error;
    }
    uci_set_confdir(uciCtx, CONFIG_PATH);

    if (UCI_OK != uci_load(uciCtx, UCI_BIND_DEVICE_LIST, &pkg))
    {
        AWN_LOG_ERR("uci_load %s error!", UCI_BIND_DEVICE_LIST);
        uci_perror(uciCtx, UCI_BIND_DEVICE_LIST);
        ret = AWND_ERROR;
        goto error;
    }

    uci_foreach_element(&pkg->sections, e)
    {
        s = uci_to_section(e);
        ouiStr = uci_lookup_option_string(uciCtx, s, "oui_version");
        if (ouiStr == NULL)
        {
            network_oui = 0;
            break;
        }
        else
        {
            if (strcmp(ouiStr, "0") == 0)
            {
                network_oui = 0;
                break;
            }
        }
    }

    uci_unload(uciCtx, pkg);
    if (uciCtx)
    {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }
    return network_oui;

error:
    if (uciCtx)
    {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }
    return ret;
}

#endif

int awnd_set_re_bridge(AWND_SUBMODE submode)
{
    char cmdbuf[128] = {0};
    if (AWND_SUBMODE_STAR == submode)
    {
       system("echo 0 >/sys/class/net/br-lan/bridge/bridge_deliver_enable");
       AWN_LOG_INFO("disable bridge deliver control");
    }
    else
    {
       system("echo 1 > /sys/class/net/br-lan/bridge/bridge_deliver_eth_to_2g_enable");
       memset(cmdbuf, 0, sizeof(cmdbuf));
#ifdef CONFIG_PRODUCT_PLC_SGMAC
       snprintf(cmdbuf, sizeof(cmdbuf), "echo 'ath02.1,ath0:ath%d2.1,ath%d:eth0.3,eth0.4:br-lan:ath03.1:ath%d3.1' >/sys/class/net/br-lan/bridge/bridge_name_matrix",
            QCA_IFINDEX_5G, QCA_IFINDEX_5G, QCA_IFINDEX_5G);
#else
       snprintf(cmdbuf, sizeof(cmdbuf), "echo 'ath02.1,ath0:ath%d2.1,ath%d:eth0,eth1:br-lan:ath03.1:ath%d3.1' >/sys/class/net/br-lan/bridge/bridge_name_matrix",
            QCA_IFINDEX_5G, QCA_IFINDEX_5G, QCA_IFINDEX_5G);      
#endif
       system(cmdbuf);
       AWN_LOG_INFO("martix cmdbuf:%s", cmdbuf);
       system("echo 1 > /sys/class/net/br-lan/bridge/bridge_deliver_enable");
       AWN_LOG_INFO("enable bridge deliver control");
        
    }    

}

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
int awnd_notify_apsd_eth_bhl_change(char * name, UINT8 state)
{
	json_object_t *root = NULL;
	char buf[256];
	if(!name)
	{
		return ERROR;
	}
	
	root = JSON_CREATE_OBJECT();
	if(!root)
	{
		return ERROR;
	}
	JSON_ADD_STRING_TO_OBJECT(root, "interface", name);
	JSON_ADD_NUMBER_TO_OBJECT(root, "state", state);

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "ubus send apsd.ethbhl_change '%s'", JSON_OBJECT_TO_STRING(root));
    system(buf);

	if (root)
	{
		JSON_DELETE(root);
	}
	return OK;
}
int awnd_config_get_eth_wlan_enable()
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    char mode_str[30];
    int eth_wlan_enable = 0;

    snprintf(mode_uci_str, sizeof(mode_uci_str), "%s", ETH_WLAN_ENABLE);

    if (AWND_OK != _uci_get_value(mode_uci_str, mode_str))
    {
        AWN_LOG_INFO("fail to get eth wlan enable config"); 
    }
    else
    {
        AWN_LOG_INFO("Success to get eth wlan enable is %s", mode_str);
        if (!strncmp(mode_str, "0", sizeof("0")))
        {
            eth_wlan_enable = 1;
        }
    }
    return eth_wlan_enable;
}
#endif

int awnd_config_get_plc_backhaul(char *plc_backhaul)
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    int result = 0;

    snprintf(mode_uci_str, sizeof(mode_uci_str), "%s", PLC_BACKHAUL_VID);

    if (AWND_OK != _uci_get_value(mode_uci_str, plc_backhaul))
    {
        AWN_LOG_ERR("fail to get plc backhaul vid %s ", mode_uci_str); 
    }
    else
    {
        result = 1;
        AWN_LOG_INFO("Success to get plc backhaul vid %s", plc_backhaul);
    }

    return result;
}

int awnd_config_get_plc_guest(char *plc_guest)
{
    char mode_uci_str[UCI_STR_MAX_LEN];
    int result = 0;

    snprintf(mode_uci_str, sizeof(mode_uci_str), "%s", PLC_GUEST_VID);

    if (AWND_OK != _uci_get_value(mode_uci_str, plc_guest))
    {
        AWN_LOG_ERR("fail to get plc backhaul vid %s ", mode_uci_str); 
    }
    else
    {
        result = 1;
        AWN_LOG_INFO("Success to get plc guest vid %s", plc_guest);
    }

    return result;
}

int awnd_write_rt_info(AWND_INTERFACE_TYPE band, BOOL status, UINT8* pMac, BOOL capHasPlc)
{
	FILE *file = NULL;
	json_object_t *root = NULL;
	INT8 *filename = NULL;
	UINT8 paraname[WIFI_PARA_NAME_LEN + 1] = {0};
	INT32 bitIdx = 0;
    INT32 index = 0;
/*	UINT8 tmpstr[4]; */
    char buf[256];
    char strMac[AWND_MAX_BSSID_LEN] = {0};
    unsigned int old_link_state = link_state;
	unsigned int old_eth_link_state = eth_link_state;
    unsigned int old_eth_link = 0;
    unsigned int eth_link = 0;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    unsigned int tmp_wireless_eth_state = 0;
    static AWND_HOTPLUG_CONFIG hotplugCfg;
#endif
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    unsigned int wlan_link = 0;
    unsigned int old_wlan_link = 0;
    unsigned int eth_wlan_link = 0;
    unsigned int old_eth_wlan_link = 0;
#endif
    AWND_REAL_BAND_TYPE real_band = 0;

    if (band < AWND_INTERFACE_PLC) {
        real_band = _get_real_band_type(band);
    }
    else { /* plc & eth */
        real_band = band;
        }

	if(0 != eth_link_state){
		old_eth_link = 1;
	}

	AWN_LOG_INFO("band:%d(0:2g 1:5g 2:5g2 3:6g 4:6g2 8:plc 16:eth), status:%s", real_band, (status ? "up" : "down"));

    if (band <= AWND_INTERFACE_PLC)
    {
        bitIdx = (real_band == AWND_INTERFACE_PLC) ? LINK_STATE_BITIDX_PLC : real_band;
        if (status)
        { 
            link_state = link_state | (1 << bitIdx);
        }
        else
        {
            link_state = link_state & (~(1 << bitIdx));
        }
    }
   
    /* update eth link status */
    if (band == AWND_INTERFACE_ETH || AWND_STATUS_CONNECTED == g_awnd.ethStatus)
    {
        for (index = 0; index < l_awnd_config.ethIfCnt; index++)
        {
            bitIdx = index;
            if (g_awnd.ethLinktoAP[index])
            { 
                eth_link_state = eth_link_state | (1 << (bitIdx));
            }
            else
            {
                eth_link_state = eth_link_state & (~(1 << (bitIdx)));
            }        
        }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        if (0 != eth_link_state){
            status = 1;
        }
#endif

    }
	if(0 != eth_link_state){
		eth_link = 1;
	}
    if( old_eth_link != eth_link )
    {
        sprintf(buf, "ubus call sync boost >/dev/null; ubus call sync probe >/dev/null");
        system(buf);
    }

	root = JSON_CREATE_OBJECT();
	if(!root)
	{
		return ERROR;
	}
	
	JSON_ADD_NUMBER_TO_OBJECT(root, "status", status);
    if (status && NULL != pMac)
    {
        _macaddr_ntop(pMac, strMac);
        JSON_ADD_STRING_TO_OBJECT(root, "rootap_mac", strMac);
    }
    if (band == AWND_INTERFACE_PLC)
    {
        JSON_ADD_NUMBER_TO_OBJECT(root, "cap_has_plc", capHasPlc);
    }

	if (real_band == AWND_REAL_BAND_2G)
	{	
		filename = WIFI_RUNTIME_FILE_2G;
	}
	else if (real_band == AWND_REAL_BAND_5G)
	{
		filename = WIFI_RUNTIME_FILE_5G;
	}
	else if (real_band == AWND_REAL_BAND_5G2)
	{
		filename = WIFI_RUNTIME_FILE_5G2;
	}
    else if (real_band == AWND_REAL_BAND_6G)
    {
        filename = WIFI_RUNTIME_FILE_6G;
    }
    else if (real_band == AWND_REAL_BAND_6G2)
    {
        filename = WIFI_RUNTIME_FILE_6G2;
    }
    else if (real_band == AWND_INTERFACE_PLC)
	{
		filename = PLC_RUNTIME_FILE;
	}
    else if (real_band == AWND_INTERFACE_ETH)
	{
		filename = ETH_RUNTIME_FILE;
	}
    else
    {
        if (root)
            JSON_DELETE(root);
        return AWND_ERROR;
    }

	JSON_WRITE_TO_FILE(filename, root);	

	if (root)
		JSON_DELETE(root);

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    if ((link_state & LINK_STATE_MASK_2G) || (link_state & LINK_STATE_MASK_5G) || 
        (g_awnd.enable5g2 && (link_state & LINK_STATE_MASK_5G2)) || 
        (g_awnd.enable6g && (link_state & LINK_STATE_MASK_6G)) || 
        (g_awnd.enable6g2 && (link_state & LINK_STATE_MASK_6G2))){
        wlan_link = 1;
    }

    if ((old_link_state & LINK_STATE_MASK_2G) || (old_link_state & LINK_STATE_MASK_5G) || 
        (g_awnd.enable5g2 && (old_link_state & LINK_STATE_MASK_5G2)) || 
        (g_awnd.enable6g && (old_link_state & LINK_STATE_MASK_6G)) || 
        (g_awnd.enable6g2 && (old_link_state & LINK_STATE_MASK_6G2))){
        old_wlan_link = 1;
    }

    eth_wlan_link = (wlan_link & eth_link) ? 1 : 0;
    old_eth_wlan_link = (old_wlan_link & old_eth_link) ? 1 : 0;
    root = JSON_CREATE_OBJECT();
    if(!root)
    {
        AWN_LOG_WARNING("JSON_CREATE_OBJECT Fail");
        return ERROR;
    }

    JSON_ADD_NUMBER_TO_OBJECT(root, "status", eth_wlan_link);
    JSON_WRITE_TO_FILE(ETH_WLAN_RUNTIME_FILE, root);

#ifdef CONFIG_EXT_SWITCH_IN_VLAN
    if (eth_wlan_link)
    {
        system("ssdk_sh fdb entry flush 0");
        AWN_LOG_WARNING("now flush fdb table");
    }
#endif

    if (root)
		JSON_DELETE(root);
#endif
    root = JSON_CREATE_OBJECT();
    if(!root)
    {
        AWN_LOG_WARNING("JSON_CREATE_OBJECT Fail");
        return ERROR;
    }

    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_WIFI_2G",   (link_state & (LINK_STATE_MASK_2G) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_WIFI_5G",   (link_state & (LINK_STATE_MASK_5G) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_WIFI_5G_2", (link_state & (LINK_STATE_MASK_5G2) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_WIFI_6G",   (link_state & (LINK_STATE_MASK_6G) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_WIFI_6G_2", (link_state & (LINK_STATE_MASK_6G2) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_PLC",       (link_state & (LINK_STATE_MASK_PCL) ? 1:0));
    JSON_ADD_NUMBER_TO_OBJECT(root, "LINK_ETH",       eth_link_state);

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    if (0 != link_state) {
        tmp_wireless_eth_state = tmp_wireless_eth_state | (1 << 0);
    }
    if (0 != eth_link_state) {
        tmp_wireless_eth_state = tmp_wireless_eth_state | (1 << 1);
    }
    if (old_link_state == 0 && old_eth_link_state == 0 && tmp_wireless_eth_state > 0) {
        //set tipc check timer, if connected, send ai roaming request
        awnd_set_tipc_check_time(70);
    }

    if (tmp_wireless_eth_state != wireless_eth_state && tmp_wireless_eth_state > 0) {
        hotplugCfg.srcMode = AWND_MODE_RE;
        hotplugCfg.dstMode = AWND_MODE_RE;
        hotplugCfg.type = AWND_HOTPLUG_LINK_STATUS_CHANGE;
        awnd_mode_call_hotplug(&hotplugCfg);
        AWN_LOG_INFO("link status change");
        wireless_eth_state = tmp_wireless_eth_state;
        awnd_set_tipc_check_time(70);
    }
#endif  /*  CONFIG_AWN_MESH_OPT_SUPPORT */

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "ubus send apsd.link_state '%s'", JSON_OBJECT_TO_STRING(root));
    system(buf);
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "ubus send sa.link_state '%s'", JSON_OBJECT_TO_STRING(root));
    system(buf);

    if (old_link_state == link_state && old_eth_link_state == eth_link_state)
    {
        if (root)
        {
            JSON_DELETE(root);
        }
        return OK;
    }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    else if (tmp_wireless_eth_state > 0)//if connect and status change, send devinfo
    {
        AWN_LOG_ERR("ubus call ai_center.debug update_devinfo");
        memset(buf, 0, sizeof(buf));
        snprintf(buf, sizeof(buf), "ubus call ai_center.debug update_devinfo >/dev/null &");
        system(buf);
    }
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

#if CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    if (old_eth_wlan_link & (!eth_wlan_link))
        awnd_repacd_set_sta_vlan_backhual_iface_enable(g_awnd.workMode, 1);
    else if (eth_wlan_link)
        awnd_repacd_set_sta_vlan_backhual_iface_enable(g_awnd.workMode, 0);
#endif
    /* set backhaul sta dev */
    if (link_state || eth_link_state)
        awnd_set_backhaul_sta_dev(link_state, eth_link_state);

    /* set neighbor pkt forward */
    awn_eth_set_forward_param((link_state || eth_link_state) ? 1 : 0);

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "ubus send link_state '%s'", JSON_OBJECT_TO_STRING(root));
    system(buf);

    AWN_LOG_WARNING("link_state:%d, eth_link_state:%d, buf:%s", link_state, eth_link_state, buf);

    if (root)
        JSON_DELETE(root);

	return OK;
	
}

int awnd_write_work_mode(AWND_MODE_TYPE workMode, int linked, UINT8* pMac, AWND_NET_TYPE netType, UINT8 level, UINT8* pParentMac)
{
	int ret = 0;
	char str[AWND_MAX_BSSID_LEN] = {0};
	json_object_t *data = NULL;
    int Pmac_check = 0;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    char buf[256] = {0};
    static AWND_HOTPLUG_CONFIG hotplugCfg;
#endif
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    UINT8 cap_mac[AWND_MAC_LEN] = {0};
    UINT8 parent_mac[AWND_MAC_LEN] = {0};
    UINT8 second_parent_mac[AWND_MAC_LEN] = {0};
    UINT8 wlan_rootap_mac[AWND_MAC_LEN] = {0};
    int first_level = 0;
    int second_level = 0;
    AWND_BAND_TYPE band;

    if (g_awnd.ethStatus == AWND_STATUS_CONNECTED && _is_vaild_mac(g_awnd.ethNetInfo.awnd_mac)) {
        linked = 1;
        memcpy(cap_mac, g_awnd.ethNetInfo.awnd_mac, AWND_MAC_LEN);

        AWN_LOG_WARNING("eth connected, eth rootap:%02x:%02x:%02x:%02x:%02x:%02x cap_mac:%02x:%02x:%02x:%02x:%02x:%02x level:%d, net_type:%d",
            g_awnd.ethRootApMac[0],g_awnd.ethRootApMac[1],g_awnd.ethRootApMac[2],
            g_awnd.ethRootApMac[3],g_awnd.ethRootApMac[4],g_awnd.ethRootApMac[5],
            cap_mac[0], cap_mac[1], cap_mac[2], cap_mac[3], cap_mac[4], cap_mac[5],
            g_awnd.ethNetInfo.awnd_level, g_awnd.ethNetInfo.awnd_net_type);
    }

    if (_is_in_connected_state(g_awnd.connStatus) && _is_vaild_mac(g_awnd.netInfo.awnd_mac)) {
        linked = 1;
        memcpy(cap_mac, g_awnd.netInfo.awnd_mac, AWND_MAC_LEN);

        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++){
            if (AWND_STATUS_DISCONNECT != g_awnd.connStatus[band] && _is_vaild_mac(g_awnd.rootAp[band].lan_mac)){
                memcpy(wlan_rootap_mac, g_awnd.rootAp[band].lan_mac, AWND_MAC_LEN);
                break;
            }
        }
        AWN_LOG_WARNING("wlan connected, wlan rootap:%02x:%02x:%02x:%02x:%02x:%02x cap_mac:%02x:%02x:%02x:%02x:%02x:%02x level:%d, net_type:%d",
            wlan_rootap_mac[0], wlan_rootap_mac[1], wlan_rootap_mac[2],
            wlan_rootap_mac[3], wlan_rootap_mac[4], wlan_rootap_mac[5],
            cap_mac[0], cap_mac[1], cap_mac[2], cap_mac[3], cap_mac[4], cap_mac[5],
            g_awnd.netInfo.awnd_level, g_awnd.netInfo.awnd_net_type);
    }

    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus && _is_vaild_mac(g_awnd.ethRootApMac)){
        memcpy(parent_mac, g_awnd.ethRootApMac, AWND_MAC_LEN);
        first_level = g_awnd.ethNetInfo.awnd_level;
        if (_is_in_connected_state(g_awnd.connStatus) && _is_vaild_mac(wlan_rootap_mac)){
            memcpy(second_parent_mac, wlan_rootap_mac, AWND_MAC_LEN);
            second_level = g_awnd.netInfo.awnd_level;
        }
        netType = g_awnd.ethNetInfo.awnd_net_type;
    }else{
        if (_is_in_connected_state(g_awnd.connStatus) && _is_vaild_mac(wlan_rootap_mac)) {
            memcpy(parent_mac, wlan_rootap_mac, AWND_MAC_LEN);
            first_level = g_awnd.netInfo.awnd_level;
            netType = g_awnd.netInfo.awnd_net_type;
        }
    }

#endif
	data = JSON_CREATE_OBJECT();
	if (NULL == data)
	{
		AWN_LOG_ERR("json object create failed.");
		ret = -1;
		goto err;
	}

	JSON_ADD_STRING_TO_OBJECT(data, "work_mode", modeToStr(workMode));

	JSON_ADD_NUMBER_TO_OBJECT(data, "link2ap", linked);

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
	if (linked && _is_vaild_mac(cap_mac))
	{
	    memset(str, 0 , sizeof(str));
	    _macaddr_ntop(cap_mac, str);
	    JSON_ADD_STRING_TO_OBJECT(data, "cap_mac", str);
	}

    JSON_ADD_STRING_TO_OBJECT(data, "net_type", modeToStr(netType));
	if (_is_vaild_mac(parent_mac))
	{
	    memset(str, 0 , sizeof(str));
	    _macaddr_ntop(parent_mac, str);
	    JSON_ADD_STRING_TO_OBJECT(data, "parent_mac", str);
        Pmac_check = 1;
	}

    JSON_ADD_NUMBER_TO_OBJECT(data, "level", first_level);

    if (memcmp(parent_mac, second_parent_mac, AWND_MAC_LEN) && _is_vaild_mac(second_parent_mac))
	{
	    memset(str, 0 , sizeof(str));
	    _macaddr_ntop(second_parent_mac, str);
	    JSON_ADD_STRING_TO_OBJECT(data, "second_parent_mac", str);
        JSON_ADD_NUMBER_TO_OBJECT(data, "second_level", second_level);
	}
#else
	if (linked && NULL != pMac)
	{
        _macaddr_ntop(pMac, str);
	    JSON_ADD_STRING_TO_OBJECT(data, "cap_mac", str);
	}

    JSON_ADD_STRING_TO_OBJECT(data, "net_type", modeToStr(netType));

	if (linked && NULL != pParentMac)
	{
	    memset(str, 0 , sizeof(str));
	    _macaddr_ntop(pParentMac, str);
	    JSON_ADD_STRING_TO_OBJECT(data, "parent_mac", str);
        Pmac_check = 1;
	}	
    JSON_ADD_NUMBER_TO_OBJECT(data, "level", level);
#endif
    
    if(Pmac_check)
    {
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        if (0 != memcmp(old_parent_mac, pParentMac, AWND_MAC_LEN))
        {
            memcpy(old_parent_mac, pParentMac, AWND_MAC_LEN);
            hotplugCfg.srcMode = AWND_MODE_RE;
            hotplugCfg.dstMode = AWND_MODE_RE;
            hotplugCfg.type = AWND_HOTPLUG_PARENT_CHANGE;
            AWN_LOG_INFO("parent_mac change");
            awnd_mode_call_hotplug(&hotplugCfg);
            snprintf(buf, sizeof(buf), "ubus call ai_center.debug update_devinfo >/dev/null &");
            system(buf);
            /* if the rootap of DUT is not equal to l_mac_prefer/l_mac_ai_roaming_target, it should be send first_roaming to FAP*/
            if ((0 != memcmp(pParentMac, l_mac_prefer, AWND_MAC_LEN)) && 0 != memcmp(pParentMac, l_mac_ai_roaming_target, AWND_MAC_LEN))
            {
                AWN_LOG_ERR("send first roaming to FAP");
                awnd_set_tipc_check_time(30);
            }
        }
        set_parent_mac(pParentMac);
#else
        memcpy(old_parent_mac, pParentMac, AWND_MAC_LEN); 
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT  */
    }

	ret = JSON_WRITE_TO_FILE("/tmp/work_mode", data);
	if (ret)
	{
		AWN_LOG_ERR("write file '/tmp/work_mode' failed.");
	}

	if (data)
	{
		JSON_DELETE(data);
		data = NULL;
	}
err:
	return ret;
}
#if GET_AP_RSSI
_json_add_rssi(json_object_t *root, int type, unsigned int state)
{
	if (AWND_REAL_BAND_5G2 == type)
	{
		JSON_ADD_NUMBER_TO_OBJECT(root, "rssi_5g2", state);
	}
	else if (AWND_REAL_BAND_6G == type)	
	{
		JSON_ADD_NUMBER_TO_OBJECT(root, "rssi_6g", state);
	}
	else if (AWND_REAL_BAND_6G2 == type)	
	{
		JSON_ADD_NUMBER_TO_OBJECT(root, "rssi_6g2", state);
	}
}

int awnd_write_rt_rootap_rssi(int curRssi[AWND_BAND_MAX])
{
    int ret = 0;
    json_object_t *root = NULL;
    int rssi_diff = 0;
    UINT8 need_update = 0;
    AWND_BAND_TYPE    band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        rssi_diff = rootap_rssi[band] - curRssi[band];
        if (rssi_diff > 2 || rssi_diff < -2)
            need_update = 1;
    }

    if (0 == need_update)
        return AWND_OK;


    root = JSON_CREATE_OBJECT();
    if (!root)
    {
        return AWND_ERROR;
    }

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        rootap_rssi[band] = curRssi[band];
        if (AWND_BAND_2G == band)
        {
            JSON_ADD_NUMBER_TO_OBJECT(root, "rssi_2g", curRssi[band]);
        }
        else if (band == AWND_BAND_5G)
        {
            JSON_ADD_NUMBER_TO_OBJECT(root, "rssi_5g", curRssi[band]);
        }
		else if (band == AWND_BAND_3RD)
		{
			_json_add_rssi(root, l_awnd_config.band_3rd_type, curRssi[band]);
		}
		else if (band == AWND_BAND_4TH)
		{
			_json_add_rssi(root, l_awnd_config.band_4th_type, curRssi[band]);
		}
		else if (band == AWND_BAND_5TH)
		{
			_json_add_rssi(root, l_awnd_config.band_5th_type, curRssi[band]);
		}
    }

    ret = JSON_WRITE_TO_FILE("/tmp/rootap_rt_rssi", root);
    if (ret)
    {
        ret = AWND_ERROR;
        AWN_LOG_ERR("write file '/tmp/rootap_rt_rssi' failed.");
    }

    if (root)
    {
        JSON_DELETE(root);
        root = NULL;
    }
    return ret;
}
#endif
/* 
 * fn       bool check_ap_mode()
 * brief    check DUT's work mode.
 * details  
 *
 * param[in]    void
 *
 * return   bool
 * retval   true - AP mode; false - Router mode.
 *
 * note     
 */
BOOL awnd_check_ap_mode()
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL; 
    struct uci_element *e;
    struct uci_section *sec;
    const char *optionVal = NULL;
    BOOL ret = false;
    
    ctx = uci_alloc_context();
    if (!ctx)
    {
        AWN_LOG_ERR("Fail to alloc context for uci.");
        return false;
    }
    if (UCI_OK != uci_load(ctx, SYSMODE_CONFIG_FILE, &pkg))
    {
        AWN_LOG_ERR("Fail to load uci package.");
        goto cleanup;
    }

    sec = uci_lookup_section(ctx, pkg, SECTION_NAME_SYSMODE);
    if(!sec)
    {
        AWN_LOG_ERR("Can't find specified section by name(%s).", SECTION_NAME_SYSMODE);
        goto cleanup;
    }

    optionVal = uci_lookup_option_string(ctx, sec, SYSMODE_OPTION_MODE);
    if (!optionVal)
    {
        AWN_LOG_ERR("Can't find option by name(%s).", SYSMODE_OPTION_MODE);
        goto cleanup;
    }

    if (!strcmp(optionVal, MODE_VAL_AP))
    {
        ret = true;
    }
cleanup:
    if (pkg != NULL)
    {
        uci_unload(ctx, pkg);
    }
    uci_free_context(ctx);  
    return ret;
}

#ifdef CONFIG_AWN_RE_ROAMING
int awnd_config_sta_bssid(char *bssid_str, const char *vap)
{
    char bssid_uci_str[UCI_STR_MAX_LEN] = {0};

    snprintf(bssid_uci_str, sizeof(bssid_uci_str), "wireless.%s.bssid", vap);
    AWN_LOG_INFO("Set sta(%s) wireless config.", vap);
    if (AWND_OK != _uci_set_value(bssid_uci_str, bssid_str))
    {
        AWN_LOG_ERR("fail to set value: %s=%s", bssid_uci_str, bssid_str);
        return AWND_ERROR;
    }
    /*
    if (AWND_OK != _uci_commit("wireless"))
    {
        AWN_LOG_ERR("fail to commit wireless");
        return AWND_ERROR;
    }
    */
    return  AWND_OK;
}
#endif

int get_radar_detect_number()
{
    FILE *fd;
    char res[128] = {0};
    char cmd[128] = {0};
    int len = 0;

    sprintf(cmd, "echo $(radartool -i wifi1 numdetects) | grep -o -E '[0-9]+'");
    fd = popen(cmd, "r");
    if (fd)
    {
        len = fread(res, sizeof(char), sizeof(res), fd);
        pclose(fd);
        if ((res[0] != '\n') && (res[0] != '\0'))
        {
            AWN_LOG_ERR("get radar detect number: %d", atoi(res));
            return atoi(res);
        }
    }
    return -1;
}

int awnd_config_check_block_chan_list(AWND_BAND_TYPE band, int *channel)
{
    char   uci_str[64]  = {0};
    char   uci_val[128] = {0};
    char   chan[5] = {0};
    int    chan_list[4] = {44, 64, 116, 153};
    int    idx = 0;
    char   *token;
    char   *tok;
    bool   found = false;

    if (!channel)
    {
        return AWND_ERROR;
    }

    snprintf(chan, sizeof(chan), "%d", *channel);
    snprintf(uci_str, sizeof(uci_str), "wireless.%s.channel_block_list", l_awnd_config.apIfnames[band]);

    if (AWND_OK != _uci_get_value(uci_str, uci_val))
    {
        AWN_LOG_ERR("fail to get channel block list %s ", uci_str);
        return AWND_ERROR;
    }

    AWN_LOG_ERR("chan %s channel block list %s ", chan, uci_val);

    if (get_radar_detect_number() <= 0)
    {
        token = strtok_r(uci_val, ",", &tok);
        while (token != NULL)
        {
            if (atoi(token) == *channel)
            {
                found = true;
            }
            if (atoi(token) == chan_list[idx])
            {
                idx++;
            }
            token = strtok_r(NULL, ",", &tok);
        }
    }

    if (found)
    {
        idx = (idx >= 4) ? 0 : idx;
        *channel = chan_list[idx];
        return AWND_ERROR;
    }

    return AWND_OK;
}
/**
 * read device special_id using getfirm, fallback to US (55530000) when error
 */
void awnd_get_special_id(char* specialid)
{
    FILE *fd;
    int len;
    char info[SPECIALID_LEN + 1] = {0};
    char cmd[50] = {0};
    int check_pass = true;

    sprintf(cmd, "echo $(getfirm SPECIAL_ID) | tr -d \"\\n\"");
    fd = popen(cmd, "r");
    if (NULL == fd)
    {
        strcpy(specialid, SPECIALID_US);
    }
    else
    {
        int i;
        len = fread(info, sizeof(char), SPECIALID_LEN + 1, fd);
        pclose(fd);

        if (len < SPECIALID_LEN) 
            check_pass = false;

        /* special id length = 8 */
        for(i = 0; i < SPECIALID_LEN; i++)
        {
            if (!((info[i] >= 'A' && info[i] <= 'F') || (info[i] >= '0' && info[i] <= '9')))
                check_pass = false;
        }

        if(check_pass)
        {
            strncpy(specialid, info, SPECIALID_LEN + 1);
        } else {
            strncpy(specialid, SPECIALID_US, SPECIALID_LEN + 1);
        }
        specialid[SPECIALID_LEN] = '\0';
    }
}


#if CONFIG_OUTDOOR_CHANNELLIMIT
BOOL awnd_get_chanlimit_support()
{
    FILE *fd;
    int len = 0;
    char buff[8] = {0};
    char cmd[128] = {0};
    BOOL res = false;

    sprintf(cmd, "uci -c /etc/profile.d get %s", CHANNELLIMIT_PROFILE_SUPPORT);
    fd = popen(cmd, "r");
    if (NULL == fd)
    {
        return false;
    }
    else
    {
        len = fread(buff, sizeof(char), 8, fd);
        pclose(fd);

        if (0 == strncmp(buff, "yes", 3)) {
            res = true;
        }
    }

    return res;
}

/**
 * get channel limit start channel
 * @return start channel, 0 on error
 */
int awnd_get_chanlimit_chan(const char *uci_path)
{
    FILE *fd;
    int len = 0;
    char buff[CHANLIMIT_CHANNEL_NUM_LEN + 1] = {0};
    char cmd[128] = {0};
    int res_chan = 0;

    if (!uci_path)
    {
        return 0;
    }

    sprintf(cmd, "uci -c /etc/profile.d get %s", uci_path);
    fd = popen(cmd, "r");
    if (NULL == fd)
    {
        return 0;
    }
    else
    {
        len = fread(buff, sizeof(char), CHANLIMIT_CHANNEL_NUM_LEN + 1, fd);
        pclose(fd);
        if (len > 0 ) 
        {
            res_chan = atoi(buff);
        }
        else
        {
            res_chan = 0;
        }
        
    }
    return res_chan;
}

void awnd_get_outdoor_channellimit(char* channellimit)
{
    FILE *fd;
    int len;
    char info[CHANNELLIMIT_LEN + 1] = {0};
    char cmd[128] = {0};

    if (!channellimit)
    {
        return;
    }

    sprintf(cmd, "echo $(uci get band_limit.outdoor.channellimit) | tr -d \"\\n\"");
    fd	= popen(cmd, "r");
    if (NULL == fd)
    {
        strcpy(channellimit, "0");
    }
    else
    {
        len = fread(info, sizeof(char), CHANNELLIMIT_LEN + 1, fd);
        pclose(fd);

        if((info[0] != '\n') && (info[0] != '\0'))
        {
            strncpy(channellimit, info, CHANNELLIMIT_LEN + 1);
        } else {
            strncpy(channellimit, "0", CHANNELLIMIT_LEN + 1);
        }
        channellimit[CHANNELLIMIT_LEN] = '\0';
    }
}
#endif

