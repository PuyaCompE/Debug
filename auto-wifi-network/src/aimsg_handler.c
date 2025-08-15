/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : aimsg_handler.c
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-05-15
 */
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>

#include <libubox/uloop.h>

#include <aidata.h>
#include <aimsg.h>
#include <dataInterface.h>
#include <dynamicNetwork.h>

#include "awn_log.h"
#include "auto_wifi_net.h"
#include "ai_nwk_defines.h"
#include "ping.h"
#include "aimsg_handler.h"
#include <jsonutl.h>

/* -------------------------------------------------------------------------- */
/*                                   DEFINES                                  */
/* -------------------------------------------------------------------------- */
#define ALG_POINT_FREE(p)                                                                                                                                      \
    do                                                                                                                                                         \
    {                                                                                                                                                          \
        if (p)                                                                                                                                                 \
        {                                                                                                                                                      \
            free(p);                                                                                                                                           \
            p = NULL;                                                                                                                                          \
        }                                                                                                                                                      \
    } while (0)

#define WORK_MODE_FILE_PATH "/tmp/work_mode"

/* -------------------------------------------------------------------------- */
/*                              EXTERN PROTOTYPES                             */
/* -------------------------------------------------------------------------- */
extern UINT8 l_mac_prefer[AWND_MAC_LEN];
extern UINT8 l_mac_ai_roaming_target[AWND_MAC_LEN];

/* -------------------------------------------------------------------------- */
/*                               LOCAL PROTOYTES                              */
/* -------------------------------------------------------------------------- */
static int hex_ctou(char c, uint8_t *u);
static int alg_get_lan_mac(char *mac_str);
static int algrank_to_rankentry(ApRank *aprank, struct aidata_rank_entry_t *rank);
#if 0
static int algpat_to_pat(PatParameter *patpar, struct aidata_pat_info_t *pat);
#else
static int algpat_to_pat(PatParameterV2 *patpar, struct aidata_pat_info_v2_t *pat);
#endif
static int update_alg_time_stamp(char mac_str[ALG_MAC_LENGTH]);
static int delete_offline_re_info(void);
static int save_aidata(struct aimsg_hdr_t *hdr, int len);
static int handle_aimsg_request(struct aimsg_hdr_t *hdr, int len);
static int handle_nwkout_request(struct aidata_network_out_t *out, int len);
static void fap_poll_timeout_cb(struct uloop_timeout *timeout);
static void re_poll_timeout_cb(struct uloop_timeout *timeout);
static void fap_alg_process_timeout_cb(struct uloop_timeout *timeout);

static int alg_get_parent_mac(uint8_t *mac_octet, int len);
static int delete_mac_sep(char *str, int len);
static int handle_sync_devinfo_request();
static bool check_dev_tipc_is_enable(struct json_object* dev);
static bool check_all_re_support_tipc();
static bool check_receive_all_re_message();
static bool awnd_check_devices_support_mesh_opt();
static int algapinfo_to_apinfoentry(ApInfoAllV2 *apInfoAllV2, struct aidata_dev_info_t *apinfo);

/* -------------------------------------------------------------------------- */
/*                                  VARIABLES                                 */
/* -------------------------------------------------------------------------- */
extern AWND_GLOBAL g_awnd;
extern AWND_CONFIG l_awnd_config;

static struct uloop_timeout fap_poll_timeout = {
    .cb = fap_poll_timeout_cb,
};
static struct uloop_timeout re_poll_timeout = {
    .cb = re_poll_timeout_cb,
};
static struct uloop_timeout fap_alg_process_timeout = {
    .cb = fap_alg_process_timeout_cb,
};

static struct _AlgTimeStamp alg_timestamp = {0};
static struct _AlgApUpdateTimeStamp alg_apUpdateTimestamp = {0};

// TODO : Needed to delete
static int NOTICE_CND = 0;

struct alg_re_test_struct {
    char candidateParentMac[ALG_MAC_LENGTH];
    char fapMac[ALG_MAC_LENGTH];
    ALG_STRATEGY alg_re_strategy;
    DN_RE_STATUS_CODE alg_re_status;
    u_int32_t starttime;
};

struct alg_fap_test_struct {
    int re_cnt;
    int finished_cnt;
    int is_in_poll_timeout;
    ALG_STRATEGY alg_fap_strategy;
    char lastApMac[ALG_MAC_LENGTH];
    bool alg_in_processing;
    int relay_num;
    char relay_mac[ALG_MAX_AP_NUM][ALG_MAC_LENGTH];
    u_int32_t starttime;
};

static struct alg_re_test_struct alg_re_test = {0};
static struct alg_fap_test_struct alg_fap_test = {0};

/* -------------------------------------------------------------------------- */
/*                               LOCAL FUNCTIONS                              */
/* -------------------------------------------------------------------------- */
static int delete_mac_sep(char *str, int len)
{
    int i, j;
    for (i = 0, j = 0; (i < len) && (str[i] != '\0'); i++) {
        if (str[i] == '-' || str[i] == ':' ||
            str[i] == '\n' || str[i] == '\r')
            continue;
        else {
            str[j] = str[i];
            j++;
        }
    }
    str[j] = '\0';
    return 0;
}

static int alg_get_parent_mac(uint8_t *mac_octet, int len)
{
    json_object_t *root = NULL;
    json_object_t *param = NULL;
    char parent_mac[18] = {0};
    int ret = -1;

    root = JSON_READ_FROM_FILE(WORK_MODE_FILE_PATH);
    if (!root) {
        AWN_LOG_ERR("Fail to open work_mode file (%s)", WORK_MODE_FILE_PATH);
        return -1;
    }

    param = JSON_GET_OBJECT(root, "parent_mac");
    if (!param) {
        AWN_LOG_ERR("Fail to get work mode.");
        goto exit;
    }

    strncpy(parent_mac, JSON_OBJECT_GET_STRING(param), sizeof(parent_mac));
    delete_mac_sep(parent_mac, sizeof(parent_mac));
    ret = mac_str_to_octet(parent_mac, sizeof(parent_mac),
        mac_octet, len);

exit:
    if (root) {
        JSON_DELETE(root);
    }
    return ret;
}

static int hex_ctou(char c, uint8_t *u)
{
    if (c >= 'a' && c <= 'f') {
        *u = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        *u = c - 'A' + 10;
    } else if (c >= '0' && c <= '9') {
        *u = c - '0';
    } else {
        return -1;
    }
    return 0;
}

static int alg_get_lan_mac(char *mac_str)
{
    extern AWND_CONFIG l_awnd_config; 
    snprintf(mac_str, ALG_MAC_LENGTH, MAC_ADDR_FMT, MAC_ADDR_DATA(l_awnd_config.mac));
    return 0;
}

static int algrank_to_rankentry(ApRank *aprank, struct aidata_rank_entry_t *rank)
{
    mac_str_to_octet(aprank->deviceMAC, sizeof(aprank->deviceMAC),
        rank->device_mac.octet, sizeof(rank->device_mac.octet));
    mac_str_to_octet(aprank->ethFatherMAC, sizeof(aprank->ethFatherMAC),
        rank->eth_father_mac.octet, sizeof(rank->eth_father_mac.octet));
    rank->rank = aprank->apRank;
    return 0;
}

static int algthrrank_to_thrrankentry(ApThrRank *apthrrank, struct aidata_thr_rank_entry_t *thr_rank)
{
    mac_str_to_octet(apthrrank->deviceMAC, sizeof(apthrrank->deviceMAC),
        thr_rank->device_mac.octet, sizeof(thr_rank->device_mac.octet));
    mac_str_to_octet(apthrrank->fatherMAC, sizeof(apthrrank->fatherMAC),
        thr_rank->father_mac.octet, sizeof(thr_rank->father_mac.octet));
    thr_rank->rank = apthrrank->apRank;
    thr_rank->throughput = apthrrank->throughput;
    return 0;
}

// for print STRATEGY string.
#define ENUM_STRATEGY_TYPE_CASE(x)   case x: return(#x);
static inline const char *strategy_enum_type_to_string(ALG_STRATEGY type)
{
    switch (type){
        ENUM_STRATEGY_TYPE_CASE(ALG_STRATEGY_UNKNOW)
        ENUM_STRATEGY_TYPE_CASE(ALG_STRATEGY_CAREFUL)
        ENUM_STRATEGY_TYPE_CASE(ALG_STRATEGY_REDICAL)
        ENUM_STRATEGY_TYPE_CASE(ALG_STRATEGY_GET_BEST)
    }
    return "Unsupported STRATEGY";
}

#if 0
static int algpat_to_pat(PatParameter *patpar, struct aidata_pat_info_t *pat)
{
    int i;
    mac_str_to_octet(patpar->deviceMac, sizeof(patpar->deviceMac),
        pat->device_mac.octet, sizeof(pat->device_mac.octet));
    for (i = 0; i < ALG_TOTAL_MODEL_COUNT; i++) {
        pat->pars[i].b = patpar->bParameter[i];
        pat->pars[i].c = patpar->cParameter[i];
    }
    return 0;
}
#else
static int algpat_to_pat(PatParameterV2 *patpar, struct aidata_pat_info_v2_t *pat)
{
    int i;
    mac_str_to_octet(patpar->deviceMac, sizeof(patpar->deviceMac),
        pat->device_mac.octet, sizeof(pat->device_mac.octet));
    pat->commonPatNum = patpar->commonPatNum;
    for (i = 0; i < ALG_TOTAL_MODEL_COUNT; i++) {
        pat->pars[i].isChanged = patpar->singlePat[i].isChanged;
        pat->pars[i].bandOrder = patpar->singlePat[i].bandOrder;
        pat->pars[i].channelWidthOrder = patpar->singlePat[i].channelWidthOrder;
        pat->pars[i].mcsOrder = patpar->singlePat[i].mcsOrder;
        pat->pars[i].b = patpar->singlePat[i].paraB;
        pat->pars[i].c = patpar->singlePat[i].paraC;
    }
    return 0;
}
#endif



int get_alg_re_status(void)
{
    return alg_re_test.alg_re_status;
}

int set_alg_re_status(int alg_re_status)
{
    alg_re_test.alg_re_status = alg_re_status;
    return 0;
}

int set_alg_done(BOOL alg_status)
{
    alg_fap_test.alg_in_processing = !alg_status;
    return 0;
}

BOOL get_alg_done()
{
    return !alg_fap_test.alg_in_processing;
}

int set_last_mac(char *last_mac)
{
    strncpy(alg_fap_test.lastApMac, last_mac, sizeof(alg_fap_test.lastApMac));
    return 0;
}

char* get_last_mac()
{
    //strncpy(alg_fap_test.lastApMac, last_mac, sizeof(alg_fap_test.lastApMac));
    return alg_fap_test.lastApMac;//(const char *)
}

static int update_alg_time_stamp(char mac_str[ALG_MAC_LENGTH])
{
    uint8_t i = 0;
    uint8_t found = 0;
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    uint32_t time_stamp = tv.tv_sec;
    for (i = 0; i < alg_apUpdateTimestamp.apNum; i++)
    {
        if (strncmp(mac_str, alg_apUpdateTimestamp.apMac[i], ALG_MAC_LENGTH) == 0)
        {
            found = 1;
            break;
        }
    }
    if (found)
    {
        // AWN_LOG_NOTICE("[notice] found mac[%12s]'s timeStamp is %d.", mac_str, time_stamp);
        alg_apUpdateTimestamp.timestamp[i] = time_stamp;
        alg_apUpdateTimestamp.newestTimeStamp = time_stamp;
    }
    else
    {
        AWN_LOG_NOTICE("[notice] cannot found mac[%12s]'s timeStamp is %d.", mac_str, time_stamp);
        strncpy(alg_apUpdateTimestamp.apMac[alg_apUpdateTimestamp.apNum], mac_str, ALG_MAC_LENGTH);
        alg_apUpdateTimestamp.newestTimeStamp = time_stamp;
        alg_apUpdateTimestamp.timestamp[alg_apUpdateTimestamp.apNum] = time_stamp;
        alg_apUpdateTimestamp.apNum++;
    }
    
    return 0;
}

static int delete_offline_re_info(void)
{
    uint8_t i = 0;
    for (i = 0; i < alg_apUpdateTimestamp.apNum; i++)
    {
        if (abs(alg_apUpdateTimestamp.newestTimeStamp - alg_apUpdateTimestamp.timestamp[i]) > ALG_DEFAULT_TIMEOUT)
        {
            AWN_LOG_NOTICE("[notice] re[%12s] is offline, delete its info.", alg_apUpdateTimestamp.apMac[i]);
            deleteSingleApAllInfo(AR_NETWORK_APINFO_FILE, alg_apUpdateTimestamp.apMac[i]);
            alg_apUpdateTimestamp.apNum--;
            strncpy(alg_apUpdateTimestamp.apMac[i], alg_apUpdateTimestamp.apMac[alg_apUpdateTimestamp.apNum], ALG_MAC_LENGTH);
            alg_apUpdateTimestamp.timestamp[i] = alg_apUpdateTimestamp.timestamp[alg_apUpdateTimestamp.apNum];
        }
    }
    return 0;
}

int delete_offline_re_by_mac(const char *mac[], int num)
{
    for (int i = 1; i <= num; i++)
    {
        AWN_LOG_ERR("[notice] re[%12s] is offline, delete its info.", mac[i]);
        deleteSingleApAllInfo(AR_NETWORK_APINFO_FILE, mac[i]);
    }
    return 0;
}


static int save_aidata(struct aimsg_hdr_t *hdr, int len)
{
    int ret = 0;
    switch (hdr->type) {
    case AI_DATA_TYPE_DEVINFO:
        return save_devinfo((struct aidata_dev_info_t *)hdr->payload, hdr->timestamp_s);
        break;

    case AI_DATA_TYPE_PATINFO:
#if 0
        return save_patinfo((struct aidata_pat_info_t *)hdr->payload, hdr->timestamp_s);
#else
        return save_patinfo((struct aidata_pat_info_v2_t *)hdr->payload, hdr->timestamp_s);
#endif
        break;

    case AI_DATA_TYPE_APMODE:
        return save_apmode((struct aidata_ap_mode_t *)hdr->payload, hdr->timestamp_s);
        break;

    case AI_DATA_TYPE_SCANINFO:
        return save_scaninfo((struct aidata_scan_info_t*)hdr->payload, hdr->timestamp_s);
        break;

    case AI_DATA_TYPE_APRANK:
        return save_rankinfo((struct aidata_ap_rank_t *)hdr->payload, hdr->timestamp_s);
        break;

    case AI_DATA_TYPE_APRANK_INDEX:
        ret = save_rankindex((struct aidata_ap_rank_index_t *)hdr->payload, hdr->timestamp_s);
        delete_offline_re_info();
        alg_re_test.alg_re_status = DN_RE_STATUS_BEFORE_ROAMING;
        snprintf(alg_re_test.fapMac, sizeof(alg_re_test.fapMac), MAC_ADDR_FMT, MAC_ADDR_DATA(g_awnd.fapMac));
        update_devinfo();
        AWN_LOG_ERR("rcv APRANK_INDEX");
        ret = re_alg_process();
        return ret;
        break;

    case AI_DATA_TYPE_FIRST_ROAMING:
        return save_dev_and_scaninfo((struct aidata_dev_and_scan_info_t *)hdr->payload, hdr->timestamp_s);

    case AI_DATA_TYPE_ALL_APINFO:
        return save_all_apinfo((struct aidata_ap_info_t *)hdr->payload, hdr->timestamp_s);

    default:
        break;
    }
    return 0;
}

static int handle_aimsg_request(struct aimsg_hdr_t *hdr, int len)
{
    switch (hdr->type) {
    case AI_DATA_TYPE_NWKOUT:
        alg_timestamp.apAlgOut_timestamp = hdr->timestamp_s;
        return handle_nwkout_request(
            (struct aidata_network_out_t *)hdr->payload, hdr->payload_len);

    case AI_DATA_TYPE_FIRST_ROAMING:
        //save_aidata(hdr, len);
        AWN_LOG_ERR("handle first roaming request");
        if (hdr->payload_len > 0)
        {
            ApAlgInterfaceOutput alg_out;
            aidata_nwkout_to_alg_out(((struct aidata_network_out_t *)hdr->payload), &alg_out);
            AWN_LOG_NOTICE("[info] Got first roaming request:%s [%12s->%12s].", strategy_enum_type_to_string(alg_out.algStrategy), alg_out.srcMAC, alg_out.dstMAC);

            //TODO:send devinfo and scaninfo in request, and save them
            //save_aidata(hdr->payload, hdr->payload_len);
            /* update itself devinfo & send update request to RE, then sleep 5s to wait for the newest devinfo */
            int j;
            bool relay_mac_found = false;
            for (j = 0; j < alg_fap_test.relay_num; j++)
            {
                if (alg_fap_test.relay_mac[j] && 0 == strcmp(alg_fap_test.relay_mac[j], alg_out.srcMAC))
                    relay_mac_found = true;
            }
            if (!relay_mac_found && alg_fap_test.relay_num < ALG_MAX_AP_NUM)
            {
                strcpy(alg_fap_test.relay_mac[alg_fap_test.relay_num], alg_out.srcMAC);
                alg_fap_test.relay_num++;
            }
            AWN_LOG_ERR("update relay mac, fap alg processing");
            print_relay_mac();
            if (!alg_fap_test.alg_in_processing)
            {
                handle_sync_devinfo_request();
                send_sync_devinfo_request();
                uloop_timeout_set(&fap_alg_process_timeout, 5 * 1000);
            }
        }
        break;

    case AI_DATA_TYPE_SYNC_DEVINFO:
        AWN_LOG_ERR("handle sync devinfo request");
        handle_sync_devinfo_request();
        break;

    default:
        break;
    }
    return 0;
}

static int handle_nwkout_request(struct aidata_network_out_t *out, int len)
{
    ApAlgInterfaceOutput alg_out;
    aidata_nwkout_to_alg_out(out, &alg_out);
    AWN_LOG_NOTICE("[info] Got:%s [%12s->%12s].", strategy_enum_type_to_string(alg_out.algStrategy), alg_out.srcMAC, alg_out.dstMAC);
    if (g_awnd.workMode == AWND_MODE_FAP || g_awnd.workMode == AWND_MODE_HAP)
    {
        uloop_timeout_cancel(&fap_poll_timeout);
        if (!alg_fap_test.alg_in_processing || (alg_out.srcMAC && 0 != strcmp(alg_fap_test.lastApMac, alg_out.srcMAC)))
        {
            AWN_LOG_NOTICE("rcv re nwkout, but alg not running or not target re");
            return -1;
        }
        fap_alg_process(alg_out.algStrategy, alg_out.srcMAC);
    }

    return 0;
}

static int handle_sync_devinfo_request()
{
    char buf[256] = {0};
    sprintf(buf, "ubus call ai_center.debug update_devinfo >/dev/null");
    system(buf);
    return 0;
}

static void fap_poll_timeout_cb(struct uloop_timeout *timeout)
{
    /* If fap poll timeouts, this function will be executed. */
    /* ALG TODO */
    AWN_LOG_NOTICE("[info] TimeOut, do next fap_alg_process.");
    //alg_fap_test.is_in_poll_timeout = 0;
    fap_alg_process(alg_fap_test.alg_fap_strategy, alg_fap_test.lastApMac);
    return;
}

static void re_poll_timeout_cb(struct uloop_timeout *timeout)
{
    /* If fap poll timeouts, this function will be executed. */
    /* ALG TODO */
    AWN_LOG_NOTICE("[info] TimeOut, change alg_re_status");
    set_alg_re_status(DN_RE_STATUS_BEFORE_ROAMING);
    return;
}

static void fap_alg_process_timeout_cb(struct uloop_timeout *timeout)
{
    if (alg_fap_test.relay_num > 0)
    {
        fap_alg_process(ALG_STRATEGY_GET_BEST, alg_fap_test.relay_mac[0]);
    }
    return;
}

static bool check_dev_tipc_is_enable(struct json_object* dev)
{
   json_object* tipc = NULL; 
   tipc = json_object_object_get(dev, "tipc");
   if(tipc == NULL)
   {
       return false;
   }
   return json_object_get_int(tipc) != 0;
}

#define MESH_DEV_LIST_FILE "/tmp/sync-server/mesh_dev_list"
static bool check_all_re_support_tipc()
{
    json_object *devlist;
    bool ret = true;

    devlist = json_object_from_file(MESH_DEV_LIST_FILE);

    if(devlist == NULL)
    {
        return true;
    }

    json_object_object_foreach(devlist,devid,dev)
    {
        (void) devid;
        if(dev && !check_dev_tipc_is_enable(dev))
        {
            ret = false; 
            break;
        }
    }

    if(devlist)
    {
        json_object_put(devlist);
    }
    return ret;

}

static int awnd_get_re_tipc_status(int *tipc_status_list, int *num)
{
    FILE* fp  = NULL;
    char line[256] = {0};
    int cluster, zone, node;
    char status_str[4] = {0};
    int status = 0;
    int idx = 0;

    fp = popen("tipc-config -n | grep up", "r");
    if (NULL == fp)
    {   
        printf("popen faild. (%d, %s)\n",errno, strerror(errno));
        return -1; 
    }   

    while (fgets(line, 256, fp) != NULL)
    {
        sscanf(line, "<%d.%d.%d>: %s", &cluster, &zone, &node, &status_str);
        AWN_LOG_NOTICE("get tipc cluster:%d, zone:%d, node :%d status:%s", cluster, zone, node, status_str);
        *((int *)tipc_status_list + idx) = node;
        *num = *num + 1;
        idx++;
    }
    pclose(fp);

    return 0;
}

static bool check_receive_all_re_message()
{
    int tipc_num = 0;
    int i, j;
    int linkup_num = 0;
    int tipc_status_list[ALG_MAX_AP_NUM] = {0};
    bool ret = false;
    int num = dataLineCounter(AR_NETWORK_APINFO_FILE);
    
    char lan_mac[ALG_MAC_LENGTH] = "";
    alg_get_lan_mac(lan_mac);

    /* 1.to get RE tipc status  */
    if (awnd_get_re_tipc_status(tipc_status_list, &tipc_num) < 0)
    {
        AWN_LOG_ERR("Failed to get tipc status");
        return false;
    }

    ApInfoAllV2 *pApInfoAll = (ApInfoAllV2 *)calloc(num, sizeof(ApInfoAllV2));

    if (false == apAllInfoReader(AR_NETWORK_APINFO_FILE, pApInfoAll, num, NULL))
    {
        AWN_LOG_ERR("Failed to read data file[%s]", AR_NETWORK_APINFO_FILE);
        return false;
    }

    for (i = 0; i < num; i++)
    {
        bool found = false;
        for (j = 0; j < tipc_num; j++)
        {
            if (pApInfoAll[i].apNodeV2.tipc_node == tipc_status_list[j])
            {
                found = true;
                linkup_num++;
                break;
            }
        }
        if (!found && strncmp(lan_mac, pApInfoAll[i].apNodeV2.deviceMAC, ALG_MAC_LENGTH))
        {
            AWN_LOG_ERR("tipc node [%d] not found in tipc_up_list.Delete entry[%s] in file %s",
                pApInfoAll[i].apNodeV2.tipc_node, pApInfoAll[i].apNodeV2.deviceMAC, AR_NETWORK_APINFO_FILE);
            deleteSingleApAllInfo(AR_NETWORK_APINFO_FILE, pApInfoAll[i].apNodeV2.deviceMAC);
        }
    }
    AWN_LOG_NOTICE("tipc num:[%d], receive msg:[%d]", tipc_num ,linkup_num);
    if (linkup_num == tipc_num)
    {
        ret = true;
    }
    ALG_POINT_FREE(pApInfoAll);
    return ret;
}

static bool awnd_check_devices_support_mesh_opt()
{
    return check_all_re_support_tipc() && check_receive_all_re_message();
}

static int algapinfo_to_apinfoentry(ApInfoAllV2 *apInfoAllV2, struct aidata_dev_info_t *apinfo)
{
    int band;
    mac_str_to_octet(apInfoAllV2->apNodeV2.deviceMAC, sizeof(apInfoAllV2->apNodeV2.deviceMAC), 
        apinfo->device_mac.octet, sizeof(apinfo->device_mac.octet));
    mac_str_to_octet(apInfoAllV2->apNodeV2.fatherDeviceMAC, sizeof(apInfoAllV2->apNodeV2.fatherDeviceMAC),
        apinfo->parent_mac.octet, sizeof(apinfo->parent_mac.octet));
    apinfo->tipc_node = apInfoAllV2->apNodeV2.tipc_node;
    for(band = 0; band < AI_DATA_WL_BAND_MAX; band++)
    {
        apinfo->link[band].rxrate = apInfoAllV2->apNodeV2.wirelessRxRate[band];
        apinfo->link[band].txrate = apInfoAllV2->apNodeV2.wirelessTxRate[band];
        apinfo->link[band].util = apInfoAllV2->apNodeV2.wirelessChannelUtilization[band];
        apinfo->mode[band].backhaul_available = apInfoAllV2->algWifiMode[band].available;
        apinfo->mode[band].num_streams = apInfoAllV2->algWifiMode[band].NSS;
        apinfo->mode[band].wifi_mode = apInfoAllV2->algWifiMode[band].wifiMode;
        apinfo->mode[band].band_width = apInfoAllV2->algWifiMode[band].bandWidth;
        apinfo->mode[band].mcs_level = apInfoAllV2->algWifiMode[band].mcsLevel;
        apinfo->mode[band].channel = apInfoAllV2->algWifiMode[band].channel;
        apinfo->mode[band].reserved = apInfoAllV2->algWifiMode[band].reserved;
    }
    apinfo->link[AI_DATA_BAND_ETH].util = apInfoAllV2->apNodeV2.ethernetUtilization;
    apinfo->link[AI_DATA_BAND_ETH].rxrate = apInfoAllV2->apNodeV2.ethernetRate;
    apinfo->link[AI_DATA_BAND_PLC].util = apInfoAllV2->apNodeV2.plcUtilization;
    apinfo->link[AI_DATA_BAND_PLC].rxrate = apInfoAllV2->apNodeV2.plcRate;
    return 0;
}


/* -------------------------------------------------------------------------- */
/*                              PUBLIC FUNCTIONS                              */
/* -------------------------------------------------------------------------- */

int mac_str_to_octet(const char *str, int str_len,
    uint8_t *octet, int octet_len)
{
    int i;
    uint8_t high = 0;
    uint8_t low = 0;
    if (!str || str_len < 13 ||
        !octet || octet_len < 6) {
        AWN_LOG_ERR("Invalid input parameter(s). "
            "octet: %p, octet_len: %d, "
            "str: %p, str_len: %d",
            octet, octet_len, str, str_len);
        return -1;
    }

    for (i = 0; i < 6; i++) {
        if (hex_ctou(str[2*i], &high) < 0 ||
            hex_ctou(str[2*i + 1], &low) < 0) {
            AWN_LOG_ERR("Invalid mac str(%12s).", str);
            return -1;
        }
        octet[i] = (high << 4) + low;
    }
    return 0;
}

void update_devinfo(void)
{
    struct aimsg_hdr_t hdr = {0};
    struct timeval tv;

    gettimeofday(&tv, NULL);
    hdr.magic = AI_MSG_MAGIC_NUMBER;
    hdr.op = AI_MSG_OP_UPDATE;
    hdr.type = AI_DATA_TYPE_DEVINFO;
    hdr.version = AI_DATA_VERSION_V1;
    hdr.payload_len = 0;
    hdr.timestamp_s = tv.tv_sec;

    aimsg_send(AI_MSG_MODULE_CENTER, &hdr, sizeof(hdr));
    return;
}

int handle_aimsg(void *data, int len, AWND_MODE_TYPE mode)
{
    struct aimsg_hdr_t *hdr;
    
    assert(data != NULL);
    hdr = (struct aimsg_hdr_t *)data;
    if(hdr->type != AI_DATA_TYPE_DEVINFO && hdr->type != AI_DATA_TYPE_SCANINFO){
        AWN_LOG_ERR("begin op[%d] type[%d]", hdr->op, hdr->type);
    }
    switch(hdr->op) {
    case AI_MSG_OP_SYNC:
    case AI_MSG_OP_REPORT:
        return save_aidata(hdr, len);
    case AI_MSG_OP_REQUEST:
        return handle_aimsg_request(hdr, len);
    default:
        break;
    }
    return 0;
}

int send_sync_devinfo_request()
{
    uint8_t *buf;
    struct aimsg_hdr_t *hdr;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t);

    buf = (uint8_t *)calloc(1, len);
    if (!buf){
        AWN_LOG_ERR("Fail to allocate memmory for sync devinfo request.");
        return -1;
    }
    gettimeofday(&tv, NULL);

    hdr = (struct aimsg_hdr_t *)buf;
    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_REQUEST;
    hdr->type = AI_DATA_TYPE_SYNC_DEVINFO;
    hdr->version = AI_DATA_VERSION_V1;
    hdr->src_module = AI_MSG_MODULE_NETWORKING;
    hdr->payload_len = 0;
    hdr->timestamp_s = tv.tv_sec;

    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    AWN_LOG_ERR("send sync devinfo request to collect info");
    free(buf);
    return 0;
}

int send_nwkout(ApAlgInterfaceOutput *out)
{
    uint8_t *buf;
    struct aimsg_hdr_t *hdr;
    struct aidata_network_out_t *req;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_network_out_t);

    buf = (uint8_t *)calloc(1, len);
    if (!buf) {
        AWN_LOG_ERR("Fail to allocate memory for reroam request.");
        return -1;
    }
    gettimeofday(&tv, NULL);

    hdr = (struct aimsg_hdr_t *)buf;
    req = (struct aidata_network_out_t *)hdr->payload;
    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_REQUEST;
    hdr->type = AI_DATA_TYPE_NWKOUT;
    hdr->version = 1;
    hdr->src_module = AI_MSG_MODULE_NETWORKING;
    hdr->payload_len = sizeof(struct aidata_network_out_t);
    hdr->timestamp_s = tv.tv_sec;
    mac_str_to_octet(out->srcMAC, sizeof(out->srcMAC),
        req->src_mac.octet, sizeof(req->src_mac.octet));
    mac_str_to_octet(out->dstMAC, sizeof(out->dstMAC),
        req->dst_mac.octet, sizeof(req->dst_mac.octet));
    req->alg_strategy = out->algStrategy;
    req->timeout_sec = out->timeout;

    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    free(buf);

    return 0;
}

int send_rank(ApRank *aprank, uint8_t num)
{
    uint8_t *buf;
    int i;
    struct aimsg_hdr_t *hdr;
    struct aidata_ap_rank_t *rank;
    struct aidata_rank_entry_t *entry;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_ap_rank_t) +
        sizeof(struct aidata_rank_entry_t) * num;
    buf = calloc(1, len);
    if (!buf) {
        AWN_LOG_ERR("Fail to allocate memory.");
        return -1;
    }

    hdr = (struct aimsg_hdr_t *)buf;
    rank = (struct aidata_ap_rank_t *)hdr->payload;
    gettimeofday(&tv, NULL);

    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_SYNC;
    hdr->type = AI_DATA_TYPE_APRANK;
    hdr->version = AI_DATA_VERSION_V1;
    hdr->payload_len = sizeof(struct aidata_ap_rank_t)
        + sizeof (struct aidata_rank_entry_t) * num;
    hdr->timestamp_s = tv.tv_sec;
    rank->num = num;
    for (i = 0; i < num; i++) {
        entry = &rank->rank_list[i];
        algrank_to_rankentry(&aprank[i], entry);
    }
    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    free(buf);
    return 0;
}

int send_rank_index(ApRankIndex *aprank_index)
{
    uint8_t *buf;
    int i;
    struct aimsg_hdr_t *hdr;
    struct aidata_ap_rank_index_t *rank;
    struct aidata_thr_rank_entry_t *entry;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_ap_rank_index_t) +
        sizeof(struct aidata_thr_rank_entry_t) * aprank_index->cnt;
    buf = calloc(1, len);
    if (!buf) {
        AWN_LOG_ERR("Fail to allocate memory.");
        return -1;
    }

    hdr = (struct aimsg_hdr_t *)buf;
    rank = (struct aidata_ap_rank_index_t *)hdr->payload;
    gettimeofday(&tv, NULL);

    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_SYNC;
    hdr->type = AI_DATA_TYPE_APRANK_INDEX;
    hdr->version = AI_DATA_VERSION_V1;
    hdr->payload_len = sizeof(struct aidata_ap_rank_index_t)
        + sizeof (struct aidata_thr_rank_entry_t) * aprank_index->cnt;
    hdr->timestamp_s = tv.tv_sec;
    rank->num = aprank_index->cnt;
	rank->process_re = aprank_index->process_re;
    rank->alg_strategy = aprank_index->alg_strategy;
    rank->starttime = aprank_index->starttime;
    for (i = 0; i < aprank_index->cnt; i++) {
        entry = &rank->rank_list[i];
        algthrrank_to_thrrankentry(&(aprank_index->apRank[i]), entry);
    }
    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    free(buf);
    return 0;
}

#if 0
static void patinfoDisplay(PatParameter *pPatParameter, int apPatNum)
{
    int i;

    AWN_LOG_NOTICE("begin apPatNum[%d]", apPatNum);
    for (i = 0; i < apPatNum; i++)
    {
        PatParameter *p = &(pPatParameter[i]);
        AWN_LOG_NOTICE("PatParameter[%d] MAC[%s]", i, p->deviceMac);
        uint16_t *a = p->bParameter;
        AWN_LOG_NOTICE("bParameter");
        AWN_LOG_NOTICE("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u ", 
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], 
            a[12], a[13], a[14], a[15], a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23], 
            a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31], a[32], a[33], a[34], a[35], 
            a[36], a[37], a[38], a[39], a[40], a[41], a[42], a[43], a[44], a[45], a[46], a[47]);
        a = p->cParameter;
        AWN_LOG_NOTICE("cParameter");
        AWN_LOG_NOTICE("%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u ", 
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], 
            a[12], a[13], a[14], a[15], a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23], 
            a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31], a[32], a[33], a[34], a[35], 
            a[36], a[37], a[38], a[39], a[40], a[41], a[42], a[43], a[44], a[45], a[46], a[47]);
    }
    return;
}
#endif

#if 0
int send_patinfo(PatParameter *patpar)
#else
int send_patinfo(PatParameterV2 *patpar)
#endif
{
    uint8_t *buf;
    struct aimsg_hdr_t *hdr;
#if 0
    struct aidata_pat_info_t *pat;
#else
    struct aidata_pat_info_v2_t *pat;
#endif
    struct timeval tv;
#if 0
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_pat_info_t);
#else
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_pat_info_v2_t);
#endif
    buf = calloc(1, len);
    if (!buf) {
        AWN_LOG_ERR("Fail to allocate memory.");
        return -1;
    }

    hdr = (struct aimsg_hdr_t *)buf;
#if 0
    pat = (struct aidata_pat_info_t *)hdr->payload;
#else
    pat = (struct aidata_pat_info_v2_t *)hdr->payload;
#endif
    gettimeofday(&tv, NULL);

    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_SYNC;
    hdr->src_module = AI_MSG_MODULE_NETWORKING;
    hdr->type = AI_DATA_TYPE_PATINFO;
    hdr->version = AI_DATA_VERSION_V1;
#if 0
    hdr->payload_len = sizeof(struct aidata_pat_info_t);
#else
    hdr->payload_len = sizeof(struct aidata_pat_info_v2_t);
#endif
    hdr->timestamp_s = tv.tv_sec;
    // patinfoDisplay(patpar, 1);
    algpat_to_pat(patpar, pat);

    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    free(buf);
    return 0;
}

int send_first_roaming_request(void)//maybe send devinfo & scan_info in future?
{
    ApAlgInterfaceOutput out = {0};
    alg_get_lan_mac(out.srcMAC);
    //strncpy(out.dstMAC, alg_re_test.fapMac, ALG_MAC_LENGTH);
    out.algStrategy = alg_re_test.alg_re_strategy;
    uint8_t *buf;
    struct aimsg_hdr_t *hdr;
    struct aidata_network_out_t *req;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_network_out_t);

    buf = (uint8_t *)calloc(1, len);
    if (!buf) {
        AWN_LOG_ERR("Fail to allocate memory for reroam request.");
        return -1;
    }
    gettimeofday(&tv, NULL);

    hdr = (struct aimsg_hdr_t *)buf;
    req = (struct aidata_network_out_t *)hdr->payload;
    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_REQUEST;
    hdr->type = AI_DATA_TYPE_FIRST_ROAMING;
    hdr->version = 1;
    hdr->src_module = AI_MSG_MODULE_NETWORKING;
    hdr->payload_len = sizeof(struct aidata_network_out_t);
    hdr->timestamp_s = tv.tv_sec;
    mac_str_to_octet(out.srcMAC, sizeof(out.srcMAC),
        req->src_mac.octet, sizeof(req->src_mac.octet));
    //mac_str_to_octet(out.dstMAC, sizeof(out.dstMAC),
    //    req->dst_mac.octet, sizeof(req->dst_mac.octet));
    req->alg_strategy = out.algStrategy;
    req->timeout_sec = out.timeout;

    int res = aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    AWN_LOG_ERR("first roaming request done:%d", res);
    return 0;
}

int send_all_apinfo(ApInfoAllV2 *apInfoAllV2, uint8_t num)
{
    uint8_t *buf;
    int i;
    struct aimsg_hdr_t *hdr;
    struct aidata_ap_info_t *info;
    struct aidata_dev_info_t *entry;
    struct timeval tv;
    int len = sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_ap_info_t) +
        sizeof(struct aidata_dev_info_t) * num;
    buf = calloc(1, len);
    if (!buf){
        AWN_LOG_ERR("Fail to allocate memory");
        return -1;
    }

    hdr = (struct aimsg_hdr_t *)buf;
    info = (struct aidata_ap_info_t*)hdr->payload;

    gettimeofday(&tv, NULL);

    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_SYNC;
    hdr->type = AI_DATA_TYPE_ALL_APINFO;
    hdr->version = AI_DATA_VERSION_V1;
    hdr->payload_len = sizeof(struct aidata_ap_info_t) +
        sizeof(struct aidata_dev_info_t) * num;
    hdr->timestamp_s = tv.tv_sec;
    info->num = num;
    for (i = 0; i < num; i++){
        entry = &info->info_list[i];
        algapinfo_to_apinfoentry(&apInfoAllV2[i], entry);
    }
    aimsg_send(AI_MSG_MODULE_CENTER, buf, len);
    free(buf);
    return 0;
}

int save_devinfo(struct aidata_dev_info_t *devinfo, uint32_t time_stamp)
{
    ApInfoAllV2 apinfoV2 = {0};
    BridgingNodeV2 brnodeV2 = {0};
    AWN_LOG_DEBUG("devinfo: devmac(" MAC_ADDR_FMT
        ") parentmac(" MAC_ADDR_FMT ").",
        MAC_ADDR_DATA(devinfo->device_mac.octet),
        MAC_ADDR_DATA(devinfo->parent_mac.octet));
    aidata_devinfo_to_alg_apinfoall(devinfo, &apinfoV2);
    aidata_devinfo_to_alg_bridgeinfo(devinfo, &brnodeV2);
    /* save to file */
    AWN_LOG_DEBUG("[Info(%d)] AP info got, [%12s->%12s].", NOTICE_CND++, apinfoV2.apNodeV2.deviceMAC, apinfoV2.apNodeV2.fatherDeviceMAC);
    updataSingleApAllInfo(AR_NETWORK_APINFO_FILE, &apinfoV2);
    update_alg_time_stamp(apinfoV2.apNodeV2.deviceMAC);
    alg_timestamp.ap_timestamp = time_stamp;

    bool isFap = false;
    if (g_awnd.workMode == AWND_MODE_FAP || g_awnd.workMode == AWND_MODE_HAP)
    {
        isFap = true;
    }
    else
    {
        char mac_str[ALG_MAC_LENGTH] = "";
        alg_get_lan_mac(mac_str);
        // AWN_LOG_NOTICE("Now let's judge the mac address. brnode.deviceMAC = %12s, lan_mac = %12s.", brnode.deviceMAC, mac_str);
        // for RE, only itself bridging info needed saved.
        if (strncmp(brnodeV2.deviceMAC, mac_str, ALG_MAC_LENGTH) != 0)
        {
            return 0;
        }
    }
    // AWN_LOG_NOTICE("[Info(%d)] Bridging info got, Now saving it.", NOTICE_CND);
    if (strncmp(brnodeV2.fatherDeviceMAC, EMPTY_ADDR, ALG_MAC_LENGTH) != 0)
    {
        updateSingleBridgingInfo(AR_BRIDGING_INFO_FILE, &brnodeV2, isFap);
        alg_timestamp.bridging_timestamp = time_stamp;
    }
    return 0;
}

int save_scaninfo(struct aidata_scan_info_t *scaninfo, uint32_t time_stamp)
{
    int i;
    ScanningInfo *entry = (ScanningInfo *)calloc(scaninfo->num_scan, sizeof(ScanningInfo));
    for (i = 0; i < scaninfo->num_scan; i++)
    {
        snprintf(entry[i].deviceMAC, sizeof(entry[i].deviceMAC), MAC_ADDR_FMT,
               MAC_ADDR_DATA(scaninfo->device_mac.octet));
        snprintf(entry[i].neighbourMAC, sizeof(entry[i].neighbourMAC),
               MAC_ADDR_FMT,
               MAC_ADDR_DATA(scaninfo->scan_list[i].neighbor_mac.octet));
        entry[i].band = scaninfo->scan_list[i].band;
        entry[i].channel = scaninfo->scan_list[i].channel;
        entry[i].rssi = scaninfo->scan_list[i].rssi;
        // AWN_LOG_NOTICE(
        //     "Scanning info[%d/%d]: devmac(%12s) parentmac(%12s) rssi(%d).", i,
        //     scaninfo->num_scan, entry[i].deviceMAC, entry[i].neighbourMAC,
        //     entry[i].rssi);
    }
    /* save to file */
    // AWN_LOG_NOTICE("[Info(%d)] Scanning info got, Now saving it.", NOTICE_CND++);
    scanningInfoDeleter(AR_SCANNING_INFO_FILE, entry[0].deviceMAC);
    appendScanningInfo(AR_SCANNING_INFO_FILE, entry, scaninfo->num_scan);
    alg_timestamp.scanning_timestamp = time_stamp;
    return 0;
}

int save_dev_and_scaninfo(struct aidata_dev_and_scan_info_t *dev_and_scan_info, uint32_t time_stamp)
{
    int result = 0;
    result = save_devinfo(&dev_and_scan_info->dev_info, time_stamp);
    if (0 == result)
    {
        result = save_scaninfo(&dev_and_scan_info->scan_info, time_stamp);
    }
    return result;
}

int save_all_apinfo(struct aidata_ap_info_t *apinfo, uint32_t time_stamp)
{
    int i;
    /* Delete origin file /tmp/dynamicNetworking/apInfo.txt before saving all apinfo*/
    char buf[256] = {0};
    sprintf(buf, "rm -rf %s", AR_NETWORK_APINFO_FILE);
    system(buf);

    for (i = 0; i < apinfo->num; i++)
    {
        save_devinfo(&apinfo->info_list[i], time_stamp);
    }
    return 0;
}

int save_rankinfo(struct aidata_ap_rank_t *rank, uint32_t time_stamp)
{
    ApRank *pApRank = (ApRank *)calloc(rank->num, sizeof(ApRank));
    int i;
    for (i = 0; i < rank->num; i++) {
        aidata_rankentry_to_alg_aprank(&rank->rank_list[i], &pApRank[i]);
    }
    apRankInfoWriter(AR_AP_RANK_INFO_FILE, pApRank, rank->num);
    alg_timestamp.rank_timestamp = time_stamp;
    ALG_POINT_FREE(pApRank);
    return 0;
}

int save_rankindex(struct aidata_ap_rank_index_t *rank_index, uint32_t time_stamp)
{
    ApRankIndex *pApRankIndex = (ApRankIndex *)calloc(1, sizeof(ApRankIndex));
    int i;
	pApRankIndex->cnt = rank_index->num;
	pApRankIndex->process_re = rank_index->process_re;
    pApRankIndex->alg_strategy = rank_index->alg_strategy;
    pApRankIndex->starttime = rank_index->starttime;
    for (i = 0; i < rank_index->num; i++) {
        aidata_thrrankentry_to_alg_aprankindex(&rank_index->rank_list[i], &(pApRankIndex->apRank[i]));
    }
    apRankIndexInfoWriter(AR_AP_RANK_INDEX_INFO_FILE, pApRankIndex);
    alg_timestamp.rank_timestamp = time_stamp;
    ALG_POINT_FREE(pApRankIndex);
    return 0;
}

#if 0
int save_patinfo(struct aidata_pat_info_t *pat, uint32_t time_stamp)
{
    PatParameter patinfo;
    aidata_patinfo_to_alg_patinfo(pat, &patinfo);
    /* save to file */
    updateSinglePat(AR_NETWOKING_PATINFORATE_FILE, &patinfo);
    alg_timestamp.pat_timestamp = time_stamp;
    return 0;
}
#else
int save_patinfo(struct aidata_pat_info_v2_t *pat, uint32_t time_stamp)
{
    PatParameterV2 patinfo;
    aidata_patinfo_to_alg_patinfo(pat, &patinfo);
    /* save to file */
    updateSinglePatV2(AR_NETWOKING_PATINFORATE_FILE, &patinfo);
    alg_timestamp.pat_timestamp = time_stamp;
    return 0;
}
#endif

int save_apmode(struct aidata_ap_mode_t *mode, uint32_t time_stamp)
{
    /* save in devinfo, return 0 directly. */
    return 0;

}

int ai_debug_print()
{
	AWN_LOG_ERR("begin");
}

void clear_relay_mac()
{
    memset(alg_fap_test.relay_mac, 0, sizeof(alg_fap_test.relay_mac));
    alg_fap_test.relay_num = 0;
}

void print_relay_mac()
{
    int i = 0;
    AWN_LOG_ERR("now have %d devs relay", alg_fap_test.relay_num);
    for (i = 0; i < alg_fap_test.relay_num; i++)
    {
        AWN_LOG_ERR("dev %d mac:%s", i + 1, alg_fap_test.relay_mac[i]);
    } 
}

void fap_alg_fin_trigger()
{
    alg_fap_test.alg_in_processing = false;
    strcpy(alg_fap_test.lastApMac, EMPTY_ADDR);
    clear_relay_mac();
}

int fap_alg_process(int alg_strategy, char *mac)
{
    int last_index = 0;
    int cur_index = 0;
    int relay_index = 0;
    int next_index = 0;
    int i, j;
    bool relay_mac_found = false;
	AWN_LOG_ERR("fap_alg_process begin");

    if (alg_fap_test.alg_in_processing && (mac && 0 != strcmp(alg_fap_test.lastApMac, mac)))
    {
        for (j = 0; j < alg_fap_test.relay_num; j++)
        {
            if (alg_fap_test.relay_mac[j] && 0 == strcmp(alg_fap_test.relay_mac[j], mac))
                relay_mac_found = true;
        }
        if (!relay_mac_found && alg_fap_test.relay_num < ALG_MAX_AP_NUM)
        {
            strcpy(alg_fap_test.relay_mac[alg_fap_test.relay_num], mac);
            alg_fap_test.relay_num++;
        }
        AWN_LOG_ERR("update relay mac, fap alg processing");
        print_relay_mac();
        return 0;
    }

    delete_offline_re_info();
    /* To check if all device support mesh opt */
    if (!awnd_check_devices_support_mesh_opt())
    {
        AWN_LOG_ERR("Some Device not support mesh opt !!! Do nothing!");
        return 0;
    }

    alg_fap_test.alg_fap_strategy = alg_strategy;
    // ------------------------ Step1 : Sort AP. ------------------------//
    int num = dataLineCounter(AR_NETWORK_APINFO_FILE);
    ApRankIndex *pApRankIndex = (ApRankIndex *)calloc(1, sizeof(ApRankIndex));
    getReRank(AR_NETWORK_APINFO_FILE, pApRankIndex, alg_strategy);

    // ------------------------ Step2 : Updata PAT parameters. ------------------------//
    // updateApPatParameters(AR_NETWORK_APINFO_FILE, AR_BRIDGING_INFO_FILE, AR_NETWOKING_PATINFORATE_FILE);
    // PatParameterV2 entry = {0};
    // patParameterReaderV2(AR_NETWOKING_PATINFORATE_FILE, 1, &entry);
    ApInfoAllV2 *pApInfoAll = (ApInfoAllV2 *)calloc(num, sizeof(ApInfoAllV2));
    if (false == apAllInfoOnlyReader(AR_NETWORK_APINFO_FILE, pApInfoAll, num, NULL))
    {
        AWN_LOG_ERR("Failed to read data file[%s]", AR_NETWORK_APINFO_FILE);
        return 0;
    }

    // ------------------------ Step3 : Decide sendRankIndex. ------------------------//
    for (i = 0; i < num; i++)
    {
        if (0 != strcmp(pApRankIndex->apRank[i].fatherMAC, EMPTY_ADDR))
        {
            if (relay_index == 0)
            {
                for (j = 0; j < alg_fap_test.relay_num; j++)
                {
                    if (alg_fap_test.relay_mac[j] && 0 == strcmp(pApRankIndex->apRank[i].deviceMAC, alg_fap_test.relay_mac[j]))
                        relay_index = i;
                }
            }
            if (alg_fap_test.lastApMac && 0 == strcmp(pApRankIndex->apRank[i].deviceMAC, alg_fap_test.lastApMac))
                last_index = i;
            if (mac && 0 == strcmp(pApRankIndex->apRank[i].deviceMAC, mac))
                cur_index = i;
        }
    }

    AWN_LOG_ERR("cur_index %d last_index %d relay_index %d next_index %d", cur_index, last_index, relay_index, next_index);
    if (cur_index > 0)
    {
        if (last_index == 0)
            next_index = cur_index;
        else if (last_index == cur_index)
        {
            if (relay_index == 0 || cur_index + 1 < relay_index)
            {
                AWN_LOG_ERR("select next, continue processing");
                pApRankIndex->starttime = alg_fap_test.starttime;
                next_index = cur_index + 1;
            }
            else
            {
                AWN_LOG_ERR("select relay, new processing");
                next_index = relay_index;
            }
        }
        else
        {
            next_index = 0;
        }

        if (next_index == 0)
        {
            AWN_LOG_ERR("wait for last re %s, fap alg processing", alg_fap_test.lastApMac);
        }
        else if (next_index < num)
        {
            if (!alg_fap_test.alg_in_processing)
            {
                AWN_LOG_ERR("start new alg from %s, fap alg processing", pApRankIndex->apRank[next_index].deviceMAC);
                alg_fap_test.alg_in_processing = true;
            }
            alg_fap_test.starttime = pApRankIndex->starttime;
            pApRankIndex->process_re = next_index;
            strcpy(alg_fap_test.lastApMac, pApRankIndex->apRank[pApRankIndex->process_re].deviceMAC);
            // AWN_LOG_ERR("send_patinfo, fap alg processing", next_index);
            // send_patinfo(&entry);
            // _stable_sleep(1);
            send_all_apinfo(pApInfoAll, num);
            _stable_sleep(1);
            send_rank_index(pApRankIndex);
            clear_relay_mac();
            AWN_LOG_ERR("next re %d, fap alg processing", next_index);
            uloop_timeout_set(&fap_poll_timeout, 22000);
        }
        else
        {
            pApRankIndex->process_re = num - 1;
            fap_alg_fin_trigger();
            AWN_LOG_ERR("final re, fap alg finished");
        }
    }
    else
    {
        pApRankIndex->process_re = num - 1;
        fap_alg_fin_trigger();
        AWN_LOG_ERR("input re not found, fap alg finished");
    }

    apRankIndexInfoWriter(AR_AP_RANK_INDEX_INFO_FILE, pApRankIndex);

    ALG_POINT_FREE(pApRankIndex);
    ALG_POINT_FREE(pApInfoAll);

    return 0;
}


void re_alg_fin_trigger(void)
{
    alg_re_test.alg_re_status = DN_RE_STATUS_BEFORE_ROAMING;
    ApAlgInterfaceOutput out = {0};
    alg_get_lan_mac(out.srcMAC);
    strncpy(out.dstMAC, alg_re_test.fapMac, ALG_MAC_LENGTH);
    out.algStrategy = alg_re_test.alg_re_strategy;
    update_devinfo();
    _stable_sleep(1);
    send_nwkout(&out);
    AWN_LOG_ERR("[info] reply nwkout:%s, [%12s->%12s]",
                    strategy_enum_type_to_string(out.algStrategy),
                    out.srcMAC, out.dstMAC);
}

int re_alg_process(void)
{
    char lan_mac[ALG_MAC_LENGTH] = {0};
    bool do_process = false;
    int apNum = 0;

    apNum = dataLineCounter(AR_NETWORK_APINFO_FILE);
    ApRankIndex *pApRankIndex = (ApRankIndex *)calloc(1, sizeof(ApRankIndex));
    alg_get_lan_mac(lan_mac);
    apRankIndexInfoReader(AR_AP_RANK_INDEX_INFO_FILE, pApRankIndex);

    if (pApRankIndex)
    {
        if (0 == strcmp(pApRankIndex->apRank[pApRankIndex->process_re].deviceMAC, lan_mac))
        {
            do_process = true;
        }
    }

    if (!do_process)
    {
        AWN_LOG_ERR("another re, do nothing");
        return 0;
    }

    AWN_LOG_ERR("re_alg_process begin");
    /*  get parent mac: compare with prefer mac */
    char parent_mac_str[ALG_MAC_LENGTH] = "";
    uint8_t parent_mac_octet[AWND_MAC_LEN] = "";

    alg_get_parent_mac(parent_mac_octet, sizeof(parent_mac_octet));
    AWN_LOG_NOTICE("get parent mac:%02X:%02X:%02X:%02X:%02X:%02X", parent_mac_octet[0], parent_mac_octet[1],
        parent_mac_octet[2], parent_mac_octet[3], parent_mac_octet[4], parent_mac_octet[5]);
    alg_re_test.alg_re_strategy = pApRankIndex->alg_strategy;
    if (0 == memcmp(l_mac_prefer, parent_mac_octet, sizeof(parent_mac_octet)))
    {
        AWN_LOG_NOTICE("No need to mesh opt!! Now RE connect to the prefer AP(%02X:%02X:%02X:%02X:%02X:%02X)",
            l_mac_prefer[0], l_mac_prefer[1], l_mac_prefer[2], l_mac_prefer[3], l_mac_prefer[4], l_mac_prefer[5]);
        alg_re_test.alg_re_status = DN_RE_STATUS_AFTER_ROAMING;
    }

    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus)
    {
        AWN_LOG_ERR("No need to mesh opt!! Now RE connect to (%02X:%02X:%02X:%02X:%02X:%02X) by ETH", parent_mac_octet[0], parent_mac_octet[1],
            parent_mac_octet[2], parent_mac_octet[3], parent_mac_octet[4], parent_mac_octet[5]);
        alg_re_test.alg_re_status = DN_RE_STATUS_AFTER_ROAMING;
    }

    /* ALG TODO */
    if (alg_re_test.alg_re_status == DN_RE_STATUS_AFTER_ROAMING) // roaming finished, so send nwkout to fap.
    {
        re_alg_fin_trigger();
    }
    else // has not roaming, choose a father, and roaming to it.
    {
        int parent_cnt = 0;
        ApAlgInterfaceInput apAlgInput = {0};

        // update re alg info
        if (alg_re_test.starttime == pApRankIndex->starttime)
        {
            AWN_LOG_ERR("re has been optimized this cycle");
            goto re_alg_end;
        }
        //alg_re_test.alg_re_strategy = pApRankIndex->alg_strategy;
        alg_re_test.starttime = pApRankIndex->starttime;

        // init ApAlgInterfaceInput
        strcpy(apAlgInput.deviceMAC, lan_mac);
        strcpy(apAlgInput.fatherMAC, EMPTY_ADDR);
        apAlgInput.algStrategy = alg_re_test.alg_re_strategy;
        /* update scaninfo:*/
        awnd_ai_network_get_scan_result();
        // TODO
        apAlgInput.staCnt = 0;
        apAlgInput.backApCnt = 0;

        AWN_LOG_ERR(
            "apAlgOut_timestamp = %d, ap_timestamp = %d, bridging_timestamp = %d, "
            "pat_timestamp = %d, rank_timestamp = %d, scanning_timestamp = %d.",
            alg_timestamp.apAlgOut_timestamp, alg_timestamp.ap_timestamp,
            alg_timestamp.bridging_timestamp, alg_timestamp.pat_timestamp,
            alg_timestamp.rank_timestamp, alg_timestamp.scanning_timestamp);

        parent_cnt = dn_ap_get_parent_main_v2(alg_re_test.candidateParentMac, &apAlgInput, AR_NETWORK_APINFO_FILE, AR_BRIDGING_INFO_FILE,
                                           AR_SCANNING_INFO_FILE, AR_AP_RANK_INDEX_INFO_FILE, AR_AP_SCORE_INFO_FILE, AR_TIME_DELAY_INFO_FILE,
                                           AR_NETWOKING_PATINFORATE_FILE);
        AWN_LOG_ERR("parentCnt = (%1d), parent = [%12s].\n", parent_cnt, alg_re_test.candidateParentMac);
        alg_re_test.alg_re_status = DN_RE_STATUS_AFTER_ROAMING;
        if (parent_cnt > 0)
        {
            uint8_t mac[6] = {0};
            AWN_LOG_ERR("[info] begin to roaming to (%12s).", alg_re_test.candidateParentMac);
            mac_str_to_octet(alg_re_test.candidateParentMac, ALG_MAC_LENGTH, mac, sizeof(mac));
            memcpy(l_mac_ai_roaming_target, mac, AWND_MAC_LEN);
            AWN_LOG_NOTICE("set ai_roaming_target mac prefer: %02X:%02X:%02X:%02X:%02X:%02X",
                                l_mac_ai_roaming_target[0],l_mac_ai_roaming_target[1],l_mac_ai_roaming_target[2],
                                l_mac_ai_roaming_target[3],l_mac_ai_roaming_target[4],l_mac_ai_roaming_target[5]);
            awnd_re_roam(mac);
            uloop_timeout_set(&re_poll_timeout, 20000);
        }
        else
        {
            re_alg_process();
        }
    }

re_alg_end:
    ALG_POINT_FREE(pApRankIndex);

    return 0;
}

int handle_setting_hops_factor(int hops_factor)
{
    ai_alg_set_hops_factor(hops_factor);
    return 0;
}

float handle_getting_hops_factor()
{
    return ai_alg_get_hops_factor();
}

int handle_setting_patc_comp(int patc_comp)
{
    ai_alg_set_patc_comp(patc_comp);
    return 0;
}

void do_pre_first_roaming()
{
    //TODO:send info in request
    //send devinfo
    char buf[256];
    sprintf(buf, "ubus call ai_center.debug update_devinfo >/dev/null");
    system(buf);

    //send scan_info
    set_send_scan_info_flag(false);
    // awnd_ai_network_get_scan_result_now();
    awnd_ai_network_get_scan_result();

    //send request
    awnd_ai_network_send_roaming();
}
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */