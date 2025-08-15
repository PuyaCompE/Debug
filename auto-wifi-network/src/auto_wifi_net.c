/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file      auto-wifi-net.c
 *\brief     
 *
 *\author    Weng Kaiping
 *\version   1.0.0
 *\date      11Apr16
 *
 *\history \arg 1.0.0, 11Apr16, Weng Kaiping, Create the file. 
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
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include <sys/time.h>
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#include <sys/timerfd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include <aidata.h>
#include <aimsg.h>
#include <dataInterface.h>
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#include <libubox/uloop.h>
#include "libubus.h"
#include "uci.h"
#include "plcApi.h"

#include "awn_log.h"
#include "auto_wifi_net.h"
#include "awn_wifi_handler_api.h"
#include "awn_plcson_netlink.h"
#include "awn_ubus.h"
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include "ping.h"
#include "aimsg_handler.h"
#include "ai_nwk_defines.h"
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

/***************************************************************************/
/*                        DEFINES                                          */
/***************************************************************************/
#define DEFAULT_CONF_FILE  "/tmp/auto-wifi-net.conf"
#define WIFI_DONE_FILE     "/tmp/wifi_set_done"
#define TMP_ONBOARDING_FILE  "/tmp/onboarding"
#define AWN_BIND_STATUS       "/tmp/is_binded"
#define AWND_ADD_DEVICE_DONE  "/tmp/quick_setup/add_device_done"
#define GROUP_ROLE_BAK          "/tmp/bak_group_role"

#define SCANNING_DURATION      70
#define STATUS_TIMER_INTERVAL  200000000   
#define AWND_MAX_LEVEL         3
#define AWND_MODE_CHANGE_TIME  10

#define AWND_HIGH_RSSI_THRESHOLD      25
#define AWND_LOW_RSSI_THRESHOLD       14
#define AWND_SUFFICIENT_RSSI_INC      10 
#define AWND_BEST_EFFORT_RSSI_THRESHOLD  20
#define AWND_BEST_EFFORT_RSSI_INC      6
#define AWND_BEST_EFFORT_UPLINK_RATE  120 

#define RE_STAGE2_PERIOD 120
#define RE_STAGE4_PERIOD 12

/* not to recv plc event, to get plc neigbor tbl periodicity */
#define AWND_PLC_EVENT_RECV 0

/* bind process control: switch to backhual network --> sync usr-config */
#define AWND_BIND_SWITCH_BACKHUAL_FIRST 1

/* WIFI coexist with PLC */
#define WIFI_COEXIST_WITH_PLC 1

/* WIFI PLC need CONNECT to same rootap */
#define WIFI_PLC_CONNECT_TO_SAME_DUT 0

#define ENABLE 1
#define DISENABLE 0

/* max scan fail count to restart band wifi interface */
#define MAX_SCAN_FAIL_NUM 5

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
#define FIND_WIFI_ROOTAP_FAIL_CNT 10
#endif

/* 6G mac address offset from br-lan mac */
#define AWND_6G_MAC_OFFSET 4

#ifdef SUPPORT_MESHMODE_2G
#define AWND_5G_WEAKLINK_RSSI_THRESH    -83
#define AWND_6G_WEAKLINK_RSSI_THRESH    -83
#define AWND_5G_WEAKLINK_RATE_THRESH    13
#define AWND_6G_WEAKLINK_RATE_THRESH    13
#define AWND_PATH_OVERLOAD_THRESH       70
#define AWND_2GAPSDNEED_5G_RSSI_THRESH  -74
#define AWND_2GAPSDNEED_6G_RSSI_THRESH  -84
#define AWND_2G_INTF_THRESH             50
#define AWND_WINDOW_FACTOR_LOW          0.95
#define AWND_WINDOW_FACTOR_HIGH         1.05

#include <json-c/json.h>
#define SYNC_DEV_LIST_FILE                  "/tmp/sync-server/mesh_dev_list"
#define AWND_MESHMODE_2G_INSPECT_FILE       "/tmp/awnd_meshmode_2g_inspect"
#endif

/***************************************************************************
dfs channel Silent Period
    if rootap work at dfs channel, we should wait for cac time out(60s or 600s), 
add 5s for DUT connecting rootAp
****************************************************************************/
#define AWND_DFS_SILENT_PERIOD  (65 * 1000)
#define AWND_DFS_WEATHER_SILENT_PERIOD  (605 * 1000)

/* AP Start opt delay */
#define AWND_NET_OPT_DELAY  120

#if CONFIG_AWN_BOOT_DELAY
#define PHY_LINKUP_FILE "/tmp/phyup_file"
#define WIAT_PHY_LINKUP_SEC_MAX 60
#define WIAT_PHY_LINKUP_SEC_ONCE 5
#endif

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#define AI_ROAMING_PAT_PATH "/tmp/ai_roaming/ar_pat/curPatInfoRate"
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

/* For ISP DCMP BACKHAUL EVENT report (secondes)*/
int DCMP_BACKHAUL_CHECK_INTERVAL = 60;

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/

/*
#define HIGH_PRIO_SUBNET(info1, info2)  (((info1)->awnd_net_type < (info2)->awnd_net_type) \
      ||(((info1)->awnd_net_type == (info2)->awnd_net_type) && ((info1)->awnd_weight > (info2)->awnd_weight \
      || ((info1)->awnd_weight == (info2)->awnd_weight && (_mac_compare((info1)->awnd_mac, (info2)->awnd_mac) > 0)))))
*/

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
#define WIFI_SCHEDULE_RUNNING_FILE  "/tmp/wifi_schedule_status"
#endif

/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/
AWND_GLOBAL      g_awnd;
AWND_CONFIG      l_awnd_config;
UINT8            l_mac_prefer[AWND_MAC_LEN] = {0};

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
RE_CONNECT_POLICY g_connect_policy = RE_CONNECT_DEFAULT;
#endif

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
UINT8            l_mac_ai_roaming_target[AWND_MAC_LEN] = {0};
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
extern UINT8 old_parent_mac[AWND_MAC_LEN];
// static AWND_SCAN_TABLE l_awnd_ai_scan_table;
static AWND_SCAN_TABLE  l_awnd_scan_table;
static AWND_GROUP_INFO  l_group_info;
static AWND_PLC_NEIGH_TABLE l_awnd_plc_neigh_table;
static AWND_ETH_NEIGH_TABLE l_awnd_eth_neigh_table;
static AWND_UNABLE_CONN_AP_TABLE unable_conn_ap_table;

#if CONFIG_RE_RESTORE_STA_CONFIG
static uint8_t full_scan_at_beginning = 1;
static uint8_t need_save_config_when_backhaul_stable = 1;
#endif

static int l_wait_prefer_connect = 0; 
static int wait_for_prefer_ap_cnt = 0;
int fap_oui_update_status = 0;
int re_oui_update_status = 0;
int oui_now_version = 1;
static struct ubus_context *ctx = NULL;

int max_rate_backhaul_eth = 0;

ISP_DCMP_PRECONFIG isp_dcmp_preconfig = 
{
    .rootap_link_state = 0,
    .rootap_link_type = 0,
    .is_add_md5 = 1,
    .preconfig_vap_state = false,
};

#define WIFI_SAMPLE_MAX_NUM 11
#define PLC_SAMPLE_MAX_NUM 5
#define PACKET_QUEUE_LEN   72
static UINT16 wifiRateSamples[AWND_BAND_MAX][2][WIFI_SAMPLE_MAX_NUM] = {0};
static UINT16 plcRateSamples[2][PLC_SAMPLE_MAX_NUM] = {0};

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
static int is_set_ignorecac = 0;
#endif
static int samplesCount = 0;

#ifdef CONFIG_AWN_RE_ROAMING
static uint8_t *roaming_mac = NULL;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
BOOL roaming_running = false;
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#endif
#if CONFIG_RX_PACKETS_CHECK
static int packetTrackIdx[PACKET_QUEUE_LEN] = {0};
static unsigned long long packetQueue[AWND_BAND_MAX][PACKET_QUEUE_LEN] = {0};
#endif /* CONFIG_RX_PACKETS_CHECK */

#if CONFIG_AWN_BOOT_DELAY
static int boot_delay_done = 0;
#endif

static char *real_band_suffix[AWND_REAL_BAND_MAX] = {"2g", "5g", "5g2", "6g", "6g2"};

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static BOOL send_scan_info_flag = false;
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

#if CONFIG_AWN_BOOT_DELAY
static int boot_delay_done = 0;
#endif

static char* locateArray[AWND_LOCATION_MAX] = {
    "RE_LocationSuitable", 
    "RE_MoveCloser",
    "RE_MoveFarther",
    "UNAVAILABLE",
    "GETTING"
};

MODE_INFO modeArray[AWND_MODE_MAX] ={
		{AWND_MODE_FAP, "FAP"},
		{AWND_MODE_HAP, "HAP"},
		{AWND_MODE_RE,  "RE"},
        {AWND_MODE_NONE,  "NONE"},
};

NET_TYPE_INFO netTypeArray[AWND_NET_MAX] ={
        {AWND_NET_FAP, "FAP"},
        {AWND_NET_HAP, "HAP"},
        {AWND_NET_LRE,  "RE"},
};

HOTPLUG_INFO hotplugArray[AWND_HOTPLUG_MAX] ={
		{AWND_HOTPLUG_MODE_CHANGE_BEGIN, "BEGIN"},
		{AWND_HOTPLUG_MODE_CHANGE_END,   "END"},
		{AWND_HOTPLUG_CAP_CHANGE,        "CAPCHANGE"},		
        {AWND_HOTPLUG_CAP_IP_CHANGE,     "CAPIPCHANGE"},
        {AWND_HOTPLUG_CAP_TYPE_CHANGE,   "CAPTYPECHANGE"},
        {AWND_HOTPLUG_CAP_DNS_CHANGE,   "CAPDNSCHANGE"},
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        {AWND_HOTPLUG_PARENT_CHANGE,   "PARENTCHANGE"},
        {AWND_HOTPLUG_LINK_STATUS_CHANGE,     "LINKSTATUSCHANGE"},
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */
};

IEEE80211_TP_OUI_LIST tp_oui_list[TP_OUI_MAX_VERSION+1] = {
    {{0x00,0x1d,0x0f}},
    {{0x00,0x31,0x92}},
};

static inline char* hotplugToStr(AWND_HOTPLUG_TYPE type)
{
    int index = 0;
    for (index = 0; index < AWND_HOTPLUG_MAX; index++)
    {
        if (type == hotplugArray[index].type)
            return hotplugArray[index].typeName;
    }

    return "--";
}
 
#define DEFAULT_HOTPLUG_PATH	"/sbin/hotplug-call"
#define MAX_WIFI_PROCESS      6
#define MAX_HOTPLUG_PROCESS   32

char *hotplug_cmd_path = DEFAULT_HOTPLUG_PATH;

void awnd_eth_inspect(struct uloop_timeout *t);
void awnd_plc_event_handler(struct uloop_fd *u, unsigned int ev);
void awnd_plc_inspect(struct uloop_timeout *t);
void awnd_backhaul_review(struct uloop_timeout *t);
void awnd_bind_confirm(struct uloop_timeout *t);
void awnd_onboarding_inspect(struct uloop_timeout *t);
void awnd_wifi_check_doing(struct uloop_timeout *t);
void awnd_update_lanip(struct uloop_timeout *t);
void awnd_server_detect_handler(struct uloop_timeout *t);
void awnd_re_stage_inspect(struct uloop_timeout *t);
#ifdef SUPPORT_MESHMODE_2G
void awnd_meshmode_2g_inspect(struct uloop_timeout *t);
#endif
void awnd_scan_create_processes(struct uloop_timeout *t);
void awnd_conn_timeout_handler(struct uloop_timeout *t);
void awnd_conn_inspect_reschedule(struct uloop_timeout *t);
#if CONFIG_WIFI_DFS_SILENT
void awnd_silent_period_handler(struct uloop_timeout *t);
#endif /* CONFIG_WIFI_DFS_SILENT */
#if CONFIG_BSS_STATUS_CHECK
void bss_status_inspect(struct uloop_timeout *t);
#endif /* CONFIG_BSS_STATUS_CHECK */
#if SCAN_OPTIMIZATION
void awnd_scan_handle_result(struct uloop_timeout *t);
#else
void awnd_scan_handle_result(struct uloop_process *proc, int ret);
#endif //SCAN_OPTIMIZATION
#if CONFIG_RE_RESTORE_STA_CONFIG
void awnd_sta_config_handler(struct uloop_timeout *t);
#endif
int awnd_mode_convert(AWND_MODE_TYPE srcMode, AWND_MODE_TYPE dstMode);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
void awnd_ai_network_get_scan_result();
void awnd_ai_re_roam(struct uloop_timeout *t);
int awnd_ai_msg_handler(void *data, int len, struct aimsg_addr *addr);
int awnd_test_ping_rootap(void);
int awnd_ai_network_tipc_connect(struct uloop_timeout *t);
int ai_network_send_roaming(struct uloop_timeout *t);
int ai_network_roaming_status_revert(struct uloop_timeout *t);
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

void awnd_preconfig_control(struct uloop_timeout *t);
void awnd_re_preconfig_control(struct uloop_timeout *t);
#ifdef CONFIG_AWN_RE_ROAMING
int awnd_re_roam(uint8_t *mac);
#endif
int awnd_config_covert_backhaul_with_same_rootap(void);

static struct uloop_timeout awnd_bind_timer = {
    .cb = awnd_bind_confirm,
};
static struct uloop_timeout onboarding_inspect_timer = {
    .cb = awnd_onboarding_inspect,
};

static struct uloop_timeout wifi_done_timer = {
    .cb = awnd_wifi_check_doing,
};

static struct uloop_timeout wifi_scan_timer = {
    .cb = awnd_scan_create_processes,
};

#if SCAN_OPTIMIZATION
static struct uloop_timeout handle_scan_result_timer = {
    .cb = awnd_scan_handle_result,
};
#endif

#if CONFIG_RE_RESTORE_STA_CONFIG
static struct uloop_timeout handle_sta_config_timer = {
    .cb = awnd_sta_config_handler,
};
#endif

static struct uloop_timeout wifi_connect_timer = {
    .cb = awnd_conn_timeout_handler,
};

static struct uloop_timeout wifi_rootap_status_timer = {
    .cb = awnd_conn_inspect_reschedule,
};

#if CONFIG_WIFI_DFS_SILENT
static struct uloop_timeout wifi_silent_period_timer = {
    .cb = awnd_silent_period_handler,
};
#endif /* CONFIG_WIFI_DFS_SILENT */

static struct uloop_timeout update_lanip_timer = {
    .cb = awnd_update_lanip,
};

static struct uloop_timeout server_detect_timer = {
    .cb = awnd_server_detect_handler,
};

static struct uloop_timeout re_stage_inspect_timer = {
    .cb = awnd_re_stage_inspect,
};

#ifdef SUPPORT_MESHMODE_2G
static struct uloop_timeout meshmode_2g_inspect_timer = {
    .cb = awnd_meshmode_2g_inspect,
};
#endif

static struct uloop_timeout eth_neigh_inspect_timer = {
    .cb = awnd_eth_inspect,
};

static struct uloop_timeout plc_neigh_inspect_timer = {
    .cb = awnd_plc_inspect,
};

static struct uloop_timeout backhaul_review_timer = {
    .cb = awnd_backhaul_review,
};

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
// static struct uloop_timeout ai_network_getscan_timer = {
//     .cb = awnd_ai_network_get_scan_result,
// };

static struct uloop_timeout ai_network_check_tipc_timer = {
    .cb = awnd_ai_network_tipc_connect,
};

static struct uloop_timeout ai_network_send_roaming_timer = {
    .cb = ai_network_send_roaming,
};

static struct uloop_timeout ai_network_roaming_status_revert_timer = {
    .cb = ai_network_roaming_status_revert,
};

static struct uloop_timeout ai_re_roam_timer = {
    .cb = awnd_ai_re_roam,
};
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

#if CONFIG_BSS_STATUS_CHECK
static struct uloop_timeout bss_status_inspect_timer = {
    .cb = bss_status_inspect,
};
#endif /* CONFIG_BSS_STATUS_CHECK */

static struct uloop_timeout preconfig_control_timer = {
    .cb = awnd_preconfig_control,
};

static struct uloop_timeout re_preconfig_control_timer = {
    .cb = awnd_re_preconfig_control,
};

#if AWND_PLC_EVENT_RECV
static struct uloop_fd plc_event_fd = {
	.cb = awnd_plc_event_handler,
};
#endif

static struct uloop_process wifi_scan_processes[MAX_WIFI_PROCESS] = {0};
static struct uloop_process hotplug_processes[MAX_HOTPLUG_PROCESS] = {0};

/***************************************************************************/
/*                        LOCAL FUNCTIONS                                  */
/***************************************************************************/
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
static void awnd_print_netInfo()
{
    if (g_awnd.ethStatus == AWND_STATUS_CONNECTED)
        AWN_LOG_INFO("eth connected, eth rootap:%02x:%02x:%02x:%02x:%02x:%02x level:%d, net_type:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X", 
            g_awnd.ethRootApMac[0],g_awnd.ethRootApMac[1],g_awnd.ethRootApMac[2],g_awnd.ethRootApMac[3],g_awnd.ethRootApMac[4],g_awnd.ethRootApMac[5], 
            g_awnd.ethNetInfo.awnd_level, g_awnd.ethNetInfo.awnd_net_type,
            g_awnd.ethNetInfo.awnd_mac[0], g_awnd.ethNetInfo.awnd_mac[1], g_awnd.ethNetInfo.awnd_mac[2],
            g_awnd.ethNetInfo.awnd_mac[3], g_awnd.ethNetInfo.awnd_mac[4], g_awnd.ethNetInfo.awnd_mac[5]);

    if (_is_in_connected_state(g_awnd.connStatus))
        AWN_LOG_INFO("wlan connected, wlan rootap:%02x:%02x:%02x:%02x:%02x:%02x level:%d, net_type:%d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X", 
            g_awnd.rootAp[AWND_BAND_2G].lan_mac[0],g_awnd.rootAp[AWND_BAND_2G].lan_mac[1],g_awnd.rootAp[AWND_BAND_2G].lan_mac[2],
            g_awnd.rootAp[AWND_BAND_2G].lan_mac[3],g_awnd.rootAp[AWND_BAND_2G].lan_mac[4],g_awnd.rootAp[AWND_BAND_2G].lan_mac[5],
            g_awnd.netInfo.awnd_level, g_awnd.netInfo.awnd_net_type,
            g_awnd.netInfo.awnd_mac[0], g_awnd.netInfo.awnd_mac[1], g_awnd.netInfo.awnd_mac[2],
            g_awnd.netInfo.awnd_mac[3], g_awnd.netInfo.awnd_mac[4], g_awnd.netInfo.awnd_mac[5]);
}
#endif /* CONFIG_ETH_WLAN_BACKHAUL_SUPPORT */

static void uloop_cb_null(struct uloop_process *proc, int ret)
{
    AWN_LOG_INFO("child process %d return %d", proc->pid, ret);
    return;
}

void uloop_fd_recv_null(struct uloop_fd *u, unsigned int ev)
{
	char buf[4096];
	int len = recv(u->fd, buf, sizeof(buf), MSG_DONTWAIT);

    AWN_LOG_INFO("receive %d data from fd and do nothing", len);
    
    return ;    
}

static struct uloop_process *uloop_get_hotplug_process()
{
    struct uloop_process *proc = NULL;
    int procId = 0;
    for (procId = 0; procId < MAX_HOTPLUG_PROCESS; procId++)
    {
        if (! hotplug_processes[procId].pending)
        {
            proc = &hotplug_processes[procId];
            proc->cb = uloop_cb_null;
            break;
        }        
    }
    return proc;
}


static struct uloop_process *uloop_get_wifi_process()
{
    struct uloop_process *proc = NULL;
    int procId = 0;
    for (procId = 0; procId < MAX_WIFI_PROCESS; procId++)
    {
        if (! wifi_scan_processes[procId].pending)
        {
            proc = &wifi_scan_processes[procId];
            proc->cb = awnd_scan_handle_result;
            break;
        }        
    }
    return proc;
}

static void uloop_clear_wifi_processes()
{
    int procId = 0;
    for (procId = 0; procId < MAX_WIFI_PROCESS; procId++)
    {
        if (wifi_scan_processes[procId].pending)
        {
            wifi_scan_processes[procId].cb = uloop_cb_null;
            AWN_LOG_INFO("Set call back of scan process %d to null.", wifi_scan_processes[procId].pid);
        }        
    }
    return;
}

static void uloop_clear_plc_event()
{
#if AWND_PLC_EVENT_RECV
    int len;
    char buf[4096];
#endif
    
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        l_awnd_plc_neigh_table.eventEnable = 0;
        awn_plcson_set_detect_param(1, 0, l_awnd_config.plc_entry_aging_time);
    }

#if AWND_PLC_EVENT_RECV
    if (plc_event_fd.fd)
    {
        len = recv(plc_event_fd.fd, buf, sizeof(buf), MSG_DONTWAIT);
        AWN_LOG_INFO("receive %d data from fd and do nothing", len);
    }
#endif

    return;
}


static void _mac_compute(UINT8 *dstMac, UINT8 *srcMac, UINT8 delta, int add)
{
    int i = 0;
    memcpy(dstMac, srcMac, AWND_MAC_LEN);
    
    if (add)
    {
        if ( (dstMac[5]+delta) <= 255 ) dstMac[5] = dstMac[5] + delta;
        else
        {
            dstMac[5] = dstMac[5] + delta - 256;
            for ( i = 4; i >= 0; i-- )
            {
                if (dstMac[i] < 255)
                {
                    dstMac[i] = dstMac[i] + 1;
                    break;
                }
                else
                {
                    dstMac[i] = 0;
                }

            }
        }        
    }
    else
    {
        if ( dstMac[5]>=delta ) dstMac[5] = dstMac[5] - delta;
        else
        {
            dstMac[5] = 256 + dstMac[5] -delta;
            for ( i = 4; i >= 0; i-- )
            {
                if (dstMac[i] >= 1)
                {
                    dstMac[i] = dstMac[i] - 1;
                    break;
                }
                else
                {
                    dstMac[i] = 255;
                }

            }
        }        
    }

    return;
}


static inline int _mac_compare(UINT8 *mac1, UINT8 *mac2)
{
    int macIdx;
    for (macIdx = 0; macIdx < AWND_MAC_LEN; macIdx++)
    {
        if (mac1[macIdx] > mac2[macIdx])
            return 1;
        else if (mac1[macIdx] < mac2[macIdx])
            return -1;        
    }
    return 0;
}

static inline int _is_vaild_mac(UINT8 *mac)
{
    UINT8 macZero[AWND_MAC_LEN]={0};

    return memcmp(mac, macZero, AWND_MAC_LEN);
}

static inline int _is_null_ssid(char *ssid)
{
    char ssidNull[AWND_MAX_SSID_LEN]={0};

    return (0 == memcmp(ssid, ssidNull, AWND_MAX_SSID_LEN));
}

static inline int HIGH_PRIO_SUBNET(AWND_NET_INFO *info1, AWND_NET_INFO *info2)
{
    if ((info1->awnd_net_type == AWND_NET_FAP || info2->awnd_net_type == AWND_NET_FAP))
    {
        if (info1->awnd_net_type < info2->awnd_net_type)
            return 1;
        else if (info1->awnd_net_type > info2->awnd_net_type)
            return 0;
    }

    if (info1->server_detected || info2->server_detected)
    {
        if (info1->server_detected && info2->server_detected)
        {
              if (info1->server_touch_time > info2->server_touch_time)
                return 1;
              else if (info1->server_touch_time < info2->server_touch_time)
                return 0;
        }
        else if (info1->server_detected)
            return 1;
        else if (info2->server_detected)
            return 0;
    }

    if ((info1->awnd_net_type == AWND_NET_HAP || info2->awnd_net_type == AWND_NET_HAP))
    {
        if (info1->awnd_net_type < info2->awnd_net_type)
            return 1;
        else if (info1->awnd_net_type > info2->awnd_net_type)
            return 0;
    }

    if(_mac_compare((info1)->awnd_mac, (info2)->awnd_mac) > 0)
        return 1;
    else
        return 0;
}
/*
    *is_better_neigh
    *return 1: a better neigh than me, to active eth backhual
    *return 0: stop active eth backhual, do nothing
*/
static int is_better_neigh(AWND_ETH_NEIGH *pNeigh)
{
    if (g_awnd.eth_wifi_coexist)
    {
        if (pNeigh->netInfo.awnd_net_type < g_awnd.netInfo.awnd_net_type)
            return 1;
        else if (pNeigh->netInfo.awnd_net_type > g_awnd.netInfo.awnd_net_type)
            return 0;

        if (pNeigh->netInfo.awnd_level < g_awnd.netInfo.awnd_level)
            return 1;
        else if (pNeigh->netInfo.awnd_level > g_awnd.netInfo.awnd_level)
            return 0;

        if (pNeigh->uplink_mask > g_awnd.uplinkMask)
            return 1;
        else if (pNeigh->uplink_mask < g_awnd.uplinkMask)
            return 0;

        if (pNeigh->uplink_rate > g_awnd.uplinkRate)
            return 1;
        else if (pNeigh->uplink_rate < g_awnd.uplinkRate)
            return 0;

        if(_mac_compare(pNeigh->lan_mac, l_awnd_config.mac) > 0)
            return 1;
    }
    else
    {
        if (pNeigh->netInfo.awnd_level < g_awnd.netInfo.awnd_level)
            return 1;
        if (pNeigh->netInfo.awnd_level == g_awnd.netInfo.awnd_level)
            {
                if (pNeigh->uplink_mask > g_awnd.uplinkMask)
                    return 1;
                else if (pNeigh->uplink_mask == g_awnd.uplinkMask)
                {
                    if (((g_awnd.uplinkMask & AWND_BACKHAUL_WIFI) && pNeigh->uplink_rate > g_awnd.uplinkRate)
                        || ((!(g_awnd.uplinkMask & AWND_BACKHAUL_WIFI) ||  pNeigh->uplink_rate == g_awnd.uplinkRate)
                             && _mac_compare(pNeigh->lan_mac, l_awnd_config.mac) > 0))
                    {
                        return 1;
                    }
                }
            }
    }

    return 0;
}

static void _bubbleSort(UINT16 *array, int array_size)
{
    int i, j;
    UINT16 tmp;

    for (i = (array_size - 1); i > 0; i--) {
        for (j = 0; j < i; j++) {
            if (array[j] > array[j+1]) {
                tmp = array[j];
                array[j] = array[j+1];
                array[j+1] = tmp;    
            }
        }
    }
}

static UINT16 _updateSample(UINT16* sampleArr, int maxSamples, UINT16 newSample, BOOL refresh)
{
    int i;
    BOOL isClear = refresh;
    UINT16 medium = 0;

    if (! refresh) 
    {
         if (!newSample)
            return medium;
         
         for (i = 0; i < maxSamples; i++)
         {
             if (!sampleArr[i])
             {
                 sampleArr[i] = newSample;
                 break;
             }
         }
         if ((i + 1) >= maxSamples) {
            _bubbleSort(sampleArr, maxSamples);
            medium = sampleArr[maxSamples/2];
            isClear = TRUE;
         }
    }

    if (isClear) 
    {
         for (i = 0; i < maxSamples; i++)
            sampleArr[i] = 0;
    }

    return medium;
}

#if CONFIG_RX_PACKETS_CHECK
#define READ_LINE_LEN                       256
static int _get_data_sum(char *ifname, unsigned long long *packets)
{
    char line[READ_LINE_LEN] = {0};
	char *s = NULL;    
	FILE *fp = NULL;
    char name[15] = {0};
    char rx_bytes[24] = {0};
    /* llu max length is 20 */
    char rx_packets[24] = {0};
    char rx_errs[24] = {0};
    char rx_drops[24] = {0};
    char rx_fifos[24] = {0};
    char rx_frame[24] = {0};
    char rx_compressed[24] = {0};
    char rx_multicast[24] = {0};
    char tx_bytes[24] = {0};
    char tx_packets[24] = {0};

    unsigned long long rx_packets_num = 0;
	
	fp = popen("cat /proc/net/dev", "r");
	if (NULL == fp)
	{
		AWN_LOG_INFO("Failed to get stat info");
		return -1;
	}

	while (fgets(line,READ_LINE_LEN , fp) != NULL)
	{
		if (NULL != (s = strstr(line, ifname)))
        {
            sscanf(s,"%s%s%s%s%s%s%s%s%s%s%s",name,rx_bytes,rx_packets,rx_errs,rx_drops,rx_fifos,rx_frame,rx_compressed,rx_multicast,tx_bytes,tx_packets);
            sscanf(rx_packets,"%llu",&rx_packets_num);
        }
	}

	pclose(fp);

    *packets = rx_packets_num;

    return 0;
}
#endif /* CONFIG_RX_PACKETS_CHECK */

static void _save_bind_status(int is_binded)
{
    char cmd[128];

    memset(cmd, 0, 128);
    snprintf(cmd, 128, "echo %d > %s", is_binded, AWN_BIND_STATUS);
    system(cmd);

    AWN_LOG_INFO("%s", cmd);
}

static void _save_group_role(AWND_CONFIG_ROLE role)
{
    char cmd[128];
    memset(cmd, 0, 128);
    if (AWND_CONFIG_AP == role)
    {
        snprintf(cmd, 128, "echo AP > %s", GROUP_ROLE_BAK);
    }
    else
    {
        snprintf(cmd, 128, "echo RE > %s", GROUP_ROLE_BAK);
    }

    system(cmd);
}

static void _reset_onboarding_status()
{
    char cmd[128] = {0};
    uloop_timeout_cancel(&onboarding_inspect_timer);

    snprintf(cmd, sizeof(cmd), "ubus call radar reset &");
    system(cmd);

    /* add handle for onboarding */
    uloop_timeout_set(&onboarding_inspect_timer, l_awnd_config.tm_onboarding_interval);
}

static void _send_apsd_configure_msg()
{
    char cmd[128] = {0};
    snprintf(cmd, sizeof(cmd), "ubus send apsd.configure");
    system(cmd);
}

static int _get_onboarding_status(int *isOnboarding)
{
	//get internet staus now by read some file
	int fd = AWND_ERROR;
	int status;
	char buff[128];

    if (access(TMP_ONBOARDING_FILE, 0))
    {
        return AWND_ERROR;
    }

	fd = open(TMP_ONBOARDING_FILE, O_RDONLY);	
	if (fd < 0)
	{
		AWN_LOG_INFO("open %s error...", TMP_ONBOARDING_FILE);
		return AWND_ERROR;
	}

	read(fd, buff, 128);
	sscanf(buff, "%d", &status);
	
	close(fd);

	*isOnboarding = status;
	
	return AWND_OK;	
}

static UINT16 _get_connect_status()
{
    UINT16 uplinkMask = 0;

    if (_is_in_connected_state(g_awnd.connStatus))
        uplinkMask |= AWND_BACKHAUL_WIFI;
    if (AWND_STATUS_CONNECTED == g_awnd.plcStatus)
        uplinkMask |= AWND_BACKHAUL_PLC; 
    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus)
        uplinkMask |= AWND_BACKHAUL_ETH;

    return  uplinkMask;   
}

#if CONFIG_BSS_STATUS_CHECK
static void _reset_bss_stats()
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        g_awnd.wlDownCnt[band]  = 0;
        g_awnd.bssDownCnt[band] = 0;
        g_awnd.reinitCnt[band]  = 0;
    }
    return;
}
#endif /* CONFIG_BSS_STATUS_CHECK */

static int is_prefer_mac(AWND_AP_ENTRY *ap_entry)
{   
    if (!ap_entry)
        return 0;
    return !memcmp(ap_entry->lan_mac, l_mac_prefer, AWND_MAC_LEN);
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static int is_ai_roaming_mac(AWND_AP_ENTRY *ap_entry)
{
    return !memcmp(ap_entry->lan_mac, l_mac_ai_roaming_target, AWND_MAC_LEN);
}
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

int check_unable_conn_ap_table(AWND_AP_ENTRY *ap_entry, AWND_UNABLE_TABLE_OP_TYPE op_type)
{
    int ret = 0;
    UINT8 macZero[AWND_MAC_LEN] = {0};

    switch (op_type)
    {
    case AWND_OP_FLUSH:
        AWN_LOG_NOTICE("flush unable_conn_ap_table ");
        memset(&unable_conn_ap_table, 0, sizeof(AWND_UNABLE_CONN_AP_TABLE));
        break;

    case AWND_OP_SET_PREFER:
        memcpy(&unable_conn_ap_table.prefer_ap_mac, &ap_entry->lan_mac, AWND_MAC_LEN);
        unable_conn_ap_table.prefer_ap_level = ap_entry->netInfo.awnd_level;
        AWN_LOG_NOTICE("set unable_conn_ap_table, new ap (mac: %02X:%02X:%02X:%02X:%02X:%02X)",
                        unable_conn_ap_table.prefer_ap_mac[0], unable_conn_ap_table.prefer_ap_mac[1], unable_conn_ap_table.prefer_ap_mac[2],
                        unable_conn_ap_table.prefer_ap_mac[3], unable_conn_ap_table.prefer_ap_mac[4], unable_conn_ap_table.prefer_ap_mac[5]);
        break;

    case AWND_OP_SET_FLAG:
        if (!memcmp(unable_conn_ap_table.prefer_ap_mac, macZero, AWND_MAC_LEN)) {
            AWN_LOG_NOTICE("set unable_conn_ap_table flag failed, prefer_ap_mac is NULL");
        }
        else {
            AWN_LOG_NOTICE("set unable_conn_ap_table flag success");
            unable_conn_ap_table.is_failed = 1;
        }

        break;

    case AWND_OP_CHECK_MAC:
        if (!memcmp(ap_entry->lan_mac, unable_conn_ap_table.prefer_ap_mac, AWND_MAC_LEN)) {
            ret = 1;
        }
        break;

    case AWND_OP_CHECK_PREFER:
        if (!memcmp(ap_entry->lan_mac, unable_conn_ap_table.prefer_ap_mac, AWND_MAC_LEN)
            && (ap_entry->netInfo.awnd_level == unable_conn_ap_table.prefer_ap_level)
            && unable_conn_ap_table.is_failed) {
            ret = 1;
        }
        break;

    default:
        break;
    }

    return ret;
}

#if CONFIG_AWN_BOOT_DELAY

static int is_phyup_file_exist(void)
{
    if( access( PHY_LINKUP_FILE, 0) ) {
        return 0;
    } else {
        return 1;
    }
}

static void awnd_boot_delay(void)
{
    time_t start_sec = time(NULL);
    time_t delay_sec = WIAT_PHY_LINKUP_SEC_MAX; // maximum delay 30 sec
    int cnt = 0;

    AWN_LOG_WARNING("awnd boot delay start");

    while( (!is_phyup_file_exist()) && (( start_sec + delay_sec ) >= time(NULL)) ) {
        AWN_LOG_WARNING("awnd boot delay (cnt=%d now)",cnt++);
        sleep(WIAT_PHY_LINKUP_SEC_ONCE);
    }

    if( is_phyup_file_exist() )
        AWN_LOG_WARNING("awnd detect phy linkup");
    else
        AWN_LOG_ERR("awnd do not detect phy linkup");

    boot_delay_done = 1;
    AWN_LOG_WARNING("awnd boot delay end");
}
#endif

/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/
UINT32 get_rootap_link_info(ISP_DCMP_PRECONFIG *isp_dcmp_preconfig)
{
    if(_is_in_connected_state(g_awnd.connStatus))
    {
        isp_dcmp_preconfig->rootap_link_state = 1;
        if(g_awnd.rootAp->isPreconfig == 1)
        {
            isp_dcmp_preconfig->rootap_link_type = 1;
        }
        else
        {
            isp_dcmp_preconfig->rootap_link_type = 0;
        }
    }
    else
    {
        isp_dcmp_preconfig->rootap_link_state = 0;
        isp_dcmp_preconfig->rootap_link_type = 0;
    }

    return 0;
}

BOOL get_preconfig_vap_state()
{
    return isp_dcmp_preconfig.preconfig_vap_state;
}

void change_rootap()
{
    awnd_disconn_all_sta(); 
    uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_sched);
}
/*!
*\fn           int awnd_set_binded_channel()
*\brief        set channel according to default mesh VAP when disconnect with rootap
*\param[in]    v
*\return       v
*/
static void awnd_set_binded_channel()
{
    int band = 0;
    int channel = 0;
	UINT8 enable_ht240 = 0;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (AWND_STATUS_DISCONNECT == g_awnd.connStatus[band])
        {
            if (AWND_OK == awnd_get_default_mesh_channel(band, &channel) && channel)
            {
                AWN_LOG_INFO("band:%s set channel:%d ", real_band_suffix[_get_real_band_type(band)], channel);
                awnd_config_set_channel(channel, band);
            }
        }
		if (band == AWND_BAND_5G)
		{
			if (AWND_OK == awnd_get_default_mesh_channel(band, &channel) && channel)
			{
				enable_ht240 = awnd_config_get_enable_5g_ht240();

				AWN_LOG_ERR("enable_ht240:%d current channel:%d ",enable_ht240,channel);
				if ( enable_ht240 != ENABLE /* && channel >= AWN_BAND3_FIRST_CHANNEL && channel <= AWN_BAND3_LAST_CHANNEL */)
				{
					if (awnd_check_block_chan_list(band, &channel) == AWND_ERROR)
					{
					    AWN_LOG_ERR("band:%s set channel:%d ", real_band_suffix[_get_real_band_type(band)], channel);
					    awnd_config_set_channel(channel, band);
					}

				}
			}

		}
    }
}
void awnd_scan_set_full_band()
{
    UINT8 scan_band = 0;
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        scan_band |= (1 << band);
    }
    l_awnd_scan_table.scan_band = scan_band;
}


int awnd_get_better_band_entry(AWND_AP_ENTRY * pApEntry1, AWND_AP_ENTRY * pApEntry2)
{
    int rssi1, rssi2;
    AWND_AP_ENTRY * pHighRSSIAp = NULL;
    AWND_AP_ENTRY * pLowRSSIAp  = NULL;
    int ret = 1;

    if (pApEntry1 && !pApEntry2)
        return 1;

    if (!pApEntry1 && pApEntry2)
        return 0;

    if (IN_SAME_SUBNET(&(pApEntry1->netInfo), &(pApEntry2->netInfo)))
    {
        if (pApEntry1->pathRate || pApEntry2->pathRate)
        {
             if (pApEntry1->pathRate > pApEntry2->pathRate)
                return 1;
             else
                return 0;
        }
    }
    else
    {
        if ((memcmp(g_awnd.fapMac, pApEntry1->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
        {   /* to find binded FAP entry first */
            return 1;
        }
        else if ((memcmp(g_awnd.fapMac, pApEntry2->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
        {   /* to find binded FAP entry first */
            return 0;
        }
        else if (HIGH_PRIO_SUBNET(&(pApEntry1->netInfo), &(pApEntry2->netInfo)))
        {
            return 1;
        }
    }

    /* 5g first */
    return 0;
}

int awnd_config_set_path_rate_threshold(int pathRate2g, int pathRate5g)
{
    l_awnd_config.wifi_pathRate_threshold_2g = pathRate2g;
    l_awnd_config.wifi_pathRate_threshold_5g = pathRate5g;
}

int awnd_compare_scan_entry(AWND_AP_ENTRY * pApEntry1, AWND_AP_ENTRY * pApEntry2)
{
    int rssi1, rssi2;
    AWND_AP_ENTRY * pHighRSSIAp   = NULL;
    AWND_AP_ENTRY * pLowRSSIAp = NULL;     
    AWND_AP_ENTRY * pHighprioAp = NULL;     
    int ret = 1;

    if (pApEntry1 && !pApEntry2)
        return 1;

    if (!pApEntry1 && pApEntry2)
        return 0;    

    if (IN_SAME_SUBNET(&(pApEntry1->netInfo), &(pApEntry2->netInfo)))
    {
        if(is_prefer_mac(pApEntry1) && !is_prefer_mac(pApEntry2)){
            return 1;
        }
        else if(!is_prefer_mac(pApEntry1) && is_prefer_mac(pApEntry2)){
            return 0;
        }
         /* 1.RSSI of up level ap >= AWND_HIGH_RSSI_THRESHOLD, choose up level ap.*/
         if (pApEntry1->netInfo.awnd_level != pApEntry2->netInfo.awnd_level)
         {
            if (pApEntry1->netInfo.awnd_level < pApEntry2->netInfo.awnd_level 
                && pApEntry1->rssi > l_awnd_config.high_rssi_threshold)
            {
                return 1;
            }
            else if (pApEntry1->netInfo.awnd_level > pApEntry2->netInfo.awnd_level 
                && pApEntry2->rssi > l_awnd_config.high_rssi_threshold)
            {
                return 0;
                               
            }                                   
         }

         /* 2.RSSI of one ap < AWND_LOW_RSSI_THRESHOLD, another increase more than AWND_BEST_EFFORT_RSSI_INC, choose another.*/
         if ((pApEntry1->rssi < l_awnd_config.low_rssi_threshold || pApEntry2->rssi < l_awnd_config.low_rssi_threshold) 
                && abs(pApEntry1->rssi - pApEntry2->rssi) >= l_awnd_config.best_effort_rssi_inc)
         {
                if (pApEntry1->rssi > pApEntry2->rssi)
                {
                    pHighRSSIAp = pApEntry1;
                    pLowRSSIAp  = pApEntry2;
                    ret = 1;
                }
                else
                {
                    pHighRSSIAp = pApEntry2;
                    pLowRSSIAp  = pApEntry1;
                    ret = 0;
                }
                
                if ((pHighRSSIAp->netInfo.awnd_level < pLowRSSIAp->netInfo.awnd_level) 
                    || (pHighRSSIAp->uplinkMask & (AWND_BACKHAUL_ETH | AWND_BACKHAUL_PLC))
                    || (pHighRSSIAp->uplinkRate > l_awnd_config.best_effort_uplink_rate))
                {                
                    return ret;
                }
         }

        if ( pApEntry1->isPreconf != pApEntry2->isPreconf )
        {
            if(1 == pApEntry1->isPreconf)
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }

         /* 3. caculate (backhaulRate * apRate)/(backhaulRate + apRate) to choose ap. if backhaulRate is 0, choose another.*/
         if (pApEntry1->pathRate || pApEntry2->pathRate)
         {
             if (pApEntry1->pathRate > pApEntry2->pathRate)
                return 1;
             else
                return 0;
         }    

         /* 4. if both backhaulRate are 0, use rssi to choose ap.*/
         rssi1= awnd_rssi_estimate(pApEntry1->rssi ,pApEntry1->netInfo.awnd_level, l_awnd_config.scaling_factor);
         rssi2= awnd_rssi_estimate(pApEntry2->rssi ,pApEntry2->netInfo.awnd_level, l_awnd_config.scaling_factor);
         if (rssi1 > rssi2)
             return 1;
         else
             return 0;
            
    }
    else 
    {
        if ((memcmp(g_awnd.fapMac, pApEntry1->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
        {   /* to find binded FAP entry first */   
            return 1;
        }
        else if ((memcmp(g_awnd.fapMac, pApEntry2->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
        {   /* to find binded FAP entry first */   
            return 0;
        }        
        else if (AWND_NET_FAP == pApEntry1->netInfo.awnd_net_type && AWND_NET_FAP == pApEntry2->netInfo.awnd_net_type)
        {   /* to chose better rssi when two FAP subnet */

            if ( pApEntry1->isPreconf != pApEntry2->isPreconf )
            {
                if(1 == pApEntry1->isPreconf)
                {
                    pHighprioAp = pApEntry1;
                    ret = 1;
                }
                else
                {
                    pHighprioAp = pApEntry2;
                    ret = 0;
                }

                if( pHighprioAp->rssi > l_awnd_config.high_rssi_threshold)
                {
                    return ret;
                }
            }

            if (pApEntry1->rssi > pApEntry2->rssi)
                return 1;
            else
                return 0;
        }
        else if (HIGH_PRIO_SUBNET(&(pApEntry1->netInfo), &(pApEntry2->netInfo)))
        {
            return 1;
        }
        else
        {
            return 0;
        }
            
    }
}

static void *_print_mac(char *str, UINT8* mac)
{
    if (!(str && mac)) return;
    AWN_LOG_INFO("%s %02x:%02x:%02x:%02x:%02x:%02x", str, mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

/* qca compatible mbssid code */
static AWND_AP_ENTRY * _find_6g_backhual_entry(AWND_SCAN_RESULT *pAwndScanResult, UINT8* lan_mac)
{
    int index = 0;
    AWND_AP_ENTRY * pApEntry = NULL;

    if (!(lan_mac && _is_vaild_mac(lan_mac)))
    {
        AWN_LOG_INFO("lan mac is unknown!");
        return NULL;
    }

    for (index = 0; index < pAwndScanResult->iApNum; index++)
    {
        // if entry from same device
        if (! memcmp(pAwndScanResult->tApEntry[index].lan_mac, lan_mac, AWND_MAC_LEN))
        {
            /* if ssid == sta.ssid not to skip */
            if (!_is_null_ssid(pAwndScanResult->tApEntry[index].ssid))
            {
                 if ((0 == strncmp(l_group_info.staGroupInfo.ssid,     pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN)) ||
                     (0 == strncmp(l_group_info.preconfGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN)))
                 {
                     AWN_LOG_INFO("%s is vaild", pAwndScanResult->tApEntry[index].ssid);
                     pApEntry = &pAwndScanResult->tApEntry[index];
                     break;
                 }
                 else
                 {
                     continue;
                 }
            }

            // just hidden ssid entry comes here.

            if (NULL == pApEntry)
            {
                pApEntry = &pAwndScanResult->tApEntry[index];
                continue;
            }

            // if A and B is both hidden, find the 6g backhual bssid by br-lan address offset
            // for the case: hidden backhual vs hidden config network
            if (_is_null_ssid(pApEntry->ssid) && _is_null_ssid(pAwndScanResult->tApEntry[index].ssid))
            {
                if(pAwndScanResult->tApEntry[index].bssid[5] == (lan_mac[5] + AWND_6G_MAC_OFFSET) % 256)
                {
                    AWN_LOG_INFO("A and B is both hidden, find the 6g backhual bssid by br-lan address offset");
                    pApEntry = &pAwndScanResult->tApEntry[index];
                    break;
                }
            }
        }
    }

    if (pApEntry)
    {
        AWN_LOG_INFO("found 6g backhual in qca compatible mbssid code");
        _print_mac("6g backhual bssid:", pApEntry->bssid);
    }

    return pApEntry;
}

#if FAST_RECONNECT_ROOTAP
/*!
*\fn           awnd_sort_scan_entry_get_second_rootAP()
*\brief        try to get secondary rootAP from scan result
*\param[in]    pAwndScanResult      state of the station
*\param[in]    band                 2G/5G/5G2/6G
*\param[in]    onlyFindFap          only to find NET_FAP when reStage less than 3
*\param[in]    tabu_flag            if need to exclude a certain mac/macs
*\param[in]    tabu_mac             a certain mac or certain macs that need to be excluded(in this function, this variable usual means the only mac from bestAP)
*\return       NULL/AWND_AP_ENTRY*
*/
AWND_AP_ENTRY *awnd_sort_scan_entry_get_second_rootAP(AWND_SCAN_RESULT *pAwndScanResult, AWND_BAND_TYPE band, UINT32 onlyFindFap, UINT8 tabu_flag, UINT8* tabu_mac, UINT8 bestap_awnd_level)
{
    int index = 0;
    int rssi1, rssi2;
    AWND_AP_ENTRY * pApEntry     = NULL;
    AWND_AP_ENTRY * pUpLevelAp   = NULL;
    AWND_AP_ENTRY * pDownLevelAp = NULL;
    AWND_AP_ENTRY * pHighRSSIAp   = NULL;
    AWND_AP_ENTRY * pLowRSSIAp = NULL;
    AWND_AP_ENTRY * pHighprioAp = NULL;
    int cur_5g_channel = 0;
#if SCAN_OPTIMIZATION
    BOOL found_fap = false;
#endif
    AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
        if (AWND_BAND_5G2 == band) {
            real_band = AWND_BAND_6G;
        }
#endif /* CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT */
#ifdef CONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE
    AWND_AP_ENTRY * pApEntry_6g_backhual = NULL;
#endif

    AWN_LOG_NOTICE("Enter awnd_sort_scan_entry_get_second_rootAP, bestap_awnd_level:%d", bestap_awnd_level);


#if CONFIG_OUTDOOR_CHANNELLIMIT
    /* reload as the channel limit config may be changed by user sometime */
    awnd_get_outdoor_channellimit(l_awnd_config.channellimit_id);
#endif

    if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
    {
        cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
    }

    for (index = 0; index < pAwndScanResult->iApNum; index++)
    {
        if (! pAwndScanResult->tApEntry[index].netInfo.id)
            continue;

        if (pAwndScanResult->tApEntry[index].netInfo.awnd_level > bestap_awnd_level)
            continue;

        if (tabu_flag)
        {
            if (0 == memcmp(pAwndScanResult->tApEntry[index].lan_mac, tabu_mac, AWND_MAC_LEN))
            {
                /* skip tabu item */
                /* AWN_LOG_NOTICE("skip tabu item:%02X:%02X:%02X:%02X:%02X:%02X", pAwndScanResult->tApEntry[index].bssid[0], pAwndScanResult->tApEntry[index].bssid[1], pAwndScanResult->tApEntry[index].bssid[2],
                                                                               pAwndScanResult->tApEntry[index].bssid[3], pAwndScanResult->tApEntry[index].bssid[4], pAwndScanResult->tApEntry[index].bssid[5]); */
                /* AWN_LOG_ERR(" --------------- is tabu, continue"); */
                continue;
            }
        }

        /* if ssid == sta.ssid not to skip */
        if (!_is_null_ssid(pAwndScanResult->tApEntry[index].ssid))
        {
            if((0 == strncmp(l_group_info.staGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN))
                || (0 == strncmp(l_group_info.preconfGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN)))
            {
                AWN_LOG_INFO("%s is vaild", pAwndScanResult->tApEntry[index].ssid);
            }
            else
            {
                continue;
            }
        }

#if CONFIG_OUTDOOR_CHANNELLIMIT
        /** channel limit - for non-US country 5G radio
         * skip process scan result.
         */
        if (AWND_BAND_5G == band && l_awnd_config.channellimit_support
            && 0 == strncmp(l_awnd_config.channellimit_id, "1", CHANNELLIMIT_LEN)
            && 0 != strncmp(l_awnd_config.special_id, SPECIALID_US, SPECIALID_LEN)
            && pAwndScanResult->tApEntry[index].channel != cur_5g_channel)
        {
            if (l_awnd_config.channellimit_start_chan != 0 && l_awnd_config.channellimit_end_chan != 0
                && (pAwndScanResult->tApEntry[index].channel < l_awnd_config.channellimit_start_chan
                    || pAwndScanResult->tApEntry[index].channel > l_awnd_config.channellimit_end_chan))
            {
                AWN_LOG_DEBUG("AWND_BAND_5G: Channel Limit: skip entry when channel(%d) is not in %d,%d, cur_5g_channel is (%d)",
                    pAwndScanResult->tApEntry[index].channel, l_awnd_config.channellimit_start_chan,
                    l_awnd_config.channellimit_end_chan, cur_5g_channel);
                continue;
            }
        }
#endif /*CONFIG_OUTDOOR_CHANNELLIMIT*/

        if (AWND_BAND_5G == band && pAwndScanResult->tApEntry[index].channel != cur_5g_channel
#if CONFIG_OUTDOOR_CHANNELLIMIT
            /* channel limit & prefer band limit is mutually exclusive */
            && (!l_awnd_config.channellimit_support || 0 != strncmp(l_awnd_config.channellimit_id, "1", CHANNELLIMIT_LEN))
#endif
            && (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
        {
            if (!((l_awnd_config.limit_scan_band1 && pAwndScanResult->tApEntry[index].channel <= 48)
                || (l_awnd_config.limit_scan_band4 && pAwndScanResult->tApEntry[index].channel >= 149)))
            {
                AWN_LOG_DEBUG("AWND_BAND_5G: skip entry when channel(%d) is not in band1 or band4", pAwndScanResult->tApEntry[index].channel);
                continue;
            }
        }

        if ( onlyFindFap && AWND_NET_FAP != pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find NET_FAP when reStage:%d less than 3", g_awnd.reStage);
            continue;
        }

        if (AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_LRE <= pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find FAP/HAP in reStage 3");
            continue;
        }

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        if (AWND_STATUS_CONNECTED == g_awnd.ethStatus && pAwndScanResult->tApEntry[index].netInfo.awnd_level > g_awnd.ethNetInfo.awnd_level)
        {
            AWN_LOG_INFO("only to find awnd_level <= myself when eth connected");
            continue;
        }
#endif

        //如果扫描到的接入点就是设置的优先接入点，直接返回该接入点
        if ((is_prefer_mac(&pAwndScanResult->tApEntry[index]) == 1) && (AWND_NET_FAP == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)) {
            if (check_unable_conn_ap_table(&pAwndScanResult->tApEntry[index], AWND_OP_CHECK_PREFER) == 1) {
                AWN_LOG_NOTICE("failed to connect this prefer ap (mac: %02X:%02X:%02X:%02X:%02X:%02X) last time, so skip it ",
                                l_mac_prefer[0],l_mac_prefer[1],l_mac_prefer[2],
                                l_mac_prefer[3],l_mac_prefer[4],l_mac_prefer[5]);
                continue;
            }
            else {
                check_unable_conn_ap_table(NULL, AWND_OP_FLUSH);
                AWN_LOG_NOTICE("get prefer_entry*** , mac: %02X:%02X:%02X:%02X:%02X:%02X",
                                l_mac_prefer[0],l_mac_prefer[1],l_mac_prefer[2],
                                l_mac_prefer[3],l_mac_prefer[4],l_mac_prefer[5]);
                /* AWN_LOG_ERR(" --------------- is prefer, return"); */
                pApEntry = &pAwndScanResult->tApEntry[index];
                return pApEntry;
            }
        }

        //如果扫描到的接入点是FAP，直接返回该接入点
        if (0 == memcmp(g_awnd.fapMac, pAwndScanResult->tApEntry[index].lan_mac, AWND_MAC_LEN))
        {
            /* AWN_LOG_ERR(" --------------- is fap, return"); */
            pApEntry = &pAwndScanResult->tApEntry[index];
            return pApEntry;
        }

        AWN_LOG_INFO("============COMPARE LOOP %d==============", index);
        AWN_LOG_INFO("New entry is BSSID:%02X:%02X:%02X:%02X:%02X:%02X, channel:%d, level:%d, rssi:%d,uplinkMask:%d, uplinkRate:%d, pathRate:%d",
            pAwndScanResult->tApEntry[index].bssid[0], pAwndScanResult->tApEntry[index].bssid[1],
            pAwndScanResult->tApEntry[index].bssid[2], pAwndScanResult->tApEntry[index].bssid[3],
            pAwndScanResult->tApEntry[index].bssid[4], pAwndScanResult->tApEntry[index].bssid[5],
            pAwndScanResult->tApEntry[index].channel, pAwndScanResult->tApEntry[index].netInfo.awnd_level,
            pAwndScanResult->tApEntry[index].rssi, pAwndScanResult->tApEntry[index].uplinkMask,
            pAwndScanResult->tApEntry[index].uplinkRate, pAwndScanResult->tApEntry[index].pathRate);
        if (pApEntry) {
            AWN_LOG_INFO("Last entry is BSSID:%02X:%02X:%02X:%02X:%02X:%02X, channel:%d, level:%d, rssi:%d, uplinkRate:%d, pathRate:%d",
                pApEntry->bssid[0], pApEntry->bssid[1], pApEntry->bssid[2],pApEntry->bssid[3], pApEntry->bssid[4], pApEntry->bssid[5],
                pApEntry->channel, pApEntry->netInfo.awnd_level, pApEntry->rssi, pApEntry->uplinkRate, pApEntry->pathRate);
        }

        if (NULL == pApEntry)
        {
            pApEntry = &pAwndScanResult->tApEntry[index];
        }
        else if (IN_SAME_SUBNET(&(pAwndScanResult->tApEntry[index].netInfo), &(pApEntry->netInfo)))
        {
            /* 1.RSSI of up level ap >= AWND_HIGH_RSSI_THRESHOLD, choose up level ap.*/
            if (pAwndScanResult->tApEntry[index].netInfo.awnd_level != pApEntry->netInfo.awnd_level)
            {
                if (pAwndScanResult->tApEntry[index].netInfo.awnd_level < pApEntry->netInfo.awnd_level)
                {
                    pUpLevelAp   = &pAwndScanResult->tApEntry[index];
                    pDownLevelAp = pApEntry;
                }
                else
                {
                    pUpLevelAp   = pApEntry;
                    pDownLevelAp = &pAwndScanResult->tApEntry[index];
                }

                if (pUpLevelAp->rssi > l_awnd_config.high_rssi_threshold)
                {
                    pApEntry = pUpLevelAp;
                    continue;
                }
            }

            /* 2.RSSI of one ap < AWND_LOW_RSSI_THRESHOLD, another increase more than AWND_BEST_EFFORT_RSSI_INC, choose another.*/
            if ((pAwndScanResult->tApEntry[index].rssi < l_awnd_config.low_rssi_threshold || pApEntry->rssi < l_awnd_config.low_rssi_threshold)
                && abs(pAwndScanResult->tApEntry[index].rssi - pApEntry->rssi) >= l_awnd_config.best_effort_rssi_inc)
            {
                if (pAwndScanResult->tApEntry[index].rssi > pApEntry->rssi)
                {

                    pHighRSSIAp = &pAwndScanResult->tApEntry[index];
                    pLowRSSIAp  = pApEntry;
                }
                else
                {
                    pHighRSSIAp = pApEntry;
                    pLowRSSIAp  = &pAwndScanResult->tApEntry[index];
                }

                if ((pHighRSSIAp->netInfo.awnd_level < pLowRSSIAp->netInfo.awnd_level)
                    || (pHighRSSIAp->uplinkMask & (AWND_BACKHAUL_ETH | AWND_BACKHAUL_PLC))
                    || (pHighRSSIAp->uplinkRate > l_awnd_config.best_effort_uplink_rate))
                {
                    pApEntry = pHighRSSIAp;
                    continue;
                }
            }

            /* if one AP is preconf backhaul, choose the preconf backhaul */
            if ( pAwndScanResult->tApEntry[index].isPreconf != pApEntry->isPreconf )
            {
                if(1 == pAwndScanResult->tApEntry[index].isPreconf)
                {
                    pApEntry = &pAwndScanResult->tApEntry[index];

                }
                continue;
            }

            /* 3. caculate (backhaulRate * apRate)/(backhaulRate + apRate) to choose ap. if backhaulRate is 0, choose another.*/
            if (pAwndScanResult->tApEntry[index].pathRate || pApEntry->pathRate)
            {
                if (pAwndScanResult->tApEntry[index].pathRate > pApEntry->pathRate)
                    pApEntry = &pAwndScanResult->tApEntry[index];
                continue;
            }

            /* 4. if both backhaulRate are 0, use rssi to choose ap.*/
            rssi1= awnd_rssi_estimate(pAwndScanResult->tApEntry[index].rssi ,pAwndScanResult->tApEntry[index].netInfo.awnd_level, l_awnd_config.scaling_factor);
            rssi2= awnd_rssi_estimate(pApEntry->rssi ,pApEntry->netInfo.awnd_level, l_awnd_config.scaling_factor);
            if (rssi1 > rssi2)
                pApEntry = &pAwndScanResult->tApEntry[index];
        }
        else
        {
            if ((memcmp(g_awnd.fapMac, pApEntry->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {
                continue;
            }

            if ((memcmp(g_awnd.fapMac, pAwndScanResult->tApEntry[index].netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {   /* to find binded FAP entry first */
                pApEntry = &pAwndScanResult->tApEntry[index];
                continue;
            }

            if (AWND_NET_FAP == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type && AWND_NET_FAP == pApEntry->netInfo.awnd_net_type)
            {   /* to chose better rssi when two FAP subnet */
                if ( pAwndScanResult->tApEntry[index].isPreconf != pApEntry->isPreconf )
                {
                    /* if one is preconf backhual and the rssi is higher than high_rssi_threshold, choose it  */
                    if(pAwndScanResult->tApEntry[index].isPreconf == 1)
                    {
                        pHighprioAp = &pAwndScanResult->tApEntry[index];
                    }
                    else
                    {
                        pHighprioAp = pApEntry;
                    }
                    if (pHighprioAp->rssi > l_awnd_config.high_rssi_threshold)
                    {
                        pApEntry = pHighprioAp;
                        continue;
                    }
                }
                /* isPreconf equal or pHighprioAp not higher than high_rssi_threshold */
                if (pAwndScanResult->tApEntry[index].rssi > pApEntry->rssi)
                {
                    pApEntry = &pAwndScanResult->tApEntry[index];
                }
            }
            else if (HIGH_PRIO_SUBNET(&(pAwndScanResult->tApEntry[index].netInfo), &(pApEntry->netInfo)))
            {
                pApEntry = &pAwndScanResult->tApEntry[index];
            }
        }
    }

    if (NULL != pApEntry)
    {
#ifdef CONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE
        if (AWND_BAND_5G2 == band)  // 6G
        {
            pApEntry_6g_backhual = _find_6g_backhual_entry(pAwndScanResult, pApEntry->lan_mac);
            if (pApEntry_6g_backhual)
            {
                pApEntry = pApEntry_6g_backhual;
            }
        }
#endif

        AWN_LOG_INFO("BESTAP:ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%d, uplinkRate:%d, pathRate:%d, awnd_net_type:%-3d, awnd_weight:%-3d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
                pApEntry->ssid, pApEntry->bssid[0], pApEntry->bssid[1], pApEntry->bssid[2],pApEntry->bssid[3],
                pApEntry->bssid[4], pApEntry->bssid[5], pApEntry->rssi, pApEntry->uplinkRate, pApEntry->pathRate,
                pApEntry->netInfo.awnd_net_type, pApEntry->netInfo.awnd_weight,
                pApEntry->netInfo.awnd_mac[0],pApEntry->netInfo.awnd_mac[1],pApEntry->netInfo.awnd_mac[2],
                pApEntry->netInfo.awnd_mac[3],pApEntry->netInfo.awnd_mac[4],pApEntry->netInfo.awnd_mac[5]);
    }
    return pApEntry;
}
#endif

AWND_AP_ENTRY *awnd_sort_scan_entry(AWND_SCAN_RESULT *pAwndScanResult, AWND_BAND_TYPE band, UINT32 onlyFindFap)
{
    int index = 0;
    int rssi1, rssi2;
    AWND_AP_ENTRY * pApEntry     = NULL;
    AWND_AP_ENTRY * pUpLevelAp   = NULL;
    AWND_AP_ENTRY * pDownLevelAp = NULL;
    AWND_AP_ENTRY * pHighRSSIAp   = NULL;
    AWND_AP_ENTRY * pLowRSSIAp = NULL;     
    AWND_AP_ENTRY * pHighprioAp = NULL;     
    int cur_5g_channel = 0;
	AWND_AP_ENTRY * pApEntry_6g_backhual = NULL;

#if SCAN_OPTIMIZATION
    BOOL found_fap = false;
#endif
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    bool find_ai_roaming_target = false;
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
    AWND_REAL_BAND_TYPE real_band = band;

    real_band = _get_real_band_type(band);
    if (AWND_OK != (awnd_get_backhaul_ap_channel(AWND_BAND_5G, &cur_5g_channel)))
    {
        cur_5g_channel = g_awnd.rootAp[AWND_BAND_5G].channel;
    }

    for (index = 0; index < pAwndScanResult->iApNum; index++)
    {
        if (! pAwndScanResult->tApEntry[index].netInfo.id)
            continue;

#if SCAN_OPTIMIZATION
        if (AWND_BAND_5G == band && g_awnd.bindStatus < AWND_BIND_OVER && g_awnd.scan_one_more_time == -1 &&
            _is_null_ssid(pAwndScanResult->tApEntry[index].ssid) && 
            _is_vaild_mac(pAwndScanResult->tApEntry[index].bssid) &&
            pAwndScanResult->tApEntry[index].netInfo.awnd_level == 0)
        {
            /*find fap in 5G's scan result, if not exist, scan one more time. */
            found_fap = true;
            g_awnd.scan_one_more_time = 0;
        }
#endif
        /* if ssid == sta.ssid not to skip */
        if (!_is_null_ssid(pAwndScanResult->tApEntry[index].ssid))
        {
            if((0 == strncmp(l_group_info.staGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN))
                || (0 == strncmp(l_group_info.preconfGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN)))
            {
                AWN_LOG_INFO("%s is vaild", pAwndScanResult->tApEntry[index].ssid);
            }
            else
            {
                continue;
            }
        }

        if (AWND_BAND_5G == band && pAwndScanResult->tApEntry[index].channel != cur_5g_channel
            && (l_awnd_config.limit_scan_band1 || l_awnd_config.limit_scan_band4))
        {
            if (!((l_awnd_config.limit_scan_band1 && pAwndScanResult->tApEntry[index].channel <= 48)
                || (l_awnd_config.limit_scan_band4 && pAwndScanResult->tApEntry[index].channel >= 149)))
            {
                AWN_LOG_DEBUG("AWND_BAND_5G: skip entry when channel(%d) is not in band1 or band4", pAwndScanResult->tApEntry[index].channel);
                continue;
            }
        }

        //发现优先节点，但是还未连接，需要重新扫描，等待
        if(is_prefer_mac(&pAwndScanResult->tApEntry[index]) == 1 && AWND_NET_LRE == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)
        {   
            //等待优先节点接入
            if(l_wait_prefer_connect < 15)
            {
                AWN_LOG_NOTICE("l_wait_prefer_connect : %d",l_wait_prefer_connect);
                l_wait_prefer_connect++;
                l_awnd_scan_table.scan_fast = 1;
                return NULL;
            }
        }

        if ( onlyFindFap && AWND_NET_FAP != pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find NET_FAP when reStage:%d less than 3", g_awnd.reStage);
            continue;
        }

        if (AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_LRE <= pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find FAP/HAP in reStage 3");
            continue;
        }

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        if (AWND_STATUS_CONNECTED == g_awnd.ethStatus && pAwndScanResult->tApEntry[index].netInfo.awnd_level > g_awnd.ethNetInfo.awnd_level)
        {
            AWN_LOG_INFO("only to find awnd_level <= myself when eth connected");
            continue;
        }
#endif

        //如果扫描到的接入点就是设置的优先接入点，直接返回该接入点
        if ((is_prefer_mac(&pAwndScanResult->tApEntry[index]) == 1) && (AWND_NET_FAP == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)) {
            if (check_unable_conn_ap_table(&pAwndScanResult->tApEntry[index], AWND_OP_CHECK_PREFER) == 1) {
                AWN_LOG_NOTICE("failed to connect this prefer ap (mac: %02X:%02X:%02X:%02X:%02X:%02X) last time, so skip it ",
                                l_mac_prefer[0],l_mac_prefer[1],l_mac_prefer[2],
                                l_mac_prefer[3],l_mac_prefer[4],l_mac_prefer[5]);
                continue;
            }
            else {
                check_unable_conn_ap_table(NULL, AWND_OP_FLUSH);
                AWN_LOG_NOTICE("get prefer_entry*** , mac: %02X:%02X:%02X:%02X:%02X:%02X",
                                l_mac_prefer[0],l_mac_prefer[1],l_mac_prefer[2],
                                l_mac_prefer[3],l_mac_prefer[4],l_mac_prefer[5]);
                pApEntry = &pAwndScanResult->tApEntry[index];
                return pApEntry;
            }
        }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        //如果扫描到的接入点就是AI ROAMING计算得到的优先接入点，直接返回该接入点
        if ((is_ai_roaming_mac(&pAwndScanResult->tApEntry[index]) == 1) && (AWND_NET_FAP == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type)) {
            if (check_unable_conn_ap_table(&pAwndScanResult->tApEntry[index], AWND_OP_CHECK_PREFER) == 1) {
                AWN_LOG_NOTICE("failed to connect this ai roaming ap (mac: %02X:%02X:%02X:%02X:%02X:%02X) last time, so skip it ",
                                l_mac_ai_roaming_target[0],l_mac_ai_roaming_target[1],l_mac_ai_roaming_target[2],
                                l_mac_ai_roaming_target[3],l_mac_ai_roaming_target[4],l_mac_ai_roaming_target[5]);
                continue;
            }
            else {
                check_unable_conn_ap_table(NULL, AWND_OP_FLUSH);
                AWN_LOG_NOTICE("get ai_roaming_entry*** , mac: %02X:%02X:%02X:%02X:%02X:%02X",
                                l_mac_ai_roaming_target[0],l_mac_ai_roaming_target[1],l_mac_ai_roaming_target[2],
                                l_mac_ai_roaming_target[3],l_mac_ai_roaming_target[4],l_mac_ai_roaming_target[5]);
                pApEntry = &pAwndScanResult->tApEntry[index];
                find_ai_roaming_target = true;
                continue;
            }
        }
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
        AWN_LOG_INFO("============COMPARE LOOP %d==============", index);
        AWN_LOG_INFO("New entry is BSSID:%02X:%02X:%02X:%02X:%02X:%02X, channel:%d, level:%d, rssi:%d,uplinkMask:%d, uplinkRate:%d, pathRate:%d", 
            pAwndScanResult->tApEntry[index].bssid[0], pAwndScanResult->tApEntry[index].bssid[1],
            pAwndScanResult->tApEntry[index].bssid[2], pAwndScanResult->tApEntry[index].bssid[3],
            pAwndScanResult->tApEntry[index].bssid[4], pAwndScanResult->tApEntry[index].bssid[5], 
            pAwndScanResult->tApEntry[index].channel, pAwndScanResult->tApEntry[index].netInfo.awnd_level,
            pAwndScanResult->tApEntry[index].rssi, pAwndScanResult->tApEntry[index].uplinkMask, 
            pAwndScanResult->tApEntry[index].uplinkRate, pAwndScanResult->tApEntry[index].pathRate);
        if (pApEntry) {
            AWN_LOG_INFO("Last entry is BSSID:%02X:%02X:%02X:%02X:%02X:%02X, channel:%d, level:%d, rssi:%d, uplinkRate:%d, pathRate:%d",
                pApEntry->bssid[0], pApEntry->bssid[1], pApEntry->bssid[2],pApEntry->bssid[3], pApEntry->bssid[4], pApEntry->bssid[5], 
                pApEntry->channel, pApEntry->netInfo.awnd_level, pApEntry->rssi, pApEntry->uplinkRate, pApEntry->pathRate);

        }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        if (find_ai_roaming_target)
        {
            continue;
        }
#endif
        if (NULL == pApEntry)
        {
            AWN_LOG_INFO("NULL == pApEntry");
            pApEntry = &pAwndScanResult->tApEntry[index];
        }
        else if (IN_SAME_SUBNET(&(pAwndScanResult->tApEntry[index].netInfo), &(pApEntry->netInfo)))
        {
            AWN_LOG_INFO("IN_SAME_SUBNET");
            
            /* isp dcmp's has the lowest priority */
            if ( pApEntry->isPreconfig == 1 )
            {
                if(1 == pAwndScanResult->tApEntry[index].isConfig || 1 == pAwndScanResult->tApEntry[index].isPreconf)
                {
                    AWN_LOG_INFO("Last entry is isp dcmp preconfig, new entry is config or preconf, so change it");
                    pApEntry = &pAwndScanResult->tApEntry[index];
                    continue;
                }
            }
            if ( pApEntry->isConfig == 1 || pApEntry->isPreconf == 1)
            {
                if ( pAwndScanResult->tApEntry[index].isPreconfig == 1 )
                {
                    AWN_LOG_INFO("Last entry is config or preconf, new entry is isp dcmp preconfig, so skip it");
                    continue;
                }
            }

            /* 1.RSSI of up level ap >= AWND_HIGH_RSSI_THRESHOLD, choose up level ap.*/
            if (pAwndScanResult->tApEntry[index].netInfo.awnd_level != pApEntry->netInfo.awnd_level)
            {
                if (pAwndScanResult->tApEntry[index].netInfo.awnd_level < pApEntry->netInfo.awnd_level)
                {
                    pUpLevelAp   = &pAwndScanResult->tApEntry[index];
                    pDownLevelAp = pApEntry;
                }
                else
                {
                    pUpLevelAp   = pApEntry;
                    pDownLevelAp = &pAwndScanResult->tApEntry[index];                    
                }
                
                if (pUpLevelAp->rssi > l_awnd_config.high_rssi_threshold)
                {
                    pApEntry = pUpLevelAp;
                    continue;
                }                    
            }

            /* 2.RSSI of one ap < AWND_LOW_RSSI_THRESHOLD, another increase more than AWND_BEST_EFFORT_RSSI_INC, choose another.*/
            if ((pAwndScanResult->tApEntry[index].rssi < l_awnd_config.low_rssi_threshold || pApEntry->rssi < l_awnd_config.low_rssi_threshold) 
                && abs(pAwndScanResult->tApEntry[index].rssi - pApEntry->rssi) >= l_awnd_config.best_effort_rssi_inc)
            {
                if (pAwndScanResult->tApEntry[index].rssi > pApEntry->rssi)
                {

                    pHighRSSIAp = &pAwndScanResult->tApEntry[index];
                    pLowRSSIAp  = pApEntry;
                }
                else
                {
                    pHighRSSIAp = pApEntry;
                    pLowRSSIAp  = &pAwndScanResult->tApEntry[index];                    
                }
                
                if ((pHighRSSIAp->netInfo.awnd_level < pLowRSSIAp->netInfo.awnd_level) 
                    || (pHighRSSIAp->uplinkMask & (AWND_BACKHAUL_ETH | AWND_BACKHAUL_PLC))
                    || (pHighRSSIAp->uplinkRate > l_awnd_config.best_effort_uplink_rate))
                {                
                    pApEntry = pHighRSSIAp;
                    continue;
                }
            }

            /* if one AP is preconf backhaul, choose the preconf backhaul */
            if ( pAwndScanResult->tApEntry[index].isPreconf != pApEntry->isPreconf )
            {
                if(1 == pAwndScanResult->tApEntry[index].isPreconf)
                {
                    pApEntry = &pAwndScanResult->tApEntry[index];

                }
                continue;
            }

            /* 3. caculate (backhaulRate * apRate)/(backhaulRate + apRate) to choose ap. if backhaulRate is 0, choose another.*/
            if (pAwndScanResult->tApEntry[index].pathRate || pApEntry->pathRate)
            {
                if (pAwndScanResult->tApEntry[index].pathRate > pApEntry->pathRate)
                    pApEntry = &pAwndScanResult->tApEntry[index]; 
                continue;
            } 
  

            /* 4. if both backhaulRate are 0, use rssi to choose ap.*/
            rssi1= awnd_rssi_estimate(pAwndScanResult->tApEntry[index].rssi ,pAwndScanResult->tApEntry[index].netInfo.awnd_level, l_awnd_config.scaling_factor);
            rssi2= awnd_rssi_estimate(pApEntry->rssi ,pApEntry->netInfo.awnd_level, l_awnd_config.scaling_factor);
            if (rssi1 > rssi2)
                pApEntry = &pAwndScanResult->tApEntry[index]; 
            
        }
        else 
        {
            if ((memcmp(g_awnd.fapMac, pApEntry->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {
                continue;
            }

            if ((memcmp(g_awnd.fapMac, pAwndScanResult->tApEntry[index].netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {   /* to find binded FAP entry first */   
                pApEntry = &pAwndScanResult->tApEntry[index];
                continue;
            }

            if (AWND_NET_FAP == pAwndScanResult->tApEntry[index].netInfo.awnd_net_type && AWND_NET_FAP == pApEntry->netInfo.awnd_net_type)
            {   /* to chose better rssi when two FAP subnet */
                if ( pAwndScanResult->tApEntry[index].isPreconf != pApEntry->isPreconf )
                {
                    /* if one is preconf backhual and the rssi is higher than high_rssi_threshold, choose it  */
                    if(pAwndScanResult->tApEntry[index].isPreconf == 1)
                    {
                        pHighprioAp = &pAwndScanResult->tApEntry[index];
                    }
                    else
                    {
                        pHighprioAp = pApEntry;
                    }
                    if (pHighprioAp->rssi > l_awnd_config.high_rssi_threshold)
                    {
                        pApEntry = pHighprioAp;
                        continue;
                    }
                }
                /* isPreconf equal or pHighprioAp not higher than high_rssi_threshold */
                if (pAwndScanResult->tApEntry[index].rssi > pApEntry->rssi)
                {
                    pApEntry = &pAwndScanResult->tApEntry[index];
                }
            }
            else if (HIGH_PRIO_SUBNET(&(pAwndScanResult->tApEntry[index].netInfo), &(pApEntry->netInfo)))
            {
                pApEntry = &pAwndScanResult->tApEntry[index];
            }
        }
    }

#if SCAN_OPTIMIZATION
    if (!found_fap && AWND_BAND_5G == band && g_awnd.scan_one_more_time == -1)
    {
        g_awnd.scan_one_more_time = 1;
    }
#endif
    if (NULL != pApEntry)
    {
        if ((g_awnd.enable6g && AWND_REAL_BAND_6G == real_band) || (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band))  // 6G1 + 6G2
        {
            pApEntry_6g_backhual = _find_6g_backhual_entry(pAwndScanResult, pApEntry->lan_mac);
            if (pApEntry_6g_backhual)
            {
                pApEntry = pApEntry_6g_backhual;
            }
        }
        AWN_LOG_INFO("BESTAP:ssid:%-32s, bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%d, uplinkRate:%d, pathRate:%d, awnd_net_type:%-3d, awnd_weight:%-3d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
                pApEntry->ssid, pApEntry->bssid[0], pApEntry->bssid[1], pApEntry->bssid[2],pApEntry->bssid[3], 
                pApEntry->bssid[4], pApEntry->bssid[5], pApEntry->rssi, pApEntry->uplinkRate, pApEntry->pathRate,
                pApEntry->netInfo.awnd_net_type, pApEntry->netInfo.awnd_weight,
                pApEntry->netInfo.awnd_mac[0],pApEntry->netInfo.awnd_mac[1],pApEntry->netInfo.awnd_mac[2],
                pApEntry->netInfo.awnd_mac[3],pApEntry->netInfo.awnd_mac[4],pApEntry->netInfo.awnd_mac[5]);
    }    
        
    return pApEntry;

}

AWND_AP_ENTRY * awnd_find_scan_entry(AWND_SCAN_RESULT *pAwndScanResult, UINT8* lan_mac, UINT8 *bssid, AWND_BAND_TYPE band)
{
    int index = 0;
    AWND_AP_ENTRY * pApEntry = NULL;
    int mac_known = 0;
	AWND_REAL_BAND_TYPE real_band = band;

    mac_known = (lan_mac && _is_vaild_mac(lan_mac));
    
	 real_band = _get_real_band_type(band);
	if ((g_awnd.enable6g && AWND_REAL_BAND_6G == real_band) || (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band))  // 6G1 + 6G2
	{
		pApEntry = _find_6g_backhual_entry(pAwndScanResult, lan_mac);
		if (pApEntry)
		{
			return pApEntry;
		}
	}

    if (!mac_known && !bssid) {
        return NULL;
    }

    for (index = 0; index < pAwndScanResult->iApNum; index++)
    {
		if (_is_null_ssid(pAwndScanResult->tApEntry[index].ssid)
			&& ((mac_known && ! memcmp(pAwndScanResult->tApEntry[index].lan_mac, lan_mac, AWND_MAC_LEN))
				|| (!mac_known && ! memcmp(pAwndScanResult->tApEntry[index].bssid, bssid, AWND_MAC_LEN)))) 
		{
			pApEntry = &(pAwndScanResult->tApEntry[index]);
			break;
		}
			
    }

    if (NULL == pApEntry)
    {
		for (index = 0; index < pAwndScanResult->iApNum; index++)
		{
			/* if ssid != sta.ssid then skip */
			if (!_is_null_ssid(pAwndScanResult->tApEntry[index].ssid))
			{
				if((0 != strncmp(l_group_info.staGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN))
				    && (0 != strncmp(l_group_info.preconfGroupInfo.ssid, pAwndScanResult->tApEntry[index].ssid, AWND_MAX_SSID_LEN)))
				{
				    continue;
				}
			}

			if ((mac_known && ! memcmp(pAwndScanResult->tApEntry[index].lan_mac, lan_mac, AWND_MAC_LEN))
				|| (!mac_known && ! memcmp(pAwndScanResult->tApEntry[index].bssid, bssid, AWND_MAC_LEN)))
			{
				pApEntry = &(pAwndScanResult->tApEntry[index]);
				break;
			}
		}    
    }	
        
    return pApEntry;
}

void awnd_transform_bssid_by_low_byte_increase(AWND_BAND_TYPE srcBand,  UINT8 *srcBssid, AWND_AP_ENTRY *pTmpEntry)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (band > srcBand)
        {
            _mac_compute(pTmpEntry[band].bssid, srcBssid, band-srcBand, 1);
        }
        else if (band < srcBand)
        {
            _mac_compute(pTmpEntry[band].bssid, srcBssid, srcBand-band, 0);        
        }
    }
        
    return ;
}

/******************************************************************************************
    https://sohoiconfluence.rd.tp-link.net/pages/viewpage.action?pageId=19674862
    QCA Deco DUT MBSSID rule:
    在ath0的MAC的基础上，Byte1-Byte5完全相同，Byte0：bit1本地化，bit2开始根据接口创建的次序，依次增长。
    getfirm MAC:   50-C7-BF-96-FE-EB
    wifi0 Link encap:UNSPEC HWaddr 50-C7-BF-96-FE-ED                br-lan MAC + 2
    ath0 Link encap:Ethernet HWaddr 50:C7:BF:96:FE:ED wifi0的MAC
    ath02 Link encap:Ethernet HWaddr 56:C7:BF:96:FE:ED wifi0的MAC(50) + local(2) + MBSS_1(b0000 0100 4) = 56
    ath01 Link encap:Ethernet HWaddr 5A:C7:BF:96:FE:ED wifi0的MAC(50) + local(2) + MBSS_2(b0000 1000 8) = 5A
    ath04 Link encap:Ethernet HWaddr 5E:C7:BF:96:FE:ED wifi0的MAC(50) + local(2) + MBSS_3(b0000 1100 c) = 5E
    ath05 Link encap:Ethernet HWaddr 62:C7:BF:96:FE:ED wifi0的MAC(50 0101 0000) + local(2) + MBSS_4(0001 0000 ) = 62

    XE200 6G MBSSID rule:
    backhaul STA BSSID(ath23) = wifi2 = 50:C7:BF:96:FE:EF
    backhaul AP BSSID (ath22) = ath23 + SET_LOCALADDR + (Byte0[2-5]= (Byte0[2-5] + Byte5[0-3])%15) = 52:C7:BF:96:FE:EF
*******************************************************************************************/
#define QCA_MBSS_UCIDX_MASK (0xf)
static void awnd_calculate_bssid_for_qca(AWND_BAND_TYPE srcBand, UINT8* lan_mac, AWND_AP_ENTRY *pTmpEntry, UINT8 isPreconf, UINT8 *srcBssid)
{
    AWND_BAND_TYPE band;
    UINT8 ucidx_value = 0;
    UINT8 base_addr[AWND_MAC_LEN] = {0};
    AWND_AP_ENTRY  *pMatchAp = NULL;
    AWND_BAND_TYPE base_Band = srcBand;
    AWND_REAL_BAND_TYPE src_real_band = 0;
    AWND_REAL_BAND_TYPE real_band = 0;
    UINT8 *base_Bssid = srcBssid;
    UINT8 has_low_band_entry = 0;
    UINT8 vether_base = 0;

    /* connot to calculate 2G/5G from 6G ath22 bssid */
    src_real_band = _get_real_band_type(srcBand);
    if ((g_awnd.enable6g && AWND_REAL_BAND_6G == src_real_band) || (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == src_real_band)) {
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
            if (band != srcBand) {
                pMatchAp = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], lan_mac, NULL, band);
                if (NULL != pMatchAp) {
                    base_Band = band;
                    base_Bssid = pMatchAp->bssid;
                    memcpy(pTmpEntry[band].bssid, pMatchAp->bssid, AWND_MAC_LEN);
                    AWN_LOG_DEBUG("srcBand:%d is 6g, to get new src_Band:%d base_Bssid:%02X:%02X:%02X:%02X:%02X:%02X",
                        srcBand, base_Band, base_Bssid[0], base_Bssid[1],
                        base_Bssid[2], base_Bssid[3], base_Bssid[4], base_Bssid[5]);
                    has_low_band_entry = 1;
                    break;
                }
            }
        }

        /* calculate for other band(not 6g or pMatchAp's band) */
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
            real_band = _get_real_band_type(band);
            if (band != srcBand && (g_awnd.enable6g && real_band >= AWND_REAL_BAND_6G)) {
                /* 6G/6G2 */
                _mac_compute(base_addr, lan_mac, band + 2, 1);

                vether_base = base_addr[5] & QCA_MBSS_UCIDX_MASK;
                /* Byte0[2-5]= (Byte0[2-5] + Byte5[0-3])%15 */
                vether_base = (vether_base + ((base_addr[0] & (QCA_MBSS_UCIDX_MASK << 2)) >> 2)) % QCA_MBSS_UCIDX_MASK;
                base_addr[0] = (base_addr[0] & (((~QCA_MBSS_UCIDX_MASK) << 2) + 3)) | (vether_base << 2);

                base_addr[0] |= 0x2; // SET_LOCALADDR
                memcpy(pTmpEntry[band].bssid, base_addr, AWND_MAC_LEN);
            }
            else if (band != srcBand && band != base_Band) {
                /* 2G/5G/5G2 */
                if (has_low_band_entry) {
                    if (band > base_Band)
                    {
                        _mac_compute(pTmpEntry[band].bssid, base_Bssid, (band - base_Band), 1);
                    }
                    else if (band < base_Band)
                    {
                        _mac_compute(pTmpEntry[band].bssid, base_Bssid, (base_Band - band), 0);
                    }
                }
                else {
                    _mac_compute(base_addr, lan_mac, band + 2, 1);
                    memcpy(pTmpEntry[band].bssid, base_addr, AWND_MAC_LEN);
                }
                AWN_LOG_DEBUG("pTmpEntry[%d].Bssid:%02X:%02X:%02X:%02X:%02X:%02X base_Band:%d",
                    band, pTmpEntry[band].bssid[0], pTmpEntry[band].bssid[1], pTmpEntry[band].bssid[2],
                    pTmpEntry[band].bssid[3], pTmpEntry[band].bssid[4], pTmpEntry[band].bssid[5], base_Band);
            }
        }

        return ;
    }
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        real_band = _get_real_band_type(band);
        if ((g_awnd.enable6g && AWND_REAL_BAND_6G == real_band) || (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band)) {
            /* QCA 6G XE200  ath22 6G backhaul AP BSSID = wifi2 BSSID + SET_LOCALADDR + (Byte0[2-5]= (Byte0[2-5] + Byte5[0-3])%15) */
            if (band != srcBand) {
                _mac_compute(base_addr, lan_mac, band + 2, 1);

                vether_base = base_addr[5] & QCA_MBSS_UCIDX_MASK;
                /* Byte0[2-5]= (Byte0[2-5] + Byte5[0-3])%15 */
                vether_base = (vether_base + ((base_addr[0] & (QCA_MBSS_UCIDX_MASK << 2)) >> 2)) % QCA_MBSS_UCIDX_MASK;
                base_addr[0] = (base_addr[0] & (((~QCA_MBSS_UCIDX_MASK) << 2) + 3)) | (vether_base << 2);

                base_addr[0] |= 0x2; // SET_LOCALADDR

                /* notBind to cal BSSID of config ap(ath24) = (ath22 + 2)%16 */
                if (g_awnd.notBind && g_awnd.bindStatus < AWND_BIND_START && 0 == isPreconf) {
                   base_addr[5] = (base_addr[5] & ~QCA_MBSS_UCIDX_MASK) | (((base_addr[5] & QCA_MBSS_UCIDX_MASK) + 2) % (QCA_MBSS_UCIDX_MASK + 1));
                }

                memcpy(pTmpEntry[band].bssid, base_addr, AWND_MAC_LEN);
            }
        }
        else
        {
            if (band > srcBand)
            {
                _mac_compute(pTmpEntry[band].bssid, srcBssid, band-srcBand, 1);
            }
            else if (band < srcBand)
            {
                _mac_compute(pTmpEntry[band].bssid, srcBssid, srcBand-band, 0);
            }
        }
        AWN_LOG_DEBUG("pTmpEntry[%d].Bssid:%02X:%02X:%02X:%02X:%02X:%02X",
        band, pTmpEntry[band].bssid[0], pTmpEntry[band].bssid[1], pTmpEntry[band].bssid[2],
        pTmpEntry[band].bssid[3], pTmpEntry[band].bssid[4], pTmpEntry[band].bssid[5]);
    }
    return ;
}

/******************************************************************************************
    https://sohoiconfluence.rd.tp-link.net/pages/viewpage.action?pageId=19674862
    BCM Deco DUT MBSSID rule:
    DUT lan_mac  24G:lan_mac + 2; 5G:lan_mac + 3; 5G2:lan_mac + 4; ==> cur_etheraddr

    (1) vether_base为cur_etheraddr的Byte5+1  (只改bit0-2 不向上增长)
    vether_base =  cur_etheraddr[0-4] +
                    (cur_etheraddr.octet[5] & ~(7)) | ((cur_etheraddr.octet[5] + 1) & 7);

    (2) vether_base.octet[0]的bit2-4 = (vether_base.octet[0]的bit2-4)+(cur_etheraddr.octet[5]的bit0-2)   (只改此3bit，不向高bit进位)
    uint8 ucidx_value = cur_etheraddr.octet[5] & 7;
    vether_base.octet[0] = (vether_base.octet[0] & (((~(7)) << 2) + 3)) |
        ((vether_base.octet[0] + (ucidx_value << 2)) & (7 << 2));

    (3) Byte0本地化 SET_LOCALADDR(vether_base)

    (XE75 6G backhaul is wl13, 6G main is wl11)

    backhaul sta(wl0): cur_etheraddr   00:19:e0:07:01:32
    backhaul ap(wl01): vether_base     0a:19:e0:07:01:33
    main     ap(wl02): vether_base + 1 0a:19:e0:07:01:34 (只改最低3bit)
    guest    ap(wl03): vether_base + 2 0a:19:e0:07:01:35
    config   ap(wl04): vether_base + 3 0a:19:e0:07:01:36
*******************************************************************************************/
#define MBSS_UCIDX_MASK (0x7)
static void awnd_calculate_bssid_for_bcm(AWND_BAND_TYPE srcBand, UINT8* lan_mac, AWND_AP_ENTRY *pTmpEntry, UINT8 isPreconf, UINT8 *srcBssid)
{
    AWND_BAND_TYPE band;
    UINT8 ucidx_value = 0;
    UINT8 base_addr[AWND_MAC_LEN] = {0};
    UINT8 vether_base = 0;
    AWND_REAL_BAND_TYPE real_band = 0;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        real_band = _get_real_band_type(band);
        //if (band != srcBand)
        {   /* get cur_etheraddr */
            _mac_compute(base_addr, lan_mac, band + 2, 1);

            ucidx_value = base_addr[5] & MBSS_UCIDX_MASK;
            vether_base = (base_addr[5] & ~MBSS_UCIDX_MASK) | ((base_addr[5] + 1) & MBSS_UCIDX_MASK);

            if ((g_awnd.enable6g && AWND_REAL_BAND_6G == real_band) || (g_awnd.enable6g2 && AWND_REAL_BAND_6G2 == real_band))
            {   /* 6G wl13: vether_base + 2 */
                base_addr[5] = (vether_base & ~MBSS_UCIDX_MASK) | ((vether_base + 2) & MBSS_UCIDX_MASK);
            }
            else
            {   /* 2G/5G wlx1 vether_base */
                base_addr[5] = vether_base;
            }

            base_addr[0] = (base_addr[0] & (((~MBSS_UCIDX_MASK) << 2) + 3)) |
                            ((base_addr[0] + (ucidx_value << 2)) & (MBSS_UCIDX_MASK << 2));
            base_addr[0] |= 0x2; // SET_LOCALADDR

            /* notBind to cal BSSID of config ap(wlx4) */
            if (g_awnd.notBind && g_awnd.bindStatus < AWND_BIND_START && 0 == isPreconf) {
               base_addr[5] = (base_addr[5] & ~MBSS_UCIDX_MASK) | ((vether_base + 3) & MBSS_UCIDX_MASK);
            }

            memcpy(pTmpEntry[band].bssid, base_addr, AWND_MAC_LEN);
        }
    }

    return ;
}

static void awnd_transform_bssid_from_select_band(AWND_BAND_TYPE selectband, UINT8* lan_mac, AWND_AP_ENTRY *pTmpEntry, UINT8 isPreconf, UINT8 *srcBssid)
{
    UINT8 base_addr[AWND_MAC_LEN] = {0};
    UINT8 vether_base = 0;
    /* get cur_etheraddr */
    _mac_compute(base_addr, lan_mac, selectband + 2, 1);

    AWN_LOG_DEBUG("srcBand:%d lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, srcBssid:%02X:%02X:%02X:%02X:%02X:%02X, base_addr:%02X:%02X:%02X:%02X:%02X:%02X,",
        selectband, lan_mac[0], lan_mac[1], lan_mac[2], lan_mac[3], lan_mac[4], lan_mac[5],
        srcBssid[0], srcBssid[1], srcBssid[2], srcBssid[3], srcBssid[4], srcBssid[5],
        base_addr[0], base_addr[1], base_addr[2], base_addr[3], base_addr[4], base_addr[5]);

    if (_mac_raw_equal(base_addr, srcBssid)) {
        AWN_LOG_DEBUG("QCA bssid to calculate_bssid_for_qca");
        awnd_calculate_bssid_for_qca(selectband, lan_mac, pTmpEntry, isPreconf, srcBssid);
        return;
    }

    awnd_calculate_bssid_for_bcm(selectband, lan_mac, pTmpEntry, isPreconf, srcBssid);
    if (0 == memcmp(pTmpEntry[selectband].bssid, srcBssid, AWND_MAC_LEN)) {
        AWN_LOG_DEBUG("BCM DUT bssid");
        return;
    }

    awnd_transform_bssid_by_low_byte_increase(selectband, srcBssid, pTmpEntry);
    return;
}

void awnd_transform_lanmac_from_wifi(UINT8 *dstmac, AWND_AP_ENTRY **pRootAp)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (pRootAp[band])
        {
            if (_is_vaild_mac(pRootAp[band]->lan_mac))
            {
            	memcpy(dstmac, pRootAp[band]->lan_mac, AWND_MAC_LEN);
            }
            else
            {
            	_mac_compute(dstmac, pRootAp[band]->bssid, band+2, 0);
            }
            break;
        }

    }        

    return;     
}

int awnd_plc_better_than_wifi(AWND_PLC_NEIGH* pPlcNeigh, AWND_AP_ENTRY **pRootAp, AWND_NET_INFO *pBestNet)
{
    AWND_BAND_TYPE band;
    UINT16 plcRate = (pPlcNeigh->txRate < 100) ? pPlcNeigh->txRate : 100;
    UINT16 wifiRate = 0;
    int i = 0;
                
    if (IN_SAME_SUBNET(&pPlcNeigh->netInfo, pBestNet))
    {
        /*1. if wifi level <= plc level and wifi is good enough, select wifi */
        if (pPlcNeigh->netInfo.awnd_level >= pBestNet->awnd_level)
        {
            for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
            {
                if (pRootAp[band] && pRootAp[band]->rssi)
                {
                    if (pRootAp[band]->rssi > 35 || (AWND_BAND_2G != band && pRootAp[band]->rssi > 18))
                        return 0;
                }

            }
        }

        /*2. estimate plc path rate, if plc path rate is too low, select wifi. */
        for(i = 0; i < pPlcNeigh->netInfo.awnd_level ; i++) {
            plcRate = (plcRate * 70)/100;
        }
        if (plcRate < 20) {
            return 0;
        }

        /*3. compare plc path rate and wifi path rate, select the higher path*/
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            if (pRootAp[band] && pRootAp[band]->pathRate > plcRate)
            {
                return 0;
            }

        }        
        return 1;        
    }
    else if (HIGH_PRIO_SUBNET(&pPlcNeigh->netInfo, pBestNet))
        return 1;
    else
        return 0;
}

void awnd_mode_call_hotplug(AWND_HOTPLUG_CONFIG *pHotplugCfg)
{
    char *argv[3];
    int pid;
    struct uloop_process *proc;    
    int status = 0;

    proc = uloop_get_hotplug_process();
    if (NULL == proc)
    {
        AWN_LOG_ERR("The whole hotplug process table is full.");
        return;
    }    

    setenv("SRCMODE", modeToStr(pHotplugCfg->srcMode), 1);
    setenv("DSTMODE", modeToStr(pHotplugCfg->dstMode), 1);
    setenv("POINT",   hotplugToStr(pHotplugCfg->type), 1);
        
    if (AWND_HOTPLUG_CAP_TYPE_CHANGE == pHotplugCfg->type)
    {
        setenv("CAPSRCTYPE",   netTypeToStr(pHotplugCfg->capSrcType), 1);
        setenv("CAPDSTTYPE",   netTypeToStr(pHotplugCfg->capDstType), 1);
    }
    pid = fork();
    if (pid < 0)
    {
        /* Failed. */
        AWN_LOG_CRIT("%s", "fork failed");
    }     
    else if (pid == 0) {        
        argv[0] = hotplug_cmd_path;
        argv[1] = "mode";
        argv[2] = NULL;
        execvp(argv[0], argv);
        exit(127);
    }
    else
    {
        /* parent process */
        proc->pid = pid;
        uloop_process_add(proc);
        AWN_LOG_INFO("add process:%d",pid);
    }    

    return ;
    
}

int awnd_plc_set_nmk(char *nmk)
{
    char buff[256];
    sprintf(buff, "/usr/bin/plcManager set %s &", nmk);
    system(buff);    
}

int awnd_plc_reload()
{
    system("/etc/init.d/plc reload &");    
}

int awnd_plc_set_root(UINT8 isPlcRoot)
{
	if (g_awnd.isPlcRoot != isPlcRoot)
		AWN_LOG_NOTICE("This device %s plc root.", isPlcRoot ? "became" : "lost");
	
    g_awnd.isPlcRoot = isPlcRoot; 
    awnd_config_set_plc_as_root(isPlcRoot);     
	_send_apsd_configure_msg();
}

int awnd_plc_disconnect_without_cleanup(UINT8 isPlcRoot)
{
    g_awnd.plcStatus = AWND_STATUS_DISCONNECT;
    g_awnd.plcWinWifi = 0;
    awnd_config_set_plc_active(0);     
    awnd_write_rt_info(AWND_INTERFACE_PLC, false, NULL, false);
    AWN_LOG_INFO("Disconnect PLC backhaul.");
}



int awnd_plc_disconnect()
{
    memset(&g_awnd.plcPeerNeigh, 0, sizeof(AWND_PLC_NEIGH));
    g_awnd.plcStatus = AWND_STATUS_DISCONNECT;
    g_awnd.plcWinWifi = 0;
    awnd_config_set_plc_active(0);
    awnd_write_rt_info(AWND_INTERFACE_PLC, false, NULL, false);
    AWN_LOG_INFO("Disconnect PLC backhaul.");
}

int awnd_plc_reconnect()
{
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        g_awnd.plcStatus = AWND_STATUS_CONNECTING;
        g_awnd.plcWinWifi = 0;        
        awnd_config_set_plc_active(1);
        AWN_LOG_NOTICE("PLC backhaul is connecting.");
    }
}

int awnd_eth_set_backhaul(UINT8 linkToFap, const char *ifname)
{
    if (linkToFap) 
    {
        if (NULL == ifname)
        {
           AWN_LOG_ERR("eth backhaul interface is null\n");
        }
        else
        {
            awnd_config_set_eth_interface(ifname);  
        }
        g_awnd.ethStatus = AWND_STATUS_CONNECTING;
    }
    else {
        g_awnd.ethStatus = AWND_STATUS_DISCONNECT;  
        g_awnd.eth_wifi_coexist = 0;
    }
    
    g_awnd.ethLinkTry = 0;
    awnd_config_set_eth_active(linkToFap);
    awnd_write_rt_info(AWND_INTERFACE_ETH, false, NULL, false);
    
}

void awnd_wifi_restart()
{
    remove(WIFI_DONE_FILE);
    system("/etc/init.d/repacd restart &");
    //sleep (1);
    _stable_sleep(1);
}


void awnd_repacd_restart(AWND_MODE_TYPE mode, int quick)
{

    if (quick)
    {
        AWN_LOG_INFO("=========awnd repacd restart quickly==============");
        if (AWND_MODE_RE == mode)
        {
            system("/etc/init.d/repacd restart_in_noncap_mode");
        }
        else
        {
            system("/etc/init.d/repacd restart_in_cap_mode");           
        }
        AWN_LOG_INFO("=========awnd repacd restart finish==============");
    }
    else
    {
        remove(WIFI_DONE_FILE);
        system("/etc/init.d/repacd restart &");
        //sleep (1);
        _stable_sleep(1);
    }
}

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
void awnd_repacd_set_sta_vlan_backhual_iface_enable(AWND_MODE_TYPE mode, int enable)
{
    char cmd[128] = {0};
    if (AWND_MODE_RE == mode)
    {
        if (enable)
        {
            AWN_LOG_INFO("=========awnd repacd add vlan bakchual iface==============");
            snprintf(cmd, 128, "/etc/init.d/repacd set_sta_vlan_backhual_iface_enable \"RE\" \"1\"");
            AWN_LOG_DEBUG("set sta cmd:%s", cmd);
            system(cmd);
        }
        else
        {
            AWN_LOG_INFO("=========awnd repacd del vlan bakchual iface==============");
            snprintf(cmd, 128, "/etc/init.d/repacd set_sta_vlan_backhual_iface_enable \"RE\" \"0\"");
            AWN_LOG_DEBUG("set sta cmd:%s", cmd);
            system(cmd);   
        }
    }

     _stable_sleep(1);
}
#endif

void awnd_wifi_check_doing(struct uloop_timeout *t)
{
    if (access(WIFI_DONE_FILE, 0))
    {
        awnd_mode_convert(g_awnd.workMode, g_awnd.workMode); 
        return;
    }

    uloop_timeout_set(t,  l_awnd_config.tm_online_interval);
    return;
}

int awnd_wifi_wait_for_done()
{
    int wifi_handling = 0;
    UINT8 bind = 0;


    AWN_LOG_INFO("*****************wait for wifi done*****************");

waitForWifi:       
    /* wait for wifi done*/
    while (access(WIFI_DONE_FILE, 0))
    {
        //sleep(1);
        usleep(500*1000);
        wifi_handling = 1;
    }
   
    if (!g_awnd.notBind && wifi_handling) {
        //sleep(1);
	_stable_sleep(1);
    }   

    if (WIFI_AP == awnd_config_get_mode())
    {
        if (AWND_MODE_HAP != g_awnd.workMode){
            g_awnd.workMode = AWND_MODE_FAP;
        }
    }
    else
    {
        g_awnd.workMode = AWND_MODE_RE;
    }

    /* config backhual ssid and pwd according to group-info */
#if AWND_BIND_SWITCH_BACKHUAL_FIRST
    if (!g_awnd.notBind)
    {
        awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_BACKHUAL);
    }
#else
    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_BACKHUAL);
#endif

    l_awnd_config.weight = awnd_config_get_weight();

#if CONFIG_AWN_WAIT_FOR_WIRED_NETWORK || CONFIG_PLATFORM_BCM || CONFIG_PLATFORM_MTK
/********************************************************************************************************
    Bug 338776 - 三台样机组网，其中两台RE有线连接，FAP断电或者断电重启都有较大概率（3/5）出现两台RE互相认为对方已连接FAP的情况
    问题分析：
    1 有线neigbor不在之后，10s才断开有线组网。
    2 X90在无线连接切换有线连接时repacd的时间为5s。
    1) RE1(wifi connect FAP)断开无线连接，RE1的组网信息切换成RE(2,0)；
    2) RE1有线组网RE2,不是立马修改组网信息至RE(0,3),而是保持FAP(2,0)至repacd重启完成；
    3) RE1 重启repacd(关闭无线接口)时间为5s；
    4) RE1重启之后，更新组网信息为(0,3)，此时RE2的10断开连接未到，重新组网RE1，组网信息(0,4)，依次循环下去。
    3 M5在无线连接切换有线连接时repacd的时间为13s。
    3) RE1重启repacd(关闭无线接口)时间为13s，在RE重启repacd完成之前，RE2已经断开有线连接，组网信息(2,0)；
    4) RE1重启repacd之后，无FAP的组网信息，会断开有线连接。

    修复方法：
    (1) 有线组网断开连接的时间10s不能变，如果不同机型超时时间不同，可能会带来更多的有线组网问题。
    (2) 组网模块：在切换为有线组网的repacd重启完成之后，进入re_loop之前，sleep 10s
*********************************************************************************************************/
    /* TODO: sleep 10s to fix wired network issue */
    if (!g_awnd.notBind && AWND_MODE_RE == g_awnd.workMode &&
        AWND_STATUS_CONNECTING == g_awnd.ethStatus )
    {
        AWN_LOG_NOTICE("***eth connecting: to sleep 10s when wifi done***");
        _stable_sleep(10);
    }
#endif

    AWN_LOG_INFO("*****************wifi has been done*****************");
}

void awnd_notify_tpie_to_kernel(AWND_NET_INFO *pAwndNetInfo)
{
    UINT16 uplinkMask = 0;
    UINT16 uplinkRate[AWND_BAND_MAX] = {0};	
    UINT16 uplinkRateMax = 0;    
    AWND_BAND_TYPE band;
    
    uplinkMask = _get_connect_status();

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
         if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band])
         {
            uplinkRate[band] = g_awnd.rootAp[band].pathRate;
            uplinkRateMax += uplinkRate[band];
         }
    }	
 

    g_awnd.uplinkMask = uplinkMask;
    g_awnd.uplinkRate = uplinkRateMax;
    awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, uplinkMask, uplinkRateMax, pAwndNetInfo, AWND_MESH_BACKHUAL);
}


void awnd_set_oui_update_status_fap(int status)
{
    fap_oui_update_status = status;
}

void awnd_set_oui_update_status_re(int status)
{
    re_oui_update_status = status;
}

void awnd_set_oui_now_version(int version)
{
    oui_now_version = version;
}

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
int awnd_update_tpie(AWND_NET_INFO *pAwndNetInfo, AWND_NETINFO_TYPE NetInfoType)
#else
int awnd_update_tpie(AWND_NET_INFO *pAwndNetInfo)
#endif
{
    UINT16 uplinkMask = 0;
    UINT16 uplinkRateMax = 0;  
    UINT16 uplinkRate[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band;
    AWND_REAL_BAND_TYPE real_band;
    AWND_NET_INFO tmpNetInfo;
    int update_ret = AWND_BUSY;
    AWND_NET_INFO netInfoFromTpie;
    int nss;
    int phyMode;
    int chwidth;
    UINT16 txRate, rxRate;
    INT32 rssi;
    int ret;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    UINT8 wifiDeliverType = 0; /* 0: pAwndNetInfo, 1: use eth(g_awnd.ethNetInfo), 2: use wifi(g_awnd.netInfo) */
    UINT8 ethDeliverType = 0; /* 0: pAwndNetInfo, 1: use eth(g_awnd.netInfo), 2: use wifi(g_awnd.netInfo) */
    AWND_NET_INFO *wifiDeliverNetInfo = NULL;
    AWND_NET_INFO *ethDeliverNetInfo = NULL;
#endif

    uplinkMask = _get_connect_status();
    g_awnd.uplinkMask = uplinkMask;

    if (pAwndNetInfo->awnd_level > 32) {
        AWN_LOG_ERR("awnd_level:%d, something is not right, stop update, awnd loop again.", pAwndNetInfo->awnd_level);
        awnd_disconn_all_sta();
        awnd_write_work_mode(g_awnd.workMode, 0, NULL, AWND_NET_LRE, 0, NULL);
        awnd_wifi_restart();
        awnd_mode_convert(g_awnd.workMode, g_awnd.workMode);
        return update_ret;
    }

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
        real_band = _get_real_band_type(band);

        if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band])
        {
            memset(&netInfoFromTpie, 0, sizeof(AWND_NET_INFO));

            rssi = 0;
            if (0 == g_awnd.rootAp[band].pathRate &&
                AWND_OK == awnd_get_tpie(g_awnd.rootAp[band].bssid, IEEE80211_TP_IE_IN_ANY, &netInfoFromTpie, band) &&
                AWND_OK == awnd_get_phy(band, &nss, &phyMode, &chwidth) &&
                AWND_OK == awnd_get_rootap_rssi(band, &rssi))
            {
                if ((netInfoFromTpie.uplink_mask & AWND_BACKHAUL_WIFI) && ((netInfoFromTpie.uplink_mask & AWND_BACKHAUL_WIFI_2G) ||
                    (netInfoFromTpie.uplink_mask & AWND_BACKHAUL_WIFI_5G) || (netInfoFromTpie.uplink_mask & AWND_BACKHAUL_WIFI_5G2) ||
                    (netInfoFromTpie.uplink_mask & AWND_BACKHAUL_WIFI_6G)))
                {   /* if current band disconnect with rootap, uplinkRate set to zero  */
                    if (!(netInfoFromTpie.uplink_mask & (1 << (8 + real_band))))
                    {
                        netInfoFromTpie.uplink_rate = 0;
                    }

                }
                netInfoFromTpie.uplink_mask &= 0x00FF;

                if (rssi > 0 && rssi <= 95) {
                    g_awnd.rootAp[band].pathRate = awnd_get_rate_estimate(netInfoFromTpie.awnd_level, l_awnd_config.scaling_factor,
                            netInfoFromTpie.uplink_mask, netInfoFromTpie.uplink_rate,
                            rssi, nss, phyMode, chwidth);
                    AWN_LOG_WARNING("band:%-6s bssid:%02X:%02X:%02X:%02X:%02X:%02X, rssi:%-4d, channel:%-3d, uplinkMask:%-5u, uplinkrate:%-5u, pathRate:%-5u",
                    real_band_suffix[_get_real_band_type(band)], g_awnd.rootAp[band].bssid[0],g_awnd.rootAp[band].bssid[1],g_awnd.rootAp[band].bssid[2],
                        g_awnd.rootAp[band].bssid[3], g_awnd.rootAp[band].bssid[4], g_awnd.rootAp[band].bssid[5], rssi, g_awnd.rootAp[band].channel,
                        netInfoFromTpie.uplink_mask, netInfoFromTpie.uplink_rate, g_awnd.rootAp[band].pathRate);
                }
            }
            uplinkRate[band] = g_awnd.rootAp[band].pathRate;
            uplinkRateMax += uplinkRate[band];

            uplinkMask = uplinkMask | (1 << (8 + real_band));			
        }
        else
            uplinkMask = uplinkMask & (~(1 << (8 + real_band)));
    }

    g_awnd.uplinkRate = uplinkRateMax;

    if (AWND_MODE_HAP == g_awnd.workMode || (AWND_MODE_RE == g_awnd.workMode && AWND_RE_STAGE_FOURTH == g_awnd.reStage))
    {
        pAwndNetInfo->server_detected = g_awnd.server_detected;
        pAwndNetInfo->server_touch_time = g_awnd.server_touch_time;
    }

    if (!g_awnd.notBind || AWND_BIND_BACKHUAL_CONNECTING <= g_awnd.bindStatus)
    {
        /* for FAP , check backhual ath02/12 oui status after received ubus msg , if diffrent , set "fap_oui_update_status" to update oui.*/
        /* However , for RE , check backhual ath02/12 oui status after get packects form FAP , if diffrent , set "re_oui_update_status" to update oui. */
        if((AWND_MODE_RE == g_awnd.workMode) && (g_awnd.netInfo.oui[1] != pAwndNetInfo->oui[1]))
        {
            AWN_LOG_INFO("RE need to change oui from 0x%x%x%x to :0x%x%x%x.",g_awnd.netInfo.oui[0],g_awnd.netInfo.oui[1],g_awnd.netInfo.oui[2], \
                                                        pAwndNetInfo->oui[0],pAwndNetInfo->oui[1],pAwndNetInfo->oui[2]);
            /* OUI_OLD_TO_NEW */
            if(g_awnd.netInfo.oui[1] != 0x31)
            {
                awnd_set_oui_update_status_re(OUI_OLD_TO_NEW);
            }
            /* OUI_NEW_TO_OLD */
            else if(g_awnd.netInfo.oui[1] != 0x1d)
            {
                awnd_set_oui_update_status_re(OUI_NEW_TO_OLD);
            }
        }
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        awnd_print_netInfo();

        if (AWND_MODE_RE == g_awnd.workMode) {
            if (AWND_NETINFO_ETH == NetInfoType) {
                /* eth: pAwndNetInfo(new ethNetInfo) wifi: Connected:g_awnd.netInfo else pAwndNetInfo */
                ethDeliverType = 0;
                ethDeliverNetInfo = pAwndNetInfo;
                if (g_awnd.ethStatus != AWND_STATUS_CONNECTED && _is_in_connected_state(g_awnd.connStatus)){
                    ethDeliverType = 1;
                    ethDeliverNetInfo = &g_awnd.netInfo;
                }

                if (_is_in_connected_state(g_awnd.connStatus)) {
                    wifiDeliverType = 2;
                    wifiDeliverNetInfo = &g_awnd.netInfo;
                }
                else {
                    wifiDeliverType = 0;
                    wifiDeliverNetInfo = pAwndNetInfo;
                }
            }
            else if (AWND_NETINFO_WIFI == NetInfoType) {
                /* wifi: pAwndNetInfo(new NetInfo) eth: Connected:g_awnd.ethNetInfo else pAwndNetInfo */
                wifiDeliverType = 0;
                wifiDeliverNetInfo = pAwndNetInfo;
                if (g_awnd.ethStatus == AWND_STATUS_CONNECTED && !_is_in_connected_state(g_awnd.connStatus)) {
                    wifiDeliverType = 1;
                    wifiDeliverNetInfo = &g_awnd.ethNetInfo;
                }

                if (g_awnd.ethStatus == AWND_STATUS_CONNECTED) {
                    ethDeliverType = 1;
                    ethDeliverNetInfo = &g_awnd.ethNetInfo;
                }
                else {
                    ethDeliverType = 0;
                    ethDeliverNetInfo = pAwndNetInfo;
                }
            }
            else {
                /* default: pAwndNetInfo, use owner if connected */
                wifiDeliverType = 0;
                wifiDeliverNetInfo = pAwndNetInfo;
                ethDeliverType = 0;
                ethDeliverNetInfo = pAwndNetInfo;
                if (g_awnd.ethStatus == AWND_STATUS_CONNECTED) {
                    ethDeliverNetInfo = &g_awnd.ethNetInfo;
                }
                if (_is_in_connected_state(g_awnd.connStatus)) {
                    wifiDeliverNetInfo = &g_awnd.netInfo;
                }
            }

            AWN_LOG_INFO("RE wifiDeliverType:%d, ethDeliverType:%d. [0: pAwndNetInfo, 1: use eth(g_awnd.ethNetInfo), 2: use wifi(g_awnd.netInfo)]",
                wifiDeliverType, ethDeliverType);

            awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, g_awnd.uplinkMask, g_awnd.uplinkRate, ethDeliverNetInfo, AWND_MESH_BACKHUAL);
            update_ret = awnd_update_wifi_tpie(wifiDeliverNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
        }
        else {
            /* HAP/FAP */
            awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, g_awnd.uplinkMask, g_awnd.uplinkRate, pAwndNetInfo, AWND_MESH_BACKHUAL);
            update_ret = awnd_update_wifi_tpie(pAwndNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
        }
#else
        /* 0 for success */
        update_ret = awnd_update_wifi_tpie(pAwndNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
        awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, g_awnd.uplinkMask, g_awnd.uplinkRate, pAwndNetInfo, AWND_MESH_BACKHUAL);        
#endif
    }
    /*
    else
    {
        if( ! _is_null_group_info(&(l_group_info.preconfGroupInfo)))
        {
            memcpy(&(tmpNetInfo), pAwndNetInfo, sizeof(AWND_NET_INFO));
            memcpy(tmpNetInfo.awnd_label, l_group_info.preconfGroupInfo.label, AWND_LABEL_LEN);
            awnd_update_wifi_tpie(&(tmpNetInfo), l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
            //awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, g_awnd.uplinkMask, g_awnd.uplinkRate, &(tmpNetInfo), AWND_MESH_BACKHUAL);      
            
        }

    }
    */
     if (ONBOARDING_ON == g_awnd.isOnboarding || ONBOARDING_ON == g_awnd.isPreOnboarding)
    {   /* make sure config mesh awnd_label generate from configGroupInfo */
        awn_plcson_set_eth_mesh_enable(AWND_MESH_CONFIG, 0);
        memcpy(&(tmpNetInfo), pAwndNetInfo, sizeof(AWND_NET_INFO));
        if(ONBOARDING_ON == g_awnd.isOnboarding)
        {
            memcpy(tmpNetInfo.awnd_label, l_group_info.configGroupInfo.label, AWND_LABEL_LEN);
            awnd_update_wifi_tpie(&(tmpNetInfo), l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_CONFIG);
        }
        if (ONBOARDING_ON == g_awnd.isPreOnboarding)    
        {
            memset(tmpNetInfo.awnd_label, 0, AWND_LABEL_LEN);
            memcpy(tmpNetInfo.awnd_label, l_group_info.preconfigGroupInfo.label, AWND_LABEL_LEN);
            // snprintf(tmpNetInfo.awnd_label, AWND_LABEL_LEN, "preconfig");
            awnd_update_wifi_tpie(&(tmpNetInfo), l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_PRECONFIG);
        }
        awn_set_net_info(l_awnd_config.mac, l_awnd_config.plcMac, g_awnd.isPlcRoot, g_awnd.uplinkMask, g_awnd.uplinkRate, &(tmpNetInfo), AWND_MESH_CONFIG);      
        awn_plcson_set_eth_mesh_enable(AWND_MESH_CONFIG, 1);
    }

    return update_ret;
}

/*!
 *\fn           awnd_update_wifi_uplink_mask()
 *\brief        update wifi uplink mask,
 *\                to indecate wifi band connected with rootap or not
 *\param[in]
 *\return
 */
void awnd_update_wifi_uplink_mask(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band_idx, AWND_CONN_STATUS connStatus)
{
    UINT16 uplinkMask = 0;
    UINT16 uplinkRate[AWND_BAND_MAX] = {0};
    AWND_BAND_TYPE band;
    AWND_REAL_BAND_TYPE real_band = 0;
    AWND_REAL_BAND_TYPE real_band_idx = 0;

    real_band_idx = _get_real_band_type(band_idx);
    uplinkMask = g_awnd.uplinkMask;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {

        real_band = _get_real_band_type(band);
        if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band])
        {
            uplinkRate[band] = g_awnd.rootAp[band].pathRate;
            uplinkMask = uplinkMask | (1 << (8 + real_band));			
        }
        else
            uplinkMask = uplinkMask & (~(1 << (8 + real_band)));
    }

    if (AWND_STATUS_CONNECTED == connStatus)
        uplinkMask = uplinkMask | (1 << (8 + real_band_idx));
    else
        uplinkMask = uplinkMask & (~(1 << (8 + real_band_idx)));

    if (AWND_MODE_HAP == g_awnd.workMode || (AWND_MODE_RE == g_awnd.workMode && AWND_RE_STAGE_FOURTH == g_awnd.reStage))
    {
        pAwndNetInfo->server_detected = g_awnd.server_detected;
        pAwndNetInfo->server_touch_time = g_awnd.server_touch_time;
    }

    if (!g_awnd.notBind)
    {
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        if (!(uplinkMask & AWND_BACKHAUL_WIFI) && g_awnd.ethStatus == AWND_STATUS_CONNECTED) {
            awnd_update_wifi_tpie(&g_awnd.ethNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
        } else {
            awnd_update_wifi_tpie(pAwndNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
        }
#else
        awnd_update_wifi_tpie(pAwndNetInfo, l_awnd_config.mac, uplinkMask, uplinkRate, AWND_MESH_BACKHUAL);
#endif /* CONFIG_ETH_WLAN_BACKHAUL_SUPPORT */
    }
}

void awnd_update_lanip(struct uloop_timeout *t)
{
    UINT32 lanip = 0;

    if (g_awnd.workMode == AWND_MODE_RE)
        return;

    if(AWND_OK == awn_get_lan_ip(&lanip))
    {
        if (g_awnd.netInfo.awnd_lanip != lanip)
        {
            g_awnd.netInfo.awnd_lanip = lanip;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            g_awnd.ethNetInfo.awnd_lanip = lanip;
            awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
            awnd_update_tpie(&g_awnd.netInfo);
#endif
        }
    }
    else
    {
        AWN_LOG_WARNING("get lan ip failed");
    }

    uloop_timeout_set(t,  l_awnd_config.tm_update_lanip_interval);
}

int awnd_netinfo_update_dns(UINT32 dns)
{

    if (AWND_MODE_RE == g_awnd.workMode || AWND_MODE_NONE == g_awnd.workMode)
    {
        AWN_LOG_INFO("work mode RE/NONE, no need to update dns");
        return AWND_ERROR;
    }

    if (g_awnd.netInfo.awnd_dns != dns)
    {
        g_awnd.netInfo.awnd_dns = dns;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            g_awnd.ethNetInfo.awnd_dns = dns;
            awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
        awnd_update_tpie(&g_awnd.netInfo);
#endif
    }

    return AWND_OK;
}

#if CONFIG_BSS_STATUS_CHECK
#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
int _is_wifi_schedule_status_on()
{
    char buf[8] = {0};
    int ret = AWND_NOT_FOUND;
    FILE *fp = NULL;

    fp = fopen(WIFI_SCHEDULE_RUNNING_FILE, "r");
    if (fp)
    {
        if (fgets(buf, sizeof(buf), fp))
        {
            if (atoi(buf) > 0)
            {
                ret = AWND_OK;
            }
        }
        fclose(fp);
    }

    return ret;
}
#endif /* CONFIG_PACKAGE_WIFI_SCHEDULE */

void bss_status_inspect(struct uloop_timeout *t)
{
#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
    if (_is_wifi_schedule_status_on() == AWND_OK)
    {
        AWN_LOG_DEBUG("bss down for long time, ignore it because of wifi schedule");
        return;
    }
    else
#endif /* CONFIG_PACKAGE_WIFI_SCHEDULE */
    if (AWND_WIFI_RESTART == awnd_bss_status_check())
    {
        AWN_LOG_CRIT("bss down for long time, to wifi reload");
        awnd_wifi_restart();
        awnd_mode_convert(g_awnd.workMode, g_awnd.workMode);
        return;
    }

    uloop_timeout_set(t,  l_awnd_config.tm_bss_status_inspect);
}
#endif /* CONFIG_BSS_STATUS_CHECK */

#if SCAN_OPTIMIZATION
static void awnd_memset_scan_table()
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        memset(&l_awnd_scan_table.apList[band], 0, sizeof(AWND_SCAN_RESULT));
    }
}
#endif //SCAN_OPTIMIZATION

void awnd_bind_confirm(struct uloop_timeout *t)
{
    UINT8 bind = 0;
    int isOnboarding = 0;
    int index = 0;

    if (AWND_OK == awnd_get_group_id(&l_group_info, &bind) && bind)
    {
        system("rm /tmp/setup_boost");
        system("rm /tmp/location");

        /* config plc.config.NetworkPassWd and reload plc */
        awnd_config_set_plc_nmk(l_group_info.backhualGroupInfo.ssid);
        awnd_plc_reload();

        _save_group_role(l_group_info.cfg_role);
        if (AWND_CONFIG_AP == l_group_info.cfg_role)
        {
            g_awnd.notBind = 0;
            /* config ssid and pwd according to group-info */
            awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_ALL);
            awnd_config_set_mode(WIFI_AP, 0);

            /* to enable config network when binding FAP */
            if (AWND_OK == _get_onboarding_status(&isOnboarding))
            {
                if (isOnboarding && 0 == awnd_config_get_cfg_mesh_enb())
                {
                    AWN_LOG_NOTICE("FAP enable config mesh when onboarding.");
                    awnd_config_set_cfg_mesh_enb(1);
                }

                g_awnd.isOnboarding = isOnboarding;
            }

            awnd_mode_convert(AWND_MODE_RE, AWND_MODE_FAP);
            _save_bind_status(1);
        }
        else
        {

#if AWND_BIND_SWITCH_BACKHUAL_FIRST
            g_awnd.bindStatus = AWND_BIND_START;

            AWN_LOG_NOTICE("RE begin to bind.");
            //sleep(1);
            _stable_sleep(1);


            /* wait for luci-app(qucik_setup) add device done */
            for (index = 0; index < 10; index ++)
            {
                if (access(AWND_ADD_DEVICE_DONE, 0))
                    //sleep(1);
                    _stable_sleep(1);
                else
                    break;
            }
            if (10 == index)
            {
                AWN_LOG_ERR("===== wait file %s for 10s =====", AWND_ADD_DEVICE_DONE);
            }
            else
            {
                //sleep(3);
                _stable_sleep(3);
            }

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
            char qca_wifi_5g[6] = {0};
            char cmd[128] = {0};
            if(access("/etc/profile.d/interfaces",0) == 0)
            {
                FILE *fp = NULL;
                fp = popen("uci -c /etc/profile.d/ get interfaces.radio_5g.name", "r");
                if(fp != NULL)
                {
                    fread(qca_wifi_5g,sizeof(qca_wifi_5g),1,fp);
                    snprintf(cmd, sizeof(cmd), "radartool -i %s ignorecac 1", qca_wifi_5g);
                    pclose(fp);
                }else
                {
                    snprintf(cmd, sizeof(cmd), "radartool -i wifi1 ignorecac 1");
                }
            }

            if(0 != awnd_config_get_radio_5g_rcac_enb())
            {
            	AWN_LOG_CRIT("system: radartool -i wifi1 ignorecac 1");
				is_set_ignorecac = 1;
                system(cmd);
                awnd_config_set_radio_5g_rcac_enb(0);
            }
#endif
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
            system("/etc/init.d/ai_center restart &");
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
            if ( (l_group_info.staType != AWND_STA_TYPE_PRE 
                  || memcmp(&l_group_info.staGroupInfo, &l_group_info.preconfGroupInfo, sizeof(GROUP_INFO)))
                && _is_in_connected_state(g_awnd.connStatus))
            {
                // if (AWND_WIFI_RESTART == awnd_config_covert_backhaul_with_same_rootap())
                // {
                //     awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                //     awnd_wifi_restart();
                //     awnd_mode_convert(g_awnd.workMode, g_awnd.workMode);
                // }
                // else
                // {
                    awnd_disconn_all_sta();
#if SCAN_OPTIMIZATION
                    awnd_memset_scan_table();
                    g_awnd.scan_one_more_time = -1;
#endif
                    g_awnd.bindFast = 1;
                    awnd_mode_convert(g_awnd.workMode, g_awnd.workMode);
                // }
            }

            g_awnd.bindStatus = AWND_BIND_BACKHUAL_CONNECTING;
            AWN_LOG_INFO("===== RE bined: switch to backhual =====");
#else
            /* config backhual ssid and pwd according to group-info */
            awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_BACKHUAL);
            if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus)
            {   /* RE use configGroupInfo before wifi restart when binding */
                memcpy(&(l_group_info.staGroupInfo), &(l_group_info.configGroupInfo), sizeof(GROUP_INFO));
            }
            g_awnd.bindStatus = AWND_BIND_START;
            AWN_LOG_INFO("===== RE not to wifi restart when onboarding =====");
#endif
        }

        return;
    }
    
    uloop_timeout_set(t, l_awnd_config.tm_bind_confirm_interval);
    return;
}

void awnd_onboarding_inspect(struct uloop_timeout *t)
{
    int isOnboarding = 0;

    if (AWND_ERROR == _get_onboarding_status(&isOnboarding))
    {
        AWN_LOG_DEBUG("get onboarding status fail");
        goto done;
    }

    if (g_awnd.notBind)
        goto done;

    if (isOnboarding)
    {
        /* check wifi.config.enable of config AP VAP */
        if( ONBOARDING_ON != g_awnd.isOnboarding || 0 == awnd_config_get_cfg_mesh_enb())
        {
            AWN_LOG_NOTICE("Enable config mesh network when onboarding.");
            awnd_config_set_cfg_mesh_enb(1);
            g_awnd.isOnboarding = ONBOARDING_ON;

#if CONFIG_AWN_CONFIG_BIND_ACCEL
            system("/usr/sbin/check_config_network open");
            awnd_update_tpie(&g_awnd.netInfo);
#else
            awnd_wifi_restart();
            awnd_mode_convert(g_awnd.workMode, g_awnd.workMode); 
            return;
#endif
        }
    }
    else
    {
        if (ONBOARDING_OFF != g_awnd.isOnboarding || 1 == awnd_config_get_cfg_mesh_enb())
        {
            AWN_LOG_NOTICE("Disable config mesh network when offboarding.");
            awnd_config_set_cfg_mesh_enb(0);
            awn_plcson_set_eth_mesh_enable(AWND_MESH_CONFIG, 0);
            g_awnd.isOnboarding = ONBOARDING_OFF;

#if CONFIG_AWN_CONFIG_BIND_ACCEL
            system("/usr/sbin/check_config_network close");
#else
            awnd_wifi_restart();
            awnd_mode_convert(g_awnd.workMode, g_awnd.workMode); 
            return;
#endif
        }
    }

    g_awnd.isOnboarding = isOnboarding;

done:
    uloop_timeout_set(t, l_awnd_config.tm_onboarding_interval);
    return;
}

void awnd_server_detect_handler(struct uloop_timeout *t)
{
    /* get server detect status and handler */
    UINT8 server_detected = 0;
    UINT32 server_touch_time = 0;
    int ret = AWND_ERROR;

    if (AWND_MODE_FAP == g_awnd.workMode ||
        (AWND_MODE_RE == g_awnd.workMode && AWND_RE_STAGE_THIRD > g_awnd.reStage))
        return;

    ret = awnd_ubus_get_server_detect(&server_detected, &server_touch_time);

    if (AWND_OK == ret)
    {
        if ((g_awnd.server_detected != server_detected) || (g_awnd.server_touch_time != server_touch_time))
        {
            g_awnd.server_detected   = server_detected;
            g_awnd.server_touch_time = server_touch_time;
            if (AWND_MODE_HAP == g_awnd.workMode || 
                (AWND_MODE_RE == g_awnd.workMode && AWND_RE_STAGE_FOURTH == g_awnd.reStage))
            {
                AWN_LOG_INFO(" ===server detct changed to update tpie.");
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
                awnd_update_tpie(&g_awnd.netInfo);
#endif
            }

        }
    }
    
    uloop_timeout_set(t,  l_awnd_config.tm_server_detect_interval);
    return;
}

void awnd_re_stage_inspect(struct uloop_timeout *t)
{
     /* get server detect status and handler */
    UINT32 curtime = 0;
    AWND_NET_INFO *cur_netInfo = NULL;

    UINT16 linkStatus = _get_connect_status();
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus) {
        cur_netInfo = &g_awnd.ethNetInfo;
    }
    else
#endif /* CONFIG_ETH_WLAN_BACKHAUL_SUPPORT */
    {
        cur_netInfo = &g_awnd.netInfo;
    }

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    AWN_LOG_DEBUG("====re_stage_inspect =======linkStatus:0x%02x restage:%d, net_type:%d, support eth_wifi_coexist:%d.", linkStatus, g_awnd.reStage, cur_netInfo->awnd_net_type, g_awnd.eth_wifi_coexist);
#else
    AWN_LOG_DEBUG("====re_stage_inspect =======linkStatus:0x%02x restage:%d, net_type:%d.", linkStatus, g_awnd.reStage, g_awnd.netInfo.awnd_net_type);
#endif
    if (0 < linkStatus && AWND_NET_FAP == cur_netInfo->awnd_net_type)
    {		
        g_awnd.stage2Timestamp = 0;
        g_awnd.stage4Timestamp = 0;
        g_awnd.reStage = AWND_RE_STAGE_FIRST;

        if (g_awnd.notBind && AWND_BIND_BACKHUAL_CONNECTING == g_awnd.bindStatus)
        {
            _reset_onboarding_status();
            g_awnd.notBind = 0;
            g_awnd.bindStatus = AWND_BIND_OVER;
#if AWND_BIND_SWITCH_BACKHUAL_FIRST
            _save_bind_status(1);
            //awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_BACKHUAL);
#else

#endif
            AWN_LOG_NOTICE("RE is bind now and connected to AP.");
            system("echo 1 > /tmp/awn_bind_over");
        }
        goto out;
    }
#ifndef CONFIG_PACKAGE_WIFI_SCHEDULE
    else if (g_awnd.notBind)
#else
    else if (g_awnd.notBind || RE_CONNECT_NO_HAP == g_connect_policy)
#endif
    {
        g_awnd.reStage = AWND_RE_STAGE_SECOND;
        goto out;
    }

    switch (g_awnd.reStage)
    {
        case AWND_RE_STAGE_NONE:
            g_awnd.reStage = AWND_RE_STAGE_SECOND;
            break;
        case AWND_RE_STAGE_FIRST:
            if (0 >= linkStatus || (AWND_NET_FAP != cur_netInfo->awnd_net_type))
            {
                g_awnd.stage2Timestamp = (unsigned long)time(NULL);
                g_awnd.reStage = AWND_RE_STAGE_SECOND;
                AWN_LOG_INFO("RE STAGE: FIRST --> SECOND");
            }
            break;
        case AWND_RE_STAGE_SECOND:

            if (0 == g_awnd.stage2Timestamp)
            {
                g_awnd.stage2Timestamp = (unsigned long)time(NULL);
                goto out;
            }

            curtime = (unsigned long)time(NULL);
            if (curtime - g_awnd.stage2Timestamp > RE_STAGE2_PERIOD)
            {
                AWN_LOG_INFO("RE STAGE: SECOND --> THIRD");
                g_awnd.reStage = AWND_RE_STAGE_THIRD;
                g_awnd.stage2Timestamp = 0;
                g_awnd.ethToHap     = 0;
                g_awnd.wifiToHap    = 0;
                g_awnd.plcToHap     = 0;
                l_awnd_scan_table.scan_fast = 0;
                uloop_timeout_set(&server_detect_timer,  l_awnd_config.tm_server_detect_start);
                AWN_LOG_NOTICE("RE couldn't found FAP for a period, try to find HAP.");
            }

            break;
        case AWND_RE_STAGE_THIRD:
            if ((AWND_STATUS_CONNECTED == g_awnd.ethStatus && g_awnd.ethToHap)
                || (g_awnd.wifiToHap && g_awnd.ethToHap && (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? g_awnd.plcToHap : 1)))
            {
                AWN_LOG_INFO("RE STAGE: THIRD --> FOURTH");
                /* to disconect all */
                awnd_eth_set_backhaul(0, NULL);
                awnd_disconn_all_sta();
                awnd_plc_disconnect();

                g_awnd.stage4Timestamp = (unsigned long)time(NULL);
                g_awnd.reStage  = AWND_RE_STAGE_FOURTH;
                g_awnd.ethToHap     = 0;
                g_awnd.wifiToHap    = 0;
                g_awnd.plcToHap     = 0;
                awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_WIFI);
#else
                awnd_update_tpie(&g_awnd.netInfo);
#endif
                AWN_LOG_NOTICE("RE is trying to become HAP.");
            }
            break;
        case AWND_RE_STAGE_FOURTH:

            if (0 == g_awnd.stage4Timestamp)
            {
                g_awnd.stage4Timestamp = (unsigned long)time(NULL);
                goto out;
            }

            curtime = (unsigned long)time(NULL);
            if (curtime - g_awnd.stage4Timestamp > RE_STAGE4_PERIOD)
            {
                g_awnd.reStage = AWND_RE_STAGE_NONE;
                g_awnd.stage4Timestamp = 0;

                AWN_LOG_INFO("RE STAGE: FOURTH --> HAP");
                /* config and convert */
                awnd_mode_convert(AWND_MODE_RE, AWND_MODE_HAP);
                return;
            }
            break;
        default: 
            break;
    }

out:    
    uloop_timeout_set(t,  l_awnd_config.tm_re_stage_inspect);
    return;   
}

#ifdef SUPPORT_MESHMODE_2G
void awnd_check_channel_apply(AWND_BAND_TYPE band)
{
    int uci_cfg_channel = 0;
    int real_channel = 0;

    uci_cfg_channel = awnd_config_get_channel(band);
    if (AWND_OK != (awnd_get_backhaul_ap_channel(band, &real_channel)))
    {
        real_channel = g_awnd.rootAp[band].channel;
    }

    if (uci_cfg_channel != real_channel && uci_cfg_channel != 0)
    {
        awnd_set_channel(band, uci_cfg_channel);
    }
}

void awnd_meshmode_2g_inspect(struct uloop_timeout *t)
{
    AWND_BAND_TYPE band;
    AWND_WIFI_BW_TYPE bw;
    AWND_WIFI_BW_TYPE targetBw = WIFI_BW_20M;
    AWND_AP_ENTRY cmpApEntry;
    UINT16 txRate, rxRate, mediumRate;
    INT32 rssi, chanutil, intf;
    int cur_chan, target_chan;
    int record_channel_2g = 0;
    int cfg_channel = 0;
    int bandwidth_2g = 2;
    int real_channel = 0;
    char buff[256];
    UINT bandMask;
    UINT8 scan_band = 0;

    memset(&cmpApEntry, 0, sizeof(AWND_AP_ENTRY));

    if (g_awnd.bindStatus != AWND_BIND_OVER)
    {
        AWN_LOG_NOTICE("lxdebug bindstatus=%d,not to meshmode_2g_inspect\n",g_awnd.bindStatus);
        uloop_timeout_set(t,  l_awnd_config.tm_meshmode_2g_inspect);
        return;
    }
    if (AWND_OK != awnd_file_exist(AWND_MESHMODE_2G_INSPECT_FILE))
    {
        system("touch /tmp/awnd_meshmode_2g_inspect");
    }
    g_awnd.meshmode_last = g_awnd.meshmode;
    g_awnd.meshmode = awnd_config_get_meshmode_2g();
    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus){
        AWN_LOG_NOTICE("lxdebug ethstatus=%d,set meshmode_2g 0\n",g_awnd.ethStatus);
        g_awnd.meshmode = AWND_MESHMODE_2G_DISCONNECT;
    }

    if ((AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5G] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_3RD] &&
         AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_4TH] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5TH])
        && AWND_STATUS_CONNECTED != g_awnd.ethStatus && g_awnd.meshmode == AWND_MESHMODE_2G_DISCONNECT)
    {
        AWN_LOG_NOTICE("lxdebug guarantee connectivity, 2g connect\n");
        g_awnd.meshmode = AWND_MESHMODE_2G_CONNECT;
    }

    record_channel_2g = awnd_config_get_record_channel_2g();
    bandwidth_2g = awnd_config_get_bandwidth_2g();
    if (record_channel_2g != 0)
    {
        cfg_channel = awnd_config_get_channel(AWND_BAND_2G);
        AWN_LOG_NOTICE("lxdebug set channel. channel: %d\n", cfg_channel);
        // awnd_check_channel_apply(AWND_BAND_2G);
    }

    if((g_awnd.meshmode_last != AWND_MESHMODE_2G_DYNAMIC ||
        (g_awnd.connected_ticks[AWND_BAND_5G] == 36 && g_awnd.connected_ticks[AWND_BAND_3RD] <= 36 && g_awnd.connected_ticks[AWND_BAND_4TH] <= 36 && g_awnd.connected_ticks[AWND_BAND_5TH] <= 36) ||
        (g_awnd.connected_ticks[AWND_BAND_3RD] == 36 && g_awnd.connected_ticks[AWND_BAND_5G] <= 36 && g_awnd.connected_ticks[AWND_BAND_4TH] <= 36 && g_awnd.connected_ticks[AWND_BAND_5TH] <= 36) ||
        (g_awnd.connected_ticks[AWND_BAND_4TH] == 36 && g_awnd.connected_ticks[AWND_BAND_5G] <= 36 && g_awnd.connected_ticks[AWND_BAND_3RD] <= 36 && g_awnd.connected_ticks[AWND_BAND_5TH] <= 36) ||
        (g_awnd.connected_ticks[AWND_BAND_5TH] == 36 && g_awnd.connected_ticks[AWND_BAND_5G] <= 36 && g_awnd.connected_ticks[AWND_BAND_3RD] <= 36 && g_awnd.connected_ticks[AWND_BAND_4TH] <= 36))
        && g_awnd.meshmode == AWND_MESHMODE_2G_DYNAMIC)
    {
        AWN_LOG_NOTICE("lxdebug need set ticks 361\n");
        g_awnd.meshstate = AWND_MESHSTATE_2G_DISCONNECT;
        g_awnd.ticks = 361;
    }
    AWN_LOG_NOTICE("lxdebug ====meshmode_2g_inspect loop====, meshmode=%d, meshstate=%d\n",
        g_awnd.meshmode,g_awnd.meshstate);

    //meshmode=0
    if (g_awnd.meshmode == AWND_MESHMODE_2G_DISCONNECT)
    {
        AWN_LOG_NOTICE("lxdebug meshmode check 0!!!\n");
        if (AWND_STATUS_DISCONNECT != g_awnd.connStatus[AWND_BAND_2G])
        {
            AWN_LOG_NOTICE("lxdebug do disconnect rootap\n");
            g_awnd.connStatus[AWND_BAND_2G] = AWND_STATUS_DISCONNECT;
            awnd_disable_sta_vap(1, AWND_BAND_2G);
        }
        if(AWND_OK == awnd_get_chanim(AWND_BAND_2G, &chanutil, &intf, &cur_chan, &bw))
        {
            target_chan = awnd_find_idle_channel(cur_chan);
            if (record_channel_2g != 0)
            {
                if (cfg_channel != 0)
                {
                    target_chan = cfg_channel;
                }
                else
                {
                    target_chan = record_channel_2g;
                }
            }
            if (bandwidth_2g == WIFI_BW_40M)
            {
                targetBw = WIFI_BW_40M;
            }
            AWN_LOG_NOTICE("lxdebug target_chan=%d, cur_chan=%d, target_bw=%d, bw=%d \n",
                target_chan,cur_chan,targetBw,bw);
            if (cur_chan != target_chan || bw != targetBw)
            {
                awnd_do_csa(target_chan,targetBw,CHAN_OFFSET_NONE);
            }
            
        }

        uloop_timeout_set(t,  l_awnd_config.tm_meshmode_2g_inspect);
        return;

    }
    //meshmode=1
    else if (g_awnd.meshmode == AWND_MESHMODE_2G_CONNECT)
    {
#ifndef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        if (AWND_STATUS_CONNECTED != g_awnd.ethStatus) {
#endif
        AWN_LOG_NOTICE("lxdebug meshmode check 1!!!\n");
        if (AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_2G] &&
            memcmp(&cmpApEntry, &g_awnd.rootAp[AWND_BAND_2G], sizeof(AWND_AP_ENTRY)) &&
            awnd_config_get_stacfg_enb(AWND_BAND_2G))
        {
            AWN_LOG_NOTICE("lxdebug do reconnect rootap\n");
            g_awnd.connStatus[AWND_BAND_2G] = AWND_STATUS_CONNECTING;
            awnd_disable_sta_vap(0, AWND_BAND_2G);
        }
#ifndef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        }
#endif
        if (AWND_STATUS_CONNECTED == g_awnd.connStatus[AWND_BAND_2G] && AWND_OK == awnd_get_backhaul_ap_channel(AWND_BAND_2G, &real_channel))
        {
            if (real_channel != 0 && real_channel != g_awnd.rootAp[AWND_BAND_2G].channel)
            {
                g_awnd.rootAp[AWND_BAND_2G].channel = real_channel;
            }
        }
        uloop_timeout_set(t,  l_awnd_config.tm_meshmode_2g_inspect);
        return;
    }
    //meshmode=2
    else if (g_awnd.meshmode == AWND_MESHMODE_2G_DYNAMIC)
    {
        AWN_LOG_NOTICE("lxdebug meshmode check 2!!!, ticks=%d\n",g_awnd.ticks);
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band] && 
                AWND_OK == awnd_get_rootap_phyRate(band, &txRate, &rxRate) &&
                AWND_OK == awnd_get_rootap_rssi(band, &rssi))
            {
                if ((mediumRate = _updateSample(wifiRateSamples[band][0], WIFI_SAMPLE_MAX_NUM, rxRate, FALSE)) != 0)
                {
                    g_awnd.rootAp[band].rxRate= mediumRate;
                }
                else
                {
                    g_awnd.rootAp[band].rxRate= rxRate;
                }
                if ((mediumRate = _updateSample(wifiRateSamples[band][1], WIFI_SAMPLE_MAX_NUM, txRate, FALSE)) != 0)
                {
                    g_awnd.rootAp[band].txRate= mediumRate;
                }
                else
                {
                    g_awnd.rootAp[band].txRate= txRate;
                }
                g_awnd.rootAp[band].maxRate = (g_awnd.rootAp[band].txRate >= g_awnd.rootAp[band].rxRate) ? g_awnd.rootAp[band].txRate : g_awnd.rootAp[band].rxRate ;
                g_awnd.rootAp[band].rssi = rssi;
                g_awnd.connected_ticks[band]++;
                
            }
            else
            {
                _updateSample(wifiRateSamples[band][0], WIFI_SAMPLE_MAX_NUM, rxRate, TRUE);
                _updateSample(wifiRateSamples[band][1], WIFI_SAMPLE_MAX_NUM, txRate, TRUE);
            }

            if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band] && 
                AWND_OK == awnd_get_chanim(band, &chanutil, &intf, &cur_chan, &bw))
            {
                g_awnd.rootAp[band].chanutil = chanutil;
                g_awnd.rootAp[band].intf = intf;
            }
            AWN_LOG_NOTICE("Band %s rssi:%d, txrate:%d, rxrate:%d, mediumRate:%d, maxRate:%d, chanutil:%d, intf:%d.\n", real_band_suffix[band],
                    g_awnd.rootAp[band].rssi, g_awnd.rootAp[band].txRate, g_awnd.rootAp[band].rxRate, mediumRate, g_awnd.rootAp[band].maxRate,g_awnd.rootAp[band].chanutil,g_awnd.rootAp[band].intf);

        }

        //condition1: rssi_5g-95<-83 && rate_5g<13
        if ((AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5G] || AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_3RD])
            || (g_awnd.rootAp[AWND_BAND_5G].maxRate < AWND_5G_WEAKLINK_RATE_THRESH * AWND_WINDOW_FACTOR_LOW
                && g_awnd.rootAp[AWND_BAND_5G].rssi -95 < AWND_5G_WEAKLINK_RSSI_THRESH * AWND_WINDOW_FACTOR_LOW)
            || (g_awnd.rootAp[AWND_BAND_3RD].maxRate < AWND_6G_WEAKLINK_RATE_THRESH * AWND_WINDOW_FACTOR_LOW
                && g_awnd.rootAp[AWND_BAND_3RD].rssi -95 < AWND_6G_WEAKLINK_RSSI_THRESH * AWND_WINDOW_FACTOR_LOW))
        {
            //360*5=1800s,30min
            if (g_awnd.ticks > 360)
            {
                AWN_LOG_NOTICE("lxdebug condition1 match, set meshstate 1!!!\n");
                g_awnd.meshstate = AWND_MESHSTATE_2G_CONNECT;
                g_awnd.ticks = 0;
            }
        }
        //condition2: util_5g>70 && util_6g>70 && (rssi_5g-95<-74 || rssi_6g-95<-84)
        else if (g_awnd.rootAp[AWND_BAND_5G].chanutil > AWND_PATH_OVERLOAD_THRESH * AWND_WINDOW_FACTOR_HIGH
                && g_awnd.rootAp[AWND_BAND_3RD].chanutil > AWND_PATH_OVERLOAD_THRESH* AWND_WINDOW_FACTOR_HIGH
                && (g_awnd.rootAp[AWND_BAND_5G].rssi -95 < AWND_2GAPSDNEED_5G_RSSI_THRESH * AWND_WINDOW_FACTOR_LOW
                    || g_awnd.rootAp[AWND_BAND_3RD].rssi -95 < AWND_2GAPSDNEED_6G_RSSI_THRESH * AWND_WINDOW_FACTOR_LOW))
        {
            if (g_awnd.ticks > 360)
            {
                AWN_LOG_NOTICE("lxdebug condition2 match, set meshstate 1!!!\n");
                g_awnd.meshstate = AWND_MESHSTATE_2G_CONNECT;
                g_awnd.ticks = 0;
            }
        }
        //condition3: obss+nopkt>50
        else if (((g_awnd.rootAp[AWND_BAND_5G].maxRate > AWND_5G_WEAKLINK_RATE_THRESH * AWND_WINDOW_FACTOR_HIGH
                        || g_awnd.rootAp[AWND_BAND_5G].rssi -95 > AWND_5G_WEAKLINK_RSSI_THRESH * AWND_WINDOW_FACTOR_HIGH)
                    && (g_awnd.rootAp[AWND_BAND_3RD].maxRate > AWND_6G_WEAKLINK_RATE_THRESH * AWND_WINDOW_FACTOR_HIGH
                        || g_awnd.rootAp[AWND_BAND_3RD].rssi -95 > AWND_6G_WEAKLINK_RSSI_THRESH * AWND_WINDOW_FACTOR_HIGH))
                && (g_awnd.rootAp[AWND_BAND_5G].chanutil < AWND_PATH_OVERLOAD_THRESH * AWND_WINDOW_FACTOR_LOW
                    || g_awnd.rootAp[AWND_BAND_3RD].chanutil < AWND_PATH_OVERLOAD_THRESH* AWND_WINDOW_FACTOR_LOW
                    || (g_awnd.rootAp[AWND_BAND_5G].rssi -95 > AWND_2GAPSDNEED_5G_RSSI_THRESH * AWND_WINDOW_FACTOR_HIGH
                        && g_awnd.rootAp[AWND_BAND_3RD].rssi -95 > AWND_2GAPSDNEED_6G_RSSI_THRESH * AWND_WINDOW_FACTOR_HIGH))
                && g_awnd.rootAp[AWND_BAND_2G].intf > AWND_2G_INTF_THRESH)
        {
            if (g_awnd.ticks > 360)
            {
                AWN_LOG_NOTICE("lxdebug condition3 match, set meshstate 0!!!\n");
                g_awnd.meshstate = AWND_MESHSTATE_2G_DISCONNECT;
                g_awnd.ticks = 0;
            }
        }

        AWN_LOG_NOTICE("lxdebug meshmode check over, state is %d \n",g_awnd.meshstate);
        if (g_awnd.meshstate == AWND_MESHSTATE_2G_DISCONNECT)
        {
            if (AWND_STATUS_DISCONNECT != g_awnd.connStatus[AWND_BAND_2G])
            {
                AWN_LOG_NOTICE("lxdebug do disconnect rootap\n");
                g_awnd.connStatus[AWND_BAND_2G] = AWND_STATUS_DISCONNECT;
                awnd_disable_sta_vap(1, AWND_BAND_2G);
            }
            if(AWND_OK == awnd_get_chanim(AWND_BAND_2G, &chanutil, &intf, &cur_chan, &bw))
            {
                target_chan = awnd_find_idle_channel(cur_chan);
                if (record_channel_2g != 0)
                {
                    if (cfg_channel != 0)
                    {
                        target_chan = cfg_channel;
                    }
                    else
                    {
                        target_chan = record_channel_2g;
                    }
                }
                if (bandwidth_2g == WIFI_BW_40M)
                {
                    targetBw = WIFI_BW_40M;
                }
                AWN_LOG_NOTICE("lxdebug target_chan=%d, cur_chan=%d, targetBw=%d, bw=%d \n",
                    target_chan,cur_chan,targetBw,bw);
                if (cur_chan != target_chan || bw != targetBw)
                {
                    awnd_do_csa(target_chan,targetBw,CHAN_OFFSET_NONE);
                }
            }
        }
        else if (g_awnd.meshstate == AWND_MESHSTATE_2G_CONNECT)
        {
            if (AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_2G] &&
                memcmp(&cmpApEntry, &g_awnd.rootAp[AWND_BAND_2G], sizeof(AWND_AP_ENTRY)) &&
                awnd_config_get_stacfg_enb(AWND_BAND_2G))
            {
                AWN_LOG_NOTICE("lxdebug do reconnect rootap\n");
                g_awnd.connStatus[AWND_BAND_2G] = AWND_STATUS_CONNECTING;
                awnd_disable_sta_vap(0, AWND_BAND_2G);
            }
            if (AWND_STATUS_CONNECTED == g_awnd.connStatus[AWND_BAND_2G] && AWND_OK == awnd_get_backhaul_ap_channel(AWND_BAND_2G, &real_channel))
            {
                if (real_channel != 0 && real_channel != g_awnd.rootAp[AWND_BAND_2G].channel)
                {
                    g_awnd.rootAp[AWND_BAND_2G].channel = real_channel;
                }
            }
        }

        g_awnd.ticks++;
        uloop_timeout_set(t,  l_awnd_config.tm_meshmode_2g_inspect);
        return;
    }

}

//to find idle channel in 2/6/10
int awnd_find_idle_channel(int cur_chan)
{
	struct json_object *root = NULL;
    UINT32 lanip = 0;
    char *role = NULL;
    int channel_2g = 0;
    int rem = 0;
    int ret = cur_chan;

    if(AWND_OK != awn_get_lan_ip(&lanip))
    {
        AWN_LOG_NOTICE("Failed to get lanip\n");
        return ret;
    }

    rem = (lanip & 0xff) % 3;
    ret = rem * 4 + 2;
    AWN_LOG_NOTICE("lxdebug lanip=%x, init_chan=%d\n", lanip, ret);

    root = json_object_from_file(SYNC_DEV_LIST_FILE);
    if (NULL == root)
    {
        AWN_LOG_NOTICE("Failed to read json file %s\n",SYNC_DEV_LIST_FILE);
        return ret;
    }

    json_object_object_foreach(root, key, val)
    {
        role = json_object_get_string(json_object_object_get(val, "role"));

        if(role && !memcmp(role, "AP", 2))
        {
            channel_2g = json_object_get_int(json_object_object_get(val, "channel_2g"));

            if (!channel_2g) {
                AWN_LOG_NOTICE("Invalid mesh device data format.\n");
            } else {
                AWN_LOG_NOTICE("lxdebug get fap channel_2g:%d\n",channel_2g);
            }

            break;
        }
    }

    if(channel_2g)
    {
        if(channel_2g <= 4)
        {
            // 如果FAP信道为2、3、4，则RE信道设置顺序为10、6、2
            rem = (rem + 3 - 2) % 3;
        }
        else if(channel_2g <= 7)
        {
            if(channel_2g <= 6)
            {
                // 如果FAP信道为5、6，则RE信道设置顺序为10、2、6
                rem = (3 - rem) % 3;
            }
            else
            {
                // 如果FAP信道为7，则RE信道设置顺序为2、10、6
                rem = (rem + 3 - 1) % 3;
            }
        }
        else
        {
            // 如果FAP信道为8、9、10，则RE信道设置顺序为2、6、10
            rem = (1 - rem + 3) % 3;
        }

        ret = rem * 4 + 2;
        AWN_LOG_NOTICE("lxdebug pick channel---%d\n", ret);
    }

	if (root)
	{
		json_object_put(root);
		root = NULL;
	}

    return ret;
}
#endif


int awnd_deliver_tpie(AWND_CONN_STATUS *pConnState, AWND_AP_ENTRY *pRootAp, UINT* disBandMask)
{
    int               bestBand;
    AWND_BAND_TYPE    band;    
    AWND_NET_INFO     tmpNetInfo;
    static AWND_HOTPLUG_CONFIG hotplugCfg;
    AWND_NET_CHANGE_TYPE netChanged = AWND_NET_HOLD;
    int linked = 0;
    int updated = 0;
    int capMacChanged = 0;
    UINT8 *pRootApMac = NULL;
    
    /*check netInfo of rootAp and update tpie*/
    bestBand = -1;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (AWND_STATUS_CONNECTED == pConnState[band] && _is_vaild_mac(pRootAp[band].netInfo.awnd_mac))
        {
            linked = 1;
            if (-1 == bestBand) bestBand = band;
            else 
            {
                bestBand = (pRootAp[bestBand].netInfo.awnd_level >= pRootAp[band].netInfo.awnd_level) ? bestBand : band ;
            }
        }
    }

    /*pass info */
    if (bestBand != -1)
    {        
        memcpy(&tmpNetInfo, &pRootAp[bestBand].netInfo, sizeof(AWND_NET_INFO));
        tmpNetInfo.awnd_level += 1;
        updated = 1;		

        if (_is_vaild_mac(pRootAp[bestBand].lan_mac))
            pRootApMac = pRootAp[bestBand].lan_mac;
#ifdef CONFIG_PRODUCT_PLC_SGMAC
        if (AWND_STATUS_CONNECTED == g_awnd.plcStatus && 
            _mac_compare(pRootApMac, g_awnd.plcPeerNeigh.lan_mac) != 0 &&
            (g_awnd.plcPeerNeigh.netInfo.awnd_net_type < tmpNetInfo.awnd_net_type))
        {
            AWN_LOG_WARNING("wifi rootap netInfo net_type(%d) > plc rootap net_type(%d) to disconenct", 
                tmpNetInfo.awnd_net_type, g_awnd.plcPeerNeigh.netInfo.awnd_net_type);
            return 3;
        }
#endif
    }
    else if (AWND_STATUS_CONNECTED != g_awnd.plcStatus)
    {
        awnd_init_tpie(&tmpNetInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
        updated = 1;

        pRootApMac = g_awnd.plcPeerNeigh.lan_mac;
    }

    if (updated && (memcmp(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO)) || (pRootApMac != NULL && memcmp(pRootApMac, old_parent_mac, AWND_MAC_LEN))))
    {        
        if (!IN_SAME_SUBNET_EXACT(&g_awnd.netInfo, &tmpNetInfo))
        {
            if (tmpNetInfo.awnd_net_type == AWND_NET_FAP && g_awnd.netInfo.awnd_net_type != tmpNetInfo.awnd_net_type)
            {
                netChanged = AWND_NET_BECOME_STABLE;
            }
            else
            {
                netChanged = AWND_NET_BECOME_UNSTABLE;
            }

        }
        
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
        //if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus){
        //    memcpy(&g_awnd.ethNetInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
        //}
        awnd_print_netInfo();
        awnd_update_tpie(&tmpNetInfo, AWND_NETINFO_WIFI);
#else
        awnd_update_tpie(&tmpNetInfo);
#endif
        awnd_write_work_mode(g_awnd.workMode, linked, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, pRootApMac);

        if (linked && memcmp(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN) && _is_vaild_mac(g_awnd.capMac))
        {   /* only to call hotplug when capMac change from vaild_mac to vaild_mac */
            hotplugCfg.srcMode = AWND_MODE_RE;
            hotplugCfg.dstMode = AWND_MODE_RE;
            hotplugCfg.type = AWND_HOTPLUG_CAP_CHANGE;
            awnd_mode_call_hotplug(&hotplugCfg);
            capMacChanged = 1;
        }
        if (linked && memcmp(l_awnd_config.mac, tmpNetInfo.awnd_mac, AWND_MAC_LEN))
        {   /* not to update g_awnd.capMac with l_awnd_config.mac */
            memcpy(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN);
        }

        if (linked && (AWND_NET_LRE != tmpNetInfo.awnd_net_type) && (AWND_NET_MAX != g_awnd.capNetType))
        {
            hotplugCfg.srcMode = AWND_MODE_RE;
            hotplugCfg.dstMode = AWND_MODE_RE;
            hotplugCfg.type = AWND_HOTPLUG_CAP_TYPE_CHANGE;

            if (tmpNetInfo.awnd_net_type != g_awnd.capNetType)
            {   /* to call hotplug when cap net_type change from vaild_type to vaild_type */
                if (AWND_NET_FAP == tmpNetInfo.awnd_net_type)
                {
                    hotplugCfg.capSrcType = AWND_NET_HAP;
                    hotplugCfg.capDstType = AWND_NET_FAP;
                }
                else if (AWND_NET_HAP == tmpNetInfo.awnd_net_type)
                {
                    hotplugCfg.capSrcType = AWND_NET_FAP;
                    hotplugCfg.capDstType = AWND_NET_HAP;
                }
                awnd_mode_call_hotplug(&hotplugCfg);
            }
            else if (capMacChanged)
            {   /* to call hotplug when cap net_type is not changed but cap mac is changed */
                hotplugCfg.capSrcType   =   tmpNetInfo.awnd_net_type;
                hotplugCfg.capDstType   =   tmpNetInfo.awnd_net_type;
                awnd_mode_call_hotplug(&hotplugCfg);
            }
        }

        if(linked && AWND_NET_LRE != tmpNetInfo.awnd_net_type)
        {   /* not to update net type when rootap's net type is LRE */
            g_awnd.capNetType = tmpNetInfo.awnd_net_type;
        }

        if (linked && (g_awnd.capLanip != tmpNetInfo.awnd_lanip)
            && (0 != g_awnd.capLanip) && (0 != tmpNetInfo.awnd_lanip))
        {   /* only to call hotplug when cap lanip change from vaild ip to vaild ip */
             hotplugCfg.srcMode = AWND_MODE_RE;
             hotplugCfg.dstMode = AWND_MODE_RE;
             hotplugCfg.type = AWND_HOTPLUG_CAP_IP_CHANGE;
             awnd_mode_call_hotplug(&hotplugCfg);
        }
        if (linked && (0 != tmpNetInfo.awnd_lanip))
        {
            g_awnd.capLanip = tmpNetInfo.awnd_lanip; 
        }

        if (linked && (g_awnd.capDns != tmpNetInfo.awnd_dns)
            && (0 != g_awnd.capDns) && (0 != tmpNetInfo.awnd_dns))
        {   /* only to call hotplug when cap dns change from vaild ip to vaild ip */
             hotplugCfg.srcMode = AWND_MODE_RE;
             hotplugCfg.dstMode = AWND_MODE_RE;
             hotplugCfg.type = AWND_HOTPLUG_CAP_DNS_CHANGE;
             awnd_mode_call_hotplug(&hotplugCfg);
        }
        if (linked && (0 != tmpNetInfo.awnd_dns))
        {
            g_awnd.capDns = tmpNetInfo.awnd_dns;
        }
        
#ifndef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
#endif
    }
    
    return netChanged;
}


/* at least disconnect a STA if STA of different bands is connected or connecting to different subnets */
int awnd_check_in_same_subnet(AWND_CONN_STATUS *pConnState, AWND_AP_ENTRY *pRootAp, UINT* disBandMask)
{
    AWND_BAND_TYPE    band;    
    AWND_NET_INFO     tmpNetInfo;
    int update_tpie = 0;
    int tryCnt = 0;

    if (!pConnState || !pRootAp )
        return 0;
    
    if (_is_one_band_disconnected(pConnState))
        return 0;

    

    while(! IN_SAME_SUBNET_EXACT(&pRootAp[AWND_BAND_2G].netInfo, &pRootAp[AWND_BAND_5G].netInfo) && tryCnt < 2)
    {
        usleep(200000 * (abs(pRootAp[AWND_BAND_2G].netInfo.awnd_level - pRootAp[AWND_BAND_5G].netInfo.awnd_level) + 1));
        
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            memset(&tmpNetInfo, 0, sizeof(AWND_NET_INFO));
            if (AWND_OK == awnd_get_tpie(pRootAp[band].bssid, IEEE80211_TP_IE_IN_ANY, &tmpNetInfo, band))
            {
                memcpy(&pRootAp[band].netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));    
            }
            else
            {
                AWN_LOG_INFO("Get band %s rootAp tpie fail, bssid:%02X:%02X:%02X:%02X:%02X:%02X", real_band_suffix[_get_real_band_type(band)],
                    pRootAp[AWND_BAND_2G].bssid[0], pRootAp[AWND_BAND_2G].bssid[1], pRootAp[AWND_BAND_2G].bssid[2],
                    pRootAp[AWND_BAND_2G].bssid[3], pRootAp[AWND_BAND_2G].bssid[4], pRootAp[AWND_BAND_2G].bssid[5]); 
            }        
        }
        
        update_tpie = 1;
        tryCnt++;
    }
    
    if (! IN_SAME_SUBNET_EXACT(&pRootAp[AWND_BAND_2G].netInfo, &pRootAp[AWND_BAND_5G].netInfo))
    {
        if (_is_both_band_connected(pConnState))
        {
            if (HIGH_PRIO_SUBNET(&(pRootAp[AWND_BAND_2G].netInfo), &(pRootAp[AWND_BAND_5G].netInfo)))
            {
                awnd_disconn_sta_pre(AWND_BAND_5G, disBandMask);
                AWN_LOG_INFO("disconnect 5g if not in same subnet");
            }
            else
            {
                awnd_disconn_sta_pre(AWND_BAND_2G, disBandMask);
                AWN_LOG_INFO("disconnect 2.4g if not in same subnet");
            }
        }
        else if (AWND_STATUS_CONNECTED == pConnState[AWND_BAND_2G])
        {
            awnd_disconn_sta_pre(AWND_BAND_5G, disBandMask);
            AWN_LOG_INFO("disconnect 5g if not in same subnet and only 2.4g link up");
        }
        else if (AWND_STATUS_CONNECTED == pConnState[AWND_BAND_5G])
        {
            awnd_disconn_sta_pre(AWND_BAND_2G, disBandMask);
            AWN_LOG_INFO("disconnect 2.4g if not in same subnet and only 5g link up");
        }
        else
        {
            awnd_disconn_sta_pre(AWND_BAND_2G, disBandMask);
            awnd_disconn_sta_pre(AWND_BAND_5G, disBandMask);
            AWN_LOG_INFO("disconnect both band if not in same subnet and both link down");
        }
    }

    return update_tpie;
}

void awnd_conn_timeout_handler(struct uloop_timeout *t)
{
#ifdef CONNECT_TO_SAME_DUT
    return;
#endif

    UINT disBandMask = 0;
    AWND_BAND_TYPE   band;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (AWND_STATUS_CONNECTING == g_awnd.connStatus[band])
        {
             awnd_disconn_sta_pre(band, &disBandMask);
             AWN_LOG_INFO("disconn sta because of connect timeout");
        }
    }

    if (_is_in_disconnected_state(g_awnd.connStatus))
    {
        awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_WIFI);
#else
        awnd_update_tpie(&g_awnd.netInfo);            
#endif
    }

    /* really disconnect STA */
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {     
        if (disBandMask & (1 << band))
        {
            AWN_LOG_INFO("disconnect band mask:%x", disBandMask);
            awnd_disconn_sta_post(band);
        }
    }
    
    return ;    
}

int awnd_conn_inspect_status(UINT8 *scanBandMask)
{
    AWND_BAND_TYPE    band;
    AWND_REAL_BAND_TYPE real_band = 0;
    AWND_NET_INFO     tmpNetInfo;
    AWND_AP_ENTRY    *pRootAp    = g_awnd.rootAp;
    AWND_CONN_STATUS *pConnState = g_awnd.connStatus;
    AWND_CONN_STATUS  oldConnState[AWND_BAND_MAX];     
    int link[AWND_BAND_MAX] = {0};
	int sta_cur_ch[AWND_BAND_MAX] = {0};
	int backhaul_ap_cur_ch[AWND_BAND_MAX] = {0};
	int config_cur_ch[AWND_BAND_MAX] = {0};	
#if CONFIG_PLATFORM_BCM
    UINT8 is_ch_same = 1;
#else
    BOOL is_ch_same = TRUE;
#endif
    int up[AWND_BAND_MAX] = {0};
    int all_disconnected = 1;
    int noEntryScanInterval = 0;
    UINT disBandMask = 0;
    int   wifi_restart = 0;
    int net_changed = 0;	
    int ret_tpie = 0; 
    int get_tpie = 1;
    int ret = AWND_OK;
    int entry_type;
    int get_channel_sta = AWND_OK;
    int get_channel_backhaul_ap = AWND_OK;
#if CONFIG_PLATFORM_BCM
    UINT8 PostBandMask = 0;
#endif /* CONFIG_PLATFORM_BCM */
#if CONFIG_5G_HT160_SUPPORT
    AWND_WIFI_BW_TYPE cur_bw = 0;
#endif /* CONFIG_5G_HT160_SUPPORT */
    int conn_prefer_ap = 0;
    BOOL scan_contiune_band = FALSE;
#if WPA_PRI_STATE_CHECK
    int wpa_sup_status = 0;
#endif
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    BOOL wds_connected[AWND_BAND_MAX_NUM] = {0};
#endif

#if FAST_RECONNECT_ROOTAP
    int need_fast_reconnect = 0;
    char bssid_str[AWND_MAX_SSID_LEN];
    char cmdline[CMDLINE_LENGTH] = {0};
    int idx_tpEntry = 0;
    AWND_AP_ENTRY* tmp_pCurApEntry;
#endif
#ifdef SUPPORT_MESHMODE_2G
    AWND_AP_ENTRY cmpApEntry;
#endif
#if CONFIG_OUTDOOR_CHANNELLIMIT
    int no_entry_threshold_sec = NO_ENTRY_THRESOLD_SEC;
#endif

    int cac_state = 0;
    *scanBandMask = 0;

    /* get link state */
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) 
    {    	
        //AWN_LOG_ERR("band:%d, num:%d, ifname:%s", band, l_awnd_config.band_num, l_awnd_config.staIfnames[band]);
        oldConnState[band] = pConnState[band];

        get_channel_sta = awnd_get_sta_channel(band, &sta_cur_ch[band]);  
        /*return msg:
            AWND_ERROR : get channel fail.
            AWND_BUSY : AWN is scanning.
            AWND_OK : get channel success.
         */
        if (AWND_ERROR == get_channel_sta)
        {
            sta_cur_ch[band] = g_awnd.rootAp[band].channel;
        }
		
        get_channel_backhaul_ap = awnd_get_backhaul_ap_channel(band, &backhaul_ap_cur_ch[band]);
        if (AWND_ERROR == get_channel_backhaul_ap)
        {
            backhaul_ap_cur_ch[band] = g_awnd.rootAp[band].channel;
        }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#if GET_AP_RSSI     
        link[band] = awnd_get_wds_state(band, &up[band], &g_awnd.rootApRtRssi[band], wds_connected);
#else
        link[band] = awnd_get_wds_state(band, &up[band], wds_connected);
#endif  /* GET_AP_RSSI */
#else
#if GET_AP_RSSI
        link[band] = awnd_get_wds_state(band, &up[band], &g_awnd.rootApRtRssi[band]);
#else
        link[band] = awnd_get_wds_state(band, &up[band]);
#endif  /* GET_AP_RSSI */
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
        if (AWND_STATUS_DISCONNECT == oldConnState[band] && link[band])
        {
            awnd_disconn_sta_post(band);
            link[band] = 0;
        }
        
        if (link[band])
        {
            all_disconnected = 0;
        }
    }

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    if (roaming_running)
    {
        BOOL roaming_connected = false;
        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        {
            if (wds_connected[band]){
                roaming_running = false;
                roaming_connected = true; 
                AWN_LOG_ERR("band %d connect: %d", band, wds_connected[band]);
                break;
            }
        }
        if (!roaming_connected)
        {
            AWN_LOG_INFO("roaming!! skip awnd_conn_inspect_status");
            return AWND_OK;
        }
    }
#endif

#if GET_AP_RSSI
    if (_is_in_connected_state(oldConnState) && !all_disconnected)
    {
        awnd_write_rt_rootap_rssi(g_awnd.rootApRtRssi);
    }
#endif
    if (_is_in_disconnected_state(oldConnState))
    {    	
        return AWND_OK;
    }


    if (_is_in_connected_state(oldConnState) && all_disconnected){
        g_awnd.unlinkcnt++;
        if (g_awnd.unlinkcnt < 10)
        {
            AWN_LOG_INFO("all band link down %u......", g_awnd.unlinkcnt);
            // return AWND_OK;
        }
        AWN_LOG_NOTICE("ALL band link down.");
        l_awnd_scan_table.scan_fast = 0;
    }
    g_awnd.unlinkcnt = 0;

#if AWND_BIND_SWITCH_BACKHUAL_FIRST

#else
    if (_is_in_connected_state(oldConnState) && all_disconnected && (g_awnd.notBind && AWND_BIND_START == g_awnd.bindStatus)) {
        _save_bind_status(1);
        memcpy(&(l_group_info.staGroupInfo), &(l_group_info.backhualGroupInfo), sizeof(GROUP_INFO));
        g_awnd.bindStatus = AWND_BIND_BACKHUAL_CONNECTING;
    }
#endif
 
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {  

#if SCAN_OPTIMIZATION
        if (link[band])
        {
            int conn_time = g_awnd.connet_time[band] * l_awnd_config.tm_status_interval; // l_awnd_config.tm_status_interval = 200
            if (conn_time < (NO_ENTRY_LONG_SCAN_SEC * 1000))
            {
                g_awnd.connet_time[band] = g_awnd.connet_time[band] + 1;
            }
        }
        else
        {
            g_awnd.connet_time[band] = 0;
        }
#endif

        if (link[band]) 
        {
            if (AWND_STATUS_CONNECTED != pConnState[band])
            {
                AWN_LOG_INFO("band %s link up", real_band_suffix[_get_real_band_type(band)]);
                awnd_write_rt_info(band, TRUE, g_awnd.rootAp[band].bssid, false);
                pConnState[band] = AWND_STATUS_CONNECTED;
#ifdef SUPPORT_MESHMODE_2G
                g_awnd.connected_ticks[band] = 0;
#endif
                // Add by CWQ, To solve BE65v2 Bug 876159
                if (band == AWND_BAND_5G)
                {
                    AWN_LOG_DEBUG("backhaul_ap_cur_ch[band] is %d, now set channel", backhaul_ap_cur_ch[band]);
                    awnd_config_set_channel(backhaul_ap_cur_ch[band],band);
                }
#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
				if (band == AWND_BAND_5G && 1 == is_set_ignorecac)
				{
                    char qca_wifi_5g[6] = {0};
                    char cmd[128] = {0};
                    if(access("/etc/profile.d/interfaces",0) == 0)
                    {
                        FILE *fp = NULL;
                        fp = popen("uci -c /etc/profile.d/ get interfaces.radio_5g.name", "r");
                        if(fp != NULL)
                        {
                            fread(qca_wifi_5g,sizeof(qca_wifi_5g),1,fp);
                            snprintf(cmd, sizeof(cmd), "radartool -i %s ignorecac 1", qca_wifi_5g);
                            pclose(fp);
                        }else
                        {
                            snprintf(cmd, sizeof(cmd), "radartool -i wifi1 ignorecac 1");
                        }
                    }
					AWN_LOG_CRIT("system: radartool -i wifi1 ignorecac 0");
					is_set_ignorecac = 0;
					system(cmd);
				}
#endif
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_WIFI);
#else
                awnd_update_tpie(&g_awnd.netInfo);
#endif

#if CONFIG_PLATFORM_BCM
                g_awnd.disconnRecord[band] = 0;
#endif
            }
        }
        else if (AWND_STATUS_CONNECTED == pConnState[band])
        {
            awnd_update_wifi_uplink_mask(&g_awnd.netInfo, band, AWND_STATUS_DISCONNECT);
            awnd_write_rt_info(band, FALSE, NULL, false);

#if CONFIG_PLATFORM_BCM
            awnd_flush_scan_table_single_band(band, TRUE);
            g_awnd.disconnRecord[band] = 3;
#endif

#if CONFIG_5G_HT160_SUPPORT
            if (!g_awnd.notBind && AWND_BAND_5G == band && ENABLE == g_awnd.ht160Enable &&
                AWND_OK == awnd_get_wifi_bw(AWND_BAND_5G, &cur_bw) && WIFI_BW_160M == cur_bw &&
                AWND_OK == g_awnd.zwdfs_support[AWND_BAND_5G])
            {
                AWN_LOG_WARNING("band %s link down, to down bw form HT160 to HT80", real_band_suffix[_get_real_band_type(band)]);
                awnd_set_wifi_bw(AWND_BAND_5G, g_awnd.rootAp[band].channel, WIFI_BW_80M);
            }
#endif /* CONFIG_5G_HT160_SUPPORT */
        }
    }

    /* check link state for connnected state */
    if (_is_in_connected_state(oldConnState))
    {
        if (all_disconnected)
        {
#if FAST_RECONNECT_ROOTAP
            need_fast_reconnect = 1;
#endif
            AWN_LOG_INFO("disconnect all band if all link down");
            awnd_disconn_all_sta_pre(&disBandMask);
        }
        else
        {
            for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
            {
                if (! link[band] && AWND_STATUS_CONNECTED == oldConnState[band])
                {
                    AWN_LOG_INFO("band %s is reconnecting", real_band_suffix[_get_real_band_type(band)]);
                    pConnState[band] = AWND_STATUS_CONNECTING;
#ifdef SUPPORT_MESHMODE_2G
                    g_awnd.connected_ticks[band] = 0;
#endif
                    ret = AWND_RECONNECTING;
                } 

            }
        }       
    }    


    /* if ! IFF_UP don't get tpie, if not link and not found, set disconnect */
    /* get tpie of rootAp */
#if CONFIG_PLATFORM_BCM
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {        
        AWN_LOG_INFO("curCh[%d]:%d rootApch[%d]:%d pConnState:%d up:%d notFind:%d",
            band, sta_cur_ch[band], band, g_awnd.rootAp[band].channel, pConnState[band], up[band], pRootAp[band].notFind);
        /*******************************************************************
         to fix: is_ch_same = FALSE
            rootAp[band].channel = 0 (no rootap channel from scan result)
            sta_cur_ch != 0 (current work channel)
        ********************************************************************/
        if (AWND_BUSY == get_channel_backhaul_ap || AWND_BUSY == get_channel_sta)
        {
            is_ch_same = -1;
            AWN_LOG_DEBUG("awn is scanning, is_ch_same = -1.");
        }
        else if (0 == g_awnd.rootAp[band].channel ||
          ((sta_cur_ch[band] == g_awnd.rootAp[band].channel) && (backhaul_ap_cur_ch[band] == g_awnd.rootAp[band].channel)))
        {
            is_ch_same = 1;
        }
        else
        {
            is_ch_same = 0;
        }
        if (AWND_STATUS_DISCONNECT != pConnState[band] && up[band])
        {
            memset(&tmpNetInfo, 0, sizeof(AWND_NET_INFO));
            entry_type = (link[band] ? IEEE80211_TP_IE_IN_NODE : IEEE80211_TP_IE_IN_SCAN);
            /* if connected get form TP_IE_IN_NODE
              disconnect: get from scan entry, if not found return AWND_NOT_FOUND */
            if ((AWND_OK == (ret_tpie = awnd_get_tpie(pRootAp[band].bssid, entry_type, &tmpNetInfo, band)))
                && (is_ch_same == 1))
            {
                pRootAp[band].notFind = 0;
                memcpy(&pRootAp[band].netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
            }
            /*todo: ret==-3,can't find scan entry, disconnect or don't print*/
            else if ((AWND_NOT_FOUND == ret_tpie) || (is_ch_same == 0))
            {
                get_tpie = 0;                
                AWN_LOG_DEBUG("can't find scan entry");

                /************************************************************************
                    enable6g=1:  wpa_supplicant disable 2G/5G/6G
                    enable6g=0:  wpa_supplicant disable 2G/5G, 6G contiue scanning
                    enable5g2=1:  wpa_supplicant disable 2G/5G/5G2
                    enable5g2=0:  wpa_supplicant disable 2G/5G, 5G2 contiue scanning
                *************************************************************************/
				if (l_awnd_config.band_num == AWND_BAND_NUM_3)
				{
					if(g_awnd.enable6g)
					{
						if((g_awnd.enable6g && band <= l_awnd_config.band_6g_type) || (!g_awnd.enable6g && band <= AWND_BAND_5G))
						{
							scan_contiune_band = FALSE;
						}else{
							/* Although wpa_supplicant is scanning, full band scanning need to be done here
								if the wrong channel has been set to wpa_supplicant */
							scan_contiune_band = TRUE;
						}
					}
					else
					{
						if((g_awnd.enable5g2 && band <= l_awnd_config.band_5g2_type) || (!g_awnd.enable5g2 && band <= AWND_BAND_5G))
						{
							scan_contiune_band = FALSE;
						}else{
							/* Although wpa_supplicant is scanning, full band scanning need to be done here
								if the wrong channel has been set to wpa_supplicant */
							scan_contiune_band = TRUE;
						}
					}
				}
				else 
				{
					if (band <= AWND_BAND_5G)
	                {                    
	                    scan_contiune_band = FALSE;
	                }
	                else
	                {
	                    /* Although wpa_supplicant is scanning, full band scanning need to be done here
	                        if the wrong channel has been set to wpa_supplicant */
	                    scan_contiune_band = TRUE;
	                }
				}

                pRootAp[band].notFind = pRootAp[band].notFind + 1;
                if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (NO_ENTRY_DISCONNECT_SEC * 1000))
                {
                    /* [600, + )  24G/5G: no scan + wpa_supplicnat disable; 5G2/6G: scan every 120s + wpa_supplicnat enable */
                    if (scan_contiune_band)
                    {
                        noEntryScanInterval = NO_ENTRY_RESCAN_LONG_TIMER;
                    }
                    else
                    {
                        awnd_disconn_sta_pre(band, &disBandMask);
                        noEntryScanInterval = 0;
                    }
                }
                else if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (NO_ENTRY_NO_SCAN_SEC * 1000))
                {
                    /* [300, 600) 24G/5G: no scan + wpa_supplicnat enable;  5G2/6G: scan every 120s + wpa_supplicnat enable */
                    if (scan_contiune_band)
                    {
                        noEntryScanInterval = NO_ENTRY_RESCAN_LONG_TIMER;
                    }
                    else
                    {
                        noEntryScanInterval = 0;
                    }
                }
                else if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (NO_ENTRY_LONG_SCAN_SEC * 1000))
                {
                    /* [180, 300) 24G/5G/5G2/6G: scan every 120s + wpa_supplicnat enable */
                    noEntryScanInterval = NO_ENTRY_RESCAN_LONG_TIMER;
                }
                else
                {
                    /* (0, 180)   scan every 30s + wpa_supplicnat enable */
                    noEntryScanInterval = NO_ENTRY_RESCAN_SHORT_TIMER;
                }

                if (noEntryScanInterval && 
                    (((pRootAp[band].notFind * l_awnd_config.tm_status_interval) % (noEntryScanInterval * 1000)) 
                       == (NO_ENTRY_RESCAN_BEGIN * 1000)))
                {
                    if (g_awnd.rootAp[band].channel && is_ch_same == 0) {
                        config_cur_ch[band] = awnd_config_get_channel(band);
                        if (config_cur_ch[band]  && backhaul_ap_cur_ch[band] && config_cur_ch[band] != backhaul_ap_cur_ch[band]) {
                            awnd_config_set_channel(backhaul_ap_cur_ch[band], band);
                            g_awnd.rootAp[band].channel = backhaul_ap_cur_ch[band];
                            wifi_restart = wifi_restart | (1 << band);
                        }
                    }

                    if (!g_awnd.notBind && 0 == wifi_restart && NO_ENTRY_RESCAN_LONG_TIMER == noEntryScanInterval && 0 == pRootAp[band].restartCnt)
                    {
                        pRootAp[band].restartCnt = pRootAp[band].restartCnt + 1;
                        AWN_LOG_WARNING("band:%d notFind in [180, 300), to wl down/up and wpa_supplicant disable/enable", band);
                        _stable_sleep(1);
                        awnd_do_band_restart(1 << band);
                        _stable_sleep(1);
                        awnd_reset_sta_connection(band);
                        _stable_sleep(1);
                    }

                    ret = AWND_SCAN_SCHED;
                    *scanBandMask |= (1 << band);
                    awnd_flush_scan_table_single_band(band, FALSE);
                }
                
                //ret = AWND_SCAN_SCHED;
                //awnd_disconn_sta_pre(band, &disBandMask);
            }
            else if (is_ch_same != -1)
            {
                pRootAp[band].notFind = 0;
                get_tpie = 0;
                AWN_LOG_INFO("Get %s rootAp tpie fail, bssid:%02X:%02X:%02X:%02X:%02X:%02X,link:%d, ret:%d", real_band_suffix[_get_real_band_type(band)],
                    pRootAp[band].bssid[0], pRootAp[band].bssid[1], pRootAp[band].bssid[2],
                    pRootAp[band].bssid[3], pRootAp[band].bssid[4], pRootAp[band].bssid[5], link[band], ret_tpie); 
            }
        }
    }
#else
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {        
        AWN_LOG_DEBUG("curCh[%d]:%d rootApch[%d]:%d pConnState:%d up:%d",
            band, sta_cur_ch[band], band, g_awnd.rootAp[band].channel, pConnState[band], up[band]);
		/*******************************************************************
		 to fix: is_ch_same = FALSE
		    rootAp[band].channel = 0 (no rootap channel from scan result)
		    sta_cur_ch != 0 (current work channel)
		********************************************************************/
		if (0 == g_awnd.rootAp[band].channel ||
            ((sta_cur_ch[band] == g_awnd.rootAp[band].channel) && (backhaul_ap_cur_ch[band] == g_awnd.rootAp[band].channel)))
		{
			is_ch_same = TRUE;
		}
		else
		{
			is_ch_same = FALSE;
		}
#ifdef SUPPORT_MESHMODE_2G
        if(AWND_BAND_2G == band && AWND_OK == awnd_file_exist(AWND_MESHMODE_2G_INSPECT_FILE) &&
           !((AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5G] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_3RD] &&
              AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_4TH] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5TH])
              && AWND_STATUS_CONNECTED != g_awnd.ethStatus))
        {
            is_ch_same = TRUE;
        }
#endif
        if (AWND_STATUS_DISCONNECT != pConnState[band] && up[band])
        {
            memset(&tmpNetInfo, 0, sizeof(AWND_NET_INFO));
            entry_type = (link[band] ? IEEE80211_TP_IE_IN_NODE : IEEE80211_TP_IE_IN_SCAN);
            /* if connected get form TP_IE_IN_NODE
                    disconnect: get from scan entry, if not found return AWND_NOT_FOUND */
            if ((AWND_OK == (ret_tpie = awnd_get_tpie(pRootAp[band].bssid, entry_type, &tmpNetInfo, band)))
				&& (is_ch_same == TRUE))
            {
                pRootAp[band].notFind = 0;
                memcpy(&pRootAp[band].netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
            }
            /*todo: ret==-3,can't find scan entry, disconnect or don't print*/
            else if ((AWND_NOT_FOUND == ret_tpie) 
					 || (is_ch_same == FALSE))
            {
                get_tpie = 0;                
                AWN_LOG_DEBUG("can't find scan entry");              

                /************************************************************************
                    wpa_supplicant disable 2G/5G
                    enable5g2/enable6g/enable6g2=1:  wpa_supplicant disable 5G2/6G/6G2
                    enable5g2/enable6g/enable6g2=0: 5G2/6G/6G2 wpa_supplicant contiue scanning
                *************************************************************************/
                if (band <= AWND_BAND_5G) {
                    scan_contiune_band = FALSE;
                }
                else {
                    scan_contiune_band = TRUE;
                    real_band = _get_real_band_type(band);
                    if (AWND_REAL_BAND_5G2 == real_band && g_awnd.enable5g2) {
                        scan_contiune_band = FALSE;
                    }
                    if (AWND_REAL_BAND_6G == real_band && g_awnd.enable6g) {
                        scan_contiune_band = FALSE;
                    }
                    if (AWND_REAL_BAND_6G2 == real_band && g_awnd.enable6g2) {
                        scan_contiune_band = FALSE;
                    }
                }

                pRootAp[band].notFind = pRootAp[band].notFind + 1;
#if CONFIG_OUTDOOR_CHANNELLIMIT
		/* reload as the channel limit config may be changed by user sometime */
                awnd_get_outdoor_channellimit(l_awnd_config.channellimit_id);
                if (AWND_BAND_5G == band && l_awnd_config.channellimit_support
                    && 0 == strncmp(l_awnd_config.channellimit_id, "1", CHANNELLIMIT_LEN)) {
                        no_entry_threshold_sec = OUTDOOR_CHANLIMIT_NO_ENTRY_THRESOLD_SEC;
                }
                if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (no_entry_threshold_sec * 1000))
#else
                if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (NO_ENTRY_THRESOLD_SEC * 1000))
#endif
                {
                    if (FALSE == scan_contiune_band)
                    {
                        awnd_disconn_sta_pre(band, &disBandMask);
                        noEntryScanInterval = 0;
                    }
                    else
                    {
                        /* Although wpa_supplicant is scanning, full band scanning need to be done here
                           if the wrong channel has been set to wpa_supplicant */
                        noEntryScanInterval = NO_ENTRY_RESCAN_LONG_TIMER;
                    }
                }
                else
                {
                    if (band == AWND_BAND_5G)
                    {
                        awnd_get_cac_state(band, &cac_state);
                        if (1 == cac_state)
                        {
                            pRootAp[band].notFind = pRootAp[band].notFind - 1;
                        }
                    }
#if CONFIG_OUTDOOR_CHANNELLIMIT
                    noEntryScanInterval = NO_ENTRY_RESCAN_SHORT_TIMER;
                    if (AWND_BAND_5G == band && l_awnd_config.channellimit_support
                        && 0 == strncmp(l_awnd_config.channellimit_id, "1", CHANNELLIMIT_LEN)) {
                            if ((pRootAp[band].notFind * l_awnd_config.tm_status_interval) >= (NO_ENTRY_THRESOLD_SEC * 1000)) {
                                noEntryScanInterval = NO_ENTRY_RESCAN_LONG_TIMER;
                            }
                    }
#else
                    noEntryScanInterval = NO_ENTRY_RESCAN_SHORT_TIMER;
#endif
                }

                if (noEntryScanInterval && 
                    (((pRootAp[band].notFind * l_awnd_config.tm_status_interval) % (noEntryScanInterval * 1000)) 
                       == (NO_ENTRY_RESCAN_BEGIN * 1000)))
                {
                    if (g_awnd.rootAp[band].channel && is_ch_same == FALSE) {
                        config_cur_ch[band] = awnd_config_get_channel(band);
                        if (config_cur_ch[band]  && config_cur_ch[band] != backhaul_ap_cur_ch[band]) {
                            AWN_LOG_WARNING(" %s config_cur_ch:%d, backhaul_ap_cur_ch:%d, to set channel & update g_awnd.rootAp[band].channel", real_band_suffix[band],
                                config_cur_ch[band], backhaul_ap_cur_ch[band]);
                            awnd_config_set_channel(backhaul_ap_cur_ch[band], band);
                            g_awnd.rootAp[band].channel = backhaul_ap_cur_ch[band];
                            wifi_restart = wifi_restart | (1 << band);
                        }					
                    }
#ifdef SUPPORT_MESHMODE_2G
                    memset(&cmpApEntry, 0, sizeof(AWND_AP_ENTRY));
                    if (AWND_BAND_2G != band || !memcmp(&cmpApEntry, &g_awnd.rootAp[AWND_BAND_2G], sizeof(AWND_AP_ENTRY)) || g_awnd.is2GCaculatedBssid || AWND_OK != awnd_file_exist(AWND_MESHMODE_2G_INSPECT_FILE) ||
                        ((AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5G] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_3RD] &&
                          AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_4TH] && AWND_STATUS_CONNECTED != g_awnd.connStatus[AWND_BAND_5TH])
                          && AWND_STATUS_CONNECTED != g_awnd.ethStatus))
                    {
#endif
                    ret = AWND_SCAN_SCHED;
                    *scanBandMask |= (1 << band);
                    awnd_flush_scan_table_single_band(band, FALSE);
#ifdef SUPPORT_MESHMODE_2G
                    }
#endif
                }
                
                //ret = AWND_SCAN_SCHED;
                //awnd_disconn_sta_pre(band, &disBandMask);
            }
            else
            {
                pRootAp[band].notFind = 0;            
                get_tpie = 0;
                AWN_LOG_INFO("Get %s rootAp tpie fail, bssid:%02X:%02X:%02X:%02X:%02X:%02X,link:%d, ret:%d", real_band_suffix[_get_real_band_type(band)],
                    pRootAp[band].bssid[0], pRootAp[band].bssid[1], pRootAp[band].bssid[2],
                    pRootAp[band].bssid[3], pRootAp[band].bssid[4], pRootAp[band].bssid[5], link[band], ret_tpie); 
            }
        }
    }
#endif /* !CONFIG_PLATFORM_BCM */

#ifndef CONNECT_TO_SAME_DUT
    if (get_tpie)
        awnd_check_in_same_subnet(pConnState, pRootAp, &disBandMask);
#endif    

    /* update tpie before disconnect ?????????*/
    net_changed = awnd_deliver_tpie(pConnState, pRootAp, &disBandMask);
    if (net_changed == AWND_NET_BECOME_UNSTABLE)
    {	
        /* reschedule scanning if net info is changed */
        ret = AWND_SCAN_SCHED;
    }
#if CONFIG_RE_RESTORE_STA_CONFIG
    else if (!full_scan_at_beginning && 0 == l_wait_prefer_connect && net_changed == AWND_NET_BECOME_STABLE && !g_awnd.notBind)
#else
    else if (0 == l_wait_prefer_connect && net_changed == AWND_NET_BECOME_STABLE && !g_awnd.notBind)
#endif
    {
        ret = AWND_SCAN_CLEAR;
    }
#ifdef CONFIG_PRODUCT_PLC_SGMAC
    else if (3 == net_changed)
    {
        AWN_LOG_WARNING("disconnect all band");
        disBandMask = 3;
        ret = AWND_SCAN_SCHED;
    }
#endif
    /* really disconnect STA */
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {     
        if (disBandMask & (1 << band))
        {
            AWN_LOG_INFO("disconnect band mask:%x", disBandMask);
            awnd_disconn_sta_post(band);
        }
    }
	/*if (disBandMask) sleep(1);*/
    if (_is_in_connected_state(oldConnState) && _is_in_disconnected_state(pConnState)) 
    {
        if (AWND_STATUS_CONNECTED == g_awnd.plcStatus) {
            l_awnd_scan_table.scan_windows = 3;
        }       
        ret = AWND_SCAN_SCHED_FAST;
    }

    if (!_is_in_connected_state(oldConnState) && _is_in_connected_state(pConnState)) 
    {
		AWN_LOG_NOTICE("WIFI backhaul is connected.");

        for (band = AWND_BAND_2G; band <= AWND_BAND_5G; band++)
        {
            conn_prefer_ap = conn_prefer_ap ? conn_prefer_ap : check_unable_conn_ap_table(&pRootAp[band], AWND_OP_CHECK_MAC);
        }
        if (conn_prefer_ap) {
            AWN_LOG_NOTICE("current connect ap is prefer ap, clean unable_conn_ap_table, op: %d ", AWND_OP_FLUSH);
            check_unable_conn_ap_table(NULL, AWND_OP_FLUSH);
        }
        else {
            AWN_LOG_NOTICE("current connect ap is not prefer ap, set unable_conn_ap_table flag, op: %d ", AWND_OP_SET_FLAG);
            check_unable_conn_ap_table(NULL, AWND_OP_SET_FLAG);
        }
    }
    if (!_is_in_disconnected_state(oldConnState) && _is_in_disconnected_state(pConnState)) 
    {
#if FAST_RECONNECT_ROOTAP
        need_fast_reconnect = 1;
#endif
		AWN_LOG_NOTICE("WIFI backhaul is disconnected.");
    }

#ifdef CONFIG_AWN_RE_ROAMING
    if (_is_in_roaming_state(oldConnState) && _is_in_connected_state(pConnState))
    {
        AWN_LOG_NOTICE("WIFI backhaul is roamed.");
        /* cancel the scan */
        l_awnd_scan_table.scan_band = 0;
        uloop_timeout_cancel(&wifi_scan_timer);
        /* proxy l2uf */
        for (band = AWND_BAND_2G; band <= AWND_BAND_5G; band++)
        {
            awnd_proxy_l2uf(band);
        }

        ret = AWND_OK;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        uloop_timeout_cancel(&ai_network_roaming_status_revert_timer);
        roaming_running = false;

        //if roamed was called by ai-roaming, send msg back
        if (get_alg_re_status() == DN_RE_STATUS_AFTER_ROAMING)
        {
            AWN_LOG_ERR("roamed called by ai-roaming, now send msg back");
            re_alg_process();
        }
        else
        {
            AWN_LOG_ERR("roamed, but not called by ai-roaming");
        }
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
    }
#endif
    
    if (g_awnd.netInfo.wait){
        ret = AWND_WAIT;
    }

    if (wifi_restart )
    {
        ret = AWND_WIFI_RESTART;
    } 	

#if FAST_RECONNECT_ROOTAP
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) /* save lan_mac of the latest rootap */
    {
        if (_is_vaild_mac(g_awnd.rootAp[band].lan_mac) && memcmp(g_awnd.rootAp[band].lan_mac, g_awnd.last_rootap_lanmac, AWND_MAC_LEN))
        {
            memcpy(g_awnd.last_rootap_lanmac, g_awnd.rootAp[band].lan_mac, AWND_MAC_LEN);
            break;
        }
    }

    if ((1 == need_fast_reconnect) && g_awnd.secondApNotEmpty) /* do fast reconnect */
    {
        AWN_LOG_NOTICE(" ------------- need_fast_reconnect_ROOTAP ---------------- ");
        need_fast_reconnect = 0;
        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) /* set each band */
        {
            if (_is_vaild_mac(g_awnd.secondAp[band].bssid))
            {
                awnd_config_set_stacfg_enb(1, band);

                memcpy(&g_awnd.rootAp[band], &g_awnd.secondAp[band], sizeof(AWND_AP_ENTRY));
                memset(bssid_str, 0, AWND_MAX_SSID_LEN);
                _macaddr_ntop(g_awnd.secondAp[band].bssid, bssid_str);
                awnd_config_set_stacfg_bssid(bssid_str, band);
#ifdef CONFIG_AWN_RE_ROAMING
                anwd_set_wireless_sta_bssid(bssid_str, band);

                memcpy(g_awnd.staConfig->bssid, g_awnd.secondAp[band].bssid, 6);
                g_awnd.connStatus[band] = AWND_STATUS_ROAMING;
#endif
                AWN_LOG_NOTICE(" ------- Second AP band:%d bssid:%02X:%02X:%02X:%02X:%02X:%02X ------- ", band, g_awnd.secondAp[band].bssid[0], g_awnd.secondAp[band].bssid[1], g_awnd.secondAp[band].bssid[2],
                                                                                                                          g_awnd.secondAp[band].bssid[3], g_awnd.secondAp[band].bssid[4], g_awnd.secondAp[band].bssid[5]);

            }
            else
            {
                AWN_LOG_NOTICE(" ------- Second AP band:%d data not exist", band);
            }
        }
#if CONFIG_PLATFORM_BCM
    snprintf(cmdline, CMDLINE_LENGTH, "wifi lostap ");
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) {
        if (band != AWND_BAND_2G) {
            awnd_strlcat(cmdline, ",", CMDLINE_LENGTH);
        }
        awnd_strlcat(cmdline, l_awnd_config.staIfnames[band], CMDLINE_LENGTH);
    }
    system(cmdline);
#else
#if CONFIG_PLATFORM_QCA
#if CONFIG_TRI_BAND_SUPPORT
        system("wifi update reroam ath03,ath13,ath23 &");
        AWN_LOG_NOTICE(" ------- wifi update reroam ath03,ath13,ath23 &");
#else
        system("wifi update reroam ath03,ath13 &");
        AWN_LOG_NOTICE(" ------- wifi update reroam ath03,ath13 &");
#endif /* CONFIG_TRI_BAND_SUPPORT */
#endif /* CONFIG_PLATFORM_QCA */
#if CONFIG_PLATFORM_MTK
    snprintf(cmdline, CMDLINE_LENGTH, "wifi update reroam ");
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) {
        if (band != AWND_BAND_2G) {
            awnd_strlcat(cmdline, ",", CMDLINE_LENGTH);
        }
        awnd_strlcat(cmdline, l_awnd_config.staIfnames[band], CMDLINE_LENGTH);
    }
    system(cmdline);
#endif /* CONFIG_PLATFORM_MTK */
#endif /* CONFIG_PLATFORM_BCM */

        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) /* set each band */
        {
            /* delete ori entry in scan result */
            for(idx_tpEntry = 0; idx_tpEntry < AWND_MAX_GROUP_MEMBER; idx_tpEntry++)
            {
                tmp_pCurApEntry = &(l_awnd_scan_table.apList[band].tApEntry[idx_tpEntry]);
                /* AWN_LOG_NOTICE(" ---------------- flush idx_tpEntry:%d band:%d g_awnd.last_rootap_lanmac:%02X:%02X:%02X:%02X:%02X:%02X tmp_pCurApEntry->lan_mac:%02X:%02X:%02X:%02X:%02X:%02X", idx_tpEntry, band, g_awnd.last_rootap_lanmac[0], g_awnd.last_rootap_lanmac[1], g_awnd.last_rootap_lanmac[2], g_awnd.last_rootap_lanmac[3], g_awnd.last_rootap_lanmac[4], g_awnd.last_rootap_lanmac[5],
                    tmp_pCurApEntry->lan_mac[0], tmp_pCurApEntry->lan_mac[1], tmp_pCurApEntry->lan_mac[2], tmp_pCurApEntry->lan_mac[3], tmp_pCurApEntry->lan_mac[4], tmp_pCurApEntry->lan_mac[5]); */
                if (tmp_pCurApEntry && 0 == memcmp(tmp_pCurApEntry->lan_mac, g_awnd.last_rootap_lanmac, AWND_MAC_LEN))
                {
                    memset(tmp_pCurApEntry, 0, sizeof(AWND_AP_ENTRY));
                    AWN_LOG_NOTICE(" ------- flush scan result:band:%d rootap_lanmac:%02X:%02X:%02X:%02X:%02X:%02X", band, g_awnd.last_rootap_lanmac[0], g_awnd.last_rootap_lanmac[1], g_awnd.last_rootap_lanmac[2],
                                                                                                                           g_awnd.last_rootap_lanmac[3], g_awnd.last_rootap_lanmac[4], g_awnd.last_rootap_lanmac[5]);
                }
            }
        }
        ret = AWND_RE_ROAMING;
    }
#endif

#if CONFIG_PLATFORM_BCM
    if (AWND_OK == ret)
    {
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            if ((AWND_STATUS_RECONNECTING == pConnState[band] ||
                AWND_STATUS_CONNECTING == pConnState[band]) && !link[band] && (0 == pRootAp[band].notFind))
            {
                UINT mod_remainder = 0;
                UINT scan_remainder = 0;
#if WPA_PRI_STATE_CHECK
                UINT wpa_remainder = 0;
#endif
                pRootAp[band].postCnt = pRootAp[band].postCnt + 1;

                /****************************************************************************************************************
                    fix RE scan AP OK, get tpie from scan result OK, but disconnect: to post scan or wpa_supplicant to reconnect
                        (1) start connnect or reconnect: g_awnd.disconnRecord = 3
                        (2) every 30s to flush scan result && g_awnd.disconnRecord --;
                        (3) every 60s to awnd_reconn_sta_post(check wpa_supplicant status)
                *****************************************************************************************************************/
                scan_remainder = (pRootAp[band].postCnt * l_awnd_config.tm_status_interval) % (CONNECT_POST_SCAN_SEC * 1000);
                if (g_awnd.disconnRecord[band] && pRootAp[band].postCnt && (scan_remainder >= 0) && (scan_remainder < l_awnd_config.tm_status_interval))
                {
                    if (AWND_OK == awnd_flush_scan_table_single_band(band, FALSE)) {
                        g_awnd.disconnRecord[band] --;
                    }
                }
#if WPA_PRI_STATE_CHECK
                /****************************************************************************************************************
                        (4) every 60s to awnd_wpa_supplicant_status_check (6G only) (check wpa_supplicant status)
                *****************************************************************************************************************/
                wpa_sup_status = AWND_OK;
                wpa_remainder = (pRootAp[band].postCnt * l_awnd_config.tm_status_interval) % (CONNECT_POST_WPA_SEC * 1000);
                if ( band != AWND_BAND_2G && band != AWND_BAND_5G && 
                    pRootAp[band].postCnt && (wpa_remainder >= 0) && (wpa_remainder < l_awnd_config.tm_status_interval))
                {
                    wpa_sup_status = awnd_wpa_supplicant_status_check(band);
                }
                if ( wpa_sup_status != AWND_OK ) {
                    /* if wpa_sup_status != AWND_OK, wpa_supplicant would be restarded by awnd_wpa_supplicant_status_check
                       Do not run awnd_reconn_sta_post() to prevent other wpa_supplicant status check
                    */
                    continue;
                }
#endif
                mod_remainder = (pRootAp[band].postCnt * l_awnd_config.tm_status_interval) % (CONNECT_POST_HOSTAPD_SEC * 1000);
                if ((0 == g_awnd.disconnRecord[band]) &&
                    pRootAp[band].postCnt && (mod_remainder >= 0) && (mod_remainder < l_awnd_config.tm_status_interval))
                {
                    PostBandMask |= (1 << band);
                    awnd_reconn_sta_post(band, true);
                    pRootAp[band].postCnt = 0;
                }
            }
            else
            {
                pRootAp[band].postCnt = 0;
            }
        }

        if (PostBandMask) {
            AWN_LOG_WARNING("pConnState 24G:%d 5G:%d PostBandMask:%d to post connect",
                pConnState[AWND_BAND_2G], pConnState[AWND_BAND_5G], PostBandMask);
        }
    }
    else {
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {          
            pRootAp[band].postCnt = 0;
        }
    }
#endif /* CONFIG_PLATFORM_BCM */

    return ret;
}

void awnd_conn_inspect_reschedule(struct uloop_timeout *t)
{
    int ret = AWND_ERROR;
    UINT8 scanBandMask = 0;
    AWND_BAND_TYPE    band;    
    
    if ((AWND_SCAN_SCHED ==(ret = awnd_conn_inspect_status(&scanBandMask))) || (AWND_SCAN_SCHED_FAST == ret))
    {
        uloop_timeout_set(&wifi_rootap_status_timer, l_awnd_config.tm_status_interval);   
        
        if (AWND_SCAN_SCHED_FAST == ret)
            l_awnd_scan_table.scan_fast = 1;
        
        if (scanBandMask /* && !l_awnd_scan_table.scan_band */){
            l_awnd_scan_table.scan_band = scanBandMask;
        }
        else if (!scanBandMask /* || (l_awnd_scan_table.scan_band != scanBandMask) */){
            awnd_scan_set_full_band();
        }
        
        uloop_clear_wifi_processes();
        uloop_timeout_set(&wifi_scan_timer,         l_awnd_config.tm_scan_sched);
        
        if (_is_in_connected_state(g_awnd.connStatus))
            awnd_plc_inspect(NULL);
                 
    }
    else if (AWND_SCAN_CLEAR == ret)		
    {
        AWN_LOG_INFO("clear scan %d.....", l_awnd_scan_table.scan_windows);	
        uloop_timeout_set(&wifi_rootap_status_timer, l_awnd_config.tm_status_interval); 
        if(!l_awnd_scan_table.scan_windows)
        {
            l_awnd_scan_table.scan_band = 0;
            uloop_timeout_cancel(&wifi_scan_timer);
            uloop_clear_wifi_processes();			
        }
    }
    else if (AWND_WIFI_RESTART == ret)
    {
        awnd_wifi_restart();
        awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
    }
    else if (AWND_WAIT == ret)
    {
        awnd_scan_set_full_band();
        uloop_clear_wifi_processes();
        uloop_timeout_set(&wifi_scan_timer,          g_awnd.netInfo.wait * 1000);
        uloop_timeout_set(&wifi_rootap_status_timer, g_awnd.netInfo.wait * 1000);
    }
    else if(AWND_RECONNECTING == ret)
    {
        uloop_timeout_set(&wifi_connect_timer,       l_awnd_config.tm_connect_duration/2);
        uloop_timeout_set(&wifi_rootap_status_timer, l_awnd_config.tm_status_interval);
    }
    else
    {
        uloop_timeout_set(&wifi_rootap_status_timer, l_awnd_config.tm_status_interval);
    }
    return;
}

#if CONFIG_WIFI_DFS_SILENT
void awnd_silent_period_handler(struct uloop_timeout *t)
{
    AWND_BAND_TYPE band;

    for (band = AWND_BAND_5G; band < l_awnd_config.band_num; band++)
    {
        if (SILENT_PERIOD_START == g_awnd.SilentPeriod[band]) {
            g_awnd.SilentPeriod[band] = SILENT_PERIOD_DONE;
            AWN_LOG_DEBUG("Silent Period over for band:%d ", band);
        }
    }
    return;
}
#endif /* CONFIG_WIFI_DFS_SILENT */

void awnd_scan_create_processes(struct uloop_timeout *t)
{
	int pid;
    int isOnboarding = 0;

    struct uloop_process *proc;
    UINT8 scanBandMask = l_awnd_scan_table.scan_band; 
        
    AWN_LOG_INFO("awnd_scan_create_processes scanBandMask:%d", scanBandMask);
    if (!WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        AWN_LOG_INFO("device will not scan when wifi backhaul is disable");
        uloop_timeout_set(t,  l_awnd_config.tm_scan_interval);
        return;
    }

    if (AWND_OK == _get_onboarding_status(&isOnboarding))
    {
        if (ONBOARDING_ON == isOnboarding && g_awnd.bindStatus < AWND_BIND_START)
        {
            AWN_LOG_INFO("device will not scan when onboarding");
            uloop_timeout_set(t,  l_awnd_config.tm_scan_interval);  
            return;
        }

    }

    if (g_awnd.notBind && (g_awnd.bindStatus < AWND_BIND_START) && _is_in_connected_state(g_awnd.connStatus))
    {
        if (g_awnd.rootAp[AWND_BAND_5G].rssi < l_awnd_config.low_rssi_threshold)
        {
        	AWN_LOG_INFO("device has a weak 5g link and onboarding still didn't start, do wifi scan on the current channel.");			
        	l_awnd_scan_table.scan_fast = 1;
        }
        else
        {
        	AWN_LOG_INFO("This device isn't binded, cancel scanning when it connected to rootap.");
        	return;
        }
    }

    if (g_awnd.bindFast)
    {
        g_awnd.bindFast = 0;
        l_awnd_scan_table.scan_fast = 1;
    }

#if CONFIG_RE_RESTORE_STA_CONFIG
    if (full_scan_at_beginning && (!g_awnd.notBind)) /* make sure to scan all bands in begining */
    {
        for (AWND_BAND_TYPE bi = AWND_BAND_2G; bi < AWND_BAND_MAX_NUM; bi++)
        {
            scanBandMask |= (1 << bi);
        }
        AWN_LOG_NOTICE("full_scan_at_beginning!~~ scanBandMask:%d ------------- ", scanBandMask);
        l_awnd_scan_table.scan_fast = 0;
    }
#endif

#if SCAN_OPTIMIZATION
#if CONFIG_RE_RESTORE_STA_CONFIG
    if((!full_scan_at_beginning) && (!g_awnd.notBind) && AWND_NET_FAP == g_awnd.netInfo.awnd_net_type && !(_is_vaild_mac(l_mac_prefer) && l_wait_prefer_connect > 0))
#else
    if((!g_awnd.notBind) && AWND_NET_FAP == g_awnd.netInfo.awnd_net_type && !(_is_vaild_mac(l_mac_prefer) && l_wait_prefer_connect > 0))
#endif
    {
        AWND_BAND_TYPE bi;
        for (bi = AWND_BAND_2G; bi < l_awnd_config.band_num; bi++)
        {
            int conn_time = g_awnd.connet_time[bi] * l_awnd_config.tm_status_interval;
            if (AWND_STATUS_CONNECTED == g_awnd.connStatus[bi] 
                && conn_time >= l_awnd_config.connect_time && (scanBandMask & (1 << bi)))
            {
                scanBandMask &= ~(1 << bi);
                AWN_LOG_WARNING("band: %d has been conneted for 2 mins, fix scanBandMask from %d to %d.", bi, l_awnd_scan_table.scan_band, scanBandMask);
            }
        }
    }

    l_awnd_scan_table.scan_band = 0;
    l_awnd_scan_table.scan_fail_mask = 0;
#if CONFIG_RE_RESTORE_STA_CONFIG
    full_scan_at_beginning = 0;
#endif
    if (l_awnd_scan_table.scan_fast)
    {
        AWN_LOG_INFO("fast scan begin scanBandMask:%d", scanBandMask);
        l_awnd_scan_table.scan_fail_mask = awnd_do_scan_fast(scanBandMask);
        uloop_timeout_set(&handle_scan_result_timer, l_awnd_config.fast_scan_time);
        return;
    }
    else
    {
        l_awnd_scan_table.scan_fail_mask = awnd_do_scan(scanBandMask);
    }

    AWN_LOG_DEBUG("set timer to check scan result.");

#if CONFIG_5G2_BAND3_BAND4_SUPPORT
    uloop_timeout_set(&handle_scan_result_timer, l_awnd_config.normal_scan_time_6g);
#else
	if(g_awnd.enable6g)
    	uloop_timeout_set(&handle_scan_result_timer, l_awnd_config.normal_scan_time_6g);
	else
    	uloop_timeout_set(&handle_scan_result_timer, l_awnd_config.normal_scan_time);
#endif
    return;

#else
    proc = uloop_get_wifi_process();
    if (NULL == proc)
    {
        AWN_LOG_ERR("The whole wifi process table is full.");
        return;
    }
#if CONFIG_RE_RESTORE_STA_CONFIG
    full_scan_at_beginning = 0;
#endif
    pid = fork();
    if (pid < 0)
    {	            /* Failed. */
        AWN_LOG_CRIT("%s", "fork failed, reset wifi scan timer.");
#if CONFIG_RE_RESTORE_STA_CONFIG
    full_scan_at_beginning = 1;
#endif
        uloop_timeout_set(t,  l_awnd_config.tm_scan_interval);
        return ;
    }

    l_awnd_scan_table.scan_band = 0;

    if (pid > 0) {
        proc->pid = pid;
        if (uloop_process_add(proc) < 0)
        {
            AWN_LOG_ERR("uloop_process_add pid: %d failed\n");
        }
        AWN_LOG_WARNING("uloop_process_add pid:%d, scanBandMask:%x\n", pid, scanBandMask);
        return;
    }

    if (l_awnd_scan_table.scan_fast)
    {
#if 0
        sleep(1);
        AWN_LOG_INFO("fast scan end");
        exit(0);
#else
        AWN_LOG_INFO("fast scan begin scanBandMask:%d", scanBandMask);
        awnd_do_scan_fast(scanBandMask);
#endif
    }
    else
    {
        awnd_do_scan(scanBandMask);
    }
    return;
#endif //SCAN_OPTIMIZATION
}

void awnd_switch_channel(AWND_BAND_TYPE band, UINT8 channel, BOOL force)
{
    int backhaul_ap_cur_ch = 0;

    /* check if channel has changed? */
    if ((AWND_OK != awnd_get_backhaul_ap_channel(band, &backhaul_ap_cur_ch)) ||
        (backhaul_ap_cur_ch != channel) || force)
    {
        AWN_LOG_INFO("Switch band %d to channel %d", band, channel);
        /* set wifi cfg*/
        awnd_config_set_channel(channel, band);
        if(AWND_MODE_RE == g_awnd.workMode)
        {
            g_awnd.rootAp[band].channel = channel;
        }
        AWN_LOG_INFO("wifi restart");
        awnd_wifi_restart();
        _stable_sleep(AWN_CHANNEL_SWITCH_INTERVAL);
    }
}

int awnd_scan_update_rootAp(int *wifi_restart)
{
    AWND_AP_ENTRY    *pMatchAp[AWND_BAND_MAX];
    AWND_BAND_TYPE    band;
    AWND_AP_ENTRY    *pRootAp    = g_awnd.rootAp;
    AWND_CONN_STATUS *pConnState = g_awnd.connStatus;   
    char  bssid[AWND_MAX_SSID_LEN];	
    UINT disBandMask = 0;
    int  update_tpie = 0;
    int  changed = 0;
    int  ret = AWND_OK;

    if (_is_in_disconnected_state(pConnState))
        return AWND_OK;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (NULL == (pMatchAp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pRootAp[band].lan_mac, pRootAp[band].bssid, band)))
        {
        
            if (AWND_STATUS_DISCONNECT != pConnState[band])
            {
#ifdef CONNECT_TO_SAME_DUT
                awnd_flush_scan_table_single_band(band, FALSE);
                AWN_LOG_INFO("Can't find rootap in the scan table for band %s", real_band_suffix[_get_real_band_type(band)]);
#else
                awnd_disconn_sta_pre(band, &disBandMask);
                AWN_LOG_INFO("disconnect band %s if can't find rootap in the scan table", real_band_suffix[_get_real_band_type(band)]);
#endif                
            }
        }
#if CONFIG_PLATFORM_BCM
        /***************************************************************************************************************
            for bcm wl driver:
            (1) scan result only to be updated when do scan
            (2) rootap tpie info can be updated when rootap's beacon changed
            So, this condition will cause problem:
            (1) RE connect rootap with 5G only. 24G will scan continuely
            (2) rootap change tpie's dns(50 --> 100), RE will call hotplug immedately.
            (3) then RE scan, RE's 24G scan result is new value(100), but 5G scan result is old value(50)
            (4) pRootAp[5G].netInfo.tpie.dns will change to old value(50) here, then get tpie change to new value(100)
            (5) call hotplug for 2 times unnecssary
            to fix: not to update pRootAp[band].netInfo with scan result
        ****************************************************************************************************************/
#else
        else
        {
            memcpy(&(pRootAp[band].netInfo), &(pMatchAp[band]->netInfo), sizeof(AWND_NET_INFO));
        }
#endif /* CONFIG_PLATFORM_BCM */
    }

#ifndef CONNECT_TO_SAME_DUT
    update_tpie = awnd_check_in_same_subnet(pConnState, pRootAp, &disBandMask);
#endif

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (NULL != pMatchAp[band] && AWND_STATUS_DISCONNECT != pConnState[band])
        {
            if (update_tpie)
            {
                memcpy(&(pMatchAp[band]->netInfo), &(pRootAp[band].netInfo), sizeof(AWND_NET_INFO));
            }
			
            changed = 0;
            if (pMatchAp[band]->channel != pRootAp[band].channel)
            {
                awnd_config_set_channel(pMatchAp[band]->channel, band);
                changed = 1;
            }
            if (memcmp(pMatchAp[band]->bssid,pRootAp[band].bssid, AWND_MAC_LEN))
            {
                memcpy(g_awnd.staConfig[band].bssid, pMatchAp[band]->bssid, AWND_MAC_LEN);
                memset(bssid, 0, AWND_MAX_SSID_LEN);
                _macaddr_ntop(pMatchAp[band]->bssid, bssid);				
				awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
				anwd_set_wireless_sta_bssid(bssid, band);
#endif

                changed = 1;
            }
			
            if (changed)
            {
                awnd_reconn_sta_pre(band, pMatchAp[band]);
                *wifi_restart = *wifi_restart | (1 << band);				
            }
			
        }
    }

#if CONFIG_PLATFORM_BCM
    /* not to deliver_tpie here for bcm */
#else
    if (AWND_NET_BECOME_UNSTABLE == awnd_deliver_tpie(pConnState, pRootAp, &disBandMask))
    {		
        /* reschedule scanning if net info is changed */
        ret = AWND_SCAN_SCHED;
    }    
#endif /* CONFIG_PLATFORM_BCM */

    /* really disconnect STA */
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {     
        if (disBandMask & (1 << band))
        {
            AWN_LOG_INFO("[%s]disconnect band mask:%x", __FUNCTION__, disBandMask);
            awnd_disconn_sta_post(band);
            /*sleep(2);*/
        }
    }
    
    return ret;
}

#if FAST_RECONNECT_ROOTAP
/*!
*\fn           awnd_get_second_rootAp()
*\brief        try to get secondary rootAP from bestAP[] and scan result
*\param[in]    pBestAp              an array of the best rootAP for each band
*\param[in]    selectband           the best band in pBestAP
*\param[in]    onlyFindFap          only to find NET_FAP when reStage less than 3
*\return       -1/secondApSelectBand
*/
int awnd_get_second_rootAp(AWND_AP_ENTRY *pBestAp[AWND_BAND_MAX_NUM], AWND_BAND_TYPE selectband, UINT32 onlyFindFap)
{
    AWND_AP_ENTRY  tmpEntry2[AWND_BAND_MAX_NUM]={0};
    AWND_AP_ENTRY  *pSecondAp_tmp[AWND_BAND_MAX_NUM] = {NULL};
    AWND_BAND_TYPE band;

    int secondApSelectBand = -1;
    g_awnd.secondApNotEmpty = 0;

    /* find if exist second AP from BeatAp[]'s band */
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (!pBestAp[selectband])
        {
            AWN_LOG_NOTICE("pBestAp is NULL!!", selectband);
            break;
        }

        if (selectband == band)
            continue;

        if (!pBestAp[band])
        {
            AWN_LOG_DEBUG("pBestAp[%d] is NULL!!", band);
            continue;
        }

        /* AWN_LOG_NOTICE("pBestAp[selectband]->lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, pBestAp[band]->lan_mac: %02X:%02X:%02X:%02X:%02X:%02X",
                    pBestAp[selectband]->lan_mac[0], pBestAp[selectband]->lan_mac[1], pBestAp[selectband]->lan_mac[2], pBestAp[selectband]->lan_mac[3], pBestAp[selectband]->lan_mac[4], pBestAp[selectband]->lan_mac[5],
                    pBestAp[band]->lan_mac[0], pBestAp[band]->lan_mac[1], pBestAp[band]->lan_mac[2], pBestAp[band]->lan_mac[3], pBestAp[band]->lan_mac[4], pBestAp[band]->lan_mac[5]); */
        if (memcmp(pBestAp[selectband]->lan_mac, pBestAp[band]->lan_mac, AWND_MAC_LEN))
        {
            secondApSelectBand = band;
            pSecondAp_tmp[secondApSelectBand] = pBestAp[band];
            break;/* if you want to find more than one AP, then change this */
        }
    }
    if (-1 == secondApSelectBand) /* not found second mac in BestAP[] */
    {
        AWN_LOG_DEBUG("not found second mac in BestAP[], so look for g_awnd.secondAp in awnd_sort_scan_entry");
        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        {
            if (!pBestAp[band]) /* if pBestAp[band] is null, then not to find pSecondAp_tmp[band] */
                continue;
            /* just like pSecondAp_tmp[band] = awnd_sort_scan_entry(&l_awnd_scan_table.apList[band], band, onlyFindFap, 0, NULL); */
            pSecondAp_tmp[band] = awnd_sort_scan_entry_get_second_rootAP(&l_awnd_scan_table.apList[band], band, onlyFindFap, 1, pBestAp[band]->lan_mac, pBestAp[band]->netInfo.awnd_level);
            if (!pSecondAp_tmp[band])
            {
                AWN_LOG_NOTICE(" ------------ pSecondAp_tmp[%d] is NULL", band);
            }
            else
            {
                /* If you print pSecondAp_tmp[band]->lan_mac while pSecondAp_tmp[band] is empty, you won't get an error print, but there will be a seriously problem!!! */
                AWN_LOG_DEBUG("found mac in awnd_sort_scan_entry:%02X:%02X:%02X:%02X:%02X:%02X, bssid: %02X:%02X:%02X:%02X:%02X:%02X pBestAp[band]->bssid:%02X:%02X:%02X:%02X:%02X:%02X",
                    pSecondAp_tmp[band]->lan_mac[0], pSecondAp_tmp[band]->lan_mac[1], pSecondAp_tmp[band]->lan_mac[2], pSecondAp_tmp[band]->lan_mac[3], pSecondAp_tmp[band]->lan_mac[4], pSecondAp_tmp[band]->lan_mac[5],
                    pSecondAp_tmp[band]->bssid[0], pSecondAp_tmp[band]->bssid[1], pSecondAp_tmp[band]->bssid[2], pSecondAp_tmp[band]->bssid[3], pSecondAp_tmp[band]->bssid[4], pSecondAp_tmp[band]->bssid[5],
                    pBestAp[band]->bssid[0], pBestAp[band]->bssid[1], pBestAp[band]->bssid[2], pBestAp[band]->bssid[3], pBestAp[band]->bssid[4], pBestAp[band]->bssid[5]);
            }
        }
#if CONFIG_TRI_BACKHAUL_SUPPORT
        if ((NULL == pSecondAp_tmp[AWND_BAND_2G] && (NULL != pSecondAp_tmp[AWND_BAND_5G] || NULL != pSecondAp_tmp[AWND_BAND_5G2]))
            || (NULL != pSecondAp_tmp[AWND_BAND_5G] && pSecondAp_tmp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold)
            || (NULL != pSecondAp_tmp[AWND_BAND_5G2] && pSecondAp_tmp[AWND_BAND_5G2]->rssi >= l_awnd_config.low_rssi_threshold))
        {
            if (awnd_compare_scan_entry(pSecondAp_tmp[AWND_BAND_5G], pSecondAp_tmp[AWND_BAND_5G2]))
            {
                secondApSelectBand = AWND_BAND_5G;
            }
            else
            {
                secondApSelectBand = AWND_BAND_5G2;
            }

            if (NULL != pSecondAp_tmp[AWND_BAND_2G] && pSecondAp_tmp[secondApSelectBand]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
                pSecondAp_tmp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
                awnd_get_better_band_entry(pSecondAp_tmp[AWND_BAND_2G], pSecondAp_tmp[secondApSelectBand]))
            {
                AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g_%d:%d), SecondAp select 2g.", pSecondAp_tmp[AWND_BAND_2G]->pathRate, secondApSelectBand, pSecondAp_tmp[secondApSelectBand]->pathRate);
                secondApSelectBand = AWND_BAND_2G;
            }
        }
#else
        if (NULL != pSecondAp_tmp[AWND_BAND_5G] && (pSecondAp_tmp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold || NULL == pSecondAp_tmp[AWND_BAND_2G]))
        {
            secondApSelectBand = AWND_BAND_5G;

            if (NULL != pSecondAp_tmp[AWND_BAND_2G] && pSecondAp_tmp[AWND_BAND_5G]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
                pSecondAp_tmp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
                awnd_get_better_band_entry(pSecondAp_tmp[AWND_BAND_2G], pSecondAp_tmp[AWND_BAND_5G]))
            {
                AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g:%d), SecondApAp select 2g.", pSecondAp_tmp[AWND_BAND_2G]->pathRate, pSecondAp_tmp[AWND_BAND_5G]->pathRate);
                secondApSelectBand = AWND_BAND_2G;
            }
        }
#endif
        else if (NULL != pSecondAp_tmp[AWND_BAND_2G])
        {
            secondApSelectBand = AWND_BAND_2G;
        }
    }
    if (-1 != secondApSelectBand)
    {
        /* find STAs of other bands by the select band of second AP*/
        AWN_LOG_NOTICE("Select: pSecondAp_tmp[%d]->lan_mac:%02X:%02X:%02X:%02X:%02X:%02X", secondApSelectBand,
                    pSecondAp_tmp[secondApSelectBand]->lan_mac[0], pSecondAp_tmp[secondApSelectBand]->lan_mac[1], pSecondAp_tmp[secondApSelectBand]->lan_mac[2], pSecondAp_tmp[secondApSelectBand]->lan_mac[3], pSecondAp_tmp[secondApSelectBand]->lan_mac[4], pSecondAp_tmp[secondApSelectBand]->lan_mac[5]);

        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        {
            awnd_transform_bssid_from_select_band(secondApSelectBand, pSecondAp_tmp[secondApSelectBand]->lan_mac, tmpEntry2, pSecondAp_tmp[secondApSelectBand]->isPreconf, pSecondAp_tmp[secondApSelectBand]->bssid);
            memcpy(tmpEntry2[band].lan_mac, pSecondAp_tmp[secondApSelectBand]->lan_mac, AWND_MAC_LEN);
            if (band == secondApSelectBand)
                continue;

#ifdef CONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE
            pSecondAp_tmp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pSecondAp_tmp[secondApSelectBand]->lan_mac,tmpEntry2[band].bssid, band);
#else
            pSecondAp_tmp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pSecondAp_tmp[secondApSelectBand]->lan_mac,tmpEntry2[band].bssid, band);
#endif
            if (pSecondAp_tmp[band])
                AWN_LOG_NOTICE("pSecondAp_tmp[%d] add bssid:%02X:%02X:%02X:%02X:%02X:%02X", band, pSecondAp_tmp[band]->bssid[0], pSecondAp_tmp[band]->bssid[1], pSecondAp_tmp[band]->bssid[2], pSecondAp_tmp[band]->bssid[3], pSecondAp_tmp[band]->bssid[4], pSecondAp_tmp[band]->bssid[5]);

            if (NULL == pSecondAp_tmp[band])
            {
                AWN_LOG_NOTICE("fail to get %s ROOTAP from %s ROOTAP.", real_band_suffix[band], real_band_suffix[secondApSelectBand]);
            }
        }
    }
    else
    {
        AWN_LOG_INFO("not found second mac in SecondAP[] and awnd_sort_scan_entry");
    }
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (pSecondAp_tmp[band])
        {
            g_awnd.secondApNotEmpty = 1;
            break;
        }
    }
    if (g_awnd.secondApNotEmpty)
    {
        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        {
            if (pSecondAp_tmp[band])
            {
                memcpy(&g_awnd.secondAp[band], pSecondAp_tmp[band], sizeof(*(pSecondAp_tmp[band]))); /* to avoid g_awnd.secondAp has value of more than one AP, so only copy each band of pSecondAp_tmp to g_awnd.secondAp */
                AWN_LOG_NOTICE(" -------++ Second AP band:%d bssid:%02X:%02X:%02X:%02X:%02X:%02X ------- ", band, g_awnd.secondAp[band].bssid[0], g_awnd.secondAp[band].bssid[1], g_awnd.secondAp[band].bssid[2],
                                                                                                                          g_awnd.secondAp[band].bssid[3], g_awnd.secondAp[band].bssid[4], g_awnd.secondAp[band].bssid[5]);
            }
        }
    }
    return secondApSelectBand;
}
#endif

int awnd_scan_handle_rootap(AWND_MODE_TYPE curMode)
{
    AWND_AP_ENTRY   *pBestAp[AWND_BAND_MAX] = {NULL}; 
    AWND_NET_INFO   *pBestNet   = NULL;
    AWND_BAND_TYPE   band;
    AWND_BAND_TYPE   selectband = AWND_BAND_MAX;
	AWND_BAND_TYPE   prefer_selectband = AWND_BAND_MAX;
    AWND_BAND_TYPE   compareband = AWND_BAND_MAX;
    AWND_VAP_TYPE    vap_type;
	int preferband_change = 1;
    int   pathDepth = 0;
    int   wifi_restart = 0;
    int   ret = AWND_OK;
    char  bssid[AWND_MAX_SSID_LEN];
    int plc_wifi_the_same_dut = 0; 
#ifdef CONNECT_TO_SAME_DUT
    UINT8 lanMac[AWND_MAC_LEN]={0};
    AWND_AP_ENTRY  tmpEntry[AWND_BAND_MAX]={0};
#endif
    AWND_NET_INFO neigh_tbl[32];
    int betterApExist = 0;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    int roamTargetExist = 0;
#endif
    int betterApInSameSubnet = 0;  
    int betterApChanged = 0;
    UINT32 betterApHoldMask = 0;	
    int cnt;
    int idx;
    UINT32 onlyFindFap = 0;
    static UINT8 preEthNeighIf[IFNAMSIZ] = {0};
    int betterServerDetect = 0;
    int valid_wifi_restart = 0;
    int BestApType = 0; /* 0:normal  1:preconf 2:preconfig(DCMP) */

    char * preconf_ssid = NULL;
    UINT8 * preconf_label = NULL;

    int wait_prefer = 1;
    UINT8 macZero[AWND_MAC_LEN] = {0};
    int cac_state = 0;

#ifdef CONFIG_AWN_RE_ROAMING
    int re_roaming = 0;
    AWND_CONN_STATUS conn_status_before_trasfer[AWND_BAND_MAX];
#endif
    int old_l_wait_prefer_connect = l_wait_prefer_connect;

    /*vap_type = (AWND_MODE_RE == g_awnd.workMode)? AWND_VAP_STA : AWND_VAP_AP;*/ 
    vap_type = AWND_VAP_AP;	   
    if(g_awnd.notBind && AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND && ! _is_null_group_info( &(l_group_info.preconfGroupInfo) ) )
    {
        /*get scan result which is filtered by preconf and default label and ssid*/
        preconf_ssid = l_group_info.preconfGroupInfo.ssid;
        preconf_label = l_group_info.preconfGroupInfo.label;
    }

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
#if SCAN_OPTIMIZATION
        //memset(&l_awnd_scan_table.apList[band], 0, sizeof(AWND_SCAN_RESULT));
#else
        memset(&l_awnd_scan_table.apList[band], 0, sizeof(AWND_SCAN_RESULT));
#endif //SCAN_OPTIMIZATION
#ifdef CONFIG_DCMP_GLOBAL_support
		if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], 
                                    l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                    preconf_ssid, preconf_label, 
                                    l_group_info.preconfigGroupInfo.ssid, l_group_info.preconfigGroupInfo.label,
									band, vap_type, l_awnd_scan_table.scan_fast))
        {
            //sleep(1);
            _stable_sleep(1);
		    if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], 
                                    l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                    preconf_ssid, preconf_label,
                                    l_group_info.preconfigGroupInfo.ssid, l_group_info.preconfigGroupInfo.label,
									band, vap_type, l_awnd_scan_table.scan_fast))
            {
                 AWN_LOG_INFO("band %s get scan result fail twice, keep scan table empty.", real_band_suffix[_get_real_band_type(band)]);
            }
        }
    }
#else
        if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                                preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
        {
            //sleep(1);
            _stable_sleep(1);
            if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                                preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
            {
                AWN_LOG_INFO("band %s get scan result fail twice, keep scan table empty.", real_band_suffix[_get_real_band_type(band)]);
            }
        }
    }
#endif
#if SCAN_OPTIMIZATION
    g_awnd.scan_band_success_mask = 0;
#endif
    if (AWND_MODE_RE == curMode)
    {
        if(AWND_OK != awnd_scan_update_rootAp(&wifi_restart))
        {
            ret = AWND_SCAN_SCHED;
            goto out;
        }
    }

    if (AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND)
        onlyFindFap = 1;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        pBestAp[band] = awnd_sort_scan_entry(&l_awnd_scan_table.apList[band], band, onlyFindFap);
        if(NULL != pBestAp[band] && (is_prefer_mac(pBestAp[band]) == 1)){
            wait_prefer = 0;
			if(prefer_selectband==AWND_BAND_2G){
				preferband_change=!(pBestAp[band]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
									pBestAp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
									awnd_get_better_band_entry(pBestAp[prefer_selectband],pBestAp[band]));
			}else if(prefer_selectband <AWND_BAND_MAX){
				preferband_change=awnd_compare_scan_entry(pBestAp[band],pBestAp[prefer_selectband]);
			}else if(prefer_selectband>=AWND_BAND_MAX){
				preferband_change=1;
			}
			prefer_selectband=(preferband_change?band:prefer_selectband);
        }
        
        //需要等待优先节点，返回重新扫描
        if(pBestAp[band] == NULL && l_wait_prefer_connect > 0 && wait_prefer)
        {

            if (old_l_wait_prefer_connect == l_wait_prefer_connect)
            {
                l_wait_prefer_connect++;
            }
            if (l_wait_prefer_connect < 15){
                AWN_LOG_WARNING("wait for prefer entry!");
                ret = AWND_SCAN_SCHED;
            }
        }
    }

    if (wait_prefer == 1 && ret == AWND_SCAN_SCHED)
    {
        AWN_LOG_INFO("need to wait for prefer device");
        return ret;
    }

    //完成扫描，将等待标志置0
    l_wait_prefer_connect = 0;

#if SCAN_OPTIMIZATION
    if (g_awnd.scan_one_more_time == 1)
    {
        AWN_LOG_INFO("can not find fap in scan result, scan one more time.");
        ret = AWND_SCAN_SCHED;
        g_awnd.scan_one_more_time = 0;
        goto out;
    }
#endif
	{		
#ifdef CONNECT_TO_SAME_DUT
		int need_select =  0;
		int tmp_index = 0;
		if(l_awnd_config.band_num == AWND_BAND_NUM_3 || l_awnd_config.band_num == AWND_BAND_NUM_4 || l_awnd_config.band_num == AWND_BAND_NUM_5)
		{
			if(NULL != pBestAp[AWND_BAND_2G])
			{
				for(tmp_index = AWND_BAND_5G; tmp_index < l_awnd_config.band_num; tmp_index ++)
				{
					if((NULL != pBestAp[tmp_index] && pBestAp[tmp_index]->rssi >= l_awnd_config.low_rssi_threshold))
					{
						need_select=1;
						break;
					}
				}
			}
			else
			{
				for(tmp_index = AWND_BAND_5G; tmp_index < l_awnd_config.band_num; tmp_index ++)
				{
					if((NULL != pBestAp[tmp_index] ))
					{
						need_select=1;
						break;
					}
				}
			}
			if(1 == need_select)
			{
				/* to be done */
				/*if(l_awnd_config == 5)
				else */
				if(l_awnd_config.band_num == AWND_BAND_NUM_4)
				{
					if (NULL != pBestAp[AWND_BAND_5G]) {		
						if (NULL != pBestAp[AWND_BAND_3RD]) {
							compareband = AWND_BAND_3RD;
						}
						else if (NULL != pBestAp[AWND_BAND_4TH]) {
							compareband = AWND_BAND_4TH;
						}

						if (l_awnd_config.band_num == compareband) {
							selectband = AWND_BAND_5G;
						}
						else {
							if (awnd_compare_scan_entry(pBestAp[AWND_BAND_5G], pBestAp[compareband])) {
								selectband = AWND_BAND_5G;
							}
							else {
								selectband = compareband;
							}
						}
					}
					else {
						if (NULL != pBestAp[AWND_BAND_3RD] && NULL != pBestAp[AWND_BAND_4TH]) {
							if (awnd_compare_scan_entry(pBestAp[AWND_BAND_3RD], pBestAp[AWND_BAND_4TH])) {
								selectband = AWND_BAND_3RD;
							}
							else {
								selectband = AWND_BAND_4TH;
							}
						}
						else if (NULL != pBestAp[AWND_BAND_3RD]) {
							selectband = AWND_BAND_3RD;
						}
						else if (NULL != pBestAp[AWND_BAND_4TH]) {
							selectband = AWND_BAND_4TH;
						}
					}
				}
				else if(l_awnd_config.band_num == AWND_BAND_NUM_3)
				{
					if (awnd_compare_scan_entry(pBestAp[AWND_BAND_5G], pBestAp[AWND_BAND_3RD]))
					{
						selectband = AWND_BAND_5G;
					}
					else
					{
						selectband = AWND_BAND_3RD;
					}
				}
			
				if (NULL != pBestAp[AWND_BAND_2G] && pBestAp[selectband]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
					pBestAp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
					awnd_get_better_band_entry(pBestAp[AWND_BAND_2G], pBestAp[selectband]))
				{
					AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g_%d:%d), bestAp select 2g.", pBestAp[AWND_BAND_2G]->pathRate, selectband, pBestAp[selectband]->pathRate);
					selectband = AWND_BAND_2G;
				}
			}             
		    else if (NULL != pBestAp[AWND_BAND_2G])
		    {
		        selectband = AWND_BAND_2G;
		    }
		}
		else
		{
				/* at this version , both band connect to the same rootap, maybe change it in the future. */
				if (NULL != pBestAp[AWND_BAND_5G] && (pBestAp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold || NULL == pBestAp[AWND_BAND_2G]))
				{
					selectband = AWND_BAND_5G;
		
					if (NULL != pBestAp[AWND_BAND_2G] && pBestAp[AWND_BAND_5G]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
						pBestAp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
						awnd_get_better_band_entry(pBestAp[AWND_BAND_2G], pBestAp[AWND_BAND_5G]))
					{
						AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g:%d), bestAp select 2g.", pBestAp[AWND_BAND_2G]->pathRate, pBestAp[AWND_BAND_5G]->pathRate);
						selectband = AWND_BAND_2G;
					}
				}  
				else if (NULL != pBestAp[AWND_BAND_2G])
				{
					selectband = AWND_BAND_2G;
				}
		}

		if(prefer_selectband < l_awnd_config.band_num){
			selectband=prefer_selectband;
			AWN_LOG_INFO("change selectband to prefer_selectband,selectband=%d\n",selectband);
		}
	    /* find STAs of other bands by the select band*/
	    if (selectband < l_awnd_config.band_num)
	    {
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
	        g_awnd.findWifiRootApFailCnt = 0;
#endif
	        awnd_transform_bssid_from_select_band(selectband, pBestAp[selectband]->lan_mac, tmpEntry, pBestAp[selectband]->isPreconf, pBestAp[selectband]->bssid);

	        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
	        {
	            memcpy(tmpEntry[band].lan_mac, pBestAp[selectband]->lan_mac, AWND_MAC_LEN);
	            if (band == selectband)
	                continue;
				pBestAp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pBestAp[selectband]->lan_mac,tmpEntry[band].bssid, band);
	            if (NULL == pBestAp[band])
	            {
	                AWN_LOG_INFO("fail to get %s ROOTAP from %s ROOTAP.", real_band_suffix[_get_real_band_type(band)], real_band_suffix[_get_real_band_type(selectband)]);
	            }                
	        }
	        /* is best ap is preconf AP */
	        if(1 == pBestAp[selectband]->isPreconf)
	        {
	            BestApType = 1;
	        }
            /* is best ap is preconfig AP */
            else if(1 == pBestAp[selectband]->isPreconfig)
            {
                BestApType = 2;
            }
	        else
	        {
	            BestApType = 0;
	        }
	    }
#endif    
	}
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (NULL != pBestAp[band] && (NULL == pBestNet || HIGH_PRIO_SUBNET(&(pBestAp[band]->netInfo), pBestNet)))
        {
            pBestNet =  &(pBestAp[band]->netInfo);
        }
    }


    if (pBestNet)
    {
        if (! IN_SAME_SUBNET(pBestNet, &g_awnd.netInfo) && HIGH_PRIO_SUBNET(pBestNet, &g_awnd.netInfo))
        {
#if 0			
            if (pBestNet->awnd_level >= AWND_MAX_LEVEL)
            {
               AWN_LOG_INFO("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
               AWN_LOG_INFO("          awnd_level reaches the limit             ");
               AWN_LOG_INFO("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");            
            }
            else
#endif				
            {
                  betterApExist = 1;
                  betterApInSameSubnet = 0;
            }
        }
        else if (IN_SAME_SUBNET(pBestNet, &g_awnd.netInfo) && (pBestNet->awnd_level <= g_awnd.netInfo.awnd_level))
        {
                  betterApExist = 1;
                  betterApInSameSubnet = 1;            
        }
        //优先节点，但是level大，可能形成环路
        else if(IN_SAME_SUBNET(pBestNet, &g_awnd.netInfo) && (pBestNet->awnd_level > g_awnd.netInfo.awnd_level) &&
        (is_prefer_mac(pBestAp[AWND_BAND_2G]) == 1 || is_prefer_mac(pBestAp[AWND_BAND_5G]) == 1)
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        ||(is_ai_roaming_mac(pBestAp[AWND_BAND_2G]) == 1 || is_ai_roaming_mac(pBestAp[AWND_BAND_5G]) == 1)
#endif
        )
        {   
            AWN_LOG_NOTICE("level bigger !!!!!!!!!!!!!!"); 
           
            for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
            { 
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
                if (NULL != pBestAp[band] && (is_prefer_mac(pBestAp[band]) == 1 || is_ai_roaming_mac(pBestAp[band]) == 1))
#else
                if (NULL != pBestAp[band] && is_prefer_mac(pBestAp[band]) == 1)
#endif
                {
                    AWN_LOG_NOTICE("best ap is prefer ap, but level bigger, record its mac and level, op: %d ", AWND_OP_SET_PREFER);
                    check_unable_conn_ap_table(pBestAp[band], AWND_OP_SET_PREFER);
                    break;
                }
            }
            awnd_disconn_all_sta();
            //初始化netInfo并更新tpie,保证IN_SAME_SUBNET比较的netinfo是当前设备情况
            awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_WIFI);
#else
            awnd_update_tpie(&g_awnd.netInfo);
#endif

            /*避免快速扫描，在断开完成前就获取到扫描结果*/
            l_awnd_scan_table.scan_fast = 0;
            return AWND_SCAN_SCHED;
        }
    }

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    /* If roam target set and the root ap is the target, regard better ap as nonexistense */
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (IN_CONNECTED_STATE(g_awnd.connStatus) && (memcmp(g_awnd.rootAp[band].lan_mac, g_awnd.roamTarget[band].entry.lan_mac, 6) == 0) )
        {
            AWN_LOG_NOTICE("Current sta connection is a roaming target, no better Ap exists.");
            betterApExist = 0;
            roamTargetExist = 1;
        }
    }
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

    if (betterApExist)
    {                
        if (pBestNet->wait > 0)
        {
            AWN_LOG_INFO("pBestNet->wait:%d", pBestNet->wait);
            goto out;
        }

#if FAST_RECONNECT_ROOTAP
        if (memcmp(pBestAp[selectband]->lan_mac, g_awnd.fapMac, AWND_MAC_LEN))
            awnd_get_second_rootAp(pBestAp, selectband, onlyFindFap);
#endif

        /* if rootap changed */
        betterApChanged = 0;
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
#ifdef SUPPORT_MESHMODE_2G
            if(!(((g_awnd.meshmode == AWND_MESHMODE_2G_DYNAMIC && g_awnd.meshstate == AWND_MESHSTATE_2G_DISCONNECT) || 
                (g_awnd.meshmode == AWND_MESHMODE_2G_DISCONNECT)) && band == AWND_BAND_2G) &&
                (NULL != pBestAp[band] && (AWND_STATUS_DISCONNECT == g_awnd.connStatus[band] 
                || memcmp(pBestAp[band]->bssid, g_awnd.rootAp[band].bssid, AWND_MAC_LEN))))
#else
            if (NULL != pBestAp[band] && (AWND_STATUS_DISCONNECT == g_awnd.connStatus[band] 
                || memcmp(pBestAp[band]->bssid, g_awnd.rootAp[band].bssid, AWND_MAC_LEN)))
#endif
            {
                betterApChanged = 1;
            } 

#if CONFIG_PLATFORM_BCM
            if (NULL == pBestAp[band] && (!(wifi_restart & (1 << band)))
                && (AWND_STATUS_CONNECTING == g_awnd.connStatus[band]
                || AWND_STATUS_RECONNECTING == g_awnd.connStatus[band])
                && _is_vaild_mac(tmpEntry[band].bssid)
                && memcmp(tmpEntry[band].bssid, g_awnd.staConfig[band].bssid, AWND_MAC_LEN))
            {   /* calculate new bssid, to update when connecting */
                AWN_LOG_WARNING("band %s calculate new bssid, to update when connecting", real_band_suffix[_get_real_band_type(band)]);
                memcpy(g_awnd.staConfig[band].bssid, tmpEntry[band].bssid, AWND_MAC_LEN);
                memset(bssid, 0, AWND_MAX_SSID_LEN);
                _macaddr_ntop(tmpEntry[band].bssid, bssid);
                awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
                anwd_set_wireless_sta_bssid(bssid, band);
#endif
                wifi_restart = wifi_restart | (1 << band);
            }
#endif /* CONFIG_PLATFORM_BCM */

            if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band] && NULL != pBestAp[band]  
                && !memcmp(pBestAp[band]->bssid, g_awnd.rootAp[band].bssid, AWND_MAC_LEN))
            {
                betterApHoldMask |= (1 << band);
            }
#ifdef CONFIG_AWN_RE_ROAMING
            conn_status_before_trasfer[band] = g_awnd.connStatus[band];
#endif
        }
        if (! betterApChanged)
        {
            AWN_LOG_INFO("The better ap is the same with the previous rootap");
            if( AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_HAP == g_awnd.netInfo.awnd_net_type)
            {
                /* compare my server detect status with rootap */
                if (pBestNet->server_detected && g_awnd.server_detected)
                {
                    if (pBestNet->server_touch_time < g_awnd.server_touch_time)
                        betterServerDetect = 1;
                }
                else if (g_awnd.server_detected)
                    betterServerDetect = 1;

                if (betterServerDetect)
                {
                    AWN_LOG_NOTICE("my server detected is better than conenncted rootap");
                    ret = AWND_MODE_CHANGE;
                }
            }
            goto out;
            
        }
              
#if 0
        /*if one of the best aps isn't in the best net, scan again */
        if (!l_awnd_scan_table.scan_in_retry)
        {
            for (band = AWND_BAND_2G; band <= AWND_BAND_5G; band++)
            {
                if (NULL == pBestAp[band] || (NULL != pBestAp[band] && ! IN_SAME_SUBNET_EXACT(&(pBestAp[band]->netInfo), pBestNet)))
                {
                    AWN_LOG_INFO("Can't not find best ap for both band or one of the best aps isn't in the best net, scan again.");
                    l_awnd_scan_table.scan_in_retry = 1;
                    ret = AWND_SCAN_SCHED;
                    goto out;
                }
            }		

            if (NULL == pBestAp[AWND_BAND_5G] || pBestAp[AWND_BAND_5G]->rssi < l_awnd_config.best_effort_rssi_threshold)
            {
                AWN_LOG_INFO("The better ap has a weak 5g rssi %d, scan again.", pBestAp[AWND_BAND_5G] ? pBestAp[AWND_BAND_5G]->rssi : 0);
                l_awnd_scan_table.scan_in_retry = 1;
                ret = AWND_SCAN_SCHED;
                goto out;				
            }

        }
        l_awnd_scan_table.scan_in_retry = 0;
#endif

        AWN_LOG_INFO("Find a better ap subnet, and betterApHoldMask is %x. selectband:%d", betterApHoldMask, selectband);


#ifdef CONNECT_TO_SAME_DUT 
        /* compare plc and wifi here */
        awnd_transform_lanmac_from_wifi(lanMac, pBestAp); 
        if (AWND_MODE_RE == curMode && AWND_STATUS_DISCONNECT != g_awnd.plcStatus)
        {
            if (!_mac_raw_equal(lanMac, g_awnd.plcPeerNeigh.lan_mac))
            {
                AWN_LOG_INFO("plc and wifi are not on the same dut, computed mac:%02x-%02x-%02x-%02x-%02x-%02x, neigh_mac:%02x-%02x-%02x-%02x-%02x-%02x",
                    lanMac[0],lanMac[1],lanMac[2],lanMac[3],lanMac[4],lanMac[5],g_awnd.plcPeerNeigh.lan_mac[0], g_awnd.plcPeerNeigh.lan_mac[1],
                    g_awnd.plcPeerNeigh.lan_mac[2],g_awnd.plcPeerNeigh.lan_mac[3],g_awnd.plcPeerNeigh.lan_mac[4],g_awnd.plcPeerNeigh.lan_mac[5]);

#if  WIFI_PLC_CONNECT_TO_SAME_DUT

                if (!g_awnd.plcPeerNeigh.txRate && !l_awnd_scan_table.scan_in_retry) {
                    l_awnd_scan_table.scan_in_retry = 1;
                    ret = AWND_SCAN_SCHED;
                    goto out;
                }
                l_awnd_scan_table.scan_in_retry = 0;

                if (awnd_plc_better_than_wifi(&g_awnd.plcPeerNeigh, pBestAp, pBestNet))
                {
                    AWN_LOG_INFO("PLC is better than wifi");            
                    goto out;                    
                }
                else
                {
                    AWN_LOG_INFO("WIFI is better than PLC");  
                    awnd_plc_disconnect();
                }

#endif

            }
#if 0
            else {
                AWN_LOG_INFO("plcmac and wifi are on the same dut");
                if (g_awnd.plcWinWifi)
                {
                    AWN_LOG_INFO("PLC is better than wifi");            
                    goto out;                    
                }
            }
#endif
#if 0
            else if ((pBestAp[AWND_BAND_5G] && pBestAp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold) 
                  || (pBestAp[AWND_BAND_2G] && pBestAp[AWND_BAND_2G]->rssi >= 25))
            {
                AWN_LOG_INFO("plcmac and wifi are on the same dut");
            }
            else
            {
                AWN_LOG_INFO("plcmac and wifi are on the same dut, but wifi is too weak");            
                goto out;                
            }
#endif

        }
        l_awnd_scan_table.scan_windows = 0;
#endif         

        if (AWND_MODE_HAP == curMode)
        {
            awnd_plc_disconnect();
            awnd_disconn_all_sta();
        }
        else 
        {
    		for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    		{
    			if (!(betterApHoldMask & (1 << band)))
    				awnd_disconn_sta(band);
    		}
        }		

        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {
            if (NULL != pBestAp[band] && IN_SAME_SUBNET_EXACT(&(pBestAp[band]->netInfo), pBestNet))
            {            
                if (g_awnd.notBind && (memcmp(g_awnd.staConfig[band].bssid, pBestAp[band]->bssid, AWND_MAC_LEN)
#ifndef CONFIG_PLATFORM_MTK
                    || (g_awnd.staConfig[band].channel != pBestAp[band]->channel)
#endif  /*CONFIG_PLATFORM_MTK*/
                    || (awnd_config_get_stacfg_enb(band) != 1)))
                {

                    valid_wifi_restart = valid_wifi_restart | (1 << band);
                }
                memcpy(g_awnd.staConfig[band].bssid, pBestAp[band]->bssid, AWND_MAC_LEN);

#ifdef CONFIG_AWN_RE_ROAMING
                if (conn_status_before_trasfer[band] == AWND_STATUS_CONNECTED && (g_awnd.staConfig[band].channel == pBestAp[band]->channel))
                {
                    re_roaming = 1;
                    roaming_mac = pBestAp[band]->lan_mac;
                }
#endif
                memset(bssid, 0, AWND_MAX_SSID_LEN);
                _macaddr_ntop(pBestAp[band]->bssid, bssid);
                awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
                anwd_set_wireless_sta_bssid(bssid, band);
#endif
                awnd_config_set_stacfg_enb(WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? 1 : 0, band);
                awnd_config_set_channel(pBestAp[band]->channel, band);    
                /* BestApType  0:normal  1:preconf  2:preconfig(DCMP) */
                if(1 == BestApType && AWND_STA_TYPE_PRE != l_group_info.staType ) 
                {
                    l_group_info.staType = AWND_STA_TYPE_PRE;
                    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                }
                else if(0 == BestApType && AWND_STA_TYPE_NORMAL != l_group_info.staType ) 
                {
                    l_group_info.staType = AWND_STA_TYPE_NORMAL;
                    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                }
                if(2 == BestApType && AWND_STA_TYPE_PRECONFIG != l_group_info.staType) 
                {
                    l_group_info.staType = AWND_STA_TYPE_PRECONFIG;
                    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                }

                awnd_reconn_sta_pre(band, pBestAp[band]);

                pathDepth = (pBestAp[band]->netInfo.awnd_level > pathDepth)? (pBestAp[band]->netInfo.awnd_level): pathDepth;
                wifi_restart = wifi_restart | (1 << band);

#ifdef SUPPORT_MESHMODE_2G
                if (AWND_BAND_2G == band)
                {
                    g_awnd.is2GCaculatedBssid = 0;
                }
#endif
                AWN_LOG_WARNING("Set bssid %02X:%02X:%02X:%02X:%02X:%02X for band %s", 
                    pBestAp[band]->bssid[0], pBestAp[band]->bssid[1], pBestAp[band]->bssid[2],
                    pBestAp[band]->bssid[3], pBestAp[band]->bssid[4], pBestAp[band]->bssid[5],real_band_suffix[_get_real_band_type(band)]);
                AWN_LOG_INFO("More info is rssi:%d, awnd_net_type:%-3d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
                     pBestAp[band]->rssi,pBestAp[band]->netInfo.awnd_net_type, 
                    pBestAp[band]->netInfo.awnd_mac[0],pBestAp[band]->netInfo.awnd_mac[1],pBestAp[band]->netInfo.awnd_mac[2],
                    pBestAp[band]->netInfo.awnd_mac[3],pBestAp[band]->netInfo.awnd_mac[4],pBestAp[band]->netInfo.awnd_mac[5]); 
                
            }
#ifdef CONNECT_TO_SAME_DUT
            else if ( _is_vaild_mac(tmpEntry[band].bssid))
            {
                if (g_awnd.notBind && (memcmp(g_awnd.staConfig[band].bssid, tmpEntry[band].bssid, AWND_MAC_LEN)
#ifndef CONFIG_PLATFORM_MTK
                    || (g_awnd.staConfig[band].channel != 0)
#endif  /*CONFIG_PLATFORM_MTK*/
                    || (awnd_config_get_stacfg_enb(band) != 1)))
                {
                    valid_wifi_restart = valid_wifi_restart | (1 << band);
                }
                memcpy(g_awnd.staConfig[band].bssid, tmpEntry[band].bssid, AWND_MAC_LEN);

#if 0
                if (conn_status_before_trasfer[band] == AWND_STATUS_CONNECTED && (g_awnd.staConfig[band].channel == pBestAp[band]->channel))
                {
                    re_roaming = 1;
                    roaming_mac = pBestAp[band]->lan_mac;
                }
#endif
                memset(bssid, 0, AWND_MAX_SSID_LEN);
                _macaddr_ntop(tmpEntry[band].bssid, bssid);
                awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
                anwd_set_wireless_sta_bssid(bssid, band);
#endif
                awnd_config_set_stacfg_enb(WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? 1 : 0, band);
#ifndef CONFIG_AWN_MESH_OPT_SUPPORT
                if (band == AWND_BAND_5G)
                {
                    awnd_get_cac_state(band, &cac_state);
                    AWN_LOG_DEBUG("cac state is %d", cac_state);
                    if (0 == cac_state)
                    {
                        awnd_config_set_channel(0, band);
                    }
                }
                else
                {
                    awnd_config_set_channel(0, band);
                }
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */   
                    
                if(1 == BestApType && AWND_STA_TYPE_NORMAL == l_group_info.staType ) 
                {
                    l_group_info.staType = AWND_STA_TYPE_PRE;
                    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                }
                else if(0 == BestApType && AWND_STA_TYPE_PRE == l_group_info.staType ) 
                {
                    l_group_info.staType = AWND_STA_TYPE_NORMAL;
                    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                }

                awnd_reconn_sta_pre(band, &tmpEntry[band]);
                wifi_restart = wifi_restart | (1 << band);

#ifdef SUPPORT_MESHMODE_2G
                if (AWND_BAND_2G == band)
                {
                    g_awnd.is2GCaculatedBssid = 1;
                }
#endif

                AWN_LOG_WARNING("Calculated and set bssid %02X:%02X:%02X:%02X:%02X:%02X for band %s",
                    tmpEntry[band].bssid[0], tmpEntry[band].bssid[1], tmpEntry[band].bssid[2],
                    tmpEntry[band].bssid[3], tmpEntry[band].bssid[4], tmpEntry[band].bssid[5], real_band_suffix[_get_real_band_type(band)]);
            }

            /* compute plc peer mac here */
            if (AWND_STATUS_DISCONNECT == g_awnd.plcStatus)
                memcpy(g_awnd.plcPeerNeigh.lan_mac, lanMac, AWND_MAC_LEN);
#endif
        }

        if (wifi_restart && AWND_MODE_RE == curMode)
        {

            for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
            {
#ifdef CONFIG_PLATFORM_QCA               
                if((wifi_restart & (1 << band) && (!(valid_wifi_restart & (1 << band)))) ||
                    (g_awnd.wpa_supplicant_disable_mask & (1 << band)))
                {
                    AWN_LOG_WARNING("wifi_restart:%d, valid_wifi_restart:%d, g_awnd.wpa_supplicant_disable_mask:%d, enable wpa_supplicant status for band %s",
                        wifi_restart, valid_wifi_restart, g_awnd.wpa_supplicant_disable_mask, real_band_suffix[_get_real_band_type(band)]);
                    awnd_reconn_sta_post(band, false);
                }
#else
                if(wifi_restart & (1 << band) && (!(valid_wifi_restart & (1 << band))))
                {
                    awnd_reconn_sta_post(band, false);
            }
#endif //CONFIG_PLATFORM_QCA
            }

            wifi_restart = 0;
#ifdef CONFIG_AWN_RE_ROAMING
            ret = re_roaming ? AWND_RE_ROAMING : AWND_WIFI_RESTART;
#else
            ret = AWND_WIFI_RESTART;
#endif
        }
        else if (AWND_MODE_HAP == curMode)
        {
            if (AWND_NET_FAP == pBestNet->awnd_net_type)
                g_awnd.reStage = AWND_RE_STAGE_SECOND;
            else
                g_awnd.reStage = AWND_RE_STAGE_THIRD;
            ret = AWND_MODE_CHANGE;
        }
        
    }
    else if (g_awnd.netInfo.awnd_net_type == AWND_NET_LRE)
    {
        if (l_awnd_scan_table.scan_fast)
        {
            ret = AWND_SCAN_SCHED;
        }
        else if (AWND_STATUS_DISCONNECT == g_awnd.plcStatus)
        {
            //awnd_disconn_sta(AWND_BAND_2G);
            //awnd_disconn_sta(AWND_BAND_5G);
            //awnd_plc_disconnect();
            wifi_restart = 0;
            ret = AWND_MODE_CHANGE;  
        }
    }
    else if (AWND_MODE_HAP == curMode && l_awnd_scan_table.scan_fast)
    {
        ret = AWND_SCAN_SCHED;        
    }

    
out:
    if (wifi_restart && AWND_MODE_RE == curMode)
    {
        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
        {

            if(wifi_restart & (1 << band))
                awnd_reconn_sta_post(band, false);
        }
        ret = AWND_WIFI_RESTART;
    }    
    
    l_awnd_scan_table.scan_fast = 0;
    
    if(((pBestAp[AWND_BAND_2G] && memcmp(pBestAp[AWND_BAND_2G]->lan_mac, l_mac_prefer, AWND_MAC_LEN) != 0) && 
        (pBestAp[AWND_BAND_5G] && memcmp(pBestAp[AWND_BAND_5G]->lan_mac, l_mac_prefer, AWND_MAC_LEN) != 0)) 
        && memcmp(l_mac_prefer, macZero, AWND_MAC_LEN) != 0
        && g_awnd.ethStatus != AWND_STATUS_CONNECTED
        && g_awnd.ethStatus != AWND_STATUS_CONNECTING
        && AWND_MODE_RE == g_awnd.workMode)
    {
        wait_for_prefer_ap_cnt++;
        if (wait_for_prefer_ap_cnt >= AWND_WAIT_PREFER_AP_CNT)
        {
            AWN_LOG_INFO("The better ap is not the prefer ap, but is wait_for_prefer_ap so long, not wait again");
            wait_for_prefer_ap_cnt = 0;
        }
        else
        {
            AWN_LOG_INFO("The better ap is not the prefer ap, wait_for_prefer_ap again");
            // l_awnd_scan_table.scan_fast = 1;
            l_wait_prefer_connect = 1;
            awnd_scan_set_full_band();
            uloop_timeout_set(&wifi_scan_timer, l_awnd_config.tm_wait_prefer_ap);
        }
    }
    else if (wait_for_prefer_ap_cnt)
    {
        AWN_LOG_INFO("reset wait_for_prefer_ap_cnt");
        wait_for_prefer_ap_cnt = 0;
    }

    return ret;
}

#if SCAN_OPTIMIZATION
void awnd_scan_handle_result(struct uloop_timeout *t)
#else
void awnd_scan_handle_result(struct uloop_process *proc, int ret)
#endif //SCAN_OPTIMIZATION
{
    AWND_BAND_TYPE    band;  
    int isOnboarding = 0;

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    UINT8 disBandMask = 0;
    AWND_REAL_BAND_TYPE real_band = band;
#endif

#if CONFIG_PLATFORM_BCM
    UINT8 BandRestartMask = 0;
#if SCAN_OPTIMIZATION
    UINT8 scanFailMask = l_awnd_scan_table.scan_fail_mask;
#else
    UINT8 scanFailMask = (ret >> 8);
#endif //SCAN_OPTIMIZATION

    AWN_LOG_DEBUG("awnd_scan_handle_result failMask:%d", scanFailMask);

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        if (scanFailMask & (1 << band)) {
            g_awnd.scanFailCnt[band] ++;
            if (g_awnd.scanFailCnt[band] >= MAX_SCAN_FAIL_NUM) {
                AWN_LOG_WARNING("band:%d scan fail for %d times to wifi restart", band, g_awnd.scanFailCnt[band]);
                g_awnd.scanFailCnt[band] = 0;
                BandRestartMask |= (1 << band);
            }
        }
        else {
            g_awnd.scanFailCnt[band] = 0;
        }
    }

    if (BandRestartMask) {
        awnd_do_band_restart(BandRestartMask);
    }

#else
    AWN_LOG_INFO("awnd_scan_handle_result");   
#endif /* CONFIG_PLATFORM_BCM */

    if(AWND_MODE_HAP == g_awnd.workMode)
    {       
        switch (awnd_scan_handle_rootap(AWND_MODE_HAP))
        {
            case AWND_MODE_CHANGE:
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                awnd_mode_convert(AWND_MODE_HAP, AWND_MODE_RE);
                return;
            case AWND_SCAN_SCHED:
                uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_sched);
                break;
            default:
                awnd_flush_scan_table();                 
                uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_interval);  
                break;
        }
                   
    }
    else if (AWND_MODE_RE == g_awnd.workMode)
    {
        if (l_awnd_scan_table.scan_windows)
            l_awnd_scan_table.scan_windows-- ;
                
        switch (awnd_scan_handle_rootap(AWND_MODE_RE))
        {
            case AWND_WIFI_RESTART:
            AWN_LOG_INFO("AWND_WIFI_RESTART");
#if 1
                if (g_awnd.notBind && g_awnd.bindStatus < AWND_BIND_START)
                {   
                    /* notBinded: to send ubus message to smartip 
                        at the beginning and the end of wifi restart */
                    awnd_ubus_send_smartip_event(2, AWND_WIFI_CONFIG_BEGIN);
                }
#endif
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
                awnd_wifi_restart();
                awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
#if 1
                if (g_awnd.notBind && g_awnd.bindStatus < AWND_BIND_START)
                {
                    awnd_ubus_send_smartip_event(2, AWND_WIFI_CONFIG_END);
                }
#endif
                return;
                                        
            case AWND_MODE_CHANGE:
            AWN_LOG_INFO("AWND_MODE_CHANGE");
                if (AWND_RE_STAGE_THIRD == g_awnd.reStage)
                {
                    g_awnd.wifiToHap = 1;
                }
				 awnd_flush_scan_table();
                if (g_awnd.notBind)
                {
                    uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_sched);
                }
                else
                {
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                    if (AWND_STATUS_CONNECTED == g_awnd.ethStatus && g_awnd.findWifiRootApFailCnt >= FIND_WIFI_ROOTAP_FAIL_CNT)
                    {
                        AWN_LOG_NOTICE("eth is connected, but can't find wifi rootap %d times, stop scan.", FIND_WIFI_ROOTAP_FAIL_CNT);

                        for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
                        {
                            awnd_disconn_sta_pre(band, &disBandMask);
                        }

                        break;
                    }
                    else if (AWND_STATUS_CONNECTED == g_awnd.ethStatus)
                    {
                        g_awnd.findWifiRootApFailCnt ++;
                        AWN_LOG_DEBUG("g_awnd.findWifiRootApFailCnt:%d", g_awnd.findWifiRootApFailCnt);
                    }
#endif
                    uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_interval);
                }
                break;

            case AWND_SCAN_SCHED:
                AWN_LOG_INFO("AWND_SCAN_SCHED");
                uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_sched);
                break;  

#ifdef CONFIG_AWN_RE_ROAMING
            case AWND_RE_ROAMING:
                awnd_re_roam(roaming_mac);
                break;
#endif
                    
            default:
                AWN_LOG_INFO("default");
                if (AWND_NET_FAP == g_awnd.netInfo.awnd_net_type && !l_awnd_scan_table.scan_windows)
                {
                    if (g_awnd.notBind && (g_awnd.bindStatus < AWND_BIND_START) && g_awnd.rootAp[AWND_BAND_5G].rssi < l_awnd_config.low_rssi_threshold)
                    {
                        _get_onboarding_status(&isOnboarding);
                        if (ONBOARDING_ON !=  isOnboarding)
                        {
                            AWN_LOG_INFO("device has a weak 5g link and onboarding still didn't start, set wifi scan timer again");
                            awnd_flush_scan_table();
                            uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_interval);  
                            break;
                        }		
                    }
                	return;
                }
				awnd_flush_scan_table();
                uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_interval); 
                break;
        }                  
    }
    else
    {
        AWN_LOG_WARNING("shouldn't scan at mode:%s", modeToStr(g_awnd.workMode));
        return;
    }

    awnd_scan_set_full_band();
      
    return;
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
BOOL check_tipc_status()
{
    FILE* pResultStr  = NULL;
    char buff[32] = {0};
    int tipc_num = 0;

    pResultStr = popen("tipc-config -n | grep up | wc -l", "r");
    if (NULL == pResultStr)
    {   
        printf("popen faild. (%d, %s)\n",errno, strerror(errno));
        return -1; 
    }   

    fread(buff, 1, sizeof(buff), pResultStr);
    sscanf(buff, "%d", &tipc_num);
    if (tipc_num == 1)
    {
        return true;
    }
    else
    {
        return false;
    }
}


int awnd_set_tipc_check_time(int n)
{
    uloop_timeout_set(&ai_network_check_tipc_timer, n * 1000);
    return 0;
}

//check if RE connect to FAP
int awnd_ai_network_tipc_connect(struct uloop_timeout *t)
{
    if (g_awnd.workMode == AWND_MODE_RE)
    {
        if (check_tipc_status())
        {
            int status = get_alg_re_status();
            AWN_LOG_ERR("alg_re_status:%d", status);
            if (status != DN_RE_STATUS_AFTER_ROAMING)
            {
                AWN_LOG_ERR("do_pre_first_roaming");
                do_pre_first_roaming();
            }
            else// has roamed
            {
                AWN_LOG_ERR("re_alg_process");
                re_alg_process();
            }
            //uloop_timeout_cancel(&ai_network_check_tipc_timer);
        }
        else
        {
            awnd_set_tipc_check_time(5);
        }
    }
    return 0;
}

int ai_network_send_roaming(struct uloop_timeout *t)
{
    AWN_LOG_NOTICE("send_scan_info_flag:%d", send_scan_info_flag);
    if (send_scan_info_flag && (0 == access(AI_ROAMING_PAT_PATH,  0)))
    {
        send_first_roaming_request();
    }
    else
    {
        uloop_timeout_set(&ai_network_send_roaming_timer, 3500);
    }
}

int ai_network_roaming_status_revert(struct uloop_timeout *t)
{
    roaming_running = false;
    return 0;
}

void set_send_scan_info_flag(BOOL flag)
{
    send_scan_info_flag = flag;
    AWN_LOG_NOTICE("set send_scan_info_flag:%d", flag);
}

/* get scan result for ai networking */
void awnd_ai_network_get_scan_result()
{
#define SCANENTRY_NUM_MAX   (AWND_BAND_MAX_NUM * AWND_MAX_GROUP_MEMBER)
#define SCANENTRY_BUF_MAX   \
    (sizeof(struct aimsg_hdr_t) + sizeof(struct aidata_scan_info_t) + SCANENTRY_NUM_MAX * sizeof(struct aidata_scan_entry_t))
#ifdef CONFIG_PLATFORM_MTK
    /* tmp for x20v3 */
    AWN_LOG_NOTICE("MTK need to scanning first");
    system("iwlist rax0 scanning &");
    system("iwlist ra0 scanning &");
    sleep(5);
    AWN_LOG_NOTICE("start to get scan result");
#endif
    AWND_BAND_TYPE band;
    uint8_t total_ap = 0;
    uint8_t buf[SCANENTRY_BUF_MAX];
    struct aimsg_hdr_t *hdr;
    struct aidata_scan_info_t *info;
    struct aidata_scan_entry_t *scan_entry;
    AWND_AP_ENTRY *ap_entry;

    AWND_VAP_TYPE vap_type = AWND_VAP_AP;
    char * preconf_ssid = NULL;
    UINT8 * preconf_label = NULL;

    int i;
    uint32_t payload_size = 0;
    struct timeval tv;

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) {
        memset(&l_awnd_scan_table.apList[band], 0, sizeof(AWND_SCAN_RESULT));
        if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                               preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
        {
            //sleep(1);
            _stable_sleep(1);
            if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                                   preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
            {
                 AWN_LOG_INFO("band %s get scan result fail twice, keep scan table empty.", real_band_suffix[band]);
            }
        }
        total_ap += l_awnd_scan_table.apList[band].iApNum;
    }

    /* Send scan info */
    if (total_ap == 0) {
        AWN_LOG_INFO("Nothing scanned.");
        goto set_timer;
    }

    payload_size = sizeof(struct aidata_scan_info_t) +
        total_ap * sizeof(struct aidata_scan_entry_t);
    hdr = (struct aimsg_hdr_t *)buf;
    hdr->magic = AI_MSG_MAGIC_NUMBER;
    hdr->op = AI_MSG_OP_REPORT;
    hdr->sub_op = AI_MSG_SUBOP_REPORT_AP;
    hdr->type = AI_DATA_TYPE_SCANINFO;
    hdr->version = AI_DATA_VERSION_V1;
    hdr->payload_len = payload_size;
    hdr->src_module = AI_MSG_MODULE_NETWORKING;
    info = (struct aidata_scan_info_t *)hdr->payload;
    memcpy(info->device_mac.octet, l_awnd_config.mac, 6);
    info->num_scan = total_ap;
    scan_entry = &info->scan_list[0];
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++) {
		AWND_BAND_TYPE real_band = band;
#if CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT
		if (AWND_BAND_5G2 == band) {
			real_band = AWND_BAND_6G;
		}
#endif /* CONFIG_TRI_BACKHAUL_SUPPORT && CONFIG_WIFI_6G_SUPPORT */
        for (i = 0; i < l_awnd_scan_table.apList[band].iApNum; i++) {
            ap_entry = &l_awnd_scan_table.apList[band].tApEntry[i];
#if 0
			AWN_LOG_NOTICE("band[%d] i[%d] lan_mac[%02X%02X] bssid[%02X%02X] channel[%u] rssi[%u]", band, i, 
				ap_entry->lan_mac[5], ap_entry->lan_mac[6], ap_entry->bssid[5], ap_entry->bssid[6], 
				ap_entry->channel, ap_entry->rssi);
#endif
            memcpy(scan_entry->neighbor_mac.octet, ap_entry->lan_mac, 6);
            memcpy(scan_entry->bssid.octet, ap_entry->bssid, 6);
            scan_entry->band = real_band;
            scan_entry->channel = ap_entry->channel;
            scan_entry->rssi = ap_entry->rssi;
            scan_entry->ip = ap_entry->netInfo.awnd_lanip;
            scan_entry++;
        }
    }
    save_scaninfo(info, hdr->timestamp_s);
    // if (g_awnd.workMode == AWND_MODE_RE) {
    //     aimsg_send(AI_MSG_MODULE_CENTER, buf, sizeof(struct aimsg_hdr_t) + payload_size);
    // }
    set_send_scan_info_flag(true);
set_timer:
    // uloop_timeout_set(t, SCANNING_DURATION * 1000);
    return ;
}

// int awnd_ai_network_get_scan_result_now(void)
// {
//     uloop_timeout_set(&ai_network_getscan_timer, 500);
//     return 0;
// }

int awnd_ai_network_send_roaming(void)
{
    uloop_timeout_set(&ai_network_send_roaming_timer, 2500);
    return 0;
}

void awnd_ai_re_roam(struct uloop_timeout *t)
{
    awnd_wifi_re_roam();
}

int awnd_ai_msg_handler(void *data, int len, struct aimsg_addr *addr)
{
    return handle_aimsg(data, len, g_awnd.workMode);
}

int awnd_ai_fap_start(int alg_strategy, char *mac)
{
    int i;
    if (g_awnd.workMode != AWND_MODE_FAP) {
        AWN_LOG_ERR("Not ad fap mode!");
        return -1;
    }
    AWN_LOG_NOTICE("[info] trigger fap_alg_process.");

    fap_alg_process(alg_strategy, mac);
    
    return 0;
}

int awnd_ai_set_hops_factor(int hops_factor)
{
    AWN_LOG_NOTICE("setting hops factor:%d", hops_factor);
    handle_setting_hops_factor(hops_factor);
    return 0;
}

int awnd_ai_get_hops_factor(float *hops_factor)
{
    *hops_factor = handle_getting_hops_factor();
    return 0;
}

int awnd_ai_set_patc_comp(int patc_comp)
{
    AWN_LOG_NOTICE("setting compensation for pat parammeter c");
    handle_setting_patc_comp(patc_comp);
}

int awnd_ai_debug_print()
{
    ai_debug_print();
    
    return 0;
}

int awnd_test_ping_rootap(void)
{
    AWN_LOG_INFO("Prepare to ping root ap. LANIP: %08X", g_awnd.rootAp[0].netInfo.awnd_lanip);
    return ping_lanip(g_awnd.capLanip);
}

int awnd_ping_root(void)
{
    return ping_lanip(g_awnd.capLanip);
}
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#if CONFIG_RE_RESTORE_STA_CONFIG
/*!
*\fn           awnd_sta_config_handler()
*\brief        Set sta_config's value
*\param[in]    t: normal uloop_timeout 
*\return       void
*/
void awnd_sta_config_handler(struct uloop_timeout *t)
{
    AWND_BAND_TYPE band;
    char old_bssid[AWND_MAX_SSID_LEN];
    u_int8_t backhaul_is_stable = 1;

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (AWND_STATUS_CONNECTED != g_awnd.connStatus[band])
        {
            backhaul_is_stable = 0;
            AWN_LOG_DEBUG("g_awnd.connStatus[%d] is connected", band);
        }
    }
    if (backhaul_is_stable && need_save_config_when_backhaul_stable)
    {
        AWN_LOG_NOTICE(" -----------backhaul_is_stable, will save config------------ ");
        if (AWND_OK == awnd_config_set_sta_config(true))
        {
            /* Rootap has changed! Save config into sta_config and do not monitor any more */
            need_save_config_when_backhaul_stable = 0;
        }
        else
        {
            /* Rootap hasn't changed, or something go wrong! Do not save, keep watching */
            uloop_timeout_set(&handle_sta_config_timer, l_awnd_config.tm_record_sta_config_monitoring_interval);
        }
    }
    else
    {
        awnd_config_set_sta_config(false);
        if (!backhaul_is_stable)
            uloop_timeout_set(&handle_sta_config_timer,  l_awnd_config.tm_record_sta_config_interval);
    }
}
#endif

int awnd_config_covert_backhaul_with_same_rootap(void)
{
    AWND_AP_ENTRY   *pBestAp[AWND_BAND_MAX_NUM] = {NULL};
    AWND_BAND_TYPE   band;
    AWND_AP_ENTRY    *pRootAp    = g_awnd.rootAp;
    char  bssid[AWND_MAX_SSID_LEN];
    AWND_BAND_TYPE   selectband = AWND_BAND_MAX_NUM;
    AWND_VAP_TYPE    vap_type;
    UINT8 lanMac[AWND_MAC_LEN]={0};
    AWND_AP_ENTRY  tmpEntry[AWND_BAND_MAX_NUM]={0};
    char * preconf_ssid = NULL;
    UINT8 * preconf_label = NULL;
    int BestApType = 0; /* 0:normal  1:preconf */
    int  same_rootap = 0;
    int  get_scan_result = 0;
    int  ret = AWND_OK;

    vap_type = AWND_VAP_AP;
    if(g_awnd.notBind && AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND && ! _is_null_group_info( &(l_group_info.preconfGroupInfo) ) )
    {
        /*get scan result which is filtered by preconf and default label and ssid*/
        preconf_ssid = l_group_info.preconfGroupInfo.ssid;
        preconf_label = l_group_info.preconfGroupInfo.label;
    }

    /* to get scan result */
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        memset(&l_awnd_scan_table.apList[band], 0, sizeof(AWND_SCAN_RESULT));
        if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                               preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
        {
            _stable_sleep(1);
            if (AWND_ERROR == awnd_get_scan_result(&l_awnd_scan_table.apList[band], l_group_info.staGroupInfo.ssid, l_group_info.staGroupInfo.label,
                                                   preconf_ssid, preconf_label, band, vap_type, l_awnd_scan_table.scan_fast))
            {
                 AWN_LOG_INFO("band %s get scan result fail twice, keep scan table empty.", real_band_suffix[band]);
            }
        }
    }

    /* to find rootap entry from scan result */
    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (NULL != (pBestAp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pRootAp[band].lan_mac, NULL, band)))
        {
            same_rootap = 1;
        }
    }

    if (1 == same_rootap) {
        ret = AWND_WIFI_RESTART;
    }
    else {
        return ret;
    }

    /* select best band */
#if CONFIG_TRI_BACKHAUL_SUPPORT
    if ((NULL == pBestAp[AWND_BAND_2G] && (NULL != pBestAp[AWND_BAND_5G] || NULL != pBestAp[AWND_BAND_5G2]))
        || (NULL != pBestAp[AWND_BAND_5G] && pBestAp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold)
        || (NULL != pBestAp[AWND_BAND_5G2] && pBestAp[AWND_BAND_5G2]->rssi >= l_awnd_config.low_rssi_threshold))
    {
        if (awnd_compare_scan_entry(pBestAp[AWND_BAND_5G], pBestAp[AWND_BAND_5G2]))
        {
            selectband = AWND_BAND_5G;
        }
        else
        {
            selectband = AWND_BAND_5G2;
        }

        if (NULL != pBestAp[AWND_BAND_2G] && pBestAp[selectband]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
            pBestAp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
            awnd_get_better_band_entry(pBestAp[AWND_BAND_2G], pBestAp[selectband]))
        {
            AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g_%d:%d), bestAp select 2g.", pBestAp[AWND_BAND_2G]->pathRate, selectband, pBestAp[selectband]->pathRate);
            selectband = AWND_BAND_2G;
        }
    }
#else
    /* at this version , both band connect to the same rootap, maybe change it in the future. */
    if (NULL != pBestAp[AWND_BAND_5G] && (pBestAp[AWND_BAND_5G]->rssi >= l_awnd_config.low_rssi_threshold || NULL == pBestAp[AWND_BAND_2G]))
    {
        selectband = AWND_BAND_5G;

        if (NULL != pBestAp[AWND_BAND_2G] && pBestAp[AWND_BAND_5G]->pathRate < l_awnd_config.wifi_pathRate_threshold_5g &&
            pBestAp[AWND_BAND_2G]->pathRate > l_awnd_config.wifi_pathRate_threshold_2g &&
            awnd_get_better_band_entry(pBestAp[AWND_BAND_2G], pBestAp[AWND_BAND_5G]))
        {
            AWN_LOG_INFO("pathRate compare(band2g:%d VS band5g:%d), bestAp select 2g.", pBestAp[AWND_BAND_2G]->pathRate, pBestAp[AWND_BAND_5G]->pathRate);
            selectband = AWND_BAND_2G;
        }
    }
#endif
    else if (NULL != pBestAp[AWND_BAND_2G])
    {
        selectband = AWND_BAND_2G;
    }

#ifdef CONFIG_AWN_QCA_6G_BACKHATL_ADAPTIVE
    AWN_LOG_INFO("selectband = %d", selectband);
#endif

    /* find STAs of other bands by the select band*/
    if (selectband < AWND_BAND_MAX_NUM)
    {
        awnd_transform_bssid_from_select_band(selectband, pBestAp[selectband]->lan_mac, tmpEntry, pBestAp[selectband]->isPreconf, pBestAp[selectband]->bssid);
        for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
        {
            memcpy(tmpEntry[band].lan_mac, pBestAp[selectband]->lan_mac, AWND_MAC_LEN);
            if (band == selectband)
                continue;

            pBestAp[band] = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], pBestAp[selectband]->lan_mac,tmpEntry[band].bssid, band);
            if (NULL == pBestAp[band])
            {
                AWN_LOG_INFO("fail to get %s ROOTAP from %s ROOTAP.", real_band_suffix[band], real_band_suffix[selectband]);
            }
        }
        /* is best ap is preconf AP */
        if(1 == pBestAp[selectband]->isPreconf)
        {
            BestApType = 1;
        }
        else
        {
            BestApType = 0;
        }
    }

    awnd_disconn_all_sta();

    for (band = AWND_BAND_2G; band < AWND_BAND_MAX_NUM; band++)
    {
        if (NULL != pBestAp[band])
        {
            memcpy(g_awnd.staConfig[band].bssid, pBestAp[band]->bssid, AWND_MAC_LEN);
            memset(bssid, 0, AWND_MAX_SSID_LEN);
            _macaddr_ntop(pBestAp[band]->bssid, bssid);
            awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
            anwd_set_wireless_sta_bssid(bssid, band);
#endif
            awnd_config_set_stacfg_enb(WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? 1 : 0, band);
            awnd_config_set_channel(pBestAp[band]->channel, band);
            if(1 == BestApType && AWND_STA_TYPE_NORMAL == l_group_info.staType)
            {
                l_group_info.staType = AWND_STA_TYPE_PRE;
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
            }
            else if(0 == BestApType && AWND_STA_TYPE_PRE == l_group_info.staType)
            {
                l_group_info.staType = AWND_STA_TYPE_NORMAL;
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
            }
            awnd_reconn_sta_pre(band, pBestAp[band]);

            AWN_LOG_WARNING("Set bssid %02X:%02X:%02X:%02X:%02X:%02X for band %s",
                pBestAp[band]->bssid[0], pBestAp[band]->bssid[1], pBestAp[band]->bssid[2],
                pBestAp[band]->bssid[3], pBestAp[band]->bssid[4], pBestAp[band]->bssid[5],real_band_suffix[band]);
            AWN_LOG_INFO("More info is rssi:%d, awnd_net_type:%-3d, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X",
                 pBestAp[band]->rssi,pBestAp[band]->netInfo.awnd_net_type,
                pBestAp[band]->netInfo.awnd_mac[0],pBestAp[band]->netInfo.awnd_mac[1],pBestAp[band]->netInfo.awnd_mac[2],
                pBestAp[band]->netInfo.awnd_mac[3],pBestAp[band]->netInfo.awnd_mac[4],pBestAp[band]->netInfo.awnd_mac[5]);
        }
        else if ( _is_vaild_mac(tmpEntry[band].bssid))
        {
            memcpy(g_awnd.staConfig[band].bssid, tmpEntry[band].bssid, AWND_MAC_LEN);
            memset(bssid, 0, AWND_MAX_SSID_LEN);
            _macaddr_ntop(tmpEntry[band].bssid, bssid);
            awnd_config_set_stacfg_bssid(bssid, band);
#ifdef CONFIG_AWN_RE_ROAMING
            anwd_set_wireless_sta_bssid(bssid, band);
#endif

            awnd_config_set_stacfg_enb(WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option) ? 1 : 0, band);
            awnd_config_set_channel(0, band);
            if(1 == BestApType && AWND_STA_TYPE_NORMAL == l_group_info.staType )
            {
                l_group_info.staType = AWND_STA_TYPE_PRE;
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
            }
            else if(0 == BestApType && AWND_STA_TYPE_PRE == l_group_info.staType )
            {
                l_group_info.staType = AWND_STA_TYPE_NORMAL;
                awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_STA);
            }
            awnd_reconn_sta_pre(band, &tmpEntry[band]);

            AWN_LOG_WARNING("Calculated and set bssid %02X:%02X:%02X:%02X:%02X:%02X for band %s",
                tmpEntry[band].bssid[0], tmpEntry[band].bssid[1], tmpEntry[band].bssid[2],
                tmpEntry[band].bssid[3], tmpEntry[band].bssid[4], tmpEntry[band].bssid[5], real_band_suffix[band]);
        }
    }

    return ret;
}

/* check if better subnet exist */
int awnd_plc_handle_neigh()
{
    AWND_PLC_NEIGH *pPeerNeigh = NULL;
    AWND_PLC_NEIGH *pBestNeigh = NULL;
    AWND_PLC_NEIGH *pNeighTbl = l_awnd_plc_neigh_table.plcNeigh;
    AWND_NET_INFO  *pPeerNetInfo;
    AWND_NET_INFO   tmpNetInfo;
    AWND_HOTPLUG_CONFIG hotplugCfg;
    AWND_BAND_TYPE band;
    int betterApExist = 0; 
    int isPlcRoot = 0;
    int oldPlcRoot = g_awnd.isPlcRoot;    
    int pathDepth = 0;
    int ret = AWND_OK;
    int i = 0;
    int update = 0;
    UINT32 onlyFindFap = 0;
    int capMacChanged = 0;
    int betterServerDetect = 0;
    BOOL capHasPlc = false;
    UINT8 *pRootApMac = NULL;	

    AWN_LOG_INFO("==============Handle plc neigh event\n");
    
    if (AWND_MODE_FAP == g_awnd.workMode)
        return 0;

    /* find peer neigh */
    if (AWND_MODE_RE == g_awnd.workMode)
    {
        pPeerNeigh = awnd_find_plc_neigh(pNeighTbl, g_awnd.plcPeerNeigh.lan_mac, 0);  
    }
     
    if (AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND)
        onlyFindFap = 1;

    /* find best neigh */
    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_VALID != pNeighTbl[i].flag)
            continue;

        if ( onlyFindFap && AWND_NET_FAP != pNeighTbl[i].netInfo.awnd_net_type)
            continue;

        if (AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_LRE <= pNeighTbl[i].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find FAP/HAP in reStage 3");
            continue;
        }

        if (!pBestNeigh)
            pBestNeigh = &pNeighTbl[i];

        else if (IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), &(pBestNeigh->netInfo))) {
            if (pNeighTbl[i].netInfo.awnd_level < pBestNeigh->netInfo.awnd_level
                || (pNeighTbl[i].netInfo.awnd_level == pBestNeigh->netInfo.awnd_level
                     && _mac_compare(pNeighTbl[i].lan_mac, pBestNeigh->lan_mac) > 0))
                pBestNeigh = &pNeighTbl[i];
        }
        else 
        {
            if ((memcmp(g_awnd.fapMac, pBestNeigh->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {
                continue;
            }
            if ((memcmp(g_awnd.fapMac, pNeighTbl[i].netInfo.awnd_mac, AWND_MAC_LEN) == 0))
            {   /* to find binded FAP entry first */   
                pBestNeigh = &pNeighTbl[i];
            }
            else if (HIGH_PRIO_SUBNET(&(pNeighTbl[i].netInfo), &(pBestNeigh->netInfo)))
            {
                pBestNeigh = &pNeighTbl[i];
            }
        }
    }


    if (pBestNeigh && pBestNeigh != pPeerNeigh)
    {
         if (pPeerNeigh == NULL && _is_in_disconnected_state(g_awnd.connStatus))
         {
             if ( ! IN_SAME_SUBNET(&(pBestNeigh->netInfo), &g_awnd.netInfo) && HIGH_PRIO_SUBNET(&(pBestNeigh->netInfo), &g_awnd.netInfo))
                 betterApExist = 1;
         }
         else 
         {
             if (pPeerNeigh)
                 pPeerNetInfo = &(pPeerNeigh->netInfo);
             else
             {
                 for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
                 {
                     if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band])
                        pPeerNetInfo = &g_awnd.rootAp[band].netInfo;
                 }
             }

             if( ! IN_SAME_SUBNET(&(pBestNeigh->netInfo), pPeerNetInfo) 
                      && HIGH_PRIO_SUBNET(&(pBestNeigh->netInfo), pPeerNetInfo))
             {
                 AWN_LOG_INFO("Find better AP due to high level AP exist.");
                 betterApExist = 1;
             }
             else if (IN_SAME_SUBNET(&(pBestNeigh->netInfo), pPeerNetInfo) 
                      && pBestNeigh->netInfo.awnd_level <= pPeerNetInfo->awnd_level)
             {
                 if (pPeerNeigh == NULL || pBestNeigh->netInfo.awnd_level < pPeerNetInfo->awnd_level)
                 {
                      if (pBestNeigh->isNew) {
                          AWN_LOG_INFO("Find better AP due to the exist connection without PLC but the same or smaller level new neigh with PLC ");
                          betterApExist = 1;                          
                      }
                 }
                 else if(pBestNeigh->plcRoot && ! pPeerNeigh->plcRoot)
                 {
                     if (AWND_STATUS_DISCONNECT != g_awnd.plcStatus || pBestNeigh->isNew) {
                         AWN_LOG_INFO("Find better AP due to PLC ROOT change.");
                         betterApExist = 1;

                     }
                 }               
                  
             }
         }         
    }


    if (NULL == pPeerNeigh && AWND_MODE_RE == g_awnd.workMode &&
        (_is_in_connected_state(g_awnd.connStatus) || AWND_STATUS_DISCONNECT != g_awnd.ethStatus))
    {
        if (NULL == pBestNeigh)
            isPlcRoot = 1;            
        else if (( ! IN_SAME_SUBNET(&g_awnd.netInfo, &(pBestNeigh->netInfo)) 
                      && HIGH_PRIO_SUBNET(&g_awnd.netInfo, &(pBestNeigh->netInfo)))
               ||  ( IN_SAME_SUBNET(&g_awnd.netInfo, &(pBestNeigh->netInfo)) 
                      && (g_awnd.netInfo.awnd_level < pBestNeigh->netInfo.awnd_level
                          || (g_awnd.netInfo.awnd_level == pBestNeigh->netInfo.awnd_level
                              && _mac_compare(l_awnd_config.mac, pBestNeigh->lan_mac) > 0))))
        {
            isPlcRoot = 1;
        }
    }
    else if (AWND_MODE_RE != g_awnd.workMode)
    {
        isPlcRoot = 1;
    }

    /* to set plc root when eth connected */
    if (AWND_MODE_RE == g_awnd.workMode && AWND_STATUS_DISCONNECT != g_awnd.ethStatus)
    {
        if (oldPlcRoot != isPlcRoot)
        {
            awnd_plc_set_root(isPlcRoot);
            AWN_LOG_INFO("plc handle: set plc root as %d when eth connected", isPlcRoot);
            awnd_repacd_restart(AWND_MODE_RE, 1);
        }
        return 0;
    }

    if (AWND_MODE_RE == g_awnd.workMode)
    {
        if (oldPlcRoot != isPlcRoot)
        {
            awnd_plc_set_root(isPlcRoot);
            ret = AWND_REPACD_QUICK_RESTART;
        }
        
        if (! betterApExist)
        {
                /* to disconnect plc connect when wifi awn_level >= pPeerNeigh level */
            if (pBestNeigh && pBestNeigh == pPeerNeigh && _is_in_connected_state(g_awnd.connStatus)
                && AWND_STATUS_CONNECTED == g_awnd.plcStatus
                && (pPeerNeigh->netInfo.awnd_level >= g_awnd.netInfo.awnd_level)
                && g_awnd.netInfo.awnd_level != 0)
            {
                AWN_LOG_NOTICE("disconnect plc when plcRoot'level >= level of myself");
                awnd_plc_disconnect();
                ret = AWND_MODE_CHANGE;
            }
#ifdef CONFIG_PRODUCT_PLC_SGMAC
            else if (NULL != pPeerNeigh && AWND_STATUS_CONNECTED == g_awnd.plcStatus &&
                NULL == pBestNeigh)
            {
                AWN_LOG_NOTICE("disconnect plc when pPeerNeigh exist but pBestNeigh is MULL");
                awnd_plc_disconnect();
                ret = AWND_MODE_CHANGE;
            }
#endif
            else if(NULL != pPeerNeigh && AWND_STATUS_CONNECTED == g_awnd.plcStatus
                && AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_HAP == g_awnd.netInfo.awnd_net_type)
            {
                /* compare my server detect status with rootap */
                if (pPeerNeigh->netInfo.server_detected && g_awnd.server_detected)
                {
                    if (pPeerNeigh->netInfo.server_touch_time < g_awnd.server_touch_time)
                        betterServerDetect = 1;
                }
                else if (g_awnd.server_detected)
                    betterServerDetect = 1;

                if (betterServerDetect)
                {
                    AWN_LOG_INFO("my server detected is better than conenncted rootap");
                    ret = AWND_MODE_CHANGE;
                }
            }
            else if (NULL != pPeerNeigh)
            {
                memcpy(&g_awnd.plcPeerNeigh, pPeerNeigh, sizeof(AWND_PLC_NEIGH));
                
                if (AWND_STATUS_DISCONNECT == g_awnd.plcStatus && pPeerNeigh->plcRoot) 
                {
                    /* only when peerneigh == bestneigh reconnect plc*/
                    awnd_plc_reconnect();
                    ret = AWND_WIFI_RESTART; 
                }
                else if (AWND_STATUS_CONNECTING == g_awnd.plcStatus) 
                {
                    AWN_LOG_NOTICE("PLC backhaul is connected.");        
                    g_awnd.plcStatus = AWND_STATUS_CONNECTED;
                    g_awnd.plcWinWifi = 0;
                    /* compare capMac with pPeerNeigh set caphasplc */
                    if(0 == memcmp(pPeerNeigh->netInfo.awnd_mac, pPeerNeigh->lan_mac, AWND_MAC_LEN))
                    {
                        capHasPlc = true;
                    }
                    awnd_write_rt_info(AWND_INTERFACE_PLC, true, pPeerNeigh->lan_mac, capHasPlc);
                }

            }
            else if (AWND_STATUS_DISCONNECT != g_awnd.plcStatus)
            {				
                AWN_LOG_NOTICE("PLC backhaul lost connection.");
#ifdef CONFIG_PRODUCT_PLC_SGMAC         
                awnd_plc_disconnect();
                ret = AWND_MODE_CHANGE;
#else
                if (_is_in_disconnected_state(g_awnd.connStatus))
                {
                    awnd_plc_disconnect();
                    ret = AWND_MODE_CHANGE;
                }
                else
                {
                    awnd_plc_disconnect_without_cleanup(isPlcRoot);
                    ret = AWND_WIFI_RESTART; 
                }           
#endif
             }

             #if 0
             else if (AWND_STATUS_DISCONNECT == g_awnd.plcStatus)
             {
                 if (oldPlcRoot != isPlcRoot)
                 {
                     awnd_plc_set_root(isPlcRoot);
                     ret = AWND_REPACD_QUICK_RESTART;
                 }
             }
             #endif
            else if (NULL == pPeerNeigh && AWND_RE_STAGE_THIRD == g_awnd.reStage
                    && AWND_STATUS_DISCONNECT == g_awnd.plcStatus)
            {
                AWN_LOG_INFO("plc inspect RE: THIRD --> FOUTH ");
                g_awnd.plcToHap = 1;
            }
        }
        else
        {
            awnd_plc_disconnect();
            ret = AWND_OK;
        }

        /* deliver tpie */
        if (NULL != pPeerNeigh && AWND_STATUS_CONNECTED == g_awnd.plcStatus && _is_in_disconnected_state(g_awnd.connStatus))
        {
                memcpy(&tmpNetInfo, &pPeerNeigh->netInfo, sizeof(AWND_NET_INFO));
                tmpNetInfo.awnd_level += 1;
                update = 1;				
											
                pRootApMac = pPeerNeigh->lan_mac;
        }
        else if (! _is_in_connected_state(g_awnd.connStatus))
        {
            awnd_init_tpie(&tmpNetInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
            update = 1;			
        }        
        if (update && memcmp(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO)))
        {
            if (!IN_SAME_SUBNET_EXACT(&g_awnd.netInfo, &tmpNetInfo))
            {
                if (tmpNetInfo.awnd_net_type != AWND_NET_FAP || g_awnd.netInfo.awnd_net_type == tmpNetInfo.awnd_net_type)
                {
                    uloop_clear_wifi_processes();

                    awnd_scan_set_full_band();
                    uloop_timeout_set(&wifi_scan_timer,         l_awnd_config.tm_scan_sched);
                }
            }
        
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            awnd_update_tpie(&tmpNetInfo, AWND_NETINFO_WIFI);
#else
            awnd_update_tpie(&tmpNetInfo);
#endif
            awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, pRootApMac);

			if (memcmp(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN) && _is_vaild_mac(g_awnd.capMac))
            {
                hotplugCfg.srcMode = AWND_MODE_RE;
                hotplugCfg.dstMode = AWND_MODE_RE;
                hotplugCfg.type = AWND_HOTPLUG_CAP_CHANGE;
                awnd_mode_call_hotplug(&hotplugCfg);
                capMacChanged = 1;
            }
            memcpy(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN);

            if ((AWND_NET_LRE != tmpNetInfo.awnd_net_type) && (AWND_NET_MAX != g_awnd.capNetType))
            {
                 hotplugCfg.srcMode = AWND_MODE_RE;
                 hotplugCfg.dstMode = AWND_MODE_RE;
                 hotplugCfg.type = AWND_HOTPLUG_CAP_TYPE_CHANGE;

                if (tmpNetInfo.awnd_net_type != g_awnd.capNetType)
                {   /* to call hotplug when cap net_type change from vaild_type to vaild_type */
                    if (AWND_NET_FAP == tmpNetInfo.awnd_net_type)
                    {
                        hotplugCfg.capSrcType = AWND_NET_HAP;
                        hotplugCfg.capDstType = AWND_NET_FAP;
                    }
                    else if (AWND_NET_HAP == tmpNetInfo.awnd_net_type)
                    {
                        hotplugCfg.capSrcType = AWND_NET_FAP;
                        hotplugCfg.capDstType = AWND_NET_HAP;
                    }
                    awnd_mode_call_hotplug(&hotplugCfg);
                }
                else if (capMacChanged)
                {   /* to call hotplug when cap net_type is not changed but cap mac is changed */
                    hotplugCfg.capSrcType   =   tmpNetInfo.awnd_net_type;
                    hotplugCfg.capDstType   =   tmpNetInfo.awnd_net_type;
                    awnd_mode_call_hotplug(&hotplugCfg);
                }
            }
            if(AWND_NET_LRE != tmpNetInfo.awnd_net_type)
            {   /* not to update net type when rootap's net type is LRE */
                g_awnd.capNetType = tmpNetInfo.awnd_net_type;
            }
            
            if ((g_awnd.capLanip != tmpNetInfo.awnd_lanip) && (0 != g_awnd.capLanip)
                && (0 != tmpNetInfo.awnd_lanip))
            {
                 hotplugCfg.srcMode = AWND_MODE_RE;
                 hotplugCfg.dstMode = AWND_MODE_RE;
                 hotplugCfg.type = AWND_HOTPLUG_CAP_IP_CHANGE;
                 awnd_mode_call_hotplug(&hotplugCfg);
            }
            if (0 != tmpNetInfo.awnd_lanip)
            {
                g_awnd.capLanip = tmpNetInfo.awnd_lanip;
            }

            if ((g_awnd.capDns != tmpNetInfo.awnd_dns) && (0 != g_awnd.capDns)
                && (0 != tmpNetInfo.awnd_dns))
            {
                 hotplugCfg.srcMode = AWND_MODE_RE;
                 hotplugCfg.dstMode = AWND_MODE_RE;
                 hotplugCfg.type = AWND_HOTPLUG_CAP_DNS_CHANGE;
                 awnd_mode_call_hotplug(&hotplugCfg);
            }
            if (0 != tmpNetInfo.awnd_dns)
            {
                g_awnd.capDns = tmpNetInfo.awnd_dns;
            }

            memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
        }
        else if (oldPlcRoot != isPlcRoot)
        {
            awnd_notify_tpie_to_kernel(&g_awnd.netInfo);
        }


        switch(ret) {
        case AWND_MODE_CHANGE:            
			if (AWND_RE_STAGE_THIRD == g_awnd.reStage)
			{
                AWN_LOG_INFO("plc inspect RE: THIRD --> FOUTH ");
                g_awnd.plcToHap = 1;
			}
            return 0;
        case AWND_WIFI_RESTART:
            awnd_wifi_restart();
            awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE); 
            return 0; 
        case AWND_REPACD_QUICK_RESTART:
            awnd_repacd_restart(AWND_MODE_RE, 1);
            return 0;
        default:
            break;
        }

    }

    /* if in the same subnet ,should judge wether plc or wifi better, otherwise it will goto a loop plc-->wifi-->plc */
    if (betterApExist) {
        
        AWN_LOG_INFO("Find better subnet from plc");		

        /* only plc connect, wifi need to scan at the scan windows */
        l_awnd_scan_table.scan_windows = 3; 
        
        /* plc reconnect*/
        memcpy(&g_awnd.plcPeerNeigh, pBestNeigh, sizeof(AWND_PLC_NEIGH));           
        awnd_plc_reconnect();        
        
        if(AWND_MODE_HAP == g_awnd.workMode) {           
            g_awnd.reStage = AWND_RE_STAGE_SECOND;
            awnd_mode_convert(AWND_MODE_HAP, AWND_MODE_RE);
            return 0;
        }
        else if (AWND_MODE_RE == g_awnd.workMode){                   
            awnd_wifi_restart();            
            awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
            return 0;           
        }
    }
   
    return 0;
}

void awnd_plc_inspect(struct uloop_timeout *t)
{
    if (! PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
        return;

#if AWND_PLC_EVENT_RECV
    if (0 == l_awnd_plc_neigh_table.eventEnable)
    {
        l_awnd_plc_neigh_table.eventEnable = 1;
        awn_plcson_set_detect_param(1, 1,  l_awnd_config.plc_entry_aging_time); 
    }
    awn_plcson_get_neigh_tbl(l_awnd_plc_neigh_table.plcNeigh);
    awnd_plc_handle_neigh();

#else

    if (!g_awnd.notBind)
    {
        awn_plcson_get_neigh_tbl(l_awnd_plc_neigh_table.plcNeigh);
        awnd_plc_handle_neigh();
    }

    uloop_timeout_set(&plc_neigh_inspect_timer,  l_awnd_config.tm_plc_inspect_interval);

#endif
}

#if AWND_PLC_EVENT_RECV
void awnd_plc_event_handler(struct uloop_fd *u, unsigned int ev)
{
    awnd_plc_event_recv(l_awnd_plc_neigh_table.plcNeigh, u->fd);
    awnd_plc_handle_neigh();
}
#endif

int awnd_eth_handle_neigh()
{
    AWND_ETH_NEIGH *pBestNeigh = NULL;
    AWND_ETH_NEIGH *pRootAPNeigh = NULL;
    AWND_ETH_NEIGH *pNeighTbl = l_awnd_eth_neigh_table.ethNeigh;
    AWND_NET_INFO   tmpNetInfo;
    AWND_HOTPLUG_CONFIG hotplugCfg;
    AWND_BAND_TYPE band;
    int fapExistInEth = 0;
    int linkStateChanged = 0;    
    int ret = AWND_OK;
    int i;
    UINT8 isEthNeighExist[MAX_ETH_DEV_NUM];
    int ethNum = 0;
    int hapChangeToRE = 0;
    int wireless_link[AWND_BAND_MAX] = {0};
    int wireless_iff_up[AWND_BAND_MAX] = {0};
    int wireless_linked = 0;
    UINT32 onlyFindFap = 0;
    static UINT8 preEthNeighIf[IFNAMSIZ] = {0};
    int betterServerDetect = 0;
    int capMacChanged = 0;
    int ethRootApMacChanged = 0;
    AWND_NET_INFO *ethNetInfo = NULL;
    int oldEthNumLinktoAP = -1;
    UINT8 ethParentMac[AWND_MAC_LEN] = {0};
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    ethNetInfo = &g_awnd.ethNetInfo;
#else
    ethNetInfo = &g_awnd.netInfo;
#endif
    int lastEthHasNeigh = 0;

    if (AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND)
        onlyFindFap = 1;

    for (ethNum = 0; ethNum < MAX_ETH_DEV_NUM; ethNum++)
    {
        if (g_awnd.ethLinktoAP[ethNum] == 1){
            oldEthNumLinktoAP = ethNum;
        }
        isEthNeighExist[ethNum] = 0;
        g_awnd.ethLinktoAP[ethNum] = 0;
    }

    /* find best neigh */
    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_VALID != pNeighTbl[i].flag)
            continue;

        if ( onlyFindFap && AWND_NET_FAP != pNeighTbl[i].netInfo.awnd_net_type)
            continue;

        if (AWND_RE_STAGE_THIRD == g_awnd.reStage && AWND_NET_LRE <= pNeighTbl[i].netInfo.awnd_net_type)
        {
            AWN_LOG_INFO("only to find FAP/HAP in reStage 3");
            continue;
        }

        if (AWND_SYSMODE_ROUTER == g_awnd.sysMode || AWND_SYSMODE_AP == g_awnd.sysMode)
        {
            //if ((AWND_MODE_FAP == g_awnd.workMode && AWND_NET_FAP == pNeighTbl[i].netInfo.awnd_net_type && !IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), &g_awnd.netInfo))
            //    || AWND_MODE_FAP != g_awnd.workMode)
            {

                for (ethNum = 0; ethNum < l_awnd_config.ethIfCnt; ethNum++)
                {
                    if (0 == strncmp(l_awnd_config.ethIfnames[ethNum], pNeighTbl[i].dev_name, IFNAMSIZ))
                    {
                        isEthNeighExist[ethNum] = 1;
                    }
                }
            }
        }

        if ( 1 /* AWND_SYSMODE_AP == g_awnd.sysMode*/ )
        {
            /* AP mode:
                if eth is conenncted,
                    not to handler neigbor that ( awnd_level >= mine && awnd_mac is the same )
                to solve the problem: all DUT connect switch, and FAP power offf. RE cannont change to AP
             2017-09-19 */
            if ( AWND_STATUS_CONNECTED == g_awnd.ethStatus &&
                    IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), ethNetInfo)
                    && pNeighTbl[i].netInfo.awnd_level >= ethNetInfo->awnd_level)
            {
                AWN_LOG_INFO("not to handler neigbor that: awnd_level(%d) >= mine(%d) && awnd_mac is the same )\n",
                    pNeighTbl[i].netInfo.awnd_level, ethNetInfo->awnd_level);
                continue;
            }
        }

        if (!(AWND_STATUS_CONNECTED == g_awnd.ethStatus &&
            IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), ethNetInfo)
            && pNeighTbl[i].netInfo.awnd_level >= ethNetInfo->awnd_level))
        {
            if (!pBestNeigh)
                pBestNeigh = &pNeighTbl[i];
            else if (IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), &(pBestNeigh->netInfo))) {
                if (pNeighTbl[i].netInfo.awnd_level < pBestNeigh->netInfo.awnd_level)
                    pBestNeigh = &pNeighTbl[i];
                else if (pNeighTbl[i].netInfo.awnd_level == pBestNeigh->netInfo.awnd_level)
                {
                     if (pNeighTbl[i].uplink_mask > pBestNeigh->uplink_mask)
                         pBestNeigh = &pNeighTbl[i];
                     else if (pNeighTbl[i].uplink_mask == pBestNeigh->uplink_mask)
                     {
                        if (((pNeighTbl[i].uplink_mask & AWND_BACKHAUL_WIFI) && pNeighTbl[i].uplink_rate > pBestNeigh->uplink_rate)
                            || ((!(pNeighTbl[i].uplink_mask & AWND_BACKHAUL_WIFI) ||  pNeighTbl[i].uplink_rate == pBestNeigh->uplink_rate)
                                && _mac_compare(pNeighTbl[i].lan_mac, pBestNeigh->lan_mac) > 0))
                        {
                            pBestNeigh = &pNeighTbl[i];
                        }
                    }
                }
            }
            else
            {
                if ((memcmp(g_awnd.fapMac, pBestNeigh->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
                {
                    continue;
                }
                if ((memcmp(g_awnd.fapMac, pNeighTbl[i].netInfo.awnd_mac, AWND_MAC_LEN) == 0))
                {   /* to find binded FAP entry first */
                    pBestNeigh = &pNeighTbl[i];
                }
                else if (HIGH_PRIO_SUBNET(&(pNeighTbl[i].netInfo), &(pBestNeigh->netInfo)))
                {
                    pBestNeigh = &pNeighTbl[i];
                }
            }
        }
        else
        {
            AWN_LOG_INFO("not to handler neigbor that: awnd_level(%d) = mine(%d) && awnd_mac is the same )\n",
                 pNeighTbl[i].netInfo.awnd_level, ethNetInfo->awnd_level);
        }

        if (0 == pNeighTbl[i].forward_num){
            if (!pRootAPNeigh)
                pRootAPNeigh = &pNeighTbl[i];
            else if (IN_SAME_SUBNET(&(pNeighTbl[i].netInfo), &(pRootAPNeigh->netInfo))) {
                if (pNeighTbl[i].netInfo.awnd_level < pRootAPNeigh->netInfo.awnd_level){
                    pRootAPNeigh = &pNeighTbl[i];
                }
                else if (pNeighTbl[i].netInfo.awnd_level == pRootAPNeigh->netInfo.awnd_level)
                {
                    if (pNeighTbl[i].uplink_mask > pRootAPNeigh->uplink_mask) {
                        pRootAPNeigh = &pNeighTbl[i];
                    }
                    else if (pNeighTbl[i].uplink_mask == pRootAPNeigh->uplink_mask)
                    {
                        if (((pNeighTbl[i].uplink_mask & AWND_BACKHAUL_WIFI) && pNeighTbl[i].uplink_rate > pRootAPNeigh->uplink_rate)
                            || ((!(pNeighTbl[i].uplink_mask & AWND_BACKHAUL_WIFI) ||  pNeighTbl[i].uplink_rate == pRootAPNeigh->uplink_rate)
                                && _mac_compare(pNeighTbl[i].lan_mac, pRootAPNeigh->lan_mac) > 0))
                        {
                            pRootAPNeigh = &pNeighTbl[i];
                        }
                    }
                }
            }else{
                if ((memcmp(g_awnd.fapMac, pRootAPNeigh->netInfo.awnd_mac, AWND_MAC_LEN) == 0))
                {
                    continue;
                }
                if ((memcmp(g_awnd.fapMac, pNeighTbl[i].netInfo.awnd_mac, AWND_MAC_LEN) == 0))
                {
                    pRootAPNeigh = &pNeighTbl[i];
                }
                else if (HIGH_PRIO_SUBNET(&(pNeighTbl[i].netInfo), &(pRootAPNeigh->netInfo)))
                {
                    pRootAPNeigh = &pNeighTbl[i];
                }
            }
        }
    }

    if (AWND_SYSMODE_ROUTER == g_awnd.sysMode || AWND_SYSMODE_AP == g_awnd.sysMode)
    {
        lastEthHasNeigh = g_awnd.ethHasNeigh;
        for (ethNum = 0; ethNum < l_awnd_config.ethIfCnt; ethNum++)
        {
            if (isEthNeighExist[ethNum] != g_awnd.ethNeighExist[ethNum])
            {
            	if(1 == isEthNeighExist[ethNum])
            	{
            		g_awnd.ethHasNeigh |= ETH_HASNEIGH_FLAG[ethNum];
            	}
				else
				{
					g_awnd.ethHasNeigh &= (~ETH_HASNEIGH_FLAG[ethNum]);
				}
                g_awnd.ethNeighExist[ethNum] = isEthNeighExist[ethNum];
                awnd_config_set_eth_neigh_interface(g_awnd.ethHasNeigh);

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                awnd_notify_apsd_eth_bhl_change(l_awnd_config.ethIfnames[ethNum], isEthNeighExist[ethNum]);
#endif
            }
        }
#if 0
        // 2024.04.03 
        // 合入edma loopback功能后，无需关闭cpu口的tx pause 
        // edma的commit id：e02dd5ecbf6b7b5cec9fabf536975fa3c5b62a59

        // 对于be65v2，对有线组网口的cpu port做disable txfc处理，规避txpause问题
        // 对于非有线组网口的cpu口，txfc默认开启
        if(lastEthHasNeigh != g_awnd.ethHasNeigh)
            awnd_set_ethbkhl_cpuport_disble_txfc(g_awnd.ethHasNeigh);
#endif
    }

	if (AWND_MODE_FAP == g_awnd.workMode)
        return 0;

    if (AWND_MODE_HAP == g_awnd.workMode)
    {

        if (pBestNeigh && ! IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo) &&
            AWND_NET_FAP == pBestNeigh->netInfo.awnd_net_type)
        {
            hapChangeToRE = 1;
        }
        else if (pBestNeigh && ! IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo)
                && HIGH_PRIO_SUBNET(&(pBestNeigh->netInfo), ethNetInfo))
        {

            /* AP mode: HAP changed to RE when Neigh is not FAP but has high prio */
            AWN_LOG_INFO("==== AP mode: HAP changed to RE when Neigh is not FAP but has high prio\n");

            hapChangeToRE = 1;
        }

        if (hapChangeToRE)
        {
            AWN_LOG_INFO("======= hap to re(eth).\n");
            AWN_LOG_NOTICE("Activaing Ethernet backhaul in %s.", pBestNeigh->dev_name);
            awnd_eth_set_backhaul(1, pBestNeigh->dev_name);
            awnd_plc_disconnect();			

            if (AWND_NET_FAP == pBestNeigh->netInfo.awnd_net_type)
                g_awnd.reStage = AWND_RE_STAGE_SECOND;
            else
                g_awnd.reStage = AWND_RE_STAGE_THIRD;

            awnd_mode_convert(AWND_MODE_HAP, AWND_MODE_RE);
            return 0;
        }
    }
    else if (AWND_MODE_RE == g_awnd.workMode)
    {
        /* AP mode: RE should handler if neighbor is HAP 
            by DengZhong 2017-08-31 */
        //if (pBestNeigh && AWND_NET_FAP == pBestNeigh->netInfo.awnd_net_type)
        if (pBestNeigh)
        {
             if(( ! IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo)
                      && HIGH_PRIO_SUBNET(&(pBestNeigh->netInfo), ethNetInfo))
               ||  (IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo)
                      && (pBestNeigh->netInfo.awnd_level < ethNetInfo->awnd_level)))
            {
                fapExistInEth = 1;              
            }

            if (IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo)
                && pBestNeigh->netInfo.awnd_level == ethNetInfo->awnd_level)
            {
                 if (pBestNeigh->uplink_mask > g_awnd.uplinkMask)
                     fapExistInEth = 1;
                 else if (pBestNeigh->uplink_mask == g_awnd.uplinkMask) 
                 {
                    if (((g_awnd.uplinkMask & AWND_BACKHAUL_WIFI) && pBestNeigh->uplink_rate > g_awnd.uplinkRate)
                        || ((!(g_awnd.uplinkMask & AWND_BACKHAUL_WIFI) ||  pBestNeigh->uplink_rate == g_awnd.uplinkRate)
                             && _mac_compare(pBestNeigh->lan_mac, l_awnd_config.mac) > 0))
                    {
                        fapExistInEth = 1;
                    }
                 }
            }

            if(fapExistInEth && IN_SAME_SUBNET(&(pBestNeigh->netInfo), ethNetInfo)
                && AWND_RE_STAGE_THIRD == g_awnd.reStage
                && AWND_NET_HAP == ethNetInfo->awnd_net_type)
            {
                /* compare my server detect status with rootap */
                if (pBestNeigh->netInfo.server_detected && g_awnd.server_detected)
                {
                    if (pBestNeigh->netInfo.server_touch_time < g_awnd.server_touch_time)
                        betterServerDetect = 1;
                }
                else if (g_awnd.server_detected)
                    betterServerDetect = 1;

                if (betterServerDetect)
                {
                    AWN_LOG_INFO("my server detected is better than conenncted rootap");
                    fapExistInEth = 0;
                }
            }

        }
        /*************************************************************************
            AP mode: RE connect with AP through eth
                when AP down and up eth
                    RE will remove neigbor and then add neigbor is about 2s-5s
                so neigbor disapper after 10s. convert RE --> HAP
            by Dengzhong 2017-09-08
        ************************************************************************/

        if (! fapExistInEth)
        {
            if (AWND_STATUS_CONNECTED == g_awnd.ethStatus && !betterServerDetect)
            {
                g_awnd.ethLinkTry++;
                if (g_awnd.ethLinkTry >= 5)
                {
                    awnd_eth_set_backhaul(fapExistInEth, NULL);
                    awnd_config_set_re_gwmode(0);
                    AWN_LOG_NOTICE("Ethernet backhaul link down.");
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                    awnd_write_work_mode(g_awnd.workMode, 0, NULL, 0, 0, NULL);
#endif
                    awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
                    memset(preEthNeighIf, 0, sizeof(preEthNeighIf));
                    return 0;
                }
            }
            else if (AWND_STATUS_CONNECTING == g_awnd.ethStatus && !betterServerDetect)
            {
                g_awnd.ethLinkTry++;
                if (g_awnd.ethLinkTry >= 5)
                {
                    awnd_eth_set_backhaul(fapExistInEth, NULL);
                    awnd_config_set_re_gwmode(0);
                    AWN_LOG_NOTICE("Ethernet backhaul link down.");					

                    awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
                    memset(preEthNeighIf, 0, sizeof(preEthNeighIf));
                    return 0;
                }                
            }
            else
            {   /* no FAP or high prio HAP/RE */
                if (AWND_RE_STAGE_THIRD == g_awnd.reStage)
                {
                    AWN_LOG_INFO("=====eth inspect==== RE: THIRD --> FOUTH\n");
                    l_awnd_scan_table.scan_fast = 0;
                    //awnd_eth_set_backhaul(fapExistInEth, NULL);
                    g_awnd.ethToHap = 1;
                }
            }
                
        }
        else
        {      
            /* inspect which eth port link to AP */
            for (ethNum = 0; ethNum < l_awnd_config.ethIfCnt; ethNum++)
            {
                if (0 == strncmp(l_awnd_config.ethIfnames[ethNum], pBestNeigh->dev_name, IFNAMSIZ))
                {
                    g_awnd.ethLinktoAP[ethNum] = 1;
                    if (oldEthNumLinktoAP != ethNum && AWND_STATUS_CONNECTED == g_awnd.ethStatus)
                    {
                        AWN_LOG_WARNING("ethLinktoAP has changed to %s",  pBestNeigh->dev_name);
                        awnd_eth_set_backhaul(1, pBestNeigh->dev_name);
                    }
                }
            }

/*fix bug 821917 RE从HAP切换为RE过程中，会修改g_awnd.ethStatus状态为AWND_STATUS_CONNECTING，导致不能正确进入以下逻辑，现将该代码移动到AWND_STATUS_DISCONNECT判断之外*/
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            if (awnd_config_get_eth_wlan_enable())
            {
                if ((pRootAPNeigh && !pRootAPNeigh->link_speed) || (NULL == pRootAPNeigh && !pBestNeigh->link_speed)) {
                    AWN_LOG_DEBUG("set g_awnd.eth_wifi_coexist = 0");
                    g_awnd.eth_wifi_coexist = 0;
                } else {
                    AWN_LOG_DEBUG("set g_awnd.eth_wifi_coexist = 1");
                    g_awnd.eth_wifi_coexist = 1;
                }
            } else {
                AWN_LOG_DEBUG("eth_wlan not enable, set g_awnd.eth_wifi_coexist = 0");
                g_awnd.eth_wifi_coexist = 0;
            }
#endif

            if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus)
            {
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                if (_is_in_connected_state(g_awnd.connStatus) && pRootAPNeigh)
                {
                    AWN_LOG_DEBUG("eth_wifi_coexist:%d, pRootAPNeigh: net_type:%d, awnd_level:%d,uplink_mask(%d),uplink_rate(%d),lan_mac(%02X:%02X:%02X:%02X:%02X:%02X)", 
                        g_awnd.eth_wifi_coexist, pRootAPNeigh->netInfo.awnd_net_type, pRootAPNeigh->netInfo.awnd_level, pRootAPNeigh->uplink_mask, pRootAPNeigh->uplink_rate,
                        pRootAPNeigh->lan_mac[0], pRootAPNeigh->lan_mac[1], pRootAPNeigh->lan_mac[2],
                        pRootAPNeigh->lan_mac[3], pRootAPNeigh->lan_mac[4],pRootAPNeigh->lan_mac[5]);

                    AWN_LOG_DEBUG("g_awnd: net_type:%d, awnd_level:%d,uplink_mask(%d),uplink_rate(%d),lan_mac(%02X:%02X:%02X:%02X:%02X:%02X)", 
                        g_awnd.netInfo.awnd_net_type, g_awnd.netInfo.awnd_level, g_awnd.uplinkMask, g_awnd.uplinkRate,
                        l_awnd_config.mac[0], l_awnd_config.mac[1], l_awnd_config.mac[2],
                        l_awnd_config.mac[3], l_awnd_config.mac[4], l_awnd_config.mac[5]);

                    if (0 == is_better_neigh(pBestNeigh))
                    {
                        AWN_LOG_DEBUG("neigh is not better than me, do nothing.");
                        return 0;
                    }

                }
#endif //CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                AWN_LOG_INFO("========= RE: change to eth conenction\n");
                AWN_LOG_NOTICE("Activaing Ethernet backhaul in %s, disconnect other backhuals.", pBestNeigh->dev_name);
                strncpy(preEthNeighIf, pBestNeigh->dev_name, sizeof(preEthNeighIf));
                awnd_eth_set_backhaul(1, pBestNeigh->dev_name);
                awnd_plc_disconnect();
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                if (0 == g_awnd.eth_wifi_coexist) {
                    AWN_LOG_NOTICE("Activaing Ethernet backhaul in %s, disconnect other backhuals.", pBestNeigh->dev_name);
                    awnd_disconn_all_sta();
                    awnd_config_set_all_stacfg_enb(0);
                } else {
                    if (pRootAPNeigh) {
                        max_rate_backhaul_eth = pRootAPNeigh->link_speed;
                        if (memcmp(g_awnd.rootAp[AWND_BAND_2G].lan_mac, pRootAPNeigh->lan_mac, AWND_MAC_LEN)) {
                            /* eth & wifi rootap is not the same one, reconnet wifi backhual*/
                            AWN_LOG_WARNING("Activaing Ethernet backhaul in %s, eth & wifi rootap is not the same one, disconnect other backhual.", pBestNeigh->dev_name);
                            awnd_disconn_all_sta();
                            awnd_config_set_all_stacfg_enb(0);
                        } else {
                            AWN_LOG_WARNING("Activaing Ethernet backhaul in wire & wireless,max_rate_backhaul_eth:%d dont disconnet other backhual", max_rate_backhaul_eth);
                        }
                    }
                }
#else
                AWN_LOG_NOTICE("Activaing Ethernet backhaul in %s, disconnect other backhuals.", pBestNeigh->dev_name);
                awnd_disconn_all_sta();
                awnd_config_set_all_stacfg_enb(0);
#endif
#if SCAN_OPTIMIZATION
                awnd_memset_scan_table();
#endif
                awnd_config_set_re_gwmode(1);
                awnd_wifi_restart();
                awnd_mode_convert(AWND_MODE_RE, AWND_MODE_RE);
                return 0;            
            }
            else if (AWND_STATUS_CONNECTING == g_awnd.ethStatus)
            {
                g_awnd.ethLinkTry = 0;
                if (NEIGH_IN_LAN == pBestNeigh->nh_dir)
                {
                    g_awnd.ethStatus = AWND_STATUS_CONNECTED;
                    strncpy(preEthNeighIf, pBestNeigh->dev_name, sizeof(preEthNeighIf));
                    awnd_write_rt_info(AWND_INTERFACE_ETH, true, NULL, false);
                    linkStateChanged = 1;
                    AWN_LOG_NOTICE("Ethernet backhaul is active now.");
                }
            }
            else if(AWND_STATUS_CONNECTED == g_awnd.ethStatus)
            {
                /*eth-connected, keep inspect if eth backhaul port switch to the other*/
                g_awnd.ethLinkTry = 0;
                if (NEIGH_IN_LAN == pBestNeigh->nh_dir && strcmp(preEthNeighIf, pBestNeigh->dev_name))
                {
                    g_awnd.ethStatus = AWND_STATUS_CONNECTED;
                    strncpy(preEthNeighIf, pBestNeigh->dev_name, sizeof(preEthNeighIf));
                    awnd_write_rt_info(AWND_INTERFACE_ETH, true, NULL, false);
                    linkStateChanged = 1;
                    AWN_LOG_NOTICE("Ethernet backhaul is active now.");
                }
            }
            else
            {
                g_awnd.ethLinkTry = 0;
            }
        }
        

        if (fapExistInEth)
        {

            /*************************************************************************
                To fix bug: RE connect with AP  both eth and wifi
                by Dengzhong 2017-09-24
            ************************************************************************/
             /* get link state */
            for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
            {
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#if GET_AP_RSSI
                BOOL tmp[AWND_BAND_MAX_NUM];
                wireless_link[band] = awnd_get_wds_state(band, &wireless_iff_up[band], &g_awnd.rootApRtRssi[band], tmp); 
#else
                BOOL tmp[AWND_BAND_MAX_NUM];
                wireless_link[band] = awnd_get_wds_state(band, &wireless_iff_up[band], tmp);
#endif  /* GET_AP_RSSI */
#else
#if GET_AP_RSSI
                wireless_link[band] = awnd_get_wds_state(band, &wireless_iff_up[band], &g_awnd.rootApRtRssi[band]);
#else
                wireless_link[band] = awnd_get_wds_state(band, &wireless_iff_up[band]);
#endif
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
                if (wireless_link[band])
                {
                    AWN_LOG_INFO("============== %s wireless_link:%d ====", real_band_suffix[_get_real_band_type(band)], wireless_link[band]);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                    if ((pRootAPNeigh && !pRootAPNeigh->link_speed) || (NULL == pRootAPNeigh && !pBestNeigh->link_speed)) {
                        AWN_LOG_WARNING("Eth backhaul and WIFI backhaul should not coexist, disconnect WIFI backhaul.");
                        awnd_disconn_all_sta();
                        awnd_config_set_all_stacfg_enb(0);
                    } else {
                        if (pRootAPNeigh) {
                            max_rate_backhaul_eth = pRootAPNeigh->link_speed;
                        }
                        AWN_LOG_DEBUG("Activaing Ethernet backhaul in wire & wireless, dont disconnet other backhual.");
                    }
#else
					AWN_LOG_WARNING("Eth backhaul and WIFI backhaul should not coexist, disconnect WIFI backhaul.");
                    awnd_disconn_all_sta();
                    awnd_config_set_all_stacfg_enb(0);
#endif
                    break;
                }
            }

            if (pRootAPNeigh && (AWND_STATUS_CONNECTED == g_awnd.ethStatus) && (_is_in_disconnected_state(g_awnd.connStatus)))
                memcpy(ethParentMac, pRootAPNeigh->lan_mac, AWND_MAC_LEN);
            else
                memcpy(ethParentMac, pBestNeigh->lan_mac, AWND_MAC_LEN);

            memcpy(&tmpNetInfo, &pBestNeigh->netInfo, sizeof(AWND_NET_INFO));
            if (pRootAPNeigh){
                tmpNetInfo.awnd_level = pRootAPNeigh->netInfo.awnd_level + 1;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                if (memcmp(g_awnd.ethRootApMac, pRootAPNeigh->lan_mac, AWND_MAC_LEN))
                {
                    memcpy(g_awnd.ethRootApMac, pRootAPNeigh->lan_mac, AWND_MAC_LEN);
                    ethRootApMacChanged = 1;
                    AWN_LOG_INFO("catch pRootAPNeigh lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, awnd_mac:%02X:%02X:%02X:%02X:%02X:%02X, forward_num:%d, awnd_level:%d, g_awnd.uplinkMask:%d", 
                        g_awnd.ethRootApMac[0], g_awnd.ethRootApMac[1], g_awnd.ethRootApMac[2],
                        g_awnd.ethRootApMac[3], g_awnd.ethRootApMac[4], g_awnd.ethRootApMac[5],
                        pRootAPNeigh->netInfo.awnd_mac[0], pRootAPNeigh->netInfo.awnd_mac[1], pRootAPNeigh->netInfo.awnd_mac[2],
                        pRootAPNeigh->netInfo.awnd_mac[3], pRootAPNeigh->netInfo.awnd_mac[4], pRootAPNeigh->netInfo.awnd_mac[5],
                        pRootAPNeigh->forward_num, pRootAPNeigh->netInfo.awnd_level, g_awnd.uplinkMask);
                }
#endif /* CONFIG_ETH_WLAN_BACKHAUL_SUPPORT */
            }else{
                tmpNetInfo.awnd_level = pBestNeigh->netInfo.awnd_level + pBestNeigh->forward_num + 1;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                if (memcmp(g_awnd.ethRootApMac, pBestNeigh->lan_mac, AWND_MAC_LEN))
                {
                    memcpy(g_awnd.ethRootApMac, pBestNeigh->lan_mac, AWND_MAC_LEN);
                    ethRootApMacChanged = 1;
                }
#endif
            }

            if (memcmp(ethNetInfo, &tmpNetInfo, sizeof(AWND_NET_INFO)) || linkStateChanged
                || (g_awnd.ethStatus == AWND_STATUS_CONNECTED && _is_in_disconnected_state(g_awnd.connStatus) && memcmp(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO))))
            {
                if (_is_in_disconnected_state(g_awnd.connStatus))
                {
                    memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
                }
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                memcpy(&g_awnd.ethNetInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
                //if (_is_in_disconnected_state(g_awnd.connStatus)){
                //    memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
                //}
                awnd_update_tpie(&tmpNetInfo, AWND_NETINFO_ETH);
                awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, g_awnd.ethRootApMac);
#else
                UINT8 mac_zero[AWND_MAC_LEN] = {};
                awnd_update_tpie(&tmpNetInfo);
        
                if (memcmp(pBestNeigh->forwarder, mac_zero, AWND_MAC_LEN) != 0)
                    awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, pBestNeigh->forwarder);
                else if (pRootAPNeigh && (AWND_STATUS_CONNECTED == g_awnd.ethStatus) && (_is_in_disconnected_state(g_awnd.connStatus)))
                    awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, pRootAPNeigh->lan_mac);
                else
                    awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, pBestNeigh->lan_mac);
#endif

                if (memcmp(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN) && _is_vaild_mac(g_awnd.capMac))
                {
                     hotplugCfg.srcMode = AWND_MODE_RE;
                     hotplugCfg.dstMode = AWND_MODE_RE;
                     hotplugCfg.type = AWND_HOTPLUG_CAP_CHANGE;
                     awnd_mode_call_hotplug(&hotplugCfg);
                     capMacChanged = 1;
                }
                memcpy(g_awnd.capMac, tmpNetInfo.awnd_mac, AWND_MAC_LEN);

                if ((AWND_NET_LRE != tmpNetInfo.awnd_net_type) && (AWND_NET_MAX != g_awnd.capNetType))
                {
                     hotplugCfg.srcMode = AWND_MODE_RE;
                     hotplugCfg.dstMode = AWND_MODE_RE;
                     hotplugCfg.type = AWND_HOTPLUG_CAP_TYPE_CHANGE;
                    
                    if (tmpNetInfo.awnd_net_type != g_awnd.capNetType)
                    {   /* to call hotplug when cap net_type change from vaild_type to vaild_type */
                        if (AWND_NET_FAP == tmpNetInfo.awnd_net_type)
                        {
                            hotplugCfg.capSrcType = AWND_NET_HAP;
                            hotplugCfg.capDstType = AWND_NET_FAP;
                        }
                        else if (AWND_NET_HAP == tmpNetInfo.awnd_net_type)
                        {
                            hotplugCfg.capSrcType = AWND_NET_FAP;
                            hotplugCfg.capDstType = AWND_NET_HAP;
                        }
                        awnd_mode_call_hotplug(&hotplugCfg);
                    }
                    else if (capMacChanged)
                    {   /* to call hotplug when cap net_type is not changed but cap mac is changed */
                        hotplugCfg.capSrcType   =   tmpNetInfo.awnd_net_type;
                        hotplugCfg.capDstType   =   tmpNetInfo.awnd_net_type;
                        awnd_mode_call_hotplug(&hotplugCfg);
                    }
                }
                if(AWND_NET_LRE != tmpNetInfo.awnd_net_type)
                {   /* not to update net type when rootap's net type is LRE */
                    g_awnd.capNetType = tmpNetInfo.awnd_net_type;
                }

                if ((g_awnd.capLanip != tmpNetInfo.awnd_lanip) && (0 != g_awnd.capLanip)
                    && (0 != tmpNetInfo.awnd_lanip))
                {   /* only to call hotplug when cap lanip change from vaild ip to vaild ip */
                     hotplugCfg.srcMode = AWND_MODE_RE;
                     hotplugCfg.dstMode = AWND_MODE_RE;
                     hotplugCfg.type = AWND_HOTPLUG_CAP_IP_CHANGE;
                     awnd_mode_call_hotplug(&hotplugCfg);
                }
                if (0 != tmpNetInfo.awnd_lanip)
                {
                    g_awnd.capLanip = tmpNetInfo.awnd_lanip;
                }

                if ((g_awnd.capDns != tmpNetInfo.awnd_dns) && (0 != g_awnd.capDns)
                    && (0 != tmpNetInfo.awnd_dns))
                {   /* only to call hotplug when cap dns change from vaild ip to vaild ip */
                     hotplugCfg.srcMode = AWND_MODE_RE;
                     hotplugCfg.dstMode = AWND_MODE_RE;
                     hotplugCfg.type = AWND_HOTPLUG_CAP_DNS_CHANGE;
                     awnd_mode_call_hotplug(&hotplugCfg);
                }
                if (0 != tmpNetInfo.awnd_dns)
                {
                    g_awnd.capDns = tmpNetInfo.awnd_dns;
                }

#ifndef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
                memcpy(&g_awnd.netInfo, &tmpNetInfo, sizeof(AWND_NET_INFO));
#endif
            }
            else if (_mac_compare(ethParentMac, g_awnd.ethRootApMac) != 0)
            {
                awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, ethParentMac);
            }

            memcpy(g_awnd.ethRootApMac, ethParentMac, AWND_MAC_LEN);

            if (ethRootApMacChanged)
                awnd_write_work_mode(g_awnd.workMode, 1, tmpNetInfo.awnd_mac, tmpNetInfo.awnd_net_type, tmpNetInfo.awnd_level, g_awnd.ethRootApMac);
        }
    }

    
    return 0;
}

#if 0
void awnd_set_ethbkhl_cpuport_disble_txfc(int eth_neigh)
{
    char cmd[128] = {0};
    int index = 0;
    int j = 0;
    int eth_port[MAX_ETH_DEV_NUM] = {0};
    int cpu_port = -1;
    int disable_cpu_port_list[MAX_ETH_DEV_NUM] = {-1};
    int cpu_port_list[MAX_ETH_DEV_NUM] = {-1};
    int need_set = 0;
    char line[8] = {0};
    FILE *fp = NULL;

    for(index = 0; index < MAX_ETH_DEV_NUM; index++) {
        disable_cpu_port_list[index] = -1;
        cpu_port_list[index] = -1;
    }
    uci_get_profile_port_id(eth_port, MAX_ETH_DEV_NUM);
    for(index = 0, j = 0; index < l_awnd_config.ethIfCnt && j < MAX_ETH_DEV_NUM; index++) {
        cpu_port = uci_get_cpuport_by_port(eth_port[index]);

    }
    for(index = 0; index < l_awnd_config.ethIfCnt; index++) {
        cpu_port = uci_get_cpuport_by_port(eth_port[index]);
        if (cpu_port == -1)
        {
            AWN_LOG_ERR("get cpu port error");
            return;
        }
        else
        {
            if(eth_neigh & (1 << index))
            {
                need_set = 0;
                for (j = 0; j < l_awnd_config.ethIfCnt; j++)
                {
                    if(cpu_port == disable_cpu_port_list[j])
                    {
                        break;
                    }
                    else if(-1 == disable_cpu_port_list[j])
                    {
                        need_set = 1;
                        break;
                    }
                }

                if(need_set)
                {
                    disable_cpu_port_list[j] = cpu_port;
                    snprintf(cmd, 128, "ssdk_sh port txfcstatus set %d disable", cpu_port);
                    system(cmd);
                    AWN_LOG_NOTICE("disable cpu_port:%d txfc", cpu_port);
                }


            }
            need_set = 0;
            for (j = 0; j < l_awnd_config.ethIfCnt; j++)
            {
                if(cpu_port == cpu_port_list[j])
                {
                    break;
                }
                else if(-1 == cpu_port_list[j])
                {
                    need_set = 1;
                    break;
                }
            }
            if(need_set)
                cpu_port_list[j] = cpu_port;
        }
    }

    for(index = 0; index < l_awnd_config.ethIfCnt; index ++)
    {
        if(cpu_port_list[index] != -1)
        {
            need_set = 1;
            for (j = 0; j < l_awnd_config.ethIfCnt; j++)
            {
                if(cpu_port_list[index] == disable_cpu_port_list[j])
                {
                    need_set = 0;
                }
            }

            if(need_set)
            {
                snprintf(cmd, 128, "ssdk_sh port txfcstatus set %d enable", cpu_port_list[index]);
                system(cmd);
                AWN_LOG_NOTICE("enable cpu_port:%d txfc",cpu_port_list[index]);
            }
        }
    }

    return ;
}
#endif

void awnd_eth_inspect(struct uloop_timeout *t)
{
    if (AWND_BIND_START == g_awnd.bindStatus)
    {
        awn_eth_get_neigh_tbl(l_awnd_eth_neigh_table.ethNeigh, l_group_info.backhualGroupInfo.label, NULL);
    }
    else
    {
        if(g_awnd.notBind && AWND_MODE_RE == g_awnd.workMode && g_awnd.reStage <= AWND_RE_STAGE_SECOND && ! _is_null_group_info( &(l_group_info.preconfGroupInfo) ) )
        {
            awn_eth_get_neigh_tbl(l_awnd_eth_neigh_table.ethNeigh, l_group_info.staGroupInfo.label, l_group_info.preconfGroupInfo.label);
        }
        else
        {
            awn_eth_get_neigh_tbl(l_awnd_eth_neigh_table.ethNeigh, l_group_info.staGroupInfo.label, NULL);
        }
    }
 
    awnd_eth_handle_neigh();
    uloop_timeout_set(&eth_neigh_inspect_timer,  l_awnd_config.tm_eth_inspect_interval); 
}

void awnd_clear_backhaul_smaples()
{
    AWND_BAND_TYPE band;

    samplesCount = 0;
    _updateSample(plcRateSamples[0], PLC_SAMPLE_MAX_NUM, 0, TRUE);
    _updateSample(plcRateSamples[1], PLC_SAMPLE_MAX_NUM, 0, TRUE);
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        _updateSample(wifiRateSamples[band][0], WIFI_SAMPLE_MAX_NUM, 0, TRUE);
        _updateSample(wifiRateSamples[band][1], WIFI_SAMPLE_MAX_NUM, 0, TRUE);
    }        
}

void awnd_backhaul_review(struct uloop_timeout *t)
{
    AWND_BAND_TYPE band;
    UINT16 txRate, rxRate, mediumRate, tmpRate;
    UINT16 PLCRate = 0, WIFIRate[AWND_BAND_MAX] = {0};
    UINT8 ifname[AWND_BAND_MAX][IFNAMSIZ + 1] = {{0},{0}};
    int stalled[AWND_BAND_MAX] = {0};
    int i;
#if CONFIG_5G_HT160_SUPPORT
    AWND_WIFI_BW_TYPE wifi_bw = 0;
#endif /* CONFIG_5G_HT160_SUPPORT */

#ifndef WIFI_COEXIST_WITH_PLC
    if (AWND_STATUS_CONNECTED == g_awnd.plcStatus && AWND_OK == awn_plc_get_capacity(l_awnd_config.plcMac, 
                                            g_awnd.plcPeerNeigh.plc_mac, &txRate, &rxRate))
    { 
        if ((mediumRate = _updateSample(plcRateSamples[0], PLC_SAMPLE_MAX_NUM, rxRate, FALSE)) != 0)
        {
            g_awnd.plcPeerNeigh.rxRate= mediumRate;
        }
        if ((mediumRate = _updateSample(plcRateSamples[1], PLC_SAMPLE_MAX_NUM, txRate, FALSE)) != 0)
        {
            g_awnd.plcPeerNeigh.txRate= mediumRate;
        }

        PLCRate = (g_awnd.plcPeerNeigh.txRate < 100) ? g_awnd.plcPeerNeigh.txRate : 100; 
        AWN_LOG_DEBUG("Peer PLC tx rate:%d, rx rate:%d, mediumRate:%d, record txRate:%d, PLCRate:%d.\n", 
            txRate, rxRate, mediumRate, g_awnd.plcPeerNeigh.txRate, PLCRate);

    }
    else 
    {
        _updateSample(plcRateSamples[0], PLC_SAMPLE_MAX_NUM, rxRate, TRUE);
        _updateSample(plcRateSamples[1], PLC_SAMPLE_MAX_NUM, txRate, TRUE);
        
    }
#endif

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
#ifndef WIFI_COEXIST_WITH_PLC
        if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band] && AWND_OK == awnd_get_rootap_phyRate(band, &txRate, &rxRate))
        {
            if ((mediumRate = _updateSample(wifiRateSamples[band][0], WIFI_SAMPLE_MAX_NUM, rxRate, FALSE)) != 0)
            {
                g_awnd.rootAp[band].rxRate= mediumRate;
            }
            if ((mediumRate = _updateSample(wifiRateSamples[band][1], WIFI_SAMPLE_MAX_NUM, txRate, FALSE)) != 0)
            {
                g_awnd.rootAp[band].txRate= mediumRate;
            }          

            WIFIRate[band] = g_awnd.rootAp[band].txRate; 
            AWN_LOG_DEBUG("Band %s tx rate:%d, rx rate:%d, mediumRate:%d, record txRate:%d.\n", real_band_suffix[_get_real_band_type(band)],
                txRate, rxRate, mediumRate, g_awnd.rootAp[band].txRate);
        }
        else
        {
            _updateSample(wifiRateSamples[band][0], WIFI_SAMPLE_MAX_NUM, rxRate, TRUE);
            _updateSample(wifiRateSamples[band][1], WIFI_SAMPLE_MAX_NUM, txRate, TRUE);
        }
#endif

#if CONFIG_RX_PACKETS_CHECK
        if (AWND_STATUS_CONNECTED == g_awnd.connStatus[band]) 
        {
            awnd_get_sta_iface_in_bridge(band, ifname[band]);
            if (0 == _get_data_sum(ifname[band], &(packetQueue[band][packetTrackIdx[band]]))) 
            {

                AWN_LOG_DEBUG("Band %s STA RX packets[%d]:%llu.\n", real_band_suffix[_get_real_band_type(band)],
                    packetTrackIdx[band], packetQueue[band][packetTrackIdx[band]]); 

                packetTrackIdx[band]++;
                if (packetTrackIdx[band] == PACKET_QUEUE_LEN) 
                {
                     packetTrackIdx[band] = 0;
                 
                     stalled[band] = 1;
                     for (i = 1; i < PACKET_QUEUE_LEN; i++) 
                     {
                          if (packetQueue[band][i-1] != packetQueue[band][i])
                          {
                              stalled[band] = 0;
                              break;
                          }
                          
                     }
                }
            }

        }
        else 
        {
            packetTrackIdx[band] = 0;
        }
#endif /* CONFIG_RX_PACKETS_CHECK */
    }

    if (_is_in_connected_state(g_awnd.connStatus)) {
         samplesCount++;
    }
    else {
         samplesCount = 0;
    }

#ifndef WIFI_COEXIST_WITH_PLC
    if (PLCRate && ((WIFIRate[AWND_BAND_2G] && WIFIRate[AWND_BAND_5G]) || 
                     (samplesCount > 40 && (WIFIRate[AWND_BAND_2G] || WIFIRate[AWND_BAND_5G]))))
    { 
        tmpRate = (WIFIRate[AWND_BAND_5G] > WIFIRate[AWND_BAND_2G]) ? (WIFIRate[AWND_BAND_5G] * 0.7) : (WIFIRate[AWND_BAND_2G] *0.7);
        if (tmpRate < PLCRate) {
            AWN_LOG_INFO("wifi is  2G %dMbps 5G %dMbps and PLC is  %dMbps.", WIFIRate[AWND_BAND_2G], WIFIRate[AWND_BAND_5G], PLCRate); 
			AWN_LOG_NOTICE("PLC is better than WIFI, disconnect WIFI.");
            awnd_disconn_sta(AWND_BAND_2G);
            awnd_disconn_sta(AWND_BAND_5G);
            g_awnd.plcWinWifi = 1;
        }
        else {
            AWN_LOG_INFO("wifi is  2G %dMbps 5G %dMbps and PLC is  %dMbps, disconnect PLC.", 
                             WIFIRate[AWND_BAND_2G], WIFIRate[AWND_BAND_5G], PLCRate);  
			AWN_LOG_NOTICE("WIFI is better than PLC, disconnect PLC.");			
            awnd_plc_disconnect();
            awnd_repacd_restart(AWND_MODE_RE, 1);
        }
    }
#endif
#if CONFIG_RX_PACKETS_CHECK
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
#if CONFIG_PLATFORM_BCM
        if ((l_awnd_config.band_num == AWND_BAND_NUM_3) && AWND_BAND_2G != band && stalled[band] &&
            ((AWND_BAND_3RD == band) || (AWND_BAND_5G == band && AWND_STATUS_DISCONNECT == g_awnd.connStatus[AWND_BAND_3RD])))
#else
        if (AWND_BAND_2G != band && stalled[band])
#endif
        {
#if CONFIG_TRI_BAND_SUPPORT || CONFIG_FOUR_BAND_SUPPORT
            if((AWND_BAND_5G != band) && (AWND_STATUS_DISCONNECT == g_awnd.connStatus[AWND_BAND_5G]))
#endif
            {
            AWN_LOG_ERR("Notice: !!!!!!!!!!!!!!! rx packets of %s didn't increase for %d seconds.", 
                        ifname[band], PACKET_QUEUE_LEN);            
            awnd_reset_sta_connection(band);          
        }
    }
    }
#endif /* CONFIG_RX_PACKETS_CHECK */

#if CONFIG_WIFI_DFS_SILENT
#if CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1
    if (ENABLE == g_awnd.ht160Enable && AWND_OK == awnd_get_wifi_bw(AWND_BAND_5G, &wifi_bw)) {
        if (WIFI_BW_160M == wifi_bw && WIFI_BW_160M != g_awnd.wifiBw[AWND_BAND_5G]) {
            AWN_LOG_INFO("wifi bw chaned form %d to %d",
                g_awnd.wifiBw[AWND_BAND_5G], WIFI_BW_160M);

            g_awnd.rootApChType = AWND_ROOTAP_CHANNEL_IS_DFS;
            g_awnd.SilentPeriod[AWND_BAND_5G] = SILENT_PERIOD_START;
            uloop_timeout_set(&wifi_silent_period_timer, AWND_DFS_SILENT_PERIOD);
        }
        else if (WIFI_BW_160M != wifi_bw && SILENT_PERIOD_START == g_awnd.SilentPeriod[AWND_BAND_5G]) {
            AWN_LOG_INFO("wifi bw chaned form %d to %d, to cancel SilentPeriod",
                g_awnd.wifiBw[AWND_BAND_5G], wifi_bw);
            g_awnd.SilentPeriod[AWND_BAND_5G] = SILENT_PERIOD_DONE;
        }
        g_awnd.wifiBw[AWND_BAND_5G] = wifi_bw;
    }
#endif /* CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1 */
#endif /* CONFIG_WIFI_DFS_SILENT */

    uloop_timeout_set(&backhaul_review_timer,  1000); 
}

void awnd_update_wifi_zwdfs_support()
{
    AWND_BAND_TYPE band;
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++)
    {
        g_awnd.zwdfs_support[band] = awnd_get_wifi_zwdfs_support(band);
    }
}

const int BIND_DEV_MAX = 20;
const int PRECONFIG_DEV_MAX = 20;
const int DEV_ID_LEN_MAX = 50;

/* 
* function:     awnd_cal_preconfig_dev_md5
* brief:        cal md5 for each DEV_ID
* discription:  input preconfig_dev_list
*               output preconfig_dev_md5_list
*/
BOOL awnd_cal_preconfig_dev_md5(char (*preconfig_dev_list)[DEV_ID_LEN_MAX], 
                                char (*preconfig_dev_md5_list)[DEV_ID_LEN_MAX])
{
#if 0
    const char* tmp_file_path = "/tmp/md5_tmp_preconfig";
    char* buf_popen[100] = {0};
    char* popen_cmd[100] = {0};

    int index = 0;
    while(*preconfig_dev_list[index] != 0 && index < PRECONFIG_DEV_MAX)
    {
        AWN_LOG_INFO("awnd_cal_preconfig_dev_md5 tmp_file:%s:",tmp_file_path);
        FILE* fp = NULL;
        if((fp = fopen(tmp_file_path, "w")) == NULL)
        {
            AWN_LOG_ERR("awnd_cal_preconfig_dev_md5 open file error");
            return false;
        }
        fprintf(fp, "%s\n", preconfig_dev_list[index]);
        fclose(fp);

        snprintf(popen_cmd, 50, "md5sum %s",tmp_file_path);
        AWN_LOG_INFO("popen_cmd:%s", popen_cmd);
        fp = popen(popen_cmd, "r");
        fgets(buf_popen, 9, fp);
        pclose(fp);
        AWN_LOG_INFO("buf_popen:%s", buf_popen);
        memcpy(preconfig_dev_md5_list[index], buf_popen, 9);
        index++;
    }
    return true;

#else
    int index = 0;
    while(index < PRECONFIG_DEV_MAX && *preconfig_dev_list[index] != 0)
    {
        /* add '\n' to the end of the string 
        *  uniform the format just like save this string in a file(echo xxx > /tmp/xxx)
        *  make shell cmd `md5sum [file]` happy(we use this shell cmd when restarting repacd)
        */
        preconfig_dev_list[index][strlen(preconfig_dev_list[index])] = '\n';
        AWN_LOG_INFO("preconfig_dev_list length:%d", strlen(preconfig_dev_list[index]));
        md5_make_digest(preconfig_dev_md5_list[index], preconfig_dev_list[index], strlen(preconfig_dev_list[index]));
        char temp[20] = {0};
        snprintf(temp, 8+1, "%02x%02x%02x%02x",preconfig_dev_md5_list[index][0],
                                            preconfig_dev_md5_list[index][1],
                                            preconfig_dev_md5_list[index][2],
                                            preconfig_dev_md5_list[index][3]);
        AWN_LOG_INFO("%d:%s", index, temp);
        index++;
    }
#endif
}

/* 
* function: awnd_wifi_driver_filter_update
* brief:    to wifi_driver_filter_update for ISP DCMP preconfig
            echo xxxxxxx > /proc/ath112(012)/preconfig_proc
*/
BOOL awnd_wifi_driver_filter_update(char (*preconfig_dev_list)[DEV_ID_LEN_MAX])
{
    AWN_LOG_INFO("awnd_wifi_driver_filter_update");
    const int DRIVE_BUF_SIZE = 102;
    char *ptr = NULL;
    int index = 0;
    char preconfig_dev_md5_list[PRECONFIG_DEV_MAX][DEV_ID_LEN_MAX];
    //const char* PATH_PROC_PRECONFIG = "/proc/ath16/preconfig_proc";

    //char cmd_line[200] = {0};
    /*Todo: do not use fixed port num*/
    const char* PATH_PROC_PRECONFIG = "/proc/ath112/preconfig_proc";
	char cmd_line[DRIVE_BUF_SIZE];

	memset(cmd_line, 0, DRIVE_BUF_SIZE);

    memset(preconfig_dev_md5_list, 0 , sizeof(preconfig_dev_md5_list));
    awnd_cal_preconfig_dev_md5(preconfig_dev_list, preconfig_dev_md5_list);
    ptr = cmd_line;

    /* total operation */
    *(ptr++) = '1';

    /* add each dev md5 */
    while(index < PRECONFIG_DEV_MAX && *preconfig_dev_md5_list[index] != 0)
    {
        /* sub operator */
        *(ptr++) = '1';

        /* preservation */
        *(ptr++) = '0';
        AWN_LOG_INFO("preconfig_dev_md5_list:%s\n", preconfig_dev_md5_list[index]);
        /* first 8 characters of each dev md5 */
        //snprintf(ptr, 8 + 1, preconfig_dev_md5_list[index]);
        snprintf(ptr, 8+1, "%02x%02x%02x%02x",preconfig_dev_md5_list[index][0],
                                            preconfig_dev_md5_list[index][1],
                                            preconfig_dev_md5_list[index][2],
                                            preconfig_dev_md5_list[index][3]);
                                            
        ptr += 8;
        index++;
    }
    /* the end */
    *(ptr++) = '#';

    if(isp_dcmp_preconfig.is_add_md5 == 1)
    {
        AWN_LOG_INFO("adding preconfig dev_list md5 to wifi driver");
        FILE *fp = fopen(PATH_PROC_PRECONFIG, "w");
        if(fp == NULL)
        {
            AWN_LOG_ERR("add preconfig dev_list md5 to wifi driver failed(proc file open error)");
            return false;
        }
        *(ptr++) = '\n';
        fprintf(fp, "%s", cmd_line);
        fclose(fp);
        AWN_LOG_INFO("update wifi driver preconfig filter:%s", cmd_line);
    }

    return true;
}

/* 
* function: awnd_preconfig_dev_check
* brief:    to check if all devices in preconfig_devlist have beed binded
            if preconfig_dev != bind_dev  =>  update wifi driver filter
*/

BOOL awnd_preconfig_dev_check()
{
    AWN_LOG_NOTICE("awnd_preconfig_dev_check");
    BOOL is_all_find = false;
    char *const PRECONFIG_DEVICE_LIST_PATH = "/etc/config/preconfig_device_list";

    if (access(PRECONFIG_DEVICE_LIST_PATH, 0) != 0)
    {
        is_all_find = true;
        return is_all_find;
    }

    char bind_dev_list[BIND_DEV_MAX][DEV_ID_LEN_MAX];
    char preconfig_dev_list[PRECONFIG_DEV_MAX][DEV_ID_LEN_MAX];
    struct uci_context *uciCtx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    struct uci_element *e = NULL;
    int ret = AWND_ERROR;
    char *const BIND_DEVICE_LIST = "bind_device_list";
    char *const PRECONFIG_DEVICE_LIST = "preconfig_device_list";
    char *const CONFIG_PATH = "/etc/config";
    char *const uci_sec_type = "device";
    //BOOL is_all_find = false;

    /* read /etc/config/bind_device_list into array bind_dev_list */
    uciCtx = uci_alloc_context();
    if (NULL == uciCtx)
    {
        AWN_LOG_ERR("Failed to alloc uci ctx");
        ret = AWND_ERROR;
        goto done;
    }
    uci_set_confdir(uciCtx, CONFIG_PATH);
    
    int index = 0;
    memset(bind_dev_list, 0, sizeof(preconfig_dev_list));

    if (UCI_OK != uci_load(uciCtx, BIND_DEVICE_LIST, &pkg))
    {
        AWN_LOG_ERR("uci_load %s error!", BIND_DEVICE_LIST);
        uci_perror(uciCtx, BIND_DEVICE_LIST);
        ret = AWND_ERROR;
    }
    else
    {
        uci_foreach_element(&pkg->sections, e)
        {
            s = uci_to_section(e);
            AWN_LOG_NOTICE("bind dev list:%s", s->e.name);
            if(index < BIND_DEV_MAX)
                snprintf(bind_dev_list[index], sizeof(bind_dev_list[index]), "%s", s->e.name);
            else
                AWN_LOG_WARNING("bind dev list num in /etc/config/bind_dev_list overstap the array boundary");
            index++;
        }
        uci_unload(uciCtx, pkg);
    }

    /* read /etc/config/preconfig_device_list into array preconfig_dev_list */
    index = 0;
    memset(preconfig_dev_list, 0 , sizeof(preconfig_dev_list));
    if (UCI_OK != uci_load(uciCtx, PRECONFIG_DEVICE_LIST, &pkg))
    {
        AWN_LOG_ERR("uci_load %s error!", PRECONFIG_DEVICE_LIST);
        //uci_perror(uciCtx, PRECONFIG_DEVICE_LIST);
        ret = AWND_ERROR;
    }
    else
    {
        if (NULL == pkg || NULL == &pkg->sections)
        {
            AWN_LOG_ERR("uci:pkg is NULL or &pkg->sections is NULL %s error!");
            goto done;
        }
        else
        {
            uci_foreach_element(&pkg->sections, e)
            {
                s = uci_to_section(e);
                if(strncmp(uci_sec_type,s->type,sizeof(uci_sec_type)) == 0)
                {
                    AWN_LOG_NOTICE("preconfig dev list:%s", s->e.name);
                    if(index < PRECONFIG_DEV_MAX)
                        snprintf(preconfig_dev_list[index], sizeof(bind_dev_list[index]), "%s", s->e.name);
                    else
                        AWN_LOG_WARNING("bind dev list num in /etc/config/preconfig_dev_list overstap the array boundary");
                    index++;
                }
            }
        }
    }
    /* check each device in /etc/config/preconfig_device_list 
       check if we can find it in /etc/config/bind_device_list */
    index = 0;
    if (strlen(preconfig_dev_list) == 0 ||  *preconfig_dev_list[index] == 0)
    {
        is_all_find = true;
    }
    else
    {    
        while (*preconfig_dev_list[index] != 0)
        {
            int i = 0;
            BOOL is_find = false;
            while (*bind_dev_list[i] != 0)
            {
                int tmp = strncmp(preconfig_dev_list[index], bind_dev_list[i], DEV_ID_LEN_MAX);
                if (tmp == 0)
                {
                    is_find = true;
                    break;
                }
                i++;
            }
            if (is_find == true)
            {
                is_all_find = true;
            }
            else
            {
                is_all_find = false;
                break;
            }
            index++;
        }
    }
    AWN_LOG_NOTICE("is all find %d", is_all_find);
    uci_unload(uciCtx, pkg);

done:
    if (uciCtx)
    {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }

    if(is_all_find == false)
    {
        awnd_wifi_driver_filter_update(preconfig_dev_list);
    }

    return is_all_find;
}

/* 
* function: awnd_preconfig_control_execute
* brief:    turn on/off preconfig vap according to BOOL action
            this function is for both fap and re
*/
int awnd_preconfig_control_execute(BOOL action)
{
    if (g_awnd.notBind)
        return 1;

    isp_dcmp_preconfig.preconfig_vap_state = action;
    if (action)
    {
        /* check wifi.preconfig.enable of preconfig AP VAP */
        if( ONBOARDING_ON != g_awnd.isPreOnboarding || 0 == awnd_config_get_precfg_mesh_enb())
        {
            char tmp[100];
            memset(tmp, 0, sizeof(tmp));
            AWN_LOG_INFO("g_awnd.isPreOnboarding=%d",g_awnd.isPreOnboarding);
            int ddd = awnd_config_get_precfg_mesh_enb();
            AWN_LOG_INFO("var state wifi preconfig enable %d", ddd);
            AWN_LOG_NOTICE("Enable preconfig mesh network when onboarding.");
            awnd_config_set_precfg_mesh_enb(1);

            g_awnd.isPreOnboarding = ONBOARDING_ON;
            AWN_LOG_INFO("__________workMode %d", g_awnd.workMode);
            awnd_wifi_restart();
            awnd_mode_convert(g_awnd.workMode, g_awnd.workMode); 
            return 0;
        }
    }
    else
    {
        if (ONBOARDING_OFF != g_awnd.isPreOnboarding || 1 == awnd_config_get_precfg_mesh_enb())
        {
            AWN_LOG_NOTICE("Disable preconfig mesh network when offpreboarding.");
            awnd_config_set_precfg_mesh_enb(0);
            // need to awn_plcson_set_eth_mesh_enable???
            //awn_plcson_set_eth_mesh_enable(AWND_MESH_CONFIG, 0);

            g_awnd.isPreOnboarding = ONBOARDING_OFF;
            awnd_wifi_restart();
            awnd_mode_convert(g_awnd.workMode, g_awnd.workMode); 
            return 0;
        }
    }

    g_awnd.isPreOnboarding = action;
    return 1;
}

/* 
* function: awnd_preconfig_control
* brief:    to decide if we should turn on/off preconfig vap
            this function is only for fap
* discribe: turn on/off preconfig vap 
            based on if all devices in preconfig_devlist have beed binded
* author:   developer_wang
* history:  Feb 9 2021
*/
void awnd_preconfig_control(struct uloop_timeout *t)
{
    /* to check if all devices in preconfig_devlist have beed binded */
    BOOL is_all_find = awnd_preconfig_dev_check();

    int ret = 0;
    /* if all binded => turn off preconfig vap
    *  if not        => turn on  preconfig vap
    */
    ret = awnd_preconfig_control_execute(!is_all_find);
    
    if(ret != 0)
    {
        uloop_timeout_set(&preconfig_control_timer, 30000); 
    }
    else
    {
        /* do nothing 
        *  timers have been re-setted in the above function:awnd_preconfig_control_execute
        */
    }
}

/* 
* function: awnd_re_preconfig_control
* brief:    to decide if we should turn on/off preconfig vap
            this function is only for re
* discribe: turn on/off preconfig vap 
            based on ubus call sync list
            (check ap's 'mix' segment in the sync list)
            since sync list's length is very close to the limitation
            so we add data segment in bit form('mix' can represent for mutiple meanings) 
* author:   developer_wang
* history:  Feb 9 2021
*/
void awnd_re_preconfig_control(struct uloop_timeout *t)
{
    if(g_awnd.notBind == 1)
    {
        AWN_LOG_INFO("not binded,no need to get fap's preconfig state");
        uloop_timeout_set(&re_preconfig_control_timer, 30000);
        return;
    }

    /* to check preconfig_dev with bind_dev 
       if preconfig_dev != bind_dev  =>  update wifi driver filter
    */
    awnd_preconfig_dev_check();

    BOOL state = awnd_ubus_get_preconfig();
    AWN_LOG_INFO("awnd_ubus_get_preconfig()=%d", state);
    int ret = awnd_preconfig_control_execute(state);
    if(ret != 0)
    {
        uloop_timeout_set(&re_preconfig_control_timer, 30000);
    }
    else
    {
        /* do nothing 
        *  timers have been re-setted in the above function:awnd_preconfig_control_execute
        */
    }
}
/*!
*\fn           int awnd_loop_re()
*\brief        Loop run in repeater mode
*\param[in]    v
*\return       AWND_MODE_TYPE
*/
void awnd_loop_re_init()
{    
    int ret = AWND_ERROR;
    int tm_compensate = 0;
    AWND_BAND_TYPE band;
    UINT8 wifi_bak_enable = 0;

    AWN_LOG_INFO("\n=======================awnd_re_loop=======================");

#if CONFIG_AWN_BOOT_DELAY
    /* Wait until phy link-up. This is a link loop prevention workaround.
       Let the ethernet backhaul detect neighbor first.
       Howevr, how long should AWND wait is not a determined value.
       Some this machanism is not 100% work for every situation.
       When a loop prevention machanism is implemented, this
       delay can be remove. */
    if (0 == boot_delay_done) {
        awnd_boot_delay();
    }
#endif

#if SCAN_OPTIMIZATION
    g_awnd.scan_band_success_mask = 0;
#endif

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    if (_is_in_disconnected_state(g_awnd.connStatus)) {
        awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
    }

    if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus) {
        awnd_init_tpie(&g_awnd.ethNetInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
    }

    awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
    awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
    awnd_update_tpie(&g_awnd.netInfo);
#endif
    
    awn_eth_set_report_param(1, l_awnd_config.eth_report_interval);
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option)) {
        awn_plcson_set_report_param(1, l_awnd_config.plc_report_interval);
    }

    if (g_awnd.notBind && g_awnd.bindStatus < AWND_BIND_START)
    {
        uloop_timeout_set(&awnd_bind_timer, l_awnd_config.tm_bind_confirm_interval);
        awn_plcson_set_eth_mesh_enable(AWND_MESH_BACKHUAL, 0);
    }
    else
    {
        awn_plcson_set_eth_mesh_enable(AWND_MESH_BACKHUAL, 1);
    }

#if CONFIG_ZERO_WAIT_DFS_SUPPORT
    /* get zero-wait DFS support */
    awnd_update_wifi_zwdfs_support();
#endif  /* CONFIG_ZERO_WAIT_DFS_SUPPORT */

    uloop_timeout_set(&wifi_done_timer,          l_awnd_config.tm_online_interval);

    /* add handle for eth */
    uloop_timeout_set(&eth_neigh_inspect_timer,  l_awnd_config.tm_eth_inspect_start); 
    
    /* add handle for onboarding */
    uloop_timeout_set(&onboarding_inspect_timer, l_awnd_config.tm_onboarding_start);

    /* add handle for plc */
    uloop_timeout_set(&plc_neigh_inspect_timer,  l_awnd_config.tm_plc_inspect_start);

#if CONFIG_RE_RESTORE_STA_CONFIG
    uloop_timeout_set(&handle_sta_config_timer,  l_awnd_config.tm_record_sta_config_interval);
#endif

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus) {
        wifi_bak_enable = 1;
    }
    else {
        /* eth connecting/connected: not to wifi scan/connect when onbording or eth_wifi_coexist = 0 */
        if (!g_awnd.notBind && 1 == g_awnd.eth_wifi_coexist) {
            wifi_bak_enable = 1;
        }
    }
#else
    if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus) {
        wifi_bak_enable = 1;
    }
#endif

    if (wifi_bak_enable)
    {
        /* add handle for wifi */
        awnd_scan_set_full_band();      
        g_awnd.rootApChType = AWND_ROOTAP_CHANNEL_IS_NORAML;

#if CONFIG_WIFI_DFS_SILENT
#if CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1
        if (ENABLE == awnd_config_get_enable_ht160())
        {   /* for 43684 160M 5G */
			AWND_WIFI_BW_TYPE wifi_bw = 0;
            if (AWND_OK == awnd_get_wifi_bw(AWND_BAND_5G, &wifi_bw)) {
                if (WIFI_BW_160M == wifi_bw) {
                    g_awnd.rootApChType = AWND_ROOTAP_CHANNEL_IS_DFS;
                    g_awnd.SilentPeriod[AWND_BAND_5G] = SILENT_PERIOD_START;
                }
                g_awnd.wifiBw[AWND_BAND_5G] = wifi_bw;
            }
            g_awnd.ht160Enable = ENABLE;
        }
        else {
            g_awnd.ht160Enable = DISENABLE;
        }
#endif /* CONFIG_5G_HT160_SUPPORT && CONFIG_WIFI_DFS_SILENT_5G1 */

#if CONFIG_WIFI_DFS_SILENT_5G2
        if((l_awnd_config.band_num == AWND_BAND_NUM_3) && 
            (AWND_COUNTRY_EU == l_awnd_config.country || AWND_COUNTRY_JP == l_awnd_config.country))
        {
            //int _tmp_idx = l_awnd_config.band_5g2_type;
            g_awnd.rootApChType = AWND_ROOTAP_CHANNEL_IS_DFS;
            g_awnd.SilentPeriod[l_awnd_config.band_5g2_type] = SILENT_PERIOD_START;
        }
#endif /* CONFIG_WIFI_DFS_SILENT_5G2 */

        /*if rootap work at dfs channel, we should wait for cac time out(60s or 600s), 
        add 5s for DUT connecting rootAp*/
        switch (g_awnd.rootApChType)
        {
        case AWND_ROOTAP_CHANNEL_IS_DFS:
            tm_compensate = AWND_DFS_SILENT_PERIOD;
            break;
        case AWND_ROOTAP_CHANNEL_IS_WEATHER:
            tm_compensate = AWND_DFS_WEATHER_SILENT_PERIOD;
            break;
        case AWND_ROOTAP_CHANNEL_IS_NORAML:
        default:
            tm_compensate = 0;
            break;
        }
        AWN_LOG_INFO("set tm compensate =%d ms!", tm_compensate);

        if (tm_compensate) {
            uloop_timeout_set(&wifi_silent_period_timer, tm_compensate);
            tm_compensate = 0;
        }
#endif /* CONFIG_WIFI_DFS_SILENT */

        g_awnd.enable6g = l_awnd_config.sp6G;//awnd_config_get_enable_6g();
        g_awnd.enable6g2 = l_awnd_config.sp6G2;//awnd_config_get_enable_6g2();

        //g_awnd.enable5g2 = awnd_config_get_enable_5g2();
        g_awnd.enable5g2 = l_awnd_config.sp5G2;

        uloop_timeout_set(&wifi_connect_timer,       l_awnd_config.tm_connect_duration + tm_compensate);

#if AWND_BIND_SWITCH_BACKHUAL_FIRST
        if (g_awnd.notBind)
        {
            uloop_timeout_set(&wifi_scan_timer,          l_awnd_config.tm_scan_sched + tm_compensate);
        }
        else
        {
            if (_is_in_disconnected_state(g_awnd.connStatus)) {
                uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_start + tm_compensate);
            }
        }
#else
        uloop_timeout_set(&wifi_scan_timer,          l_awnd_config.tm_scan_start + tm_compensate);
#endif
        uloop_timeout_set(&wifi_rootap_status_timer, l_awnd_config.tm_status_start + tm_compensate);

        awnd_clear_backhaul_smaples();
        uloop_timeout_set(&backhaul_review_timer,  2000); 
    }
    
    if (AWND_RE_STAGE_THIRD <= g_awnd.reStage)
    {
        uloop_timeout_set(&server_detect_timer,  l_awnd_config.tm_server_detect_start);
    }

    uloop_timeout_set(&re_stage_inspect_timer, l_awnd_config.tm_re_stage_inspect);
#ifdef SUPPORT_MESHMODE_2G
    uloop_timeout_set(&meshmode_2g_inspect_timer, l_awnd_config.tm_meshmode_2g_inspect);
#endif

    uloop_timeout_set(&re_preconfig_control_timer, 10000);
#if CONFIG_BSS_STATUS_CHECK
    _reset_bss_stats();
    uloop_timeout_set(&bss_status_inspect_timer, 30000);
#endif /* CONFIG_BSS_STATUS_CHECK */

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    /* Temperorily use 70s */
    // uloop_timeout_set(&ai_network_getscan_timer, SCANNING_DURATION * 1000);

    aimsg_server_init(AI_MSG_MODULE_NETWORKING, awnd_ai_msg_handler);
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */
    return ;
}


/*!
*\fn           int awnd_loop_hap()
*\brief        Loop run in half ap mode
*\param[in]    v
*\return       AWND_MODE_TYPE
*/
void awnd_loop_hap_init()
{
    UINT32 lanip = 0;
    AWN_LOG_INFO("\n=======================awnd_hap_loop======================="); 
    
#if SCAN_OPTIMIZATION
    g_awnd.scan_band_success_mask = 0;
#endif

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_HAP);
#else
    awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_HAP);
#endif
    if(AWND_OK == awn_get_lan_ip(&lanip))
    {
        g_awnd.netInfo.awnd_lanip = lanip;
    }
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
    awnd_update_tpie(&g_awnd.netInfo);
#endif
    
    awn_eth_set_report_param(1, l_awnd_config.eth_report_interval);
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option)) {
        awn_plcson_set_report_param(1, l_awnd_config.plc_report_interval);
    }
    awn_plcson_set_eth_mesh_enable(AWND_MESH_BACKHUAL, 1);

#if CONFIG_ZERO_WAIT_DFS_SUPPORT
    /* get zero-wait DFS support */
    awnd_update_wifi_zwdfs_support();
#endif  /* CONFIG_ZERO_WAIT_DFS_SUPPORT */

    uloop_timeout_set(&wifi_done_timer,  l_awnd_config.tm_online_interval);

    /* add handle for server detct */
    uloop_timeout_set(&server_detect_timer,  l_awnd_config.tm_server_detect_start);

    /* add handle for eth */
    uloop_timeout_set(&eth_neigh_inspect_timer,  l_awnd_config.tm_eth_inspect_start);  

    /* add handle for plc */
    uloop_timeout_set(&plc_neigh_inspect_timer,  l_awnd_config.tm_plc_inspect_start);

    /* add handle for onboarding */
    uloop_timeout_set(&onboarding_inspect_timer, l_awnd_config.tm_onboarding_start);

    /*  add handle for lanip update  */   
    uloop_timeout_set(&update_lanip_timer,  l_awnd_config.tm_update_lanip_start);

    /* add handle for wifi*/
    awnd_scan_set_full_band();
    uloop_timeout_set(&wifi_scan_timer,  l_awnd_config.tm_scan_start);

#if CONFIG_BSS_STATUS_CHECK
    _reset_bss_stats();
    uloop_timeout_set(&bss_status_inspect_timer, 30000);
#endif /* CONFIG_BSS_STATUS_CHECK */

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    // uloop_timeout_set(&ai_network_getscan_timer, 30 * 1000);

    aimsg_server_init(AI_MSG_MODULE_NETWORKING, awnd_ai_msg_handler);
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

    return;
}


/*!
*\fn           int awnd_loop_fap()
*\brief        Loop run in full ap mode
*\param[in]    v
*\return       AWND_MODE_TYPE
*/
void awnd_loop_fap_init()
{
    UINT32 lanip = 0;

    AWN_LOG_INFO("\n=======================awnd_fap_loop========================="); 
    
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_FAP);
#else
    awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_FAP);
#endif
    if(AWND_OK == awn_get_lan_ip(&lanip))
    {
        g_awnd.netInfo.awnd_lanip = lanip;
    }
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
    awnd_update_tpie(&g_awnd.netInfo);
#endif
    
    awn_eth_set_report_param(1, l_awnd_config.eth_report_interval);
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option)) {
        awn_plcson_set_report_param(1, l_awnd_config.plc_report_interval);
    }
    awn_plcson_set_eth_mesh_enable(AWND_MESH_BACKHUAL, 1);

#if CONFIG_ZERO_WAIT_DFS_SUPPORT
    /* get zero-wait DFS support */
    awnd_update_wifi_zwdfs_support();
#endif  /* CONFIG_ZERO_WAIT_DFS_SUPPORT */

    /* add handle for eth */
    uloop_timeout_set(&eth_neigh_inspect_timer,  l_awnd_config.tm_eth_inspect_start);

    /*  add handle for wifi configure  */   
    uloop_timeout_set(&wifi_done_timer,  l_awnd_config.tm_online_interval);

    /*  add handle for onboarding  */   
    uloop_timeout_set(&onboarding_inspect_timer,  l_awnd_config.tm_onboarding_start);

    /*  add handle for lanip update  */   
    uloop_timeout_set(&update_lanip_timer,  l_awnd_config.tm_update_lanip_start);

    /*  add handle for isp preconfig  */   
    uloop_timeout_set(&preconfig_control_timer,  10000);

#if CONFIG_BSS_STATUS_CHECK
    _reset_bss_stats();
    uloop_timeout_set(&bss_status_inspect_timer, 30000);
#endif /* CONFIG_BSS_STATUS_CHECK */

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    // uloop_timeout_set(&ai_network_getscan_timer, 30 * 1000);
    aimsg_server_init(AI_MSG_MODULE_NETWORKING, awnd_ai_msg_handler);
#endif

    return;
}



/*!
*\fn           int awnd_loop_prepare()
*\brief        Loop prepare of auto-wifi-network
*\param[in]    v
*\return       v
*/
void awnd_loop_prepare()
{
    char buff[128];
    UINT8 bind = 0;     
    int dstMode = AWND_MODE_NONE;
    int netType = AWND_NET_LRE;
#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
    int channel = 0;
#endif

    AWN_LOG_INFO("===============awnd_loop_prepare===============");

    if (AWND_OK != awnd_get_group_id(&l_group_info, &bind))
    {
        AWN_LOG_ERR("get group info failed");
    }
    l_group_info.staType = AWND_STA_TYPE_NORMAL;

    if (! bind)
    {
        g_awnd.notBind = 1;   
        g_awnd.bindStatus = AWND_BIND_NONE;
        _save_bind_status(0);
        g_awnd.locate = AWND_LOCATION_GETTING;
        sprintf(buff, "echo \"%s\" >/tmp/location", locateArray[g_awnd.locate]);
        system(buff);
        system("touch /tmp/setup_boost"); 
        dstMode = AWND_MODE_RE;
        awnd_config_set_mode(WIFI_REPEATER, (AWND_STATUS_DISCONNECT != g_awnd.ethStatus));
    }
    else
    {
        g_awnd.notBind = 0;
        g_awnd.bindStatus = AWND_BIND_OVER;
        _save_bind_status(1);

        if (AWND_CONFIG_AP == l_group_info.cfg_role)
        {
            dstMode = AWND_MODE_FAP;
            netType = AWND_NET_FAP;
            awnd_config_set_mode(WIFI_AP, 0);
        }
        else
        {
            dstMode = AWND_MODE_RE;
            awnd_config_set_mode(WIFI_REPEATER, (AWND_STATUS_DISCONNECT != g_awnd.ethStatus));
            if (!WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
            {
                awnd_config_set_all_stacfg_enb(0);
            }
            if (AWND_ERROR == awnd_get_bind_fap_mac())
            {
                AWN_LOG_ERR("get fap mac from bind dev list fail");
            }
        }
    }

    /* config ssid and pwd according to group-info */
    awnd_check_wifi_ssid_pwd(&l_group_info, WIFI_IFACE_ALL);

    awn_eth_set_detect_param(1, 0, l_awnd_config.eth_entry_aging_time);  

    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        g_awnd.isPlcRoot = 1;
        awn_plcson_set_detect_param(1, 0, l_awnd_config.plc_entry_aging_time);
#if AWND_PLC_EVENT_RECV
        uloop_fd_add(&plc_event_fd, ULOOP_READ);        
#endif
    }

    awnd_write_work_mode(dstMode, 0, NULL, netType, 0, NULL);

#if CONFIG_5G_HT160_SUPPORT
    /* FAP --> RE to reduce BW to 80M */
    if (AWND_MODE_RE == dstMode && !g_awnd.notBind &&
        ENABLE == awnd_config_get_enable_ht160())
    {
        AWND_WIFI_BW_TYPE cur_bw = 0;
        if (AWND_OK == awnd_get_wifi_bw(AWND_BAND_5G, &cur_bw) && WIFI_BW_160M == cur_bw )
        {
            AWN_LOG_WARNING("HT160 to reduce bandwith to HT80 when starting");
            awnd_disconn_sta_post(AWND_BAND_5G);
            awnd_set_wifi_bw(AWND_BAND_5G, 0, WIFI_BW_80M);
        }
    }
#endif /* CONFIG_5G_HT160_SUPPORT */

    awnd_mode_convert(AWND_MODE_NONE, dstMode);

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
    awnd_get_default_mesh_channel(1, &channel);
    awnd_get_backhaul_ap_channel(1, &channel);
#endif

}

void awnd_loop_clear(void)
{
	uloop_timeout_cancel(&wifi_connect_timer);
	uloop_timeout_cancel(&wifi_scan_timer);
    uloop_timeout_cancel(&update_lanip_timer);
    uloop_timeout_cancel(&server_detect_timer);
    uloop_timeout_cancel(&awnd_bind_timer);
    uloop_timeout_cancel(&re_stage_inspect_timer);
#ifdef SUPPORT_MESHMODE_2G
    uloop_timeout_cancel(&meshmode_2g_inspect_timer);
#endif
	uloop_timeout_cancel(&onboarding_inspect_timer);
	uloop_timeout_cancel(&wifi_done_timer);
	uloop_timeout_cancel(&wifi_rootap_status_timer);
	uloop_timeout_cancel(&eth_neigh_inspect_timer);
	uloop_timeout_cancel(&plc_neigh_inspect_timer);
    uloop_timeout_cancel(&backhaul_review_timer); 
     //need to cancel?????
    uloop_timeout_cancel(&preconfig_control_timer); 
    uloop_timeout_cancel(&re_preconfig_control_timer);
    system("echo void awnd_loop_clear(void) > /dev/console"); 
#if SCAN_OPTIMIZATION
    uloop_timeout_cancel(&handle_scan_result_timer);
#endif
#if CONFIG_RE_RESTORE_STA_CONFIG
    uloop_timeout_cancel(&handle_sta_config_timer);
#endif
#if CONFIG_WIFI_DFS_SILENT
    uloop_timeout_cancel(&wifi_silent_period_timer);
#endif /* CONFIG_WIFI_DFS_SILENT */
#if CONFIG_BSS_STATUS_CHECK
    uloop_timeout_cancel(&bss_status_inspect_timer);
#endif /* CONFIG_BSS_STATUS_CHECK */

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    /* ai networking */
    // uloop_timeout_cancel(&ai_network_getscan_timer);
    aimsg_server_fini();
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

	uloop_clear_wifi_processes();
    l_awnd_scan_table.scan_in_retry = 0;
    l_awnd_scan_table.scan_fast     = 0;
    l_awnd_scan_table.scan_band     = 0;

    uloop_clear_plc_event();
}

void awnd_loop_init(AWND_MODE_TYPE work_mode)
{
    switch(work_mode)
    {
        case AWND_MODE_FAP:
            awnd_loop_fap_init();
            break;
        case AWND_MODE_HAP:
            awnd_loop_hap_init();
            break;
        case AWND_MODE_RE:
            awnd_loop_re_init();    
            break;                        
        default:
            AWN_LOG_CRIT("invaild awnd mode:%d", work_mode);                 
            return;
    }

    return;
}

#ifdef CONFIG_AWN_RE_ROAMING
int awnd_re_roam(uint8_t *mac)
{
    AWND_BAND_TYPE band;
    AWND_BAND_TYPE base_band;
    uint8_t base_bssid[6] = {0};
    uint8_t bssid[6] = {0};
    char bssid_str[AWND_MAX_BSSID_LEN] = {0};
    AWND_AP_ENTRY *entry = NULL;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    AWND_AP_ENTRY last_entry = {0};
    AWND_AP_ENTRY  tmpEntry[AWND_BAND_MAX_NUM]={0};
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
    int entry_found[AWND_BAND_MAX] = {0};
    int found = 0;

    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
        entry = awnd_find_scan_entry(&l_awnd_scan_table.apList[band], mac, NULL, band);
        if (entry != NULL) {
            base_band = band;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
            memcpy(&last_entry, entry, sizeof(AWND_AP_ENTRY));
#endif
            memcpy(&g_awnd.rootAp[band], entry, sizeof(AWND_AP_ENTRY));
            memcpy(base_bssid, entry->bssid, 6);
            entry_found[band] = 1;
            found = 1;
        }
    }
    if (!found) {
        AWN_LOG_ERR("Fail to find target entry.");
        return -1;
    }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    // memcpy(l_mac_ai_roaming_target, mac, AWND_MAC_LEN);

    AWN_LOG_NOTICE("base band:%d", base_band);
    awnd_transform_bssid_from_select_band(base_band, last_entry.lan_mac, tmpEntry, last_entry.isPreconf, last_entry.bssid);
    AWN_LOG_ERR("calculate bssid done");
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
    for (band = AWND_BAND_2G; band < l_awnd_config.band_num; band++) {
        /* set bssid */
        if (entry_found[band]) {
            entry = &g_awnd.rootAp[band];
            memcpy(bssid, entry->bssid, 6);
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        } else if(tmpEntry[band].bssid) {
            AWN_LOG_ERR("band %d use calculate bssid", band);
            memcpy(bssid, tmpEntry[band].bssid, 6);
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
        } else {
            if (band == base_band) {
                memcpy(bssid, base_bssid, 6);
            } else if (band > base_band) {
                _mac_compute(bssid, base_bssid, band - base_band, 1);
            } else if (band < base_band) {
                _mac_compute(bssid, base_bssid, base_band - band, 0);
            }
        }
        memcpy(g_awnd.rootAp[band].lan_mac, mac, 6);
        memcpy(g_awnd.rootAp[band].bssid, bssid, 6);
        memcpy(g_awnd.staConfig->bssid, bssid, 6);
        g_awnd.connStatus[band] = AWND_STATUS_ROAMING;
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
        _macaddr_ntop(bssid, bssid_str);
        awnd_config_set_stacfg_bssid(bssid_str, band);
        anwd_set_wireless_sta_bssid(bssid_str, band);
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
#ifdef SUPPORT_MESHMODE_2G
        g_awnd.connected_ticks[band] = 0;
#endif
    }
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    if(!l_awnd_scan_table.scan_windows)
    {
        uloop_timeout_cancel(&wifi_scan_timer);                 
        uloop_clear_wifi_processes();                     
    }
    roaming_running = true;
    uloop_timeout_set(&ai_network_roaming_status_revert_timer, l_awnd_config.roaming_status_revert_interval);
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */
    // awnd_write_work_mode(g_awnd.workMode, TRUE, l_awnd_config.mac, entry->netInfo.awnd_net_type,entry->netInfo.awnd_level+1, mac);
    awnd_wifi_re_roam();

    return 0;
}
#endif

/*   All possible mode convert:
 *   1.none  --> none, hap
 *   2.re    --> none, hap, fap
 *   3.hap   --> none, fap, re
 *   4.fap   --> hap
 */
int awnd_mode_convert(AWND_MODE_TYPE srcMode, AWND_MODE_TYPE dstMode)
{
    AWND_HOTPLUG_CONFIG hotplugCfg;
    AWND_MODE_TYPE notifyMode;

    if (srcMode != dstMode)
    {
    	AWN_LOG_NOTICE("This device changes mode from %s to %s", modeToStr(srcMode), modeToStr(dstMode));
    }
    AWN_LOG_NOTICE("The configuration is going into effect.");

    awnd_loop_clear();

    if (dstMode != srcMode && (AWND_MODE_RE == dstMode || AWND_MODE_RE == srcMode) && (AWND_MODE_NONE != srcMode))
    {
        notifyMode = (AWND_MODE_NONE == dstMode) ? AWND_MODE_DEFAULT : dstMode;
        hotplugCfg.srcMode = srcMode;
        hotplugCfg.dstMode = notifyMode;
        hotplugCfg.type = AWND_HOTPLUG_MODE_CHANGE_BEGIN;
        awnd_mode_call_hotplug(&hotplugCfg);
    }                   

#ifdef CONFIG_SUPPORT_WAN_LAN_FLOW_CONTROL
    if (dstMode != srcMode && (AWND_MODE_RE == dstMode || AWND_MODE_FAP == dstMode))
    {
    char cmd[128];
    memset(cmd, 0, 128);
    snprintf(cmd, 128, "flow_control mode_change %s",modeToStr(dstMode));
    system(cmd);
    }
#endif

    g_awnd.workMode = dstMode;       

#if CONFIG_PRODUCT_IS_QCA_RCAC_CTRL
	if(0 == g_awnd.notBind)
	{
		if(AWND_MODE_RE == dstMode)
		{
			if(0 != awnd_config_get_radio_5g_rcac_enb())
			{
				awnd_config_set_radio_5g_rcac_enb(0);
			}
		}
		else
		{
			if(1 != awnd_config_get_radio_5g_rcac_enb())
			{
				awnd_config_set_radio_5g_rcac_enb(1);
			}
		}
	}
#endif

    /* none --> ap  || wifi restart at the same mode */ 
    if ((AWND_MODE_NONE != srcMode && srcMode == dstMode))
    {
        awnd_wifi_wait_for_done();

        if (AWND_MODE_RE == srcMode && AWND_MODE_RE == dstMode)
        {
            if (AWND_RE_STAGE_FOURTH == g_awnd.reStage)
            {
                g_awnd.reStage = AWND_RE_STAGE_THIRD;
                g_awnd.stage4Timestamp = 0;
            }

#if AWND_BIND_SWITCH_BACKHUAL_FIRST

#else
            if (g_awnd.notBind && AWND_BIND_START == g_awnd.bindStatus)
            {
                _save_bind_status(1);
                if (_is_in_connected_state(g_awnd.connStatus))
                {
                    awnd_disconn_all_sta();
                }
                memcpy(&(l_group_info.staGroupInfo), &(l_group_info.backhualGroupInfo), sizeof(GROUP_INFO));
                AWN_LOG_INFO("===========================RE-->RE (not binded to binded)");

                g_awnd.bindStatus = AWND_BIND_BACKHUAL_CONNECTING;
                if (AWND_STATUS_DISCONNECT == g_awnd.ethStatus)
                {
                    g_awnd.bindFast = 1;
                }
            }
#endif

        }
    }
    /* none --> re */
    else if (AWND_MODE_NONE == srcMode && AWND_MODE_RE == dstMode)
    {
        awnd_plc_set_root(0);
        awnd_config_set_mode(WIFI_REPEATER,(AWND_STATUS_DISCONNECT != g_awnd.ethStatus));
        if (!WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
        {
            awnd_config_set_all_stacfg_enb(0);
        }
        g_awnd.reStage = AWND_RE_STAGE_SECOND;
        g_awnd.stage2Timestamp = 0;
        g_awnd.stage4Timestamp = 0;
        awnd_wifi_restart();
        awnd_wifi_wait_for_done();
    }
    /* hap --> re */
    else if (AWND_MODE_HAP == srcMode && AWND_MODE_RE == dstMode)
    {
        awnd_plc_set_root(0);
        awnd_config_set_mode(WIFI_REPEATER,(AWND_STATUS_DISCONNECT != g_awnd.ethStatus));
        g_awnd.stage2Timestamp = 0;
        g_awnd.stage4Timestamp = 0;        
        awnd_wifi_restart();
        awnd_wifi_wait_for_done();
    }
    /* re --> ap or none-->fap */
    else if ((AWND_MODE_RE == srcMode && (AWND_MODE_FAP == dstMode || AWND_MODE_HAP ==dstMode)) || (AWND_MODE_NONE == srcMode && AWND_MODE_FAP == dstMode))
    {
        awnd_eth_set_backhaul(0, NULL);
        awnd_plc_set_root(1);
        awnd_plc_reconnect();
        awnd_disconn_all_sta();        

        /* RE-->FAP (not binded to binded) no need to update tpie */
        if (!(AWND_MODE_RE == srcMode && AWND_MODE_FAP == dstMode))
        {
            awnd_init_tpie(&g_awnd.netInfo, l_awnd_config.mac, l_group_info.staGroupInfo.label, l_awnd_config.weight, AWND_NET_LRE);
            //g_awnd.netInfo.wait = AWND_MODE_CHANGE_TIME;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
            awnd_update_tpie(&g_awnd.netInfo, AWND_NETINFO_ND);
#else
            awnd_update_tpie(&g_awnd.netInfo);
#endif
            usleep(200000);
        }

        awnd_config_set_all_stacfg_enb(0);        
        awnd_config_set_mode(WIFI_AP, 0);	

        if (AWND_MODE_RE == srcMode && AWND_MODE_FAP == dstMode)
        {
			awnd_set_binded_channel();
            AWN_LOG_INFO("RE-->FAP (not binded to binded) ==> to sleep 15s to wait for wifi reload");
            //sleep(15);
            _stable_sleep(15);
        }

        awnd_wifi_restart();
        awnd_wifi_wait_for_done();
    }
    /* fap <--> hap || hap --> none || none --> none */
    else
    {
        AWN_LOG_INFO("fap <--> hap || hap --> none || none --> none");
    }

    /* notify if work mode is changed.*/
    if (srcMode != g_awnd.workMode)
    {
        if (AWND_MODE_RE == g_awnd.workMode || AWND_MODE_FAP == g_awnd.workMode)
        {
            l_awnd_config.weight = (AWND_MODE_FAP == g_awnd.workMode)? 1 : 0;
        }

        notifyMode = (AWND_MODE_NONE == g_awnd.workMode) ? AWND_MODE_DEFAULT : g_awnd.workMode;
        awnd_write_work_mode(notifyMode, 0, NULL, notifyMode, 0, NULL);
        if (AWND_MODE_NONE == srcMode || AWND_MODE_RE == srcMode 
            || AWND_MODE_RE == g_awnd.workMode || AWND_MODE_FAP == g_awnd.workMode) 
        {
            AWN_LOG_INFO("call hotplug after mode change");
            hotplugCfg.srcMode = srcMode;
            hotplugCfg.dstMode = notifyMode;
            hotplugCfg.type = AWND_HOTPLUG_MODE_CHANGE_END;
            awnd_mode_call_hotplug(&hotplugCfg);
        }
    }

    /*init for the new mode and goto loop run again */
    awnd_loop_init(g_awnd.workMode);

    return AWND_OK;
}


/*!
*\fn           int awnd_loop_run()
*\brief        Loop run of auto-wifi-network
*\param[in]    v
*\return       N/A
*/
void awnd_loop_run()
{
    uloop_init();

    awnd_loop_prepare();

    ctx = ubus_connect(NULL);
    if (!ctx)
    {
        AWN_LOG_ERR("Failed to connect to ubus.");
    }
    else if (AWND_ERROR == awn_start_ubus_server(ctx))
    {
        AWN_LOG_ERR("add awn ubus object failed");
    }

    uloop_run();

    if (ctx)
        ubus_free(ctx);
    uloop_done();
}

/*!
*\fn           int awnd_plc_init()
*\brief        Init of plc device
*\param[out]   dev plc device
*\return       OK/ERROT
*/
static int awnd_plc_init(PLC_DEV_BASE *dev)
{
    PLC_STATUS ret = PLC_ERR;
    int try = 3;
    
    if (plcNicInit(l_awnd_config.plcIfname) != PLC_OK)
    {
        AWN_LOG_ERR("init plc interface failed");
        return AWND_ERROR;
    }

    while (ret != PLC_OK && try > 0)
    {
        ret = plcScanDev(0, dev);
        AWN_LOG_INFO("scan plc device %s", (PLC_OK == ret) ? "success" : "failed");
        try--;
    }

    return (PLC_OK == ret) ? AWND_OK : AWND_ERROR;
}

/*!
*\fn           int awnd_init()
*\brief        Init of auto-wifi-network
*\param[in]    fpath  Path of the configuration 
*\return       OK/ERROT
*/
int awnd_init(char * fpath)
{
    char buff[1024];
    int wifi_boot = 0;
    PLC_DEV_BASE dev = {0};

    /* init config */
    memset(&l_awnd_config, 0, sizeof(l_awnd_config));

#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
    awnd_init_cfg80211();
#endif
    l_awnd_config.mac[0]=0x00;
    l_awnd_config.mac[1]=0x1d;
    l_awnd_config.mac[2]=0x0f;
    l_awnd_config.mac[3]=0x11;
    l_awnd_config.mac[4]=0x22;
    l_awnd_config.mac[5]=0x7b;
#ifdef CONFIG_PRODUCT_PLC_SGMAC
    strcpy(l_awnd_config.plcIfname,      "eth0-p2");
#else
    strcpy(l_awnd_config.plcIfname,      "eth2");
#endif
    strcpy(l_awnd_config.lanDevName,     "br-lan"); 
    strcpy(l_awnd_config.wanDevName,     "br-wan");
    if(uci_get_profile_eths(l_awnd_config.ethIfnames, MAX_ETH_DEV_NUM)) {
        AWN_LOG_CRIT("%s-%d get profile eths failed\r\n", __func__, __LINE__);
        return AWND_ERROR;
    }
/*    strcpy(l_awnd_config.ethIfnames[0],  "eth0");
    strcpy(l_awnd_config.ethIfnames[1],  "eth1"); */
    //l_awnd_config.ethIfCnt = 2;
	if(uci_get_eth_port_num(&(l_awnd_config.ethIfCnt))) {
        AWN_LOG_CRIT("%s-%d get eth port num failed\r\n", __func__, __LINE__);
        return AWND_ERROR;
	}
	{
		AWN_LOG_CRIT("%s-%d l_awnd_config.ethIfCnt[%d]\r\n", __func__, __LINE__, l_awnd_config.ethIfCnt);
		int i = 0;
	    while (i < l_awnd_config.ethIfCnt)
	    {
	        if (strlen(l_awnd_config.ethIfnames[i]) <= 0)
	            break;
	        AWN_LOG_CRIT("ethIfnames:%s i[%d]", l_awnd_config.ethIfnames[i], i);
	        i++;
	    }
	}

    l_awnd_config.tm_status_start     = 2000;
    l_awnd_config.tm_status_interval  = 100;    

    l_awnd_config.tm_online_start     = 1000;
    l_awnd_config.tm_online_interval  = 1000;

    l_awnd_config.tm_scan_start       = 3000;
    l_awnd_config.tm_wait_prefer_ap   = 60000;
    l_awnd_config.tm_scan_interval    = 5000;
    l_awnd_config.tm_scan_sched       = 1000;

    l_awnd_config.tm_connect_duration = 60000;

    l_awnd_config.tm_plc_inspect_start     = 1000;
    l_awnd_config.tm_plc_inspect_interval  = 2000;
    l_awnd_config.tm_eth_inspect_start     = 1000;
    l_awnd_config.tm_eth_inspect_interval  = 2000;  

    l_awnd_config.tm_update_lanip_start     = 1000;
    l_awnd_config.tm_update_lanip_interval  = 10000;
    l_awnd_config.tm_server_detect_start    = 1000;
    l_awnd_config.tm_server_detect_interval = 2000;
    l_awnd_config.tm_re_stage_inspect       = 1000;
#if CONFIG_RE_RESTORE_STA_CONFIG
    l_awnd_config.tm_record_sta_config_interval = 60000;
    l_awnd_config.tm_record_sta_config_monitoring_interval = 600000;
#endif
#ifdef SUPPORT_MESHMODE_2G
    l_awnd_config.tm_meshmode_2g_inspect    = 5000;
#endif
    l_awnd_config.tm_onboarding_start       = 1000;
	l_awnd_config.tm_onboarding_interval    = 2000;

    l_awnd_config.tm_bind_confirm_interval  = 2000;

    l_awnd_config.plc_entry_aging_time = 3000;
    l_awnd_config.plc_report_interval  = 200;    
    l_awnd_config.eth_entry_aging_time = 4000;
    l_awnd_config.eth_report_interval  = 2000;      
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
    l_awnd_config.roaming_status_revert_interval  = 12000;  
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */

    l_awnd_config.scaling_factor          = 86;
    l_awnd_config.high_rssi_threshold     = AWND_HIGH_RSSI_THRESHOLD;
    l_awnd_config.low_rssi_threshold      = AWND_LOW_RSSI_THRESHOLD;
    l_awnd_config.best_effort_rssi_threshold = AWND_BEST_EFFORT_RSSI_THRESHOLD; 	
    l_awnd_config.best_effort_rssi_inc    = AWND_BEST_EFFORT_RSSI_INC; 
    l_awnd_config.best_effort_uplink_rate = AWND_BEST_EFFORT_UPLINK_RATE;     
    l_awnd_config.plc_rate_good           = 50;
    l_awnd_config.wifi_lost_rate_to_plc   = 70;
    l_awnd_config.wifi_pathRate_threshold_2g = 100;
    l_awnd_config.wifi_pathRate_threshold_5g = 200;
    l_awnd_config.limit_scan_band1 = 1;
    l_awnd_config.limit_scan_band4 = 0;
#if SCAN_OPTIMIZATION
    l_awnd_config.fast_scan_time = 3000;
    l_awnd_config.normal_scan_time = 3000;
    l_awnd_config.normal_scan_time_6g = 5000;
    l_awnd_config.connect_time = 60000 * 2; // 2 mins
#endif
#if CONFIG_BSS_STATUS_CHECK
    l_awnd_config.tm_bss_status_inspect = 20000;  /* 20 seconds */
#endif /* CONFIG_BSS_STATUS_CHECK */
	l_awnd_config.band_5g2_type = AWND_BAND_MAX;
	l_awnd_config.band_6g_type = AWND_BAND_MAX;
	l_awnd_config.band_6g2_type = AWND_BAND_MAX;
	l_awnd_config.band_3rd_type = AWND_REAL_BAND_MAX;
	l_awnd_config.band_4th_type = AWND_REAL_BAND_MAX;
	l_awnd_config.band_5th_type = AWND_REAL_BAND_MAX;

    if (AWND_ERROR == awnd_read_config(fpath, &l_awnd_config))
    {
        return AWND_ERROR;
    }
    AWN_LOG_NOTICE("l_mac_prefer :%02X-%02X-%02X-%02X-%02X-%02X", l_mac_prefer[0], l_mac_prefer[1], l_mac_prefer[2],
						l_mac_prefer[3], l_mac_prefer[4], l_mac_prefer[5]);

    if (! l_awnd_config.enable) 
        return AWND_OK;
         
    if (l_awnd_config.tm_status_start <= 0 || l_awnd_config.tm_status_interval <= 0 
        || l_awnd_config.tm_online_start <= 0 || l_awnd_config.tm_online_interval <= 0
        || l_awnd_config.tm_scan_start   <= 0 || l_awnd_config.tm_scan_interval <= 0
        || l_awnd_config.tm_connect_duration <= 0 || l_awnd_config.debug_level <= 0)
    {
        AWN_LOG_CRIT("awnd read config fail"); 
        return AWND_ERROR;
    }

    if (!l_awnd_config.plc_attached)
    {
        AWN_LOG_ERR("plc backhaul can not be enable without plc_attached");
        l_awnd_config.backhaul_option &= ~AWND_BACKHAUL_PLC;
        AWN_LOG_ERR("backhaul_option:%d", l_awnd_config.backhaul_option);
    }

    if (!CHECK_BACKHAUL_OPT(l_awnd_config.backhaul_option))
    {
        AWN_LOG_ERR("backhaul_option fix(%d) to dft", l_awnd_config.backhaul_option);
        l_awnd_config.backhaul_option = BACKHAUL_OPT_MAX ;
    }

    if (WIFI_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        AWN_LOG_ERR("wifi backhaul is enable");
    }

    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
        AWN_LOG_ERR("plc backhaul is enable");
    }

    g_awn_debug = l_awnd_config.debug_level;
    l_awnd_config.country = awnd_config_get_country_code();

    AWN_LOG_DEBUG("l_awnd_config.mac:%02X:%02X:%02X:%02X:%02X:%02X", l_awnd_config.mac[0], l_awnd_config.mac[1], 
        l_awnd_config.mac[2], l_awnd_config.mac[3], l_awnd_config.mac[4], l_awnd_config.mac[5]);
    AWN_LOG_DEBUG("l_awnd_config.tm_status_start:%d",     l_awnd_config.tm_status_start);
    AWN_LOG_DEBUG("l_awnd_config.tm_status_interval:%d",  l_awnd_config.tm_status_interval);
    AWN_LOG_DEBUG("l_awnd_config.tm_online_start:%d",     l_awnd_config.tm_online_start);
    AWN_LOG_DEBUG("l_awnd_config.tm_online_interval:%d",  l_awnd_config.tm_online_interval);
    AWN_LOG_DEBUG("l_awnd_config.tm_scan_start:%d",       l_awnd_config.tm_scan_start);
    AWN_LOG_DEBUG("l_awnd_config.tm_scan_interval:%d",    l_awnd_config.tm_scan_interval);
    AWN_LOG_DEBUG("l_awnd_config.tm_connect_duration:%d", l_awnd_config.tm_connect_duration);
    AWN_LOG_DEBUG("l_awnd_config.scaling_factor:%d",      l_awnd_config.scaling_factor);
    AWN_LOG_DEBUG("l_awnd_config.high_rssi_threshold:%d", l_awnd_config.high_rssi_threshold); 
    AWN_LOG_DEBUG("l_awnd_config.low_rssi_threshold:%d",  l_awnd_config.low_rssi_threshold); 
    AWN_LOG_DEBUG("l_awnd_config.best_effort_rssi_threshold:%d",l_awnd_config.best_effort_rssi_threshold);   	
    AWN_LOG_DEBUG("l_awnd_config.best_effort_rssi_inc:%d",l_awnd_config.best_effort_rssi_inc);     
    AWN_LOG_DEBUG("l_awnd_config.debug_level:%d",         l_awnd_config.debug_level);    

#if CONFIG_OUTDOOR_CHANNELLIMIT
    awnd_get_special_id(l_awnd_config.special_id);
    awnd_get_outdoor_channellimit(l_awnd_config.channellimit_id);
    l_awnd_config.channellimit_support = awnd_get_chanlimit_support();
    l_awnd_config.channellimit_start_chan = awnd_get_chanlimit_chan(CHANNELLIMIT_PROFILE_START_CHANNEL);
    l_awnd_config.channellimit_end_chan = awnd_get_chanlimit_chan(CHANNELLIMIT_PROFILE_END_CHANNEL);

    AWN_LOG_DEBUG("l_awnd_config.special_id:%s",                l_awnd_config.special_id);
    AWN_LOG_DEBUG("l_awnd_config.channellimit_support:%s",      l_awnd_config.channellimit_support ? "yes" : "no");
    AWN_LOG_DEBUG("l_awnd_config.channellimit_id:%s",           l_awnd_config.channellimit_id);
    AWN_LOG_DEBUG("l_awnd_config.channellimit_start_chan:%d",   l_awnd_config.channellimit_start_chan);
    AWN_LOG_DEBUG("l_awnd_config.channellimit_end_chan:%d",     l_awnd_config.channellimit_end_chan);
#endif

    /* init global */
    memset(&g_awnd, 0 , sizeof(AWND_GLOBAL));    
    g_awnd.workMode = AWND_MODE_NONE;
    g_awnd.rootApChType = AWND_ROOTAP_CHANNEL_IS_NORAML;
    g_awnd.capNetType = AWND_NET_MAX;
#ifdef SUPPORT_MESHMODE_2G
    g_awnd.meshmode = AWND_MESHMODE_2G_CONNECT;
    g_awnd.meshstate = AWND_MESHSTATE_2G_CONNECT;
    g_awnd.ticks = 0;
    g_awnd.is2GCaculatedBssid = 1;
#endif

    memset(&l_awnd_eth_neigh_table, 0, sizeof(AWND_ETH_NEIGH_TABLE));
    memset(&l_awnd_plc_neigh_table, 0, sizeof(AWND_PLC_NEIGH_TABLE));
    memset(&unable_conn_ap_table, 0, sizeof(AWND_UNABLE_CONN_AP_TABLE));

    /* init eth discover module */
    if (AWND_ERROR == awn_plcson_set_pid(getpid()) || AWND_ERROR == awn_eth_set_dev(l_awnd_config.lanDevName, l_awnd_config.wanDevName, l_awnd_config.ethIfCnt, l_awnd_config.ethIfnames))
    {
        AWN_LOG_ERR("fail to init eth dev or pid"); 
        return AWND_ERROR;    
    }

    /* init plc module */
    if (PLC_BACKHAUL_ENABLE(l_awnd_config.backhaul_option))
    {
	    if (AWND_OK == awnd_plc_init(&dev))
	    {
		    AWN_LOG_INFO("dev.type is %d\n", dev.type);
		    AWN_LOG_INFO("dev.mac is %02X:%02X:%02X:%02X:%02X:%02X\n", dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);

            memcpy(l_awnd_config.plcMac, dev.mac, AWND_MAC_LEN);
            
            if (AWND_ERROR == awn_plcson_set_dev(l_awnd_config.plcIfname) )
            {
                AWN_LOG_ERR("fail to init dev or pid"); 
                return AWND_ERROR;
            }        

#if AWND_PLC_EVENT_RECV    
            if (AWND_ERROR == netlink_event_listen(&plc_event_fd.fd))
            {
                AWN_LOG_ERR("fail to init event netlink"); 
                return AWND_ERROR;
            }
#endif
	    }
        else {
            l_awnd_config.plc_attached = 0;
            l_awnd_config.backhaul_option &= ~AWND_BACKHAUL_PLC;
        }
        
    }

	awnd_config_set_eth_neigh_interface(0);

    if(awnd_check_ap_mode())
    {
        g_awnd.sysMode = AWND_SYSMODE_AP;
    }
    else
    {
        g_awnd.sysMode = AWND_SYSMODE_ROUTER;
    }

    /* init files about state */
#if CONFIG_RE_RESTORE_STA_CONFIG
    if (AWND_OK == awnd_config_restore_sta_config()) 
    {
        AWN_LOG_WARNING("=========== to connect old rootap=============> "); 
    }
#endif

    /* init files about state */
    awnd_write_rt_info(AWND_INTERFACE_ETH, false, NULL, false);
    awnd_write_rt_info(AWND_INTERFACE_PLC, false, NULL, false);
    awnd_write_rt_info(AWND_INTERFACE_WIFI_2G, false, NULL, false);
    awnd_write_rt_info(AWND_INTERFACE_WIFI_5G, false, NULL, false);

    awnd_set_oui_now_version(awnd_get_network_oui());
    AWN_LOG_DEBUG("oui_now_version update to %d", oui_now_version);

    return AWND_OK;
}


/*!
 *\fn           awnd_create_pid_file()
 *\brief        Create pid file for auto-wifi-network
 *\return       N/V
 */
int awnd_create_pid_file()
{
    char buff[1024];
    int  pid = 0;
    FILE *pidfile = NULL;

    pidfile = fopen("/var/run/awnd.pid", "r");
    if (NULL != pidfile)
    {       
        if (NULL != fgets(buff, 1024, pidfile))
        {
            pid = atoi(buff);
        
            fclose(pidfile);
            pidfile = NULL;

            sprintf(buff, "/proc/%d/status", pid);
            pidfile = fopen(buff, "r");
            if (NULL != pidfile)
            {
                AWN_LOG_CRIT("%s", "awnd already run");            
                fclose(pidfile);
                return AWND_ERROR;
            }
        }
        else
        {
            fclose(pidfile);
        }
		
    }
    else
    {
        pidfile = fopen("/var/run/awnd.pid", "w");
        if (NULL == pidfile)
            return AWND_ERROR;

        fprintf(pidfile, "%d\n", getpid());
        fclose(pidfile);
    }
	

    return AWND_OK;
}

/*!
 *\fn           awnd_remove_pid_file()
 *\brief        Remove pid file for auto-wifi-network
 *\return       N/V
 */
void awnd_remove_pid_file()
{
    char buff[128];
    sprintf(buff, "rm /var/run/awnd.pid");
    system(buff);

    return ;
}

void channel_switch_state_set()
{
    FILE *fp = NULL;

    if(AWND_MODE_RE == g_awnd.workMode)
    {
        /* publish channel switch event -> sync-server */
        if (NULL == (fp = fopen("/var/run/awn_switch_channel", "w+")))
        {
            AWN_LOG_ERR("Failed to create channel switch state file");
            return ;
        }
        fclose(fp);
    }

    return ;
}

void channel_switch_state_clear()
{
    if(AWND_MODE_RE == g_awnd.workMode)
    {
        remove("/var/run/awn_switch_channel");
    }
    return ;
}

void awnd_remove_scan_running_file()
{
    char cmdline[128] = {0};
    snprintf(cmdline, sizeof(cmdline), "rm %s", WIFI_SCAN_RUNNING_FILE);
    system(cmdline);
    return ;
}

void awn_daemonize(void) 
{
    unsigned int  fd = 0;

    if (fork() != 0) 
        exit(0); /* parent exits */

    /* Every output goes to /dev/null. If Redis is daemonized but
     * the 'logfile' is set to 'stdout' in the configuration file
     * it will not log at all. */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) 
    {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) 
        {
            close(fd);
        }
    }
}

void set_prefer()
{
    AWN_LOG_NOTICE("start set prefer");
    if(AWND_MODE_RE == g_awnd.workMode)
    {
        l_awnd_scan_table.scan_fast = 1;
        l_wait_prefer_connect = 1;
        awnd_scan_set_full_band();
        uloop_timeout_set(&wifi_scan_timer, l_awnd_config.tm_scan_start);
    }
}

void awnd_start_scan_new()
{   
    AWN_LOG_NOTICE("topology change, start fast scan");
    if(AWND_MODE_RE == g_awnd.workMode)
    {
        l_awnd_scan_table.scan_fast = 1;
        l_wait_prefer_connect = 1;
        awnd_scan_set_full_band();
        uloop_timeout_set(&wifi_scan_timer, l_awnd_config.tm_scan_start);
    }
}

void awnd_prefer_change_scan()
{
    AWN_LOG_NOTICE("prefer device change");
    if(AWND_MODE_RE == g_awnd.workMode)
    {
        l_wait_prefer_connect = 1;
        awnd_scan_set_full_band();
        uloop_timeout_set(&wifi_scan_timer, l_awnd_config.tm_scan_start);
    }
}

void awn_dump_timer(struct blob_buf *buf) {
    void *nested;

    nested = blobmsg_open_table(buf, "timers(ms)");
    if (nested) {
#ifdef HAVE_ULOOP_TIMEOUT_REMAINING64
        blobmsg_add_u64(buf, "wifi_rootap_status_timer", uloop_timeout_remaining64(&wifi_rootap_status_timer));
        blobmsg_add_u64(buf, "wifi_connect_timer", uloop_timeout_remaining64(&wifi_connect_timer));
        blobmsg_add_u64(buf, "re_stage_inspect_timer", uloop_timeout_remaining64(&re_stage_inspect_timer));
        blobmsg_add_u64(buf, "wifi_scan_timer", uloop_timeout_remaining64(&wifi_scan_timer));
        blobmsg_add_u64(buf, "awnd_bind_timer", uloop_timeout_remaining64(&awnd_bind_timer));
#else
        blobmsg_add_u32(buf, "wifi_rootap_status_timer", uloop_timeout_remaining(&wifi_rootap_status_timer));
        blobmsg_add_u32(buf, "wifi_connect_timer", uloop_timeout_remaining(&wifi_connect_timer));
        blobmsg_add_u32(buf, "re_stage_inspect_timer", uloop_timeout_remaining(&re_stage_inspect_timer));
        blobmsg_add_u32(buf, "wifi_scan_timer", uloop_timeout_remaining(&wifi_scan_timer));
        blobmsg_add_u32(buf, "awnd_bind_timer", uloop_timeout_remaining(&awnd_bind_timer));
#endif

        blobmsg_close_table(buf, nested);
    }
}

/*!
 *\fn           int main()
 *\brief        main routine of auto-wifi-network
 *\param[in]       argc
 *\param[in]       argv 
 *\return       OK/ERROR
 */
int main(int argc,char *argv[])
{
    char confPath[256];
    /*awn_daemonize();*/
    
    awn_log_init();    

    if (AWND_ERROR == awnd_create_pid_file())
        return 0;
      
    if (3 == argc && !strncmp(argv[1], "-C", 2))
    {
         strcpy(confPath, argv[2]);
    }
    else
    {
         strcpy(confPath, DEFAULT_CONF_FILE);
    }
    
    if (AWND_ERROR == awnd_init(confPath))
    {
        AWN_LOG_ERR("awnd init fail"); 
        goto exit;
    }

    AWN_LOG_NOTICE("awnd loaded configure and initialize."); 

    awnd_loop_run();

exit:
    awn_log_exit();
    awnd_remove_pid_file();
    awnd_remove_scan_running_file();
#ifdef CONFIG_DECO_WIFIHAL_SUPPORT
    awnd_deinit_cfg80211();
#endif

    AWN_LOG_NOTICE("awnd exit."); 	
    return 0;
}


