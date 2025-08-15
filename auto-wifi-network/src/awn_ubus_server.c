/*!
 *\file		awn_ubus_server.c
 *\brief	provide interface for other programs.
 *
 *\author	dengzhong@tp-link.com.cn
 *\version	v1.0
 *\date		02Jan18
 *
 *\history	\arg 1.0, 02Jan18, create the file.
 */
/***************************************************************************/
/*                    CONFIGURATIONS                    */
/***************************************************************************/

/***************************************************************************/
/*                    INCLUDE FILES                     */
/***************************************************************************/
#include <signal.h>
#include <sys/time.h>
#include <libubox/ustream.h>
#include <libubox/blobmsg_json.h>
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include <json/json.h>
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT */
#include <sys/socket.h>

#include "awn_ubus.h"
#include "auto_wifi_net.h"
#include "awn_plcson_netlink.h"
#include "awn_log.h"
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
#include "aimsg_handler.h"
#endif	/* CONFIG_AWN_MESH_OPT_SUPPORT	*/

/***************************************************************************/
/*                    DEFINES                           */
/***************************************************************************/
#define AWN_NAME     	"awn"

#define TOPOLOGY_CHANGE_EVENT     "topology_change"

/***************************************************************************/
/*                    TYPES                             				   */
/***************************************************************************/

enum
{
    __UPDATE_MAX,
};

enum {
	DEBUG_LEVEL,
	DEBUG_SYSLOG_LEVEL,
	DEBUG_LEVEL_MAX
};

enum {
	PATH_RATE_2G,
	PATH_RATE_5G,
	PATH_RATE_MAX
};

enum {
	DNS_ADDRESS,
	DNS_ADDRESS_MAX
};

enum {
	OPERATION,
	VALUE,
	PRECONFIG_OP_MAX
};

enum{
	PREFER_DEVICE,
	PREFER_DEVICE_MAX,
};

enum
{
	SCAN_NEW_MAX,
};

enum
{
	CHECK_PREFER,
	CHECK_PREFER_MAX
};

enum {
	OUI_TYPE,
	OUI_TYPE_MAX
};

enum {
	DUMP_CATEGORY,
	DUMP_MAX
};

#define AWN_DUMP_CATEGORY_ALL			"all"
#define AWN_DUMP_CATEGORY_GENERAL		"gen"
#define AWN_DUMP_CATEGORY_CONN_INFO		"conn"
#define AWN_DUMP_CATEGORY_CONFIG		"conf"
#define AWN_DUMP_CATEGORY_TPIE			"tpie"
#define AWN_DUMP_CATEGORY_TIMER			"timer"

#ifdef CONFIG_AWN_RE_ROAMING
enum {
	REROAM_TARGETMAC,
	REROAM_MAX,
};

enum {
	ALG_POLICY,
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
	ALG_FROM_MAC,
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/
	ALG_POLICY_MAX,
};
#endif

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
enum {
	RE_CONN_DEFAULT,
	RE_CONN_MAX
};
#endif

enum {
	SWITCH_BAND,
	SWITCH_CHANNEL,
	SWITCH_FORCE,
	SWITCH_CAHNNEL_MAX
};

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
enum {
    AI_HOPS_FACTOR,
    AI_HOPS_FACTOR_MAX,
};

enum
{
    TO_DELETE_MAC,
    __TO_DELETE_MAX,
};

enum {
	NWKOUT_SRCMAC,
	NWKOUT_DSTMAC,
	NWKOUT_STRATEGY,
	NWKOUT_POLICY_MAX,
};

enum {
	ALG_DONE,
	LAST_MAC,
	AI_STATUS_POLICY_MAX,
};

enum {
	ALG_PATC_COMP,
	ALG_PATC_COMP_MAX,
};
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/

/***************************************************************************/
/*                    EXTERN_PROTOTYPES                 */
/***************************************************************************/
extern AWND_CONFIG l_awnd_config;

/***************************************************************************/
/*                    LOCAL_PROTOTYPES                  */
/***************************************************************************/

static int awn_update_fap_mac(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_set_dbg_level(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_set_path_rate_threshold(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_update_dns(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);
static int awn_preconfig_opt(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_prefer_device(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_check_prefer_device(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_update_oui(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_update_eth_names(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_dump(struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method, struct blob_attr *msg);

#ifdef CONFIG_AWN_RE_ROAMING
static int awn_reroam_test(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method, struct blob_attr *msg);
#endif

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
static int awn_set_re_connect_policy(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);
#endif

static int awn_handle_switch_channel(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static int awn_start_ai(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);
static int awn_test_ping(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);
static int awn_test_simplex(struct ubus_context *ctx, struct ubus_object *obj,
	struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int ai_awn_set_hops_factor(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int ai_awn_get_hops_factor(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_first_roaming(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_link_up_roaming_test(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_ai_delete_re(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_send_nwkout(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_set_ai_status(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static int awn_set_patc_compensation(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg);
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/

/***************************************************************************/
/***************************************************************************/


extern UINT8 l_mac_prefer[AWND_MAC_LEN];
extern AWND_GLOBAL  g_awnd;
#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
extern RE_CONNECT_POLICY g_connect_policy;
#endif
extern int oui_now_version;
extern IEEE80211_TP_OUI_LIST tp_oui_list[TP_OUI_MAX_VERSION+1];
static struct blob_buf buffer;
struct ubus_event_handler togology_change_event_handler;

static const struct blobmsg_policy update_fapmac_policy[__UPDATE_MAX] = {
};

static const struct blobmsg_policy debug_level_policy[] = {
	[DEBUG_LEVEL] = {.name = "level", .type = BLOBMSG_TYPE_INT32},
	[DEBUG_SYSLOG_LEVEL] = {.name = "syslog_level", .type = BLOBMSG_TYPE_INT32},		
};

static const struct blobmsg_policy pathRate_threshold_policy[] = {
	[PATH_RATE_2G] = {.name = "2g", .type = BLOBMSG_TYPE_INT32},
	[PATH_RATE_5G] = {.name = "5g", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy dns_policy[] = {
	[DNS_ADDRESS] = {.name = "dns", .type = BLOBMSG_TYPE_INT32},
};
static const struct blobmsg_policy preconfig_opt[] = {
	[OPERATION] = {.name = "operation", .type = BLOBMSG_TYPE_INT32},
	[VALUE] = {.name = "value", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy prefer_device_plicy[] = {
	[PREFER_DEVICE] = {.name = "prefer_device", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy check_prefer_device_policy[] = {
	[PREFER_DEVICE] = {.name = "new_prefer_mac", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy update_oui_policy[] = {
	[OUI_TYPE] = {.name = "version", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy dump_policy[] = {
	[DUMP_CATEGORY] = {.name = "cat", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy update_eth_names_policy[] = {
};

#ifdef CONFIG_AWN_RE_ROAMING
static const struct blobmsg_policy reroam_policy[] = {
	[REROAM_TARGETMAC] = {.name = "mac", .type = BLOBMSG_TYPE_STRING},
};
#endif

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
static const struct blobmsg_policy re_connect_policy[] = {
	[RE_CONN_DEFAULT] = {.name = "policy", .type = BLOBMSG_TYPE_INT32},
};
#endif

static const struct blobmsg_policy switch_channel_policy[] = {
	[SWITCH_BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
	[SWITCH_CHANNEL] = {.name = "channel", .type = BLOBMSG_TYPE_INT32},
	[SWITCH_FORCE] = {.name = "force", .type = BLOBMSG_TYPE_INT8},
};

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static const struct blobmsg_policy ai_start_policy[] = {
	[ALG_POLICY] = {.name = "policy", .type = BLOBMSG_TYPE_INT32},
	[ALG_FROM_MAC] = {.name = "from_mac", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy test_ping_policy[] = {
};

static const struct blobmsg_policy test_simplex_policy[] = {
};

static const struct blobmsg_policy set_hops_factor_policy[] = {
    [AI_HOPS_FACTOR] = {.name = "hops_factor", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy get_hops_factor_policy[] = {
};

static const struct blobmsg_policy first_roaming_policy[] = {
};

static const struct blobmsg_policy delete_re_policy[__TO_DELETE_MAX] = {
	[TO_DELETE_MAC] = {"mac", BLOBMSG_TYPE_ARRAY},
};

static const struct blobmsg_policy nwkout_policy[] = {
	[NWKOUT_SRCMAC] = {.name = "srcmac", .type = BLOBMSG_TYPE_STRING},
	[NWKOUT_DSTMAC] = {.name = "dstmac", .type = BLOBMSG_TYPE_STRING},
	[NWKOUT_STRATEGY] = {.name = "alg_strategy", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy ai_status_policy[] = {
	[ALG_DONE] = {.name = "alg_done", .type = BLOBMSG_TYPE_INT32},
	[LAST_MAC] = {.name = "last_mac", .type = BLOBMSG_TYPE_STRING},
};

static const struct blobmsg_policy set_patc_comp_policy[] = {
    [AI_HOPS_FACTOR] = {.name = "patc_comp", .type = BLOBMSG_TYPE_INT32},
};
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT */

static struct ubus_method awn_object_methods[] = {    
    UBUS_METHOD("update", awn_update_fap_mac, update_fapmac_policy ), 
    UBUS_METHOD("debug",  awn_set_dbg_level, debug_level_policy ),   
    UBUS_METHOD("path_rate",  awn_set_path_rate_threshold, pathRate_threshold_policy ),
    UBUS_METHOD("update_dns", awn_update_dns, dns_policy ),
    UBUS_METHOD("update_prefer_device", awn_prefer_device, prefer_device_plicy ),
	UBUS_METHOD("check_prefer_device", awn_check_prefer_device, check_prefer_device_policy),
	UBUS_METHOD("update_oui", awn_update_oui, update_oui_policy ),
	UBUS_METHOD("update_eth_names", awn_update_eth_names, update_eth_names_policy ),
	UBUS_METHOD("preconfig", awn_preconfig_opt, preconfig_opt ),
	UBUS_METHOD("dump", awn_dump, dump_policy ),
#ifdef CONFIG_AWN_RE_ROAMING
    UBUS_METHOD("re_roam", awn_reroam_test, reroam_policy ),
#endif
#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
	UBUS_METHOD("re_connect_policy", awn_set_re_connect_policy, re_connect_policy),
#endif
	UBUS_METHOD("switch_channel", awn_handle_switch_channel, switch_channel_policy),
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
	UBUS_METHOD("ai_start", awn_start_ai, ai_start_policy ),
	UBUS_METHOD("test_simplex", awn_test_simplex, test_simplex_policy ),
    UBUS_METHOD("set_hops", ai_awn_set_hops_factor, set_hops_factor_policy),
    UBUS_METHOD("get_hops", ai_awn_get_hops_factor, get_hops_factor_policy),
	UBUS_METHOD("first_roaming", awn_first_roaming, first_roaming_policy ),
	UBUS_METHOD("link_up_test", awn_link_up_roaming_test, first_roaming_policy ),
	UBUS_METHOD("ai_delete_re", awn_ai_delete_re, delete_re_policy ),
	UBUS_METHOD("send_nwkout", awn_send_nwkout, nwkout_policy ),
	UBUS_METHOD("set_ai_status", awn_set_ai_status, ai_status_policy ),
	UBUS_METHOD("set_patc_comp", awn_set_patc_compensation, set_patc_comp_policy),
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/
};

static struct ubus_object_type awn_object_type =
            UBUS_OBJECT_TYPE(AWN_NAME, awn_object_methods);

static struct ubus_object awn_object = {
    .name = AWN_NAME,
    .type = &awn_object_type,
    .methods = awn_object_methods,
    .n_methods = ARRAY_SIZE(awn_object_methods),
};

/***************************************************************************/
/*                    LOCAL_FUNCTIONS                   */
/***************************************************************************/
/* 
 * fn		static int awn_update_fap_mac(struct ubus_context *ctx, struct ubus_object *obj,
 *					    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
 * brief	update fap mac
 *
 * return	 
 */
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static int awn_test_simplex(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int ret = testSimplex();
	blob_buf_init(&buffer, 0);
	if (ret) {
		blobmsg_add_u32(&buffer, "fail", 0);	
	} else {
		blobmsg_add_u32(&buffer, "success", 0);
	}
	ubus_send_reply(ctx, req, buffer.head);

	return 0;
}
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/

int awn_update_fap_mac(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{	


	/* 1. update fap mac from bind_device_list */
	awnd_get_bind_fap_mac();

	/* 2. return result */
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}
static void show_preconfig_usage(void)
{
	AWN_LOG_CRIT("echo This is preconfig control interface in awn module");
	AWN_LOG_CRIT("echo developed by wangchaoran@tp-link.com.cn");
	AWN_LOG_CRIT("echo usage:ubus call awn preconfig '{\"operation\":int32,\"value\":int32}'");
	AWN_LOG_CRIT("echo operation 1:get rootap link info {state:link or not, type:preconfig or others}");
	AWN_LOG_CRIT("echo operation 2:get preconfig vap state {state:RUNNING or not}");
	AWN_LOG_CRIT("echo operation 11:turn on/off writing md5s to wifi driver");
	AWN_LOG_CRIT("echo operation 12:switch an root ap");
	AWN_LOG_CRIT("echo operation 13:update ip segment limit to kmod_preconfig_hook");
	AWN_LOG_CRIT("echo Good Luck!!!");
}

/* 
 * fn			update_preconfig_hook_lan
 * 
 * brief		for ISP DCMP to update ip_u32 limitation to /proc/preconfig_hook/preconfig_hook_lan
 * 
 * discription	get ip && mask from ifconfig br-lan
 * 				calculate ip_lower = ip & mask
 * 				calculate ip_upper = ip_lower + 0xffffffff ^ mask
 * 				send ip_lower ip_upper to kmod_preconfig_hook
 * return	 
 */
static int update_preconfig_hook_lan(void)
{
	FILE *fp = NULL;
	#define BUFFER_SIZE 20
	char line[BUFFER_SIZE] = {0};
	char ip_str[BUFFER_SIZE] = {0};
	char mask_str[BUFFER_SIZE] = {0};
	u_int32_t ip_u32 = 0;
	u_int32_t mask_u32 = 0;
	u_int32_t ip_limit_upper = 0;
	u_int32_t ip_limit_lower = 0;
	char cmd[100] = {0};
	char *p = NULL;
	const char *PATH_PRECONFIG_HOOK = "/proc/preconfig_hook/preconfig_hook_lan";

	/* get ip from ifconfig br-lan */
	fp = popen("ifconfig br-lan | grep \"inet \" | awk '{print $2}'", "r");
	if (NULL == fp)
	{
		AWN_LOG_INFO("Failed to get ifconfig br-lan info");
		return -1;
	}
	fgets(line, BUFFER_SIZE, fp);
	pclose(fp);
	p = strchr(line,':');
	if(*(++p) == 0)
	{return -1;}
	if (strlen(p) < BUFFER_SIZE)
	{
		if(p[strlen(p) - 1] == '\n')			
			strncpy(ip_str, p, strlen(p) - 1);
		else
			strncpy(ip_str, p, strlen(p));
	}
	else
	{
		strncpy(ip_str, p, BUFFER_SIZE-1 );
	}
	//ip_u32 = ntohl(inet_addr(ip_str));
	//AWN_LOG_INFO("ip_u32:%u", ip_u32);
	ip_u32 = ntohl(inet_addr(ip_str));		
	AWN_LOG_INFO("ip:%s, ip_u32:%u", ip_str, ip_u32);

	/* get mask from ifconfig br-lan */
	memset(line, 0, sizeof(line));
	fp = popen("ifconfig br-lan | grep \"inet \" | awk '{print $4}'", "r");
	if (NULL == fp)
	{
		AWN_LOG_INFO("Failed to get ifconfig br-lan info");
		return -1;
	}
	fgets(line, BUFFER_SIZE, fp);
	pclose(fp);
	p = strchr(line,':');
	if(*(++p) == 0)
	{return -1;}
	if (strlen(p) < BUFFER_SIZE)
	{
		if(p[strlen(p) - 1] == '\n')			
			strncpy(mask_str, p, strlen(p) - 1);
		else
			strncpy(mask_str, p, strlen(p));
	}
	else
	{
		strncpy(mask_str, p, BUFFER_SIZE-1);
	}
	
	mask_u32 = ntohl(inet_addr(mask_str));
	//AWN_LOG_INFO("mask_u32:%u", mask_u32);
	AWN_LOG_INFO("mask:%s, mask_u32:%u", mask_str, mask_u32);
	ip_limit_lower = ip_u32 & mask_u32;
	ip_limit_upper = ip_limit_lower + ((0xffffffff)^mask_u32);
	AWN_LOG_INFO("ip_limit_upper:%u", ip_limit_upper);
	AWN_LOG_INFO("ip_limit_lower:%u", ip_limit_lower);

	FILE *fp_preconfig = fopen(PATH_PRECONFIG_HOOK, "w");
	if(fp_preconfig == NULL)
	{
		AWN_LOG_ERR("update_preconfig_hook_lan open file:%s error", PATH_PRECONFIG_HOOK);
		return -1;
	}
	fprintf(fp_preconfig, "1%u#%u#", ip_limit_upper, ip_limit_lower);
	fclose(fp_preconfig);
	AWN_LOG_INFO("update kmod_preconfig:1%u#%u#", ip_limit_upper, ip_limit_lower);
	return 0;
}

/* 
 * fn		static int awn_set_dbg_level(struct ubus_context *ctx, struct ubus_object *obj,
 *					    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
 * brief	set debug level
 *
 * return	 
 */
int awn_set_dbg_level(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[DEBUG_LEVEL_MAX] = {NULL};
	int debug_level = 0;
	int syslog_level = 0;

	/* 1. get msg */
	parse_status = blobmsg_parse(debug_level_policy, DEBUG_LEVEL_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
		AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

	/* 2 get debug level */
	if (tb[DEBUG_LEVEL] && blob_data(tb[DEBUG_LEVEL]) )
	{
		debug_level = blobmsg_get_u32(tb[DEBUG_LEVEL]);
		if (debug_level < 1 || debug_level > 7)
		{
			AWN_LOG_ERR("set debug level(%d) error, should be between 1 and 7", debug_level);
		}
		else
		{
			/* 2 set debug level */
			g_awn_debug = debug_level;
			AWN_LOG_NOTICE("set debug level:%d.", g_awn_debug);			
		}
	}	

	/* 2 get debug level */
	if (tb[DEBUG_SYSLOG_LEVEL] && blob_data(tb[DEBUG_SYSLOG_LEVEL]) )
	{
		syslog_level = blobmsg_get_u32(tb[DEBUG_SYSLOG_LEVEL]);
		if (syslog_level < 1 || syslog_level > 7)
		{
			AWN_LOG_ERR("set syslog level(%d) error, should be between 1 and 7", syslog_level);		
		}
		else
		{
			/* 2 set debug level */
			g_awn_syslog_level = syslog_level;
			AWN_LOG_NOTICE("set syslog level:%d.", g_awn_syslog_level);			
		}	
	}
	

END_HANDLE:
	/* 4. return result */
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

/* 
 * fn		static int awn_set_path_rate_threshold(struct ubus_context *ctx, struct ubus_object *obj,
 *					    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
 * brief	set wifi path rate threshold
 *
 * return
 */
int awn_set_path_rate_threshold(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[PATH_RATE_MAX] = {NULL};
	int path_rate_2g = 0;
	int path_rate_5g = 0;

	/* 1. get msg */
	parse_status = blobmsg_parse(pathRate_threshold_policy, PATH_RATE_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
		AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

	/* 2 get path rate */
	if (!tb[PATH_RATE_2G] || !blob_data(tb[PATH_RATE_2G]) || !tb[PATH_RATE_5G] || !blob_data(tb[PATH_RATE_5G]))
	{
		AWN_LOG_ERR("pathRate_threshold_policy error.");
		goto END_HANDLE;
	}

	path_rate_2g = blobmsg_get_u32(tb[PATH_RATE_2G]);
	path_rate_5g = blobmsg_get_u32(tb[PATH_RATE_5G]);
	if (path_rate_2g <= 0 || path_rate_5g <= 0)
	{
		AWN_LOG_ERR("set path rate(2g:%d 5g:%d) error.", path_rate_2g, path_rate_5g);
		goto END_HANDLE;
	}

	/* 2 set path rate */
	awnd_config_set_path_rate_threshold(path_rate_2g, path_rate_5g);
	AWN_LOG_INFO("set path rate (2g:%d 5g:%d).", path_rate_2g, path_rate_5g);

END_HANDLE:
	/* 4. return result */
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

/*
 * fn		static int awn_update_dns(struct ubus_context *ctx, struct ubus_object *obj,
 *					    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
 * brief	update dns server
 *
 * return
 */
static int awn_update_dns(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{

	int parse_status = 0;
	struct blob_attr *tb[DNS_ADDRESS_MAX] = {NULL};
	UINT32 dns = 0;

	/* 1. get msg */
	parse_status = blobmsg_parse(dns_policy, DNS_ADDRESS_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
		AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

	/* 2 get dns address */
	if (!tb[DNS_ADDRESS] || !blob_data(tb[DNS_ADDRESS]))
	{
		AWN_LOG_ERR("get dns error.");
		goto END_HANDLE;
	}

	dns = blobmsg_get_u32(tb[DNS_ADDRESS]);

	/* 2 set path rate */
	awnd_netinfo_update_dns(dns);
	AWN_LOG_INFO("update dns address:%d.", dns);

END_HANDLE:
	/* 4. return result */
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

static int awn_prefer_device(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{	
	UINT8 mac_prefer[AWND_MAC_LEN] = {0};
	int parse_status = 0;  
	struct blob_attr *tb[PREFER_DEVICE_MAX] = {NULL};
	char* ubus_prefer_mac = NULL;
	
	parse_status = blobmsg_parse(prefer_device_plicy, PREFER_DEVICE_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_NOTICE("Parse blog msg failed.");
		goto END_HANDLE;
	}

	ubus_prefer_mac = blobmsg_get_string(tb[PREFER_DEVICE]);
	//string->UINT8
	_macaddr_ston_(mac_prefer, ubus_prefer_mac);    

	if(memcmp(l_mac_prefer, mac_prefer, AWND_MAC_LEN) != 0 )
	{	
		memcpy(l_mac_prefer, mac_prefer, AWND_MAC_LEN);
		AWN_LOG_NOTICE("new l_mac_prefer :%02X-%02X-%02X-%02X-%02X-%02X", l_mac_prefer[0], l_mac_prefer[1], l_mac_prefer[2],
						l_mac_prefer[3], l_mac_prefer[4], l_mac_prefer[5]);
	}
	//每次用户主动设置优先节点时，都清空之前记录的无法连接的节点
	AWN_LOG_NOTICE("set prefer device, clean unable_conn_ap_table, op: %d ", AWND_OP_FLUSH);
	check_unable_conn_ap_table(NULL, AWND_OP_FLUSH);
	//当前设备前端不是优先节点，需要扫描连接
	if((memcmp(g_awnd.rootAp[AWND_BAND_2G].lan_mac, l_mac_prefer, AWND_MAC_LEN) != 0) || (memcmp(g_awnd.rootAp[AWND_BAND_5G].lan_mac, l_mac_prefer, AWND_MAC_LEN) != 0))
	{
		AWN_LOG_NOTICE("try to connect prefer_mac: :%02X-%02X-%02X-%02X-%02X-%02X", l_mac_prefer[0], l_mac_prefer[1], l_mac_prefer[2],
						l_mac_prefer[3], l_mac_prefer[4], l_mac_prefer[5]);
		set_prefer();
	}

END_HANDLE:	
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

//检查优先节点是否发生了变化
static int awn_check_prefer_device(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{	
	UINT8 mac_prefer[AWND_MAC_LEN] = {0};
	int parse_status = 0;  
	struct blob_attr *tb[CHECK_PREFER_MAX] = {NULL};
	char* new_prefer_mac = NULL;
	
	parse_status = blobmsg_parse(check_prefer_device_policy, CHECK_PREFER_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_NOTICE("Parse blog msg failed.");
		goto END_HANDLE;
	}

	new_prefer_mac = blobmsg_get_string(tb[CHECK_PREFER]);
	//string->UINT8
	_macaddr_ston_(mac_prefer, new_prefer_mac);

	/* 当前设备的优先节点配置信息变化才进行重新扫描 */
	if(memcmp(l_mac_prefer, mac_prefer, AWND_MAC_LEN) != 0 )
	{
		memcpy(l_mac_prefer, mac_prefer, AWND_MAC_LEN);
		AWN_LOG_NOTICE("l_mac_prefer change ， start to scan");
		awnd_prefer_change_scan();
	}

END_HANDLE:	
	/* 2. return result */
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

static int awn_update_oui(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	AWN_LOG_CRIT("awn_update_oui : start! .");
	int parse_status = 0;
	struct blob_attr *tb[OUI_TYPE_MAX] = {NULL};
	AWND_OUI_TYPE dst_oui = AWND_OLD_OUI;
	int change_oui = 0;
	int update_result ;
	/* 1. get msg */
	parse_status = blobmsg_parse(update_oui_policy, OUI_TYPE_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
		AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

	dst_oui = blobmsg_get_u32(tb[OUI_TYPE]);

	/* 2. check and set status */
	/* check to set flag oui_update_status_fap, oui would be change according to oui_update_status_fap in func update_wifi_tpie_qca(). */
	if (dst_oui == AWND_NEW_OUI && g_awnd.netInfo.oui[1] != 0x31)
	{
		change_oui = 1;
		awnd_set_oui_update_status_fap(OUI_OLD_TO_NEW);
	}
	else if (dst_oui == AWND_OLD_OUI && g_awnd.netInfo.oui[1] != 0x1d)
	{
		change_oui = 1;
		awnd_set_oui_update_status_fap(OUI_NEW_TO_OLD);
	}
	else
	{
		update_result = AWND_OK;
	}	

	/* 3. change fap oui */
	if (change_oui == 1)
	{
                awnd_set_oui_now_version(dst_oui);
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
		update_result = awnd_update_tpie(&g_awnd.netInfo, 0);
#else
		update_result = awnd_update_tpie(&g_awnd.netInfo);
#endif
		AWN_LOG_CRIT("Network change oui to %d with result %d.", dst_oui, update_result);
	}
END_HANDLE:
	/* 4. return result */
	blob_buf_init(&buffer, 0);
	if( update_result == AWND_OK )
	{
		if (change_oui == 0)
		{
			AWN_LOG_CRIT("Network oui is the dst oui %d, no need to change", dst_oui);
		}
		blobmsg_add_u32(&buffer, "success", 0);
	}
	else 
	{
		blobmsg_add_u32(&buffer, "success", -1);
	}
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

static int awn_update_eth_names(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	AWN_LOG_NOTICE("awn_update_eth_names start");
	if(uci_get_profile_eths(l_awnd_config.ethIfnames, MAX_ETH_DEV_NUM)) {
		AWN_LOG_CRIT("%s-%d get profile eths failed\r\n", __func__, __LINE__);
		return AWND_ERROR;
	}

	if ( AWND_ERROR == awn_eth_set_dev(l_awnd_config.lanDevName, l_awnd_config.wanDevName, l_awnd_config.ethIfCnt, l_awnd_config.ethIfnames))
	{
		AWN_LOG_CRIT("fail to init eth dev or pid");
		return AWND_ERROR;
	}

	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

extern AWND_GLOBAL      g_awnd;
extern AWND_CONFIG      l_awnd_config;

static void awn_dump_general(struct blob_buf *buf) {
	void *nested;

	nested = blobmsg_open_table(buf, "general");
	if (nested) {
		blobmsg_add_u32(buf, "workMode", g_awnd.workMode);
		blobmsg_add_u32(buf, "bindStatus", g_awnd.bindStatus);
		blobmsg_add_u32(buf, "link_status", g_awnd.link_status);
		blobmsg_add_u32(buf, "isOnboarding", g_awnd.isOnboarding);
		blobmsg_add_u32(buf, "wifiToHap", g_awnd.wifiToHap);

		blobmsg_close_table(buf, nested);
	}
}

static void awn_dump_conf(struct blob_buf *buf) {
	void *nested;
	char sbuf1[64];

	nested = blobmsg_open_table(buf, "configs");
	if (nested) {
		for(int i=0; i<AWND_BAND_MAX; i++){
			snprintf(sbuf1, sizeof(sbuf1), "apIfnames[%d]", i);
			blobmsg_add_string(buf, sbuf1, l_awnd_config.apIfnames[i]);
			snprintf(sbuf1, sizeof(sbuf1), "staIfnames[%d]", i);
			blobmsg_add_string(buf, sbuf1, l_awnd_config.staIfnames[i]);
			snprintf(sbuf1, sizeof(sbuf1), "configIfnames[%d]", i);
			blobmsg_add_string(buf, sbuf1, l_awnd_config.configIfnames[i]);
		}
		blobmsg_add_u32(buf, "band_num", l_awnd_config.band_num);
		blobmsg_add_u32(buf, "limit_scan_band1", l_awnd_config.limit_scan_band1);
		blobmsg_add_u32(buf, "limit_scan_band4", l_awnd_config.limit_scan_band4);
		blobmsg_add_u32(buf, "debug_level", l_awnd_config.debug_level);

		blobmsg_close_table(buf, nested);
	}
}

static void awn_dump_conn(struct blob_buf *buf) {
	void *nested;
	char sbuf1[64];
	char sbuf2[256];

	nested = blobmsg_open_table(buf, "conn status");
	if (nested) {
		blobmsg_add_u32(buf, "link_status", g_awnd.link_status);
		snprintf(sbuf2, sizeof(sbuf2), MACFMT, MACDAT(g_awnd.fapMac));
		blobmsg_add_string(buf, "fapMac", sbuf2);
		snprintf(sbuf2, sizeof(sbuf2), MACFMT, MACDAT(g_awnd.capMac));
		blobmsg_add_string(buf, "capMac", sbuf2);
		blobmsg_add_u32(buf, "reStage", g_awnd.reStage);
		blobmsg_add_u32(buf, "server_detected", g_awnd.server_detected);
		for(int i=0; i<AWND_BAND_MAX; i++){
			snprintf(sbuf1, sizeof(sbuf1), "connStatus[%d]", i);
			blobmsg_add_u32(buf, sbuf1, g_awnd.connStatus[i]);
			snprintf(sbuf1, sizeof(sbuf1), "staIfnames[%d]", i);
			blobmsg_add_string(buf, sbuf1, l_awnd_config.staIfnames[i]);
			snprintf(sbuf1, sizeof(sbuf1), "staConfig[%d].enable", i);
			blobmsg_add_u32(buf, sbuf1, g_awnd.staConfig[i].enable);
			snprintf(sbuf1, sizeof(sbuf1), "staConfig[%d].bssid", i);
			snprintf(sbuf2, sizeof(sbuf2), MACFMT, MACDAT(g_awnd.staConfig[i].bssid));
			blobmsg_add_string(buf, sbuf1, sbuf2);
			snprintf(sbuf1, sizeof(sbuf1), "staConfig[%d].channel", i);
			blobmsg_add_u32(buf, sbuf1, g_awnd.staConfig[i].channel);
		}

		blobmsg_close_table(buf, nested);
	}
}

static void awn_dump_tpie(struct blob_buf *buf) {
	void *nested;
	char sbuf1[64];

	nested = blobmsg_open_table(buf, "TPIE(netInfo)");
	if (nested) {
		strncpy(sbuf1, g_awnd.netInfo.awnd_label, sizeof(g_awnd.netInfo.awnd_label));
		sbuf1[sizeof(g_awnd.netInfo.awnd_label) - 1] = 0;
		blobmsg_add_string(buf, "awnd_label", sbuf1);
		snprintf(sbuf1, sizeof(sbuf1), "%02X %02X %02X", g_awnd.netInfo.oui[0],
					g_awnd.netInfo.oui[1], g_awnd.netInfo.oui[2]);
		blobmsg_add_string(buf, "oui", sbuf1);
		snprintf(sbuf1, sizeof(sbuf1), MACFMT, MACDAT(g_awnd.netInfo.lan_mac));
		blobmsg_add_string(buf, "lan_mac", sbuf1);
		snprintf(sbuf1, sizeof(sbuf1), MACFMT, MACDAT(g_awnd.netInfo.awnd_mac));
		blobmsg_add_string(buf, "awnd_mac", sbuf1);
		snprintf(sbuf1, sizeof(sbuf1), IPFMT, IPDAT(g_awnd.netInfo.awnd_lanip));
		blobmsg_add_string(buf, "lanip", sbuf1);

		blobmsg_close_table(buf, nested);
	}
}

extern void awn_dump_timer(struct blob_buf *buf);

static int awn_dump(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method, struct blob_attr *msg){
	int parse_status = 0;
	struct blob_attr *tb[DUMP_MAX] = {NULL};
	char* s_category = NULL;

	blob_buf_init(&buffer, 0);
	parse_status = blobmsg_parse(dump_policy, DUMP_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_NOTICE("Parse blog msg failed.");
	} else {
		s_category = blobmsg_get_string(tb[DUMP_CATEGORY]);
	}

	if (!s_category || 0 == strlen(s_category) || 0 == strncmp(s_category, AWN_DUMP_CATEGORY_ALL, SSTR_SIZE(AWN_DUMP_CATEGORY_ALL))) {
		awn_dump_general(&buffer);
		awn_dump_conn(&buffer);
		awn_dump_conf(&buffer);
		awn_dump_tpie(&buffer);
		awn_dump_timer(&buffer);
	} else if (0 == strncmp(s_category, AWN_DUMP_CATEGORY_GENERAL, SSTR_SIZE(AWN_DUMP_CATEGORY_GENERAL))) {
		awn_dump_general(&buffer);
	} else if (0 == strncmp(s_category, AWN_DUMP_CATEGORY_CONN_INFO, SSTR_SIZE(AWN_DUMP_CATEGORY_CONN_INFO))) {
		awn_dump_conn(&buffer);
	} else if (0 == strncmp(s_category, AWN_DUMP_CATEGORY_CONFIG, SSTR_SIZE(AWN_DUMP_CATEGORY_CONFIG))) {
		awn_dump_conf(&buffer);
	} else if (0 == strncmp(s_category, AWN_DUMP_CATEGORY_TIMER, SSTR_SIZE(AWN_DUMP_CATEGORY_TIMER))) {
		awn_dump_timer(&buffer);
	} else if (0 == strncmp(s_category, AWN_DUMP_CATEGORY_TPIE, SSTR_SIZE(AWN_DUMP_CATEGORY_TPIE))) {
		awn_dump_tpie(&buffer);
	}

	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

#ifdef CONFIG_AWN_RE_ROAMING
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

#ifndef CONFIG_AWN_MESH_OPT_SUPPORT
static int mac_str_to_octet(const char *str, int str_len, uint8_t *octet, int octet_len)
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
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/

static int awn_reroam_test(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[REROAM_MAX] = {NULL};
	char *target_mac = NULL;
	uint8_t mac[AWND_MAC_LEN] = {0};

	/* 1. get msg */
	parse_status = blobmsg_parse(reroam_policy, REROAM_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Fail to parse blobmsg.");
		goto END_HANDLE;
	}

	target_mac = blobmsg_get_string(tb[REROAM_TARGETMAC]);
	if (mac_str_to_octet(target_mac, strlen(target_mac) + 1, mac, AWND_MAC_LEN) < 0)
	{
		AWN_LOG_ERR("Fail to transfer mac str(%s) to octects.", target_mac);
		goto END_HANDLE;
	}
	AWN_LOG_INFO("Try to roam to %s", target_mac);
	awnd_re_roam(mac);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);
}
#endif

#ifdef CONFIG_PACKAGE_WIFI_SCHEDULE
static int awn_set_re_connect_policy(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int ret = -1;
	int parse_status = 0;
	RE_CONNECT_POLICY policy = RE_CONN_DEFAULT;
	struct blob_attr *tb[RE_CONN_MAX] = {NULL};
	parse_status = blobmsg_parse(re_connect_policy, RE_CONN_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Parse blog msg failed.");
		goto END_HANDLE;
	}

	policy = blobmsg_get_u32(tb[RE_CONN_DEFAULT]);
	if (policy >= RE_CONNECT_DEFAULT && policy < RE_CONNECT_MAX) {
		g_connect_policy = policy;
		ret = 0;
	} else {
		AWN_LOG_ERR("Invalid policy(%d) for RE connection", policy);
	}

	AWN_LOG_CRIT("awn_set_re_connect_policy: current policy = %d", g_connect_policy);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", ret);

	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}
#endif

static int awn_handle_switch_channel(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	AWND_BAND_TYPE band = AWND_BAND_2G;
	UINT8 channel = 0;
	bool force = false;
	int parse_status = 0;
	struct blob_attr *tb[SWITCH_CAHNNEL_MAX] = {NULL};

	parse_status = blobmsg_parse(switch_channel_policy, SWITCH_CAHNNEL_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Parse blog msg failed.");
		goto END_HANDLE;
	}

	band = blobmsg_get_u32(tb[SWITCH_BAND]);
	channel = blobmsg_get_u32(tb[SWITCH_CHANNEL]);

	if (tb[SWITCH_FORCE]) {
		force = blobmsg_get_bool(tb[SWITCH_FORCE]);
	}

	if (band < AWND_BAND_2G || band >= AWND_BAND_MAX) {
		AWN_LOG_ERR("Invalid band %d.", band);
		goto END_HANDLE;
	}

	if (!channel) {
		AWN_LOG_INFO("Scan radio %d all-channel.", band);
	}

	AWN_LOG_INFO("Update radio %d channel %d", band, channel);

	channel_switch_state_set();
	/* switch channel */
	awnd_switch_channel(band, channel, force);
	channel_switch_state_clear();

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);

	return AWND_OK;
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static int awn_start_ai(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[ALG_POLICY_MAX] = {NULL};
	int alg_policy = 0;
	char *from_mac = NULL;
	uint8_t mac[AWND_MAC_LEN] = {0};

	/* 1. get msg */
	parse_status = blobmsg_parse(ai_start_policy, ALG_POLICY_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Fail to parse blobmsg.");
		goto END_HANDLE;
	}

	/* 2 get ai params */
	if (tb[DEBUG_LEVEL] && blob_data(tb[ALG_POLICY]))
	{
		alg_policy = blobmsg_get_u32(tb[ALG_POLICY]);
	}

	if (tb[ALG_FROM_MAC] && blob_data(tb[ALG_FROM_MAC]))
	{
		from_mac = blobmsg_get_string(tb[ALG_FROM_MAC]);
	}

	AWN_LOG_NOTICE("[info] got start_ai policy %d from mac %s", alg_policy, from_mac);
	awnd_ai_fap_start(alg_policy, from_mac);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

static int ai_awn_set_hops_factor(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
    int parse_status = 0;
    struct blob_attr *tb[AI_HOPS_FACTOR_MAX] = {NULL};
    int hops_factor_int = 0;

    /* 1. get msg */
    parse_status = blobmsg_parse(set_hops_factor_policy, AI_HOPS_FACTOR_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
        AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

    /* 2 get hops_factor_int */
    if (!tb[AI_HOPS_FACTOR] || !blob_data(tb[AI_HOPS_FACTOR]))
    {
        AWN_LOG_ERR("set_hops_factor_policy error.");
        goto END_HANDLE;
    }

    hops_factor_int = blobmsg_get_u32(tb[AI_HOPS_FACTOR]);
    awnd_ai_set_hops_factor(hops_factor_int);
END_HANDLE:
    blob_buf_init(&buffer, 0);
    blobmsg_add_u32(&buffer, "success", 0);
    ubus_send_reply(ctx, req, buffer.head);

    return 0;
}

static int ai_awn_get_hops_factor(struct ubus_context *ctx, struct ubus_object *obj,
    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	float hops_factor;
	hops_factor = awnd_ai_get_hops_factor();
	AWN_LOG_NOTICE("hops factor = [%f]", hops_factor);
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);
	ubus_send_reply(ctx, req, buffer.head);
	return 0;
}

static int awn_first_roaming(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	do_pre_first_roaming();

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

static int awn_link_up_roaming_test(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	awnd_set_tipc_check_time(0);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}

static int awn_ai_delete_re(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	const char *err;
	const char *mac_list[AWND_MAX_GROUP_MEMBER];
	int i = 0;
	struct blob_attr *tb[__TO_DELETE_MAX];
	int rc;
	rc = blobmsg_parse(delete_re_policy, __TO_DELETE_MAX, tb, blob_data(msg), blob_len(msg));
    if (rc < 0)
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    if (!tb[TO_DELETE_MAC])
    {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

	char *s = blobmsg_format_json(tb[TO_DELETE_MAC], true);
	if (!s)
	{
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	struct json_object *to_delete_mac = json_tokener_parse(s);

	if (to_delete_mac && json_object_is_type(to_delete_mac, json_type_array))
	{
		struct json_object *tmp_info = json_object_array_get_idx(to_delete_mac, i);
		while (tmp_info != NULL)
		{
			mac_list[++i] = json_object_get_string(tmp_info);
			tmp_info = json_object_array_get_idx(to_delete_mac, i);
		}
	}

	//TODO:delete_re(mac);
	delete_offline_re_by_mac(mac_list, i);
	json_object_put(to_delete_mac);
}

static int awn_send_nwkout(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[NWKOUT_POLICY_MAX] = {NULL};
	char *src_mac = NULL;
	char *dst_mac = NULL;
	int strategy = 3;

	/* 1. get msg */
	parse_status = blobmsg_parse(nwkout_policy, NWKOUT_POLICY_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Fail to parse blobmsg.");
		goto END_HANDLE;
	}

	if (tb[NWKOUT_SRCMAC]) src_mac = blobmsg_get_string(tb[NWKOUT_SRCMAC]);
	if (tb[NWKOUT_DSTMAC]) dst_mac = blobmsg_get_string(tb[NWKOUT_DSTMAC]);
	if (tb[NWKOUT_STRATEGY]) strategy = blobmsg_get_u32(tb[NWKOUT_STRATEGY]);

	ApAlgInterfaceOutput out = {0};
    //alg_get_lan_mac(out.srcMAC);
    strncpy(out.srcMAC, src_mac, ALG_MAC_LENGTH);
    strncpy(out.dstMAC, dst_mac, ALG_MAC_LENGTH);
    out.algStrategy = strategy;

    AWN_LOG_ERR("[info] active send nwkout:%d, [%12s->%12s]",
                        out.algStrategy,out.srcMAC, out.dstMAC);
    send_nwkout(&out);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;

}

static int awn_set_ai_status(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	struct blob_attr *tb[AI_STATUS_POLICY_MAX] = {NULL};
	int alg_done = 0;
	char *last_mac = NULL;
	int strategy = 3;

	/* 1. get msg */
	parse_status = blobmsg_parse(ai_status_policy, AI_STATUS_POLICY_MAX, tb, blob_data(msg), blob_len(msg));
	if (parse_status < 0)
	{
		AWN_LOG_ERR("Fail to parse blobmsg.");
		goto END_HANDLE;
	}

	if (tb[ALG_DONE])
	{
		alg_done = blobmsg_get_u32(tb[ALG_DONE]);
		set_alg_done(alg_done);
	}
	else
	{
		set_alg_done(!get_alg_done());
	}
	if (tb[LAST_MAC])
	{
		last_mac = blobmsg_get_string(tb[LAST_MAC]);
		set_last_mac(last_mac);
	}
	print_relay_mac();
	//if (tb[NWKOUT_STRATEGY]) strategy = blobmsg_get_u32(tb[NWKOUT_STRATEGY]);

	// ApAlgInterfaceOutput out = {0};
 //    //alg_get_lan_mac(out.srcMAC);
 //    strncpy(out.srcMAC, src_mac, ALG_MAC_LENGTH);
 //    strncpy(out.dstMAC, dst_mac, ALG_MAC_LENGTH);
 //    out.algStrategy = strategy;

 //    AWN_LOG_ERR("[info] active send nwkout:%d, [%12s->%12s]",
 //                        out.algStrategy,out.srcMAC, out.dstMAC);
 //    send_nwkout(&out);

END_HANDLE:
	blob_buf_init(&buffer, 0);
	blobmsg_add_u32(&buffer, "alg_done", get_alg_done());
	blobmsg_add_u32(&buffer, "re_status", get_alg_re_status());
	blobmsg_add_string(&buffer, "last_mac", get_last_mac());
	blobmsg_add_u32(&buffer, "success", 0);	
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;

}

static int awn_set_patc_compensation(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
   	int parse_status = 0;
    struct blob_attr *tb[ALG_PATC_COMP_MAX] = {NULL};
    int patc_compensation_int = 0;

    /* 1. get msg */
    parse_status = blobmsg_parse(set_patc_comp_policy, ALG_PATC_COMP_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
        AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

    /* 2 get hops_factor_int */
    if (!tb[ALG_PATC_COMP] || !blob_data(tb[ALG_PATC_COMP]))
    {
        AWN_LOG_ERR("set_hops_factor_policy error.");
        goto END_HANDLE;
    }

    patc_compensation_int = blobmsg_get_u32(tb[ALG_PATC_COMP]);
    awnd_ai_set_patc_comp(patc_compensation_int);
END_HANDLE:
    blob_buf_init(&buffer, 0);
    blobmsg_add_u32(&buffer, "success", 0);
    ubus_send_reply(ctx, req, buffer.head);

    return 0;
}

static int awn_test_ping(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int ret = awnd_test_ping_rootap();

	blob_buf_init(&buffer, 0);
	if (ret) {
		blobmsg_add_u32(&buffer, "fail", 0);	
	} else {
		blobmsg_add_u32(&buffer, "success", 0);
	}
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT	*/

void awn_handle_topology_change_event(struct ubus_context *ctx, struct ubus_event_handler *ev,
				  const char *type, struct blob_attr *msg)
{
	AWN_LOG_INFO("handle device online or offline event");
	UINT8 macZero[AWND_MAC_LEN] = {0};
	if(((memcmp(g_awnd.rootAp[AWND_BAND_2G].lan_mac, l_mac_prefer, AWND_MAC_LEN) == 0) || 
		(memcmp(g_awnd.rootAp[AWND_BAND_5G].lan_mac, l_mac_prefer, AWND_MAC_LEN) == 0)) 
		&& memcmp(l_mac_prefer, macZero, AWND_MAC_LEN) != 0)
	{
		AWN_LOG_INFO("connected with prefer deivce, do nothing");
		return;
	}
	if (g_awnd.ethStatus != AWND_STATUS_CONNECTED 
		&& g_awnd.ethStatus != AWND_STATUS_CONNECTING) {
		awnd_start_scan_new();
	} else {
		AWN_LOG_INFO("eth connected, do noting");
	}
}

void ubus_add_probe_info_event(struct ubus_context *ctx)
{
	int ret = 0;
	AWN_LOG_NOTICE("set probe event handler");
	memset(&togology_change_event_handler, 0, sizeof(togology_change_event_handler));
	togology_change_event_handler.cb = awn_handle_topology_change_event;

	if (ret = ubus_register_event_handler(ctx, &togology_change_event_handler, TOPOLOGY_CHANGE_EVENT))
	{
		AWN_LOG_ERR("Failed to publish TOPOLOGY_CHANGE_EVENT handler, continue awn process: %s\n", ubus_strerror(ret));
	}
}
int awn_preconfig_opt(struct ubus_context *ctx, struct ubus_object *obj,
		    	struct ubus_request_data *req, const char *method, struct blob_attr *msg)
{
	int parse_status = 0;
	int operation = 0;
	int value = 0;
	struct blob_attr *tb[PRECONFIG_OP_MAX] = {NULL};
	int ret_val = 0;
	char *title = "Hello buddy";

	/* 1. get msg */
	parse_status = blobmsg_parse(preconfig_opt, PRECONFIG_OP_MAX, tb, blob_data(msg), blob_len(msg));
    if (parse_status < 0)
    {
		AWN_LOG_ERR("Parse blog msg failed.");
        goto END_HANDLE;
    }

	/* 2 get operation setting */
	if (tb[OPERATION] && blob_data(tb[OPERATION]))
	{
		operation = blobmsg_get_u32(tb[OPERATION]);
	}
	else
	{
		show_preconfig_usage();
		goto END_HANDLE;
	}
	
	/* 2 get value setting */
	if (tb[VALUE] && blob_data(tb[VALUE]) )
	{
		value = blobmsg_get_u32(tb[VALUE]);
	}

	/* 3 processing */
	if(operation == 1)//get get rootap link info
	{
		title = "rootap link status";
		ret_val = get_rootap_link_info(&isp_dcmp_preconfig);
	}
	if(operation == 2)//get preconfig vap state
	{
		title = "preconfig vap state";
		ret_val = (int)get_preconfig_vap_state();
	}
	else if(operation == 11)//if write md5s to wifi driver
	{
		title = "control md5";
		isp_dcmp_preconfig.is_add_md5 = value;
		ret_val = isp_dcmp_preconfig.is_add_md5;
	}
	else if(operation == 12)//change rootap
	{
		title = "change rootap";
		ret_val = 0;
		/* experiment under testing */
		change_rootap();
	}
	else if(operation == 13)//update ip segment to kmod_preconfig_hook
	{
		title = "update ip limitation";
		ret_val = update_preconfig_hook_lan();
	}
	else
	{
		show_preconfig_usage();
	}

END_HANDLE:	
	blob_buf_init(&buffer, 0);
	if(operation == 1)
	{
		AWN_LOG_INFO("%s:%d", title, isp_dcmp_preconfig.rootap_link_state);
		AWN_LOG_INFO("%s:%d", title, isp_dcmp_preconfig.rootap_link_type);
		blobmsg_add_u32(&buffer, "link_state", isp_dcmp_preconfig.rootap_link_state);
		blobmsg_add_u32(&buffer, "link_type", isp_dcmp_preconfig.rootap_link_type);
	}
	else
	{
		AWN_LOG_INFO("%s:%d", title, ret_val);
		blobmsg_add_u32(&buffer, "state", ret_val);	
	}
	ubus_send_reply(ctx, req, buffer.head);
	
	return AWND_OK;
}
/***************************************************************************/
/*                    PUBLIC_FUNCTIONS                  */
/***************************************************************************/

/*
 *\fn           awn_start_ubus_server
 *\brief        start the ubus server
 *
 *\param[in]    N/A
 *\param[out]   N/A
 *
 *\return       N/A
 */
int awn_start_ubus_server(struct ubus_context *ctx)
{
    int ret = AWND_ERROR;

    ubus_add_uloop(ctx);
	
	ret = ubus_add_object(ctx, &awn_object);
    if (ret != 0)
    {
        fprintf(stderr, "awn: Failed to publish object: %s\n", ubus_strerror(ret));
		goto ERROR_HANDLE;
    }

	ubus_add_probe_info_event(ctx);

    return AWND_OK;

ERROR_HANDLE:
	if (ctx)
		ubus_free(ctx);

    return AWND_ERROR;
}

/***************************************************************************/
/*                    GLOBAL_FUNCTIONS                  */
/***************************************************************************/

