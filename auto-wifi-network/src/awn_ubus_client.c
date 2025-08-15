/*!Copyright(c) 2013-2014 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     awn_ubus_client.c
 *\brief    auto-wifi-network
 *
 *\author   dengzhong@tp-link.com.cn
 *\version  v1.0
 *\date     02Jan18
 *
 *\history  \arg 1.0, 02Jan18, create the file.
 *                  
 */
/***************************************************************************/
/*                      CONFIGURATIONS                   */
/***************************************************************************/


/***************************************************************************/
/*                      INCLUDE_FILES                    */
/***************************************************************************/
#include    <sys/time.h>
#include    <unistd.h>
#include    <string.h>
#include 	<json-c/json.h>
#include    <libubox/ustream.h>
#include    <libubox/blobmsg_json.h>

#include "auto_wifi_net.h"
#include "awn_log.h"
#include "awn_ubus.h"

#include "jsonutl.h"

/***************************************************************************/
/*                      DEFINES                      */
/***************************************************************************/
/* ubus的socket */
#define UBUS_PATH 		"/var/run/ubus.sock"

/* network.interface.lan or  network.interface.wan */
#define NETWORK_INTERFACE		"network.interface.%s"
/***************************************************************************/
/*                      TYPES                            */
/***************************************************************************/


/***************************************************************************/
/*                      EXTERN_PROTOTYPES                    */
/***************************************************************************/
extern AWND_GLOBAL g_awnd;

/***************************************************************************/
/*                      LOCAL_PROTOTYPES                     */
/***************************************************************************/
/*!
 *\fn           static void _receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
 *\brief        接收服务器返回的数据
 *\return       none
 */
static void _receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg);

/*!
 *\fn           static void _client_main(void)
 *\brief        发送请求，接收回复
 *\return       none
 */
static void _client_main(void);

/***************************************************************************/
/*                      VARIABLES                        */
/***************************************************************************/
/* ubus上下文 */
static struct ubus_context *ctx = NULL;

/* ubus传递参数 */
static struct blob_buf b;

static u_int32_t    g_uptime = 0;
static u_int8_t     l_server_detected;         /* server detect fail/sucess */
static u_int32_t    l_server_touch_time;       /* server detect success time*/
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static u_int32_t    l_client_cnt;         /* client counts of single device */
#endif
static BOOL         fap_preconfig_state;
/***************************************************************************/
/*                      LOCAL_FUNCTIONS                  */
/***************************************************************************/

/*!
 *\fn           static void _receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
 *\brief        接收服务器返回的数据
 *\return       none
 */
static void _receive_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct json_object *root = NULL;
    struct json_object *para = NULL;
    char  *jtok = NULL;

    if (!msg)
    {
    	AWN_LOG_ERR("_receive_call_result_data msg is NULL");
        return;
    }
        
	jtok = blobmsg_format_json(msg, true);
	if (NULL == jtok)
	{
		AWN_LOG_ERR("Invalid Message (null).");
		return;
	}

	root = json_tokener_parse(jtok);

	if (root)
	{
		para = json_object_object_get(root, "uptime");
		if (para)
		{
			g_uptime = json_object_get_int(para);
			//AWN_LOG_INFO("=====uptime = %ld", g_uptime);
		}
		else
		{
			g_uptime = 0;
			goto out;
		}
	}

out:
	if (root)
		json_object_put(root);
	if (jtok)
		free(jtok);

}

/*!
 *\fn           static void _get_uptime(struct ubus_request *req, int type, struct blob_attr *msg)
 *\brief        发送请求，接收回复
 *\return       none
 */
static void _get_uptime(void)
{
    uint32_t id;
	char network_interface[128] = {0};

    if(AWND_SYSMODE_AP == g_awnd.sysMode)
    {	/*AP mode*/
    	sprintf(network_interface, NETWORK_INTERFACE, "lan");
    }
    else
    {	/* Router mode*/
    	sprintf(network_interface, NETWORK_INTERFACE, "wan");
    }

    /* 查找xxxx服务，将其id写入变量id */
    if (ubus_lookup_id(ctx, network_interface, &id)) {
        AWN_LOG_ERR("dos:Failed to look up stats object\n");
        return;
    }

    /* 初始化要发给服务器的参数 */
    blob_buf_init(&b, 0);

    /* 向服务器发送请求 （阻塞式，收到回复才会返回）*/
    /*
    #1：上下文
    #2：服务器ID
    #3：请求的远程方法名
    #4：传递给远程方法的参数
    #5：注册接收服务器回传数据的函数
    #6：priv，在add的时候用来存放object
    #7：超时时间
    */

    ubus_invoke(ctx, id, "status", b.head,  _receive_call_result_data, 0, 3000);
    return;
}


/*!
 *\fn           static void _receive_call_result_server_detct(struct ubus_request *req, int type, struct blob_attr *msg)
 *\brief        接收服务器返回的数据
 *\return       none
 */
static void _receive_call_result_server_detct(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct json_object *root = NULL;
    struct json_object *para = NULL;
    char  *jtok = NULL;

    if (!msg)
    {
        AWN_LOG_ERR("_receive_call_result_data msg is NULL");
        return;
    }
        
    jtok = blobmsg_format_json(msg, true);
    if (NULL == jtok)
    {
        AWN_LOG_ERR("Invalid Message (null).");
        return;
    }

    root = json_tokener_parse(jtok);
    if (root)
    {
        para = json_object_object_get(root, "status");
        if (para)
        {
            l_server_detected = json_object_get_int(para);
            AWN_LOG_INFO("=====server_detected = %d", l_server_detected);
        }

        para = json_object_object_get(root, "duration");
        if (para)
        {
            l_server_touch_time = json_object_get_int(para);
            AWN_LOG_INFO("=====server_touch_time = %ld", l_server_touch_time);
        }
    }

out:
    if (root)
        json_object_put(root);
    if (jtok)
        free(jtok);

}

/*!
 *\fn           static void _get_server_detect()
 *\brief        发送请求，接收回复
 *\return       none
 */
static void _get_server_detect(void)
{
    uint32_t id;

    /* 查找xxxx服务，将其id写入变量id */
    if (ubus_lookup_id(ctx, "server-probe", &id)) {
        AWN_LOG_ERR("dos:Failed to look up stats object\n");
        return;
    }

    /* 初始化要发给服务器的参数 */
    blob_buf_init(&b, 0);

    ubus_invoke(ctx, id, "get", b.head,  _receive_call_result_server_detct, NULL, 3000);
    return;
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
static void _receive_call_result_client_count(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct json_object *root = NULL;
    char *jtok = NULL;

    if (!msg)
    {
        AWN_LOG_ERR("_receive_call_result_client_count msg .");
        return;
    }

    jtok = blobmsg_format_json(msg, true);
    if (NULL == jtok)
    {
        AWN_LOG_ERR("Invalid message (null).");
        return;
    }

    root = json_tokener_parse(jtok);
    if (root)
    {
        l_client_cnt = json_object_array_length(root);
        AWN_LOG_INFO("==== client cnt = %d", l_client_cnt);
    }

out:
    if (root)
        json_object_put(root);
    if (jtok)
        free(jtok);
}

static void _get_client_cnt(void)
{
    uint32_t id;

    if (ubus_lookup_id(ctx, "client_mgmt", &id)) {
        AWN_LOG_ERR("dos:Failed to look up stats object\n");
        return;
    }

    blob_buf_init(&b, 0);

    ubus_invoke(ctx, id, "get_myself", b.head, _receive_call_result_client_count, NULL, 3000);
    return;
}
#endif /*  CONFIG_AWN_MESH_OPT_SUPPORT */

/*
 * function:    _receive_call_result_preconfig
 * brief:       reveive data from server
 * description: to record fap's preconfig vap state in BOOL fap_preconfig_state
 */
//#ifdef CONFIG_DCMP_PRECONFIG_support
static void _receive_call_result_preconfig(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct json_object *root = NULL;
    struct json_object *para = NULL;
    char  *jtok = NULL;
    static int lost_sync_list_count = 0;

    if (!msg)
    {
        AWN_LOG_ERR("_receive_call_result_preconfig msg is NULL");
        return;
    }
        
    jtok = blobmsg_format_json(msg, true);
    if (NULL == jtok)
    {
        AWN_LOG_ERR("Invalid Message (null).");
        return;
    }

    root = json_tokener_parse(jtok);
    if (root)
    {
        lost_sync_list_count = 0;
        BOOL is_mix_finded = false;
        json_object_object_foreach(root, key, val)
        {
            const char *role = NULL;
            int mix = NULL;
            AWN_LOG_NOTICE("preconfig ubus call sync list: %s", json_object_to_json_string(val));
            AWN_LOG_NOTICE("preconfig ubus call sync list: %s", key);
            role = json_object_get_string(json_object_object_get(val, "role"));
            AWN_LOG_NOTICE("role: %s", role);
            if(strncmp(role, "AP",sizeof(role)) == 0)
            {
                AWN_LOG_NOTICE("!!!AP: %s", key);
                /* 
                * 'mix' segment represents for multiple meanings
                * for now it only represents for fap preconfig state
                */
                if((para = json_object_object_get(val, "mix")) != NULL)
                {
                    is_mix_finded = true;
                    mix = json_object_get_int(para);
                    /* TBD:bit operation */
                    fap_preconfig_state = (BOOL)(mix&(1<<0));
                }
                AWN_LOG_NOTICE("!!!AP: %d", mix);
            }
        }
        if(!is_mix_finded)
        {
            fap_preconfig_state = false;
        }
    }
    else
    {
        lost_sync_list_count++;
        if(lost_sync_list_count > 2)
        {
            lost_sync_list_count = 3;
            fap_preconfig_state = false;
        }
        AWN_LOG_ERR("preconfig no ubus call sync list found");
        AWN_LOG_ERR("set fap_preconfig_state = false");
    }

    if (root)
        json_object_put(root);
    if (jtok)
        free(jtok);
}

/*!
 *\fn           static BOOL _get_preconfig_state()
 *\brief        send request and receive ack
 *\return       none
 */
static BOOL _get_preconfig_state(void)
{
    uint32_t id;

    /* find xxxx service，set id into variable id */
    if (ubus_lookup_id(ctx, "sync", &id)) {
        AWN_LOG_ERR("dos:Failed to look up sync object\n");
        return;
    }

    /* init params to be send to server */
    blob_buf_init(&b, 0);

    ubus_invoke(ctx, id, "list", b.head,  _receive_call_result_preconfig, NULL, 3000);

    return fap_preconfig_state;
}
//#endif
/***************************************************************************/
/*                      GLOBAL_FUNCTIONS                     */
/***************************************************************************/
/*!
 *\fn           int dosd_ubus_get_stat()
 *\brief        get tf stat into g_stat_entry_list
 *\return       none
 */
int awnd_ubus_get_uptime(u_int32_t *uptime)
{

    /* 初始化 */
    ctx = ubus_connect(UBUS_PATH);
    if (!ctx) {
        AWN_LOG_ERR("Failed to connect to ubus\n");
        return -1;
    }

    g_uptime = 0;

    /* client发送请求 */
    _get_uptime();

    *uptime = g_uptime;

    /* 退出 */
    ubus_free(ctx);

    return 0;
}

/*!
 *\fn           int awnd_ubus_get_server_detect()
 *\brief        get tf stat into g_stat_entry_list
 *\return       none
 */
int awnd_ubus_get_server_detect(u_int8_t *server_detected, u_int32_t *server_touch_time)
{

    /* 初始化 */
    ctx = ubus_connect(UBUS_PATH);
    if (!ctx) {
        AWN_LOG_ERR("Failed to connect to ubus\n");
        return -1;
    }

    l_server_detected = 0;
    l_server_touch_time = 0;

    /* client发送请求 */
    _get_server_detect();

    *server_detected    = l_server_detected;
    *server_touch_time  = l_server_touch_time;

    /* 退出 */
    ubus_free(ctx);

    return 0;
}

/*!
 *\fn           int awnd_ubus_get_preconfig()
 *\brief        get awnd_ubus_get_preconfig_state_from_fap
 *\return       none
 */
//#ifdef CONFIG_DCMP_PRECONFIG_support
int awnd_ubus_get_preconfig()
{
    /* init */
    ctx = ubus_connect(UBUS_PATH);
    if (!ctx) {
        AWN_LOG_ERR("Failed to connect to ubus\n");
        return -1;
    }

    /* client send request */
    BOOL state = _get_preconfig_state();

    /* exit */
    ubus_free(ctx);

    return state;
}
//#endif

void awnd_ubus_send_smartip_event(int action, int status)
{
    json_object_t *root = NULL;
    char buf[128];

    root = JSON_CREATE_OBJECT();
    if(!root)
    {
        AWN_LOG_ERR("Fail to create object");
        return;
    }

    JSON_ADD_NUMBER_TO_OBJECT(root, "action", action);
    JSON_ADD_NUMBER_TO_OBJECT(root, "status", status);

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "ubus send smartip '%s'", JSON_OBJECT_TO_STRING(root));
    system(buf);

    AWN_LOG_INFO("%s", buf);

    if (root)
        JSON_DELETE(root);
}

#ifdef CONFIG_AWN_MESH_OPT_SUPPORT
int awnd_ubus_get_client_count(u_int32_t *cnt)
{
    ctx = ubus_connect(UBUS_PATH);
    if (!ctx) {
        AWN_LOG_ERR("Fail to connect to ubus\n");
        return -1;
    }

    _get_client_cnt();

    *cnt = l_client_cnt;

    ubus_free(ctx);

    return 0;
}
#endif /* CONFIG_AWN_MESH_OPT_SUPPORT */
