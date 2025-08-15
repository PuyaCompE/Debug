/******************************************************************************
*
* Copyright (c) 2017 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   plcson_netlink.h
* VERSION    :   1.0
* DESCRIPTION:   Handle message for PLC SON
*
* AUTHOR     :   wengkaiping <wengkaiping@tp-link.com.cn>
* CREATE DATE:   19/01/2016
*
* HISTORY    :
* 01   19/01/2017 wengkaiping		Create.
*
******************************************************************************/

#ifndef _AWN_PlCSON_NETLINK_H
#define _AWN_PlCSON_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/* netlink define */
/* netlink port */
#define NETLINK_NEIGHBOR_DISCOVER            ( 32 )
#define NETLINK_NEIGHBOR_DISCOVER_EVENT      ( 33 )
#define NLEVENT_INVALID_PID -1



/* netlink message type */
enum {
    NEIGHBOR_SET_EVENT_PID = 1,
    NEIGHBOR_SET_PLC_DEV,
    NEIGHBOR_SET_ETH_DEV,
    NEIGHBOR_SET_NET_INFO,
    NEIGHBOR_SET_PLC_DETECT_PARAM,
    NEIGHBOR_SET_PLC_REPORT_PARAM,
    NEIGHBOR_GET_PLC_GET_NEIGH,
    NEIGHBOR_SET_ETH_DETECT_PARAM,
    NEIGHBOR_SET_ETH_REPORT_PARAM,
    NEIGHBOR_SET_ETH_FORWARD_PARAM,
    NEIGHBOR_GET_ETH_GET_NEIGH,
    NEIGHBOR_SET_MESH_ENABLE,
    NEIGHBOR_SET_NOTIFY_EVENT_PID,
    NEIGHBOR_SET_NOTIFY_PARAM,
    NEIGHBOR_SET_SA_EVENT_PID,
    NEIGHBOR_SET_SA_MSG_PARAM,
};


/* netlink event type */
enum {
	PLC_EVENT_UPDATE_NEIGH,
	PLC_EVENT_AGEOUT_NEIGH,
	ETH_EVENT_UPDATE_NEIGH,
	ETH_EVENT_AGEOUT_NEIGH,	
};


struct neigh_info {
    u_int8_t            net_type;                     /* subnet type:FAP,HAP,RE */
    u_int8_t            weight;                       /* weight calculated by previous mode*/    
    u_int8_t            level;                        /* level in the subnet  */
    u_int8_t            net_mac[6];                   /* mac of the subnet */
    u_int8_t            net_label[16];                /* label of the subnet */ 
    u_int32_t           lanip;                         /* lan ip of AP*/
    u_int8_t            server_detected;                /* is server detected */
    u_int32_t           server_touch_time;              /* server detect time */
    u_int32_t           dns;                            /* dns of AP*/
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
    u_int32_t           link_speed;                      /* link_speed of eth port */
    unsigned long       tx_speed;                        /* tx_speed of eth port */
    unsigned long       rx_speed;                        /* rx_speed of eth port */
#endif
    u_int32_t           plc_bkhl_vlanid;                 /* plc backhaul vlan id*/
}; 

struct plc_neigh_info {
    u_int8_t            lan_mac[6];                   /* mac of lan */    
    u_int8_t            plc_mac[6];                   /* mac of plc */
    u_int8_t            plc_root;    
    struct neigh_info   plc_info;    
};

struct eth_neigh_info {
    u_int8_t             lan_mac[6];                   /* mac of plc */ 
    u_int8_t             nh_dir;       
    char                 dev_name[IFNAMSIZ]; 
    u_int16_t            uplink_mask;                  /* wifi: 1 << 1, PLC: 1<< 2; ETH: 1<<3  */
    u_int16_t            uplink_rate;  
    struct neigh_info    eth_info;        
    u_int8_t             forward_num;                   /* num of eth pkt forward */
    u_int8_t             forwarder[6];
};

struct __neigh_info_global {
    u_int8_t            lan_mac[6];                   /* mac of lan */
    u_int8_t            plc_mac[6];                   /* mac of plc */    
    u_int8_t            plc_root;
    u_int16_t           uplink_mask;      /* wifi: 1 << 1, PLC: 1<< 2; ETH: 1<<3  */
    u_int16_t           uplink_rate;
    u_int8_t            mesh_type;
    struct neigh_info   info;    
};


struct __event_info {
	u_int32_t event_pid;
};

struct __config_mesh_enable {
    u_int8_t mesh_type;
    u_int8_t mesh_enable;
};

struct __dev_param {
    char  lanname[IFNAMSIZ];
    char  wanname[IFNAMSIZ]; 
    char  ethname[MAX_ETH_DEV_NUM][IFNAMSIZ]; 
};

struct __report_param {
    u_int8_t  report_enable;
    u_int32_t report_interval;
};

struct __forward_param {
    u_int8_t  forward_enable;
};

struct __detect_param {
    u_int8_t   detect_enable;
    u_int8_t   event_notify_enable;      
	u_int32_t  aging_time;     
};

struct __neigh_tbl {
    u_int32_t cnt;      
    struct plc_neigh_info neigh_tbl[ 0 ];  
};

struct __neigh_eth_tbl {
    u_int32_t cnt;      
    struct eth_neigh_info neigh_tbl[ 0 ];  
};


int awn_plc_get_capacity(UINT8 *plcMac, UINT8 *peerMac, UINT16 *txRate, UINT16 *rxRate);
extern AWND_PLC_NEIGH *awnd_find_plc_neigh(AWND_PLC_NEIGH *neigh_tbl, UINT8 * mac, UINT8 alloced);
extern int netlink_event_listen(int *sock_fd);
extern int awnd_plc_event_recv(AWND_PLC_NEIGH  *neigh_tbl, int fd);

extern int32_t awn_plcson_get_neigh_tbl(AWND_PLC_NEIGH  *neigh_tbl);

extern int32_t awn_plcson_set_dev(const char* devName);
extern int32_t awn_plcson_set_report_param(u_int8_t report_enable, u_int32_t report_interval);
extern int32_t awn_plcson_set_detect_param(u_int8_t detect_enable, u_int8_t notify_enable, u_int32_t aging_time);
extern int32_t awn_set_net_info(u_int8_t *lan_mac, u_int8_t *plc_mac, u_int8_t isPlcRoot, u_int16_t uplinkMask, 
                         u_int16_t uplinkRate, AWND_NET_INFO *pAwndNetInfo, u_int8_t meshType);
extern int32_t awn_plcson_set_pid(u_int32_t pid);
extern int32_t awn_plcson_set_eth_mesh_enable(u_int8_t meshType, u_int8_t configEnable);

extern int32_t awn_eth_set_report_param(u_int8_t report_enable, u_int32_t report_interval);
extern int32_t awn_eth_set_detect_param(u_int8_t detect_enable, u_int8_t notify_enable, u_int32_t aging_time);
extern int32_t awn_eth_set_forward_param(u_int8_t forward_enable);
int32_t awn_eth_set_dev(const char* lanName, const char* wanName, int ethNum, char ethName[][IFNAMSIZ]);
int32_t awn_eth_get_neigh_tbl(AWND_ETH_NEIGH  *neigh_tbl, UINT8 *label, UINT8 * preconf_label);

extern int awnd_config_get_plc_backhaul(char *plc_backhaul);
int awn_get_lan_ip(UINT32 *lanIP);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PLCSON_NETLINK_H_ */
