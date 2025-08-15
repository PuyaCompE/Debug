/*!Copyright(c) 2017 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file      awn_plcson_handler.c
 *\brief     
 *
 *\author    Weng Kaiping
 *\version   1.0.0
 *\date      03Jan17
 *
 *\history \arg 1.0.0, 03Jan17, Weng Kaiping, Create the file. 
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h> 

#include "plcApi.h"

#include "auto_wifi_net.h"
#include "awn_plcson_netlink.h"
#include "awn_log.h"
/***************************************************************************/
/*                        DEFINES                                          */
/***************************************************************************/
#define AWN_NETLINK_MESSAGE_SIZE( x )		( NLMSG_LENGTH(0) + x )
#define IEEE80211_ELEMID_VENDOR 		221

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/



/***************************************************************************/
/*                        LOCAL_PROTOTYPES                                 */
/***************************************************************************/

/***************************************************************************/
/*                        VARIABLES                                        */
/***************************************************************************/
extern int oui_now_version;
extern IEEE80211_TP_OUI_LIST tp_oui_list[TP_OUI_MAX_VERSION+1];
/***************************************************************************/
/*                        LOCAL FUNCTIONS                                  */
/***************************************************************************/
int awn_plc_get_capacity(UINT8 *plcMac, UINT8 *peerMac, UINT16 *txRate, UINT16 *rxRate)
{
    int index;
    PLC_DEV_BASE localDev={0};
	PLC_RMT_DEV_INFO networkInfo;

    *txRate = 0;
    *rxRate = 0;
    
    memcpy(localDev.mac, plcMac, AWND_MAC_LEN);
    
	if (plcGetNtwInfo(&localDev, &networkInfo) == PLC_OK)
	{
		AWN_LOG_DEBUG("The number of remote devices in the network is %d\n", networkInfo.rmtDevNum);
		for (index = 0; index < networkInfo.rmtDevNum; index++)
		{
			AWN_LOG_DEBUG("host: %02X:%02X:%02X:%02X:%02X:%02X	avgRx is %d	avgTx is %d\n", networkInfo.rmtDev[index].dev.mac[0], networkInfo.rmtDev[index].dev.mac[1], networkInfo.rmtDev[index].dev.mac[2], 
						networkInfo.rmtDev[index].dev.mac[3], networkInfo.rmtDev[index].dev.mac[4], networkInfo.rmtDev[index].dev.mac[5], 
						networkInfo.rmtDev[index].avgRx, networkInfo.rmtDev[index].avgTx);		
		    if (!memcmp(networkInfo.rmtDev[index].dev.mac, peerMac, AWND_MAC_LEN)) {
                  *txRate = networkInfo.rmtDev[index].avgTx * 16 / 21;
                  *rxRate = networkInfo.rmtDev[index].avgRx * 16 / 21;                  
                  return AWND_OK;
            }
		}
	}

    return AWND_ERROR;

}

void awnd_clean_plc_neigh_new_flag(AWND_PLC_NEIGH *neigh_tbl)
{
    int i = 0;
    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++)
    {
        neigh_tbl[i].isNew = 0;            
    }
}

AWND_PLC_NEIGH *awnd_find_plc_neigh(AWND_PLC_NEIGH *neigh_tbl, UINT8 * mac, UINT8 alloced)
{
    int i = 0;
    AWND_PLC_NEIGH *pn = NULL;

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++)
    {
        if (AWND_NEIGH_CLEAR != neigh_tbl[i].flag && _mac_raw_equal(mac, neigh_tbl[i].lan_mac)) {
            pn = &(neigh_tbl[i]);
            break;
        }            
    }

    if (NULL == pn && alloced){
        for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
            if (AWND_NEIGH_CLEAR == neigh_tbl[i].flag) {
                pn = &(neigh_tbl[i]);
                pn->isNew = 1;
                break;
            }
        }
    }

    return pn;
}


int awnd_update_plc_neigh(AWND_PLC_NEIGH *neigh_tbl, struct plc_neigh_info *pni)
{
    AWND_PLC_NEIGH *pn = NULL;

    pn = awnd_find_plc_neigh(neigh_tbl, pni->lan_mac, 1);
    if (NULL != pn) {
        memcpy(pn->lan_mac, pni->lan_mac, AWND_MAC_LEN);        
        memcpy(pn->plc_mac, pni->plc_mac, AWND_MAC_LEN);
        pn->plcRoot = pni->plc_root;
        pn->flag = AWND_NEIGH_VALID;
        if ((pn->netInfo.awnd_net_type == AWND_NET_LRE && pni->plc_info.net_type <= AWND_NET_HAP)
            || pn->netInfo.awnd_level != pni->plc_info.level)
            pn->isNew = 1;
                
        memcpy(pn->netInfo.awnd_mac, pni->plc_info.net_mac, AWND_MAC_LEN);
        memcpy(pn->netInfo.awnd_label, pni->plc_info.net_label, AWND_LABEL_LEN);
        pn->netInfo.awnd_net_type = pni->plc_info.net_type;        
        pn->netInfo.awnd_weight   = pni->plc_info.weight;
        pn->netInfo.awnd_level    = pni->plc_info.level;
        pn->netInfo.awnd_lanip    = pni->plc_info.lanip;
        pn->netInfo.server_detected      = pni->plc_info.server_detected;
        pn->netInfo.server_touch_time    = pni->plc_info.server_touch_time;
        pn->netInfo.awnd_dns      = pni->plc_info.dns;
        pn->netInfo.id  = IEEE80211_ELEMID_VENDOR;
        pn->netInfo.len = sizeof(AWND_NET_INFO) -2;
        pn->netInfo.oui[0] = 0x00;
        pn->netInfo.oui[1] = 0x1d;
        pn->netInfo.oui[2] = 0x0f;
        pn->netInfo.type = 0x01;        

        if(WIFI_REPEATER == awnd_config_get_mode())
        {
            if(pni->plc_info.plc_bkhl_vlanid > 0)
            {
                awnd_update_plc_backhaul(pni->plc_info.plc_bkhl_vlanid);
            }
        }
            
        AWN_LOG_INFO("lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, plc_mac:%02X:%02X:%02X:%02X:%02X:%02X, \
               net_type:%d, weight:%d, level:%d, lanip:%x, net_mac:%02X:%02X:%02X:%02X:%02X:%02X, label:%s\n, isNew:%d, \
               server_detected:%d, server_touch_time:%d, dns:%x",
               pni->lan_mac[0], pni->lan_mac[1], pni->lan_mac[2], pni->lan_mac[3], pni->lan_mac[4], pni->lan_mac[5],               
               pni->plc_mac[0], pni->plc_mac[1], pni->plc_mac[2], pni->plc_mac[3], pni->plc_mac[4], pni->plc_mac[5],
               pni->plc_info.net_type, pni->plc_info.weight, pni->plc_info.level, pni->plc_info.lanip,
               pni->plc_info.net_mac[0], pni->plc_info.net_mac[1], pni->plc_info.net_mac[2], 
               pni->plc_info.net_mac[3], pni->plc_info.net_mac[4], pni->plc_info.net_mac[5], 
               pni->plc_info.net_label, pn->isNew, pni->plc_info.server_detected, pni->plc_info.server_touch_time,
               pni->plc_info.dns);
            
        return AWND_OK;
    }
    else {
        AWN_LOG_WARNING("Can't find plc neigh:%02x-%02x-%02x-%02x-%02x-%02x", pni->lan_mac[0],
            pni->lan_mac[1],pni->lan_mac[2], pni->lan_mac[3], pni->lan_mac[4], pni->lan_mac[5]);
        return AWND_ERROR;
    }
}

int awnd_update_plc_neigh_tbl(AWND_PLC_NEIGH *neigh_tbl, struct plc_neigh_info *pnt, UINT32 cnt)
{
    AWND_PLC_NEIGH *pn = NULL;
    int i;

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_VALID == neigh_tbl[i].flag)
            neigh_tbl[i].flag= AWND_NEIGH_AGING;
    }

    for (i = 0; i < cnt; i++) {
        awnd_update_plc_neigh(neigh_tbl, &pnt[i]);
    }

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_AGING == neigh_tbl[i].flag)
            neigh_tbl[i].flag= AWND_NEIGH_CLEAR;
    }

    return AWND_OK;
}

AWND_ETH_NEIGH *awnd_find_eth_neigh(AWND_ETH_NEIGH *neigh_tbl, UINT8 * mac, UINT8 alloced)
{
    int i = 0;
    AWND_ETH_NEIGH *pn = NULL;

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++)
    {
        if (AWND_NEIGH_CLEAR != neigh_tbl[i].flag && _mac_raw_equal(mac, neigh_tbl[i].lan_mac)) {
            pn = &(neigh_tbl[i]);
            break;
        }            
    }

    if (NULL == pn && alloced){
        for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
            if (AWND_NEIGH_CLEAR == neigh_tbl[i].flag) {
                pn = &(neigh_tbl[i]);
                break;
            }
        }
    }

    return pn;
}


int awnd_update_eth_neigh(AWND_ETH_NEIGH *neigh_tbl, struct eth_neigh_info *pni)
{
    AWND_ETH_NEIGH *pn = NULL;

    pn = awnd_find_eth_neigh(neigh_tbl, pni->lan_mac, 1);
    if (NULL != pn) {
        memcpy(pn->lan_mac, pni->lan_mac, AWND_MAC_LEN);
        memcpy(pn->dev_name, pni->dev_name, IFNAMSIZ);        
        pn->nh_dir = pni->nh_dir;
        pn->uplink_mask = pni->uplink_mask;
        pn->uplink_rate = pni->uplink_rate;
        pn->forward_num = pni->forward_num;
        memcpy(pn->forwarder, pni->forwarder, AWND_MAC_LEN);
        pn->flag = AWND_NEIGH_VALID;
                
        memcpy(pn->netInfo.awnd_mac, pni->eth_info.net_mac, AWND_MAC_LEN);
        memcpy(pn->netInfo.awnd_label, pni->eth_info.net_label, AWND_LABEL_LEN);
        pn->netInfo.awnd_net_type = pni->eth_info.net_type;        
        pn->netInfo.awnd_weight   = pni->eth_info.weight;
        pn->netInfo.awnd_level    = pni->eth_info.level;
        pn->netInfo.awnd_lanip    = pni->eth_info.lanip;
        pn->netInfo.server_detected      = pni->eth_info.server_detected;
        pn->netInfo.server_touch_time    = pni->eth_info.server_touch_time;
        pn->netInfo.awnd_dns      = pni->eth_info.dns;
#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        pn->link_speed    = pni->eth_info.link_speed;
        pn->tx_speed      = pni->eth_info.tx_speed;
        pn->rx_speed      = pni->eth_info.rx_speed;
#endif
        pn->netInfo.id  = IEEE80211_ELEMID_VENDOR;
        pn->netInfo.len = sizeof(AWND_NET_INFO) -2;
        pn->netInfo.oui[0] = tp_oui_list[oui_now_version].tp_oui[0];
        pn->netInfo.oui[1] = tp_oui_list[oui_now_version].tp_oui[1];
        pn->netInfo.oui[2] = tp_oui_list[oui_now_version].tp_oui[2];
        pn->netInfo.type = 0x01;

#ifdef CONFIG_ETH_WLAN_BACKHAUL_SUPPORT
        AWN_LOG_INFO("lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, net_type:%d, weight:%d, level:%d, lanip:%x, \
               \nnet_mac:%02X:%02X:%02X:%02X:%02X:%02X, server_detected:%d, server_touch_time:%d, dns:%x, \
               \nuplink_mask:%d, uplink_rate:%d, forward_num:%d, link_speed:%d, tx_speed:%ld, rx_speed:%ld", 
               pni->lan_mac[0], pni->lan_mac[1], pni->lan_mac[2], pni->lan_mac[3], pni->lan_mac[4], pni->lan_mac[5],
               pni->eth_info.net_type, pni->eth_info.weight, pni->eth_info.level, pni->eth_info.lanip,
               pni->eth_info.net_mac[0], pni->eth_info.net_mac[1], pni->eth_info.net_mac[2], 
               pni->eth_info.net_mac[3], pni->eth_info.net_mac[4], pni->eth_info.net_mac[5],
               pni->eth_info.server_detected, pni->eth_info.server_touch_time, pni->eth_info.dns,
               pni->uplink_mask, pni->uplink_rate, pni->forward_num, pni->eth_info.link_speed, pni->eth_info.tx_speed, pni->eth_info.rx_speed);
#else
        AWN_LOG_INFO("lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, net_type:%d, weight:%d, level:%d, lanip:%x, \
               \nnet_mac:%02X:%02X:%02X:%02X:%02X:%02X, server_detected:%d, server_touch_time:%d, dns:%x, \
               \nuplink_mask:%d, uplink_rate:%d, forward_num:%d", 
               pni->lan_mac[0], pni->lan_mac[1], pni->lan_mac[2], pni->lan_mac[3], pni->lan_mac[4], pni->lan_mac[5],
               pni->eth_info.net_type, pni->eth_info.weight, pni->eth_info.level, pni->eth_info.lanip,
               pni->eth_info.net_mac[0], pni->eth_info.net_mac[1], pni->eth_info.net_mac[2], 
               pni->eth_info.net_mac[3], pni->eth_info.net_mac[4], pni->eth_info.net_mac[5],
               pni->eth_info.server_detected, pni->eth_info.server_touch_time, pni->eth_info.dns,
               pni->uplink_mask, pni->uplink_rate, pni->forward_num);
            
#endif
        return AWND_OK;
    }
    else {
        AWN_LOG_WARNING("Can't find eth neigh:%02x-%02x-%02x-%02x-%02x-%02x", pni->lan_mac[0],
            pni->lan_mac[1],pni->lan_mac[2], pni->lan_mac[3], pni->lan_mac[4], pni->lan_mac[5]);
        return AWND_ERROR;
    }
}

int awnd_update_eth_neigh_tbl(AWND_ETH_NEIGH *neigh_tbl, struct eth_neigh_info *pnt, UINT32 cnt, UINT8 *label, UINT8 * preconf_label)
{
    int i;

    for (i = 0; i < cnt; i++) {
        if (!memcmp(pnt[i].eth_info.net_label, label, AWND_LABEL_LEN))
            awnd_update_eth_neigh(neigh_tbl, &pnt[i]);
        else if (preconf_label && !memcmp(pnt[i].eth_info.net_label, preconf_label, AWND_LABEL_LEN))
            awnd_update_eth_neigh(neigh_tbl, &pnt[i]);
        else
            AWN_LOG_INFO("Different subnets are connected by Ethernet, label: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", 
        pnt[i].eth_info.net_label[0], pnt[i].eth_info.net_label[1], pnt[i].eth_info.net_label[2],pnt[i].eth_info.net_label[3],
        pnt[i].eth_info.net_label[4], pnt[i].eth_info.net_label[5], pnt[i].eth_info.net_label[6],pnt[i].eth_info.net_label[7],
        pnt[i].eth_info.net_label[8], pnt[i].eth_info.net_label[9], pnt[i].eth_info.net_label[10],pnt[i].eth_info.net_label[11],
        pnt[i].eth_info.net_label[12], pnt[i].eth_info.net_label[13], pnt[i].eth_info.net_label[14],pnt[i].eth_info.net_label[15]);

    }

    return AWND_OK;
}



/***************************************************************************/
/*                        PUBLIC FUNCTIONS                                 */
/***************************************************************************/

int netlink_event_listen(int *sock_fd)
{
	struct sockaddr_nl nls;
	int nlbufsize = 512 * 1024;

	memset(&nls,0,sizeof(struct sockaddr_nl));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = 0;

	*sock_fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_NEIGHBOR_DISCOVER_EVENT);
    if (*sock_fd < 0) {
        AWN_LOG_ERR("netlink event socket create failed\n");
        goto err_out;
    } 
    
	if (bind(*sock_fd, (void *)&nls, sizeof(struct sockaddr_nl))) {
		AWN_LOG_ERR("Failed to bind event socket: %s\n", strerror(errno));
        goto err_out;
	}

	if (setsockopt(*sock_fd, SOL_SOCKET, SO_RCVBUFFORCE, &nlbufsize, sizeof(nlbufsize))){
		AWN_LOG_ERR("Failed to resize receive buffer: %s\n", strerror(errno));
        goto err_out;        
	}

    return AWND_OK;

err_out:
    if (*sock_fd)
        close(*sock_fd);
    return AWND_ERROR;   
}

int awn_get_lan_ip(UINT32 *lanIP)
{
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in *sin;
    UINT32 lanip = 0;
    int ret =  AWND_OK;

    if ((sockfd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
    {
        AWN_LOG_ERR("socket error");
        return AWND_ERROR;
    }

    strncpy(ifr.ifr_name, "br-lan", IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
    {
        AWN_LOG_ERR("ioctl error");
        ret = AWND_ERROR;
        goto err_out;
    }

    sin = (struct sockaddr_in *)&(ifr.ifr_addr);
    memcpy(&lanip, &(sin->sin_addr.s_addr), 4);
    *lanIP = ntohl(lanip);

    AWN_LOG_INFO("ip is %s return lanip:%x \n",inet_ntoa(sin->sin_addr), *lanIP);

err_out:
    close(sockfd);
    return ret;
}


int awnd_plc_event_recv(AWND_PLC_NEIGH  *neigh_tbl, int fd)
{
	int i = 0;
	static char buf[4096];
	struct nlmsghdr *nlh = NULL;  
	int len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	void *index;
    
	if (len < sizeof(struct nlmsghdr))
		return -1;

	nlh=(struct nlmsghdr *)buf;
    switch (nlh->nlmsg_type) {
	case PLC_EVENT_UPDATE_NEIGH: { 
        AWN_LOG_INFO("=======PLC_EVENT_UPDATE_NEIGH=======");
        struct plc_neigh_info *p = NLMSG_DATA(buf);
        awnd_clean_plc_neigh_new_flag(neigh_tbl);
        awnd_update_plc_neigh(neigh_tbl, p);
		break;
        }
	case PLC_EVENT_AGEOUT_NEIGH: {
        AWN_LOG_INFO("=======PLC_EVENT_AGEOUT_NEIGH=======");     
		struct __neigh_tbl *p = NLMSG_DATA(buf);
        awnd_clean_plc_neigh_new_flag(neigh_tbl);
        awnd_update_plc_neigh_tbl(neigh_tbl, p->neigh_tbl, p->cnt);
		break;
        }
	default:
		break;        
    }

    return 0;
    
}

//#define DEBUG_HY_NETLINK

/*-F- netlink_msg --
 */
int32_t netlink_msg(int32_t msg_type, u_int8_t *data, int32_t msgdatalen, int32_t netlink_key)
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    socklen_t fromlen;
    int32_t ret = AWND_ERROR;
    int32_t sock_fd;
    static pid_t myPid = 0;

    /* Do it only once per context, save a system call */
    if(!myPid)
    	myPid = getpid();

    do {
        sock_fd = socket(AF_NETLINK, SOCK_DGRAM, netlink_key);
        if (sock_fd <0) {
            AWN_LOG_ERR("netlink socket create failed\n");
            break;
        }

        /* Set nonblock. */
        if (fcntl(sock_fd, F_SETFL, fcntl(sock_fd, F_GETFL) | O_NONBLOCK)) {
            AWN_LOG_ERR("fcntl():");
            break;
        }

        fromlen = sizeof(src_addr);
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = myPid;  /* self pid */
        src_addr.nl_groups = 0;  /* not in mcast groups */
        bind(sock_fd, (struct sockaddr*)&src_addr,sizeof(src_addr));

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;   /* For Linux Kernel */
        dest_addr.nl_groups = 0; /* unicast */
        nlh=(struct nlmsghdr *)data;
        /* Fill the netlink message header */
        nlh->nlmsg_type = msg_type;
        nlh->nlmsg_len = NLMSG_SPACE(msgdatalen);
        nlh->nlmsg_pid = myPid;  /* self pid */
        nlh->nlmsg_flags = 0;

        int optval;

        optval = nlh->nlmsg_len;
        if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUFFORCE,
                       &optval, sizeof(optval))) {
            AWN_LOG_ERR("Setsockopt SO_SNDBUF: ");
            break;
        }

        if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUFFORCE,
                       &optval, sizeof(optval))) {
            AWN_LOG_ERR("Setsockopt SO_RCVBUF: ");
            break;
        }

        if (sendto(sock_fd,
                     (void*)nlh,
                     nlh->nlmsg_len,
                     0,
                     (struct sockaddr *)&dest_addr,
                     sizeof(struct sockaddr_nl)) <= 0) {
            AWN_LOG_ERR("netlink socket send failed\n");
            break;
        }

        struct pollfd pollfd = {
		    sock_fd,
		    POLLIN,
		    0
	    };

        if (poll(&pollfd, 1, 2000) <= 0) { /* timeout:2s */
            AWN_LOG_ERR("poll(): msg_type[%d]", msg_type);
            break;
        }

        if (recvfrom(sock_fd,
                       (void*)nlh,
                       NLMSG_SPACE(msgdatalen),
                       MSG_WAITALL,
                       (struct sockaddr *)&src_addr,
                       &fromlen) <= 0) {
            AWN_LOG_ERR("netlink socket receive failed\n");
            break;
        }

        ret = AWND_OK;

        if (ret !=AWND_OK)
            AWN_LOG_ERR("netlink socket status failed %d\n", ret);

    } while (0);

    if (sock_fd >0)
        close(sock_fd);

    return ret;
}


int32_t awn_plcson_get_neigh_tbl(AWND_PLC_NEIGH  *neigh_tbl)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE(sizeof(struct __neigh_tbl) + sizeof(struct plc_neigh_info) * AWN_NEIGH_MAX_CNT ) ];
    struct __neigh_tbl *p;
    struct plc_neigh_info *neigh_entry;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->cnt = AWN_NEIGH_MAX_CNT;
    retval = netlink_msg(NEIGHBOR_GET_PLC_GET_NEIGH, nlmsgbuf,  (sizeof(struct __neigh_tbl) + sizeof(struct plc_neigh_info) * AWN_NEIGH_MAX_CNT ), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else {
        awnd_clean_plc_neigh_new_flag(neigh_tbl);
        awnd_update_plc_neigh_tbl(neigh_tbl,p->neigh_tbl, p->cnt);
    }
        
    return 0;
}

int32_t awn_set_net_info(u_int8_t *lan_mac, u_int8_t *plc_mac, u_int8_t isPlcRoot, u_int16_t uplinkMask, 
                         u_int16_t uplinkRate, AWND_NET_INFO *pAwndNetInfo, u_int8_t meshType)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __neigh_info_global) ) ];
    struct __neigh_info_global *p;
    char plc_bkhl_vlanid[8];

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    
    memcpy(p->lan_mac,   lan_mac, 6);
    memcpy(p->plc_mac,   plc_mac, 6);    
    p->plc_root = isPlcRoot;
    p->uplink_mask = uplinkMask;
    p->uplink_rate = uplinkRate;
    p->mesh_type = meshType;   /* backual/config */

    memcpy(p->info.net_mac,   pAwndNetInfo->awnd_mac, 6);
    memcpy(p->info.net_label, pAwndNetInfo->awnd_label, 16);
    p->info.net_type = pAwndNetInfo->awnd_net_type;
    p->info.weight   = pAwndNetInfo->awnd_weight;
    p->info.level    = pAwndNetInfo->awnd_level;
    p->info.lanip    = pAwndNetInfo->awnd_lanip;
    p->info.server_detected      = pAwndNetInfo->server_detected;
    p->info.server_touch_time    = pAwndNetInfo->server_touch_time;
    p->info.dns      = pAwndNetInfo->awnd_dns;

    if(WIFI_AP == awnd_config_get_mode() && 1 == awnd_config_get_plc_backhaul(plc_bkhl_vlanid))
    {
        //if FAP add plc_bkhl_vlanid section
        p->info.plc_bkhl_vlanid = strtoul(plc_bkhl_vlanid, NULL, 10);
    }

    AWN_LOG_INFO("set net info lan_mac:%02X:%02X:%02X:%02X:%02X:%02X, net_type:%d, weight:%d, level:%d, lanip:%x, dns:%x\
           net_mac:%02X:%02X:%02X:%02X:%02X:%02X, server_detected:%d, server_touch_time:%d, mesh_type:%d\n", 
           p->lan_mac[0], p->lan_mac[1], p->lan_mac[2], p->lan_mac[3], p->lan_mac[4], p->lan_mac[5],
           p->info.net_type, p->info.weight, p->info.level, p->info.lanip, p->info.dns,
           p->info.net_mac[0], p->info.net_mac[1], p->info.net_mac[2], 
           p->info.net_mac[3], p->info.net_mac[4], p->info.net_mac[5],
           p->info.server_detected, p->info.server_touch_time, p->mesh_type);

    retval = netlink_msg(NEIGHBOR_SET_NET_INFO, nlmsgbuf,  sizeof(struct __neigh_info_global), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_plcson_set_report_param(u_int8_t report_enable, u_int32_t report_interval)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __report_param) ) ];
    struct __report_param *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->report_enable   = report_enable;
    p->report_interval = report_interval;

    retval = netlink_msg(NEIGHBOR_SET_PLC_REPORT_PARAM, nlmsgbuf,  sizeof(struct __report_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_plcson_set_detect_param(u_int8_t detect_enable, u_int8_t notify_enable, u_int32_t aging_time)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __detect_param) ) ];
    struct __detect_param *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->detect_enable       = detect_enable;
    p->event_notify_enable = notify_enable;
    p->aging_time          = aging_time;

    retval = netlink_msg(NEIGHBOR_SET_PLC_DETECT_PARAM, nlmsgbuf,  sizeof(struct __detect_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_plcson_set_pid(u_int32_t pid)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __event_info) ) ];
    struct __event_info *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->event_pid = pid;

    retval = netlink_msg(NEIGHBOR_SET_EVENT_PID, nlmsgbuf,  sizeof(struct __event_info), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_plcson_set_eth_mesh_enable(u_int8_t meshType, u_int8_t configEnable)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __config_mesh_enable) ) ];
    struct __config_mesh_enable *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->mesh_type = meshType;
    p->mesh_enable = configEnable;

    retval = netlink_msg(NEIGHBOR_SET_MESH_ENABLE, nlmsgbuf,  sizeof(struct __config_mesh_enable), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}


int32_t awn_plcson_set_dev(const char* devName)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( IFNAMSIZ ) ];
    char *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);

    if (devName)
    	strncpy(p, devName, IFNAMSIZ-1);

    retval = netlink_msg(NEIGHBOR_SET_PLC_DEV, nlmsgbuf,  IFNAMSIZ, NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}


int32_t awn_eth_set_report_param(u_int8_t report_enable, u_int32_t report_interval)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __report_param) ) ];
    struct __report_param *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->report_enable   = report_enable;
    p->report_interval = report_interval;

    retval = netlink_msg(NEIGHBOR_SET_ETH_REPORT_PARAM, nlmsgbuf,  sizeof(struct __report_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_eth_set_detect_param(u_int8_t detect_enable, u_int8_t notify_enable, u_int32_t aging_time)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __detect_param) ) ];
    struct __detect_param *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->detect_enable       = detect_enable;
    p->event_notify_enable = notify_enable;
    p->aging_time          = aging_time;

    retval = netlink_msg(NEIGHBOR_SET_ETH_DETECT_PARAM, nlmsgbuf,  sizeof(struct __detect_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_eth_set_forward_param(u_int8_t forward_enable)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __forward_param) ) ];
    struct __forward_param *p;

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->forward_enable = forward_enable;

    retval = netlink_msg(NEIGHBOR_SET_ETH_FORWARD_PARAM, nlmsgbuf, sizeof(struct __forward_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}

int32_t awn_eth_set_dev(const char* lanName, const char* wanName, int ethNum, char ethName[][IFNAMSIZ])
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE( sizeof(struct __dev_param)) ];
    struct __dev_param *p;
    int i = 0;
   

    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);

    if (lanName)
        strncpy(p->lanname, lanName, IFNAMSIZ-1);

    if (wanName)
        strncpy(p->wanname, wanName, IFNAMSIZ-1);

    if (ethNum > MAX_ETH_DEV_NUM)
        return -1;

    while (i < ethNum)
    {
        if (strlen(ethName[i]) <= 0)
            break;
        
        strncpy(p->ethname[i], ethName[i], IFNAMSIZ-1);
        AWN_LOG_INFO("set ethname:%s", p->ethname[i]);
        i++;
    }

    retval = netlink_msg(NEIGHBOR_SET_ETH_DEV, nlmsgbuf,  sizeof(struct __dev_param), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else
        return 0;
}


int32_t awn_eth_get_neigh_tbl(AWND_ETH_NEIGH  *neigh_tbl, UINT8 *label, UINT8 * preconf_label)
{
    int32_t retval;
    u_int8_t nlmsgbuf[ AWN_NETLINK_MESSAGE_SIZE(sizeof(struct __neigh_eth_tbl) + sizeof(struct eth_neigh_info) * AWN_NEIGH_MAX_CNT ) ];
    struct __neigh_eth_tbl *p;
    struct eth_neigh_info *neigh_entry;
    u_int32_t preconf_cnt = 0;
    int i = 0;

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_VALID == neigh_tbl[i].flag)
            neigh_tbl[i].flag= AWND_NEIGH_AGING;
    }

    /* to get preconf_label entry first */
    if (NULL != preconf_label) {
        memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
        p = NLMSG_DATA(nlmsgbuf);
        p->cnt = AWN_NEIGH_MAX_CNT;
        memcpy(p->neigh_tbl[0].eth_info.net_label, preconf_label, 16);
        retval = netlink_msg(NEIGHBOR_GET_ETH_GET_NEIGH, nlmsgbuf,  (sizeof(struct __neigh_eth_tbl) + sizeof(struct eth_neigh_info) * AWN_NEIGH_MAX_CNT ), NETLINK_NEIGHBOR_DISCOVER);

        if (retval != AWND_OK)
            return -1;
        else {
            preconf_cnt = p->cnt;
            awnd_update_eth_neigh_tbl(neigh_tbl, p->neigh_tbl, p->cnt, label, preconf_label);
        }
    }

    /* to get sta label entry */
    memset(nlmsgbuf, 0 , sizeof(nlmsgbuf));
    p = NLMSG_DATA(nlmsgbuf);
    p->cnt = AWN_NEIGH_MAX_CNT - preconf_cnt;
    memcpy(p->neigh_tbl[0].eth_info.net_label, label, 16);
    retval = netlink_msg(NEIGHBOR_GET_ETH_GET_NEIGH, nlmsgbuf,  (sizeof(struct __neigh_eth_tbl) + sizeof(struct eth_neigh_info) * AWN_NEIGH_MAX_CNT ), NETLINK_NEIGHBOR_DISCOVER);

    if (retval != AWND_OK)
        return -1;
    else {
        awnd_update_eth_neigh_tbl(neigh_tbl,p->neigh_tbl, p->cnt, label, preconf_label);
    }

    for (i = 0; i < AWN_NEIGH_MAX_CNT; i++) {
        if (AWND_NEIGH_AGING == neigh_tbl[i].flag)
            neigh_tbl[i].flag= AWND_NEIGH_CLEAR;
    }

    return 0;
}

void awnd_update_plc_backhaul(int fap_plc_bkhl_vlanid)
{
    int re_plc_bkhl_vlanid;
    char tmp[8];
    if( 1 == awnd_config_get_plc_backhaul(tmp))
    {
        re_plc_bkhl_vlanid = strtoul(tmp, NULL, 10);
        if( re_plc_bkhl_vlanid != fap_plc_bkhl_vlanid)
        {
            AWN_LOG_ERR("awnd_update_plc_backhaul re_plc_bkhl_vlanid is %d",re_plc_bkhl_vlanid);
            AWN_LOG_ERR("awnd_update_plc_neigh update id is %d",fap_plc_bkhl_vlanid);
            char cmd[128];
            memset(cmd, 0, sizeof(cmd));
            sprintf(cmd, "lua /usr/sbin/handle_plc_bkhl_vlanid %d", fap_plc_bkhl_vlanid);
            system(cmd);
            system("sleep 1");
            system("/etc/init.d/plc_vlan reload &");
        }
        
    }
}
