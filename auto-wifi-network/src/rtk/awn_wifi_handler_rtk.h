/******************************************************************************
Copyright (c) 2009-2019 TP-Link Technologies CO.,LTD.  All rights reserved.

File name   : awn_wifi_handler_RTK.h
Version     : v0.1 
Description : awn wifi handler for RTK

Author      :  <puhaowen@tp-link.com.cn>
Create date : 2019/4/28

History     :
01, 2019/4/28 Pu Haowen, Created file.

*****************************************************************************/
#ifndef _AWN_WIFI_HANDLER_RTK_H_
#define _AWN_WIFI_HANDLER_RTK_H_

/***************************************************************************/
/*                      INCLUDE_FILES                                      */
/***************************************************************************/
#include <net/ethernet.h>   /* struct ether_addr */
#include <net/if_arp.h>     /* For ARPHRD_ETHER */
#include <sys/socket.h>     /* For AF_INET & struct sockaddr */
#include <netinet/in.h>     /* For struct sockaddr_in */
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

#include "../auto_wifi_net.h"
#include "../awn_wifi_handler_api.h"
#include "../awn_log.h"

/***************************************************************************/
/*                      DEFINES                                            */
/***************************************************************************/
/*************** H70x ***************/
/* type         5G          24G     */
/* STA          apclix0     apcli0  */
/* backhaul AP  rax0        ra0     */
/* AP           rax2        ra2     */
/* guest AP     rax4        ra4     */
/* config AP    rax1        ra1     */
/* default AP   rax3        ra3     */

/*************** M4v4 ***************/
/* type         5G          24G     */
/* STA          apclii0     apcli0  */
/* backhaul AP  rai0        ra0     */
/* AP           rai2        ra2     */
/* guest AP     rai4        ra4     */
/* config AP    rai1        ra1     */
/* default AP   rai3        ra3     */

#define RTK_IFNAMESIZE 16

#define RTK_IFNAME_2G_AP_PREFIX_STR "wlan1"
#define RTK_IFNAME_5G_AP_PREFIX_STR "wlan0"
#define RTK_IFNAME_5G2_AP_PREFIX_STR "wlan2"

#define RTK_IFNAME_2G_STA_PREFIX_STR "wlan1"
#define RTK_IFNAME_5G_STA_PREFIX_STR "wlan0"
#define RTK_IFNAME_5G2_STA_PREFIX_STR "wlan2"

#define RTK_IFNAME_2G_STA_POST_STR "-vxd"
#define RTK_IFNAME_5G_STA_POST_STR "-vxd"
#define RTK_IFNAME_5G2_STA_POST_STR "-vxd"


#define RTK_AP_IFNAME_FMT  "%s%s"
#define RTK_STA_IFNAME_FMT "%s%s"

#define	IEEE80211_RATE_VAL      0x7f

/* Add TP-Link Spcific Vendor IE Support */
#define TP_IE_MAX_LEN           128
#define IEEE80211_MAX_TP_IE     (TP_IE_MAX_LEN + 5) //elemid + len + oui[3]
#define VENDORIE_OUI_LEN        3

/***************************************************************************/
/*                        TYPES                                            */
/***************************************************************************/


/***************************************************************************/
/*                        FUNCTIONS                                        */
/***************************************************************************/

int get_default_mesh_channel_RTK(AWND_BAND_TYPE band, int *channel);
int get_sta_channel_RTK(AWND_BAND_TYPE band, int *channel);
int get_backhaul_ap_channel_RTK(AWND_BAND_TYPE band, int *channel);

int get_phy_RTK(AWND_BAND_TYPE band, int *nss, int *phyMode, int *chwidth);
#if GET_AP_RSSI
int get_wds_state_RTK(AWND_BAND_TYPE band, int *up, int *rssi);
#else
int get_wds_state_RTK(AWND_BAND_TYPE band, int *up);
#endif
int get_rootap_phyRate_RTK(AWND_BAND_TYPE band, UINT16 *txrate, UINT16 *rxrate);
int get_rootap_info_RTK(AWND_AP_ENTRY *pApEntry, AWND_BAND_TYPE band);
int get_rootap_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);
int get_tpie_RTK(UINT8 *pMac, UINT8 entry_type, AWND_NET_INFO *pAwndNetInfo, AWND_BAND_TYPE band);

int init_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, UINT8* pApMac, UINT8* pLabel, UINT8 weight, UINT8 netType);
int update_wifi_tpie_RTK(AWND_NET_INFO *pAwndNetInfo, u_int8_t *lan_mac, u_int16_t uplinkMask, u_int16_t *uplinkRate, u_int8_t meshType);

int flush_scan_table_single_band_RTK(AWND_BAND_TYPE band, BOOL force);
int flush_scan_table_RTK(void);
int do_scan_RTK(UINT8 scanBandMask);
int do_scan_fast_RTK(UINT8 scanBandMask);
int get_scan_result_RTK(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label,
        char* preconf_ssid, UINT8* preconf_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);
int scan_RTK(AWND_SCAN_RESULT *pAwndScanResult, char* match_ssid, UINT8* match_label, AWND_BAND_TYPE band, AWND_VAP_TYPE vap_type, UINT8 isFast);

int set_channel_RTK(AWND_BAND_TYPE band, UINT8 channel);
int get_sta_iface_in_bridge_RTK(AWND_BAND_TYPE band, UINT8* ifname);

int disconn_sta_pre_RTK(AWND_BAND_TYPE band, UINT* pBandMask);
int disconn_all_sta_pre_RTK(UINT* pBandMask);
int disconn_sta_post_RTK(AWND_BAND_TYPE band);
int disconn_sta_RTK(AWND_BAND_TYPE band);
int disconn_all_sta_RTK(void);
int reconn_sta_pre_RTK(AWND_BAND_TYPE band, AWND_AP_ENTRY *pRootAp);
int reconn_sta_post_RTK(AWND_BAND_TYPE band, BOOL check_wpa_status);
int reset_sta_connection_RTK(AWND_BAND_TYPE band);
int set_backhaul_sta_dev_RTK(UINT32 link_state, unsigned int eth_link_state);
void do_band_restart_RTK(UINT8 BandMask);
int get_wifi_bw_RTK(AWND_BAND_TYPE band, AWND_WIFI_BW_TYPE *wifi_bw);
void set_wifi_bw_RTK(AWND_BAND_TYPE band, UINT8 channel, AWND_WIFI_BW_TYPE wifi_bw);
int bss_status_check_RTK();
#endif /* _AWN_WIFI_HANDLER_RTK_H_ */

