/******************************************************************************
Copyright (c) 2009-2023 TP-Link Technologies CO.,LTD.  All rights reserved.

File name	: awn_hostapd_rtk.c
Version		: v0.1 
Description	: Get/Set wifi info through hostapd, first use in Realtek chip

Author		: Jiang Ji <jiangji@tp-link.com.hk>
Create date	: 2023/3/23

History		:
01, 2023/3/23 Jiangji, Created file.

*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <wpa_ctrl.h>
#include "awn_log.h"

#define MAC_ADDR_LEN		6
#define HOSTAPD_CTRL_IFACE	"/var/run/hostapd" 
#define HOSTAPD_SET_PARAM	"SET"
#define HOSTAPD_UPDATE_BCN	"UPDATE_BEACON"

/*
 * Main function to communicate with Hostapd
 * para:
 *     in @ifname: dev_name indicate which interface to connect
 *        @cmd: specify cmd type
 *     out @data: record data after transfer from hostapd message to local private struct
 *         @data_len: data len which has been transfered
 * return: 0 for success; others for fail
 */
static
int wifi_hostapd_send_cmd(const char *ifname, char *cmd, void *data, size_t *data_len)
{
	struct wpa_ctrl *ctrl = NULL;
	char ctrl_path[256] = {'\0'};
	char *buf = (char *)data;
	int ret = 0;

	/* control path */
	snprintf(ctrl_path, sizeof(ctrl_path), "%s/%s", HOSTAPD_CTRL_IFACE, ifname);

	/* init wpa_ctrl */
	ctrl = wpa_ctrl_open(ctrl_path);
	if (!ctrl)
	{
		AWN_LOG_ERR("wpa_ctrl_open fail");
		ret = -1;
		goto end;
	}

	AWN_LOG_INFO("-->hostapd_cmd:%s.", cmd);

	ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, data_len, NULL);
	if (ret == -2) {
		 AWN_LOG_ERR("'%s' command timed out.", cmd);
	} else if (ret < 0) {
		AWN_LOG_ERR("'%s' command failed.", cmd);
	}
	else
	{
		buf[*data_len] = '\0';
	}

	/* close wpa_ctrl link */
	wpa_ctrl_close(ctrl);

	/* check common error return form hostapd */
	if (strncmp(buf, "FAIL", 4) == 0)
	{
		AWN_LOG_ERR("hostapd return fail.");
		ret = -1;
	}

	if (strncmp(buf, "UNKONWN", 7) == 0)
	{
		AWN_LOG_ERR("hostapd return unkonwn.");
		ret =  -1;
	}
	
end:
	AWN_LOG_INFO("-->hostapd return %d", ret);
	return ret;
}

/* tell hostapd to update TPIE
 * para:
 *     in @ifname: which wifi interface
 *        @ie: TPIE content
 * return: 0 for success; others for fail
 */
int hostapd_update_tpie(const char *ifname, const char *ie)
{
	char cmd[1024] = {'\0'};
	char buf[4096] = {'\0'};
	size_t len = sizeof(buf) - 1;
	int ret = 0;

	if (ifname == NULL || ie == NULL)
	{
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "%s vendor_elements %s", HOSTAPD_SET_PARAM, ie);

	ret = wifi_hostapd_send_cmd(ifname, cmd, buf, &len);
	if (ret < 0)
	{
		AWN_LOG_ERR("%s: send vendor_elements to hostapd fail!", __func__);
		return ret;
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "%s", HOSTAPD_UPDATE_BCN);
	ret = wifi_hostapd_send_cmd(ifname, cmd, buf, &len);
	if (ret < 0)
	{
		AWN_LOG_ERR("%s: send update_beacon to hostapd fail!", __func__);
		return ret;
	}

	AWN_LOG_INFO("%s update tpie ok.", ifname);
	return ret;
}

/* tell hostapd to del TPIE
 * para:
 *     in @ifname: which wifi interface
 * return: 0 for success; others for fail
 */
int hostapd_del_tpie(const char *ifname)
{
#if 0
	char cmd[1024] = {'\0'};
	char buf[4096] = {'\0'};
	size_t len = sizeof(buf) - 1;
	int ret = 0;

	if (ifname == NULL)
	{
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "%s vendor_elements \"\"", HOSTAPD_SET_PARAM);
	ret = wifi_hostapd_send_cmd(ifname, cmd, buf, &len);
	if (ret < 0)
	{
		fprintf(stderr, "%s: send vendor_elements to hostapd fail!", __func__);
		return ret;
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "%s", HOSTAPD_UPDATE_BCN);
	ret = wifi_hostapd_send_cmd(ifname, cmd, buf, &len);
	if (ret < 0)
	{
		fprintf(stderr, "%s: send update_beacon to hostapd fail!", __func__);
		return ret;
	}

	fprintf(stderr, "hostapd_update_tpie ok.\n");
	return ret;
#else
	/* driver already del old TPIE during beacon_update process, 
	 * so there is nothing to do with this func.
	 */
	AWN_LOG_INFO("%s del tpie ok", ifname);
	return 0;
#endif
}

