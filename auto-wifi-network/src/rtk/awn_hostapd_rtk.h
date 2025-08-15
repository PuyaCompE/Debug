/******************************************************************************
Copyright (c) 2009-2023 TP-Link Technologies CO.,LTD.  All rights reserved.

File name	: awn_hostapd_rtk.h
Version		: v0.1 
Description	: Hostapd control API for AWN, support by Realtek

Author		: Jiang Ji <jiangji@tp-link.com.hk>
Create date	: 2023/3/23

History		:
01, 2023/3/23 Jiang Ji, a Copy of awn_hostapd_rtk.h

*****************************************************************************/
#include <wpa_ctrl.h>
#ifndef __AWN_HOSTAPD_RTK_H_
#define __AWN_HOSTAPD_RTK_H_

int hostapd_del_tpie(const char *ifname);
int hostapd_update_tpie(const char *ifname, const char *ie);
#endif
