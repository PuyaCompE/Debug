/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : ping.h
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-05-15
 */

#ifndef __PING_H__
#define __PING_H__



/* -------------------------------------------------------------------------- */
/*                                 PROTOTYPES                                 */
/* -------------------------------------------------------------------------- */
int ping_lanip(uint32_t lanip);
int set_parent_mac(uint8_t *p_mac);

#endif /* __PING_H__ */