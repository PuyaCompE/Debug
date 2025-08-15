/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : ai_defines.h
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-05-17
 */

#ifndef __AI_NWK_DEFINES_H__
#define __AI_NWK_DEFINES_H__

/* -------------------------------------------------------------------------- */
/*                                   DEFINES                                  */
/* -------------------------------------------------------------------------- */
#define AI_AP_SCORE_INFO_FILE "tmp/dynamicNetworkData/scoreInfo.txt"
#define AI_BRIDGING_INFO_FILE "tmp/dynamicNetworkData/bridgingInfo.txt"
#define AI_SCANNING_INFO_FILE "tmp/dynamicNetworkData/scanningInfo.txt"
#define AI_NETWORK_APINFO_FILE "tmp/dynamicNetworkData/apInfo.txt"
#define AI_TIME_DELAY_INFO_FILE "tmp/dynamicNetworkData/timeDelayInfo.txt"
#define AI_AP_LAST_RANK_INFO_FILE "tmp/dynamicNetworkData/lastApRank.txt"
#define AI_NETWOKING_PATINFORATE_FILE "tmp/dynamicNetworkData/patInfoRate.txt"

#define MAC_ADDR_FMT    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define MAC_ADDR_DATA(_octet) \
    _octet[0], _octet[1], _octet[2], _octet[3], _octet[4], _octet[5]


#endif /* __AI_NWK_DEFINES_H__ */