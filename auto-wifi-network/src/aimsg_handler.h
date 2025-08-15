/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : aimsg_handler.h
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-05-15
 */

#ifndef __AIMSG_HANDLER_H__
#define __AIMSG_HANDLER_H__
#include <stdint.h>
#include "auto_wifi_net.h"
#include <algDataInterfaceStruct.h>


/* -------------------------------------------------------------------------- */
/*                                   DEFINES                                  */
/* -------------------------------------------------------------------------- */

typedef struct _AlgTimeStamp
{
    uint32_t ap_timestamp;
    uint32_t rank_timestamp;
    uint32_t bridging_timestamp;
    uint32_t scanning_timestamp;
    uint32_t pat_timestamp;
    uint32_t apAlgOut_timestamp;
    uint32_t score_timestamp;
    uint32_t timeDelay_timestamp;
    uint32_t mode_timestamp;
} AlgTimeStamp;

typedef struct _AlgApUpdateTimeStamp
{
    char apMac[ALG_MAX_AP_NUM][ALG_MAC_LENGTH];
    uint32_t timestamp[ALG_MAX_AP_NUM];
    uint8_t apNum;
    uint32_t newestTimeStamp;
} AlgApUpdateTimeStamp;

typedef enum
{
    DN_RE_STATUS_INIT = 0,
    DN_RE_STATUS_BEFORE_ROAMING = 1,
    DN_RE_STATUS_AFTER_ROAMING = 2,
} DN_RE_STATUS_CODE;

/* -------------------------------------------------------------------------- */
/*                                 PROTOTYPES                                 */
/* -------------------------------------------------------------------------- */
int mac_str_to_octet(const char *str, int str_len,
    uint8_t *octet, int octet_len);
void update_devinfo(void);
int handle_aimsg(void *data, int len, AWND_MODE_TYPE mode);
int send_nwkout(ApAlgInterfaceOutput *out);
int send_rank(ApRank *aprank, uint8_t num);
int send_first_roaming_request(void);
int get_alg_re_status(void);
int set_alg_re_status(int alg_re_status);
int delete_offline_re_by_mac(const char *mac[], int num);
void do_pre_first_roaming();
int set_alg_done(BOOL alg_status);
BOOL get_alg_done();
int set_last_mac(char *last_mac);
char* get_last_mac();
void print_relay_mac();
#if 0
int send_patinfo(PatParameter *patpar);
#else
int send_patinfo(PatParameterV2 *patpar);
#endif
int save_devinfo(struct aidata_dev_info_t *devinfo, uint32_t time_stamp);
int save_scaninfo(struct aidata_scan_info_t *scaninfo, uint32_t time_stamp);
int save_rankinfo(struct aidata_ap_rank_t *rank, uint32_t time_stamp);
#if 0
int save_patinfo(struct aidata_pat_info_t *pat, uint32_t time_stamp);
#else
int save_patinfo(struct aidata_pat_info_v2_t *pat, uint32_t time_stamp);
#endif
int save_apmode(struct aidata_ap_mode_t *mode, uint32_t time_stamp);
int cancel_re_alg_timeout_process(void);
int fap_alg_process(int alg_strategy, char *mac);
int re_alg_process(void);
#endif /* __AIMSG_HANDLER_H__ */