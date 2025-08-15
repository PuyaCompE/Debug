/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : ai_config.h
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-06-01
 */

#ifndef __AI_CONFIG_H__
#define __AI_CONFIG_H__

#include <algDataInterfaceStruct.h>


/* -------------------------------------------------------------------------- */
/*                                 PROTOTYPES                                 */
/* -------------------------------------------------------------------------- */

//int config_save_pat(const PatParameter *par);
int config_save_score(const ScoreInfo *score);
//int config_load_pat(PatParameter *par);
/* Invalid MAC string stored in socre->fatherMAC is required. */
int config_load_score(ScoreInfo *score);
int config_load_scores(const char *filepath);



#endif /* __AI_CONFIG_H__ */