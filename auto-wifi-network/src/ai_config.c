/*
 * Copyright (c) 2006-2020 TP-Link Technologies CO.,LTD. All rights reserved.
 * 
 * File name       : ai_config.c
 * Description     :
 * 
 * Author          : Wu Kan
 * Date Created    : 2020-06-01
 */
#ifdef CONFIG_AWN_MESH_OPT_SUPPORT

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uci.h>
#include "ai_config.h"
#include "awn_log.h"


/* -------------------------------------------------------------------------- */
/*                                   DEFINES                                  */
/* -------------------------------------------------------------------------- */
#define ARRAY_SIZE(x)       (sizeof (x) / sizeof ((x)[0]) )
#define UCI_STR_MAX_LEN     64
#define UCI_VALUE_MAX_LEN   24
#define UCI_CONF_PATH       "/etc/config"
#define UCI_SAVE_PATH       "/var/state"

#define UCI_AI_NETWORK_CONFIG       "ainetwork"

#define UCI_PATPARAM_SECTION        "ainetwork.patparam"
#define UCI_PATPARAM_B_OPTION       "ainetwork.patparam.mode_%d_b"
#define UCI_PATPARAM_C_OPTION       "ainetwork.patparam.mode_%d_c"

#define UCI_SCORE_SECTION_TYPE      "score"
#define UCI_SCORE_SECTION_PREFIX    "ainetwork.score_%s"
#define UCI_SCORE_MAC_OPTION        "ainetwork.score_%s.mac"
#define UCI_SCORE_RANK_OPTION       "ainetwork.score_%s.rank"
#define UCI_SCORE_DELAY_CNT_OPTION  "ainetwork.score_%s.delay_cnt"
#define UCI_SCORE_DELAY_AVG_OPTION  "ainetwork.score_%s.delay_avg"
#define UCI_SCORE_THRPUT_OPTION     "ainetwork.score_%s.thrput"
#define UCI_SCORE_RSSI_OPTION       "ainetwork.score_%s.rssi_%d"
#define UCI_SCORE_RATE_OPTION       "ainetwork.score_%s.rate_%d"
#define UCI_SCORE_PAT_RATE_OPTION   "ainetwork.score_%s.pat_rate_%d"
#define UCI_SCORE_MAC_OPT_KEY       "mac"
#define UCI_SCORE_RANK_OPT_KEY      "rank"
#define UCI_SCORE_DELAYCNT_OPT_KEY  "delay_cnt"
#define UCI_SCORE_DELAYAVG_OPT_KEY  "delay_avg"
#define UCI_SCORE_THRPUT_OPT_KEY    "thrput"
#define UCI_SCORE_RSSI_OPT_KEY      "rssi_%d"
#define UCI_SCORE_RATE_OPT_KEY      "rate_%d"
#define UCI_SCORE_PAT_RATE_OPT_KEY  "pat_rate_%d"



/* -------------------------------------------------------------------------- */
/*                               LOCAL PROTOTYES                              */
/* -------------------------------------------------------------------------- */
static int uci_get_value(char *uciTupleStr, char *pValue);
static int uci_set_value(char *uciTupleStr, char *pValue);
static bool uci_check_value(const char *uciTupleStr, const char *valueStr);
static int uci_an_add_section(const char *macStr);
static int uci_load_score_section(struct uci_context *ctx,
    struct uci_section *s, ScoreInfo *score);



/* -------------------------------------------------------------------------- */
/*                               LOCAL FUNCTIONS                              */
/* -------------------------------------------------------------------------- */
static int uci_get_value(char *uciTupleStr, char *pValue)
{
    struct uci_context *uci_ctx = NULL;
    struct uci_element *e = NULL;
    struct uci_ptr uci_ptr;
    int ret = -1;

    if (NULL == uciTupleStr || NULL == pValue) {
        AWN_LOG_ERR("Null argument(s)");
        return ret;
    }

    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        AWN_LOG_ERR("fail to init uci context: %s", uciTupleStr);
        return ret;
    }
    uci_set_confdir(uci_ctx, UCI_CONF_PATH);
    uci_set_savedir(uci_ctx, UCI_SAVE_PATH);

    if (UCI_OK != uci_lookup_ptr(uci_ctx, &uci_ptr, uciTupleStr, true)) {
        AWN_LOG_ERR("fail to get ptr: %s", uciTupleStr);
        goto out;
    }

    e = uci_ptr.last;
    if (UCI_TYPE_OPTION != e->type) {
        AWN_LOG_ERR("element type is not option");
        goto out;
    }

    if (UCI_TYPE_STRING != uci_ptr.o->type) {
        AWN_LOG_ERR("option type is not string: %d", uci_ptr.o->type);
        goto out;
    }

    snprintf(pValue, UCI_VALUE_MAX_LEN, uci_ptr.o->v.string);
    AWN_LOG_DEBUG("Success to get option value %s = %s", uciTupleStr, uci_ptr.o->v.string);
    ret = 0;

out:
    if (uci_ctx) {
        uci_free_context(uci_ctx);
    }
    return ret;
}

static int uci_set_value(char *uciTupleStr, char *value)
{
    struct uci_context *uciCtx = NULL;
    struct uci_ptr uciPtr;
    char revertTuple[UCI_STR_MAX_LEN] = {0};
    int ret = -1;

    if (!uciTupleStr || !value) {
        AWN_LOG_ERR("null uciTupleStr or pValue");
        goto out;
    }

    uciCtx = uci_alloc_context();
    if (!uciCtx) {
        AWN_LOG_ERR("fail to alloc uciCtx");
        goto out;
    }

    uci_set_confdir(uciCtx, UCI_CONF_PATH);

    strncpy(revertTuple, uciTupleStr, UCI_STR_MAX_LEN);
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, revertTuple, true)) {
        AWN_LOG_ERR("fail to get ptr %s", uciTupleStr);
        goto out;
    }

    if (UCI_OK != (ret = uci_revert(uciCtx, &uciPtr))) {
        AWN_LOG_ERR("fail to revert ptr %s (ret: %d)", uciTupleStr, ret);
        goto out;
    }

    /* set and save in /var/state/ */
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, uciTupleStr, true)) {
        AWN_LOG_ERR("fail to get ptr again %s", uciTupleStr);
        goto out;
    }

    uciPtr.value = value;
    if (UCI_OK != (ret = uci_set(uciCtx, &uciPtr))) {
        AWN_LOG_ERR("fail to set ptr: %s (ret: %d)", uciTupleStr, ret);
        goto out;
    }

    if (UCI_OK != uci_save(uciCtx, uciPtr.p)) {
        AWN_LOG_ERR("fail to commit %s", uciTupleStr);
        goto out;
    }
    ret = 0;

out:

    if (uciCtx) {
        uci_free_context(uciCtx);
    }
    return ret;
}

static bool uci_check_value(const char *uciTupleStr, const char *valueStr)
{
    char root_uci_str[UCI_STR_MAX_LEN] = {0};
    char root_str[UCI_VALUE_MAX_LEN] = {0};
    bool ret = false;
    if (!uciTupleStr || !valueStr) {
        return false;
    }

    snprintf(root_uci_str, sizeof(root_uci_str), "%s", uciTupleStr);
    if (uci_get_value(root_uci_str, root_str) < 0) {
        return ret;
    }

    ret = (0 == strncmp(root_str, valueStr, UCI_VALUE_MAX_LEN)) ? true : false;
    return ret;
}

static int uci_an_add_section(const char *macStr)
{
    struct uci_context *uciCtx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *pSection = NULL;
    struct uci_ptr uciPtr = {0};
    char uciCfgStr[UCI_STR_MAX_LEN] = {0};

    uciCtx = uci_alloc_context();
    uci_set_confdir(uciCtx, UCI_CONF_PATH);

    if (UCI_OK != uci_load(uciCtx, UCI_AI_NETWORK_CONFIG, &pkg)) {
        uci_free_context(uciCtx);
        return -1;
    }

    snprintf(uciCfgStr, sizeof (uciCfgStr), UCI_SCORE_SECTION_PREFIX, macStr);
    if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, uciCfgStr, false)) {
        if (uci_add_section(uciCtx, pkg, UCI_SCORE_SECTION_TYPE, &pSection) || !pSection) {
            AWN_LOG_ERR("Fail to add score section");
            goto err;
        }
        memset(uciCfgStr, 0, sizeof(uciCfgStr));
        snprintf(uciCfgStr, sizeof(uciCfgStr), "%s.%s=score_%s",
            UCI_AI_NETWORK_CONFIG, pSection->e.name, macStr);
        if (UCI_OK != uci_lookup_ptr(uciCtx, &uciPtr, uciCfgStr, true)) {
            AWN_LOG_ERR("Fail to lookup uci ptr: %s", uciCfgStr);
            goto err;
        }
        if (UCI_OK != uci_rename(uciCtx, &uciPtr)) {
            AWN_LOG_ERR("Fail to rename");
            goto err;
        }
    }
    uci_unload(uciCtx, pkg);
    uci_free_context(uciCtx);
    return 0;


err:
    uci_unload(uciCtx, pkg);
    uci_free_context(uciCtx);
    return -1;
}

static int uci_load_score_section(struct uci_context *ctx,
    struct uci_section *s, ScoreInfo *score)
{
    int i;
    const char *value = NULL;
    char opt_key[UCI_STR_MAX_LEN] = {0};

    value = uci_lookup_option_string(ctx, s, UCI_SCORE_MAC_OPT_KEY);
    if (!value) {
        AWN_LOG_ERR("Null mac");
        return -1;
    }
    snprintf(score->fatherMAC, sizeof (score->fatherMAC), "%s", value);

    value = uci_lookup_option_string(ctx, s, UCI_SCORE_RANK_OPT_KEY);
    if (!value) {
        AWN_LOG_ERR("Null rank for mac(%s).", score->fatherMAC);
        return -1;
    }
    sscanf(value, "%hhu", &score->apRank);

    value = uci_lookup_option_string(ctx, s, UCI_SCORE_DELAYCNT_OPT_KEY);
    if (!value) {
        AWN_LOG_ERR("Null delay count for mac(%s).", score->fatherMAC);
        return -1;
    }
    sscanf(value, "%hhu", &score->timeDelayTestCnt);

    value = uci_lookup_option_string(ctx, s, UCI_SCORE_DELAYAVG_OPT_KEY);
    if (!value) {
        AWN_LOG_ERR("Null delay average for mac(%s).", score->fatherMAC);
        return -1;
    }
    sscanf(value, "%hu", &score->timeDelayAverage);

    value = uci_lookup_option_string(ctx, s, UCI_SCORE_THRPUT_OPT_KEY);
    if (!value) {
        AWN_LOG_ERR("Null thrput for mac(%s).", score->fatherMAC);
        return -1;
    }
    sscanf(value, "%hu", &score->thrputPredict);

    for (i = 0; i < ARRAY_SIZE(score->rssi); i++) {
        snprintf(opt_key, sizeof (opt_key), UCI_SCORE_RSSI_OPT_KEY, i);
        if ((value = uci_lookup_option_string(ctx, s, opt_key)) == NULL) {
            AWN_LOG_ERR("Null rssi_%d for mac(%s).", i, score->fatherMAC);
            return -1;
        }
        sscanf(value, "%hhu", &score->rssi[i]);
    }

    for (i = 0; i < ARRAY_SIZE(score->negoRate); i++) {
        snprintf(opt_key, sizeof (opt_key), UCI_SCORE_RATE_OPT_KEY, i);
        if ((value = uci_lookup_option_string(ctx, s, opt_key)) == NULL) {
            AWN_LOG_ERR("Null rate_%d for mac(%s).", i, score->fatherMAC);
            return -1;
        }
        sscanf(value, "%hu", &score->negoRate[i]);
    }

    for (i = 0; i < ARRAY_SIZE(score->patRate); i++) {
        snprintf(opt_key, sizeof (opt_key), UCI_SCORE_PAT_RATE_OPT_KEY, i);
        if ((value = uci_lookup_option_string(ctx, s, opt_key)) == NULL) {
            AWN_LOG_ERR("Null pat_rate_%d for mac(%s).", i, score->fatherMAC);
            return -1;
        }
        sscanf(value, "%hu", &score->negoRate[i]);
    }

    return 0;
}


/* -------------------------------------------------------------------------- */
/*                              PUBLIC FUNCTIONS                              */
/* -------------------------------------------------------------------------- */
#if 0
int config_save_pat(const PatParameter *par)
{
    int i;
    char value[UCI_VALUE_MAX_LEN] = {0};
    char uciTupleStr[UCI_STR_MAX_LEN] = {0};

    if (!par) {
        AWN_LOG_ERR("Null par.");
        return -1;
    }

    for (i = 0; i < ALG_TOTAL_MODEL_COUNT; i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_PATPARAM_B_OPTION, i);
        snprintf(value, sizeof(value), "%hu", par->bParameter);
        if (uci_set_value(uciTupleStr, value) < 0) {
            AWN_LOG_ERR("Fail to set param_b @mode%d", i);
            return -1;
        }

        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_PATPARAM_C_OPTION, i);
        snprintf(value, sizeof (value), "%hu", par->cParameter);
        if (uci_set_value(uciTupleStr, value) < 0) {
            AWN_LOG_ERR("Fail to set param_c @mode%d", i);
            return -1;
        }
    }
    system("saveconfig device-config");

    return 0;
}
#endif

int config_save_score(const ScoreInfo *score)
{
    char uciTupleStr[UCI_STR_MAX_LEN] = {0};
    char value[UCI_VALUE_MAX_LEN] = {0};
    int i;

    if (!score) {
        AWN_LOG_ERR("Null socre.");
        return -1;
    }

    if (uci_an_add_section(score->fatherMAC) < 0) {
        AWN_LOG_ERR("Fail to add score section for %s.", score->fatherMAC);
        return -1;
    }

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_RANK_OPTION, score->fatherMAC);
    snprintf(value, sizeof (value), "%hhu", score->apRank);
    uci_set_value(uciTupleStr, value);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_DELAY_CNT_OPTION, score->fatherMAC);
    snprintf(value, sizeof (value), "%hhu", score->timeDelayTestCnt);
    uci_set_value(uciTupleStr, value);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_DELAY_AVG_OPTION, score->fatherMAC);
    snprintf(value, sizeof (value), "%hu", score->timeDelayAverage);
    uci_set_value(uciTupleStr, value);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_THRPUT_OPTION, score->fatherMAC);
    snprintf(value, sizeof (value), "%hu", score->thrputPredict);
    uci_set_value(uciTupleStr, value);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    for (i = 0; i < ARRAY_SIZE(score->rssi); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_RSSI_OPTION, score->fatherMAC, i);
        snprintf(value, sizeof (value), "%hhu", score->rssi[i]);
        uci_set_value(uciTupleStr, value);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    for (i = 0; i < ARRAY_SIZE(score->negoRate); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_RATE_OPTION, score->fatherMAC, i);
        snprintf(value, sizeof (value), "%hu", score->negoRate[i]);
        uci_set_value(uciTupleStr, value);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    for (i = 0; i < ARRAY_SIZE(score->patRate); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_PAT_RATE_OPTION, score->fatherMAC, i);
        snprintf(value, sizeof (value), "%hu", score->patRate[i]);
        uci_set_value(uciTupleStr, value);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    system("saveconfig device-config");
    return 0;
}

#if 0
int config_load_pat(PatParameter *par)
{
    int i;
    char uciTupleStr[UCI_STR_MAX_LEN] = {0};
    char value[UCI_VALUE_MAX_LEN] = {0};

    if (!par) {
        AWN_LOG_ERR("Null par");
        return -1;
    }
    snprintf(par->deviceMac, sizeof (par->deviceMac),
        EMPTY_ADDR);

    for (i = 0; i < ALG_TOTAL_MODEL_COUNT; i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_PATPARAM_B_OPTION, i);
        if (uci_get_value(uciTupleStr, value) < 0) {
            AWN_LOG_ERR("Fail to load param_b @mode%d", i);
            return -1;
        }
        sscanf(value, "%hu", &par->bParameter[i]);

        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_PATPARAM_C_OPTION, i);
        if (uci_get_value(uciTupleStr, value) < 0) {
            AWN_LOG_ERR("Fail to load param_c @mode%d", i);
            return -1;
        }
    }

    return 0;
}
#endif

int config_load_score(ScoreInfo *score)
{
    char uciTupleStr[UCI_STR_MAX_LEN] = {0};
    char value[UCI_VALUE_MAX_LEN] = {0};
    int i;

    if (!score) {
        AWN_LOG_ERR("Null socre.");
        return -1;
    }

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_RANK_OPTION, score->fatherMAC);
    uci_get_value(uciTupleStr, value);
    sscanf(value, "%hhu", score->apRank);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_DELAY_CNT_OPTION, score->fatherMAC);
    uci_get_value(uciTupleStr, value);
    sscanf(value, "%hhu", &score->timeDelayTestCnt);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_DELAY_AVG_OPTION, score->fatherMAC);
    uci_get_value(uciTupleStr, value);
    sscanf(value, "%hu", &score->timeDelayAverage);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    snprintf(uciTupleStr, sizeof (uciTupleStr),
        UCI_SCORE_THRPUT_OPTION, score->fatherMAC);
    uci_get_value(uciTupleStr, value);
    sscanf(value, "%hu", &score->thrputPredict);
    memset(uciTupleStr, 0, sizeof (uciTupleStr));
    memset(value, 0, sizeof (value));

    for (i = 0; i < ARRAY_SIZE(score->rssi); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_RSSI_OPTION, score->fatherMAC, i);
        uci_get_value(uciTupleStr, value);
        sscanf(value, "%hhu", &score->rssi[i]);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    for (i = 0; i < ARRAY_SIZE(score->negoRate); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_RATE_OPTION, score->fatherMAC, i);
        uci_get_value(uciTupleStr, value);
        sscanf(value, "%hu", &score->negoRate[i]);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    for (i = 0; i < ARRAY_SIZE(score->patRate); i++) {
        snprintf(uciTupleStr, sizeof (uciTupleStr),
            UCI_SCORE_PAT_RATE_OPTION, score->fatherMAC, i);
        uci_get_value(uciTupleStr, value);
        sscanf(value, "%hu", &score->patRate[i]);
        memset(uciTupleStr, 0, sizeof (uciTupleStr));
        memset(value, 0, sizeof (value));
    }

    return 0;
}

int config_load_scores(const char *filepath)
{
    struct uci_context *uciCtx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *s = NULL;
    struct uci_element *e = NULL;
    char uciTupleStr[UCI_STR_MAX_LEN] = {0};
    int i = 0;
    const char *mac = NULL;
    ScoreInfo score = {0};

    if ((uciCtx = uci_alloc_context()) == NULL) {
        AWN_LOG_ERR("Fail to alloc uci context.");
        return -1;
    }
    uci_set_confdir(uciCtx, UCI_CONF_PATH);

    if (UCI_OK != uci_load(uciCtx, UCI_AI_NETWORK_CONFIG, &pkg)) {
        AWN_LOG_ERR("Fail to load ainetwork config.");
        goto err;
    }

    uci_foreach_element(&pkg->sections, e) {
        AWN_LOG_DEBUG("element name: %s", e->name);
        if (0 == strcmp(s->type, UCI_SCORE_SECTION_TYPE)) {
            if (uci_load_score_section(uciCtx, s, &score) < 0) {
                AWN_LOG_ERR("Fail to load seciton %s", e->name);
                goto err;
            }
            /* ALG TODO */
            /* save alg score to file path */
        }
    }
    uci_free_context(uciCtx);
    return 0;

err:
    if (uciCtx) {
        uci_free_context(uciCtx);
        uciCtx = NULL;
    }
    return -1;
}
#endif  /* CONFIG_AWN_MESH_OPT_SUPPORT */