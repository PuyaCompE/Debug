/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file        awn_log.h
 *\brief     
 *
 *\author    Weng Kaiping
 *\version    1.0.0
 *\date        11Apri16
 *
 *\history \arg 1.0.0, 11Aug16, Weng Kaiping, Create the file.     
 */

#ifndef __AWN_LOG_H__
#define __AWN_LOG_H__

#include <syslog.h>
#include <errno.h>

extern int g_awn_debug;
extern int g_awn_syslog_level;

#define AWN_LOG_DEBUG(fmt, args...) do { \
        awn_log(LOG_DEBUG, "[%s:%d]: " fmt "", __func__, __LINE__, ## args); \
} while (0)

#define AWN_LOG_INFO(fmt, args...) do { \
        awn_log(LOG_INFO, "[%s:%d]: " fmt "\n", __func__, __LINE__, ## args); \
} while (0)

#define AWN_LOG_NOTICE(fmt, args...) do { \
        awn_log(LOG_NOTICE, "[%s:%d]: " fmt "\n", __func__, __LINE__, ## args); \
} while (0)


#define AWN_LOG_WARNING(fmt, args...) do { \
        awn_log(LOG_WARNING, "[%s:%d]: " fmt "\n", __func__, __LINE__, ## args); \
} while (0)

#define AWN_LOG_ERR(fmt, args...) do { \
        awn_log(LOG_ERR, "[%s:%d]: " fmt "\n", __func__, __LINE__, ## args); \
} while (0)

#define AWN_LOG_CRIT(fmt, args...) do { \
        awn_log(LOG_CRIT, "[%s:%d]: " fmt "\n", __func__, __LINE__, ## args); \
} while (0)

/* Initialize log function. */
extern void awn_log_init(void);

extern void awn_log_exit(void);

/**
 * awn_log - Do logging for awn.
 * @level: See syslog level
 * @err: errno from syscall
 * @format: printf like format string
 *
 */
extern void awn_log(int level, const char *format, ...);

#endif  /* __AWN_LOG_H__ */

