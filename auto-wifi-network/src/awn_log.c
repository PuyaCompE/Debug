/*!Copyright(c) 2016 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file      awn_log.c
 *\brief     
 *
 *\author    Weng Kaiping
 *\version   1.0.0
 *\date      11Apr16
 *
 *\history \arg 1.0.0, 11Apr16, Weng Kaiping, Create the file. 
 */

/***************************************************************************/

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>

#include "awn_log.h"


#define _LOG_MSG_LEN (512)

int g_awn_debug = LOG_NOTICE;
int g_awn_syslog_level = LOG_NOTICE;

void awn_log_init(void)
{
    openlog("awn", LOG_PID, LOG_DAEMON);
}

void awn_log(int level, const char *format, ...)
{
    char buf[_LOG_MSG_LEN + 32];
    char msg[_LOG_MSG_LEN];
    int len;
    va_list args;

    if (level > g_awn_debug && level > g_awn_syslog_level)
        return;

    va_start(args, format);
    len = vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);


    if (len < 0)
    {
        syslog(LOG_WARNING, "%s", "Failed to write log.");
    }
    else
    {
        if (level <= g_awn_syslog_level) 
        {
        	syslog(level, "%s", msg);
        }

        if (level <= g_awn_debug) 
        {
			snprintf(buf, sizeof(buf), "echo \"%s\" > /dev/console \r\n", msg);
			system(buf);
        }
    }
}

void awn_log_exit(void)
{
    closelog();
}






