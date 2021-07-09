#ifndef KSC_DEBUG_H
#define KSC_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*0-CONST 1-ERROR 2-WARN  3-INFO*/
#define TRACE_ON 0
#define DEBUG_LEVEL 1

#define ksc_pconst(fmt,arg...) printf(fmt,##arg)
#define ksc_poneline(fmt,arg...) printf("\r\033[k");printf(fmt,##arg)

#if DEBUG_LEVEL > 0
#if TRACE_ON
#define ksc_perror(fmt,arg...) printf("[ERROR][%s():%d]",__FUNCTION__,__LINE__);printf(fmt,##arg)
#else
#define ksc_perror(fmt,arg...) printf(fmt,##arg)
#endif
#else
#define ksc_perror(fmt,arg...)
#endif

#if DEBUG_LEVEL > 1
#if TRACE_ON
#define ksc_pwarn(fmt,arg...) printf("[WARN][%s():%d]",__FUNCTION__,__LINE__);printf(fmt,##arg)
#else
#define ksc_pwarn(fmt,arg...) printf(fmt,##arg)
#endif
#else
#define ksc_pwarn(fmt,arg...)
#endif

#if DEBUG_LEVEL > 2
#if TRACE_ON
#define ksc_pinfo(fmt,arg...) printf("[INFO][%s():%d]",__FUNCTION__,__LINE__);printf(fmt,##arg)
#else
#define ksc_pinfo(fmt,arg...) printf(fmt,##arg)
#endif
#else
#define ksc_pinfo(fmt,arg...)
#endif

#define MAX_CMDLINE_BUFFER_SIZE 1024
#define MAX_PATH_LENGTH 512
#define MAX_CONF_LINE_LENGTH 512
#define MAX_URL_LENGTH 512

#endif
