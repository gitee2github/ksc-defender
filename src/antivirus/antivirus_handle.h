#ifndef KYLIN_ANTIVIRUS_HANDLE_H
#define KYLIN_ANTIVIRUS_HANDLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ksc_public.h"

typedef enum
{
    ANTIVIRUS_CMD_SCAN = 0,
    ANTIVIRUS_CMD_STOP,
    ANTIVIRUS_CMD_FRESH,
    ANTIVIRUS_CMD_REPORT,
    ANTIVIRUS_CMD_DEAL,
    ANTIVIRUS_CMD_INVALID,
}antivirus_cmd_e;

typedef struct 
{
    antivirus_cmd_e cmd;
    union 
    {
        char scan_path[MAX_PATH_LENGTH];
    }content;
   
}antivirus_args_t;

int antivirus_parse_args(int argc, char **argv,antivirus_args_t * args);
int antivirus_handle(antivirus_args_t * args);

#ifdef __cplusplus
}
#endif

#endif //end VURUS
