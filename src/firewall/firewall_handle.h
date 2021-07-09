#ifndef KYLIN_FIREWALL_HANDLE_H
#define KYLIN_FIREWALL_HANDLE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    FIREWALL_CMD_SET_ZONE = 0,
    FIREWALL_CMD_OPEN,
    FIREWALL_CMD_CLOSE,
    FIREWALL_CMD_STATUS,
    FIREWALL_CMD_INVALID,
}firewall_cmd_e;

typedef struct 
{
    firewall_cmd_e cmd;
    union
    {
        int zone;
    }content;
}firewall_args_t;

int firewall_parse_args(int argc, char **argv,firewall_args_t * args);

int firewall_handle(firewall_args_t * args);

int firewall_handle_switch_zone(int zone);

#ifdef __cplusplus
}
#endif

#endif //end FIREWALL
