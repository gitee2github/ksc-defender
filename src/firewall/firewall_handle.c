#include <errno.h>
#include <netdb.h>
#include "firewall_handle.h"
#include "ksc_firewall.h"
#include "ksc_public.h"
#include "ksc_comdef.h"

void firewall_usage(int status)
{
    if (status != EXIT_SUCCESS)
    {
        ksc_pconst("Try 'ksc-cmd --firewall --help' for more information.\n");
    }
    else 
    {
        ksc_pconst("\
Usage: ksc-defender --firewall [options] \n");
        ksc_pconst("\n\
<mode>\n\
      ksc-defender --firewall\n\
[options]\n\
      --policy <public|work|custom>  Set firewall policy. \n\
      --status                       View firewall status. \n\
      --enable                       Open firewall.        \n\
      --disable                      Close firewall.       \n");
    }
    exit(0);
}

int firewall_parse_args(int argc, char **argv,firewall_args_t * args)
{
    if(NULL == argv || NULL == args)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    const char *cmd = argv[1];
    argc--;
    argv++;
    if(NULL == cmd)
    {
        ksc_perror("Invalid usage.\n");
        firewall_usage(EXIT_SUCCESS);
        return -1;
    }
   
    if (!strcmp(cmd, "--help")) 
    {
        firewall_usage(EXIT_SUCCESS);
    }
    else if(!strcmp(cmd, "--policy"))
    {           
        const char *zone = argv[1];
        argc--;
        //argv++;
        if(NULL == zone)
        {
            ksc_perror("Option \'--policy\' miss arguments.\n");
            firewall_usage(EXIT_SUCCESS);
        }
        args->cmd = FIREWALL_CMD_SET_ZONE;
        if (!strcmp(zone, "public")) 
        {     
            args->content.zone = PUBLIC_ZONE;
            return 0;
        }
        else if(!strcmp(zone, "work"))
        {
            args->content.zone = WORK_ZONE;
            return 0;
        }
        else if(!strcmp(zone, "custom"))
        {
            args->content.zone = CUSTOM_ZONE;
            return 0;
        }
        else
        {
            args->cmd = FIREWALL_CMD_INVALID;
            ksc_pconst("Invalid policy:%s.\n",zone);
            firewall_usage(EXIT_SUCCESS);
        }
    }
    else if(!strcmp(cmd, "--status"))
    {           
        args->cmd = FIREWALL_CMD_STATUS;
    }
    else if(!strcmp(cmd, "--enable"))
    {           
        args->cmd = FIREWALL_CMD_OPEN;
    }
    else if(!strcmp(cmd, "--disable"))
    {           
        args->cmd = FIREWALL_CMD_CLOSE;
    }
    else
    {
        args->cmd = FIREWALL_CMD_INVALID;
        ksc_perror("Invalid usage.\n");
        firewall_usage(EXIT_SUCCESS);
    }
    return 0;
}

static int firewall_check_protocol(const char * protocol)
{
    struct protoent * ptr = NULL;

    ptr = getprotobyname(protocol);
    if(NULL == ptr)
    {
        return -1;
    }
    return 0;
}

static int check_port_string(const char * port_str)
{
    int str_len = strlen(port_str);
    int i = 0;
    for(i = 0; i < str_len; i++)
    {
        if(*(port_str+i) < '0' || *(port_str+i) > '9')
        {            
            return -1;
        }
    }
    return 0;
}

static int firewall_add_custom_rules()
{
    int ret = 0;
    Service_P_Node services_node;
    char str_protocol[MAX_CMDLINE_BUFFER_SIZE];
    char str_port[MAX_CMDLINE_BUFFER_SIZE];

    memset(str_protocol,0,sizeof(str_protocol));
    scanf("%1023s",str_protocol);
    ksc_pinfo("str_buf=%s\n",str_protocol);

    ret = firewall_check_protocol(str_protocol);
    if(ret)
    {
        ksc_pconst("Unknown protocol:%s,should in [tcp|udp|sctp|dccp|icmp|igmp|ah]\n",str_protocol);
        return -1;
    }

    memset(&services_node,0,sizeof(services_node));

    if((0 == strcmp(str_protocol,"tcp"))
     || (0 == strcmp(str_protocol,"udp"))
     || (0 == strcmp(str_protocol,"sctp"))
     || (0 == strcmp(str_protocol,"dccp")))
    {
        memset(str_port,0,sizeof(str_port));
        scanf("%1023s",str_port);
        ksc_pinfo("str_buf=%s\n",str_port);
        ret = check_port_string(str_port);
        if(ret)
        {
            ksc_pconst("Invalid format:%s,should be numbers\n",str_port);
            return -1;
        }
        strncpy(services_node.s_port,str_port,sizeof(services_node.s_port)-1);

    }
    else if((0 == strcmp(str_protocol,"icmp"))
     || (0 == strcmp(str_protocol,"ah"))
     || (0 == strcmp(str_protocol,"igmp")))
    {
        /*do nothing*/
    }
    else
    {
        ksc_pconst("Unknown protocol:%s,should in [tcp|udp|sctp|dccp|icmp|igmp|ah]\n",str_protocol);
        return -1;
    }
    strncpy(services_node.protocol,str_protocol,sizeof(services_node.protocol)-1);
    ret = ksc_firewall_service_check_protocol_port(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME,services_node);
    if(1 != ret)
    {    
        ret = ksc_firewall_service_add_protocol_port(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME,services_node);
        if(ret < 0)
        {
            ksc_perror("ksc_firewall_service_add_protocol_port failed,ret=%d\n",ret);
        }
        else
        {
            ksc_pinfo("ksc_firewall_service_add_protocol_port success\n");
        }
        ret = ksc_firewall_service_enable(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
        if(ret < 0)
        {
            ksc_perror("ksc_firewall_service_enable failed,ret=%d\n",ret);
        }
        else
        {
            ksc_pinfo("ksc_firewall_service_enable success\n");
        }
    }
    else
    {
        ksc_pconst("The rule is already exist.\n");
        return 0;
    }
    ksc_pconst("Add a rule success.\n");
    return 0;
}

static int firewall_del_custom_rules()
{
    int index = 0,ret = 0;
    char str_index[MAX_CMDLINE_BUFFER_SIZE];

    memset(str_index,0,sizeof(str_index));
    scanf("%1023s",str_index);
    ksc_pinfo("str_index=%s\n",str_index);
    index = atoi(str_index);
    if(index <= 0)
    {
        if(strstr(str_index,"all"))
        {
            ksc_pconst("you want to delete all rules?[yes/no]\n");
            memset(str_index,0,sizeof(str_index));
            scanf("%1023s",str_index);
            if((!strcmp(str_index, "yes")) || (!strcmp(str_index, "Y")) || (!strcmp(str_index, "y")))
            {
                ksc_pconst("delete all rules,please wait\n");
                ret = ksc_firewall_service_delete_all_node(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
                if(ret < 0)
                {
                    ksc_pconst("try to delete all rules failed,ret=%d\n", ret);
                    return -1;
                }

                ret = ksc_firewall_service_enable(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
                if(ret < 0)
                {
                    ksc_perror("ksc_firewall_service_enable failed,ret=%d\n", ret);
                }
                else
                {
                    ksc_pinfo("ksc_firewall_service_enable success\n");
                }
                
                ksc_pconst("delete all rules success\n");
                return 0;
            }
            else
            {
                ksc_pconst("Do nothing.\n");
                return 0;   
            }
        }
        else
        {
            ksc_perror("Invalid index=%s\n", str_index);
            return -1;
        }
    }
    ret = ksc_firewall_service_delete_node(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME,index);
    if(0 == ret)
    {
        ksc_pconst("Delete a rules success.\n");
    }
    else if(1 == ret)
    {
        ksc_pconst("Not found index:%d in the custom rules\n",index);
    }
    else
    {
        ksc_perror("ksc_firewall_service_delete_node failed,ret=%d\n",ret);
    }

    ret = ksc_firewall_service_enable(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
    if(ret < 0)
    {
        ksc_perror("ksc_firewall_service_enable failed,ret=%d\n", ret);
    }
    else
    {
        ksc_pinfo("ksc_firewall_service_enable success\n");
    }
    return 0;   
}

static int firewall_bakup_custom_rules(void)
{
    int ret = 0;
    ret = ksc_firewall_service_bakup(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
    if(ret)
    {
        ksc_perror("ksc_firewall_service_bakup failed,ret=%d\n", ret);
        return -1;
    }
    return 0;
}

static int firewall_restore_custom_rules(void)
{
    int ret = 0;
    ret = ksc_firewall_service_restore(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
    if(ret)
    {
        ksc_perror("ksc_firewall_service_restore failed,ret=%d\n", ret);
        return -1;
    }
    return 0;
}

static int firewall_remove_bakup_custom_rules(void)
{
    int ret = 0;
    ret = ksc_firewall_service_remove_bakup(KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME);
    if(ret)
    {
        ksc_perror("ksc_firewall_service_remove_bakup failed,ret=%d\n", ret);
        return -1;
    }
    return 0;

}

static int firewall_show_custom_rules()
{
    int ret = 0, index = 1;
    Service_Detail services;
    memset(&services,0,sizeof(Service_Detail));
    services.ports = (Service_P_Node*)calloc(1, sizeof(Service_P_Node));
    services.ports->next = NULL;

    ret = ksc_firewall_service_get(CUSTOM_ZONE,KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME,&services);
    if(ret)
    {
        ksc_perror("ksc_firewall_service_get CUSTOM_ZONE failed,ret=%d\n", ret);
    }
    ksc_pinfo("service_name=%s\n",services.service_name);
    ksc_pinfo("short_cut=%s\n",services.short_cut);
    ksc_pinfo("description=%s\n",services.description);
    ksc_pinfo("uuid=%s\n",services.uuid);

    ksc_pconst("      index  protocol port:\n");
    Service_P_Node *p = services.ports;
    while (p->next)
    {
        p = p->next;
        ksc_pconst("        %d      %s    %s\n", index++, p->protocol, p->s_port);
    }

out:
    service_node_free(services.ports);
    return ret;
}

static void firewall_custom_menu(void)
{
    ksc_pconst("[commands]\n");
    ksc_pconst("      ls                          View custom rules.\n");
    ksc_pconst("      del <index|all>             Delete a rule by index,or delete all rules.\n");
    ksc_pconst("      add <protocol> <port>       Add a rule with protocol and port.\n");
    ksc_pconst("      exit                        Only exit custom menu.\n");
    ksc_pconst("      apply                       Apply and exit custom menu. \n");
    ksc_pconst("      help                        Display this help.\n");
}

int firewall_handle_custom_zone(void)
{
    char str_buf[MAX_CMDLINE_BUFFER_SIZE];
    int ret = 0;
    firewall_custom_menu();
    firewall_bakup_custom_rules();
    while(1)
    {
        memset(str_buf,0,sizeof(str_buf));
        ksc_pconst(": ");
        scanf("%1023s",str_buf);
        ksc_pinfo("str_buf=%s\n",str_buf);

        if (!strcmp(str_buf, "help")) 
        {
            firewall_custom_menu();
        }
        else if(!strcmp(str_buf, "ls"))
        {
            ret = firewall_show_custom_rules();
            if(ret)
            {
                ksc_perror("firewall_show_custom_rules failed,ret=%d\n",ret);
            }
        }
        else if(!strcmp(str_buf, "add"))  
        {
            ret = firewall_add_custom_rules();
            if(ret)
            {
                ksc_perror("add a rule failed,ret=%d\n",ret);
            }
        }
        else if(!strcmp(str_buf, "del"))  
        {
            ret = firewall_del_custom_rules();
            if(ret)
            {
                ksc_perror("del the rule failed,ret=%d\n",ret);
            }
        }
        else if(!strcmp(str_buf, "exit"))  
        {            
            firewall_restore_custom_rules();
            firewall_remove_bakup_custom_rules();
            ksc_pconst("Exit and not apply.\n");
            return 0;
        }
        else if(!strcmp(str_buf, "apply"))  
        {
            firewall_remove_bakup_custom_rules();
            ksc_pconst("Exit and apply.\n");
            return 1;
        }
        else
        {
            ksc_pconst("Invalid command.Input \"help\" to view commands format.\n");
        }
    }
    return 0;
}

int firewall_handle_switch_zone(int zone)
{
    int file_zone = ksc_firewall_zone_get();
    int ret = 0;
    if(TRUSTED_ZONE == file_zone)
    {
        ksc_perror("firewall not open. use --enable open it,before you set policy\n");
        return -1;
    }

    switch(zone)
    {
        case PUBLIC_ZONE:
        {
            /*set public rules*/
            ret = ksc_firewall_zone_set(PUBLIC_ZONE);
            if(0 != ret)
            {
                ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
                return -1;
            }
            ksc_pconst("firewall set policy: public\n");
        }
        break;

        case WORK_ZONE:
        {
            /*set work rules*/
            ret = ksc_firewall_zone_set(WORK_ZONE);
            if(0 != ret)
            {
                ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
                return -1;
            }
            ksc_pconst("firewall set policy: work\n");
        }
        break;

        case CUSTOM_ZONE:        
        {
            ret = ksc_firewall_zone_set(CUSTOM_ZONE);
            if(0 != ret)
            {
                ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
                return -1;
            }
            /*change CUSTOM rules*/
            int choose = 0;/*<0 error ,0 not apply custom rules, 1 apply custom rules*/
            choose = firewall_handle_custom_zone();
            if(choose < 0)
            {
                ksc_perror("firewall_handle_custom_zone failed,ret=%d\n");
            }
            else if(1 == choose)
            {
                ret = ksc_firewall_zone_set(CUSTOM_ZONE);
                if(0 != ret)
                {
                    ksc_perror("ksc_firewall_zone_set failed,ret=%d\n", ret);
                    return -1;
                }
                ksc_pconst("firewall set policy: custom\n");
            }
            else if(0 == choose)
            {
                ret = ksc_firewall_zone_set(file_zone);
                if(0 != ret)
                {
                    ksc_perror("ksc_firewall_zone_set failed,ret=%d\n", ret);
                    return -1;
                }
                ksc_pinfo("firewall not set policy: custom\n");
            }
        }
        break;

        default:
        ksc_perror("invalid policy type\n");
        break;

    }
    return 0;
}

int firewall_handle_open()
{
    int file_zone = ksc_firewall_zone_get();
    int ret = 0;
    if((file_zone >= PUBLIC_ZONE) && (file_zone < TRUSTED_ZONE))
    {
        ret = ksc_firewall_zone_set(file_zone);
        if(0 != ret)
        {
            ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
            return -1;
        }        
        ksc_pconst("firewall has already been opened\n");
    }
    else
    {
        ret = ksc_firewall_zone_set(PUBLIC_ZONE);
        if(0 != ret)
        {
            ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
            return -1;
        }        
        ksc_pconst("firewall has been opened\n");
    }

    return 0;
}

int firewall_handle_close()
{
    int file_zone = ksc_firewall_zone_get();
    int ret = 0;
    if(TRUSTED_ZONE == file_zone)
    {
        ksc_pconst("firewall has already been closed\n");
    }
    else
    {
        ret = ksc_firewall_zone_set(TRUSTED_ZONE);
        if(0 != ret)
        {
            ksc_perror("ksc_firewall_zone_set failed,ret=%d\n",ret);
            return -1;
        }
        ksc_pconst("firewall has been closed\n");
    }
    return 0;
}

int firewall_handle_status()
{
    int file_zone = ksc_firewall_zone_get();

    if(TRUSTED_ZONE == file_zone)
    {
        ksc_pconst("      firewall: off\n");
    }
    else if(file_zone >= PUBLIC_ZONE && file_zone < TRUSTED_ZONE)
    {
        ksc_pconst("      firewall: on\n");
        if(WORK_ZONE == file_zone)
        {
            ksc_pconst("      policy:   work\n");
        }
        else if(PUBLIC_ZONE == file_zone)
        {
            ksc_pconst("      policy:   public\n");
        }
        else if(CUSTOM_ZONE == file_zone)
        {
            ksc_pconst("      policy:   custom\n");
            ksc_pconst("      custom rules:\n");
            firewall_show_custom_rules();
        }
    }
    else
    {
        ksc_pconst("      firewall: off\n");
    }
}

int firewall_handle(firewall_args_t * args)
{
    if(NULL == args)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    switch(args->cmd)
    {
        case FIREWALL_CMD_SET_ZONE:
            firewall_handle_switch_zone(args->content.zone);
        break;

        case FIREWALL_CMD_OPEN:
            firewall_handle_open();
        break;

        case FIREWALL_CMD_CLOSE:
            firewall_handle_close();
        break;

        case FIREWALL_CMD_STATUS:
            firewall_handle_status();
        break;

        default:
        ksc_perror("invalid cmd\n");
        break;

    }
    return 0;
}

