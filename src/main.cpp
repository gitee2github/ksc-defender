#define program_name "ksc-defender"

#include <stdio.h>
#include <getopt.h>
#include <limits.h>
#include <memory.h>
#include "KscAccountCli.h"
#include "antivirus_handle.h"
#include "firewall_handle.h"
#include "ksc_public.h"
#include "ksc_comdef.h"
#include "ksc_error.h"
#include "KscStringConvert.h"

void usage(int status)
{
    if (status != EXIT_SUCCESS)
    {
        emit_try_help();
    } 
    else
    {
        printf(_("\
Usage: %s <mode> [options] \n\
        "), program_name);
        fputs(_("\n\
Supported mode: \n\
      --account         Configure account lock and password security. \n\
      --firewall        Configure firewall security. \n\
      --antivirus       Configure antivirus security. \n\
        \n\
      --help            Display this help. \n\
      --version         Display version. \n\
"), stdout);
    }
}

void version()
{  
    FILE *pp = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;

    pp = popen("rpm -qa ksc-defender-cmd", "r");
    if(NULL == pp)
    {
        return;
    }

    while((read = getline(&line, &len, pp)) != -1)
    {
        ksc_pconst("VersionInfo: %s",line);
    }

    free(line);
    pclose(pp);
}

int main(int argc, char **argv)
{
    const char *mode;
    CKscBase *handler = nullptr;
    int ret = 0;
    if (2 > argc)
    {
        ksc_perror("invalid usage.\n");
        usage(EXIT_SUCCESS);
    }
    else
    {
        mode = argv[1];
        argc--;
        argv++;
        if (!strcmp(mode, "--help"))
        {
            usage(EXIT_SUCCESS);
            return 0;
        }
        else if (!strcmp(mode, "--version"))
        {
            version();
            return 0;
        }
        else if (!strcmp(mode, "--account"))
        {
            handler = new CKscAccountCli();
            if(handler != nullptr)
            {
                ret = handler->handle_options(argc, argv);
                delete handler;
            }
        }
        else if (!strcmp(mode, "--firewall"))
        {
            firewall_args_t firewall_args;
            memset(&firewall_args,0,sizeof(firewall_args_t));
            ret = firewall_parse_args(argc,argv,&firewall_args);
            if(0 != ret)
            {
                ksc_perror("firewall_parse_args failed,ret=%d\n",ret);
                return ret;
            }
            ret = firewall_handle(&firewall_args);
            if(0 != ret)
            {
                ksc_perror("firewall_handle failed,ret=%d\n",ret);
                return ret;
            }

        }
        else if (!strcmp(mode, "--antivirus"))
        {
            antivirus_args_t antivirus_args;
            memset(&antivirus_args,0,sizeof(antivirus_args_t));
            ret = antivirus_parse_args(argc,argv,&antivirus_args);
            if(0 != ret)
            {
                ksc_perror("antivirus_parse_args failed,ret=%d\n",ret);
            }
            ret = antivirus_handle(&antivirus_args);
            if(0 != ret)
            {
                ksc_perror("antivirus_handle failed,ret=%d\n",ret);
            }
        }
        else
        {
            ksc_perror("not support mode: %s\n", mode);
            usage(EXIT_SUCCESS);
            return -1;
        }
    }

    return ret;
}
