#include "KscPswConf.h"
#include "ksc_public.h"
#include "ksc_struct_info.h"

CKscPswConf::CKscPswConf()
{

}

CKscPswConf::~CKscPswConf()
{

}

int CKscPswConf::get_psw_mode(int &strmode)
{
    int ret = 0;
    FILE *fd = NULL;
    char buf[128];

    fd = fopen(KSC_PSW_MODE_CONF, "r");
    if (NULL == fd)
    {
        ksc_perror("fopen %s failed\n",KSC_PSW_MODE_CONF);
        return -1;
    }

    while (fgets(buf, 128, fd) != NULL)
    {
        // ignore comment
        if (!strncmp(buf, "#", 1))
        {
            continue;
        }

        if (!strncmp(buf, "PswMode", 7))
        {
            if (!strncmp(buf+8, "default", 7))
            {
            strmode = EnumPSWMode::DEFAULT;
            }
            if (!strncmp(buf+8, "custom", 6))
            {
            strmode = EnumPSWMode::CUSTOM;
            }
        }
    }

    fclose(fd);
    return ret;
}

int CKscPswConf::set_psw_mode(int strmode)
{
    FILE *fd = NULL;
    long offset = 0;
    char buf[128];

    fd = fopen(KSC_PSW_MODE_CONF, "r+");
    if (NULL == fd)
    {
        ksc_perror("fopen %s failed\n",KSC_PSW_MODE_CONF);
        return -1;
    }

    while (fgets(buf, 128, fd) != NULL)
    {
        if (!strncmp(buf, "PswMode", 7))
        {
            fseek(fd, offset, SEEK_SET);
            switch (strmode) {
                case DEFAULT:
                    strncpy(buf+8, "default ", 8);
                    fputs(buf, fd);
                    break;
                case CUSTOM:
                    strncpy(buf+8, "custom   ", 8);
                    fputs(buf, fd);
                    break;
                default:
                    fclose(fd);
                    return -1;
            }
        }
        offset = ftell(fd);
    }

    fclose(fd);
    return 0;
}

