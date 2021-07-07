#ifndef KSC_STRUCT_INFO_H
#define KSC_STRUCT_INFO_H

#include "ksc_comdef.h"

struct SPamAccountLock{
    int enable;              //是否启用账户锁定
    long long locktime;   //账户锁定时间
    int deny;                //账户锁定阈值

    SPamAccountLock(){
        enable = 0;
        locktime = 0;
        deny = 0;
    }
};

struct SPamLoginInfo{
    int showfailed;
    int lastlog;
};

typedef struct _st_pam_pswcheck{
    int enable;                             //是否启用密码强度检查

    //int remember;                           //是否启用历史密码记录检测
    int usercheck;                    //是否拒绝使用用户名作为密码
    int palindromecheck;                   //是否启用回文检查
    int similarcheck;                      //是否启用相似性检查
    char dictpath[KSC_PATH_MAX];                //密码字典路径
    int limitday;                  //密码有效期,单位天，0表示不限制

    int minlen;                             //密码最小长度
    int minclass;                           //密码至少包含种类
    int warnday;                  //密码到期前提醒时间,单位天，0表示不提醒

}SPamPswCheck;

enum EnumPSWMode{
    DEFAULT = 0,
    CUSTOM
};

#endif // KSC_STRUCT_INFO_H
