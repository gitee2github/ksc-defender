#ifndef CKSCPAMCONFIGPARSE_H
#define CKSCPAMCONFIGPARSE_H

#include "ksc_struct_info.h"
#include "KscStringConvert.h"
#include "pwquality.h"
#include <iostream>
#include <fstream>

class CKscPamconfigParse
{
public:
    static CKscPamconfigParse *get_instance();
    virtual ~CKscPamconfigParse();

    int load_pam_psw_check(SPamPswCheck &pswcheck);
    int save_pam_psw_check(SPamPswCheck pswcheck);

    int save_pam_account(const SPamAccountLock& account);
    int read_pam_account(SPamAccountLock& account);
    int read_pam_login(SPamLoginInfo& logininfo);
    int save_pam_login(const SPamLoginInfo& logininfo);
    int init_pam_login();
    bool is_set_sudoers();
    int is_show_failed();
    int set_sudoers();

private:
    CKscPamconfigParse();

    CKscStringConvert * m_KscStringConvert;

    int parse_psw_check_enable(SPamPswCheck &pswcheck);
    int parse_psw_check_detail_by_pwquality(SPamPswCheck &pswcheck);
    int pam_pwquality_get_int_value(pwquality_settings_t *settings, int setting);
    int get_psw_check_passwd_time(int &limittime, int &warntime);
    const char *pam_pwquality_get_str_value(pwquality_settings_t *settings, int setting);

    int save_pam_psw_check_enable(SPamPswCheck pswcheck);
    int save_psw_login_time(int limittime, int warntime);
    int save_pam_psw_check_disable();
    int save_pam_psw_check_pwquality(SPamPswCheck pswcheck);

    int update_user_pass_time(int limittime, int warntime);
    int update_cfg_pass_time(int limittime, int warntime);

    int copy_file(char * file,char * filecopy);
};

#endif // CKSCPAMCONFIGPARSE_H
