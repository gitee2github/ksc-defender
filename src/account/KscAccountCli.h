#ifndef CKSCACCOUNTCLI_H
#define CKSCACCOUNTCLI_H

#include "KscBase.h"
#include "ksc_struct_info.h"
#include "ksc_public.h"
#include "KscPamConfigParse.h"
#include "KscPswConf.h"

#define PROGRAM_ACCOUNT_NAME "ksc-defender --account"

class CKscAccountCli : public CKscBase
{

public:
    CKscAccountCli();
    virtual ~CKscAccountCli();

    int handle_options(int argc, char **argv);
    void usage();

private:
    CKscPamconfigParse * m_CKscPamconfigParse;
    CKscPswConf * m_KscPswConf;

    int m_pswMode;

    bool is_root();
    bool check_is_root();
    bool check_sudo_with_uname(const char *uname);

    int get_status();
    int set_lock_enable(const char * optarg);
    int set_lock_deny(const char * optarg);
    int set_lock_time(const char * optarg);

    int set_pwd_enable(const char * optarg);
    int get_pwd_mode();
    int get_pwd_mode_info(const SPamPswCheck now_pswcheck);
    int get_psw_check_info();
    int set_psw_check_info(SPamPswCheck pswgrade);
    int set_pwd_status(const char * optarg);
    int handle_psw_check_default(SPamPswCheck pampswcheck);

    int handle_psw_custom_grade();
    int show_custom_menu();
    int show_custom_info_list(SPamPswCheck pampswcheck);
    int get_custom_minlen(SPamPswCheck &pampswcheck);
    int get_custom_minclass(SPamPswCheck &pampswcheck);
    int get_custom_user_check(SPamPswCheck &pampswcheck);
    int get_custom_dictpath(SPamPswCheck &pampswcheck);
    int get_custom_limit_time(SPamPswCheck &pampswcheck);
    int get_custom_warn_time(SPamPswCheck &pampswcheck);

};

#endif // CKSCACCOUNTCLI_H
