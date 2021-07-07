#include "KscAccountCli.h"
#include <getopt.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>

const SPamPswCheck pswcheck_default_R_serials = {1, 0, 1, 1, "", 0, 8, 2, 7};
const SPamPswCheck pswcheck_off_R_serials = {0, 0, 0, 0, "", 0, 0, 0, 0};
const SPamPswCheck pswcheck_custom_R_serials = {1, 0, 1, 1,"", 0, 8, 2, 7};

CKscAccountCli::CKscAccountCli()
{
    m_CKscPamconfigParse = CKscPamconfigParse::get_instance();
    m_KscPswConf = new CKscPswConf();
    m_pswMode = 0;
}

CKscAccountCli::~CKscAccountCli()
{

}

struct option const long_opts[] =
{
    {"help", no_argument, NULL, 'h'},
    {"status", no_argument, NULL, 'a'},
    {"lock", required_argument, NULL, 'l'},
    {"lock_deny", required_argument, NULL, 'd'},
    {"lock_time", required_argument, NULL, 't'},
    {"pwd", required_argument, NULL, 'p'},
    {"pwd_get", no_argument, NULL, 'g'},
    {"pwd_set", required_argument, NULL, 's'},
    {NULL, 0, NULL, 0}
};

void CKscAccountCli::usage()
{
    ksc_pconst("\
Usage: ksc-defender --account [options] \n");
    ksc_pconst(_("\n\
<mode>\n\
      ksc-defender --account\n\
[options] \n\
      --help                         Display this help menu.\n\
      --status                       The status of account security. \n\
      --lock <on|off>                Enable or disable account locking. \n\
      --lock_deny [number]           Deny after <number> times error password. \n\
      --lock_time [minutes]          Account locked time if denied. \n\
      --pwd <on|off>                 Enable or disable account password. \n\
      --pwd_get                      The current grade of account password. \n\
      --pwd_set <default|custom>     The grade of account password settings. \n\
 "));

        exit(0);
}

int CKscAccountCli::handle_options(int argc, char **argv)
{
    int rc = 0, ret = 0;
    if(NULL == argv)
    {
        ksc_perror("Invalid usage.\n");
        return -1;
    }
    const char *cmd = argv[1];

    if(NULL == cmd)
    {
        ksc_perror("Invalid usage.\n");
        this->usage();
        return -1;
    }
    else
    {
        if(strcmp(cmd, "--help") != 0 && strcmp(cmd, "--status") != 0 && strcmp(cmd, "--lock") != 0
                && strcmp(cmd, "--lock_deny") != 0 && strcmp(cmd, "--lock_time") != 0
                && strcmp(cmd, "--pwd") != 0 && strcmp(cmd, "--pwd_get") != 0
                && strcmp(cmd, "--pwd_set") != 0)
        {
            ksc_perror("Invalid usage.\n");
            this->usage();
            return -1;
        }
    }

    while ((rc = getopt_long(argc, argv, "hl", long_opts, NULL)) != -1)
    {
        switch (rc)
        {
            case 'h':
                this->usage();
                break;
            case 'a':
                ret = get_status();
                break;
            case 'l':
                ret = set_lock_enable(optarg);
                break;
            case 'd':
                ret = set_lock_deny(optarg);
                break;
            case 't':
                ret = set_lock_time(optarg);
                break;
            case 'p':
                ret = set_pwd_enable(optarg);
                break;
            case 'g':
                ret = get_psw_check_info();
                break;
            case 's':
                ret = set_pwd_status(optarg);
                break;
            default:
                ksc_pconst("Invalid usage.\n");
                this->usage();
                break;
        }
    }

    return 0;
}

bool CKscAccountCli::is_root()
{    
    char *strUser = getenv("USER");
    bool isroot = strcmp("root", strUser);
    return !isroot;
    //return check_isRoot();
}

bool CKscAccountCli::check_is_root()
{
    uid_t uid = getuid();
    struct passwd *pwd = NULL;

    std::cout << uid << std::endl;
    pwd = getpwuid(uid);
    if (!pwd) {
        printf("Failed to get passwd struct for %d: %s\n", uid, strerror(errno));
        return -1;
    }

    std::cout << pwd->pw_name << std::endl;
    if (check_sudo_with_uname(pwd->pw_name) == 1)
    {
        return true;
    }

    return false;
}

bool CKscAccountCli::check_sudo_with_uname(const char *uname)
{
    const char *gname = "wheel";

    struct group *grp_info = NULL;
    int i = 0;

    grp_info = getgrnam(gname);
    if (!grp_info) {
        printf("Failed to get group for %s: %s\n", gname, strerror(errno));
        return -1;
    }

    while (grp_info->gr_mem[i]) {
        std::cout << grp_info->gr_mem[i++] << std::endl;
        if (0 == strcmp(grp_info->gr_mem[i++], uname)) {
            printf("%s is sudo group\n", uname);
            return 1;
        }
    }

    return 0;
}

int CKscAccountCli::get_status()
{
    struct SPamAccountLock account;
    int ret = 0;

    ret = m_CKscPamconfigParse->read_pam_account(account);
    if(ret != 0){
        ksc_perror("ksc-defender_account read_apmAccount failed:%d \n", ret);
        return ret;
    }

    std::string status;
    if(account.enable == 1)
    {
        status = "on";
        std::cout << "ksc-defender_account: lockswitch         " << status << std::endl;
        std::cout << "ksc-defender_account: denynum            " << account.deny << std::endl;
        std::cout << "ksc-defender_account: locktime[minute]   " << account.locktime / 60 << std::endl << std::endl;
    }
    else
    {
        status = "off";
        std::cout << "ksc-defender_account: lockswitch         " << status << std::endl << std::endl;
    }

    get_pwd_mode();

    return KSC_OK;
}

int CKscAccountCli::set_lock_enable(const char *optarg)
{
    if(!is_root()){
        ksc_perror("ksc-defender_account please use sudo or su to try again! \n");
        return KSC_PERMISSIONSERR;
    }
    if(optarg == nullptr){
        ksc_perror("ksc-defender_account parameter error:%d \n", KSC_PARAMETERERR);
        return KSC_PARAMETERERR;
    }

    struct SPamAccountLock account;
    if(strcmp(optarg, "on") && strcmp(optarg, "off"))
    {
        ksc_perror("ksc-defender_account parameter error:%d \n", KSC_PARAMETERERR);
        return KSC_PARAMETERERR;
    }

    struct SPamAccountLock originally;
    int ret = 0;

    if((ret = m_CKscPamconfigParse->read_pam_account(originally))){
        ksc_perror("ksc-defender_account read_apmAccount failed:%d \n", ret);
        return ret;
    }

    if(!strcmp(optarg, "on")){
        if(originally.enable == 1)
        {
            ksc_pconst("ksc-defender_account current lock status has already been opened! \n");
            return KSC_STATEERR;
        }

        account.locktime = KSC_ACCOUNT_UNLOCK_TIME;
        account.deny = KSC_ACCOUNT_DENY;
        account.enable = 1;
    }

    if(!strcmp(optarg, "off")){
        if(originally.enable == 0)
        {
            ksc_pconst("ksc-defender_account current lock status has already been closed! \n");
            return KSC_STATEERR;
        }

        account.locktime = 0;
        account.deny = 0;
        account.enable = 0;
    }

    ret = m_CKscPamconfigParse->save_pam_account(account);
    if(ret)
    {
        return -1;
    }
    ksc_pconst("ksc-defender_account set_lock %s success!\n", optarg);

    return 0;
}

int CKscAccountCli::set_lock_deny(const char *optarg)
{
    if(!is_root()){
        ksc_perror("ksc-defender_account please use sudo or su to try again! \n");
        return KSC_PERMISSIONSERR;
    }
    if(optarg == nullptr){
        ksc_perror("ksc-defender_account parameter error:%d \n", KSC_PARAMETERERR);
        return KSC_PARAMETERERR;
    }

    struct SPamAccountLock account;
    struct SPamAccountLock originally;
    int ret = 0;

    if((ret = m_CKscPamconfigParse->read_pam_account(originally))){
        ksc_perror("ksc-defender_account read_apmLogin failed:%d \n", ret);
        return ret;
    }
    if(originally.enable == 0){
        ksc_pconst("ksc-defender_account lock status is off,Please lock on and try again! \n");
        return KSC_STATEERR;
    }

    account.deny = atoi(optarg);
    if(account.deny < KSC_ACCOUNT_DENY || account.deny > KSC_ACCOUNT_DENY_MAX){
        ksc_perror("ksc-defender_account: The denytimes should be be 3 to 16! Please try again! \n");
        return KSC_RANGE_RERR;
    }

    account.enable = originally.enable;
    account.locktime = originally.locktime;

    ret =  m_CKscPamconfigParse->save_pam_account(account);
    if(ret)
    {
        return -1;
    }
    ksc_pconst("ksc-defender_account set_lockDeny success!\n");
    return 0;
}

int CKscAccountCli::set_lock_time(const char *optarg)
{
    if(!is_root()){
        ksc_perror("ksc-defender_account please use sudo or su to try again! \n");
        return KSC_PERMISSIONSERR;
    }
    if(optarg == nullptr){
        ksc_perror("ksc-defender_account parameter error:%d \n", KSC_PARAMETERERR);
        return KSC_PARAMETERERR;
    }

    struct SPamAccountLock account;
    struct SPamAccountLock originally;
    int ret = 0;
    int locktimes = 0;

    if((ret = m_CKscPamconfigParse->read_pam_account(originally))){
        ksc_perror("ksc-defender_account read_apmLogin failed:%d \n", ret);
        return ret;
    }

    if(originally.enable == 0){
        ksc_pconst("ksc-defender_account lock status is off,Please lock on and try again! \n");
        return KSC_STATEERR;
    }

    locktimes = atoi(optarg);
    if(locktimes < KSC_ACCOUNT_LOCK_TIME_MIN || locktimes > KSC_ACCOUNT_LOCK_TIME_MAX){
        ksc_perror("ksc-defender_account: The denytimes should be be 1 to 30! Please try again! \n");
        return KSC_RANGE_RERR;
    }

    account.locktime = locktimes * 60;
    account.enable = originally.enable;
    account.deny = originally.deny;

    ret = m_CKscPamconfigParse->save_pam_account(account);
    if(ret)
    {
        return -1;
    }
    ksc_pconst("ksc-defender_account set_locktime success!\n");
    return 0;
}

int CKscAccountCli::set_pwd_enable(const char *optarg)
{
    if(!is_root()){
        ksc_perror("ksc-defender_account please use sudo or su to try again! \n");
        return KSC_PERMISSIONSERR;
    }
    if(optarg == nullptr){
        ksc_perror("ksc-defender_account invalid parameter!\n");
        return KSC_PARAMETERERR;
    }

    int ret = 0;

    SPamPswCheck pampswcheck;
    memset(&pampswcheck, 0x00, sizeof(SPamPswCheck));
    if(strcmp(optarg, "on") != 0 && strcmp(optarg, "off") != 0)
    {
        ksc_perror("ksc-defender_account pwe switch: invalid parameter!\n");
        return KSC_PARAMETERERR;
    }

    if(!strcmp(optarg, "on")){
        ret = m_KscPswConf->get_psw_mode(m_pswMode);
        if (ret)
        {
            ksc_perror("ksc-defender_account: get_pswMode failed, ret =%d \n", ret);
            return -1;
        }

        if(m_pswMode == DEFAULT)
        {
            pampswcheck = pswcheck_default_R_serials;
        }
        else
        {
            pampswcheck = pswcheck_custom_R_serials;
        }

        ret = handle_psw_check_default(pampswcheck);
        if (ret)
        {
            ksc_pconst("ksc-defender_account pswswitch has already been opend!\n");
            return -1;
        }
    }

    if(!strcmp(optarg, "off"))
    {
        pampswcheck = pswcheck_off_R_serials;

        ret = handle_psw_check_default(pampswcheck);
        if (ret)
        {
            ksc_pconst("ksc-defender_account pswswitch has already been closed!\n");
            return -1;
        }
    }

    ksc_pconst("ksc-defender_account pwdswitch %s success\n", optarg);
    return ret;
}

int CKscAccountCli::get_pwd_mode()
{
    int ret = 0;
    SPamPswCheck now_pswcheck;

    ret = m_CKscPamconfigParse->load_pam_psw_check(now_pswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account: load_pamPswCheck failed, ret =%d\n", ret);
        return -1;
    }

    ret = get_pwd_mode_info(now_pswcheck);
    if (ret)
    {
        return -1;
    }
    return 0;
}

int CKscAccountCli::get_pwd_mode_info(const SPamPswCheck now_pswcheck)
{
    int ret = 0;
    std::string status;
    if(now_pswcheck.enable == 1)
    {
        status = "on";
        std::cout << "ksc-defender_account: pwd switch         " << status << std::endl;

        ret = m_KscPswConf->get_psw_mode(m_pswMode);
        if(ret)
        {
            ksc_perror("ksc-defender_account: get_pswMode failed, ret =%d\n", ret);
            return -1;
        }

        SPamPswCheck defaultpampswcheck;
        memset(&defaultpampswcheck, 0x00, sizeof(SPamPswCheck));
        defaultpampswcheck = pswcheck_default_R_serials;

        if(m_pswMode == DEFAULT)
        {
            if(memcmp(&defaultpampswcheck, &now_pswcheck, sizeof(SPamPswCheck)) == 0)
            {

                std::cout << "ksc-defender_account: pwdmode            default" << std::endl;
            }
            else
            {
                ret = m_KscPswConf->set_psw_mode(CUSTOM);
                if(ret)
                {
                    ksc_perror("ksc-defender_account: set_pswMode failed, ret =%d\n", ret);
                    return -1;
                }
                std::cout << "ksc-defender_account: pwdmode            custom" << std::endl;
            }
        }
        else
        {
            std::cout << "ksc-defender_account: pwdmode            custom" << std::endl;
        }
    }
    else
    {
        status = "off";
        std::cout << "ksc-defender_account: pwd switch         " << status << std::endl;
    }

    return 0;
}

int CKscAccountCli::get_psw_check_info()
{
    int ret = 0;

    if(optarg != nullptr){
        ksc_perror("ksc-defender_account pwd_get: invalid parameter!\n");
        return KSC_PARAMETERERR;
    }

    SPamPswCheck pampswcheck;
    ret = m_CKscPamconfigParse->load_pam_psw_check(pampswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account get_pswCheckInfo failed! ret = %d \n", ret);
        return -1;
    }

    ret = get_pwd_mode_info(pampswcheck);
    if (ret)
    {
        return -1;
    }

    std::cout << std::endl;

    ret = show_custom_info_list(pampswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account show_customInfoList failed! ret = %d \n", ret);
        return -1;
    }
    return ret;
}

int CKscAccountCli::set_pwd_status(const char *optarg)
{
    if(!is_root()){
        ksc_perror("ksc-defender_account: please use sudo or su to try again! \n");
        return KSC_PERMISSIONSERR;
    }
    if(optarg == nullptr){
        ksc_perror("ksc-defender_account: optarg parameter is invalid.\n");
        return KSC_PARAMETERERR;
    }

    int ret = 0;

    SPamPswCheck now_pswcheck;
    ret = m_CKscPamconfigParse->load_pam_psw_check(now_pswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account get_pswCheckInfo failed! ret = %d \n", ret);
        return -1;
    }
    if(now_pswcheck.enable == 0)
    {
        ksc_pconst("ksc-defender_account pwd status is off,Please pwd on and try again! \n");
        return KSC_STATEERR;
    }

    if(strcmp(optarg, "default") != 0 && strcmp(optarg, "custom") != 0)
    {
        ksc_perror("ksc-defender_account pwe_set: invalid parameter!\n");
        return KSC_PARAMETERERR;
    }

    if(strcmp(optarg, "default") == 0)
    {
        SPamPswCheck defaultpampswcheck;
        memset(&defaultpampswcheck, 0x00, sizeof(SPamPswCheck));
        defaultpampswcheck = pswcheck_default_R_serials;

        ret = m_KscPswConf->get_psw_mode(m_pswMode);
        if(ret)
        {
            ksc_perror("ksc-defender_account: get_pswMode failed, ret =%d\n", ret);
            return -1;
        }

        if(m_pswMode == DEFAULT)
        {
            if(memcmp(&defaultpampswcheck, &now_pswcheck, sizeof(SPamPswCheck)) == 0)
            {
                ksc_pconst("ksc-defender_account pwd mode has already been default! \n");
                return -1;
            }
        }

        ret = m_CKscPamconfigParse->save_pam_psw_check(defaultpampswcheck);
        if (ret < 0)
        {
            ksc_perror("ksc-defender_account save_pamPswCheck failed : %d\n", ret);
            return -1;
        }
        m_pswMode = DEFAULT;
    }
    else if(strcmp(optarg, "custom") == 0)
    {
        ret = handle_psw_custom_grade();
        if (ret < 0)
        {
            ksc_perror("ksc-defender_account password get edit data failed!\n");
            return ret;
        }
        else if(ret > 0)
        {
            ksc_perror("ksc-defender_account exit custom psw mode !\n");
            return ret;
        }

        m_pswMode = CUSTOM;
    }

    ret = m_KscPswConf->set_psw_mode(m_pswMode);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account set_pswMode failed! ret = %d \n", ret);
        return -1;
    }

    if(m_pswMode == DEFAULT)
    {
        ksc_pconst("ksc-defender_account set_pswMode: default success!\n");
    }
    else
    {
        ksc_pconst("ksc-defender_account set_pswMode: custom success!\n");
    }
    return ret;
}

int CKscAccountCli::handle_psw_check_default(SPamPswCheck pampswcheck)
{
    int ret = 0;
    SPamPswCheck now_pswcheck;
    ret = m_CKscPamconfigParse->load_pam_psw_check(now_pswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account load_pamPswCheck failed : %d\n", ret);
        return -1;
    }

    if (memcmp(&pampswcheck, &now_pswcheck, sizeof(SPamPswCheck)) == 0)
    {
        return -1;
    }

    ret = m_CKscPamconfigParse->save_pam_psw_check(pampswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account save_pamPswCheck failed : %d\n", ret);
        return -1;
    }
    return ret;
}

int CKscAccountCli::handle_psw_custom_grade()
{
    int ret = 0;
    char in_buf[KSC_MAX_LEN];

    SPamPswCheck pampswcheck;
    ret = m_CKscPamconfigParse->load_pam_psw_check(pampswcheck);
    if (ret < 0)
    {
        ksc_perror("ksc-defender_account load_pamPswCheck failed : %d\n", ret);
        return -1;
    }

    show_custom_menu();
    while(1)
    {
        memset(in_buf,0,sizeof(in_buf));
        ksc_pconst(": ");
        scanf("%1023s", in_buf);

        if(strcmp(in_buf,"ls") == 0)
        {
            ret = show_custom_info_list(pampswcheck);
            if(ret)
            {
                ksc_perror("ksc-defender_account show_customInfoList failed : %d\n", ret);
                return -1;
            }
        }
        else if(strcmp(in_buf,"minlen") == 0)
        {
            get_custom_minlen(pampswcheck);
        }
        else if(strcmp(in_buf,"minclass") == 0)
        {
            get_custom_minclass(pampswcheck);
        }
        else if(strcmp(in_buf,"usercheck") == 0)
        {
            get_custom_user_check(pampswcheck);
        }
        else if(strcmp(in_buf,"dictcheck") == 0)
        {
            get_custom_dictpath(pampswcheck);
        }
        else if(strcmp(in_buf,"limitday") == 0)
        {
            get_custom_limit_time(pampswcheck);
        }
        else if(strcmp(in_buf,"warnday") == 0)
        {
            if(pampswcheck.limitday == 0)
            {
                ksc_pconst(": ksc-defender_account limitday is 0,no need to set warnday value!\n");
                continue;
            }
            get_custom_warn_time(pampswcheck);
        }
        else if(strcmp(in_buf,"exit") == 0)
        {
            return 1;
        }
        else if(strcmp(in_buf,"apply") == 0)
        {
            break;
        }
        else if(strcmp(in_buf,"help") == 0)
        {
            show_custom_menu();
        }
        else
        {
            ksc_pconst("Please re-enter the corrent custom parameter!\n");
            continue;
        }
    }

    ret = set_psw_check_info(pampswcheck);
    if(ret)
    {
        ksc_perror("ksc-defender_account handle_pswCustomGrade failed : %d\n", ret);
        return -1;
    }

    return 0;
}

int CKscAccountCli::set_psw_check_info(SPamPswCheck pswgrade)
{
    int ret = 0;
    SPamPswCheck now_pswcheck;
    ret = m_CKscPamconfigParse->load_pam_psw_check(now_pswcheck);
    if (ret < 0)
    {
        std::cout << "CKscPamconfigParse::load_pamPswCheck failed, ret = " << ret << std::endl;
        return -1;
    }

    if (memcmp(&pswgrade, &now_pswcheck, sizeof(SPamPswCheck)) == 0)
    {
        return 0;
    }

    ret = m_CKscPamconfigParse->save_pam_psw_check(pswgrade);
    if (ret < 0)
    {
        std::cout << "CKscPamconfigParse:: save_pamPswCheck failed, ret = " << ret << std::endl;
        return -1;
    }
    return ret;
}

int CKscAccountCli::show_custom_menu()
{
    ksc_pconst(_("\
[commands]\n\
      ls                      View custom rules.\n\
      minlen   <6~32>         Minimum acceptable size for the new password.\n\
      minclass <1~4>          Minimum of required classes of characters for the new password.\n\
      usercheck[on/off]       Whether to check if it contains the user name in some form.\n\
      dictcheck[on/off]       Whether to check for the words from the cracklib dictionary.\n\
      limitday[index]         Maximum number of days a password may be used(0 means unlimited). \n\
      warnday[index]          Reminder days before expiration. when limitday is 0,warnday is disable.\n\
      exit                    Only exit custom menu. \n\
      apply                   Apply and exit custom menu.\n\
      help                    Display this help menu.\n"
            ));
    return 0;
}

int CKscAccountCli::show_custom_info_list(SPamPswCheck pampswcheck)
{
    std::cout << "ksc-defender_account: minlen             " << pampswcheck.minlen << std::endl;
    std::cout << "ksc-defender_account: minclass           " << pampswcheck.minclass << std::endl;

    if(pampswcheck.usercheck)
    {
        std::cout << "ksc-defender_account: usercheck          " << "on" << std::endl;
    }
    else
    {
        std::cout << "ksc-defender_account: usercheck          " << "off" << std::endl;
    }

    if(strcmp(pampswcheck.dictpath,KSC_DEFAULT_PASSWD_DICTIONARY_R_SERIALS) == 0)
    {
        std::cout << "ksc-defender_account: dictpath           " << "on" << std::endl;
    }
    else
    {
        std::cout << "ksc-defender_account: dictpath           " << "off" << std::endl;
    }

    std::cout << "ksc-defender_account: limitday           " << pampswcheck.limitday << std::endl;
    if(pampswcheck.limitday)
    {
        std::cout << "ksc-defender_account: warnday            " << pampswcheck.warnday << std::endl;
    }

    std::cout << "ksc-defender_account: palindromecheck    " << "on" << std::endl;
    std::cout << "ksc-defender_account: similarcheck       " << "on" << std::endl;

    return 0;
}

int CKscAccountCli::get_custom_minlen(SPamPswCheck &pampswcheck)
{
    char minlen[KSC_MAX_LEN];
    int len = 0;

    memset(minlen,0,sizeof(minlen));
    scanf("%1023s", minlen);

    len = atoi(minlen);
    if(len <= 0 || len < KSC_ACCOUNT_PSW_MINLEN_MIN || len > KSC_ACCOUNT_PSW_MINLEN_MAX)
    {
        ksc_perror("minlen should be greater than or equal to 6, and less than or equal to 32,please try again!\n");
        return -1;
    }

    if(pampswcheck.minlen == len)
    {
        ksc_perror("minlen has already been set!\n");
        return -1;
    }

    pampswcheck.minlen = len;
    ksc_pinfo("ksc-defender_account custom pswsetting minlen = %d\n", pampswcheck.minlen);
    return 0;
}

int CKscAccountCli::get_custom_minclass(SPamPswCheck &pampswcheck)
{
    char minclass[KSC_MAX_LEN];
    int num = 0;

    memset(minclass,0,sizeof(minclass));
    scanf("%1023s", minclass);

    num = atoi(minclass);
    if(num <= 0 || num < 1 || num > 4)
    {
        ksc_perror("minclass should be greater than or equal to 1 , and less than  or equal to 4,please try again!\n");
        return -1;
    }

    if(pampswcheck.minclass == num)
    {
        ksc_perror("minclass has already been set!\n");
        return -1;
    }

    pampswcheck.minclass = num;
    ksc_pinfo("ksc-defender_account custom pswsetting minclass = %d\n", pampswcheck.minclass);
    return 0;
}

int CKscAccountCli::get_custom_user_check(SPamPswCheck &pampswcheck)
{
    char usercheck[KSC_MAX_LEN];

    memset(usercheck,0,sizeof(usercheck));
    scanf("%1023s",usercheck);

    if(strstr(usercheck, "on"))
    {
        if(pampswcheck.usercheck == 1)
        {
            ksc_perror("usercheck has already been opened!\n");
            return -1;
        }

        pampswcheck.usercheck = 1;
    }
    else if(strstr(usercheck, "off"))
    {
        if(pampswcheck.usercheck == 0)
        {
            ksc_perror("usercheck has already been closed!\n");
            return -1;
        }

        pampswcheck.usercheck = 0;
    }
    else
    {
        ksc_pconst("Please re-enter the corrent usercheck parameter!\n");
        return 0;
    }

    ksc_pinfo("ksc-defender_account custom pswsetting usercheck = %d\n", pampswcheck.usercheck);
    return 0;
}

int CKscAccountCli::get_custom_dictpath(SPamPswCheck &pampswcheck)
{
    char dictcheck[KSC_MAX_LEN];

    memset(dictcheck,0,sizeof(dictcheck));
    scanf("%1023s", dictcheck);

    if(strstr(dictcheck, "on"))
    {
        if(strcmp(pampswcheck.dictpath,KSC_DEFAULT_PASSWD_DICTIONARY_R_SERIALS) == 0)
        {
            ksc_perror("usercheck has already been opened!\n");
            return -1;
        }

        memset(pampswcheck.dictpath, 0x00, sizeof(pampswcheck.dictpath));
        strncpy(pampswcheck.dictpath, KSC_DEFAULT_PASSWD_DICTIONARY_R_SERIALS, sizeof(pampswcheck.dictpath)-1);
    }
    else if(strstr(dictcheck, "off"))
    {
        if(strcmp(pampswcheck.dictpath,"") == 0)
        {
            ksc_perror("usercheck has already been closed!\n");
            return -1;
        }

        memset(pampswcheck.dictpath, 0x00, sizeof(pampswcheck.dictpath));
    }
    else
    {
        ksc_pconst("Please re-enter the corrent dictpath parameter!\n");
        return 0;
    }

    ksc_pinfo("ksc-defender_account custom pswsetting dictpath = %s\n", pampswcheck.dictpath);
    return 0;
}

int CKscAccountCli::get_custom_limit_time(SPamPswCheck &pampswcheck)
{
    char limittime[KSC_MAX_LEN];
    int num = 0;

    memset(limittime,0,sizeof(limittime));
    scanf("%1023s", limittime);

    num = atoi(limittime);
    if(num < 0)
    {
        ksc_perror("limittime should be greater than or equal to 0,please try again!\n");
        return -1;
    }

    if(pampswcheck.limitday == num)
    {
        ksc_perror("limitday has already been set!\n");
        return -1;
    }

    pampswcheck.limitday = num;
    ksc_pinfo("ksc-defender_account custom pswsetting limitdays = %d\n", pampswcheck.limitday);
    return 0;
}

int CKscAccountCli::get_custom_warn_time(SPamPswCheck &pampswcheck)
{
    char warndays[KSC_MAX_LEN];
    int num = 0;

    memset(warndays,0,sizeof(warndays));
    scanf("%1023s", warndays);

    num = atoi(warndays);
    if(num < 0)
    {
        ksc_perror("warntime should be greater than 0, please try again!\n");
        return -1;
    }

    if(pampswcheck.warnday == num)
    {
        ksc_perror("warnday has already been set!\n");
        return -1;
    }

    pampswcheck.warnday = num;
    ksc_pinfo("ksc-defender_account custom pswsetting warndays = %d\n", pampswcheck.warnday);
    return 0;
}
