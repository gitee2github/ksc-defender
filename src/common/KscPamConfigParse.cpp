#include "KscPamConfigParse.h"
#include "string.h"
#include "ksc_error.h"
#include "ksc_public.h"
#include <unistd.h>
#include <pwd.h>
#include <fstream>
using namespace std;

const char *g_pwquality_items[]{
    "PWQ_SETTING_UNDEFINE",
    "PWQ_SETTING_DIFF_OK",
    "PWQ_SETTING_UNDEFINE",
    "PWQ_SETTING_MIN_LENGTH",
    "PWQ_SETTING_DIG_CREDIT",
    "PWQ_SETTING_UP_CREDIT",
    "PWQ_SETTING_LOW_CREDIT",
    "PWQ_SETTING_OTH_CREDIT",
    "PWQ_SETTING_MIN_CLASS",
    "PWQ_SETTING_MAX_REPEAT",
    "PWQ_SETTING_DICT_PATH",
    "PWQ_SETTING_MAX_CLASS_REPEAT",
    "PWQ_SETTING_GECOS_CHECK",
    "PWQ_SETTING_BAD_WORDS",
    "PWQ_SETTING_MAX_SEQUENCE",
    "PWQ_SETTING_DICT_CHECK",
    "PWQ_SETTING_USER_CHECK",
    "PWQ_SETTING_ENFORCING",
    "PWQ_SETTING_RETRY_TIMES",
    "PWQ_SETTING_ENFORCE_ROOT",
    "PWQ_SETTING_LOCAL_USERS",
    "PWQ_SETTING_PALINDROME",
    "PWQ_SETTING_NO_SIMILAR_CHECK"
};

const char *pamctrlErrName[] = {
    "ksc.pamctrl.Error.SavePSWCheckErr",             /* 保存密码检查模块数据失败 */
    "ksc.pamctrl.Error.SaveAccountLockErr",			/* 保存账户锁定模块数据失败 */
    "ksc.pamctrl.Error.SaveLoginInfoErr",			/* 保存登录信息模块数据失败 */
    "ksc.pamctrl.Error.ExecuteUpdateErr",            /* 更新系统配置信息失败 */
};

CKscPamconfigParse::CKscPamconfigParse()
{
    m_KscStringConvert = CKscStringConvert::get_instance();
}

CKscPamconfigParse::~CKscPamconfigParse()
{

}

CKscPamconfigParse *CKscPamconfigParse::get_instance()
{
    static CKscPamconfigParse* m_pInstance = nullptr;
    if (!m_pInstance)
    {
        m_pInstance = new CKscPamconfigParse();
    }
    return m_pInstance;
}

int CKscPamconfigParse::load_pam_psw_check(SPamPswCheck &pswcheck)
{    
    int ret = -1;
    memset(&pswcheck, 0x00, sizeof(SPamPswCheck));

    ret = parse_psw_check_enable(pswcheck);
    if(ret < 0)
    {
        ksc_perror("ksc-defender_acctpwd load_pam_config parse_pswcheck_enable failed: %d\n",ret);
        return -1;
    }

    ksc_pinfo("CKscPamconfigParse::parse_pswcheck_enable : %d\n", pswcheck.enable);
    if(pswcheck.enable)
    {
        ret = parse_psw_check_detail_by_pwquality(pswcheck);
        if(ret < 0)
        {
            ksc_perror("ksc-defender_acctpwd load_pam_config parse_pswcheck_detail failed: %d\n",ret);
            return -2;
        }
    }

    return 0;
}

int CKscPamconfigParse::parse_psw_check_enable(SPamPswCheck &pswcheck)
{
    ifstream input;
    pswcheck.enable = 0;

    input.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH,ifstream::in);
    if(input.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PATH_SYSTEM_AUTH);
        return KSC_FILEOPENERR;
    }

    string str;
    while(getline(input, str))
    {
        if(m_KscStringConvert->contains(str,"pam_pwquality.so") && !m_KscStringConvert->is_start_with(str,"#"))
        {
            pswcheck.enable = 1;
            break;
        }
    }
    input.close();
    return KSC_OK;
}

int CKscPamconfigParse::parse_psw_check_detail_by_pwquality(SPamPswCheck &pswcheck)
{
    pwquality_settings_t *settings = NULL;
    void *auxerror = NULL;
    int ret = -1;
    char buf[256] = {0};

    int limitdays = 0;
    int warndays = 0;

    settings = pwquality_default_settings();
    if (!settings)
    {
        ksc_perror("ksc-defender_acctpwd pwquality_default_settings failed : %d!\n",ret);
        return -1;
    }

    if (access(KSC_PSW_CONFIG_DETAIL_FILE, R_OK) == 0)
    {
        ret = pwquality_read_config(settings, KSC_PSW_CONFIG_DETAIL_FILE, &auxerror);
        if (ret != 0)
        {
            const char* error = pwquality_strerror(buf, sizeof(buf),ret, auxerror);
            ksc_perror("ksc-defender_acctpwd read pwquality settings failed: %s\n",error);
        }
    }

    pswcheck.minlen = pam_pwquality_get_int_value(settings, PWQ_SETTING_MIN_LENGTH);
    pswcheck.minclass = pam_pwquality_get_int_value(settings, PWQ_SETTING_MIN_CLASS);
    pswcheck.usercheck = pam_pwquality_get_int_value(settings, PWQ_SETTING_USER_CHECK);
    pswcheck.similarcheck = 1;
    pswcheck.palindromecheck = 1;

    ret = get_psw_check_passwd_time(limitdays,warndays);
    if (ret != 0)
    {
        ksc_perror("ksc-defender_acctpwd get_pswCheckPasswdTime failed : %d!\n",ret);
        return -1;
    }
    pswcheck.limitday = limitdays;
    pswcheck.warnday = warndays;

    if (pam_pwquality_get_int_value(settings, PWQ_SETTING_DICT_CHECK))
    {
        const char *dict = pam_pwquality_get_str_value(settings, PWQ_SETTING_DICT_PATH);
        if (dict)
        {
            strncpy(pswcheck.dictpath, dict, sizeof(pswcheck.dictpath) - 1);
            ksc_pinfo("ksc-defender_acctpwd dict: %s\n", dict);
        }
        else
        {
            strncpy(pswcheck.dictpath, KSC_DEFAULT_PASSWD_DICTIONARY_R_SERIALS, sizeof(pswcheck.dictpath) - 1);
            ksc_pinfo("ksc-defender_acctpwd no dict: %s\n", dict);
        }
    }

    pwquality_free_settings(settings);
    return KSC_OK;
}

int CKscPamconfigParse::pam_pwquality_get_int_value(pwquality_settings_t *settings, int setting)
{
    if (!settings)
    {
        return 0;
    }

    int value = 0;
    void *auxerror = NULL;
    char buf[256] = {0};
    int ret = pwquality_get_int_value(settings, setting, &value);
    if (ret != 0)
    {
        ksc_perror("ksc-defender_acctpwd pwquality_get_int_value[%s] failed: %s\n",
                   g_pwquality_items[setting], pwquality_strerror(buf, sizeof(buf), ret, auxerror));
        return 0;
    }

    return value;
}

int CKscPamconfigParse::get_psw_check_passwd_time(int &limittime, int &warntime)
{
    ifstream input;

    input.open(KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE,ifstream::in);
    if(input.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE);
        return KSC_FILEOPENERR;
    }

    string str;
    bool islimit = false;
    bool iswarn = false;
    while(getline(input, str))
    {
        if(islimit && iswarn)
        {
            break;
        }

        if(m_KscStringConvert->contains(str,"PASS_MAX_DAYS") && !m_KscStringConvert->contains(str,"#"))
        {
            m_KscStringConvert->del_sub_str(str, "PASS_MAX_DAYS");
            m_KscStringConvert->trimmed(str);
            limittime = atoi(str.c_str());
            ksc_pinfo("ksc-defender_acctpwd get limittime: %d\n", limittime);
            islimit = true;
        }
        if(m_KscStringConvert->contains(str,"PASS_WARN_AGE") && !m_KscStringConvert->contains(str,"#"))
        {
            m_KscStringConvert->del_sub_str(str, "PASS_WARN_AGE");
            m_KscStringConvert->trimmed(str);
            warntime = atoi(str.c_str());
            ksc_pinfo("ksc-defender_acctpwd get warntime: %d\n", warntime);
            iswarn = true;
        }
    }

    input.close();

    if (limittime == 99999)
    {
        limittime = 0;
    }

    return KSC_OK;
}

const char *CKscPamconfigParse::pam_pwquality_get_str_value(pwquality_settings_t *settings, int setting)
{
    if (!settings)
    {
        return NULL;
    }

    const char *value;
    void *auxerror = NULL;
    char buf[256] = {0};
    int ret = pwquality_get_str_value(settings, setting, &value);
    if(ret != 0)
    {
        ksc_perror("ksc-defender_acctpwd pam_pwqualityGetStrValue[%s] failed: %s\n",
                   g_pwquality_items[setting], pwquality_strerror(buf, sizeof(buf), ret, auxerror));
        return NULL;
    }

    return value;
}

int CKscPamconfigParse::save_pam_psw_check(SPamPswCheck pswcheck)
{
    int ret = -1;

    if (pswcheck.enable == 1)
    {
        ksc_pinfo("ksc-defender_acctpwd save_pamPswCheckEnable\n");
        ret = save_pam_psw_check_enable(pswcheck);
        if(ret < 0)
        {
            ksc_perror("ksc-defender_acctpwd save_pamPswCheck failed[ret: %d]\n", ret);
            return -1;
        }

        ret = save_psw_login_time(pswcheck.limitday,pswcheck.warnday);
        if(ret < 0)
        {
            ksc_perror("ksc-defender_acctpwd save_pswLoginTime failed[ret: %d]\n", ret);
            return -2;
        }    
    }
    else
    {
        ksc_pinfo("save_pamPswCheckDisable\n");
        ret = save_pam_psw_check_disable();
        if(ret < 0)
        {
            ksc_perror("ksc-defender_acctpwd save_pamPswCheckDisable failed[ret: %d]\n", ret);
            return -1;
        }

        ret = save_psw_login_time(0, 7);
        if(ret < 0)
        {
            ksc_perror("ksc-defender_acctpwd save_pswLimitTime failed[ret: %d]\n", ret);
            return -2;
        }       
    }
    return ret;
}

int CKscPamconfigParse::save_pam_psw_check_enable(SPamPswCheck pswcheck)
{
    ifstream enable_file;
    vector<string> infoList;
    string str;

    ofstream out_file;

    enable_file.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH,ifstream::in);
    if(enable_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PATH_SYSTEM_AUTH);
        return KSC_FILEOPENERR;
    }

    char buff[1024] = {0};
    while(getline(enable_file, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(m_KscStringConvert->contains(str, "pam_passwdqc.so") || m_KscStringConvert->contains(str, "pam_cracklib.so"))
        {
            continue;
        }

        if(m_KscStringConvert->contains(str, "pam_pwquality.so"))
        {
            snprintf(buff, sizeof(buff),"password    requisite    pam_pwquality.so try_first_pass local_users_only enforce_for_root");
            str = buff;
        }

        if(m_KscStringConvert->contains(str, "pam_unix.so") &&  m_KscStringConvert->is_start_with(str, "password"))
        {
            if(!m_KscStringConvert->contains(str, "use_authtok"))
            {
                m_KscStringConvert->rep_sub_str(str, "\n", "");
                str = str + " use_authtok";
            }
        }
        str.push_back('\n');
        infoList.push_back(str);
    }

    enable_file.close();

    out_file.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH, ofstream::out);
    if(out_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PATH_SYSTEM_AUTH);
        return KSC_FILEOPENERR;
    }

    vector<string>::iterator itor;
    for(itor = infoList.begin(); itor!= infoList.end(); ++itor)
    {
        out_file << *itor;
    }
    out_file.close();

    int ret = save_pam_psw_check_pwquality(pswcheck);
    if (ret != 0)
    {
        ksc_perror("ksc-defender_acctpwd save_pamPSWCheckPwquality failed[ret: %d]\n", ret);
        return -3;
    }

    return KSC_OK;
}

int CKscPamconfigParse::save_psw_login_time(int limittime, int warntime)
{
    if(limittime == 0)
    {
        limittime = 99999;
    }

    int ret = update_user_pass_time(limittime, warntime);
    if(ret)
    {
        return -1;
    }

    ret = update_cfg_pass_time(limittime, warntime);
    if(ret != 0)
    {
        ksc_perror("ksc-defender_acctpwd update_CfgPassTime failed[ret: %d]\n", ret);
        return -1;
    }
    return ret;
}

int CKscPamconfigParse::save_pam_psw_check_disable()
{
    ifstream enable_file;
    vector<string> infoList;
    string str;

    enable_file.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH,ifstream::in);
    if(enable_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PATH_SYSTEM_AUTH);
        return KSC_FILEOPENERR;
    }

    char buff[1024] = {0};
    while(getline(enable_file, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行
        if(m_KscStringConvert->contains(str, "pam_passwdqc.so")
                || m_KscStringConvert->contains(str, "pam_cracklib.so"))
        {
            continue;
        }

        if(m_KscStringConvert->contains(str, "pam_pwquality.so"))
        {
            snprintf(buff, sizeof(buff),
                    "#password    requisite    pam_pwquality.so try_first_pass local_users_only enforce_for_root");
            str = buff;
        }

        if(m_KscStringConvert->contains(str, "pam_unix.so")
                && m_KscStringConvert->is_start_with(str, "password"))
        {
            if(m_KscStringConvert->contains(str, "use_authtok"))
            {
                m_KscStringConvert->replace_str(str, " use_authtok", "");
            }
        }

        str.push_back('\n');
        infoList.push_back(str);
    }

    enable_file.close();

    ofstream out_file;
    out_file.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH, ofstream::out);
    if(out_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PATH_SYSTEM_AUTH);
        return KSC_FILEOPENERR;
    }

    vector<string>::iterator itor;
    for(itor = infoList.begin(); itor!= infoList.end(); ++itor)
    {
        out_file << *itor;
    }
    out_file.close();

    return KSC_OK;
}

int CKscPamconfigParse::save_pam_psw_check_pwquality(SPamPswCheck pswcheck)
{   
    int ret = 0;

    if(access(KSC_PSW_CONFIG_FILE_TEMP_BAK, F_OK) != -1)
    {
        if(remove(KSC_PSW_CONFIG_FILE_TEMP_BAK) != 0)
        {
            ksc_perror("ksc-defender_acctpwd save_pamPSWCheckPwquality remove:%s faild\n",
                        KSC_PSW_CONFIG_FILE_TEMP_BAK);
            return KSC_FILEOPENERR;
        }
    }

    ret = copy_file((char*)KSC_PSW_CONFIG_FILE_TEMP,(char*)KSC_PSW_CONFIG_FILE_TEMP_BAK);
    if(ret)
    {
        ksc_perror("ksc-defender_acctpwd copy_file:%s faild\n", KSC_PSW_CONFIG_FILE_TEMP_BAK);
        return KSC_FILEOPENERR;
    }

    ifstream in_file;
    in_file.open(KSC_PSW_CONFIG_FILE_TEMP_BAK,ifstream::in);
    if(in_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_FILE_TEMP_BAK);
        return KSC_FILEOPENERR;
    }

    bool dictory_check = strlen(pswcheck.dictpath) == 0 ? false : true;
    vector<string> infolist;
    string str;
    char buff[KSC_PATH_MAX] = {0};
    while(getline(in_file, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行
        if(m_KscStringConvert->contains(str, "minlen"))
        {
            snprintf(buff, sizeof(buff), "minlen = %d", pswcheck.minlen);
            str = buff;
        }
        else if(m_KscStringConvert->contains(str, "minclass"))
        {
            snprintf(buff,sizeof(buff), "minclass = %d", pswcheck.minclass);
            str = buff;
        }
        else if(m_KscStringConvert->contains(str, "usercheck"))
        {
            snprintf(buff,sizeof(buff), "usercheck = %d", pswcheck.usercheck);
            str = buff;
        }

        if(dictory_check)
        {
            if(m_KscStringConvert->contains(str, "dictpath"))
            {
                snprintf(buff, sizeof(buff),"dictpath = %s", pswcheck.dictpath);
                str = buff;
            }
            else if(m_KscStringConvert->contains(str, "dictcheck"))
            {
                snprintf(buff,sizeof(buff), "dictcheck = 1");
                str = buff;
            }
        }
        else
        {
            if(m_KscStringConvert->contains(str, "dictcheck"))
            {
                snprintf(buff, sizeof(buff),"dictcheck = 0");
                str = buff;
            }
        }

        str.push_back('\n');
        infolist.push_back(str);
    }
    in_file.close();

    ofstream out_file;
    out_file.open(KSC_PSW_CONFIG_FILE_TEMP_BAK, ofstream::out);
    if(out_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_FILE_TEMP_BAK);
        return KSC_FILEOPENERR;
    }

    vector<string>::iterator itor;
    for(itor = infolist.begin(); itor!= infolist.end(); ++itor)
    {
        out_file << *itor;
    }

    out_file.close();

    if(access(KSC_PSW_CONFIG_DETAIL_FILE, F_OK) != -1)
    {
        if(remove(KSC_PSW_CONFIG_DETAIL_FILE) != 0)
        {
            ksc_perror("ksc-defender_acctpwd  save_pamPSWCheckPwquality remove:%s faild\n", KSC_PSW_CONFIG_DETAIL_FILE);
            return KSC_FILEOPENERR;
        }
    }

    ret = copy_file((char*)KSC_PSW_CONFIG_FILE_TEMP_BAK,(char*)KSC_PSW_CONFIG_DETAIL_FILE);
    if(ret)
    {
        ksc_perror("ksc-defender_acctpwd copy_file:%s faild\n", KSC_PSW_CONFIG_DETAIL_FILE);
        return KSC_FILEOPENERR;
    }

    return ret;
}

int CKscPamconfigParse::update_user_pass_time(int limittime, int warntime)
{
    struct passwd *pwent;
    char buff[1024] = {0};

    setpwent();

    while(true)
    {
        pwent = getpwent();
        if(!pwent)
        {
            break;
        }

        if(pwent->pw_uid < 1000)
        {
            if(pwent->pw_uid != 0 && pwent->pw_uid != 600 && pwent->pw_uid != 700)
            {
                continue;
            }
        }

        if(strstr(pwent->pw_shell, "/sbin/nologin"))
        {
            continue;
        }

        snprintf(buff, sizeof(buff), "chage -M %d -W %d %s", limittime, warntime, pwent->pw_name);
        char* cmd = buff;
        ksc_pinfo("ksc-defender_acctpwd update_userPassTime: %s\n", cmd);

        //system("setenforce 0");
        system(cmd);
        //system("setenforce 1");
    }
        endpwent();
        return 0;
}

int CKscPamconfigParse::update_cfg_pass_time(int limittime, int warntime)
{
    ifstream in_file;
    vector<string> infoList;
    string str;

    ofstream out_file;

    in_file.open(KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE,ifstream::in);
    if(in_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE);
        return KSC_FILEOPENERR;
    }

    char buff[1024] = {0};
    while(getline(in_file, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(m_KscStringConvert->is_start_with(str, "PASS_MAX_DAYS") && !m_KscStringConvert->is_start_with(str, "#"))
        {
            snprintf(buff,sizeof(buff), "PASS_MAX_DAYS\t%d", limittime);
            str = buff;
        }

        if(m_KscStringConvert->is_start_with(str, "PASS_WARN_AGE") && !m_KscStringConvert->is_start_with(str, "#"))
        {
            snprintf(buff, sizeof(buff),"PASS_WARN_AGE\t%d", warntime);
            str = buff;
        }

        str.push_back('\n');
        infoList.push_back(str);
    }

    in_file.close();

    out_file.open(KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE, ofstream::out);
    if(out_file.fail())
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE);
        return KSC_FILEOPENERR;
    }

    vector<string>::iterator itor;
    for(itor = infoList.begin(); itor!= infoList.end(); ++itor)
    {
        out_file << *itor;
    }
    out_file.close();

    return KSC_OK;
}

int CKscPamconfigParse::copy_file(char *infile, char *outfile)
{
    ifstream input(infile, ios::binary);
    ofstream output(outfile, ios::binary);
    if (!input)
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", infile);
        return -1;
    }
    if (!output)
    {
        ksc_perror("ksc-defender_acctpwd open file error: %s \n", outfile);
        return -1;
    }
    output << input.rdbuf();
    input.close();
    output.close();
    return 0;
}

bool is_pam_failockso(const string& s)
{
    size_t size = s.find("#");
    string temp;

    if(size == string::npos){
        temp = s;
    }
    else
    {
        temp = s.substr(0, size);
    }

    size = temp.find("pam_faillock.so");
    if(size == string::npos)
    {
        return false;
    }

    return true;
}

int CKscPamconfigParse::is_show_failed()
{
    ifstream in;

    in.open(KSC_SUDO_CONFIG_PATH_FILE,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }
    in.close();

    string tmpMd5;
    tmpMd5 = system("md5sum KSC_ACCOUNT_PATH_SHOW_FAILED_SH | awk $1");
    if(tmpMd5 != KSC_ACCOUNT_SHOW_FAILED_SH_MD5)
    {
        return KSC_MD5ERROR;
    }

    return KSC_OK;
}

bool CKscPamconfigParse::is_set_sudoers()
{
    ifstream in;
    string str;

    in.open(KSC_SUDO_CONFIG_PATH_FILE,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }
    while(getline(in, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(m_KscStringConvert->contains(str,"ALL ALL=ALL NOPASSWD:/usr/bin/lastb"))
        {      //检测sudo配置文件中是否允许lastb命令具有sudo权限
                in.close();
                return true;
        }
    }
    in.close();

    return false;
}

int CKscPamconfigParse::set_sudoers()
{
    ifstream in;
    ofstream out;
    vector<string> info;
    string str;

    in.open(KSC_SUDO_CONFIG_PATH_FILE,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }
    while(getline(in, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(m_KscStringConvert->contains(str,"root    ALL=(ALL)       ALL"))
        {      //检测sudo配置文件中的root配置行
                str = str + "\nALL ALL=ALL NOPASSWD:/usr/bin/lastb";
        }

        str.push_back('\n');
        info.push_back(str);
    }
    in.close();

    out.open(KSC_SUDO_CONFIG_PATH_FILE, ofstream::out);
    if(out.fail())
    {
        return KSC_FILEOPENERR;
    }

    for(vector<string>::iterator it = info.begin(); it != info.end(); ++it)
    {
        out << *it;
    }
    out.close();

    return KSC_OK;
}

int CKscPamconfigParse::save_pam_account(const SPamAccountLock& account)
{
    ifstream in;
    ofstream out;
    vector<string> info;
    string str;

    in.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }

    while(getline(in, str))
    {
        char buff[1024] = {0};
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(account.enable == 0)
        {
            if(m_KscStringConvert->contains(str, "pam_faillock.so") && !m_KscStringConvert->is_start_with(str, "#"))
            {
                str = string("#") + str;
            }
        }
        else
        {
            if(m_KscStringConvert->contains(str, "pam_faillock.so"))
            {
                string temp;
                if(m_KscStringConvert->is_start_with(str, "#"))
                {
                    temp = m_KscStringConvert->del_char(str, '#');
                    str = temp;
                }
                else
                {
                    temp = str;
                }

                if(m_KscStringConvert->contains(temp, "required") && m_KscStringConvert->contains(temp, "auth"))
                {
                    snprintf(buff, sizeof(buff),
                    "auth        required    pam_faillock.so preauth audit deny=%d even_deny_root unlock_time=%lld",
                    account.deny, account.locktime);
                    str = buff;
                }
                else if(m_KscStringConvert->contains(temp,"[default=die]") && m_KscStringConvert->contains(temp,"auth"))
                {
                    snprintf(buff, sizeof(buff),
                    "auth        [default=die] pam_faillock.so authfail audit deny=%d even_deny_root unlock_time=%lld",
                    account.deny, account.locktime);
                    str = buff;
                }
                else if(m_KscStringConvert->contains(temp,"sufficient") && m_KscStringConvert->contains(temp,"auth"))
                {
                    snprintf(buff,sizeof(buff),
                    "auth        sufficient    pam_faillock.so authsucc audit deny=%d even_deny_root unlock_time=%lld",
                    account.deny, account.locktime);
                    str = buff;
                }
            }
        }

        str.push_back('\n');
        info.push_back(str);
    }
    in.close();

    out.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH, ofstream::out);
    if(out.fail())
    {
        return KSC_FILEOPENERR;
    }

    for(vector<string>::iterator it = info.begin(); it != info.end(); ++it)
    {
        out << *it;
    }
    out.close();
    return KSC_OK;
}

int CKscPamconfigParse::read_pam_account(SPamAccountLock& account)
{
    ifstream in;

    in.open(KSC_PSW_CONFIG_PATH_SYSTEM_AUTH,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }

    string str;
    while(getline(in, str))
    {
        if(m_KscStringConvert->is_exist(str,"pam_faillock.so"))
        {
            account.enable = 1;
            if(m_KscStringConvert->is_exist(str,"deny=") && m_KscStringConvert->is_exist(str,"required"))
            {
                account.deny = m_KscStringConvert->get_str_int(str, "deny=");
            }

            if(m_KscStringConvert->is_exist(str,"deny=") && m_KscStringConvert->is_exist(str,"required"))
            {
                account.locktime = m_KscStringConvert->get_str_int(str, "unlock_time=");
            }
        }

    }
    in.close();
    return KSC_OK;
}

int CKscPamconfigParse::init_pam_login()
{
    ifstream in;
    ofstream out;
    string str;
    vector<string> info;

    in.open(KSC_PSW_CONFIG_PATH_POSTLOGIN,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }

    while(getline(in, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        if(m_KscStringConvert->is_exist(str, "session") && m_KscStringConvert->is_exist(str, "default")
                && m_KscStringConvert->is_exist(str, "pam_lastlog.so"))
        {
            str = "session     [default=1]   pam_lastlog.so nowtmp";
        }
        if(m_KscStringConvert->is_exist(str, "session") && m_KscStringConvert->is_exist(str, "pam_lastlog.so")
                && m_KscStringConvert->is_exist(str, "optional"))
        {
            str = "session     optional   pam_lastlog.so noupdate showfailed";
        }
        str.push_back('\n');
        info.push_back(str);
    }

    in.close();
    out.open(KSC_PSW_CONFIG_PATH_POSTLOGIN, ofstream::out);
    if(out.fail())
    {
        return KSC_FILEOPENERR;
    }

    for(vector<string>::iterator it = info.begin(); it != info.end(); ++it)
    {
        out << *it;
    }
    out.close();

    return KSC_OK;
}

int CKscPamconfigParse::read_pam_login(SPamLoginInfo& logininfo)
{
    ifstream in;
    string str;

    in.open(KSC_PSW_CONFIG_PATH_POSTLOGIN,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }

    while(getline(in, str))
    {
        if(m_KscStringConvert->contains(str, "session") && m_KscStringConvert->contains(str, "pam_lastlog.so")
                && m_KscStringConvert->contains(str, "optional"))
        {
            if(m_KscStringConvert->contains(str, "showfailed"))
            {
                logininfo.showfailed = 1;
            }
            else
            {
                logininfo.showfailed = 0;
            }

            if(!m_KscStringConvert->contains(str, "silent"))
            {
                logininfo.lastlog = 1;
            }
            else
            {
                logininfo.lastlog = 0;
            }
        }
    }

    in.close();
    return KSC_OK;
}

int CKscPamconfigParse::save_pam_login(const SPamLoginInfo& logininfo)
{
    ifstream in;
    ofstream out;
    vector<string> info;

    string lastlogCfg;
    if(logininfo.lastlog == 0 && logininfo.showfailed == 1)
    {
        lastlogCfg = "noupdate showfailed silent";
    }

    if(logininfo.lastlog == 1 && logininfo.showfailed == 1)
    {
        lastlogCfg = "noupdate showfailed";
    }

    if(logininfo.lastlog == 1 && logininfo.showfailed == 0)
    {
        lastlogCfg = "noupdate";
    }

    if(logininfo.lastlog == 0 && logininfo.showfailed == 0)
    {
        lastlogCfg = "noupdate silent";
    }

    in.open(KSC_PSW_CONFIG_PATH_POSTLOGIN,ifstream::in);
    if(in.fail())
    {
        return KSC_FILEOPENERR;
    }

    string str;
    char buff[1024] = {0};
    char temp[1024] = {0};
    while(getline(in, str))
    {
        m_KscStringConvert->trimmed(str);  //删除头部空行

        for (int i = 0; i < lastlogCfg.length(); i++)
        {
            temp[i] = lastlogCfg[i];
        }
        if(m_KscStringConvert->is_exist(str, "session") && m_KscStringConvert->is_exist(str, "lastlog")
                && m_KscStringConvert->is_exist(str, "optional"))
        {
            snprintf(buff, sizeof(buff),"session     optional                   pam_lastlog.so %s", temp);
            str = buff;
        }

        str.push_back('\n');
        info.push_back(str);
    }

    out.open(KSC_PSW_CONFIG_PATH_POSTLOGIN, ofstream::out);
    if(out.fail())
    {
        return KSC_FILEOPENERR;
    }
    for(vector<string>::iterator it = info.begin(); it != info.end(); ++it)
    {
        out << *it;
    }
    out.close();

    return KSC_OK;
}



