#ifndef KYLIN_DEFENDER_COMDEF_H
#define KYLIN_DEFENDER_COMDEF_H


/* Import gettext() */
#include <libintl.h>
#define _(msgid) gettext (msgid)

/* Import macro EXIT_SUCCESS EXIT_FAILURE */

#define KSC_ACCOUNT_UNLOCK_TIME 300
#define KSC_ACCOUNT_DENY        3
#define KSC_ACCOUNT_DENY_MAX   16
#define KSC_ACCOUNT_LOCK_TIME_MIN 1
#define KSC_ACCOUNT_LOCK_TIME_MAX 30

#define KSC_ACCOUNT_PSW_MINLEN_MIN 6
#define KSC_ACCOUNT_PSW_MINLEN_MAX 32

#define KSC_MAX_LEN         1024
#define KSC_PATH_MAX        4096	/* # chars in a path name including nul */

#define KSC_PSW_CONFIG_PATH_SYSTEM_AUTH "/etc/pam.d/system-auth"  //R系密码复杂度启用配置文件
#define KSC_PSW_CONFIG_PATH_POSTLOGIN   "/etc/pam.d/postlogin"  //R系配置保存临时文件
#define KSC_PSW_CONFIG_PASSWD_LIMIT_TIME_FILE "/etc/login.defs"       //密码有效期配置文件
#define KSC_PSW_CONFIG_DETAIL_FILE "/etc/security/pwquality.conf"  //密码检查模块配置读取文件

#define KSC_PSW_CONFIG_FILE_TEMP   "/usr/share/ksc-defender/kylin-password/pam-config/pwquality.conf"  //密码检查模块配置保存临时文件
#define KSC_PSW_CONFIG_FILE_TEMP_BAK   "/usr/share/ksc-defender/kylin-password/pam-config/pwquality_bak.conf"  //密码检查模块配置保存临时文件

#define KSC_PSW_SAVE_FILE_PWQUALITY "pam-auth-update --package --force"

#define KSC_DEFAULT_PASSWD_DICTIONARY_R_SERIALS "/usr/share/cracklib/pw_dict"

#define KSC_PAM_UPDATE_CMD "pam-auth-update --package --force"
#define KSC_PSW_MODE_CONF "/usr/share/ksc-defender/kylin-password/kylin-password.conf"

#define KSC_SUDO_CONFIG_PATH_FILE "/etc/sudoers"     //sudo权限配置文件
#define KSC_ACCOUNT_SRC_PATH_SHOW_FAILED_SH "/usr/share/Ksc_defender_cmd/showfailed.sh"     //显示登录错误信息脚本源文件存储位置
#define KSC_ACCOUNT_PATH_SHOW_FAILED_SH "/etc/profile.d/showfailed.sh"     //显示登录错误信息脚本最终存储位置
#define KSC_ACCOUNT_SHOW_FAILED_SH_MD5 "ac5a1066e659bba6f0815b1e60be8182"     //显示登录错误信息脚本MD5值

/*病毒防护模块配置文件*/
#define KSC_ANTIVIRUS_CONF_PATH                 "/usr/share/ksc-defender/antivirus/antivirus.conf"
/*病毒库更新镜像地址*/
#define KSC_ANTIVIRUS_DEFAULT_DB_UPDATE_URL     "https://database.clamav.net"
/*病毒库存放目录*/
#define KSC_ANTIVIRUS_DEFAULT_DB_DIR            "/usr/share/ksc-defender/antivirus/clamav"
/*病毒扫描日志存放目录*/
#define KSC_ANTIVIRUS_SCAN_LOG_DIR              "/usr/share/ksc-defender/antivirus/log"
/*病毒扫描日志文件*/
#define KSC_ANTIVIRUS_SCAN_LOG_FILE             "/usr/share/ksc-defender/antivirus/log/scan.log"
/*病毒隔离目录*/
#define KSC_ANTIVIRUS_SCAN_ISOLATE_DIR          "/usr/share/ksc-defender/antivirus/.isolate"
/*病毒感染文件数据库目录*/
#define KSC_ANTIVIRUS_DB_VIRUS_DIR              "/usr/share/ksc-defender/antivirus/db"
/*病毒感染文件数据库*/
#define KSC_ANTIVIRUS_DB_VIRUS                  "/usr/share/ksc-defender/antivirus/db/virus.db"

#define KSC_ANTIVIRUS_MAX_DB_LIST_NUM  10
#define KSC_ANTIVIRUS_MAX_UPDATE_LIST_NUM  10

/*防火墙用户自定义模式默认服务名*/
#define KSC_FIREWALL_CUSTOM_SERVICE_DEFAULT_NAME "default"

#endif //end KYLIN_DEFENDER_COMDEF_H
