#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include "antivirus_handle.h"
#include "ksc_public.h"
#include "ksc_db.h"
#include "clamav.h"
#include "libfreshclam.h"
#include "ksc_comdef.h"

typedef struct fc_ctx_ {
    uint32_t bTestDatabases;
    uint32_t bBytecodeEnabled;
} fc_ctx;

typedef struct
{
    unsigned int sig_num;
    unsigned int total_files;
    unsigned int scan_dirs;
    unsigned int scan_files;
    unsigned int infected_files;
    unsigned int error_files;
    FILE * fd_log;
}antivirus_scan_info_t;

const char * deal_status[] = {"nodeal","delete","isolate","unknown"};

static int antivirus_init_flag = 0;
static int rand_seed_flag = 0;
static struct cl_engine * antivirus_engine = NULL;
char * g_standard_database_list[KSC_ANTIVIRUS_MAX_DB_LIST_NUM] = {"daily", "main", "bytecode"};
static u_int32_t g_standard_database_num = 3;
char * g_standard_update_url_list[KSC_ANTIVIRUS_MAX_UPDATE_LIST_NUM];
static u_int32_t g_standard_update_url_num = 0;

static fc_ctx fc_context = {0};

void antivirus_usage(int status)
{
    if (status != EXIT_SUCCESS)
    {
        ksc_pconst("Try 'ksc-defender --antivirus --help' for more information.\n");
    }
    else
    {
        ksc_pconst("\
Usage: ksc-defender --antivirus [options] \n");
        ksc_pconst("\n\
<mode>\n\
      ksc-defender --antivirus\n\
[options]\n\
      --scan <dir|file>              Scan dir or file. \n\
      --update                       Update antivirus database.\n\
      --report                       Report antivirus log.    \n\
      --deal                         Enter viruses deal submenu.\n");
    }
    exit(0);
}

static int parse_string(const char *arg,char * str,int len)
{
    int i = 0;
    if(NULL == arg || NULL == str)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    /*skip space and tab*/
    for (i = 0; i < (int)strlen(arg) - 1 && (arg[i] == ' ' || arg[i] == '\t'); i++)
    {

    }

    if(i >= strlen(arg))
    {
        ksc_perror("cannot found para\n");
        return -1;
    }

    arg += i;
    strncpy(str,arg,len-1);
    return 0;
}

int antivirus_parse_args(int argc, char **argv,antivirus_args_t * args)
{
    int ret = 0;
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
        antivirus_usage(EXIT_SUCCESS);
        return -1;
    }
   
    if (!strcmp(cmd, "--help")) 
    {
        antivirus_usage(EXIT_SUCCESS);
    }
    else if(!strcmp(cmd, "--scan"))
    {           
        const char *path = argv[1];
        argc--;
        //argv++;
        if(NULL == path)
        {
            ksc_perror("Option \'--scan\' miss arguments.\n");
            antivirus_usage(EXIT_SUCCESS);
        }
        else
        {
            memset(args->content.scan_path,0,sizeof(args->content.scan_path));
            ret = parse_string(path,args->content.scan_path,sizeof(args->content.scan_path));
            if(ret)
            {
                ksc_perror("parse_string failed,ret=%d\n",ret);
                antivirus_usage(EXIT_SUCCESS);
            }
        }

        args->cmd = ANTIVIRUS_CMD_SCAN;
    }
    else if(!strcmp(cmd, "--report"))
    {           
        args->cmd = ANTIVIRUS_CMD_REPORT;
    }
    else if(!strcmp(cmd, "--deal"))
    {           
        args->cmd = ANTIVIRUS_CMD_DEAL;
    }
    else if(!strcmp(cmd, "--update"))
    {           
        args->cmd = ANTIVIRUS_CMD_FRESH;
    }
    else
    {
        args->cmd = ANTIVIRUS_CMD_INVALID;
        ksc_perror("Invalid usage.\n");
        antivirus_usage(EXIT_SUCCESS);
    }
    return 0;
}

static unsigned int antivirus_randnum(unsigned int max)
{
    if (0 == rand_seed_flag)
    {
        struct timeval tv;
        gettimeofday(&tv, (struct timezone *)0);
        srand(tv.tv_usec + clock() + rand());
        rand_seed_flag = 1;
    }
    return 1 + (unsigned int)(max * (rand() / (1.0 + RAND_MAX)));
}

int antivirus_rmdirs(const char *dirname)
{
    DIR *dd = NULL;
    struct dirent *dent;
    STATBUF maind, statbuf;
    char *path = NULL;

    chmod(dirname, 0700);
    if ((dd = opendir(dirname)) != NULL)
    {
        while (CLAMSTAT(dirname, &maind) != -1)
        {
            if (!rmdir(dirname))
            {
                break;
            }

            if (errno != ENOTEMPTY && errno != EEXIST && errno != EBADF)
            {
                ksc_perror("Can't remove directory %s\n", dirname);
                closedir(dd);
                return -1;
            }

            while ((dent = readdir(dd))) 
            {
                if (dent->d_ino)
                 {
                    if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) 
                    {
                        path = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                        if (!path)
                        {
                            ksc_perror("Unable to allocate memory for path %llu\n",
                                       (long long unsigned)(strlen(dirname) + strlen(dent->d_name) + 2));
                            closedir(dd);
                            return -1;
                        }

                        snprintf(path, "%s" "/" "%s", dirname, dent->d_name);

                        /* stat the file */
                        if (LSTAT(path, &statbuf) != -1)
                        {
                            if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
                            {
                                if (rmdir(path) == -1)
                                {
                                     /* can't be deleted */
                                    if (errno == EACCES)
                                    {
                                        ksc_perror("Can't remove some  directories due to access problem.\n");
                                        closedir(dd);
                                        free(path);
                                        return -1;
                                    }
                                    if (antivirus_rmdirs(path))
                                    {
                                        ksc_perror("Can't remove nested directory %s\n", path);
                                        free(path);
                                        closedir(dd);
                                        return -1;
                                    }
                                }
                            } 
                            else
                            {
                                if (unlink(path)) 
                                {
                                    free(path);
                                    closedir(dd);
                                    return -1;
                                }
                            }
                        }
                        free(path);
                    }
                }
            }
            rewinddir(dd);
        }
    }
    else
    {
        return -1;
    }

    closedir(dd);
    return 0;
}

static int antivirus_get_arg_by_conf_name(const char* conf_name,char* conf_arg,int conf_arg_len)
{
    int ret = 0;
    int i = 0;
    int line = 0;
    FILE *fd = NULL;
    char buf[MAX_CONF_LINE_LENGTH];
    char *ptr_buf = NULL;
    char *pt = NULL;

    fd = fopen(KSC_ANTIVIRUS_CONF_PATH, "r");
    if (NULL == fd)
    {
        ksc_pconst("fopen failed,%s\n",strerror(errno));
        return -1;
    }

    while (fgets(buf, sizeof(buf), fd) != NULL) 
    {
        ptr_buf = buf;

        /*skip space and tab*/
        for (i = 0; i < (int)strlen(buf) - 1 && (buf[i] == ' ' || buf[i] == '\t'); i++)
        {
            ;
        }
        ptr_buf += i;

        line++;
        /*ignore comment*/
        if (strlen(ptr_buf) <= 2 || ptr_buf[0] == '#')
        {
            continue;
        }
        if(strncmp(ptr_buf,conf_name,strlen(conf_name)))
        {
            continue;
        }

        if (!(pt = strpbrk(ptr_buf, " \t"))) 
        {
            ksc_perror("Missing argument for option at %s:%d\n", KSC_ANTIVIRUS_CONF_PATH, line);
            ret = 1;
            break;
        }

        *pt++ = 0;

        /*skip space and tab*/
        for (i = 0; i < (int)strlen(pt) - 1 && (pt[i] == ' ' || pt[i] == '\t'); i++)
        {
            ;
        }
        pt += i;

        /*find the end of the line*/
        for (i = strlen(pt); i >= 1 && (pt[i - 1] == ' ' || pt[i - 1] == '\t' || pt[i - 1] == '\n'); i--)
        {
            ;
        }

        if (!i)
        {
            ksc_perror("Missing argument for option at %s:%d\n", KSC_ANTIVIRUS_CONF_PATH, line);
            ret = 1;
            break;
        }
        pt[i] = 0;
        
        if(i < conf_arg_len)
        {
            strncpy(conf_arg,pt,i);
        }

        ret = 0;
        break;
    }

    fclose(fd);
    return ret;
}

static int antivirus_get_database_mirror(char * url,int url_len)
{
    int ret = 0;
    ret = antivirus_get_arg_by_conf_name("DatabaseMirror",url,url_len);
    if(ret)
    {
        ksc_perror("get DatabaseMirror failed,ret=%d\n",ret);
    }
    return ret;
}

static int antivirus_get_db_dir(char * db_dir,int db_dir_len)
{
    int ret = 0;
    ret = antivirus_get_arg_by_conf_name("DatabaseDirectory",db_dir,db_dir_len);
    if(ret)
    {
        ksc_perror("get DatabaseDirectory failed,ret=%d\n",ret);
    }
    return ret;
}

static int antivirus_init()
{
    int ret = 0;
    if (!antivirus_init_flag)
    {        
        /* initialize libclamav*/
        ret = cl_init(CL_INIT_DEFAULT);
        if (CL_SUCCESS != ret)
        {
            ksc_perror("Can't initialize libclamav,ret=%d\n",ret);
            return -1;
        }
        ksc_pconst("cl_init success\n");
        antivirus_init_flag = 1;
    }
    return 0;
}

static int antivirus_engine_new(unsigned int * sig_num)
{
    int ret = 0;
    if(NULL == antivirus_engine)
    {
        /* create a new scan engine*/
        antivirus_engine = cl_engine_new();
        if (NULL == antivirus_engine)
        {
            ksc_perror("cl_engine_new failed\n");
            return -1;
        }
        ksc_pconst("cl_engine_new success\n");

        char db_dir[MAX_PATH_LENGTH];
        memset(db_dir,0,sizeof(db_dir));
        ret = antivirus_get_db_dir(db_dir,sizeof(db_dir));
        if(ret)
        {
            snprintf(db_dir,sizeof(db_dir)-1,KSC_ANTIVIRUS_DEFAULT_DB_DIR);
            ksc_pconst("get database dir failed,use default dir:%s\n",db_dir);        
        }
        else
        {        
            ksc_pconst("get database dir success:%s\n",db_dir);
        }
        ksc_pconst("try to load engine,please wait\n");
        ret = cl_load(db_dir, antivirus_engine, sig_num, CL_DB_STDOPT);
        if (ret != CL_SUCCESS)
        {
            ksc_perror("cl_load failed,ret=%d\n",ret);
            cl_engine_free(antivirus_engine);
            antivirus_engine = NULL;
            return -1;
        }
        ksc_pconst("cl_load success\n");

        /*detect engine*/
        ret = cl_engine_compile(antivirus_engine);
        if (ret != CL_SUCCESS)
        {
            ksc_perror("cl_engine_compile failed,ret=%d\n",ret);
            cl_engine_free(antivirus_engine);
            antivirus_engine = NULL;
            return -1;
        }
        ksc_pconst("cl_engine_compile success\n");        
        ksc_pconst("antivirus_engine startup\n");
    }
    else
    {
        ksc_pconst("antivirus_engine already startup\n");
    }
    return 0;
}

static int get_file_num(const char * dirname,int * total_num,int scan_symbol)
{
    DIR *dd = NULL;
    struct dirent *dent;
    STATBUF lstatbuf;
    STATBUF stat_buf;
    char *path = NULL;
    if (lstat(dirname, &lstatbuf) != -1)
    {
        if(S_ISLNK(lstatbuf.st_mode))
        { 
            if(scan_symbol)
            {             
                ksc_pinfo("%s is a symbolic link\n",dirname);          
                path = malloc(MAX_PATH_LENGTH);
                if (!path)
                {  
                    ksc_perror("Unable to allocate memory for path,len= %d\n", MAX_PATH_LENGTH); 
                    return -1;
                }
                memset(path,0,MAX_PATH_LENGTH);
                if(realpath(dirname,path)) 
                {
                    ksc_pinfo("realpath:%s\n",path);
                    if(stat(dirname, &stat_buf) != -1)
                    {
                        if(S_ISREG(stat_buf.st_mode))
                        {
                            ksc_pinfo("scan file realpath:%s\n",path);
                            *total_num = *total_num + 1;
                            ksc_pinfo("file found:total_num=%d\n",*total_num);
                        }
                        else if(S_ISDIR(stat_buf.st_mode))
                        {
                            ksc_pinfo("scan dir realpath:%s\n",path);
                            get_file_num(path,total_num,1);   
                        }
                        else
                        {
                            ksc_pinfo("%s: unkown symbolic link,do nothing\n",dirname);
                        }
                    }
                }
                else
                {
                    ksc_pconst("realpath failed,path:%s,errno:%s\n",dirname,strerror(errno));

                }
                free(path);
            }
            else
            {
                /*do nothing when scan_symbol is false*/
                ksc_pinfo("do nothing when scan_symbol is false\n");
                return 0;
            }
        }
        else if(S_ISREG(lstatbuf.st_mode))
        {
            *total_num = *total_num +1;
            ksc_pinfo("file found:total_num=%d\n",*total_num);
        }
        else if(S_ISDIR(lstatbuf.st_mode))
        {
            if ((dd = opendir(dirname)) != NULL)
            {                
                while ((dent = readdir(dd))) 
                {                        
                    if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) 
                    {
                        int path_len = strlen(dirname) + strlen(dent->d_name) + 3;
                        path = malloc(path_len);
                        if (!path)
                        {
                            ksc_perror("Unable to allocate memory for path,len= %d\n", path_len);
                            closedir(dd);
                            return -1;
                        }
                        memset(path,0,path_len);
                        snprintf(path,path_len-1,"%s/%s",dirname,dent->d_name);
                        /*not scan symbolic in subdirectories,maybe endless loop*/
                        get_file_num(path,total_num,0);   
                        free(path); 
                    }
                }
                closedir(dd);
            }
        }
    }
    else
    {
        ksc_pconst("lstat: %s failed,%s\n",dirname,strerror(errno));
        return -1;
    }
    return 0;
}

static int get_file_total_num(const char * dirname,int * total_num)
{
    int ret = 0;
    if(NULL == dirname || NULL == total_num)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    ret = get_file_num(dirname,total_num,1);
    if(ret)
    {
        ksc_perror("get_file_num failed,ret=%d\n",ret);
        return -1;
    }
    return 0;
}

static int scan_file(const char * file_name,antivirus_scan_info_t * scan_info)
{
    int ret = 0;
    const char *virus_name = NULL;
    struct cl_scan_options options;
    static uint64_t cur_percent = 0;
    uint64_t new_percent = 0;
    ksc_pinfo("scan file %s\n",file_name);

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general = CL_SCAN_GENERAL_ALLMATCHES;

    ret = cl_scanfile(file_name, &virus_name, NULL,antivirus_engine,&options);
    if (ret == CL_VIRUS)
    {
        ksc_pconst("virus file:%s,type:%s\n",file_name,virus_name);
        scan_info->infected_files++;
        scan_info->scan_files++;
        fprintf(scan_info->fd_log,"%u  %s  %s  nodeal\r\n",scan_info->infected_files,file_name,virus_name);

        /*write to virus db*/
        ksc_db_table_t array[1];
        memset(&(array[0]),0,sizeof(ksc_db_table_t));
        array[0].tables.virus_table.deal_status = KSC_DB_VIRUS_DEAL_STATUS_NODEAL;
        strncpy(array[0].tables.virus_table.virus_type,virus_name,sizeof(array[0].tables.virus_table.virus_type)-1);
        strncpy(array[0].tables.virus_table.file_path,file_name,sizeof(array[0].tables.virus_table.file_path)-1);
        ret = ksc_db_add_item(KSC_DB_TYPE_VIRUS,array,1);
        if(ret)
        {
            ksc_perror("ksc_db_add_item failed,ret=%d\n",ret);
        }        
    }
    else if (ret == CL_CLEAN)
    {
        ksc_pinfo("clean file:%s\n",file_name);
        scan_info->scan_files++;
    }
    else
    {
        ksc_pconst("error file:%s\n",file_name);
        scan_info->error_files++;
        scan_info->scan_files++;
    }

    /*show scan process*/

    new_percent = (1000*(uint64_t)(scan_info->scan_files)) / (uint64_t)(scan_info->total_files);
    if(new_percent != cur_percent)
    {
        cur_percent = new_percent;
        ksc_pconst("total:%u,cur:%u,process:%llu.%llu%\n",
                   scan_info->total_files,scan_info->scan_files,
                   cur_percent / 10,cur_percent % 10);
    }

    return ret;
}

static int scan_dir(const char * dirname,antivirus_scan_info_t * scan_info,int scan_symbol)
{
    DIR *dd = NULL;
    struct dirent *dent;
    STATBUF lstatbuf;
    STATBUF stat_buf;
    char *path = NULL;
    if (lstat(dirname, &lstatbuf) != -1)
    {
        if(S_ISLNK(lstatbuf.st_mode))
        {
            if(scan_symbol)
            {             
                ksc_pinfo("%s is a symbolic link\n",dirname);          
                path = malloc(MAX_PATH_LENGTH);
                if (!path)
                {  
                    ksc_perror("Unable to allocate memory for path,len= %d\n", MAX_PATH_LENGTH); 
                    return -1;
                }
                memset(path,0,MAX_PATH_LENGTH);
                if(realpath(dirname,path)) 
                {
                    ksc_pinfo("realpath:%s\n",path);
                    if(stat(dirname, &stat_buf) != -1)
                    {
                        if(S_ISREG(stat_buf.st_mode))
                        {
                            ksc_pinfo("scan file realpath:%s\n",path);
                            scan_file(path,scan_info);
                        }
                        else if(S_ISDIR(stat_buf.st_mode))
                        {
                            ksc_pinfo("scan dir realpath:%s\n",path);
                            scan_dir(path,scan_info,1);
                        }
                        else
                        {
                            ksc_pinfo("%s: unkown symbolic link,do noting\n",dirname);
                        }
                    }
                }
                else
                {
                    ksc_pconst("realpath failed,%s\n",strerror(errno));

                }
                free(path);
            }
            else
            {
                /*do nothing when scan_symbol is false*/
                ksc_pinfo("do nothing when scan_symbol is false\n");
                return 0;
            } 
        }
        else if(S_ISREG(lstatbuf.st_mode))
        {
            scan_file(dirname,scan_info);
        }
        else if (S_ISDIR(lstatbuf.st_mode))
        {
            ksc_pinfo("scan dir %s\n",dirname);
            if ((dd = opendir(dirname)) != NULL)
            {        
                scan_info->scan_dirs++;        
                while ((dent = readdir(dd))) 
                {                        
                    if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) 
                    {
                        int path_len = strlen(dirname) + strlen(dent->d_name) + 3;
                        path = malloc(path_len);
                        if (!path)
                        {
                            ksc_perror("Unable to allocate memory for path,len= %d\n", path_len);
                            closedir(dd);
                            return -1;
                        }
                        memset(path,0,path_len);
                        if(strlen(dirname)&&('/' == *(dirname+strlen(dirname)-1)))
                        {
                            snprintf(path,path_len-1,"%s%s",dirname,dent->d_name);
                        }
                        else
                        {
                            snprintf(path,path_len-1,"%s/%s",dirname,dent->d_name);
                        }
                        /*not scan symbolic in subdirectories,maybe endless loop*/
                        scan_dir(path,scan_info,0);   
                        free(path); 
                    }
                }
                closedir(dd);
            }
        }
    }
    else
    {
        ksc_pconst("lstat: %s failed,%s\n",dirname,strerror(errno));
        return -1;
    }
    return 0;
}

static void libclamav_msg_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx)
{
    UNUSEDPARAM(fullmsg);
    UNUSEDPARAM(ctx);

    switch (severity) {
        case CL_MSG_ERROR:
            ksc_pconst("^[LibClamAV] %s", msg);
            break;
        case CL_MSG_WARN:
            ksc_pconst("~[LibClamAV] %s", msg);
            break;
        default:
            ksc_pconst("*[LibClamAV] %s", msg);
            break;
    }
}

fc_error_t download_complete_callback(const char *dbFilename, void *context)
{
    fc_error_t status = FC_EARG;
    fc_error_t ret;
    fc_ctx *fc_context = (fc_ctx *)context;

    if ((NULL == context) || (NULL == dbFilename))
    {
        ksc_perror("^Invalid arguments to download_complete_callback.\n");
        goto done;
    }

    ksc_pinfo("*download_complete_callback: Download complete for database : %s\n", dbFilename);
    ksc_pinfo("*download_complete_callback:   fc_context->bTestDatabases   : %u\n", fc_context->bTestDatabases);
    ksc_pinfo("*download_complete_callback:   fc_context->bBytecodeEnabled : %u\n", fc_context->bBytecodeEnabled);

    ksc_pinfo("Testing database: '%s' ...\n", dbFilename);

    if (fc_context->bTestDatabases) 
    {
        ret = fc_test_database(dbFilename, fc_context->bBytecodeEnabled);
        if (FC_SUCCESS != ret)
        {
            ksc_perror("^Database load exited with \"%s\"\n", fc_strerror(ret));
            status = FC_ETESTFAIL;
            goto done;
        }
    }

    status = FC_SUCCESS;

done:
    if (FC_SUCCESS == status)
    {
        ksc_pinfo("Database test success.\n");
    } 
    else
    {
        ksc_perror("Database test failed.\n");
    }
    return status;
}

static int antivirus_fresh(void)
{
    int ret = 0;
    int status = 0;
    struct stat statbuf;
    fc_config fcConfig;
    time_t currtime;
    uint32_t updated_num = 0;

    memset(g_standard_update_url_list,0,sizeof(g_standard_update_url_list));
    g_standard_update_url_list[0] = malloc(MAX_URL_LENGTH);
    if(NULL == g_standard_update_url_list[0])
    {
        ksc_perror("standard_update_url_list malloc failed\n");
        return -1;
    }

    ret = antivirus_get_database_mirror(g_standard_update_url_list[0],MAX_URL_LENGTH);
    if(ret)
    {
        snprintf(g_standard_update_url_list[0],MAX_URL_LENGTH-1,KSC_ANTIVIRUS_DEFAULT_DB_UPDATE_URL);
        ksc_pconst("get database mirror failed,use default url:%s\n",g_standard_update_url_list[0]);
        g_standard_update_url_num = 1;
    }
    else
    {        
        ksc_pconst("get database mirror success:%s\n",g_standard_update_url_list[0]);
        g_standard_update_url_num = 1;
    }

    ret = antivirus_init();
    if(ret)
    {
        ksc_perror("antivirus_init failed,ret=%d\n",ret);
        status = -1;
        goto done;
    }

    /*update antivirus database*/
    memset(&fcConfig, 0, sizeof(fcConfig));
    fcConfig.maxAttempts = 3;
    fcConfig.connectTimeout = 15;
    fcConfig.requestTimeout = 0;

    char db_dir[MAX_PATH_LENGTH];
    char temp_dir[MAX_PATH_LENGTH];
    char temp_db_dir[MAX_PATH_LENGTH];
    memset(db_dir,0,sizeof(db_dir));
    memset(temp_dir,0,sizeof(temp_dir));
    memset(temp_db_dir,0,sizeof(temp_db_dir));

    ret = antivirus_get_db_dir(db_dir,sizeof(db_dir));
    if(ret)
    {
        snprintf(db_dir,sizeof(db_dir)-1,KSC_ANTIVIRUS_DEFAULT_DB_DIR);
        ksc_pconst("get database dir failed,use default dir:%s\n",db_dir);        
    }
    else
    {        
        ksc_pconst("get database dir success:%s\n",db_dir);
    }

    snprintf(temp_dir,sizeof(temp_dir)-1,"%s/temp",db_dir);
    snprintf(temp_db_dir,sizeof(temp_db_dir)-1,"%s/temp.%u",temp_dir,antivirus_randnum(65536));

    fcConfig.databaseDirectory = db_dir;
    fcConfig.tempDirectory = temp_db_dir;

    if (lstat(fcConfig.databaseDirectory, &statbuf) == -1)
    {
        if (0 != mkdir(fcConfig.databaseDirectory, 0755))
        {
            ksc_pinfo("create database directory failed: %s\n", fcConfig.databaseDirectory);
        }
    }
    else
    {
        ksc_pinfo("database directory exist: %s\n", fcConfig.databaseDirectory);
    }

    if (lstat(temp_dir, &statbuf) == -1)
    {
        if (0 != mkdir(temp_dir, 0755))
        {
            ksc_pinfo("create temp directory failed: %s\n",temp_dir);
        }
    }
    else
    {
        ksc_pinfo("temp directory exist: %s\n", temp_dir);
    }

    if(lstat(fcConfig.tempDirectory, &statbuf) == -1)
    {
        if (0 != mkdir(fcConfig.tempDirectory, 0755))
        {
            ksc_perror("create temp db directory failed:%s\n", fcConfig.tempDirectory);
            ksc_pconst("Hint: The database db directory must be writable for UID %d or GID %d\n", getuid(), getgid());
            status = -1;
            goto done;
        }
    }
    else
    {
        ksc_pinfo("temp db directory exist: %s\n", temp_dir);
    }

    cl_set_clcb_msg(libclamav_msg_callback);

    if(FC_SUCCESS != (ret = fc_initialize(&fcConfig)))
    {
        ksc_perror("libfreshclam init failed.\n");
        status = -1;
        goto done;
    }

    fc_set_fccb_download_complete(download_complete_callback);

    time(&currtime);
    ksc_pconst("update process started at %s", ctime(&currtime));

    fc_context.bTestDatabases = 1;
    fc_context.bTestDatabases = 0;

    if((NULL != g_standard_database_list) && (0 < g_standard_database_num))
    {
        /*
        * Download/update the desired official databases.
         */
        ret = fc_update_databases(
            g_standard_database_list,
            g_standard_database_num,
            g_standard_update_url_list,
            g_standard_update_url_num,
            0,
            NULL,
            0,
            (void *)&fc_context,
            &updated_num);
        if (FC_SUCCESS != ret) 
        {
            ksc_perror("!Database update process failed: %s\n", fc_strerror(ret));
            status = -1;
            goto done;
        }
        else
        {
            ksc_pconst("Database update success\n");
        }
    }

    time(&currtime);
    ksc_pconst("update process end at %s", ctime(&currtime));

    status = 0;

done:
    if (lstat(temp_dir, &statbuf) != -1)
    {
        /* Remove temp directory */
        if (*(temp_dir)) 
        {
            antivirus_rmdirs(temp_dir);
        }
    }

    return status;
}

static int antivirus_scan_dir(const char * path)
{
    struct stat statbuf;
    int ret = 0;
    int status = 0;
    struct timeval t1, t2;
    int ds = 0,dms = 0;
    time_t date_start, date_end;
    struct tm tmp;
    char start_buffer[30];
    char end_buffer[30];
    antivirus_scan_info_t scan_info;

    memset(&scan_info,0,sizeof(antivirus_scan_info_t));

    cl_initialize_crypto();

    /*libclamav debug switch, default off*/ 
    /*
    cl_debug();
    */

    ret = antivirus_init();
    if(ret)
    {
        ksc_perror("antivirus_init failed,ret=%d\n",ret);
        status = -1;
        goto done;
    }

    ret = antivirus_engine_new(&(scan_info.sig_num));
    if(ret)
    {
        ksc_perror("antivirus_engine_new failed,ret=%d\n",ret);
        status = -1;
        goto done;
    }
    
    /*cl_engine_set_clcb_virus_found(antivirus_engine, clamscan_virus_found_cb);*/

    date_start = time(NULL);
    gettimeofday(&t1, NULL);
    localtime_r(&date_start, &tmp);
    strftime(start_buffer,sizeof(start_buffer),"%Y:%m:%d %H:%M:%S",&tmp);

    ksc_pconst("scan start,path:%s\n",path);

    /*create log dir*/
    if (stat(KSC_ANTIVIRUS_SCAN_LOG_DIR, &statbuf) == -1)
    {
        if (0 != mkdir(KSC_ANTIVIRUS_SCAN_LOG_DIR, 0755))
        {
            ksc_pinfo("create log directory failed: %s\n",KSC_ANTIVIRUS_SCAN_LOG_DIR);
        }
    }
    else
    {
        ksc_pinfo("log directory exist: %s\n",KSC_ANTIVIRUS_SCAN_LOG_DIR);
    }

    /*open log file fd */

    scan_info.fd_log = fopen(KSC_ANTIVIRUS_SCAN_LOG_FILE, "w");
    if (NULL == scan_info.fd_log)
    {
        ksc_pconst("fopen log file failed,%s\n",strerror(errno));
        return -1;
    }

    /*write virus list title to log file */
    fprintf(scan_info.fd_log,"index        files        virus_type        status\r\n");

    ret = get_file_total_num(path,&(scan_info.total_files));
    if(ret)
    {
        ksc_perror("get_file_total_num failed,ret=%d\n",ret);
        status = -1;
        goto done;
    }
    ksc_pconst("%d files need to be scaned\n",scan_info.total_files);
    scan_dir(path,&scan_info,1);

    date_end = time(NULL);
    gettimeofday(&t2, NULL);
    localtime_r(&date_end, &tmp);
    strftime(end_buffer,sizeof(end_buffer),"%Y:%m:%d %H:%M:%S",&tmp);
    ds = t2.tv_sec - t1.tv_sec;
    dms = (t2.tv_usec - t1.tv_usec) / 1000;
    if(dms < 0)
    {
        ds = ds - 1;
        dms = 1000 + dms;
    }
    ksc_pconst("----------Scan info----------\n");
    ksc_pconst("Scan Target: %s\n", path);
    ksc_pconst("Start Date: %s\n", start_buffer);
    ksc_pconst("End Date:   %s\n", end_buffer);
    ksc_pconst("Times:      %d m %d s %d ms\n", ds / 60,ds % 60,dms);
    ksc_pconst("Scanned directories: %d\n",scan_info.scan_dirs);
    ksc_pconst("Scanned files: %d\n",scan_info.scan_files);
    ksc_pconst("Infected files: %d\n",scan_info.infected_files);
    ksc_pconst("Error files: %d\n",scan_info.error_files);
    ksc_pconst("Engine version: %s\n",LIBCLAMAV_VERSION);
    ksc_pconst("Engine known viruses: %d\n",scan_info.sig_num);
    
    /*write to scan log*/
    fprintf(scan_info.fd_log,"----------Scan info----------\r\n");
    fprintf(scan_info.fd_log,"Scan Target: %s\n", path);
    fprintf(scan_info.fd_log,"Start Date: %s\r\n", start_buffer);
    fprintf(scan_info.fd_log,"End Date:   %s\r\n", end_buffer);
    fprintf(scan_info.fd_log,"Times:      %d m %d s\r\n", ds / 60,ds % 60);
    fprintf(scan_info.fd_log,"Scanned directories: %u\r\n",scan_info.scan_dirs);
    fprintf(scan_info.fd_log,"Scanned files: %u\r\n",scan_info.scan_files);
    fprintf(scan_info.fd_log,"Infected files: %u\r\n",scan_info.infected_files);
    fprintf(scan_info.fd_log,"Error files: %u\r\n",scan_info.error_files);
    fprintf(scan_info.fd_log,"Engine version: %s\r\n",LIBCLAMAV_VERSION);
    fprintf(scan_info.fd_log,"Engine known viruses: %u\r\n",scan_info.sig_num);

done:
    if(scan_info.fd_log)
    {
        fclose(scan_info.fd_log);
    }

    return status;
}

static int antivirus_show_scan_log()
{
    FILE * fd_log = NULL;
    char read_buffer[1024];
    /*open log fd */
    fd_log = fopen(KSC_ANTIVIRUS_SCAN_LOG_FILE, "r");
    if (NULL == fd_log)
    {
        ksc_pconst("fopen log file failed,%s\n",strerror(errno));
        return -1;
    }
    while (fgets(read_buffer,sizeof(read_buffer),fd_log) != NULL)
    {
        ksc_pconst("%s",read_buffer);
    }
    fclose(fd_log);
    return 0;
}

static int antivirus_report(void)
{   
    antivirus_show_scan_log();
    return 0;
}

static int get_viruses_count(unsigned int * total_num)
{
    int ret = 0;
    if(NULL == total_num)
    {
        ksc_perror("invalid pare\n");
        return -1;
    }
    ksc_db_select_count_t select_count;
    memset(&select_count,0,sizeof(ksc_db_select_count_t));
    select_count.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    ret = ksc_db_select_count(KSC_DB_TYPE_VIRUS,&select_count,total_num);
    if(ret)
    {
        ksc_perror("ksc_db_select_count failed,ret=%d\n",ret);
        return -1;
    }
    return 0;
}

static int show_a_page_viruses(unsigned int start_index,unsigned int num_per_page)
{
    int ret = 0,i = 0;
    unsigned int total_num = 0;
    ksc_db_select_item_t select_item;
    ksc_db_table_t * array = NULL;
    unsigned int array_num = 0;
    
    ret = get_viruses_count(&total_num); 
    if(ret)
    {
        ksc_perror("get_viruses_count failed,ret=%d\n",ret);
        return -1;
    }

    /*set select conditions*/
    memset(&select_item,0,sizeof(ksc_db_select_item_t));
    select_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    select_item.order = KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME;
    select_item.offset = start_index - 1;
    select_item.limits = num_per_page;

    array = malloc(sizeof(ksc_db_table_t)*num_per_page);
    if(NULL == array)
    {
        ksc_perror("malloc array failed,len:%d\n",sizeof(ksc_db_table_t)*num_per_page);
        return -1;
    }
    memset(array,0,sizeof(ksc_db_table_t)*num_per_page);

    ret = ksc_db_select_item(KSC_DB_TYPE_VIRUS,&select_item,array,&array_num);
    if(ret)
    {
        free(array);
        ksc_perror("ksc_db_select_item failed,ret=%d\n",ret);
        return -1;
    }
    ksc_pconst("index        files        virus_type        status\r\n");
    for(i = 0; i < array_num; i++)
    {
        ksc_pconst("%d    %s    %s    %s\n",select_item.offset+1+i,
                   (array+i)->tables.virus_table.file_path,
                   (array+i)->tables.virus_table.virus_type,
                   deal_status[(array+i)->tables.virus_table.deal_status]);
    }
    ksc_pconst("    list[%d-%d]    totoal[%d] \n",select_item.offset+1,
               select_item.offset+array_num,total_num);

    free(array);
    return 0;
}

static int antivirus_show_virus_list()
{
    int index = -1,ret = 0;
    unsigned int num_per_page = 30;
    char str_index[MAX_CMDLINE_BUFFER_SIZE];
    memset(str_index,0,sizeof(str_index));
    scanf("%1023s",str_index);
    ksc_pinfo("str_index=%s\n",str_index);
    index = atoi(str_index);
    if(index <= 0)
    {
        ksc_perror("invalid index=%s\n",str_index);
        return -1;
    }    
    ret = show_a_page_viruses(index,num_per_page);
    if(ret)
    {
        ksc_perror("show_a_page_viruses failed ret=%d\n",ret);
        return -1;
    }
    return 0;
}

static int restore_a_virus(int index)
{
    int ret = 0;
    ksc_db_select_item_t select_item;
    ksc_db_table_t array;
    unsigned int array_num = 0;
    unsigned char hash_name[60];
    unsigned int hash_len = 0;
    char isolate_filepath[MAX_PATH_LENGTH];

    /*set select conditions*/
    memset(&select_item,0,sizeof(ksc_db_select_item_t));
    select_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    select_item.order = KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME;
    select_item.offset = index-1;
    select_item.limits = 1;
    memset(&array,0,sizeof(ksc_db_table_t));
    ret = ksc_db_select_item(KSC_DB_TYPE_VIRUS,&select_item,&array,&array_num);
    if(ret)
    {
        ksc_perror("ksc_db_select_item failed,ret=%d\n",ret);
        return -1;
    }
    if(array_num != 1)
    {
        ksc_perror("ksc_db_select_item failed,array_num=%d\n",array_num);
        return -1;
    }

    if(KSC_DB_VIRUS_DEAL_STATUS_IOSLATE == array.tables.virus_table.deal_status)
    {
        /*virus has been isolated,try to restore it*/
        ksc_pconst("try to restore the virus \n");  
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_DELETE == array.tables.virus_table.deal_status)
    {
        /*the virus has been deleted*/
        ksc_pconst("the virus has been deleted,can not restore\n");
        return -1;
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_NODEAL == array.tables.virus_table.deal_status)
    {   
        ksc_pconst("the virus has been restore,do nothing\n");
        return 1;   
    }
    else
    {
        ksc_pconst("virus status is unknown\n");
        return -1;
    }

    /*generate sha1 hash file name*/
    memset(hash_name,0,sizeof(hash_name));
    cl_sha1(array.tables.virus_table.file_path,strlen(array.tables.virus_table.file_path),hash_name,&hash_len);
    int i = 0;
    ksc_pconst("hash_len:%d,isolate_name:",hash_len);
    for(i = 0; i < hash_len; i++)
    {
        ksc_pconst("%x",hash_name[i]);
    }
    ksc_pconst("\n");

    memset(isolate_filepath,0,sizeof(isolate_filepath));
    snprintf(isolate_filepath,sizeof(isolate_filepath)-1,
            "%s/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            KSC_ANTIVIRUS_SCAN_ISOLATE_DIR,
            hash_name[0],hash_name[1],hash_name[2],hash_name[3],hash_name[4],
            hash_name[5],hash_name[6],hash_name[7],hash_name[8],hash_name[9],
            hash_name[10],hash_name[11],hash_name[12],hash_name[13],hash_name[14],
            hash_name[15],hash_name[16],hash_name[17],hash_name[18],hash_name[19]);
    ret = rename(isolate_filepath,array.tables.virus_table.file_path);
    if(ret)
    {
        ksc_pconst("rename %s failed,%s\n",isolate_filepath,strerror(errno));
        return -1;
    }

    /*change deal status to nodeal*/
    array.tables.virus_table.deal_status = KSC_DB_VIRUS_DEAL_STATUS_NODEAL;
    ret = ksc_db_update_item(KSC_DB_TYPE_VIRUS,&array,1);
    if(ret)
    {
        ksc_perror("ksc_db_update_item failed,ret=%d\n",ret);
        return -1;
    }
    ksc_pconst("restore %s success\n",array.tables.virus_table.file_path);
    return 0;
}

static int restore_all_viruses(void)
{
    int ret = 0,i = 0;
    unsigned int total_num = 0;
    ret = get_viruses_count(&total_num); 
    if(ret)
    {
        ksc_perror("get_viruses_count failed,ret=%d\n",ret);
        return -1;
    }
    for(i = 0; i < total_num; i++)
    {
        ret = restore_a_virus(i+1);
        if(ret < 0)
        {
            ksc_perror("restore_a_virus failed,ret=%d,index=%d\n",ret,i+1);
        }
    }
    return 0;
}

static int delete_a_isolate_virus(int index)
{
    int ret = 0;
    ksc_db_select_item_t select_item;
    ksc_db_table_t array;
    unsigned int array_num = 0;
    unsigned char hash_name[60];
    unsigned int hash_len = 0;
    char isolate_filepath[MAX_PATH_LENGTH];    

    /*set select conditions*/
    memset(&select_item,0,sizeof(ksc_db_select_item_t));
    select_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    select_item.order = KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME;
    select_item.offset = index-1;
    select_item.limits = 1;
    memset(&array,0,sizeof(ksc_db_table_t));
    ret = ksc_db_select_item(KSC_DB_TYPE_VIRUS,&select_item,&array,&array_num);
    if(ret)
    {
        ksc_perror("ksc_db_select_item failed,ret=%d\n",ret);
        return -1;
    }
    if(array_num != 1)
    {
        ksc_perror("ksc_db_select_item failed,array_num=%d\n",array_num);
        return -1;
    }

    if(KSC_DB_VIRUS_DEAL_STATUS_IOSLATE != array.tables.virus_table.deal_status)
    {
        /*virus has been isolated,delete in isolate dir*/
        ksc_pconst("the virus status is not isolate\n");
        return -1;
    }

    /*generate sha1 hash file name*/
    memset(hash_name,0,sizeof(hash_name));
    cl_sha1(array.tables.virus_table.file_path,strlen(array.tables.virus_table.file_path),
            hash_name,&hash_len);
    int i = 0;

    ksc_pconst("hash_len:%d,isolate_name:",hash_len);
    for(i = 0; i < hash_len; i++)
    {
        ksc_pconst("%02x",hash_name[i]);
    }
    ksc_pconst("\n");

    memset(isolate_filepath,0,sizeof(isolate_filepath));
    snprintf(isolate_filepath,sizeof(isolate_filepath)-1,
            "%s/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            KSC_ANTIVIRUS_SCAN_ISOLATE_DIR,
            hash_name[0],hash_name[1],hash_name[2],hash_name[3],hash_name[4],
            hash_name[5],hash_name[6],hash_name[7],hash_name[8],hash_name[9],
            hash_name[10],hash_name[11],hash_name[12],hash_name[13],hash_name[14],
            hash_name[15],hash_name[16],hash_name[17],hash_name[18],hash_name[19]);
    ret = remove(isolate_filepath);
    if(ret&&(ENOENT != errno))
    {
        ksc_pconst("remove %s failed,%s\n",isolate_filepath,strerror(errno));
        return -1;
    }

    /*change deal status to delete*/
    array.tables.virus_table.deal_status = KSC_DB_VIRUS_DEAL_STATUS_DELETE;
    ret = ksc_db_update_item(KSC_DB_TYPE_VIRUS,&array,1);
    if(ret)
    {
        ksc_perror("ksc_db_update_item failed,ret=%d\n",ret);
        return -1;
    }
    ksc_pconst("delete %s success\n",isolate_filepath);
    return 0;
}

static int isolate_a_virus(int index)
{
    int ret = 0;
    ksc_db_select_item_t select_item;
    ksc_db_table_t array;
    unsigned int array_num = 0;
    struct stat statbuf;
    unsigned char hash_name[60];
    unsigned int hash_len = 0;
    char isolate_filepath[MAX_PATH_LENGTH];

    /*create isolate dir*/
    if (stat(KSC_ANTIVIRUS_SCAN_ISOLATE_DIR, &statbuf) == -1)
    {
        if (0 != mkdir(KSC_ANTIVIRUS_SCAN_ISOLATE_DIR, 0755))
        {
            ksc_pinfo("create isolate directory failed: %s\n",KSC_ANTIVIRUS_SCAN_ISOLATE_DIR);
        }
    }
    else
    {
        ksc_pinfo("isolate directory exist: %s\n",KSC_ANTIVIRUS_SCAN_ISOLATE_DIR);
    }

    /*set select conditions*/
    memset(&select_item,0,sizeof(ksc_db_select_item_t));
    select_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    select_item.order = KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME;
    select_item.offset = index - 1;
    select_item.limits = 1;

    memset(&array,0,sizeof(ksc_db_table_t));
    ret = ksc_db_select_item(KSC_DB_TYPE_VIRUS,&select_item,&array,&array_num);
    if(ret)
    {
        ksc_perror("ksc_db_select_item failed,ret=%d\n",ret);
        return -1;
    }
    if(array_num != 1)
    {
        ksc_perror("ksc_db_select_item failed,array_num=%d\n",array_num);
        return -1;
    }

    if(KSC_DB_VIRUS_DEAL_STATUS_IOSLATE == array.tables.virus_table.deal_status)
    {
        /*virus has been isolated*/
        ksc_pconst("the virus has been isolated,do nothing\n");
        return 1;
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_DELETE == array.tables.virus_table.deal_status)
    {
        /*virus has been deleted*/
        ksc_pconst("the virus has been deleted,can not isolate\n");
        return -1;
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_NODEAL == array.tables.virus_table.deal_status)
    {
        ksc_pconst("try to isolate the virus \n");
    }
    else
    {
        ksc_pconst("virus status is unknown\n");
        return -1;
    }

    /*generate sha1 hash file name*/
    memset(hash_name,0,sizeof(hash_name));
    cl_sha1(array.tables.virus_table.file_path,strlen(array.tables.virus_table.file_path),hash_name,&hash_len);
    int i = 0;

    ksc_pconst("hash_len:%d,isolate_name:",hash_len);
    for(i = 0;i < hash_len; i++)
    {
        ksc_pconst("%02x",hash_name[i]);
    }
    ksc_pconst("\n");

    memset(isolate_filepath,0,sizeof(isolate_filepath));
    snprintf(isolate_filepath,sizeof(isolate_filepath)-1,
        "%s/%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        KSC_ANTIVIRUS_SCAN_ISOLATE_DIR,
        hash_name[0],hash_name[1],hash_name[2],hash_name[3],hash_name[4],
        hash_name[5],hash_name[6],hash_name[7],hash_name[8],hash_name[9],
        hash_name[10],hash_name[11],hash_name[12],hash_name[13],hash_name[14],
        hash_name[15],hash_name[16],hash_name[17],hash_name[18],hash_name[19]);
    ret = rename(array.tables.virus_table.file_path,isolate_filepath);
    if(ret)
    {
        ksc_pconst("rename %s failed,%s\n",array.tables.virus_table.file_path,strerror(errno));
        return -1;
    }

    /*change deal status to isolate*/
    array.tables.virus_table.deal_status = KSC_DB_VIRUS_DEAL_STATUS_IOSLATE;
    ret = ksc_db_update_item(KSC_DB_TYPE_VIRUS,&array,1);
    if(ret)
    {
        ksc_perror("ksc_db_update_item failed,ret=%d\n",ret);
        return -1;
    }
    ksc_pconst("isolate %s success\n",array.tables.virus_table.file_path);
    return 0;
}

static int isolate_all_viruses(void)
{
    int ret = 0,i = 0;
    unsigned int total_num = 0;
    ret = get_viruses_count(&total_num); 
    if(ret)
    {
        ksc_perror("get_viruses_count failed,ret=%d\n",ret);
        return -1;
    }
    for(i = 0;i < total_num; i++)
    {
        ret = isolate_a_virus(i+1);
        if(ret < 0)
        {
            ksc_perror("isolate_a_virus failed,ret=%d,index=%d\n",ret,i+1);
        }
    }
    return 0;
}

static int delete_a_virus(int index)
{
    int ret = 0;

    ksc_db_select_item_t select_item;
    ksc_db_table_t array;
    unsigned int array_num = 0;

    /*set select conditions*/
    memset(&select_item,0,sizeof(ksc_db_select_item_t));
    select_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;
    select_item.order = KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME;
    select_item.offset = index - 1;
    select_item.limits = 1;
    memset(&array,0,sizeof(ksc_db_table_t));

    ret = ksc_db_select_item(KSC_DB_TYPE_VIRUS,&select_item,&array,&array_num);
    if(ret)
    {
        ksc_perror("ksc_db_select_item failed,ret=%d\n",ret);
        return -1;
    }
    if(array_num != 1)
    {
        ksc_perror("ksc_db_select_item failed,array_num=%d\n",array_num);
        return -1;
    }

    ret = remove(array.tables.virus_table.file_path);
    if(ret&&(ENOENT != errno))
    {
        ksc_pconst("remove %s failed,%s\n",array.tables.virus_table.file_path,strerror(errno));
        return -1;
    }

    if(KSC_DB_VIRUS_DEAL_STATUS_IOSLATE == array.tables.virus_table.deal_status)
    {
        /*virus has been isolated,delete in isolate dir*/
        ksc_pconst("the virus has been isolated,try to delete in isolate dir\n");
        ret = delete_a_isolate_virus(index);
        if(ret)
        {
            ksc_perror("delete_a_isolate_virus failed,ret=%d\n",ret);
            return -1;
        }
        else
        {
            return 0;
        }
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_DELETE == array.tables.virus_table.deal_status)
    {
        /*virus has been deleted*/
        ksc_pconst("the virus has been deleted,do nothing\n");
        return 1;
    }
    else if(KSC_DB_VIRUS_DEAL_STATUS_NODEAL == array.tables.virus_table.deal_status)
    {
        ksc_pconst("try to delete the virus \n");
    }
    else
    {
        ksc_pconst("virus status is unknown\n");
        return -1;
    }
    /*change deal status to delete*/
    array.tables.virus_table.deal_status = KSC_DB_VIRUS_DEAL_STATUS_DELETE;
    ret = ksc_db_update_item(KSC_DB_TYPE_VIRUS,&array,1);
    if(ret)
    {
        ksc_perror("ksc_db_update_item failed,ret=%d\n",ret);
        return -1;
    }
    ksc_pconst("remove %s success\n",array.tables.virus_table.file_path);
    return 0;
}

static int delete_all_viruses(void)
{
    int ret = 0,i = 0;
    unsigned int total_num = 0;
    ret = get_viruses_count(&total_num); 
    if(ret)
    {
        ksc_perror("get_viruses_count failed,ret=%d\n",ret);
        return -1;
    }
    for(i = 0; i < total_num; i++)
    {
        ret = delete_a_virus(i + 1);
        if(ret < 0)
        {
            ksc_perror("delete_a_virus failed,ret=%d,index=%d\n",ret,i + 1);
        }
    }
    return 0;
}

static int clean_virus_db(void)
{
    int ret = 0;
    ksc_db_del_item_t del_item;
    /*set delete conditions*/
    memset(&del_item,0,sizeof(ksc_db_del_item_t));
    del_item.select_type = KSC_DB_SELECT_TYPE_VIRUS_ALL;

    ret = ksc_db_del_item(KSC_DB_TYPE_VIRUS,&del_item);
    if(ret)
    {
        ksc_perror("ksc_db_del_item failed,ret=%d\n",ret);
        return -1;
    }
    return 0;
}

static int antivirus_del_virus()
{
    int index = -1,ret = 0;
    char str_index[MAX_CMDLINE_BUFFER_SIZE];
   // char path[MAX_PATH_LENGTH];
    //ksc_db_virus_deal_status_e status=KSC_DB_VIRUS_DEAL_STATUS_INVALID;
    memset(str_index,0,sizeof(str_index));
    scanf("%1023s",str_index);
    ksc_pinfo("str_index=%s\n",str_index);
    index = atoi(str_index);
    if(index <= 0)
    {
        if(strstr(str_index,"all"))
        {
            ksc_pconst("you want to delete all viruses?[yes/no]\n");
            memset(str_index,0,sizeof(str_index));
            scanf("%1023s",str_index);

            if((!strcmp(str_index, "yes")) || (!strcmp(str_index, "Y")) || (!strcmp(str_index, "y")))
            {
                ksc_pconst("delete all viruses,please wait\n");
                ret = delete_all_viruses();
                if(ret)
                {
                    ksc_pconst("try to delete_all_viruses failed,ret=%d\n",ret);
                    return -1;
                }
                ksc_pconst("delete all viruses success\n");
                return 0;
            }
            else
            {
                ksc_pconst("do nothing\n");
                return 0;   
            }
        }
        else if(strstr(str_index,"db"))
        {
            ksc_pconst("you want to delete virus database?[yes/no]\n");
            memset(str_index,0,sizeof(str_index));
            scanf("%1023s",str_index);

            if((!strcmp(str_index, "yes")) || (!strcmp(str_index, "Y")) || (!strcmp(str_index, "y")))
            {
                ksc_pconst("try to clean virus database,please wait\n");
                ret = clean_virus_db();
                if(ret)
                {
                    ksc_pconst("clean_virus_db failed,ret=%d\n",ret);
                    return -1;
                }
                ksc_pconst("clean virus database success\n");
                return 0;
            }
            else
            {
                ksc_pconst("do nothing\n");
                return 0;   
            }
        }
        else
        {
            ksc_perror("invalid index=%s\n",str_index);
            return -1;
        }
    }

    ret = delete_a_virus(index);
    if(ret < 0)
    {
        ksc_pconst("delete_a_virus failed,ret=%d\n",ret);
        return -1;
    }
    else if(0 == ret)
    {
        ksc_pconst("delete a virus success\n");
    }
    return 0;
  
}

static int antivirus_isolate_virus()
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
            ksc_pconst("you want to isolate all viruses?[yes/no]\n");
            memset(str_index,0,sizeof(str_index));
            scanf("%1023s",str_index);

            if((!strcmp(str_index, "yes")) || (!strcmp(str_index, "Y")) || (!strcmp(str_index, "y")))
            {
                ksc_pconst("try to isolate all viruses,please wait\n");
                isolate_all_viruses();
                ksc_pconst("isolate all viruses success\n");
                return 0;
            }
            else
            {
                ksc_pconst("do nothing\n");
                return 0;   
            }
        }
        else
        {
            ksc_perror("invalid index=%s\n",str_index);
            return -1;
        }        
    }
    ret = isolate_a_virus(index);
    if(ret < 0)
    {
        ksc_pconst("isolate_a_virus failed,ret=%d\n",ret);
        return -1;
    }
    else if(0 == ret)
    {
        ksc_pconst("isolate a virus success\n");
    }
    return 0;   
}

static int antivirus_restore_virus()
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
            ksc_pconst("you want to restore all viruses?[yes/no]\n");
            memset(str_index,0,sizeof(str_index));
            scanf("%1023s",str_index);

            if((!strcmp(str_index, "yes")) || (!strcmp(str_index, "Y")) || (!strcmp(str_index, "y")))
            {
                ksc_pconst("try to restore all viruses,please wait\n");
                restore_all_viruses();
                ksc_pconst("restore all viruses success\n");
                return 0;
            }
            else
            {
                ksc_pconst("do nothing\n");
                return 0;   
            }
        }
        else
        {
            ksc_perror("invalid index=%s\n",str_index);
            return -1;
        }        
    }

    ret = restore_a_virus(index);
    if(ret < 0)
    {
        ksc_pconst("restore_a_virus failed,ret=%d\n",ret);
        return -1;
    }    
    else if(0 == ret)
    {
        ksc_pconst("restore a virus success\n");
    }
    return 0;    
}

static void antivirus_deal_menu(void)
{
    ksc_pconst("[commands]\n");
    ksc_pconst("      ls <index>                  View virus list start with index.\n");
    ksc_pconst("      del <index|all|db>          Delete a virus by index,or delete all,or delete virus database.\n");
    ksc_pconst("      iso <index|all>             Isolate a virus by index,or isolate all.\n");
    ksc_pconst("      res <index|all>             Restore a virus by index,or restore all.\n");
    ksc_pconst("      exit                        Exit viruses deal submenu.\n");
    ksc_pconst("      help                        Display this help.\n");
}

static int antivirus_deal(void)
{
    char str_buf[MAX_CMDLINE_BUFFER_SIZE];
    antivirus_deal_menu();
    while(1)
    {
        memset(str_buf,0,sizeof(str_buf));
        ksc_pconst(": ");
        scanf("%1023s",str_buf);
        ksc_pinfo("str_buf=%s\n",str_buf);

        if (!strcmp(str_buf, "help")) 
        {
            antivirus_deal_menu();
        }
        else if (!strcmp(str_buf, "ls")) 
        {
            antivirus_show_virus_list();
        }
        else if(!strcmp(str_buf, "del"))  
        {
            antivirus_del_virus();
        }
        else if(!strcmp(str_buf, "iso"))  
        {
            antivirus_isolate_virus();
        }
        else if(!strcmp(str_buf, "res"))  
        {
            antivirus_restore_virus();           
        }
        else if(!strcmp(str_buf, "exit"))  
        {        
            return 0;
        }
        else
        {
            ksc_pconst("Invalid command.Input \"help\" to view commands format.\n");
        }

    }
    return 0;
}

int antivirus_handle(antivirus_args_t * args)
{
    int ret = 0;

    ret = ksc_db_init(KSC_DB_TYPE_VIRUS);
    if(ret)
    {
        ksc_perror("ksc_db_init virus failed,ret=%d\n",ret);
        return -1;        
    }

    ret = ksc_db_open(KSC_DB_TYPE_VIRUS);
    if(ret)
    {
        ksc_perror("ksc_db_open virus failed,ret=%d\n",ret);
        return -1;        
    }   

    switch(args->cmd)
    {
        case ANTIVIRUS_CMD_SCAN:
            ret = antivirus_scan_dir(args->content.scan_path);
            if(ret<0)
            {
                ksc_perror("antivirus_scan_dir failed,ret=%d\n",ret);
            }
        break;
        case ANTIVIRUS_CMD_REPORT:
            ret = antivirus_report();
            if(ret<0)
            {
                ksc_perror("antivirus_report failed,ret=%d\n",ret);
            }
        break;
        case ANTIVIRUS_CMD_FRESH:
            ret = antivirus_fresh();
            if(ret<0)
            {
                ksc_perror("antivirus_fresh failed,ret=%d\n",ret);
            }
        break;
        case ANTIVIRUS_CMD_DEAL:
            ret = antivirus_deal();
            if(ret<0)
            {
                ksc_perror("antivirus_deal failed,ret=%d\n",ret);
            }
        break;
        default:
        break;
    }
   
    if(ksc_db_close(KSC_DB_TYPE_VIRUS))
    {
        ksc_perror("ksc_db_close virus db failed\n");
    }

    return ret;
}
