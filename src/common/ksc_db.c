
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include "sqlite3.h"
#include "ksc_public.h"
#include "ksc_comdef.h"
#include "ksc_db.h"

#define SQL_CMD_LEN  1024

const char *create_table_virus_cmd =
        "CREATE TABLE tb_virus(file_path TEXT,virus_type TEXT,deal_status INTEGER,primary key(file_path));";

static sqlite3 *tb_virus_handle = NULL;
static int tb_virus_open_flag = 0;

static int db_virus_init()
{
    char *errmsg = NULL;
    static int virus_init_flag = 0;
    struct stat statbuf;
    if(!virus_init_flag)
    {
        /*create virus db dir*/
        if (stat(KSC_ANTIVIRUS_DB_VIRUS_DIR, &statbuf) < 0)
        {
            if (0 != mkdir(KSC_ANTIVIRUS_DB_VIRUS_DIR, 0755))
            {
                ksc_perror("create db virus directory failed:%s,%s\n",KSC_ANTIVIRUS_DB_VIRUS_DIR,strerror(errno));
                return -1;
            }
        }
        else
        {
            ksc_pinfo("db virus directory already exist: %s\n",KSC_ANTIVIRUS_DB_VIRUS_DIR);
        }

        /*create virus db file*/

        if (stat(KSC_ANTIVIRUS_DB_VIRUS, &statbuf) < 0)
        {
            sqlite3 * virus_handle = NULL;

            if (SQLITE_OK != sqlite3_open(KSC_ANTIVIRUS_DB_VIRUS,&virus_handle))
            {
                ksc_perror("sqlite3_open failed,file_path:%s\n",KSC_ANTIVIRUS_DB_VIRUS);
                return -1;
            }

            if (SQLITE_OK != sqlite3_exec(virus_handle,create_table_virus_cmd, 0, 0,&errmsg))
            {
                ksc_perror("error when create table virus, errmsg = %s\n",errmsg);
                sqlite3_close(virus_handle);
                sqlite3_free(errmsg);
                return -1;
            }

            if (SQLITE_OK != sqlite3_close(virus_handle))
            {
                ksc_perror("sqlite3_close failed\n");
                return -1;
            }
        }
        else
        {
            ksc_pinfo("db virus file already exist: %s\n",KSC_ANTIVIRUS_DB_VIRUS);
        }

        virus_init_flag = 1;
    }
    return 0;
}
static int db_virus_open()
{
    if(!tb_virus_open_flag)
    {
        if (SQLITE_OK != sqlite3_open(KSC_ANTIVIRUS_DB_VIRUS,&tb_virus_handle))
        {
            ksc_perror("sqlite3_open failed,file_path:%s\n",KSC_ANTIVIRUS_DB_VIRUS);
            return -1;
        }
        ksc_pinfo("open db: %s success\n",KSC_ANTIVIRUS_DB_VIRUS);
        tb_virus_open_flag = 1;
    }
    else
    {
        ksc_pinfo("open db: %s success\n",KSC_ANTIVIRUS_DB_VIRUS);
    }
    return 0;
}

static int db_virus_close()
{
    if(tb_virus_open_flag)
    {
        if (SQLITE_OK != sqlite3_close(tb_virus_handle))
        {
            ksc_perror("sqlite3_close failed,file_path:%s\n",KSC_ANTIVIRUS_DB_VIRUS);
            return -1;
        }
        ksc_pinfo("close db: %s success\n",KSC_ANTIVIRUS_DB_VIRUS);
        tb_virus_open_flag = 0;
    }
    else
    {
        ksc_pinfo("close db: %s success\n",KSC_ANTIVIRUS_DB_VIRUS);
    }

    return 0;
}

static int db_virus_add_item(ksc_db_table_t*array,unsigned int array_num)
{
    char sql[SQL_CMD_LEN];
    char *errmsg = NULL;
    int i = 0;

    if (NULL == array)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if (NULL == tb_virus_handle)
    {
        ksc_perror("table virus not open\n");
        return -1;
    }
    
    memset(sql, 0, sizeof(sql));
    for(i = 0; i < array_num; i++)
    {
        snprintf(sql,sizeof(sql)-1,"REPLACE INTO tb_virus VALUES(\"%s\",\"%s\",%d)",
                 array->tables.virus_table.file_path,array->tables.virus_table.virus_type,
                 array->tables.virus_table.deal_status);
        if (SQLITE_OK != sqlite3_exec(tb_virus_handle, sql, NULL, NULL, &errmsg))
        {
            ksc_perror("sqlite3_exec failed = %s\n",errmsg);
            sqlite3_free(errmsg);
            return -1;
        }
        array++;
    }
    
    return 0;
}

static int db_virus_update_item(ksc_db_table_t*array,unsigned int array_num)
{
    char sql[SQL_CMD_LEN];
    char *errmsg = NULL;
    int i = 0;

    if (NULL == array)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if (NULL == tb_virus_handle)
    {
        ksc_perror("table virus not open\n");
        return -1;
    }
    
    memset(sql, 0, sizeof(sql));
    for(i = 0;i < array_num; i++)
    {
        snprintf(sql,sizeof(sql)-1,"REPLACE INTO tb_virus VALUES(\"%s\",\"%s\",%d)",
                 array->tables.virus_table.file_path,array->tables.virus_table.virus_type,
                 array->tables.virus_table.deal_status);
        if (SQLITE_OK != sqlite3_exec(tb_virus_handle, sql, NULL, NULL, &errmsg))
        {
            ksc_perror("sqlite3_exec failed = %s\n",errmsg);
            sqlite3_free(errmsg);
            return -1;
        }
        array++;
    }
    
    return 0;
}

static int db_virus_del_item(ksc_db_del_item_t * del_item)
{
    int ret = -1;
    char sql[SQL_CMD_LEN];
    char *errmsg = NULL;
    char **result = NULL;
    int nrow = 0;
    int ncolumn = 0;
    int i = 0;

    if (NULL == tb_virus_handle)
    {
        ksc_perror("table virus not open\n");
        return -1;
    }

    memset(sql, 0, sizeof(sql));    
    switch(del_item->select_type)
    {
        case KSC_DB_SELECT_TYPE_VIRUS_ALL:
        {
            snprintf(sql, sizeof(sql)-1,"DELETE FROM tb_virus");            
        }
        break;

        case KSC_DB_SELECT_TYPE_VIRUS_FILE_NAME:
        {
            snprintf(sql, sizeof(sql)-1,"DELETE FROM tb_virus WHERE (file_path=\"%s\")",del_item->conditions.file_name);
        }
        break;

        default:
        ksc_perror("invalid para\n");
        return -1;
    }
    if (SQLITE_OK != sqlite3_exec(tb_virus_handle,sql,0,0,&errmsg))
    {
        ksc_perror("error when delete tb_virus,errmsg:%s\n",errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}

static int db_virus_select_item(ksc_db_select_item_t * select_item,ksc_db_table_t * array,unsigned int *array_num)
{
    char sql[SQL_CMD_LEN];
    char *errmsg = NULL;
    char **result = NULL;
    int nrow = 0;
    int ncolumn = 0;
    int i = 0;

    if (NULL == tb_virus_handle)
    {
        ksc_perror("table virus not open\n");
        return -1;
    }

    memset(sql, 0, sizeof(sql));    
    switch(select_item->select_type)
    {
        case KSC_DB_SELECT_TYPE_VIRUS_ALL:
        {
            if(KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME == select_item->order)
            {
                snprintf(sql, sizeof(sql)-1,"SELECT * FROM tb_virus ORDER BY file_path LIMIT %u OFFSET %u",
                         select_item->limits,select_item->offset);
            }
            else
            {
                snprintf(sql, sizeof(sql)-1,"SELECT * FROM tb_virus LIMIT %u OFFSET %u",
                         select_item->limits,select_item->offset);
            }
        }
        break;

        default:
        ksc_perror("invalid para\n");
        return -1;
    }
    
    if (SQLITE_OK != sqlite3_get_table(tb_virus_handle,sql,&result,&nrow,&ncolumn,&errmsg))
    {
        ksc_perror("sqlite3_get_table failed,errmsg:%s\n",errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    if (0 < nrow)
    {
        *array_num = nrow;
        for (i = 0; i < nrow; i++)
        {
            int index = 0;
            char ** db = (result + (i + 1) * ncolumn);
            ksc_db_table_t * info = array + i;

            strncpy(info->tables.virus_table.file_path,db[index],sizeof(info->tables.virus_table.file_path) - 1);
            index++;
            strncpy(info->tables.virus_table.virus_type,db[index],sizeof(info->tables.virus_table.virus_type) - 1);
            index++;
            info->tables.virus_table.deal_status = atoi(db[index]);
            index++;
        }
    }
    sqlite3_free_table(result);
    return 0;
}

static int db_virus_select_count(ksc_db_select_count_t * select_count,unsigned int * count)
{
    char sql[SQL_CMD_LEN];
    char* errmsg = NULL;
    char** result = NULL;

    if (NULL == tb_virus_handle)
    {
        ksc_perror("tb_virus_handle not open\n");
        return -1;
    }

    memset(sql, 0, sizeof(sql));

    switch(select_count->select_type)
    {
        case KSC_DB_SELECT_TYPE_VIRUS_ALL:
        {
            snprintf(sql, sizeof(sql)-1,"SELECT count(*) FROM tb_virus");
        }
        break;
        
        default:
            ksc_perror("invalid select_type:%d\n",select_count->select_type);
        return -1;
    }

    if (SQLITE_OK != sqlite3_get_table(tb_virus_handle, sql, &result, NULL, NULL, &errmsg))
    {
        ksc_perror("sqlite3_get_table failed errmsg:%s\n",errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    *count = 0;
    if (NULL != result[1])
    {
        *count = atoi(result[1]);
    }
    sqlite3_free_table(result);
    return 0;
}

int ksc_db_init(ksc_db_type_t type)
{
    int ret = 0;
    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_init();
        if(ret)
        {
            ksc_perror("db_virus_init failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_open(ksc_db_type_t type)
{

    int ret = 0;
    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_open();
        if(ret)
        {
            ksc_perror("db_virus_open failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_close(ksc_db_type_t type)
{
    int ret = 0;
    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_close();
        if(ret)
        {
            ksc_perror("db_virus_close failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_add_item(ksc_db_type_t type,ksc_db_table_t*array,unsigned int array_num)
{
    int ret = 0;
    if(NULL == array)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_add_item(array,array_num);
        if(ret)
        {
            ksc_perror("db_virus_add_item failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_update_item(ksc_db_type_t type,ksc_db_table_t*array,unsigned int array_num)
{
    int ret = 0;
    if(NULL == array)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_update_item(array,array_num);
        if(ret)
        {
            ksc_perror("db_virus_update_item failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_del_item(ksc_db_type_t type,ksc_db_del_item_t * del_item)
{  
    int ret = 0;
    if(NULL == del_item)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_del_item(del_item);
        if(ret)
        {
            ksc_perror("db_virus_del_item failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_select_item(ksc_db_type_t type,ksc_db_select_item_t * select_item,
                       ksc_db_table_t * array,unsigned int *array_num)
{
    int ret = 0;
    if(NULL == select_item || NULL == array || NULL == array_num)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_select_item(select_item,array,array_num);
        if(ret)
        {
            ksc_perror("db_virus_query_item failed\n");
            return -1;
        }
    }
    return 0;
}

int ksc_db_select_count(ksc_db_type_t type,ksc_db_select_count_t * select_count,unsigned int * count)
{
    int ret = 0;
    if(NULL == select_count || NULL == count)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    if(KSC_DB_TYPE_VIRUS == type)
    {
        ret = db_virus_select_count(select_count,count);
        if(ret)
        {
            ksc_perror("db_virus_query_item failed\n");
            return -1;
        }
    }
    return 0;
}
