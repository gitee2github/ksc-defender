#ifndef KSC_DB_H
#define KSC_DB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ksc_public.h"

/*table virus definition start*/

#define MAX_VIRUS_TYPE_LENGTH 50
typedef enum
{
    KSC_DB_VIRUS_DEAL_STATUS_NODEAL = 0,
    KSC_DB_VIRUS_DEAL_STATUS_DELETE,
    KSC_DB_VIRUS_DEAL_STATUS_IOSLATE,
    KSC_DB_VIRUS_DEAL_STATUS_INVALID
}ksc_db_virus_deal_status_e;

typedef struct 
{
    char file_path[MAX_PATH_LENGTH];/*primary key*/
    char virus_type[MAX_VIRUS_TYPE_LENGTH];
    ksc_db_virus_deal_status_e deal_status;
}ksc_db_virus_table_t;

/*table virus definition end*/

/*common definition start */

typedef enum
{
    KSC_DB_TYPE_VIRUS = 0,
    KSC_DB_TYPE_INVALID,
}ksc_db_type_t;

/*select type*/
typedef enum
{
    /*tb_virus select type start*/
    KSC_DB_SELECT_TYPE_VIRUS_FILE_NAME = 0,
    KSC_DB_SELECT_TYPE_VIRUS_ALL,
    /*tb_virus select type end*/

    KSC_DB_SELECT_TYPE_INVALID,
}ksc_db_select_type_e;

/*order type*/
typedef enum
{
    /*common order type start*/
    KSC_DB_SELECT_ORDER_NO_SORT = 0,    /*no sort*/
    /*common order type end*/

    /*tb_virus order type start*/
    KSC_DB_SELECT_ORDER_VIRUS_FILE_NAME,
    /*tb_virus order type end*/

    KSC_DB_SELECT_ORDER_INVALID,
}ksc_db_select_order_e;

typedef struct
{
    ksc_db_select_type_e select_type;  
    ksc_db_select_order_e order;  
    unsigned int offset;/*skip offset,get items from offset +1 */
    unsigned int limits;/*limit number of items*/
    /*select conditions*/
    union 
    {
        char file_name[MAX_PATH_LENGTH];
    }conditions;
}ksc_db_select_item_t;

typedef struct
{
    ksc_db_select_type_e select_type;  
    /*delete conditions*/
    union 
    {
        char file_name[MAX_PATH_LENGTH];
    }conditions;
}ksc_db_del_item_t;

typedef struct 
{
    union
    {
        ksc_db_virus_table_t virus_table;
    }tables;
}ksc_db_table_t;

typedef struct
{
    ksc_db_select_type_e select_type;  
    /*select count conditions*/
    union 
    {
        char file_name[MAX_PATH_LENGTH];
    }conditions;
}ksc_db_select_count_t;

/*common definition end */

int ksc_db_init(ksc_db_type_t type);
int ksc_db_open(ksc_db_type_t type);
int ksc_db_close(ksc_db_type_t type);
int ksc_db_add_item(ksc_db_type_t type,ksc_db_table_t*array,unsigned int array_num);
int ksc_db_update_item(ksc_db_type_t type,ksc_db_table_t*array,unsigned int array_num);
int ksc_db_del_item(ksc_db_type_t type,ksc_db_del_item_t * del_info);
int ksc_db_select_item(ksc_db_type_t type,ksc_db_select_item_t * select_item,
                       ksc_db_table_t * array,unsigned int *array_num);
int ksc_db_select_count(ksc_db_type_t type,ksc_db_select_count_t * select_count,unsigned int * count);

#ifdef __cplusplus
}
#endif

#endif /* KSC_DB_H */
