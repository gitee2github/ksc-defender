#ifndef KYLIN_FIREWALL_H
#define KYLIN_FIREWALL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ksc_public.h"

#define FIREWALL_CONF "/etc/kylin-firewall/kylin-firewall.conf"
#define ZONE_CONFDIR "/etc/kylin-firewall/zones/"
#define SERVICE_CONFDIR "/etc/kylin-firewall/services/"
#define CUSTOM_SERVICE_CONFDIR "/etc/kylin-firewall/custom_services/"
#define CUSTOM_SERVICE_CONFDIR_3TH "/etc/kylin-firewall/custom_services_3th/"

#define PUBLIC_ZONE 0
#define WORK_ZONE   1
#define CUSTOM_ZONE 2
#define TRUSTED_ZONE 3

enum custom_mode {
    SERVICE = 0,
    IPTABLES
};

/* 保存端口信息的链表 */
typedef struct P_Node {
    struct P_Node *next;
    char protocol[20];
    int port;
} P_Node;

typedef struct Service_P_Node {
    struct Service_P_Node *next;
    char protocol[20];
    char s_port[16];
} Service_P_Node;

typedef struct Service_Detail   {
    char service_name[256];
    char version[32];
    char short_cut[32];
    char description[1024];
    char uuid[256];
    Service_P_Node *ports;
}Service_Detail;

/* 存储iptables命令的链表 */

typedef struct C_Node {
    struct C_Node *next;
    char command[512];
    int state;
    /*
     * TODO: use enum replace this.
     * -1 - 不合法
     * 0  - 合法, 已执行
     * 1  - 合法, 执行失败
     */
}C_Node;

/*
 * 功能：设置当前防火墙网络区域
 * 参数：网络区域，取值范围为：0(PUBLIC_ZONE),1(WORK_ZONE),2(CUSTOM_ZONE),3(TRUSTED_ZONE)
 * 返回值：设置成功返回0， 设置失败返回-1
 */
int ksc_firewall_zone_set(int zone);

/*
 * 功能：从配置文件中获取当前防火墙网络区域
 * 返回值：获取成功返回0(PUBLIC_ZONE),1(WORK_ZONE),2(CUSTOM_ZONE),3(TRUSTED_ZONE)
 *        获取失败返回-1
 */
int ksc_firewall_zone_get();

/*
 * 功能：放行服务中保存的网络端口该接口只能在CUSTOM与WORK区域中使用
 *      WORK区域仅在初始化阶段使用,CUSTOM区域调用时会更新custom.xml
 * 参数：service为待放行的服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_enable(char *service);

/*
 * 功能：禁止服务中保存的网络端口,该接口只能在CUSTOM区域中使用
 * 参数：service为待禁止的服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_disable(char *service);

/*
 * 功能：获取服务详细信息
 * 参数：待功能：获取服务详细信息
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_get(int zone, char *service_name, Service_Detail *service);

/*
 * 功能：为服务添加管控规约、端口,该接口只能在CUSTOM区域中使用
 * 参数：服务名称、待添加规约、端口
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_add_protocol_port(char *service, Service_P_Node node);

/*
 * 功能：检查规约、端口是否已经存在,该接口只能在CUSTOM区域中使用
 * 参数：服务名称、待添加规约、端口
 * 返回值：规约、端口存在返回1，规约、端口不存在返回0，失败返回-1
 */
int ksc_firewall_service_check_protocol_port(char *service, Service_P_Node node);

/*
 * 功能：备份服务xml文件,该接口只能在CUSTOM区域中使用
 * 参数：服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_bakup(char *service);

/*
 * 功能：用备份xml文件恢复服务,该接口只能在CUSTOM区域中使用
 * 参数：服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_restore(char *service);

/*
 * 功能：删除备份xml文件,该接口只能在CUSTOM区域中使用
 * 参数：服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_remove_bakup(char *service);

/*
 * 功能：为服务删除指定索引的管控规约、端口,该接口只能在CUSTOM区域中使用
 * 参数：服务名称、待删除的索引
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_delete_node(char *service,int index);

/*
 * 功能：为服务删除所有的管控规约、端口,该接口只能在CUSTOM区域中使用
 * 参数：服务名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_service_delete_all_node(char *service);

void service_node_free(Service_P_Node *node);

/*
 * 功能：放行新端口,该接口只能在CUSTOM与WORK区域中使用
 *      WORK区域仅在初始化阶段使用
 * 参数：port结构体保存待添加的端口信息
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_port_add(P_Node port, int isCustom3th);

/*
 * 功能：删除已放行的端口,该接口只能在CUSTOM区域中使用
 * 参数：port结构体保存待添加的端口信息
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_port_delete(P_Node port, int isCustom3th);

void pnode_free(P_Node *node);

/*
 * 功能：放行协议,该接口只能在CUSTOM与WORK区域中使用
 *      WORK区域仅在初始化阶段使用
 * 参数：protocol为待放行协议名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_protocol_add(char *protocol, int isCustom3th);

/*
 * 功能：删除已放行的协议,该接口只能在CUSTOM区域中使用
 * 参数：protocol为待放行协议名称
 * 返回值：成功返回0，失败返回-1
 */
int ksc_firewall_protocol_delete(char *protocol, int isCustom3th);


/*
 * 功能: 校验服务是否已存在, 该接口只能在WORK、CUSTOM区域中使用
 * 参数: service 规约名称
 * 返回值:合法返回0,失败返回-1
 */
int ksc_firewall_service_check(int zone, char *service);

/*
 * 功能: 校验规约是否合法
 * 参数: protocol 规约名称
 * 返回值:合法返回0,失败返回-1
 */
int net_protocol_check(char *protocol);

/*
 * 功能: 校验规约是否可以添加端口进行管控
 * 参数: protocol 规约名称
 * 返回值:合法返回0,失败返回-1
 */
int net_port_protocol_check(char *protocol);

/**
 * 功能: 从xml获取所有iptables命令, 该接口只能在CUSTOM区域中使用 
 * 参数: commands [out] 指向保存命令信息的链表头节点, 头节点不保存命令信息
 * 返回值:成功返回命令数目, 失败返回-1
 * 注意: commands链表头节点内存由调用者分配并将next置空
 *      调用后统一使用cnode_free()接口释放内存
 */
int ksc_firewall_iptables_commands_get(C_Node *commands);

/**
 * 功能: 向xml中写入iptables命令, 该接口只能在CUSTOM区域中使用
 * 参数: commands [in] 指向保存命令信息的链表头节点, 头节点不保存命令信息
 * 返回值:成功返回0, 失败返回-1
 * 注意: node->state 将会改变.
 */
int ksc_firewall_iptables_commands_set(C_Node *commands);

void cnode_free(C_Node *commands);

/**
 * 功能: 获取CUSTOM区域应用的MODE, 该接口只能在CUSTOM区域中使用
 * 参数: mode [out] 正在生效的MODE值
 * 返回值:成功返回0, 失败返回-1
 */
int ksc_firewall_custom_mode_get(int *mode);

//3th custom
#define NOT_3TH_CUSTOM  0
#define IS_3TH_CUSTOM   1

int ksc_firewall_service_check_c3th(int zone, char *service);
int ksc_firewall_service_enable_c3th(char *service);
int ksc_firewall_service_disable_c3th(char *service);
int ksc_firewall_service_add_c3th(Service_Detail service);
int ksc_firewall_service_delete_c3th(char *service);
int ksc_firewall_service_add_protocol_port_c3th(char *service, Service_P_Node node);
int ksc_firewall_service_delete_protocol_port_c3th(char *service, Service_P_Node node);
int ksc_firewall_service_update_protocol_port_c3th(char *service, Service_P_Node node_old, Service_P_Node node_new);

#ifdef __cplusplus
}
#endif

#endif /* KYLIN_FIREWALL_H */
