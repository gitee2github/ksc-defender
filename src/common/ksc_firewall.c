
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/xmlwriter.h>
#include <libxml2/libxml/tree.h>

#include "ksc_public.h"
#include "ksc_firewall.h"

#define KSC_FIRE_WALL_CUSTOM_FILE "/etc/kylin-firewall/zones/custom.xml"
#define KSC_FIRE_WALL_CUSTOM_3TH_FILE "/etc/kylin-firewall/zones/custom_3th.xml"
#define KSC_FIRE_WALL_KSC_IPTABLES_FILE "/etc/kylin-firewall/ksc-iptables.xml"

#include <locale.h>
#include <libintl.h>
#define _(STRING) gettext(STRING)

static void setenv_sbin()
{
    if (!getenv("PATH"))
    {
        setenv("PATH", "/sbin:/usr/sbin:/bin:/usr/bin", 0);
    }
}

int custom_iptables_cfg_create(char *version)
{
    xmlDocPtr doc;
    xmlNodePtr ksc_root;

    doc = xmlNewDoc(BAD_CAST(version));
    ksc_root = xmlNewNode(NULL, BAD_CAST("iptables_root"));
    xmlDocSetRootElement(doc, ksc_root);
    int retval = xmlSaveFile(KSC_FIRE_WALL_KSC_IPTABLES_FILE, doc);
    if(retval < 0)
    {
        ksc_perror("xmlSaveFileEnc /etc/kylin-firewall/ksc-iptables.xml failed,ret=%d\n",retval);
    }
    else
    {
        ksc_pinfo("xmlSaveFileEnc /etc/kylin-firewall/ksc-iptables.xml success,ret=%d\n",retval);
    }

    xmlFreeDoc(doc);
    return 0;
}

int ksc_firewall_zone_get()
{
    int ret = -1;
    FILE *fd = NULL;
    char buf[128];

    fd = fopen(FIREWALL_CONF, "r");
    if (NULL == fd)
    {
        perror("fopen failed");
        return ret;
    }

    while (fgets(buf, 128, fd) != NULL)
    {
        // ignore comment
        if (!strncmp(buf, "#", 1))
        {
            continue;
        }

        if (!strncmp(buf, "Zone", 4))
        {
            if (!strncmp(buf+5, "public", 6))
            {
                ret = PUBLIC_ZONE;
            }
            if (!strncmp(buf+5, "work", 4))
            {
                ret = WORK_ZONE;
            }
            if (!strncmp(buf+5, "custom", 6))
            {
                ret = CUSTOM_ZONE;
            }
            if (!strncmp(buf+5, "trusted", 7))
            {
                ret = TRUSTED_ZONE;
            }
        }
    }

    fclose(fd);
    return ret;
}

static int conf_file_zone_set(int zone)
{
    FILE *fd = NULL;
    long offset = 0;
    char buf[128];

    fd = fopen(FIREWALL_CONF, "r+");
    if (NULL == fd) {
        perror("fopen failed");
        return -1;
    }

    while (fgets(buf, 128, fd) != NULL)
    {
        if (!strncmp(buf, "Zone", 4))
        {
            fseek(fd, offset, SEEK_SET);
            switch (zone) {
                case PUBLIC_ZONE:
                    strncpy(buf+5, "public ", 8);
                    fputs(buf, fd);
                    break;
                case WORK_ZONE:
                    strncpy(buf+5, "work   ", 8);
                    fputs(buf, fd);
                    break;
                case CUSTOM_ZONE:
                    strncpy(buf+5, "custom ", 8);
                    fputs(buf, fd);
                    break;
                case TRUSTED_ZONE:
                    strncpy(buf+5, "trusted", 8);
                    fputs(buf, fd);
                    break;
                default:
                    fclose(fd);
                    return -1;
            }
        }
        offset = ftell(fd);
    }

    fclose(fd);
    return 0;
}

static int init_firewall_accept_all()
{
    int res = 0;

    setenv_sbin();

    res = system("iptables -P INPUT ACCEPT");
    if (res)
    {
        return -3;
    }

    res = system("iptables -P OUTPUT ACCEPT");
    if (res)
    {
        return -4;
    }

    res = system("iptables -P FORWARD ACCEPT");
    if (res)
    {
        return -5;
    }

    return 0;
}

static int init_firewall_rule()
{
    int res = 0;

    setenv_sbin();

    res = system("iptables -N INPUT_ZONES");
    res = system("iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT");
    res = system("iptables -A INPUT -i lo -j ACCEPT");
    res = system("iptables -A INPUT -j INPUT_ZONES");
    res = system("iptables -A INPUT -m conntrack --ctstate INVALID -j DROP");
    res = system("iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited");

    return 0;
}

static int remove_pre_zone_rule(int zone)
{
    char chain[16] = {0};
    int res = 0;
    char chaincmd1[64] = {0};
    char chaincmd2[64] = {0};

    switch (zone)
    {
        case TRUSTED_ZONE:
            return 0;
        case PUBLIC_ZONE:
            strncpy(chain, "IN_public", 16);
            break;
        case WORK_ZONE:
            strncpy(chain, "IN_work", 16);
            break;
        case CUSTOM_ZONE:
            strncpy(chain, "IN_custom", 16);
            break;
        default:
            return -1;
    }
    snprintf(chaincmd1, 64, "iptables -F %s 2> /dev/null", chain);
    snprintf(chaincmd2, 64, "iptables -X %s 2> /dev/null", chain);

    setenv_sbin();

    res = system(chaincmd1);
    res = system("iptables -F INPUT_ZONES 2> /dev/null");
    res = system("iptables -D INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2> /dev/null");
    res = system("iptables -D INPUT -i lo -j ACCEPT 2> /dev/null");
    res = system("iptables -D INPUT -j INPUT_ZONES 2> /dev/null");
    res = system("iptables -D INPUT -m conntrack --ctstate INVALID -j DROP 2> /dev/null");
    res = system("iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited 2> /dev/null");
    res = system("iptables -X INPUT_ZONES 2> /dev/null");
    res = system(chaincmd2);

    return 0;
}

static int custom_iptables_apply_rules()
{
    C_Node *pList = (C_Node *)calloc(1, sizeof(C_Node));
    pList->next = NULL;

    int ret = ksc_firewall_iptables_commands_get(pList);
    if (ret <= 0)
    {
        cnode_free(pList);
        return 0;
    }

    ret = ksc_firewall_iptables_commands_set(pList);
    if (ret != 0)
    {
        return -2;
    }

    cnode_free(pList);
    return 0;
}

static int custom_iptables_clear_rules()
{
    char cmd[512] = {0};
    C_Node *pList = (C_Node *)calloc(1, sizeof(C_Node));
    pList->next = NULL;

    int ret = ksc_firewall_iptables_commands_get(pList);
    if (ret <= 0)
    {
        cnode_free(pList);
        return 0;
    }

    C_Node *node = pList->next;
    while (node != NULL)
    {
        if (node->state != 0)
        {
            node = node->next;
            continue;
        }

        memset(cmd, 0x00, sizeof(cmd));
        strncpy(cmd, node->command, sizeof(cmd));
        node = node->next;

        char *p = strstr(cmd, "-I ");
        if (p)
        {
            p = p + 1;
            *p = 'D';
            printf("execute %s: ret=%d\n", cmd, system(cmd));
            ret = system(cmd);
            continue;
        }

        p = strstr(cmd, "-A ");
        if (p)
        {
            p = p + 1;
            *p = 'D';
            printf("execute %s: ret=%d\n", cmd, system(cmd));
            continue;
        }
    }

    return 0;
}

static int zone_apply_rules(int zone, int isCustom3th)
{
    int res = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    xmlChar *name = NULL;
    P_Node port;
    port.next = NULL;

    if (zone == WORK_ZONE)
    {
        path = "/etc/kylin-firewall/zones/work.xml";
    }
    else
    {
        if (isCustom3th)
        {
            path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
        }
        else
        {
            path = "/etc/kylin-firewall/zones/custom.xml";
        }
    }

    doc = xmlReadFile(path, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", path);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", path);
        res = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"service"))
        {
            name = xmlGetProp(node, (xmlChar *)"name");
            if (isCustom3th){
                res = ksc_firewall_service_enable_c3th((char *)name);
            }
            else
            {
                res = ksc_firewall_service_enable((char *)name);
            }
            if (res<0)
            {
                ksc_perror("failed to enable service: %s\n", name);
            }
        }

        if (!xmlStrcmp(node->name, (xmlChar *)"protocol"))
        {
            name = xmlGetProp(node, (xmlChar *)"name");
            res = ksc_firewall_protocol_add((char *)name, isCustom3th);
            if (res)
            {
                ksc_perror("failed to enable protocol: %s\n", name);
            }
        }

        if (!xmlStrcmp(node->name, (xmlChar *)"port"))
        {
            strncpy(port.protocol, (char *)xmlGetProp(node, (xmlChar *)"protocol"), 20);
            port.port = strtol((char *)xmlGetProp(node, (xmlChar *)"port"), NULL, 10);
            res = ksc_firewall_port_add(port, isCustom3th);
            if (res)
            {
                ksc_perror("failed to enable port: %d\n", port.port);
            }
        }

        node = node->next;
    }

out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return res;
}

static int firewall_rule_set(int zone)
{
    int ret = 0;
    char chain[16];
    char cmd[128];

    setenv_sbin();

    if (zone == TRUSTED_ZONE)
    {
        ret = init_firewall_accept_all();
        if (ret != 0)
        {
            ksc_perror("failed to init firewall rules accept all\n");
            return -1;
        }
    }
    else {
        int mode = 0;
        ksc_firewall_custom_mode_get(&mode);
        if (zone == CUSTOM_ZONE && mode == IPTABLES)
        {
            custom_iptables_apply_rules();
        }
        else
        {
            ret = init_firewall_rule();
            if (ret != 0) {
                ksc_perror("failed to init firewall rules\n");
                return -1;
            }

            switch (zone)
            {
                case PUBLIC_ZONE:
                    strncpy(chain, "IN_public", 16);
                    break;
                case WORK_ZONE:
                    strncpy(chain, "IN_work", 16);
                    break;
                case CUSTOM_ZONE:
                    strncpy(chain, "IN_custom", 16);
                    break;
                default:
                    return -1;
            }

            snprintf(cmd, 128, "iptables -N %s", chain);
            ret = system(cmd);

            snprintf(cmd, 128, "iptables -A INPUT_ZONES -j %s", chain);
            ret = system(cmd);

            snprintf(cmd, 128,
                     "iptables -A %s -j REJECT --reject-with icmp-host-prohibited", chain);
            ret = system(cmd);

            if (zone != PUBLIC_ZONE)
            {
                zone_apply_rules(zone, 0);
                if (zone == CUSTOM_ZONE)
                {   //3th custom
                   /*
                   zone_apply_rules(zone, IS_3TH_CUSTOM);
                   */
                }
            }
        }
    }

    return 0;
}

int ksc_firewall_zone_set(int zone)
{
    int ret = 0;

    switch (zone)
    {
        case PUBLIC_ZONE:
        case WORK_ZONE:
        case CUSTOM_ZONE:
        case TRUSTED_ZONE:
            break;    
        default:
            ksc_perror("invalid zone[%d]\n",zone);
            return -1;
    }

    int pre_zone = ksc_firewall_zone_get();
    if (pre_zone != -1)
    {
        int mode = SERVICE;
        ksc_firewall_custom_mode_get(&mode);
        if (zone == CUSTOM_ZONE && mode == IPTABLES)
        {
            ret = custom_iptables_clear_rules();
        }
        else
        {
            ret = remove_pre_zone_rule(pre_zone);
        }

        if (ret != 0)
        {
            ksc_perror("failed to remove prezone[%d:%d] rules \n", pre_zone, mode);
            return -1;
        }
    }

    ret = conf_file_zone_set(zone);
    if (ret != 0)
    {
        ksc_perror("failed to set zone[%d] to firewall.conf\n", zone);
        return -1;
    }

    ret = firewall_rule_set(zone);
    if (ret != 0)
    {
        ksc_perror("failed to set zone[%d] firewall rules\n", zone);
        if (pre_zone >= 0)         //还原当前zone
        {
            conf_file_zone_set(pre_zone);
        }
        return -1;
    }

    return 0;
}

static int tran_path_service(char *name, char *service)
{
    int l = 0;
    if (NULL == name)
    {
        ksc_perror("xml name error\n");
        return -1;
    }

    l = strlen(name);
    if (l < 5) /*name too short*/
    {
        return -1;
    }

    l -= 4;
    if (l > NAME_MAX) /*name too long*/
    {
        return -1;
    }
    /* not xml file */
    if (strncmp(name + l, ".xml", 4))
    {
        return -1;
    }

    strncpy(service, name, l);
    return 0;
}

/* FIXME: realize it with a smarter way */
int net_protocol_check(char *protocol)
{
    int i = 0;
    char *prot[56] = {"ip", "hopopt", "icmp", "igmp", "ggp",
      "ipencap", "st", "tcp", "egp", "igp", "pup", "udp", "hmp",
      "xns-idp", "rdp", "iso-tp4", "dccp", "xtp", "ddp", "idpr-cmtp",
      "ipv6", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre",
      "esp", "ah", "skip", "ipv6-icmp", "ipv6-nonxt", "ipv6-opts",
      "rspf", "vmtp", "eigrp", "ospf", "ax.25", "ipip", "etherip",
      "encap", "pim", "ipcomp", "vrrp", "l2tp", "isis", "sctp", "fc",
      "mobility-header", "udplite", "mpls-in-ip", "manet", "hip", "shim6",
      "wesp", "rohc"};

    if (NULL == protocol)
    {
        return -1;
    }

    for (i = 0; i < 55; i++)
    {
        if (!strncasecmp(protocol, prot[i], (size_t)16))
        {
            return 0;
        }
    }

    return -1;
}

static int tran_service_path(int zone, char *service, char *path, int isCustom3th)
{
    if (NULL == service)
    {
        ksc_perror("service name error\n");
        return -1;
    }

    if (CUSTOM_ZONE != zone && WORK_ZONE != zone)
    {
        ksc_perror("zone error\n");
        return -2;
    }

    if (WORK_ZONE == zone)
    {
        snprintf(path, PATH_MAX, "%s%s.xml", SERVICE_CONFDIR, service);
    }
    else
    {
        if (isCustom3th && zone!=CUSTOM_ZONE)
        {
            snprintf(path, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR_3TH, service);
        }
        else
        {
            snprintf(path, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);
        }

    }

    return 0;
}

static void P_Node_push_back(char *protocol, int port, P_Node *ports)
{
    if (protocol == NULL || ports == NULL)
    {
        return;
    }

    P_Node *pNewNode = (P_Node *)calloc(1, sizeof(P_Node));
    strncpy(pNewNode->protocol, protocol, sizeof(pNewNode->protocol) - 1);
    pNewNode->port = port;
    pNewNode->next = NULL;

    if (ports->next == NULL)
    {
        //链表没有节点的情况
        ports->next = pNewNode;
    }
    else
    {
        P_Node *pCur = ports->next;
        while (pCur->next)
        {
            pCur = pCur->next;
        }
        //让最后一个节点指向新节点
        pCur->next = pNewNode;
    }
}

static void parse_protocol_port(xmlChar *proto, xmlChar *port, P_Node *ports)
{
    if (proto == NULL)
    {
        return;
    }

    if (port == NULL)
    {
        P_Node_push_back((char *)proto, -1, ports);
    }
    else
    {
        if (NULL == strstr((char *)port, "-"))
        {
            P_Node_push_back((char *)proto, strtol((char *)port, NULL, 10), ports);
        }
        else
        {
            char tmp[32] = {0};
            memset(tmp, 0x00, sizeof(tmp));
            strncpy(tmp, (char *)port, sizeof(tmp) - 1);
            char *p = strtok(tmp, "-");
            int begin = strtol(p, NULL, 10);
            int end = begin;
            p = strtok(NULL, "-");
            if(p)
            {
                end = strtol(p, NULL, 10);
            }            
            for (int i = begin; i <= end; i++)
            {
                P_Node_push_back((char *)proto, i, ports);
            }
        }
    }
}

static int get_service_port(int zone, char *service, P_Node *ports, int isCustom3th)
{
    int ret = 0;
    char path[PATH_MAX];
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    xmlChar *proto = NULL, *port = NULL;

    if (NULL == ports)
    {
        ksc_perror("invalid input parameters\n");
        return -1;
    }

    ret = tran_service_path(zone, service, path, isCustom3th);
    if (ret != 0)
    {
        ksc_perror("failed to tranServicePath\n");
        return -1;
    }

    doc = xmlReadFile(path, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", path);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", path);
        ret = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"port"))
        {
            proto = xmlGetProp(node, (xmlChar *)"protocol");
            port = xmlGetProp(node, (xmlChar *)"port");
            if (proto)
            {
                parse_protocol_port(proto, port, ports);
            }
            xmlFree(proto);
            xmlFree(port);
        }
        node = node->next;
    }
out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return ret;
}

static int add_service(char *service, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, newnode;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }
    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }
    newnode = xmlNewNode(NULL, (xmlChar *)"service");
    xmlNewProp(newnode, (xmlChar *)"name", (xmlChar *)service);
    xmlAddChild(root_node, newnode);
    ret = xmlSaveFileEnc(path, doc, "utf-8");
    if(ret < 0)
    {
        ksc_perror("xmlSaveFileEnc failed,ret=%d\n",ret);
    }
    else
    {
        ksc_pinfo("xmlSaveFileEnc success,path=%s,ret=%d\n",path,ret);
    }

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return 0;
}

static int remove_service(char *service, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }
    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"service") &&
            !xmlStrcmp(xmlGetProp(node, (xmlChar *)"name"), (xmlChar *)service))
        {
            node->prev->next = node->next;
        }
        node = node->next;
    }
    xmlSaveFileEnc(path, doc, "utf-8");

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return ret;
}

void pnode_free(P_Node *node)
{
    P_Node *tmp = NULL;

    while (node->next != NULL)
    {
        tmp = node->next;
        node->next = tmp->next;
        free(tmp);
    }
    free(node);
}

int ksc_firewall_service_enable(char *service)
{
    int ret = 0, zone = 0, t = 0;
    char chain[16];
    char cmd[1024];
    P_Node *ports = NULL, *port = NULL;

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
    case WORK_ZONE:
        strncpy(chain, "IN_work", 16);
        break;
    case CUSTOM_ZONE:
        strncpy(chain, "IN_custom", 16);
        break;
    default:
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        return -1;
    }
    ksc_pinfo("disable %s\n",service);
    /* Disable service first , in case add redundant rules */
    ret = ksc_firewall_service_disable(service);

    /* apply iptables rules */
    ports = (P_Node *)calloc(1, sizeof(P_Node));
    if (NULL == ports)
    {
        ksc_perror("P_Node alloc error");
        return -1;
    }
    ports->next = NULL;
    ret = get_service_port(zone, service, ports, NOT_3TH_CUSTOM);
    if (ret != 0)
    {
        ksc_perror("failed to get_service_port: %s\n", service);
        ret = -1;
        goto out;
    }
    port = ports->next;
    while (port != NULL)
    {
        if (port->port >= 0)
        {
            snprintf(cmd, 1024, "iptables -I %s 1 -p %s --dport %d -j ACCEPT",
                        chain, port->protocol, port->port);
        }
        else
        {
            snprintf(cmd, 1024, "iptables -I %s 1 -p %s -j ACCEPT",
                        chain, port->protocol);
        }
        t = system(cmd);
        port = port->next;
    }

    /* write service to zones/custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        ksc_pinfo("add %s\n",service);
        ret = add_service(service, NOT_3TH_CUSTOM);
        if (ret < 0)
        {
            ksc_perror("failed to add_service: %s\n", service);
            ret = -1;
            goto out;
        }
    }

out:
    pnode_free(ports);
    return ret;
}

int ksc_firewall_service_disable(char *service)
{
    int ret = 0, zone = 0, t = 0;
    char chain[16];
    char cmd[1024];
    P_Node *ports = NULL, *port = NULL;

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
    case WORK_ZONE:
        strncpy(chain, "IN_work", 16);
        break;
    case CUSTOM_ZONE:
        strncpy(chain, "IN_custom", 16);
        break;
    default:
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        return -1;
    }
    /* remove iptables rules */
    ports = (P_Node *)calloc(1, sizeof(P_Node));
    if (NULL == ports)
    {
        perror("P_Node alloc error");
        return -1;
    }
    ports->next = NULL;
    ret = get_service_port(zone, service, ports, NOT_3TH_CUSTOM);
    if (ret != 0)
    {
        ksc_perror("failed to get_service_port: %s\n", service);
        ret = -1;
        goto out;
    }
    port = ports->next;
    while (port != NULL)
    {
        if (port->port >= 0)
         {
            snprintf(cmd, 1024, "iptables -D %s -p %s --dport %d -j ACCEPT 2> /dev/null",
                     chain, port->protocol, port->port);
        }
        else
        {
            snprintf(cmd, 1024, "iptables -D %s -p %s -j ACCEPT 2> /dev/null",
                     chain, port->protocol);
        }

        do
        {
            t = system(cmd);
//            printf ("cmd = %s, t = %d\n", cmd, t);
        }while (!t);
        port = port->next;
    }

    /* remove service from zones/custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        ret = remove_service(service, NOT_3TH_CUSTOM);
        if (ret != 0)
        {
            ksc_perror("failed to add_service: %s\n", service);
            ret = -1;
            goto out;
        }
    }

out:
    pnode_free(ports);
    return ret;
}

int net_port_protocol_check(char *protocol)
{
    if (NULL == protocol)
    {
        return -1;
    }
    if (!strncmp(protocol, "udp", (size_t)4) ||
        !strncmp(protocol, "tcp", (size_t)4) ||
        !strncmp(protocol, "sctp", (size_t)5) ||
        !strncmp(protocol, "dccp", (size_t)5))
    {
        return 0;
    }

    return -1;
}

static int save_port(P_Node port, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    char p[6];
    xmlDocPtr doc;
    xmlNodePtr root_node, newnode;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }

    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }
    newnode = xmlNewNode(NULL, (xmlChar *)"port");
    xmlNewProp(newnode, (xmlChar *)"protocol", (xmlChar *)port.protocol);
    snprintf(p, 6, "%d", port.port);
    xmlNewProp(newnode, (xmlChar *)"port", (xmlChar *)p);
    xmlAddChild(root_node, newnode);
    xmlSaveFileEnc(path, doc, "utf-8");

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return ret;
}

int ksc_firewall_port_add(P_Node port, int isCustom3th)
{
    int res = 0, zone = 0;
    char *chain = NULL;
    char cmd[256];

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
    case CUSTOM_ZONE:
        chain = "IN_custom";        
        break;
    case WORK_ZONE:
        chain = "IN_work";
        break;
    default:
        ksc_perror("Zone[%d] not support add port\n", zone);
        return -1;
    }

    /* parameter check */
    res = net_port_protocol_check(port.protocol);
    if (res) {
        ksc_perror("Protocol[%s] not support port\n", port.protocol);
        return -1;
    }
    if (port.port > 65535 || port.port < 0)
    {
        ksc_perror("Port[%d] out of range\n", port.port);
        return -1;
    }

    res = ksc_firewall_port_delete(port, isCustom3th);

    if(chain == NULL)
    {
        return -1;
    }
    /* apply iptables rule */
    snprintf(cmd, 256, "iptables -I %s 1 -p %s --dport %d -j ACCEPT",
                chain, port.protocol, port.port);
    res = system(cmd);

    /* save to custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        res = save_port(port, isCustom3th);
        if (res)
        {
            ksc_perror("failed to save [%s:%d]\n", port.protocol, port.port);
            return -1;
        }
    }

    return 0;
}

static int delete_port(P_Node port, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }

    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"port") &&
            !xmlStrcmp(xmlGetProp(node, (xmlChar *)"protocol"), (xmlChar *)port.protocol) &&
            strtol((char *)xmlGetProp(node, (xmlChar *)"port"), NULL, 10) == port.port)
        {
            node->prev->next = node->next;
        }
        node = node->next;
    }
    xmlSaveFileEnc(path, doc, "utf-8");

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return ret;
}

int ksc_firewall_port_delete(P_Node port, int isCustom3th)
{
    int res = 0, zone = 0;
    char *chain = NULL;
    char cmd[256];

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
    case WORK_ZONE:
        chain = "IN_work";
        break;
    case CUSTOM_ZONE:
        chain = "IN_custom";
        break;
    default:
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    /* parameter check */
    res = net_port_protocol_check(port.protocol);
    if (res)
    {
        ksc_perror("%s: not support port\n", port.protocol);
        return -1;
    }
    if (port.port > 65535 || port.port < 0)
    {
        ksc_perror("%s: invalid port[%d]\n", port.protocol, port.port);
        return -1;
    }

    if(chain == NULL)
    {
        return -1;
    }

    /* apply iptables rule */
    snprintf(cmd, 256,
        "iptables -D %s -p %s --dport %d -j ACCEPT 2> /dev/null",
            chain, port.protocol, port.port);
    do
    {
        res = system(cmd);
    } while (!res);

    /* delete from custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        res = delete_port(port, isCustom3th);
        if (res)
        {
            ksc_perror("faild to delete protocol[%s] port[%d]\n", port.protocol, port.port);
            return -1;
        }
    }

    return 0;
}

static int save_protocol(char *protocol, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, newnode;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }
    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("Failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }
    newnode = xmlNewNode(NULL, (xmlChar *)"protocol");
    xmlNewProp(newnode, (xmlChar *)"name", (xmlChar *)protocol);
    xmlAddChild(root_node, newnode);
    xmlSaveFileEnc(path, doc, "utf-8");

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return ret;
}

int ksc_firewall_protocol_add(char *protocol, int isCustom3th)
{
    int res = 0, zone = 0;
    char *chain = NULL;
    char cmd[256];

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
    case WORK_ZONE:
        chain = "IN_work";        
        break;
    case CUSTOM_ZONE:
        chain = "IN_custom";
        break;    
    default:
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    /* parameter check */
    res = net_protocol_check(protocol);
    if (res)
    {
        ksc_perror("invalid protocol: %s\n", protocol);
        return -1;
    }

    res = ksc_firewall_protocol_delete(protocol, isCustom3th);

    if(chain == NULL)
    {
         return -1;
    }
    /* apply iptables rule */
    snprintf(cmd, 256, "iptables -I %s 1 -p %s -j ACCEPT", chain, protocol);
    res = system(cmd);

    /* save to custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        res = save_protocol(protocol, isCustom3th);
        if (res)
        {
            ksc_perror("failed to save protocol: %s\n", protocol);
            return -1;
        }
    }

    return 0;
}

static int delete_protocol(char *protocol, int isCustom3th)
{
    int ret = 0;
    char *path = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;

    if (isCustom3th)
    {
        path = KSC_FIRE_WALL_CUSTOM_3TH_FILE;
    }
    else
    {
        path = KSC_FIRE_WALL_CUSTOM_FILE;
    }

    doc = xmlParseFile(path);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"protocol") &&
            !xmlStrcmp(xmlGetProp(node, (xmlChar *)"name"), (xmlChar *)protocol))
        {
            node->prev->next = node->next;
        }
        node = node->next;
    }
    xmlSaveFileEnc(path, doc, "utf-8");

out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump(); 
    return ret;
}

int ksc_firewall_protocol_delete(char *protocol, int isCustom3th)
{
    int res = 0, zone = 0;
    char *chain = NULL;
    char cmd[256];

    setenv_sbin();

    zone = ksc_firewall_zone_get();
    switch (zone)
    {
        case WORK_ZONE:
            chain = "IN_work";
            break;
        case CUSTOM_ZONE:
            chain = "IN_custom";
            break;
        default:
            ksc_pinfo("error zone[%d]\n", zone);
            return -1;
    }

    /* parameter check */
    res = net_protocol_check(protocol);
    if (res)
    {
        ksc_perror("invalid protocol: %s\n", protocol);
        return -1;
    }

    if(chain == NULL)
    {
        return -1;
    }

    /* apply iptables rule */
    snprintf(cmd, 256,
      "iptables -D %s -p %s -j ACCEPT 2> /dev/null", chain, protocol);
    do
    {
        res = system(cmd);
    }
    while (!res);

    /* delete protocol from custom.xml */
    if (zone == CUSTOM_ZONE)
    {
        res = delete_protocol(protocol, isCustom3th);
        if (res)
        {
            ksc_perror("failed to delete protocol: %s\n", protocol);
            return -1;
        }
    }

    return 0;
}

int ksc_firewall_service_get(int zone, char* service_name, Service_Detail *service)
{
    int ret = 0;
    char path[PATH_MAX];
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    xmlChar *proto = NULL, *port = NULL, *short_cut = NULL, *version = NULL, *description = NULL;
    Service_P_Node *newPort = NULL;

    if (service_name == NULL || service == NULL || service->ports == NULL)
    {
        ksc_perror("invalid input parameter\n");
        return -1;
    }

    if (zone == CUSTOM_ZONE)
    {
        if (ksc_firewall_service_check(zone, service_name) == 0)
        {
            ret = tran_service_path(zone, service_name, path, 1);
        }
        else
        {
            ret = tran_service_path(zone, service_name, path, 0);
        }
    }
    else
    {
        ret = tran_service_path(zone, service_name, path, 0);
    }

    if (ret != 0)
    {
        ksc_perror("failed to tranServicePath\n");
        return -1;
    }

    doc = xmlReadFile(path, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", path);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", path);
        ret = -1;
        goto out;
    }

    newPort = service->ports;
    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"port"))
        {
            Service_P_Node* p_node = (Service_P_Node *)calloc(1, sizeof(Service_P_Node));
            if (NULL == p_node)
            {
                perror("P_Node alloc failed");
                ret = -1;
                goto out;
            }
            proto = xmlGetProp(node, (xmlChar *)"protocol");
            port = xmlGetProp(node, (xmlChar *)"port");
            if (proto)
            {
                strncpy(p_node->protocol, (char *)proto, sizeof(p_node->protocol));
            }
            if (port)
            {
                 strncpy(p_node->s_port, (char *)port, sizeof(p_node->s_port));
            }

            p_node->next = NULL;
            newPort->next = p_node;
            newPort = p_node;

            xmlFree(proto);
            xmlFree(port);
        }

        if (!xmlStrcmp(node->name, (xmlChar *)"short"))
        {
            short_cut = xmlNodeGetContent(node);
            if (short_cut)
            {
                strncpy(service->short_cut, (char *)short_cut, sizeof(service->short_cut));
            }
            xmlFree(short_cut);
        }

        if (!xmlStrcmp(node->name, (xmlChar *)"version"))
        {
            version = xmlNodeGetContent(node);
            if (version)
            {
                strncpy(service->version, (char *)version, sizeof(service->version));
            }
            xmlFree(version);
        }

        if (!xmlStrcmp(node->name, (xmlChar *)"description"))
        {
            description = xmlNodeGetContent(node);
            if (description)
            {
                strncpy(service->description, (char *)description, sizeof(service->description));
            }
            xmlFree(description);
        }

        node = node->next;
    }

    strncpy(service->service_name, service_name, sizeof(service->service_name));
out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return ret;
}

int ksc_firewall_service_check_protocol_port(char *service, Service_P_Node node)
{
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        ksc_perror("invalid service[%s]\n", service);
        return -1;
    }

    char xmlfile[PATH_MAX] = {0};
    char protocol[20] = {0}, s_port[16] = {0};
    int ret = 0;
    xmlChar *proto = NULL, *xml_port = NULL;

    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);

    if (access(xmlfile, F_OK) != 0)
    {
        ksc_perror("failed to find service configure file: %s\n", xmlfile);
        return -1;
    }

    xmlKeepBlanksDefault(0);//libxml2 global variable .
    xmlIndentTreeOutput = 1;// indent .with \n

    xmlDocPtr doc;
    xmlNodePtr root_node, xml_node;

    doc = xmlReadFile(xmlfile, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", xmlfile);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node) {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", xmlfile);
        ret = -1;
        goto out;
    }

    xml_node = root_node->children;
    while (xml_node != NULL)
    {
        if (!xmlStrcmp(xml_node->name, (xmlChar *)"port"))
        {
            memset(protocol, 0x00, sizeof(protocol));
            memset(s_port, 0x00, sizeof(s_port));

            proto = xmlGetProp(xml_node, (xmlChar *)"protocol");
            xml_port = xmlGetProp(xml_node, (xmlChar *)"port");
            if (proto)
            {
                strncpy(protocol, (char *)proto, sizeof(protocol));
            }
            if (xml_port)
            {
                strncpy(s_port, (char *)xml_port, sizeof(s_port));
            }

            xmlFree(proto);
            xmlFree(xml_port);

            if (strcmp(protocol, node.protocol) == 0 && strcmp(s_port, node.s_port) == 0)
            {
                ret = 1;/*find same protocol and port*/
                break;
            }
        }

        xml_node = xml_node->next;
    }

out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return ret;
}

int ksc_firewall_service_add_protocol_port(char *service, Service_P_Node node)
{
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        ksc_perror("invalid service[%s]\n", service);
        return -1;
    }

    char xmlfile[PATH_MAX] = {0};

    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);

    ksc_firewall_service_disable(service);
    if (access(xmlfile, F_OK) != 0)
    {
        ksc_perror("failed to find service configure file: %s\n", xmlfile);
        return -1;
    }

    xmlKeepBlanksDefault(0);//libxml2 global variable .
    xmlIndentTreeOutput = 1;// indent .with \n

    xmlDocPtr doc;
    xmlNodePtr root_node, xml_node;
    int ret = 0;

    doc = xmlReadFile(xmlfile, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", xmlfile);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", xmlfile);
        ret = -1;
        goto out;
    }

    xml_node = xmlNewChild(root_node, NULL, BAD_CAST "port", BAD_CAST "");
    xmlNewProp(xml_node, (xmlChar *)"protocol", (xmlChar *)node.protocol);
    if (strlen(node.s_port) > 0)
    {
        xmlNewProp(xml_node, (xmlChar *)"port", (xmlChar *)node.s_port);
    }

    ret = xmlSaveFormatFile(xmlfile, doc, 1);
    if(ret<0)
    {
        ksc_perror("xmlSaveFormatFile failed,ret=%d\n",ret);
    }
out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
    return ret;
}

static int file_copy(char *in_fname,char *out_fname)
{
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    unsigned char copy_buf[4096];
    unsigned int  read_count = 0, write_count = 0;
   
    if(0 == in_fname || NULL == out_fname)
    {
        ksc_perror(" in_fname out_fname NULL\n");
        return -1;
    }

    in_file = fopen((const char *)in_fname, "rb");
    if (in_file == NULL)
    {
        ksc_perror(" fopen failed, in_fname=%s, errno=%s!\n", in_fname, strerror(errno));
        return -1;
    }

    out_file = fopen((const char *)out_fname,"wb");
    if (out_file == NULL)
    {
        ksc_perror(" fopen failed, out_fname=%s, errno=%s!\n", out_fname, strerror(errno));
        fclose(in_file);
        return -1;
    }

    while (!feof(in_file))
    {
        read_count = fread(copy_buf, 1, 4096,in_file);

        if (read_count > 0)
        {
            write_count = fwrite(copy_buf,1,read_count,out_file);
            if (write_count < read_count)
            {
                fclose(in_file);
                fclose(out_file);
                ksc_perror(" fwrite failed, errno=%s!\n", strerror(errno));
                return -1;
            }
        }
        else if ((0 == read_count) && (0 == feof(in_file)))
        {
            /*read failure and do not at end of file*/
            fclose(in_file);
            fclose(out_file);
            ksc_perror(" read_count is 0 error!!\n");
            return -1;
        }
    }

    fclose(in_file);
    fclose(out_file);
    ksc_pinfo("Copy %s to %s success\n",in_fname,out_fname);
    return 0;
}

int ksc_firewall_service_bakup(char *service)
{
    char xmlfile[PATH_MAX] = {0};
    char bakupxmlfile[PATH_MAX] = {0};
    int ret = 0;
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }
    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);
    snprintf(bakupxmlfile, PATH_MAX, "%s%s_bakup.xml", CUSTOM_SERVICE_CONFDIR, service);
    ret = file_copy(xmlfile,bakupxmlfile);
    if(ret)
    {
        ksc_perror("filecopy %s failed,ret=%d\n",xmlfile,ret);
        return -1;
    }
    ksc_pinfo("Bakup %s success\n",xmlfile);
    return 0;
}

int ksc_firewall_service_restore(char *service)
{
    char xmlfile[PATH_MAX] = {0};
    char bakupxmlfile[PATH_MAX] = {0};
    int ret = 0;
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }
    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);
    snprintf(bakupxmlfile, PATH_MAX, "%s%s_bakup.xml", CUSTOM_SERVICE_CONFDIR, service);

    ret = file_copy(bakupxmlfile,xmlfile);
    if(ret)
    {
        ksc_perror("Restore %s failed,ret=%d\n",xmlfile,ret);
        return -1;
    }  
    ksc_pinfo("Restore %s success\n",xmlfile);
    return 0;
}

int ksc_firewall_service_remove_bakup(char *service)
{
    char bakupxmlfile[PATH_MAX] = {0};
    int ret = 0;
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }
    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }
    snprintf(bakupxmlfile, PATH_MAX, "%s%s_bakup.xml", CUSTOM_SERVICE_CONFDIR, service);

    ret = unlink(bakupxmlfile);
    if(ret)
    {
        ksc_perror("Unlink %s failed,errno=%s\n",bakupxmlfile,strerror(errno));
        return -1;
    }
    ksc_pinfo("Unlink %s success\n",bakupxmlfile);
    return 0;
}

int ksc_firewall_service_delete_all_node(char *service)
{
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        ksc_perror("invalid service[%s]\n", service);
        return -1;
    }

    char xmlfile[PATH_MAX] = {0};
    int ret = 0;

    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);

    ksc_firewall_service_disable(service);
    if (access(xmlfile, F_OK) != 0)
    {
        ksc_perror("failed to find service configure file: %s\n", xmlfile);
        return -1;
    }

    xmlKeepBlanksDefault(0);//libxml2 global variable .
    xmlIndentTreeOutput = 1;// indent .with \n

    xmlDocPtr doc;
    xmlNodePtr root_node, xml_node, node_to_del;

    doc = xmlReadFile(xmlfile, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", xmlfile);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", xmlfile);
        ret = -1;
        goto out;
    }

    xml_node = root_node->children;
    while (xml_node != NULL)
    {
        if (!xmlStrcmp(xml_node->name, (xmlChar *)"port")){
            node_to_del = xml_node;
            xml_node = xml_node->next;
            xmlUnlinkNode(node_to_del);
            xmlFreeNode(node_to_del);
        }
        else
        {
            xml_node = xml_node->next;
        }
    }

    ret = xmlSaveFormatFile(xmlfile, doc, 1);
out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
    return ret;
}

int ksc_firewall_service_delete_node(char *service,int index)
{
    if(NULL == service)
    {
        ksc_perror("invalid para\n");
        return -1;
    }

    int zone = ksc_firewall_zone_get();
    if (CUSTOM_ZONE != zone)
    {
        ksc_perror("invalid zone[%d]\n", zone);
        return -1;
    }

    if (ksc_firewall_service_check(zone, service) == 0)
    {
        ksc_perror("invalid service[%s]\n", service);
        return -1;
    }

    char xmlfile[PATH_MAX] = {0};
    int ret = 0,service_index = 0;

    snprintf(xmlfile, PATH_MAX, "%s%s.xml", CUSTOM_SERVICE_CONFDIR, service);

    ksc_firewall_service_disable(service);
    if (access(xmlfile, F_OK) != 0)
    {
        ksc_perror("failed to find service configure file: %s\n", xmlfile);
        return -1;
    }

    xmlKeepBlanksDefault(0);//libxml2 global variable .
    xmlIndentTreeOutput = 1;// indent .with \n

    xmlDocPtr doc;
    xmlNodePtr root_node, xml_node, node_to_del;

    doc = xmlReadFile(xmlfile, "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlReadFile: %s\n", xmlfile);
        return -1;
    }
    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", xmlfile);
        ret = -1;
        goto out;
    }

    int found_node_flag = 0;

    xml_node = root_node->children;
    while (xml_node != NULL)
    {
        if (!xmlStrcmp(xml_node->name, (xmlChar *)"port"))
        {
            service_index++;
            if(service_index == index)
            {
                node_to_del = xml_node;
                xmlUnlinkNode(node_to_del);
                xmlFreeNode(node_to_del);
                found_node_flag = 1;
                break;
            }
        }

        xml_node = xml_node->next;
    }

    ret = xmlSaveFormatFile(xmlfile, doc, 1);
out:
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlMemoryDump();
    
    if(ret < 0)
    {
        ksc_perror("xmlSaveFormatFile failed,ret=%d\n",ret);
        return -1;
    }

    if(found_node_flag)
    {
        return 0;
    }
    else
    {
        /*not found node*/
        return 1;
    }
}

void service_node_free(Service_P_Node *node)
{
    Service_P_Node *tmp = NULL;
    if (NULL == node)
    {
        return;
    }

    while (node->next != NULL)
    {
        tmp = node->next;
        node->next = tmp->next;
        free(tmp);
        tmp = NULL;
    }
    free(node);
    //node = NULL;
}

int ksc_firewall_service_check(int zone, char *service)
{
    DIR *dp = NULL;
    struct dirent *dirp;
    int i = 0;
    char service_name[NAME_MAX] = {0};
    char *p = NULL;
    int exist = 0;

    if (zone != CUSTOM_ZONE && zone != WORK_ZONE)
    {
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    if (zone == WORK_ZONE)
    {
        dp = opendir(SERVICE_CONFDIR);
    }
    else
    {
        dp = opendir(CUSTOM_SERVICE_CONFDIR);
    }

    if (dp == NULL)
    {
        ksc_perror("opendir failed\n");
        return -2;
    }

    for (i = 0; (dirp = readdir(dp)) != NULL; i++)
    {
        /* ignore hidden files and . .. directory */
        if (!strncmp(dirp->d_name, ".", 1))
        {
            continue;
        }

        memset(service_name, 0x00, sizeof(service_name));
        strncpy(service_name, dirp->d_name, sizeof(service_name));

        p = strrchr(service_name, '.');
        if (NULL == p)
        {
            continue;
        }

        *p = '\0';
        ksc_pinfo("service=%s,service_name=%s\n",service,service_name);
        if (strcmp(service, service_name) == 0)
        {
            exist = 1;
            break;
        }
    }

    closedir(dp);
    return exist;
}

//3th custom
int ksc_firewall_service_check_c3th(int zone, char *service)
{
    /*add thirdparty firewall code*/   
    return 0;
}

int ksc_firewall_service_enable_c3th(char *service)
{
    /*add thirdparty firewall code*/   
    return 0;  
}

int ksc_firewall_service_disable_c3th(char *service)
{
    /*add thirdparty firewall code*/   
    return 0;
}

int ksc_firewall_service_add_c3th(Service_Detail service)
{
    /*add thirdparty firewall code*/   
    return 0;    
}

int ksc_firewall_service_delete_c3th(char *service)
{  
    /*add thirdparty firewall code*/   
    return 0;
}

int ksc_firewall_service_add_protocol_port_c3th(char *service, Service_P_Node node)
{
    /*add thirdparty firewall code*/   
    return 0;
}

int ksc_firewall_service_delete_protocol_port_c3th(char *service, Service_P_Node node)
{   
    /*add thirdparty firewall code*/   
    return 0;
}

int ksc_firewall_service_update_protocol_port_c3th(char *service, Service_P_Node node_old, Service_P_Node node_new)
{
    /*add thirdparty firewall code*/   
    return 0;
}

/**
 * 功能: 从xml获取所有iptables命令, 该接口只能在CUSTOM区域中使用 
 * 参数: commands [out] 指向保存命令信息的链表头节点, 头节点不保存命令信息
 * 返回值:成功返回命令数目, 失败返回-1
 * 注意: commands链表头节点内存由调用者分配并将next置空
 *      调用后统一使用cnodeFree()接口释放内存
 */
int ksc_firewall_iptables_commands_get(C_Node *commands)
{
    int count = 0, zone = 0;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    C_Node *new_command = NULL, *cmd = commands;

    /* Check input */
    if (NULL == cmd)
    {
        fprintf(stderr, "Invalid parameters!\n");
        return -1;
    }

    /* Ensure in custom zone */
    zone = ksc_firewall_zone_get();
    if (zone != CUSTOM_ZONE)
    {
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }    

    /* Parse XML file */
    doc = xmlReadFile(KSC_FIRE_WALL_KSC_IPTABLES_FILE,
                            "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_KSC_IPTABLES_FILE);
        return 0;
    }

    root_node = xmlDocGetRootElement(doc);  
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement\n");
        count = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"cmd"))
        {
            new_command = (C_Node *)calloc(1, sizeof(C_Node));
            strncpy(new_command->command, (char *)xmlGetProp(node, (xmlChar *)"name"), 256);
            new_command->state = strtol((char *)xmlGetProp(node, (xmlChar *)"state"), NULL, 10);
            new_command->next = NULL;
            cmd->next = new_command;
            cmd = cmd->next;
            count += 1;
        }
        node = node->next;
    }

out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    return count;
}

static int ksc_firewall_iptables_commands_conf_set(C_Node *commands)
{
    C_Node *node = NULL;
    xmlDocPtr doc;
    xmlNodePtr root_node, new_node;
    char state[10];

    remove(KSC_FIRE_WALL_KSC_IPTABLES_FILE);
    custom_iptables_cfg_create("1.0");

    /* Parse XML file*/
    /* Replace XML_PARSE_RECOVER with XML_PARSE_NOBLANKS, otherwise "\n" will miss between every added node.
     * doc = xmlReadFile(KSC_FIRE_WALL_KSC_IPTABLES_FILE,
     *                      "utf-8", XML_PARSE_NOBLANKS);
     */
    doc = xmlReadFile(KSC_FIRE_WALL_KSC_IPTABLES_FILE,
                            "utf-8", XML_PARSE_NOBLANKS);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_KSC_IPTABLES_FILE);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement\n");
        goto out;
    }

    /* Try to execute current command */
    node = commands->next;
    while (NULL != node)
    {
        new_node = xmlNewNode(NULL, BAD_CAST "cmd");
        xmlNewProp(new_node, BAD_CAST "name", BAD_CAST node->command);
        printf("\nCMD is %s, state is %d\n", node->command, node->state);
        memset(state, 0x00, sizeof(state));
        snprintf(state, sizeof(state),"%d", node->state);
        xmlSetProp(new_node, BAD_CAST "state", BAD_CAST state);
        xmlAddChild(root_node, new_node);
        node = node->next;
    }

    /* Same as the reason above - keep "\n"
     * xmlSaveFileEnc(KSC_FIRE_WALL_KSC_IPTABLES_FILE, doc, "utf-8");
     */
    xmlSaveFormatFileEnc(KSC_FIRE_WALL_KSC_IPTABLES_FILE, doc, "utf-8", 1);

out:
    xmlCleanupParser();
    xmlFreeDoc(doc);
    xmlMemoryDump();

    return 0;
}

/**
 * 功能: 清空并向xml中写入iptables命令, 该接口只能在CUSTOM区域中使用
 * 参数: commands [in] 指向保存命令信息的链表头节点, 头节点不保存命令信息
 * 返回值:成功返回0, 失败返回-1
 * 注意: node->state 将会改变.
 */
int ksc_firewall_iptables_commands_set(C_Node *commands)
{
    /* Check input */
    if (NULL == commands)
    {
        printf("Invalid parameters!\n");
        return -1;
    }

    /* Ensure in proper zone and mode */
    int mode = 0;
    int ret = ksc_firewall_custom_mode_get(&mode);
    if (IPTABLES != mode)
    {
        printf("Bad zond and mode!");
        return -1;
    }

    ret = custom_iptables_clear_rules();
    if (ret != 0)
    {
        ksc_perror("failed to clear custom iptables rules\n");
        return -2;
    }

    C_Node *node = commands->next;
    while (node)
    {
        if (strncmp(node->command, "iptables ", strlen("iptables ")) != 0)
        {
            node->state = -1;
            node = node->next;
            continue;
        }

        ret = system(node->command);
        if (ret != 0)
        {
            node->state = 1;
        }
        else
        {
            node->state = 0;
        }

        node = node->next;
        continue;
    }

    ret = ksc_firewall_iptables_commands_conf_set(commands);
    if (ret != 0)
    {
        ksc_perror("failed to set custom conf iptables rules\n");
        return -2;
    }

    return 0;
}

void cnode_free(C_Node *commands)
{
    C_Node *tmp = NULL;

    while (commands->next != NULL) 
    {
        tmp = commands->next;
        commands->next = tmp->next;
        free(tmp);
    }
    if (commands) {
        free(commands);
    }
    
}

/**
 * 功能: 获取CUSTOM区域应用的MODE, 该接口只能在CUSTOM区域中使用
 * 参数: mode [out] 正在生效的MODE值
 * 返回值:成功返回0, 失败返回-1
 */
int ksc_firewall_custom_mode_get(int *mode)
{
    int ret = -1, zone = 0;
    xmlDocPtr doc;
    xmlNodePtr root_node, node;
    xmlChar *mode_str = NULL;

    if (NULL == mode)
    {
        printf("Invalid parameters!\n");
        return -1;
    }

    /* Ensure in custom zone */
    zone = ksc_firewall_zone_get();
    if (zone != CUSTOM_ZONE)
    {
        ksc_pinfo("error zone[%d]\n", zone);
        return -1;
    }

    /* Parse XML file */
    doc = xmlReadFile(KSC_FIRE_WALL_CUSTOM_FILE,
                            "utf-8", XML_PARSE_RECOVER);
    if (NULL == doc)
    {
        ksc_perror("failed to xmlParseFile: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    if (NULL == root_node)
    {
        ksc_perror("failed to xmlDocGetRootElement: %s\n", KSC_FIRE_WALL_CUSTOM_FILE);
        ret = -1;
        goto out;
    }

    node = root_node->children;
    while (node != NULL)
    {
        if (!xmlStrcmp(node->name, (xmlChar *)"mode"))
        {
            mode_str = xmlNodeGetContent(node);
            if (mode_str)
            {
                if (!strcmp((char *)mode_str, "service"))
                {
                    (*mode) = SERVICE;
                    ret = 0;
                }
                else if (!strcmp((char *)mode_str, "iptables"))
                {
                    (*mode) = IPTABLES;
                    ret = 0;
                } 
            }
            xmlFree(mode_str);
            break;
        }
        node = node->next;
    }

out:
    xmlCleanupParser();
    xmlFreeDoc(doc);

    return 0;
}
