#ifndef __SNMP_WALK_H__
#define __SNMP_WALK_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#define COLLIE_VERSION_1 "1.0"

#define LINUX_JSON_TYPE 1
#define GET_TYPE 2
#define WALK_TYPE 3
#define LINUX_PING_TYPE 4
#define DISK_TYPE 5
#define TCP_SHELL_TYPE 6

#define ERROR_INTASK_JSON -11  	//read task.conf line isn't json string
#define ERROR_INTASK_IP -12  	//task.conf line's ip is error
#define ERROR_INTASK_INT -13 	//task.conf line's intervals have error
#define ERROR_INTASK_PTID -14	//task.conf line's ptid have error
#define ERROR_INTASK_MID -15	//task.conf line's mid hava error
#define ERROR_INTASK_STATUS -16 //task.conf line's status hava error
#define ERROR_IP_ILLEGAL -17	//task.conf line's ip illegal

#define ERROR_INMIB_JSON -21
#define ERROR_INMIB_TYPE -22
#define ERROR_INMIB_MIB -23
#define ERROR_INMIB_OID -24

#define ERROR_GET_OPENFAILED -31
#define ERROR_GET_NETWORK -32
#define ERROR_GET_NOTSUPPORT -33
#define ERROR_GET_NOTJSON -34
#define ERROR_GET_UNINSTALL -35

#define READ_MAX_LEN 2048
#define COMMAND_MAX_LEN 256
#define FILE_MAX_LEN 256
#define MD5_RESULT_MAX 64
#define MD5_SIGNAL_LEN 1
#define IP_MAX_LEN 16
#define OID_MAX_LEN 64
#define INDEX_MAX_LEN 4

#define TASK_HEADER_V "V"
#define TASK_HEADER_IP "IP"
#define TASK_HEADER_TS "TS"
#define TASK_HEADER_MID "MID"
#define TASK_HEADER_INT "Intervals"
#define TASK_HEADER_STATUS "Status"

#define MIB_HEADER_TYPE "Type"
#define MIB_HEADER_MID "MID"
#define MIB_HEADER_NAME "Name"
#define MIB_HEADER_OID "Oid"

#define TASK_ERROR_FILE "error_task"

#define SLOT_NUM 29
#define OID_MAX_COUNT 16

typedef struct 
{
	char logstash_path[FILE_MAX_LEN];
	char task_conf[FILE_MAX_LEN];
	char mib_conf[FILE_MAX_LEN];
	char file_md5[MD5_RESULT_MAX];
	int threads;
	int log_level;
}sct_config_t;

typedef struct 
{
	char name[OID_MAX_LEN];
	char oid_val[OID_MAX_LEN];
}sct_oid_t;

typedef struct _hash_mibs_t
{
	int ptid;
	unsigned long keyid;
	sct_oid_t oid[OID_MAX_COUNT];
	int oid_count;
	int type;
	struct _hash_mibs_t *next;
}sct_hashset_t;

typedef struct item_list
{
	unsigned long nextcheck;
	int intervals;
	char ip_addr[IP_MAX_LEN];
	int ptid;
	unsigned long keyid;
	int index[256];
	int index_count;
	int type;
	int status;
	struct item_list *next;
} sct_item_list;

typedef struct
{
	sct_item_list *run_list;
	sct_item_list *bak_list;
	sct_item_list *err_list;
	sct_item_list *bakerr_list;
}sct_list_table;

typedef struct 
{
	sct_hashset_t **entry;
	int slot_num;
}sct_hashmap_table;

typedef struct 
{
	sct_list_table list;
	sct_hashmap_table hash;
	sct_config_t config;
}sct_all_table;

sct_item_list *sct_insert_item_list(sct_item_list *head, sct_item_list *add_node);
sct_hashset_t *sct_find_oid_hash(unsigned long  keyid, const sct_hashmap_table *mibs);
int sct_snmp_get_test(char *ip_addr, char *oid_str);
int sct_snmp_walk_index(sct_item_list *item, char *oid_str, int flag, sct_list_table *list);
int sct_get_task_md5(const char *file_path, char *md5_result);
int sct_init_item_list(sct_config_t *config, sct_list_table *list, sct_hashmap_table *mibs, int flag);
int sct_init(char *config_file, sct_config_t *config, sct_hashmap_table *mibs, sct_list_table *list);

#endif
