#ifndef __SNMP_LIST_H__
#define __SNMP_LIST_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

#include "json.h"

#include "init.h"
#include "snmp_collect.h"

#define ISARRIVE_STR_LEN 8

#define ISARRIVE_TRUE "true"
#define ISARRIVE_FALSE "false"

#define DATA_HEADER_V "V"
#define DATA_HEADER_TS "TS"
#define DATA_HEADER_IP "IP"
#define DATA_HEADER_PTID "PTID"
#define DATA_HEADER_MID "MID"
#define DATA_HEADER_DATA "Data"

#define DATA_HOSTIP_STR "HostIP"
#define DATA_ISARRIVE_STR "IsArrive"
#define UNLONG_LEN 20

typedef struct _snmp_result
{
	char str[4096];
	uint64_t ul;
	int type;
}snmp_result;


int sct_write_logstash(char *buff, char *filename);
int sct_init_json_object(json_object **ob, const sct_item_list *task);
int sct_ping_result(char *ip_addr);
int sct_linux_get_item(sct_item_list *item);
int sct_linux_ping(sct_item_list *item);
int sct_other_get_item(sct_item_list *item);
int sct_snmp_get(char *ip_addr, char *oid_str, snmp_result *result);
int sct_child_process(int pid_loc) ;
int sct_tcp_get(char *ip_addr, unsigned long key, snmp_result *result);

#endif
