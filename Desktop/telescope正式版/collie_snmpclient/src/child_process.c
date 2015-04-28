/**
 * File:child_process.c
 * Data:2014-05-19
 *
 * The file is msg recv item, snmp get result and
 * write json string to logstash file.
 *
 * Author:LiQinglong
 */

 #include "child_process.h"


#define SNMP_COLLECT_OK 0
#define SNMP_COLLECT_NG -1
#define RESULT_MAX_LEN 1023
#define RECV_MAX_LEN 4096

#define CLIENT_PORT 7779

#define IPC_MSG_FLAG 1234

extern sct_config_t g_conf;
extern sct_hashmap_table g_mibs;

int sct_write_logstash(char *buff, char *filename)
{
	int fd = -1;
	
	if(NULL == buff || NULL == filename)
	{
		sct_log_write(ERROR, "write_logstash parameter is null.");
		return SNMP_COLLECT_NG;
	}
	
	fd = open(filename, O_CREAT | O_APPEND | O_RDWR, 0666);
	if (fd < 0) 
	{
		sct_log_write(ERROR, "write json to logstash's file failed.");
		return SNMP_COLLECT_NG;
	}

	strcat(buff,"\n");
	write(fd, buff, strlen(buff));

	close(fd);
	return SNMP_COLLECT_OK;
}

int sct_init_json_object(json_object **ob, const sct_item_list *task)
{
	
	time_t now = 0;
	unsigned long temp_ip = 0;

	if(NULL == task || NULL == ob)
	{
		sct_log_write(ERROR, "sct_init_json_object parameter is null.");
		return SNMP_COLLECT_NG;
	}
	
	now = time(NULL);

	*ob = json_object_new_object();
	/*init json header*/
	json_object_object_add(*ob, DATA_HEADER_V, json_object_new_string(COLLIE_VERSION_1));
	json_object_object_add(*ob, DATA_HEADER_TS, json_object_new_int(now));

	temp_ip = inet_addr(task->ip_addr);
	if(temp_ip == -1)
	{
		sct_log_write(ERROR, "sct_init_json_object change ip failed.");
		return SNMP_COLLECT_NG;
	}
	temp_ip = ntohl(temp_ip);

	sct_log_write(DEBUG, "sct_init_json_object change ip is %ld.", temp_ip);
	
	json_object_object_add(*ob, DATA_HEADER_IP, json_object_new_int64(temp_ip));

	json_object_object_add(*ob, DATA_HEADER_MID, json_object_new_int64(task->keyid));

	return SNMP_COLLECT_OK;
}

static int sct_write_item_error(const sct_item_list *item, int result)
{
	json_object *hdr_ob = NULL, *err_ob = NULL;
	char *send_buff = NULL;
	char file_name[FILE_MAX_LEN] = {0};
	char err_str[COMMAND_MAX_LEN] = {0};
	int ret = SNMP_COLLECT_OK;

	if(NULL == item)
	{
		sct_log_write(ERROR, "sct_write_item_error parameter is null.");
		return SNMP_COLLECT_NG;
	}
	/*init error json header, "V" "TS" "IP" "MID".......*/
	ret = sct_init_json_object(&hdr_ob, item);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_write_item_error init object failed.");
		return SNMP_COLLECT_NG;
	}

	//json_object_object_add(hdr_ob, "IP_STR", json_object_new_string(item->ip_addr));
	memset(&err_str, 0, COMMAND_MAX_LEN);
	sprintf(err_str, "[{\"error\":%d, \"ip\":\"%s\"}]", result, item->ip_addr);
	
	/*string change to json object, if have error return -1*/
	err_ob = json_tokener_parse(err_str);
	if(is_error(err_ob))
	{
		sct_log_write(ERROR, "recv %d %ld result isn't json string.", item->ip_addr, item->keyid);
		return SNMP_COLLECT_NG;
	}

	json_object_object_add(hdr_ob, DATA_HEADER_DATA, err_ob);

	send_buff = NULL;
	send_buff = (char *) json_object_to_json_string(hdr_ob);
	if(NULL == send_buff )
	{
		sct_log_write(ERROR, "recv_get_item: Json to string failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(DEBUG, "fork%d: logstash is %s", g_conf.log_level, send_buff);

	memset(&file_name, 0, FILE_MAX_LEN);
	sprintf(file_name, "%s/error_task.log", g_conf.logstash_path);
	
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_write_item_error: write data error failed.");
		return SNMP_COLLECT_NG;
	}	

	json_object_put(hdr_ob);
	json_object_put(err_ob);
	
	return SNMP_COLLECT_OK;
}

int sct_linux_get_item(sct_item_list *item)
{
	json_object *get_object = NULL, *new_ob = NULL;
	snmp_result result, ex_result;
	int res_len = 0;
	sct_hashset_t *mib = NULL;
	int ret = SNMP_COLLECT_OK;
	unsigned long temp_ip = 0;

	char *send_buff = NULL, file_name[FILE_MAX_LEN] = {0};

	if(NULL == item)
	{
		sct_log_write(ERROR,"item is null");
		return SNMP_COLLECT_NG;
	}	

	/*init json header, "V" "TS" "IP" "MID".....*/
	sct_init_json_object(&get_object, item);

//	sct_log_write(DEBUG, "task's ip addr is %s, task.oid is %s", item->ip_addr, mib->oid.oid_val);
	mib = sct_find_oid_hash(item->keyid, &g_mibs);
	if(NULL == mib)
	{
	
		sct_log_write(ERROR, "linux_get_item:%ld %d %s not found item oid.", 
			item->keyid, item->intervals, item->ip_addr);
		json_object_put(get_object);
		return SNMP_COLLECT_NG;
	}

	sct_log_write(WARNING, "find oid info.");
	/*get snmp value, result save to third parameter*/
	memset(&result, 0, sizeof(snmp_result));
	ret = sct_snmp_get(item->ip_addr, mib->oid[0].oid_val, &result);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "recv_getsnmp:snmp get failed.");
		sct_write_item_error(item, ret); 
		json_object_put(get_object);
		return SNMP_COLLECT_NG;
	}
	
	res_len = strlen(result.str);
	if(res_len >= 999)
	{
		usleep(500);
		if(909000001005 == item->keyid)	
		{
			ret = sct_snmp_get(item->ip_addr, ".1.3.6.1.4.1.2021.8.1.101.13", &ex_result);
			strcat(result.str, ex_result.str);
		}
		else if(909000001006 == item->keyid)	
		{
			ret = sct_snmp_get(item->ip_addr, ".1.3.6.1.4.1.2021.8.1.101.14", &ex_result);
			strcat(result.str, ex_result.str);
		}
		else if(909000001004 == item->keyid)
		{
			ret = sct_snmp_get(item->ip_addr, ".1.3.6.1.4.1.2021.8.1.101.15", &ex_result);
			strcat(result.str, ex_result.str);
		}
		else if(909000001002 == item->keyid)
		{
			ret = sct_snmp_get(item->ip_addr, ".1.3.6.1.4.1.2021.8.1.101.16", &ex_result);
			strcat(result.str, ex_result.str);
		}
	}
	sct_log_write(WARNING, "snmp protocal recv linux json string.");

	
	/*string change to json object, if have error return -1*/
	new_ob = json_tokener_parse(result.str);
	if(is_error(new_ob))
	{
		if(result.str[0] != '[')
		{
			sct_log_write(ERROR, "Collie SNMP Server not install.");
			sct_write_item_error(item, ERROR_GET_UNINSTALL); 
			json_object_put(get_object);
			return SNMP_COLLECT_NG;
		}
		else
		{
			sct_log_write(ERROR, "recv %s %ld result isn't json string.",
				item->ip_addr, item->keyid);
			sct_write_item_error(item, ERROR_GET_NOTJSON); 
			json_object_put(get_object);
			return SNMP_COLLECT_NG;
		}
	}

	sct_log_write(WARNING, "result is %s", result.str);

	json_object_object_add(get_object, DATA_HEADER_DATA, new_ob);

	send_buff = NULL;
	send_buff = (char *) json_object_to_json_string(get_object);
	if(NULL == send_buff)
	{
		sct_log_write(ERROR, "recv_get_item: Json to string failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(DEBUG, "fork%d: logstash is %s", g_conf.log_level, send_buff);

	memset(&file_name, 0, FILE_MAX_LEN);
	temp_ip = inet_addr(item->ip_addr);
	temp_ip = ntohl(temp_ip);
	sprintf(file_name, "%s/%lu_%lu.log", g_conf.logstash_path, item->keyid/10000, temp_ip);
	
	sct_log_write(WARNING, "write log file start.");
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_linux_get_item: write data file failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(WARNING, "write log file end.");
	json_object_put(get_object);
	json_object_put(new_ob);

	return SNMP_COLLECT_OK;
}

int sct_linux_ping(sct_item_list *item)
{
	int ret = SNMP_COLLECT_OK;
	int result = -1;

	//char isarrive[ISARRIVE_STR_LEN] = {0};
        int isarrive = -1;
	json_object *get_object = NULL, *walk_array = NULL, *data_object = NULL;
	unsigned long temp_ip = 0;

	char *send_buff = NULL, file_name[FILE_MAX_LEN] = {0};

	if(NULL == item)
	{
		sct_log_write(ERROR,"item is null");
		return SNMP_COLLECT_NG;
	}	

	/*init json header, "V" "TS" "IP" "MID".....*/
	sct_init_json_object(&get_object, item);

	/*get snmp value, result save to third parameter*/
	result = sct_ping_result(item->ip_addr);
	if(result < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "recv_getsnmp:snmp get failed.");
		sct_write_item_error(item, ret); 
		return SNMP_COLLECT_NG;
	}

	temp_ip = inet_addr(item->ip_addr);
	if(temp_ip == -1)
	{
		sct_log_write(ERROR, "sct_init_json_object change ip failed.");
		return SNMP_COLLECT_NG;
	}
	temp_ip = ntohl(temp_ip);

	walk_array = json_object_new_array();
	data_object = json_object_new_object();

	json_object_object_add(data_object, DATA_HOSTIP_STR, json_object_new_int64(temp_ip));

	memset(&isarrive, 0, ISARRIVE_STR_LEN);
	if(0 < result)
	{
	//	strncpy(isarrive, ISARRIVE_TRUE, ISARRIVE_STR_LEN);
                isarrive = 1;
	}
	else
	{
//		strncpy(isarrive, ISARRIVE_FALSE, ISARRIVE_STR_LEN);
                isarrive = 0;
	}
	
	json_object_object_add(data_object, DATA_ISARRIVE_STR, json_object_new_boolean(isarrive));

	json_object_array_add(walk_array, data_object);

	json_object_object_add(get_object, DATA_HEADER_DATA, walk_array);
	
	send_buff = NULL;
	send_buff = (char *) json_object_to_json_string(get_object);
	if(NULL == send_buff)
	{
		sct_log_write(ERROR, "recv_get_item: Json to string failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(DEBUG, "fork%d: logstash is %s", g_conf.log_level, send_buff);

	memset(&file_name, 0, FILE_MAX_LEN);
	temp_ip = inet_addr(item->ip_addr);
	temp_ip = ntohl(temp_ip);
	sprintf(file_name, "%s/%lu_%lu.log", g_conf.logstash_path, item->keyid/10000, temp_ip);
	
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_linux_get_item: write data file failed.");
		return SNMP_COLLECT_NG;
	}

	json_object_put(get_object);
	json_object_put(walk_array);
	json_object_put(data_object);
	
	return SNMP_COLLECT_OK;
}

int sct_tcp_shell(sct_item_list *item)
{
	json_object *get_object = NULL, *new_ob = NULL;
	snmp_result result;
//	int res_len = 0;
	int ret = SNMP_COLLECT_OK;
	unsigned long temp_ip = 0;

	char *send_buff = NULL, file_name[FILE_MAX_LEN] = {0};

	if(NULL == item)
	{
		sct_log_write(ERROR,"item is null");
		return SNMP_COLLECT_NG;
	}

	/*init json header, "V" "TS" "IP" "MID".....*/
	sct_init_json_object(&get_object, item);

	sct_log_write(WARNING, "find oid info.");
	
	/*get snmp value, result save to third parameter*/
	memset(&result, 0, sizeof(snmp_result));
	ret = sct_tcp_get(item->ip_addr, item->keyid, &result);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "recv_getsnmp:snmp get failed.");
		sct_write_item_error(item, ret); 
		json_object_put(get_object);
		return SNMP_COLLECT_NG;
	}
		
	/*string change to json object, if have error return -1*/
	new_ob = json_tokener_parse(result.str);
	if(is_error(new_ob))
	{
		if(result.str[0] != '[')
		{
			sct_log_write(ERROR, "Collie SNMP Server not install, string is %s.", result.str);
			sct_write_item_error(item, ERROR_GET_UNINSTALL); 
			json_object_put(get_object);
			return SNMP_COLLECT_NG;
		}
		else
		{
			sct_log_write(ERROR, "recv %s %ld result isn't json string, string is %s.",
				item->ip_addr, item->keyid, result.str);
			sct_write_item_error(item, ERROR_GET_NOTJSON); 
			json_object_put(get_object);
			return SNMP_COLLECT_NG;
		}
	}

	//asser(result);

	json_object_object_add(get_object, DATA_HEADER_DATA, new_ob);

	send_buff = NULL;
	send_buff = (char *) json_object_to_json_string(get_object);
	if(NULL == send_buff)
	{
		sct_log_write(ERROR, "recv_get_item: Json to string failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(DEBUG, "fork%d: logstash is %s", g_conf.log_level, send_buff);

	memset(&file_name, 0, FILE_MAX_LEN);
	temp_ip = inet_addr(item->ip_addr);
	temp_ip = ntohl(temp_ip);
	sprintf(file_name, "%s/%lu_%lu.log", g_conf.logstash_path, item->keyid/10000, temp_ip);
	
	sct_log_write(WARNING, "write log file start.");
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_linux_get_item: write data file failed.");
		return SNMP_COLLECT_NG;
	}

	sct_log_write(WARNING, "write log file end.");
	json_object_put(get_object);
	json_object_put(new_ob);

	return SNMP_COLLECT_OK;
}

int sct_ping_result(char *ip_addr)
{
	FILE *fp = NULL;
	int read_len = 0;
	char cmd[COMMAND_MAX_LEN] = {0};
	char ping_result[COMMAND_MAX_LEN] = {0};
	int result = -1;

	if(NULL == ip_addr)
	{
		sct_log_write(ERROR, "sct_linux_ping: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}
	/*md5sum + <file>, get file's md5 value*/
	
	memset(&cmd, 0, COMMAND_MAX_LEN);
	sprintf(cmd, "ping -c 1  %s |grep received |awk -F\"received\" '{print $1}' |awk -F, '{print $2}'", ip_addr);
	
	fp = popen(cmd, "r");
	if(NULL == fp)
	{
		sct_log_write(ERROR, "popen md5sum failed.");
		return SNMP_COLLECT_NG;
	}

	read_len = fread(ping_result, MD5_SIGNAL_LEN, MD5_RESULT_MAX, fp);
	if(ferror(fp))
	{
		sct_log_write(ERROR, "fread error.");
		return SNMP_COLLECT_NG;
	}
	else
	{
		ping_result[read_len] = '\0';
	}
	
	if(fp)
		pclose(fp);

	result = strtoul(ping_result, NULL, 10);
	
	return result;
}



int sct_other_get_item(sct_item_list *item)
{
	sct_hashset_t *mib = NULL;
	snmp_result result;
	
	json_object *walk_object = NULL, *data_object = NULL, *walk_array = NULL;

	char *send_buff = NULL, file_name[FILE_MAX_LEN] = {0}, oid[OID_MAX_LEN] = {0};
	
	int i = 0, j = 0, ret = SNMP_COLLECT_OK;
	int retry = 0;
	unsigned long temp_ip = 0;
	
	if(NULL == item)
	{
		sct_log_write(ERROR,"item is null");
		return -1;
	}	
	
	/*init json header, "V" "TS" "IP" "MID".....*/
	sct_init_json_object(&walk_object, item);
	walk_array = json_object_new_array();
	
	mib = sct_find_oid_hash(item->keyid, &g_mibs);
	if(NULL == mib)
	{
		sct_log_write(ERROR, "other_get_item:%s %ld not found item oid.", item->ip_addr, item->keyid);
		return SNMP_COLLECT_NG;
	}

	if(GET_TYPE == item->type)
		item->index_count = 1;
	
	if(0 == item->index_count){
		json_object_put(walk_object);
		json_object_put(walk_array);
		return -1;
	}
	for(j = 0; j < item->index_count; j++){

		data_object = json_object_new_object();

		for(i = 0; i < mib->oid_count; i++)
		{
			retry = 3;
			/*copy index to oid, 1.3.6.2.1 + 2 = 1.3.6.2.1.2*/
			memset(&oid, 0, sizeof(oid));
			if(GET_TYPE== item->type)
			{
				strncpy(oid, mib->oid[i].oid_val, strlen(mib->oid[i].oid_val));
			}
			else if(WALK_TYPE== item->type)
			{
				sprintf(oid, "%s.%d", mib->oid[i].oid_val, item->index[j]);
			}
			
			/*get snmp value, result save to third parameter*/
			while(retry > 0){
				memset(&result, 0, sizeof(snmp_result));
				ret = sct_snmp_get(item->ip_addr, oid, &result);
				if(ret < SNMP_COLLECT_OK)
				{
					sct_log_write(ERROR, "recv_getsnmp:snmp get failed.");
					//sct_write_item_error(item, ret);
				}
				retry--;
			}
			if (ASN_OCTET_STR == result.type) 
			{
			       json_object_object_add(data_object, mib->oid[i].name, 
				   	json_object_new_string(result.str));
			}
			else
			{
			       json_object_object_add(data_object, mib->oid[i].name,
			              json_object_new_int64(result.ul));
			}
		}
		json_object_array_add(walk_array, data_object);

	}
	json_object_object_add(walk_object, DATA_HEADER_DATA, walk_array);

	send_buff = (char *) json_object_to_json_string(walk_object);
	if(NULL ==  send_buff)
	{
	        sct_log_write(ERROR,"change json str failed.");
	        return -1;
	}
	sct_log_write(DEBUG, "logstash is %s", send_buff);
	
	memset(&file_name, 0, FILE_MAX_LEN);
	temp_ip = inet_addr(item->ip_addr);
	temp_ip = ntohl(temp_ip);
	sprintf(file_name, "%s/%lu_%lu.log", g_conf.logstash_path, item->keyid/10000, temp_ip);
	
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_other_get_item: write other data file failed.");
		return SNMP_COLLECT_NG;
	}
	

	json_object_put(walk_object);
	json_object_put(walk_array);
	json_object_put(data_object);
	
	return SNMP_COLLECT_OK;
}



/******************************************************************
 * Function: snmp_get
 * Purpose: net-snmp api for get snmp value, and value is result or ul
 *
 * Parameters: struct task is ip and oid, type is value type, 
 *             result or ul is value *
 *
 * Author: Li qinglong                                          *
 *****************************************************************/
 
int sct_snmp_get(char *ip_addr, char *oid_str, snmp_result *result)
{
	struct snmp_session session, *ss = NULL;
	struct snmp_pdu *pdu = NULL, *response = NULL;
	struct variable_list *vars = NULL;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;

	char *comm = "public";

	int status = 0;
	int len = 0;
	int ret = SNMP_COLLECT_OK;

	if(NULL == ip_addr || NULL == oid_str || NULL == result)
	{
		sct_log_write(ERROR, "sct_snmp_get: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}

	snmp_sess_init(&session);

	session.version = SNMP_VERSION_2c;
	session.peername = ip_addr;
	session.community = (unsigned char *)comm;
	session.community_len = strlen((void *) session.community);

	SOCK_STARTUP;

	snmp_close(ss);

	if (NULL == (ss = snmp_open(&session))) 
	{
		sct_log_write(ERROR, "snmp open session failed.");
		SOCK_CLEANUP;
		return ERROR_GET_OPENFAILED;
	}

	snmp_parse_oid(oid_str, anOID, &anOID_len);

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, anOID, anOID_len);

	status = snmp_synch_response(ss, pdu, &response);

	if (STAT_SUCCESS == status && SNMP_ERR_NOERROR == response->errstat)
	{
		for (vars = response->variables; vars; vars = vars->next_variable)
		{

			result->type = vars->type;
			if(ASN_OCTET_STR == vars->type)
			{
				len = RESULT_MAX_LEN<vars->val_len?RESULT_MAX_LEN:vars->val_len;
				memcpy(result->str, vars->val.string, vars->val_len);
				result->str[vars->val_len] = '\0';
			}
			else if(ASN_UINTEGER == vars->type ||ASN_COUNTER == vars->type ||
			ASN_TIMETICKS == vars->type || ASN_GAUGE == vars->type)
			{
				result->ul = (uint64_t)*vars->val.integer;
			}	
			else if(ASN_COUNTER64 == vars->type)
			{
				result->ul = (((uint64_t)vars->val.counter64->high) << 32) +
				(uint64_t)vars->val.counter64->low;
			}
			else if (ASN_INTEGER == vars->type || ASN_INTEGER64 == vars->type)
			{
				result->ul = (uint64_t)*vars->val.integer;
			}
			break;
		}
	}
	else
	{
		if (STAT_SUCCESS == status)
		{
			sct_log_write(ERROR, "SNMP error: %s, ", snmp_errstring(response->errstat));
			ret = ERROR_GET_NOTSUPPORT;
		}
		else if (STAT_ERROR == status)
		{
			sct_log_write(ERROR,"Could not connect to \"%s:%s\": %s",
				ip_addr, oid_str, snmp_api_errstring(ss->s_snmp_errno));
			switch (ss->s_snmp_errno)
			{
				case SNMPERR_UNKNOWN_USER_NAME:
				case SNMPERR_UNSUPPORTED_SEC_LEVEL:
				case SNMPERR_AUTHENTICATION_FAILURE:
					ret = ERROR_GET_NOTSUPPORT;
					break;
				default:
					ret = ERROR_GET_NETWORK;
			}
		}
		else if (STAT_TIMEOUT == status)
		{
			sct_log_write(ERROR, "SNMP TimeOut connect %s:%s", ip_addr, oid_str);
			ret = ERROR_GET_NETWORK;
		}
		else
		{
			sct_log_write(ERROR, "SNMP error [%d]", status);
			ret = ERROR_GET_NOTSUPPORT;
		}
		
	}
	
	if (response)
		snmp_free_pdu(response);
	snmp_close(ss);

	SOCK_CLEANUP;

	return (ret);
}

int sct_tcp_get(char *ip_addr, unsigned long keyid, snmp_result *result)
{
	
	int fd = -1,sockfd = -1;
	struct sockaddr_in addr;
	int len = sizeof(struct sockaddr_in);
	int send_len = 0, recv_len = 0;
	char recv_buff[4096] = {0};
	char key[32] = {0};

	keyid = keyid % 90900000;
	sprintf(key, "%ld", keyid);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		return -1;
	}
	
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip_addr);
	addr.sin_port = htons(CLIENT_PORT);


	fd = connect(sockfd, (struct sockaddr *)&addr, len);
	if(fd < 0){
		sct_log_write(ERROR, "connect failed.");
		return -35;
	}

	
	send_len = send(sockfd, key, strlen(key), MSG_NOSIGNAL);
	if(send_len <=0)
	{
		sct_log_write(ERROR, "send failed.");
	}
	else
	{
		memset(recv_buff, 0, 4096);
		recv_len = recv(sockfd, recv_buff, 4096, 0);
		if(recv_len <= 0)
		{
			sct_log_write(ERROR, "recv result errno is %s[%d].", strerror(errno), errno); 
		}
		
		memcpy(result->str, recv_buff, recv_len);
		result->str[recv_len] = '\0';
	}

	close(sockfd);	
	return SNMP_COLLECT_OK;
}

/******************************************************************
 * Function: child_process
 * Purpose: ipc msg recv item, use net-snmp api get value  
 *			and change value to json write logstash             *
 *
 * Parameters: pid_loc is fork child pid                        *
 *
 * Author: Li qinglong                                          *
 *****************************************************************/
int sct_child_process(int pid_loc) 
{

	sct_item_list item;
	int  len = 0;
	char buff[RECV_MAX_LEN] = {0};

	int ret = SNMP_COLLECT_OK;
	int msgfd = -1;

	sct_log_write(DEBUG, "recv_getsnmp");
	/*loop recv task buff and get value*/
	while (1) {

		msgfd = msgget(IPC_MSG_FLAG, IPC_EXCL);
		if(msgfd < 0)
		{
			sct_log_write(ERROR,"collie_snmpcollect child is killed.");
		}

		memset(&buff, 0, RECV_MAX_LEN);
		/*recv buff, and max size is 2048*/
		len = msgrcv(msgfd, buff, RECV_MAX_LEN, 0, IPC_NOWAIT);
		if(len < 0)
		{
			sleep(1);
			/*if father pid is 1, the main process is exit, 1 is init*/
			if(1 == getpid()) 
			{
				sct_log_write(ERROR, "child is end");
				break;
			}
			continue;
		}
		
		
		memset(&item, 0, sizeof(sct_item_list));
		item = *(sct_item_list *) buff;
		sct_log_write(WARNING, "recv msg success.%ld, %s, type is %d", item.keyid, item.ip_addr, item.type);
		/*if type is linux(snmp_get result is json array)*/
		if (LINUX_JSON_TYPE == item.type)
		{
			/*get value and write json string to logstash*/
			ret = sct_linux_get_item(&item);
			if(ret < 0)
			{
				sct_log_write(ERROR, "linux type get result failed or write failed.");
				continue;
			}	
		}
		else if(LINUX_PING_TYPE == item.type)
		{
			ret = sct_linux_ping(&item);
			if(ret < 0)
			{
				sct_log_write(ERROR, "linux type get result failed or write failed.");
				continue;
			}
		}
		else if(TCP_SHELL_TYPE == item.type)
		{
			ret = sct_tcp_shell(&item);
			if(ret < 0)
			{
				sct_log_write(ERROR, "linux type get result failed or write failed.");
				continue;
			}
		}
		/*other type's snmp result is int or string*/
		else 
		{
			/*get value and write json string to logstash*/
			ret = sct_other_get_item(&item);
			if(ret < 0)
			{
				sct_log_write(ERROR, "other type get result and write failed.");
				continue;
			}			
		}
		
	}
	
	sct_log_write(DEBUG, "fork%d is end.....",pid_loc);
	return SNMP_COLLECT_OK;
}

