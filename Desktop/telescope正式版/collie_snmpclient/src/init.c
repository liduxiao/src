/**
 * File:init.c
 * Data:2014-05-19
 *
 * The file is walk many oid from task table and oids table, and
 * insert new table that task_oids
 *
 * Author:LiQinglong
 */

#include "snmp_collect.h"
#include "child_process.h"
#include "init.h"

#define SNMP_COLLECT_OK 0
#define SNMP_COLLECT_NG -1

#define MID_MAX_LEN 16

#define TYPE_INIT 1
#define TYPE_UPDATE 2

sct_item_list *sct_insert_item_list(sct_item_list *head, sct_item_list *add_node)
{
	sct_item_list *p = NULL, *item = NULL;

	 p = head;

	 if(NULL == add_node)
	 {
		 return NULL;
	 }

	item = (sct_item_list *)malloc(sizeof(sct_item_list));
	if(NULL == item)
	{
		sct_log_write(ERROR, "insert_item_list: malloc item failed.");
		return NULL;
	}
	
	memcpy(item, add_node, sizeof(sct_item_list));
	item->next = NULL;
	item->nextcheck = time(NULL) + item->intervals;
	
	if(head == add_node || NULL == head)
	{
		return item;
	}

	if(p->nextcheck > item->nextcheck)
	{
		item->next = p;
		return item;
	}
	else
	{
		while(p->next != NULL)
		{
	 	
			if(item->nextcheck >= p->next->nextcheck)
			{
				p = p->next;
			}
			else
			{
				item->next = p->next;
				p->next = item;
				return head;
			}
	 	}
		 p->next = item;
		 item->next = NULL;

	 	return head;
	}

	return NULL;
 }

int sct_snmp_get_test(char *ip_addr, char *oid_str)
{
	struct snmp_session session, *ss = NULL;
	struct snmp_pdu *pdu = NULL, *response = NULL;
	struct variable_list *vars = NULL;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	char *comm="public";

	int status = 0;
	int ret = SNMP_COLLECT_OK;

	if(NULL == ip_addr || NULL == oid_str)
	{
		sct_log_write(ERROR, "sct_snmp_get_test: parameter ip_addr or oid_str is NULL.");
		return SNMP_COLLECT_NG;
	}

	/*init session, set ip and public*/
	snmp_sess_init(&session);

	session.version = SNMP_VERSION_2c;
	session.peername = ip_addr;
	session.community = (unsigned char *)comm;
	session.community_len = strlen((void *)session.community);
	session.rcvMsgMaxSize = 4096;

	SOCK_STARTUP;

	snmp_close(ss);

	if (NULL == (ss = snmp_open(&session)))
	{
		SOCK_CLEANUP;
		return ERROR_GET_OPENFAILED;
	}

	snmp_close(ss);

	if (NULL == (ss = snmp_open(&session))) {

		sct_log_write(ERROR, "snmp open session failed.");
		SOCK_CLEANUP;
		return SNMP_COLLECT_NG;
	}

	snmp_parse_oid(oid_str, anOID, &anOID_len);

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	snmp_add_null_var(pdu, anOID, anOID_len);

	status = snmp_synch_response(ss, pdu, &response);

	if (STAT_SUCCESS == status && SNMP_ERR_NOERROR == response->errstat)
	{
		for (vars = response->variables; vars; vars = vars->next_variable)
		{

			ret = SNMP_COLLECT_OK;
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


int sct_snmp_walk_index(sct_item_list *item, char *oid_str, int flag, sct_list_table *list)
{
	struct snmp_session session, *ss = NULL;
	struct snmp_pdu *pdu, *response;
	struct variable_list *vars;
	oid anOID[MAX_OID_LEN];
	oid rootOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	size_t rootOID_len = MAX_OID_LEN;
	char *comm = "public";
	int status = 0;
	int running = 0;
	int ret = SNMP_COLLECT_OK;

	if(NULL == item || NULL == oid_str || NULL == list)
	{
		sct_log_write(ERROR, "sct_snmp_walk_index: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}

	/*init session, set ip and public*/
	snmp_sess_init(&session);

	session.version = SNMP_VERSION_2c;
	session.peername = item->ip_addr;
	session.community = (unsigned char *)comm;
	session.community_len = strlen((void *)session.community);


	SOCK_STARTUP;

	snmp_close(ss);

	if (NULL == (ss = snmp_open(&session)))
	{
		SOCK_CLEANUP;
		return ERROR_GET_OPENFAILED;
	}

	/*set oid*/
	snmp_parse_oid(oid_str, rootOID, &rootOID_len);

	memcpy(anOID, rootOID, rootOID_len * sizeof(oid));
	anOID_len = rootOID_len;

	int i = 0;
	running = 1;
	while(running){
		/*create snmp type, snmp_msg_get or snmp_msg_getnext(walk)*/
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, anOID, anOID_len);

		/*get snmp value and put response*/
		status = snmp_synch_response(ss, pdu, &response);

		if(STAT_SUCCESS == status && SNMP_ERR_NOERROR == response->errstat)
		{
			for (vars = response->variables; vars; vars = vars->next_variable)
			{
				if (vars->name_length < rootOID_len ||
						0 != memcmp(rootOID, vars->name, rootOID_len * sizeof(oid)))
				{
					/* not part of this subtree */
					running = 0;
				}
				else
				{
					if (snmp_oid_compare(anOID, anOID_len, vars->name, vars->name_length) >= 0)
					{
						running = 0;
						break;
					}

					/*save index, 1 2 3 4.....*/
					/*
					sprintf(item->index, "%ld", vars->name[vars->name_length-1]);

					
					if(TYPE_INIT == flag)
					{
						list->run_list = sct_insert_item_list(list->run_list , item);
					}
					else if(TYPE_UPDATE == flag)
					{
						list->bak_list  = sct_insert_item_list(list->bak_list , item);
					}
					*/
					item->index[i] = vars->name[vars->name_length-1];
					i++;
					
					/*set getnext oid*/
					memmove((char *)anOID, (char *)vars->name, vars->name_length * sizeof(oid));
					anOID_len = vars->name_length;
				}
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
				sct_log_write(ERROR,"Could not connect to \"%s:%s\": %s",item->ip_addr,
					oid_str, snmp_api_errstring(ss->s_snmp_errno));
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
				sct_log_write(ERROR, "SNMP TimeOut connect %s:%s", item->ip_addr, oid_str);
				ret = ERROR_GET_NETWORK;
			}
			else
			{
				sct_log_write(ERROR, "SNMP error [%d]", status);
				ret = ERROR_GET_NOTSUPPORT;
			}
			running = 0;
		}

		if (response)
			snmp_free_pdu(response);
	}
	snmp_close(ss);

	SOCK_CLEANUP;

	item->index_count = i;

	if(0 == item->index_count){
		return -1;
	}
	
	if(TYPE_INIT == flag ){
		list->run_list = sct_insert_item_list(list->run_list , item);
	}
	else if(TYPE_UPDATE == flag){
		list->bak_list  = sct_insert_item_list(list->bak_list , item);
	}
	return ret;
}



static int sct_read_collect_config(const char * config_path, sct_config_t *config)
{
	FILE *fp = NULL;
	char *tok = NULL, *saveptr =NULL;
	char line[READ_MAX_LEN] = {0};

	if(NULL == config_path || NULL == config)
	{
		sct_log_write(ERROR, "read_db_config: parameter config_path is null.");
		return SNMP_COLLECT_NG;
	}
	
	fp = fopen(config_path, "r");
	if(NULL == fp)
	{
		sct_log_write(ERROR, "read_db_config: fopen %s failed.", config_path);
		return SNMP_COLLECT_NG;
	}

	memset(&line, 0, READ_MAX_LEN);
	while(fgets(line, READ_MAX_LEN, fp) != NULL)
	{
		tok = strtok_r (line, " \t\r\n=", &saveptr);
		if ((tok == NULL) || (strncmp (tok, "#", 1) == 0))
		{
			continue ;
		}

		/*out interface, result file path*/
		if(0 == strncmp (tok, "LogstashPath", strlen (tok)))
		{
			tok = strtok_r (NULL, " \t\r\n", &saveptr);
                        if (tok != NULL)
                        {
                                strncpy (config->logstash_path, tok, sizeof(config->logstash_path));
                        }
		}
		else if(0 == strncmp (tok, "TaskPath", strlen (tok)))
		{
			tok = strtok_r (NULL, " \t\r\n", &saveptr);
                        if (tok != NULL)
                        {
                                strncpy (config->task_conf, tok, sizeof(config->task_conf));
                        }
		}
		else if(0 == strncmp (tok, "MibPath", strlen (tok)))
		{
			tok = strtok_r (NULL, " \t\r\n", &saveptr);
                        if (tok != NULL)
                        {
                                strncpy (config->mib_conf, tok, sizeof(config->mib_conf));
                        }
		}
		/*child process num*/
		else if (0 == strncmp (tok, "Threads", strlen (tok)))
		{
			tok = strtok_r (NULL, " \t\r\n", &saveptr);
			if (tok != NULL)
			{
				config->threads = atoi(tok);
			}
		}
		/*log level, debug,warning,error*/
		else if (0 == strncmp (tok, "LogLevel", strlen (tok)))
		{
			tok = strtok_r (NULL, " \t\r\n", &saveptr);
			if (tok != NULL)
			{
				config->log_level = atoi(tok);
			}
		}
		memset(&line, 0, READ_MAX_LEN);

	}

	if(fp)  
		fclose(fp);
	
	return SNMP_COLLECT_OK;
}


int sct_get_task_md5(const char *file_path, char *md5_result)
{
	FILE *fp = NULL;
	int read_len = 0;
	char cmd[COMMAND_MAX_LEN] = {0};

	if(NULL == file_path || NULL == md5_result)
	{
		sct_log_write(ERROR, "get_task_md5: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}
	/*md5sum + <file>, get file's md5 value*/
	
	memset(&cmd, 0, COMMAND_MAX_LEN);
	sprintf(cmd, "md5sum \"%s\" |awk '{print $1}'",file_path);
	
	fp = popen(cmd, "r");
	if(NULL == fp)
	{
		sct_log_write(ERROR, "popen md5sum failed.");
		return SNMP_COLLECT_NG;
	}

	read_len = fread(md5_result, MD5_SIGNAL_LEN, MD5_RESULT_MAX, fp);
	if(ferror(fp))
	{
		sct_log_write(ERROR, "fread error.");
		return SNMP_COLLECT_NG;
	}
	else
	{
		md5_result[read_len-1] = '\0';
	}
	
	if(fp)
		pclose(fp);
	
	return SNMP_COLLECT_OK;
}

static int sct_parse_json_task(char *line, sct_item_list *item)
{
	/*json functions is json-c-0.10 lib*/
	json_object *task_obj = NULL,*temp_obj = NULL;
	char temp_ip[IP_MAX_LEN] = {0};
	int ret = SNMP_COLLECT_OK;
	
	if(NULL == line || NULL ==  item)
	{
		sct_log_write(ERROR, "parse_json_task: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}

	/*string change to json object, if have error return -1*/
	task_obj=json_tokener_parse(line);
	if(NULL == task_obj || is_error(task_obj))
	{
		sct_log_write(ERROR, "%s is not json.", line);
		return  ERROR_INTASK_JSON;
	}
	
	/*json to string, and save to parameter item*/
	temp_obj = json_object_object_get(task_obj,TASK_HEADER_IP);
	if(NULL == temp_obj || is_error(temp_obj))
	{
		sct_log_write(ERROR, "%s 's ip is error", line);
		ret =  ERROR_INTASK_IP;
		goto parse_task_end;
	}
	memset(&temp_ip, 0, IP_MAX_LEN);
	strncpy(temp_ip, json_object_get_string(temp_obj), IP_MAX_LEN);
	if(-1 == inet_addr(temp_ip))
	{
		sct_log_write(ERROR, "%s 's ip is illegal.", line);
		ret =  ERROR_IP_ILLEGAL;
		goto parse_task_end;
	}
	else
	{
		strncpy(item->ip_addr, temp_ip, IP_MAX_LEN);
	}

	temp_obj = json_object_object_get(task_obj,TASK_HEADER_INT);
	if(NULL == temp_obj || is_error(temp_obj))
	{
		sct_log_write(ERROR, "sct_parse_json_task: intervals is error.");
		ret =  ERROR_INTASK_INT;
		goto parse_task_end;
	}
	item->intervals = json_object_get_int(temp_obj);
	if(item->intervals <= 0)
	{
		sct_log_write(ERROR, "sct_parse_json_task: interval should than zero.");
		ret =  ERROR_INTASK_INT;
		goto parse_task_end;
	}

	temp_obj = json_object_object_get(task_obj,TASK_HEADER_MID);
	if(NULL == temp_obj || is_error(temp_obj))
	{
		sct_log_write(ERROR, "sct_parse_json_task: mid is error.");
		ret =  ERROR_INTASK_MID;
		goto parse_task_end;
	}

/*
	memset(&temp_mid, 0, MID_MAX_LEN);
	strncpy(temp_mid, json_object_get_string(temp_obj), MID_MAX_LEN);
	item->keyid = strtoul(temp_mid, NULL, 10);
*/
	item->keyid = json_object_get_int64(temp_obj);

	temp_obj = json_object_object_get(task_obj,TASK_HEADER_STATUS);
	if(NULL == temp_obj || is_error(temp_obj))
	{
		sct_log_write(ERROR, "line is not json.");
		ret =  ERROR_INTASK_STATUS;
		goto parse_task_end;
	}
	item->status = json_object_get_int(temp_obj);

parse_task_end:

	json_object_put(task_obj);
	json_object_put(temp_obj);
	
	return ret;
}

static int sct_parse_json_oid(const char *line, sct_hashset_t **mib) //hash_mibs_t parst_json_oid
{
	/*json functions is json-c-0.10 lib*/
	json_object *task_obj = NULL,*temp_obj = NULL, *array_obj = NULL, *name_obj = NULL, *oid_obj = NULL;
	json_type oid_type;
	
	char temp_mid[MID_MAX_LEN] = {0};
	int ret = SNMP_COLLECT_OK;
	//hash_mibs_t *mib_temp = NULL;

	int i = 0, oid_len = 0;

	if(NULL == line || NULL == mib)
	{
		sct_log_write(ERROR, "parse_json_oid: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}
	
	*mib = (sct_hashset_t *)malloc(sizeof(sct_hashset_t));
	if(NULL == *mib)
	{
		sct_log_write(ERROR, "parse_json_oid: malloc mib failed.");
		return SNMP_COLLECT_NG;
	}

	memset(*mib, 0, sizeof(sct_hashset_t));

	/*string change to json object, if have error return -1*/
	task_obj=json_tokener_parse(line);
	if(is_error(task_obj))
	{
		sct_log_write(ERROR, "parse_json_oid: %s  is not json.", line);
		return ERROR_INMIB_JSON;
	}

	/*get task type*/
	temp_obj = json_object_object_get(task_obj, MIB_HEADER_TYPE);
	if(is_error(temp_obj))
	{
		sct_log_write(ERROR, "parse_json_oid: %s 's type exist error.", line);
		return ERROR_INMIB_TYPE;
	}
	(*mib)->type = json_object_get_int(temp_obj);

	/*get task keyid to struct mib's keyid*/
	temp_obj = json_object_object_get(task_obj,MIB_HEADER_MID);
	if(is_error(temp_obj))
	{
		sct_log_write(ERROR, "parse_json_oid: %s 's type exist error.", line);
		return ERROR_INMIB_MIB;
	}
	memset(&temp_mid, 0, MID_MAX_LEN);
	strncpy(temp_mid, json_object_get_string(temp_obj), MID_MAX_LEN);
	(*mib)->keyid = strtoul(temp_mid, NULL, 10);
//	(*mib)->keyid = json_object_get_int(temp_obj); 

	temp_obj = json_object_object_get(task_obj, MIB_HEADER_OID);
	if(is_error(temp_obj))
	{	
		sct_log_write(ERROR, "parse_json_oid: %s 's type exist error.", line);
		return ERROR_INMIB_OID;
	}
	
	/*get oid json type, if type isn't json array don't parse*/
	oid_type = json_object_get_type(temp_obj);	
	if(oid_type == json_type_array)
	{
		/*get array len, [{},{}] the len is 2*/
		oid_len = json_object_array_length(temp_obj);
		if(oid_len > OID_MAX_COUNT)
		{
			oid_len = OID_MAX_COUNT;
			sct_log_write(ERROR, "tasks config keyid is %d 's oid count greater than 16.",(*mib)->keyid);
		}

		/*save array's value to oid*/
		for(i = 0; i < oid_len; i++)
		{
			array_obj = json_object_array_get_idx(temp_obj,i);
			if(is_error(array_obj))
			{	
				sct_log_write(ERROR, "parse_json_oid: oid's name is error.");
				continue;
			}
			else
			{
				name_obj = json_object_object_get(array_obj, MIB_HEADER_NAME);
				if(is_error(name_obj))
				{	
					sct_log_write(ERROR, "parse_json_oid: oid's name is error.");
					continue;
				}
				else
				{
					strcpy((*mib)->oid[i].name, json_object_get_string(name_obj));
				}

				oid_obj = json_object_object_get(array_obj, MIB_HEADER_OID);
				if(is_error(oid_obj))
				{	
					sct_log_write(ERROR, "parse_json_oid: oid's value is error.");
					continue;
				}
				else
				{
					strcpy((*mib)->oid[i].oid_val, json_object_get_string(oid_obj));		
				}
			}
			
		}

		(*mib)->oid_count = i;
	}
	else
	{
		sct_log_write(ERROR, "parse_json_oid: %s 's oid isn't array.", line);
		ret = ERROR_INMIB_OID;
	}
	
	return ret;
}

static int sct_write_task_error(char *file_path, sct_item_list *item, int result)
{
	json_object  *ob = NULL;
	char *send_buff = NULL;
	char file_name[FILE_MAX_LEN] = {0};
	int ret = SNMP_COLLECT_OK;
	time_t now = 0;
	unsigned long temp_ip = 0;

	if(NULL == item || NULL == file_path )
	{
		sct_log_write(ERROR, "write_task_error:parameter is null");
		return SNMP_COLLECT_NG;
	}
	
	ob = json_object_new_object();

	now = time(NULL);
	
	sct_log_write(DEBUG, "write_task_error:In.");

	/*init task error json*/
	json_object_object_add(ob, TASK_HEADER_V, json_object_new_string(COLLIE_VERSION_1));

	temp_ip = inet_addr(item->ip_addr);
	if(temp_ip == -1)
	{
		sct_log_write(ERROR, "sct_init_json_object change ip failed.");
		return SNMP_COLLECT_NG;
	}
	temp_ip = ntohl(temp_ip);
	json_object_object_add(ob, TASK_HEADER_TS, json_object_new_int64(now));
	json_object_object_add(ob, TASK_HEADER_IP, json_object_new_int64(temp_ip));
	json_object_object_add(ob, TASK_HEADER_MID, json_object_new_int64(item->keyid));
	json_object_object_add(ob, TASK_HEADER_INT, json_object_new_int(item->intervals));
	json_object_object_add(ob, TASK_HEADER_STATUS, json_object_new_int(result));

	/*json object change to string*/
	send_buff = (char *)json_object_to_json_string(ob);
	if(NULL == send_buff)
	{
		sct_log_write(ERROR, "error json change to string failed.");
		return SNMP_COLLECT_NG;
	}

	memset(&file_name, 0, FILE_MAX_LEN);
	sprintf(file_name, "%s/%s.log", file_path, TASK_ERROR_FILE);
	
	/*write error json to logstash path, /var/log/collie/ptids/error_task.log*/
	ret = sct_write_logstash(send_buff, file_name);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "sct_write_task_error: write task error file failed.");
		return SNMP_COLLECT_NG;
	}
		
	return SNMP_COLLECT_OK;
	
}

static int sct_get_hash_key(unsigned long keyid)
{
	return (keyid%SLOT_NUM);
}

sct_hashset_t *sct_find_oid_hash(unsigned long  keyid, const sct_hashmap_table *mibs)
{
	int key = -1;
	sct_hashset_t *mib = NULL;

	if(NULL == mibs)
	{
		sct_log_write(ERROR, "find_oid_hash:parameter is null");
		return NULL;
	}
	
	key = sct_get_hash_key(keyid);

	sct_log_write(DEBUG, "find oid hash key is %d", key);
	
	if(mibs->entry[key] != NULL)
	{
		mib = mibs->entry[key];
	}
	else 
	{
		return NULL;
	}
	while(mib != NULL)
	{
		/*find keyid node*/
		if(mib->keyid == keyid)
		{
			return mib;
		}
		
		mib = mib->next;
	}

	return NULL;
}

/******************************************************************
 * Function: init_mibs_hash
 * Purpose: read mibs.conf, and save to hash table, the key is keyid%29,
 *		and if have clash save list's next
 * 
 * Author: Li qinglong                                          *
 *****************************************************************/
static int sct_init_mibs_hash(const char *file_path, sct_hashmap_table *mibs)
{
	FILE *fp = NULL;
	char line[READ_MAX_LEN] = {0};
	sct_hashset_t *mib = NULL;
	int ret = SNMP_COLLECT_OK;
	int key = -1;

	if(NULL == file_path || NULL == mibs)
	{
		sct_log_write(ERROR, "sct_init_mibs_hash:file_path or mibs is NULL."); 
		return SNMP_COLLECT_NG;
	}

	fp = fopen(file_path, "r");
	if(NULL == fp)
	{
		sct_log_write(ERROR, "sct_init_mibs_hash:open failed."); 
		return SNMP_COLLECT_NG;
	}

	mibs->entry = malloc(SLOT_NUM*sizeof(sct_hashset_t *));
	if(NULL == mibs->entry)
	{
		sct_log_write(ERROR, "sct_init_mibs_hash:mibs malloc failed."); 
		return SNMP_COLLECT_NG;
	}
	memset(mibs->entry, 0, SLOT_NUM*sizeof(sct_hashset_t *));
	
	/*read file's one line*/
	memset(&line, 0, READ_MAX_LEN);
	while(fgets(line, READ_MAX_LEN, fp) != NULL) 
	{
		if(0 == strncmp (line, "#", 1) || 0 == strncmp(line, "\n", sizeof("\n")))
		{
			continue;
		}

		/*parse json str to struct mib*/
		ret = sct_parse_json_oid(line, &mib);
		if(ret < SNMP_COLLECT_OK)
		{
			sct_log_write(ERROR, "parse json string failed");
			mib = NULL;
			continue;
		}

		if(NULL == mib)
		{
			sct_log_write(ERROR, "parse mib is null.");
			continue;
		}

		/*get mib's key, and save to g_mibs*/
		key = sct_get_hash_key(mib->keyid);
		
		if(NULL == mibs->entry[key])
		{
			mibs->entry[key] = mib;
		}
		else
		{
			mib->next = mibs->entry[key];
			mibs->entry[key] = mib;
		}
		memset(&line, 0, READ_MAX_LEN);
	}

	fclose(fp);

	return SNMP_COLLECT_OK;
}

/******************************************************************
 * Function: init_item_list
 * Purpose: init some task list, save to three list,g_run_list g_bak_list g_fail_list.
 * 	    g_run_list: process poller this list and run the task;
 * 	    g_bak_list: from new file, and g_run_list will replace this list;
 *	    g_fail_list: save snmp get failed's task, and will retry this list's task node.
 *
 * Parameters: the flag is TYPE_INIT and TYPE_UPDATE, 
 *             for init g_run_list or g_bak_list
 *
 * Author: Li qinglong                                          *
 *****************************************************************/
int sct_init_item_list(sct_config_t *config, sct_list_table *list, sct_hashmap_table *mibs, int flag)
{
	FILE *fp = NULL;
	char line[READ_MAX_LEN] = {0};
	sct_item_list item;
	sct_hashset_t *walk_oid = NULL;
	int ret = SNMP_COLLECT_OK;
	char task_path[FILE_MAX_LEN] = {0}, logstash_path[FILE_MAX_LEN] = {0};

	if(NULL == config || NULL == list || NULL == mibs)
	{
		sct_log_write(ERROR, "sct_init_item_list: parameter config list or mibs is NULL.");
		return SNMP_COLLECT_NG;
	}

	memset(&task_path, 0, FILE_MAX_LEN);
	strncpy(task_path, config->task_conf, FILE_MAX_LEN);
	
	fp = fopen(task_path, "r");
	if(NULL == fp)
	{
		sct_log_write(ERROR, "open failed.");
		return SNMP_COLLECT_NG;
	}

	memset(&line, 0, READ_MAX_LEN);
	while(fgets(line, sizeof(line), fp) != NULL)
	{
		if(0 == strncmp (line, "#", 1) || 0 == strncmp(line, "\n", sizeof("\n")))
		{
			continue;
		}

		memset(&item, 0, sizeof(sct_item_list));
		/*parse json str to struct item*/
		ret = sct_parse_json_task(line, &item);
		if(ret < 0)
		{
			sct_log_write(ERROR, "parse json string failed");
			continue;
		}

		if(909000001012 == item.keyid)
		{
			item.type = LINUX_PING_TYPE;
		}
		else
		{
			/*keyid is hash key, get oid info from mibs_hash*/
			walk_oid = sct_find_oid_hash(item.keyid, mibs);
			if(NULL == walk_oid)
			{
				sct_log_write(ERROR, "key is %ld not found task's oid.", item.keyid);
				continue;
			}
			item.type = walk_oid->type;
		}

		memset(&logstash_path, 0, FILE_MAX_LEN);
		strncpy(logstash_path, config->logstash_path, FILE_MAX_LEN);

		if(LINUX_JSON_TYPE == item.type|| GET_TYPE == item.type || TCP_SHELL_TYPE == item.type)
		{
			/*snmp get task for testing and insert list*/
			//ret = sct_snmp_get_test(item.ip_addr, walk_oid->oid[0].oid_val);
			ret = 0;
			if(TYPE_UPDATE == flag)
			{
				if(ret < 0)
				{
					/*testing failed to insert fail list*/
	                                sct_log_write(ERROR, "snmp get test failed.");
        	                        list->bakerr_list = sct_insert_item_list(list->bakerr_list, &item);
                	                sct_write_task_error(logstash_path, &item, ret);
				}
				else
				{
					list->bak_list = sct_insert_item_list(list->bak_list, &item);
				}
			}
			else if(TYPE_INIT == flag)
			{
				if(ret < 0)
                                {
					/*testing failed to insert fail list*/
	                                sct_log_write(ERROR, "snmp get test failed.");
        	                        list->err_list = sct_insert_item_list(list->err_list, &item);
                	                sct_write_task_error(logstash_path, &item, ret);
                                }
                                else
                                {
					list->run_list = sct_insert_item_list(list->run_list, &item);	
                                }
				
			}
			else
			{
				 sct_log_write(ERROR, "flag is error.");
                                 continue;
			}
		}

		else if(WALK_TYPE == item.type)
		{			
			/*walk index result and insert list*/
			ret = sct_snmp_walk_index(&item, walk_oid->oid[0].oid_val, flag, list);
			if(ret < 0)
			{
				
				/*testing failed to insert fail list*/
				sct_log_write(ERROR, "walk index failed.");
				if(TYPE_INIT == flag)
				{
					list->err_list = sct_insert_item_list(list->err_list, &item);
				}
				else if(TYPE_UPDATE == flag)
				{
					list->bakerr_list = sct_insert_item_list(list->bakerr_list, &item);
				}
				sct_write_task_error(logstash_path, &item, ret);
			}
		}			
		else if(LINUX_PING_TYPE == item.type)
		{
			if(TYPE_INIT == flag)
			{
				list->run_list = sct_insert_item_list(list->run_list, &item);
			}
			else if(TYPE_UPDATE == flag)
			{
				list->bak_list = sct_insert_item_list(list->bak_list, &item);
			}	
		}
		else
		{
			sct_log_write(ERROR, "%s %ld type is error.", item.ip_addr, item.keyid);
			continue;
		}
		memset(&line, 0, READ_MAX_LEN);
	}

	if(fp)
		fclose(fp);
	return 0;
}


/******************************************************************
 * Function: init
 * Purpose: read config file, snmp.conf, task.conf, mibs.conf
 *               init some global variable(g_conf, g_misb_hash, g_run_list)
 *
 * Author: Li qinglong                                          *
 *****************************************************************/

int sct_init(char *config_file, sct_config_t *config, sct_hashmap_table *mibs, sct_list_table *list)
{
	int ret = SNMP_COLLECT_NG;

	if(NULL == config_file || NULL == config || NULL == mibs || NULL == list)
	{
		sct_log_write(ERROR, "sct_init: parameter is NULL.");
		return SNMP_COLLECT_NG;
	}

	/*read conf, path is /run/collie/collie_snmpcollect/conf/, save to g_conf*/
	ret = sct_read_collect_config(config_file, config);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "init: read config failed");
		return SNMP_COLLECT_NG;
	}

	/*get task.conf md5 value, save to g_conf.file_md5*/
	ret = sct_get_task_md5(config->mib_conf, config->file_md5);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "init: get task md5 failed.");
		return SNMP_COLLECT_NG;
	}
	
	/*read mibs.conf, save mibs hash table, len is 29*/
	ret = sct_init_mibs_hash(config->mib_conf, mibs);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "init: init mib hash tables failed.");
		return SNMP_COLLECT_NG;
	}

	/*read task.conf, snmp test and save to run list*/
	ret = sct_init_item_list(config, list, mibs,TYPE_INIT);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "init: init item list failed.");
		return SNMP_COLLECT_NG;
	}

	return SNMP_COLLECT_OK;
}
