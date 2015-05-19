/**
 * File:crond_snmpget.c
 * Data:2014-05-19
 *
 * The file is walk many oid from task table and oids table, and
 * insert new table that task_oids
 *
 * Author:LiQinglong
 */

#include "snmp_collect.h"

#define SNMP_COLLECT_NG -1
#define SNMP_COLLECT_OK 0
#define TYPE_INIT 1
#define TYPE_UPDATE 2

#define TIME_BUFF_LEN 64
#define LEVEL_STR_LEN 8

#define SLEEP_ERR_TIME 180
#define SCT_LOG_PATH "/var/log/collie/snmpclient.log"
#define CONFIG_PID_FILE "/var/run/snmpclient.pid"
#define IPC_MSG_FLAG 1234

#define SCT_PARAMETER_NUM 3

int end_flag;

sct_config_t  g_conf;
sct_hashmap_table g_mibs;
sct_list_table g_list;

pthread_mutex_t run_lock;

int g_bak_status;

static FILE	*fpid = NULL;
static int	fdpid = -1;

int create_pid_file(const char *pidfile)
{
	int		fd;
	struct stat	buf;
	struct flock	fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	/* check if pid file already exists */
	if (0 == stat(pidfile, &buf))
	{
		if (-1 == (fd = open(pidfile, O_WRONLY | O_APPEND)))
		{
			sct_log_write(ERROR, "cannot open PID file [%s]: %s", pidfile, strerror(errno));
			return SNMP_COLLECT_NG;
		}

		if (-1 == fcntl(fd, F_SETLK, &fl))
		{
			close(fd);
			sct_log_write(ERROR, "Is this process already running? Could not lock PID file [%s]: %s",
					pidfile, strerror(errno));
			return SNMP_COLLECT_NG;
		}

		close(fd);
	}

	/* open pid file */
	if (NULL == (fpid = fopen(pidfile, "w")))
	{
		sct_log_write(ERROR, "cannot create PID file [%s]: %s", pidfile, strerror(errno));
		return SNMP_COLLECT_NG;
	}

	/* lock file */
	if (-1 != (fdpid = fileno(fpid)))
	{
		fcntl(fdpid, F_SETLK, &fl);
		fcntl(fdpid, F_SETFD, FD_CLOEXEC);
	}

	/* write pid to file */
	fprintf(fpid, "%d", (int)getpid());
	fflush(fpid);

	return SNMP_COLLECT_OK;
}

void	drop_pid_file(const char *pidfile)
{
	struct flock	fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	/* unlock file */
	if (-1 != fdpid)
		fcntl(fdpid, F_SETLK, &fl);

	/* close pid file */
	fclose(fpid);
	fpid = NULL;

	unlink(pidfile);
}
void daemon_stop()
{
	drop_pid_file(CONFIG_PID_FILE);
}
int sct_log_write(int level, char *fmt, ...)
{
	FILE *fp = NULL;
	va_list vargs;
	struct timeval current_time;
	struct tm *tm = NULL;
	long milliseconds = 0;
	char time_buff[TIME_BUFF_LEN] = {0};
	char level_str[][LEVEL_STR_LEN] = {{""},{"DEBUG"},{"WARNING"},{"ERROR"}};

	if(level < g_conf.log_level)
	{
		return SNMP_COLLECT_OK;
	}

	/*write log to /var/log/collie/snmp.log*/
	fp = fopen(SCT_LOG_PATH, "a+");
	if (NULL == fp)
	{
		return SNMP_COLLECT_NG;
	}
	memset(&current_time, 0, sizeof(struct timeval));

	/*log write time*/
	gettimeofday(&current_time, NULL);
	tm = localtime(&current_time.tv_sec);
	milliseconds = current_time.tv_usec / 1000;

	sprintf(time_buff, "%.4d%.2d%.2d:%.2d%.2d%.2d", tm->tm_year + 1900,
			tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

	va_start(vargs, fmt);
	vfprintf(fp, time_buff, vargs);
	vfprintf(fp, "    ", vargs);
	vfprintf(fp, level_str[level], vargs);
	vfprintf(fp, "    ", vargs);
	vfprintf(fp, fmt, vargs);
	vfprintf(fp, "\n", vargs);
	va_end(vargs);

	fflush(fp);

	if(fp)
		fclose(fp);

	return SNMP_COLLECT_OK;
}

void *sct_output_list(sct_item_list *head)
{

	if(head == NULL) return NULL;
	if(head->next == NULL)
	{
		sct_log_write(ERROR, "%s:%d,%ld",head->ip_addr,head->nextcheck,head->keyid);
		return NULL;
	}
	while(head->next!=NULL)
	{
		sct_log_write(ERROR, "%s:%d,%ld",head->ip_addr,head->nextcheck,head->keyid);
		head = head->next;
	}
	sct_log_write(ERROR, "%s:%d,%ld",head->ip_addr,head->nextcheck,head->keyid);
	return NULL;
	
}

void sct_output_all()
{

#ifdef DEBUG
	sct_log_write(ERROR, "--------running_head---------------------");
	sct_output_list(g_list.run_list);
	
	sct_log_write(ERROR, "--------fail_head---------------------");
	sct_output_list(g_list.err_list);	
	
	sct_log_write(ERROR, "--------bak_head---------------------");
	sct_output_list(g_list.bak_list);
#endif

}

int sct_destory_list(sct_item_list *head)
{
        sct_item_list *p = NULL, *q = NULL;
        if(NULL == head)
        {
                return SNMP_COLLECT_NG;
        }
	sct_log_write(DEBUG, "----------free head is %s %ld", head->ip_addr, head->keyid);
        p = head;
        while(p != NULL)
        {
                q = p->next;
                free(p);
                p=NULL;
                p = q;
        }

        return SNMP_COLLECT_OK;
}
void sig_term(int signo)
{	
	int msgfd;

	end_flag = 0;
	
	msgfd = msgget(IPC_MSG_FLAG, IPC_EXCL);
        if(msgfd < 0)
        {
        	sct_log_write(ERROR,"collie_snmpcollect is stoped.");
        }
	msgctl(msgfd, IPC_RMID, 0);	

	sct_destory_list(g_list.bak_list);
	sct_destory_list(g_list.err_list);
	sct_destory_list(g_list.run_list);
	sct_destory_list(g_list.bakerr_list);

	pthread_mutex_destroy(&run_lock);
	
	exit(-1);
}


/******************************************************************
 * Function: sct_fail_node_run
 * Purpose: read config file, snmp.conf, task.conf, mibs.conf
 *               init some global variable(g_conf, g_misb_hash, g_run_list)
 *
 * Author: Li qinglong                                          *
 *****************************************************************/
int sct_fail_node_run(sct_item_list *item)
{
	sct_hashset_t *walk_oid = NULL;
	int ret = SNMP_COLLECT_NG;

	if(NULL == item)
	{
		sct_log_write(ERROR, "fail_node_run: parameter item is NULL.");
		return SNMP_COLLECT_NG;
	}
	
	/*search hash tables, get task's oid*/
	walk_oid = sct_find_oid_hash(item->keyid, &g_mibs);
	if(NULL == walk_oid)
	{
		sct_log_write(ERROR, "fail_node_run: not found oid.");
		return SNMP_COLLECT_NG;
	}
	item->type = walk_oid->type;

	/*type is linux json result or snmp get*/
	if(LINUX_JSON_TYPE == walk_oid->type|| GET_TYPE == walk_oid->type)
	{
		ret = sct_snmp_get_test(item->ip_addr, walk_oid->oid[0].oid_val);
		if(ret < 0)
		{
			sct_log_write(ERROR, "fail_node_run: snmp get test failed.");
			return SNMP_COLLECT_NG;	
		}
		else 
		{
			/*sucess task insert to run list*/
			sct_log_write(WARNING, "fail_node_run: %s %s fail to run sucess.", item->ip_addr, item->keyid);
			
			pthread_mutex_lock(&run_lock);
			g_list.run_list= sct_insert_item_list(g_list.run_list, item);
			pthread_mutex_unlock(&run_lock);
			
			return SNMP_COLLECT_OK;
		}

	}

	/*type is walk*/
	else if(WALK_TYPE == walk_oid->type)
	{			
		/*walk index result, result is 1,2,3,4,5.......*/
		pthread_mutex_lock(&run_lock);
		ret = sct_snmp_walk_index(item, walk_oid->oid[0].oid_val, TYPE_INIT, &g_list);
		pthread_mutex_unlock(&run_lock);
		if(ret < 0)
		{
			sct_log_write(ERROR, "fail_node_run: walk index failed.");
			return SNMP_COLLECT_NG;
		}
		else 
		{
			sct_log_write(ERROR, "fail_node_run: %s %s fail to run sucess.", item->ip_addr, item->keyid);
			return SNMP_COLLECT_OK;
		}
	}			
	else
	{
		sct_log_write(ERROR, "fail_node_run: type is error.");
		return SNMP_COLLECT_NG;
	}

	return SNMP_COLLECT_NG;
}

/******************************************************************
 * Function: sct_poller_fail_list
 * Purpose: read config file, snmp.conf, task.conf, mibs.conf
 *               init some global variable(g_conf, g_misb_hash, g_run_list)
 *
 * Author: Li qinglong                                          *
 *****************************************************************/
int sct_poller_fail_list()
{
	sct_item_list *item = NULL, *q = NULL, *p = NULL;
//	sct_hashset_t *walk_oid;
	int ret = SNMP_COLLECT_NG;

	if(NULL == g_list.err_list)
	{
		return SNMP_COLLECT_OK;
	}

	item = g_list.err_list;

	/*poller the err list*/
	while(item != NULL)
	{
		/*node is last*/
		if(NULL == item->next)
		{
			p = item;
			/*get item test, if ok insert run list*/
			ret = sct_fail_node_run(item);
			if(SNMP_COLLECT_OK == ret)
			{
				/*node is signal, free head*/
				if(item == g_list.err_list)
				{
					free(g_list.err_list);
					g_list.err_list = NULL;
					break;
				}
				else
				{
					free(p);
					p = NULL;
					q->next = NULL;
				}
			}
			else
			{
				break;
			}
		}
		else
		{
			/*get item test, if ok insert run list*/
			ret = sct_fail_node_run(item);
			if(SNMP_COLLECT_OK == ret)
			{
				if(item == g_list.err_list)
				{
					q = item->next;
					free(g_list.err_list);
					g_list.err_list = NULL;
					g_list.err_list = q;
					item = q;
					continue;
				}
				else
				{
					q->next = item->next;
					free(p);
					p = NULL;
					item = q->next;
					continue;
				}
			}
			else
			{
				q = item;
				item = item->next;
			}
		}
		
	}

	return SNMP_COLLECT_OK;
}

int sct_change_head()
{
	sct_item_list *p = NULL, *q = NULL;

	p = g_list.run_list;
	q = g_list.err_list;

	/*new list replace old list*/
	g_list.run_list = g_list.bak_list;
	g_list.err_list = g_list.bakerr_list;

	/*free old list*/
	sct_destory_list(p);
	sct_destory_list(q);

	g_list.bak_list = NULL;	
	g_list.bakerr_list = NULL;

	return SNMP_COLLECT_OK;
}

/******************************************************************
 * Function: update_poller
 * Purpose: read config file, update g_bak_head and retry failed task
 *datea is null
 * Author: Li qinglong                                          *
 *****************************************************************/
 
void sct_update_poller(void *data)
{
	char md5_result[MD5_RESULT_LINE+1] = {0};
	int ret = 0, sleeptime = 0;
	
	
	while(end_flag)
	{
		sleeptime = SLEEP_TIME;
		sleep(sleeptime);
		
		memset(&md5_result, 0, MD5_RESULT_LINE+1);
		/*get task.conf md5 value, and compare old md5(g_conf.file_md5)*/
		ret = sct_get_task_md5(g_conf.task_conf, md5_result);
		
		if(ret < 0)
		{
			continue;
		}
		
		
		if(0 != strcmp(md5_result, g_conf.file_md5))
		{
			/*init new item list, head is "g_bak_head"*/
			g_bak_status = BAK_STATUS_START;

			sct_init_item_list(&g_conf, &g_list, &g_mibs, TYPE_UPDATE);

			g_bak_status = BAK_STATUS_END;
		}

		strncpy(g_conf.file_md5,md5_result, MD5_RESULT_LINE+1);

		/*poller failed task, while g_fail_list*/
		sct_poller_fail_list();
		
	}
}

static int sct_poller_run_list(int msgfd)
{
	sct_item_list *task_node = NULL;
	int ret = SNMP_COLLECT_OK;
	
	if(g_list.run_list == NULL)
	{
		sct_log_write(ERROR, "item list is null, wait thread update item.");
		return SNMP_COLLECT_NG;
	}

	pthread_mutex_lock(&run_lock);

	/*get run list's head node is timed task*/
	task_node = g_list.run_list;
	/*
	if(g_list.run_list->next == NULL)
		g_list.run_list = NULL;
	else
		g_list.run_list = g_list.run_list->next;
	*/
	/*send task to child process*/
	ret = msgsnd(msgfd, task_node, sizeof(sct_item_list), IPC_NOWAIT);
	if(ret < 0)
	{
		sct_log_write(WARNING, "send task buff failed, send task is %s, %ld", task_node->ip_addr, task_node->keyid);
		/*insert task node to run list*/
	        //g_list.run_list = sct_insert_item_list(g_list.run_list, task_node);
		pthread_mutex_unlock(&run_lock);
		return -2;
	}

	if(g_list.run_list->next == NULL)
                g_list.run_list = NULL;
        else
                g_list.run_list = g_list.run_list->next;	
	sct_log_write(DEBUG, "send msg node is %s:%d,%ld",task_node->ip_addr,task_node->nextcheck,task_node->keyid);	
	/*calculate task's next send time*/
	/*nextcheck is timed, eg. 5s task, nextcheck is now=142136782+5s*/
	task_node->nextcheck = time(NULL) + task_node->intervals;

	/*insert task node to run list*/
	g_list.run_list = sct_insert_item_list(g_list.run_list, task_node);

	pthread_mutex_unlock(&run_lock);
	free(task_node);
	
	return SNMP_COLLECT_OK;
}

static int parse_parameter(int argc, char **args, char *config_file)
{

	if(argc != SCT_PARAMETER_NUM || NULL == args ||NULL == config_file)
	{
		sct_log_write(ERROR, "parse_parameter: parameter is NULL!");
		return SNMP_COLLECT_NG;
	}

	/*judge parameter*/
	if(0 == strncmp(args[1], "-c", 2))
	{
		strncpy(config_file, args[2], strlen(args[2]));
	}
	else
	{
		sct_log_write(ERROR, "parameter error!");
		return SNMP_COLLECT_NG;
	}
	
	return SNMP_COLLECT_OK;
}

static int sct_calculate_sleeptime()
{
	unsigned long nexttime = 0;
	int sleeptime = 0;
	
	/*calculate head node nextcheck and sleep some seconds*/
	nexttime = g_list.run_list->nextcheck;

	sleeptime = nexttime - time(NULL);

	if(sleeptime < 0)
	{
		sleeptime = 0;
	}
	sct_log_write(DEBUG, "sleeptime is %d",sleeptime);

	return sleeptime;
}

int main(int argc, char **args) 
{
	int i = 0;
	int msgfd = -1;

	int task_count = 0;
	int server_num = 0;
	pid_t pid;
	int ret = 0;
	char config_file[FILE_MAX_LEN] = {0};
	
	int sleeptime = 0;
	pthread_t update_th;

	sct_log_write(DEBUG, "main IN");
	
	ret = parse_parameter(argc, args, config_file);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "snmp collect read config file failed.");
		return SNMP_COLLECT_NG;
	}

	memset(&g_conf, 0, sizeof(sct_config_t));
	memset(&g_mibs, 0, sizeof(sct_hashmap_table));
	memset(&g_list, 0, sizeof(sct_list_table));
	
	daemon(1, 0);
	if (SNMP_COLLECT_NG == create_pid_file(CONFIG_PID_FILE))
		exit(-1);
	atexit(daemon_stop);

	ret = sct_init(config_file, &g_conf, &g_mibs, &g_list);
	if(ret < SNMP_COLLECT_OK)
	{
		sct_log_write(ERROR, "snmp collect read config file failed.");
		return SNMP_COLLECT_NG;
	}

	if(signal(SIGTERM, sig_term) == SIG_ERR)
	{
		return SNMP_COLLECT_NG;
	}

	if(signal(SIGINT, sig_term) == SIG_ERR)
        {
		return SNMP_COLLECT_NG;
        }

	if(signal(SIGQUIT, sig_term) == SIG_ERR)
        {
		return SNMP_COLLECT_NG;
        }

	
	//daemon(1, 0);
	
	end_flag = 1;

	pthread_mutex_init(&run_lock, 0);

	/*thread is poller failed item and read task.conf to update new g_bak_list*/
	ret = pthread_create(&update_th, NULL, (void *)sct_update_poller, NULL);
	if(ret < 0)
	{
		sct_log_write(ERROR, "create upadte thread failed.");
		return SNMP_COLLECT_NG;
	}


	/*calculate child process number*/

	task_count = g_conf.threads;

	/*fork child process, and function in else branch*/
	for (i = 0; i < task_count; i++)
	{
		if ((pid = fork()) < 0)
		{
			sct_log_write(ERROR, "ERR Fork process failed.");
			return SNMP_COLLECT_NG;
		} 
		else if (0 == pid)
		{
			server_num = i + 1;
			break;
		}
	}

	/*main functions, calculate task time and msg send task to child process*/
	if (0 == server_num)
	{

		/*create msg 1024*/
		msgfd = msgget(IPC_MSG_FLAG, IPC_CREAT|0660);
		if(msgfd < 0){
				sct_log_write(ERROR, "ERR Create msg failed.");
				return SNMP_COLLECT_NG;
		}

		while(end_flag)
		{
			ret = sct_poller_run_list(msgfd);
			if(SNMP_COLLECT_OK != ret)
			{
				if(ret != -2)
				{
					sleep(SLEEP_ERR_TIME);
				}
				else	
				{
					sleep(1);
				}
				/*if have new task, replace new list to run list, and destory old list*/
                if(BAK_STATUS_END == g_bak_status)
                {
                        sct_change_head();
                        g_bak_status = BAK_STATUS_FREE;
                }
				continue;
			}

			/*calculate next time, get head node time - now*/
			sleeptime = 0;
			sleeptime = sct_calculate_sleeptime();
			sct_log_write(DEBUG, "sleeptime is %d.", sleeptime);
			
			while(sleeptime--)
			{
				sleep(1);
				
				/*if have new task, replace new list to run list, and destory old list*/
				if(BAK_STATUS_END == g_bak_status)
				{
					sct_change_head();
					g_bak_status = BAK_STATUS_FREE;
				}
			}
		}

		wait(&i);

		/*delete IPC msg*/
		msgctl(msgfd, IPC_RMID, 0);
		exit(0);

	}

	else
	{
		/*child recv msg task, and get value change to json*/
		sct_log_write(DEBUG, "start fork%d.....", i);
		sleep(1);
		sct_child_process(i);
	}

	return SNMP_COLLECT_OK;
}

