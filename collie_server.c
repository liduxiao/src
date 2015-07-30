#include "collie_server.h"

#define CLIENT_PORT 7779

#define RECV_MAX_LEN 4096

#define MAX_CONNECT 20
#define MAX_THREAD 4
#define MAX_FD_NUM 2
#define ERROR 3
#define SCT_LOG_PATH "/var/log/collie_snmpserver.log"
#define CONFIG_PID_FILE "/var/run/collie_snmpserver"

static FILE     *fpid = NULL;
static int      fdpid = -1;
static unsigned int s_thread_para[MAX_THREAD][4];
static pthread_t s_tid[MAX_THREAD];
pthread_mutex_t s_mutex[MAX_THREAD];

static int	fdset[MAX_FD_NUM] = {-1, -1};
static int	max_fd;

int create_pid_file(const char *pidfile)
{
	int fd = -1;
	struct stat	buf;
	struct flock	fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	/* check if pid file already exists */
	if (0 == stat(pidfile, &buf)){
		if (-1 == (fd = open(pidfile, O_WRONLY | O_APPEND))){
			sct_log_write(ERROR, "cannot open PID file [%s]: %s", pidfile, strerror(errno));
			return COLLIE_SERVER_NG;
		}

		if (-1 == fcntl(fd, F_SETLK, &fl)){
			close(fd);
			sct_log_write(ERROR, "Is this process already running? Could not lock PID file [%s]: %s",
					pidfile, strerror(errno));
			return COLLIE_SERVER_NG;
		}

		close(fd);
	}

	/* open pid file */
	if (NULL == (fpid = fopen(pidfile, "w"))){
		sct_log_write(ERROR, "cannot create PID file [%s]: %s", pidfile, strerror(errno));
		return COLLIE_SERVER_NG;
	}

	/* lock file */
	if (-1 != (fdpid = fileno(fpid))){
		fcntl(fdpid, F_SETLK, &fl);
		fcntl(fdpid, F_SETFD, FD_CLOEXEC);
	}

	/* write pid to file */
	fprintf(fpid, "%d", (int)getpid());
	fflush(fpid);

	return COLLIE_SERVER_OK;
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
	char time_buff[64] = {0};
	char level_str[][8] = {{""},{"DEBUG"},{"WARNING"},{"ERROR"}};

	/*write log to /var/log/collie/snmp.log*/
	fp = fopen(SCT_LOG_PATH, "a+");
	if (NULL == fp){
		return COLLIE_SERVER_NG;
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

	return COLLIE_SERVER_OK;
}


int handle_data(int sockfd, struct sockaddr_in addr)
{
	int ret = 0;
	int fd = 0;
	fd_set rsets;
	int len = sizeof(struct sockaddr_in);

	int i = 0, j = 0;

	fdset[0] = sockfd;
	max_fd = sockfd;
	while(1){
		
		FD_ZERO(&rsets);
		for (i=0; i < MAX_FD_NUM; i++) {
			if (fdset[i] != -1) {
				FD_SET(fdset[i], &rsets);
			}	
		}

		ret = select(max_fd + 1, &rsets, NULL, NULL, NULL);
        if (ret == -1) {
			if (errno == EINTR){
				continue;
			}
			else{
				perror("select error");
				exit(0);
			}
		}
    	else if (ret) {
			if (FD_ISSET(sockfd, &rsets))
			{
				if((fd = accept(sockfd, (struct sockaddr *)&addr, (socklen_t *)&len)) == -1) {
					sct_log_write(ERROR,"accept socket error: %s(errno: %d)\n",strerror(errno),errno);
					continue;
				}
				sct_log_write(ERROR,"accept a new  connection from client: %s\n", inet_ntoa(addr.sin_addr));
				for(j = 0; j < MAX_THREAD; j++){ 
					if (0 == s_thread_para[j][0]) 
						break;
				}
				if (j >= MAX_THREAD){
					sct_log_write(ERROR,"thread_pool is full %d%d%d%d",s_thread_para[0][0],s_thread_para[1][0],s_thread_para[2][0],s_thread_para[3][0]);
					shutdown(fd, SHUT_RDWR);
					close(fd);
					continue;
				} 
				//copy parameter to gobal
				s_thread_para[j][0] = 1;
				s_thread_para[j][1] = fd;

				//thread unlock
				pthread_mutex_unlock(s_mutex + j); 

				fdset[1] = fd;
				max_fd = fd;
			} 
			
		}
		else{
        		sct_log_write(ERROR,"time out\n");
    	}

	}
	
	return 0;
}

int get_result(char *key, char *result)
{
	FILE *fp = NULL;
	char cmd[4096];
	int read_len = 0;

	if(NULL == key)	{
		return -1;
	}

	memset(cmd, 0, 4096);
	sprintf(cmd, "sh /run/collie/collie_snmpserver/userscripts/%s.sh", key);

	fp = popen(cmd, "r");
	if(NULL == fp)	{
		return -1;
	}

	read_len = fread(result, 1, 4096, fp);
	if(ferror(fp))	{
		return -1;
	}
	else
		result[read_len] = '\0';
	
	if(fp)
		pclose(fp);

	
	return read_len;
}

static int init_thread_pool(void) 
{ 
	int i, rc; 
	
	for(i = 0; i < MAX_THREAD; i++) {
		//connection and index
		s_thread_para[i][0] = 0;
		s_thread_para[i][3] = i;
		pthread_mutex_lock(s_mutex + i);
	} 


	for(i = 0; i < MAX_THREAD; i++){ 
		rc = pthread_create(s_tid + i, 0, (void* (*)(void *))get_send_result, (void *)(s_thread_para[i])); 
		if (0 != rc) { 
			return(-1); 
		} 
	} 

	return(0); 
} 

void * get_send_result(unsigned int thread_para[]) 
{ 
	//临时变量 
	int sock_cli; 
	int pool_index; 


	char recv_buff[4096] = {0}, key[4096] = {0}; 
	int len; 

	//线程脱离创建者 
	pthread_detach(pthread_self()); 
	pool_index = thread_para[3]; 

wait_unlock: 
	pthread_mutex_lock(s_mutex + pool_index);

	
	sock_cli = thread_para[1];

	memset(recv_buff, 0, RECV_MAX_LEN);
	len = recv(sock_cli, recv_buff, sizeof(recv_buff), MSG_NOSIGNAL);
	if(len <= 0){
		sct_log_write(ERROR,"error is %s[%d].\n", strerror(errno),errno);
	} 

	strcpy(key, recv_buff);

	memset(recv_buff, 0, RECV_MAX_LEN);
	len = 0;
	len = get_result(key, recv_buff);

	//send result
	send(sock_cli, recv_buff, len, MSG_NOSIGNAL); 

	fdset[1] = -1;
	max_fd = sock_cli;	  
	//free connect
	shutdown(sock_cli, SHUT_RDWR); 
	close(sock_cli); 

	//thread is end, and flag is free
	thread_para[0] = 0;
	goto wait_unlock; 

	pthread_exit(NULL); 
}

int main()
{
	int sockfd = -1;
	struct sockaddr_in addr;
	int ret = 0;
	int len = sizeof(struct sockaddr_in);


	daemon(1, 0);
	if (-1 == create_pid_file(CONFIG_PID_FILE))
		exit(-1);
	
	atexit(daemon_stop);

	ret = init_thread_pool();
	if(ret < 0)	{
		exit(-1);
	}	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0){
		sct_log_write(ERROR,"socket errno %d, error is [%s]\n",errno, strerror(errno));
		return -1;
	}
	
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(CLIENT_PORT);

	ret = bind(sockfd, (struct sockaddr *)&addr, len);
	if(ret < 0){
		sct_log_write(ERROR,"bind errno %d, error is [%s]\n",errno, strerror(errno));
		return -1;
	}	
	
	ret = listen(sockfd, MAX_CONNECT);
	if(ret < 0){
		sct_log_write(ERROR,"listen errno %d, error is [%s]\n",errno, strerror(errno));
		return -1;
	}

	handle_data(sockfd, addr);

	close(sockfd);
	return 0;
}



