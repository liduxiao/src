#include <stdio.h>

int main()
{
	char recv_buff[4096] = {0};
	int recv_len = 0;
	
	int epfd = -1;
	int i = 0;
	


	int fd = -1,sockfd = -1;
	struct sockaddr_in addr;
	int len = sizeof(struct sockaddr_in);
	int send_len = 0, recv_len = 0;
	char key[32] = {0};

	keyid = keyid % 90900000;
	sprintf(key, "%ld", keyid);


	epfd = epoll_create(4096);

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
		return -1;
	}

	
	send_len = send(sockfd, key, strlen(key), MSG_NOSIGNAL);
	if(send_len <=0)
	{
		sct_log_write(ERROR, "send failed.");
	}

	
	epoll_ctl(epfd, EPOLL_CTL_ADD, c_connect().fd[i], &ev);
	
	for(;;)
	{
		nfds = epoll_wait(epdf, events, 4096, -1);
		for(i = 0; i < nfds; i++){
			memset(recv_buff, 0, 4096);
			recv_len = recv(sockfd, recv_buff, 4096, 0);
			if(recv_len <= 0)
			{
				sct_log_write(ERROR, "recv result errno is %s[%d].", strerror(errno), errno); 
			}
			
			memcpy(result->str, recv_buff, recv_len);
			result->str[recv_len] = '\0';
		}
		
	}

	epoll_ctl(epfd, EPOLL_CTL_DEL, c_connect().fd[i], &ev)
	close(sockfd);	
}

int sct_tcp_get(char *ip_addr, unsigned long keyid, snmp_result *result)
{
	
	
	return SNMP_COLLECT_OK;
}

