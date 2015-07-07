#ifndef __COLLIE_SERVER_H__
#define __COLLIE_SERVER_H__

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

void *get_send_result(unsigned int thread_para[]);
int sct_log_write(int level, char *fmt, ...);


#define COLLIE_SERVER_OK 0
#define COLLIE_SERVER_NG -1

#endif
