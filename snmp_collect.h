#ifndef __SNMP_COLLECT_H__
#define __SNMP_COLLECT_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
#include <pthread.h>
#include <signal.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "json.h"
#include "init.h"
#include "child_process.h"

#define DEBUG 1
#define WARNING 2
#define ERROR 3

#define MD5_RESULT_LINE 32
#define SLEEP_TIME 300



#define BAK_STATUS_FREE 0
#define BAK_STATUS_START 1
#define BAK_STATUS_END 2

int sct_log_write(int level, char *fmt, ...);

#endif

