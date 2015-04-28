CC = gcc

BIN += collie_snmpclient

CFLAGS +=-g -Wall -O

INCLUDE = -I../include/
LIBDIR = -L../lib -L/usr/lib64/

LIB = -lnetsnmp -lcrypto -ljson -lpthread
RM = rm -f
all: $(BIN)

collie_snmpclient :
	$(CC) $(CFLAGS) $(INCLUDE)  $(LIBDIR) $(LIB) -o $@ snmp_collect.c init.c child_process.c
#	mv collie_snmpclient ../bin/
clean:
	$(RM) $(BIN) *.core
