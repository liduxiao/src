CC = gcc

BIN += collie_snmpserver

CFLAGS +=-g -Wall -O

LIB = -lpthread
RM = rm -f
all: $(BIN)

collie_snmpserver :
	$(CC) $(CFLAGS)  $(LIB) -o $@ collie_server.c

clean:
	$(RM) $(BIN) *.core
