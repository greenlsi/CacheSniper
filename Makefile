CC=gcc
CFLAGS=-Werror -mrtm
LIB_PATH = $(shell pwd)

all: libTable.so server send_request attack_tsx

attack_tsx: LDLIBS= -lm -L$(LIB_PATH) -lTable
attack_tsx: common.o cache_utils.o attack_tsx.o

cache_utils.o: common.o

send_request: send_request.o

libTable.so: Table.o
	gcc -shared -o $(LIB_PATH)/$@ $^

Table.o: Table.c
	gcc -c -Wall -Werror -fpic $^

common.o: LDLIBS= -lm

server.o: server.c
	gcc -c -o $@ $^

server: server.o libTable.so
	gcc -o $@ server.o -L$(LIB_PATH) -lTable

clean:
	$(RM) *.o *~ *.so
	$(RM) server send_request attack_tsx
