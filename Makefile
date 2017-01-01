CC=gcc
CFLAGS=-fPIC -O2 -c -g -Wall -Wformat-security -fno-strict-aliasing
LDFLAGS=--shared `mysql_config --libs`
DESTDIR=

all: pam_mariadb.so

pam_mariadb.so: config.o database.o hash.o pam_mariadb.o utils.o
	$(LD) $(LDFLAGS) -o pam_mariadb.so config.o database.o hash.o pam_mariadb.o utils.o

config.o: config.c config.h
	$(CC) $(CFLAGS) -c config.c

database.o: database.c
	$(CC) $(CFLAGS) -c database.c

hash.o: hash.c
	$(CC) $(CFLAGS) -c hash.c

pam_mariadb.o: pam_mariadb.c
	$(CC) $(CFLAGS) -c pam_mariadb.c

utils.o: utils.c
	$(CC) $(CFLAGS) -c utils.c

clean:
	$(RM) *.so *.o

install: pam_mariadb.so
	install -D -m 0755 pam_mariadb.so $(DESTDIR)/usr/lib64/security/pam_mariadb.so
