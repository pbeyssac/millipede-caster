DEST_DIR	=	/usr/local/sbin/
#
# -DDEBUG_JEMALLOC
#	enable jemalloc statistics
#
#OPT	=	-DDEBUG_JEMALLOC
OPT	=

CFLAGS	=	-g $(OPT) -I/usr/local/include -Wall
LDFLAGS	=	-L/usr/local/lib -levent_core -levent_extra -levent_pthreads -levent_openssl -lcyaml -lssl -lcrypto -ljson-c -lpthread -lm

SRCS	=	adm.c api.c caster.c conf.c config.c fetcher_sourcetable.c gelf.c graylog_sender.c hash.c http.c ip.c jobs.c livesource.c log.c main.c ntrip_common.c ntrip_task.c ntripcli.c ntripsrv.c packet.c redistribute.c sourceline.c sourcetable.c util.c
OBJS	=	adm.o api.o caster.o conf.o config.o fetcher_sourcetable.o gelf.o graylog_sender.o hash.o http.o ip.o jobs.o livesource.o log.o main.o ntrip_common.o ntrip_task.o ntripcli.o ntripsrv.o packet.o redistribute.o sourceline.o sourcetable.o util.o
BINS	=	tests caster

TESTOBJS	=	conf.o log.o tests.o util.o ip.o

all:	$(BINS)

depend:
	mkdep $(CFLAGS) $(SRCS)

install:	caster
	install -m 0755 caster $(DEST_DIR)


clean:
	rm -f .depend $(OBJS) $(BINS) tests.o

tests:	$(TESTOBJS)
	cc -o tests -lm $(TESTOBJS) $(LDFLAGS)

caster:	$(OBJS)
	cc -Wall -g -o caster $(OBJS) $(LDFLAGS)
