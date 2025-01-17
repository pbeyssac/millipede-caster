DEST_DIR	=	/usr/local/sbin/
#
# -DDEBUG_JEMALLOC
#	enable jemalloc statistics
#
#OPT	=	-DDEBUG_JEMALLOC
OPT	=

CFLAGS	=	-g $(OPT) -I/usr/local/include -Wall
LDFLAGS	=	-L/usr/local/lib -levent_core -levent_extra -levent_pthreads -lcyaml -lpthread -ljson-c -lm

SRCS	=	adm.c caster.c conf.c config.c fetcher_sourcetable.c http.c ip.c jobs.c livesource.c log.c main.c ntrip_common.c ntripcli.c ntripsrv.c packet.c redistribute.c sourceline.c sourcetable.c util.c
OBJS	=	adm.o caster.o conf.o config.o fetcher_sourcetable.o http.o ip.o jobs.o livesource.o log.o main.o ntrip_common.o ntripcli.o ntripsrv.o packet.o redistribute.o sourceline.o sourcetable.o util.o
BINS	=	tests caster

TESTOBJS	=	conf.o tests.o util.o

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
