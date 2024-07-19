DEST_DIR	=	/usr/local/sbin/
OPT	=
#OPT	=	-DTHREADS
CFLAGS	=	-g $(OPT) -I/usr/local/include -Wall
LDFLAGS	=	-L/usr/local/lib -levent_core -levent_extra -levent_pthreads -lcyaml -lpthread -lm

SRCS	=	caster.c config.c fetcher_sourcetable.c http.c jobs.c livesource.c log.c main.c ntrip_common.c ntripcli.c ntripsrv.c packet.c redistribute.c sourceline.c sourcetable.c util.c
OBJS	=	caster.o config.o fetcher_sourcetable.o http.o jobs.o livesource.o log.o main.o ntrip_common.o ntripcli.o ntripsrv.o packet.o redistribute.o sourceline.o sourcetable.o util.o
BINS	=	tests caster

all:	$(BINS)

depend:
	mkdep $(CFLAGS) $(SRCS)

install:	caster
	install -m 0755 $> $(DEST_DIR)


clean:
	rm -f .depend $(OBJS) $(BINS) tests.o

tests:	tests.o util.o
	cc -o tests -lm $>

caster:	$(OBJS)
	cc -Wall -g $(LDFLAGS) -o caster $>
