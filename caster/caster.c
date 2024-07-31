/*
 * NTRIP 1/2 caster
 */


#include "conf.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/thread.h>

#include "caster.h"
#include "config.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "util.h"
#include "sourcetable.h"
#include "fetcher_sourcetable.h"

#if DEBUG
  #ifdef THREADS
  const char *malloc_conf = "junk:true,retain:false";
  #else
  const char *malloc_conf = "junk:true,retain:false,narenas:4";
  #endif
#else
  const char *malloc_conf = "retain:false";
#endif

static void caster_log(void *arg, const char *fmt, va_list ap);
static void caster_alog(void *arg, const char *fmt, va_list ap);
static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *arg);

/*
 * Read user authentication file for the NTRIP server.
 */
static struct auth_entry *auth_parse(struct caster_state *caster, const char *filename) {
	struct parsed_file *p;
	p = file_parse(filename, 3, ":");

	if (p == NULL) {
		logfmt(&caster->flog, "Can't read or parse %s\n", filename);
		return NULL;
	}
	struct auth_entry *auth = (struct auth_entry *)malloc(sizeof(struct auth_entry)*(p->nlines+1));

	int n;
	for (n = 0; n < p->nlines; n++) {
		auth[n].key = mystrdup(p->pls[n][0]);
		auth[n].user = mystrdup(p->pls[n][1]);
		auth[n].password = mystrdup(p->pls[n][2]);
	}
	auth[n].key = NULL;
	auth[n].user = NULL;
	auth[n].password = NULL;
	file_free(p);
	return auth;
}

static void auth_free(struct auth_entry *this) {
	struct auth_entry *p = this;
	if (this == NULL)
		return;
	while (p->key || p->user || p->password) {
		free((char *)p->key);
		free((char *)p->user);
		free((char *)p->password);
		p++;
	}
	free(this);
}

static void
_caster_log(FILE *log, const char *fmt, va_list ap) {
	char date[36];
	logdate(date, sizeof date);
	fputs(date, log);
	vfprintf(log, fmt, ap);
}

static void
caster_alog(void *arg, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	_caster_log(this->alog.logfile, fmt, ap);
}

static void
caster_log(void *arg, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	_caster_log(this->flog.logfile, fmt, ap);
}

static struct caster_state *
caster_new(struct config *config, const char *config_file) {
	struct caster_state *this = (struct caster_state *)calloc(1, sizeof(struct caster_state));
	if (this == NULL)
		return this;

	struct event_base *base;
	struct evdns_base *dns_base;

	base = event_base_new();
	if (!base) {
		fprintf(stderr, "Could not initialize libevent!\n");
		return NULL;
	}
	dns_base = evdns_base_new(base, 1);
	if (!dns_base) {
		fprintf(stderr, "Could not initialize dns_base!\n");
		return NULL;
	}

	this->listeners = NULL;
	this->socks = NULL;
	this->sourcetable_fetcher = NULL;

	P_RWLOCK_INIT(&this->livesources.lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.lock, NULL);
	this->ntrips.next_id = 1;

	// Used only for access to source_auth and host_auth
	P_RWLOCK_INIT(&this->authlock, NULL);

	P_RWLOCK_INIT(&this->sourcetablestack.lock, NULL);

	this->config = config;
#ifdef THREADS
	this->joblist = joblist_new(this);
#endif
	int r1 = log_init(&this->flog, this->config->log, &caster_log, this);
	int r2 = log_init(&this->alog, this->config->access_log, &caster_alog, this);

	if (r1 < 0 || r2 < 0
#ifdef THREADS
		|| this->joblist == NULL
#endif
	) {
#ifdef THREADS
		if (this->joblist) joblist_free(this->joblist);
#endif
		if (r1 < 0) log_free(&this->flog);
		if (r2 < 0) log_free(&this->alog);
		free(this);
		return NULL;
	}

	this->base = base;
	this->dns_base = dns_base;
	TAILQ_INIT(&this->livesources.queue);
	TAILQ_INIT(&this->ntrips.queue);
	TAILQ_INIT(&this->sourcetablestack.list);
	return this;
}

void caster_free(struct caster_state *this) {
	event_free(this->signalpipe_event);
	event_free(this->signalhup_event);
	event_free(this->signalint_event);

	for (int i = 0; i < this->config->bind_count; i++)
		evconnlistener_free(this->listeners[i]);
	free(this->listeners);
	free(this->socks);
	free(this->sourcetable_fetcher);

	evdns_base_free(this->dns_base, 1);
	event_base_free(this->base);

	P_RWLOCK_WRLOCK(&this->sourcetablestack.lock);
	struct sourcetable *s;
	while ((s = TAILQ_FIRST(&this->sourcetablestack.list))) {
		TAILQ_REMOVE_HEAD(&this->sourcetablestack.list, next);
		sourcetable_free(s);
	}

#ifdef THREADS
	if (this->joblist) joblist_free(this->joblist);
#endif
	P_RWLOCK_DESTROY(&this->sourcetablestack.lock);
	P_RWLOCK_DESTROY(&this->livesources.lock);
	P_RWLOCK_DESTROY(&this->ntrips.lock);
	P_RWLOCK_DESTROY(&this->authlock);
	log_free(&this->flog);
	log_free(&this->alog);
	config_free(this->config);
	free(this);
}

/*
 * Configure and activate listening ports.
 */
static int caster_listen(struct caster_state *this) {
	if (this->config->bind_count == 0) {
		fprintf(stderr, "No configured ports to listen to, aborting.\n");
		return -1;
	}

	this->socks = (union sock *)malloc(sizeof(union sock)*this->config->bind_count);
	if (!this->socks) {
		fprintf(stderr, "Can't allocate socket addresses\n");
		return -1;
	}

	this->listeners = (struct evconnlistener **)malloc(sizeof(struct evconnlistener *)*this->config->bind_count);
	if (!this->listeners) {
		fprintf(stderr, "Can't allocate listeners\n");
		return -1;
	}

	/*
	 * Create listening socket addresses.
	 * Create a libevent listener for each.
	 */
	int err = 0;
	for (int i = 0; i < this->config->bind_count; i++) {
		int r, port;
		struct sockaddr *sin = (struct sockaddr *)(this->socks+i);
		size_t size_sin = 0;

		memset(&this->socks[i], 0, sizeof(this->socks[i]));

		port = htons(this->config->bind[i].port);
		r = inet_pton(AF_INET6, this->config->bind[i].ip, &this->socks[i].sin6.sin6_addr);
		if (r) {
			this->socks[i].sin6.sin6_port = port;
			this->socks[i].sin6.sin6_family = AF_INET6;
			size_sin = sizeof(struct sockaddr_in6);
		} else {
			r = inet_pton(AF_INET, this->config->bind[i].ip, &this->socks[i].sin.sin_addr);
			if (r) {
				this->socks[i].sin.sin_port = port;
				this->socks[i].sin.sin_family = AF_INET;
				size_sin = sizeof(struct sockaddr_in);
			} else {
				fprintf(stderr, "Invalid IP %s\n", this->config->bind[i].ip);
				err = 1;
				continue;
			}
		}
		this->listeners[i] = evconnlistener_new_bind(this->base, listener_cb, this,
			LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, this->config->bind[i].queue_size,
			sin, size_sin);
		if (!this->listeners[i]) {
			fprintf(stderr, "Could not create a listener for %s:%d!\n", this->config->bind[i].ip, this->config->bind[i].port);
			err = 1;
		}
	}

	if (err)
		return -1;
	return 0;
}

void caster_del_livesource(struct caster_state *this, struct livesource *livesource) {
	P_RWLOCK_WRLOCK(&this->livesources.lock);

	TAILQ_REMOVE(&this->livesources.queue, livesource, next);
	livesource_free(livesource);

	P_RWLOCK_UNLOCK(&this->livesources.lock);
}

static void
caster_reload_sourcetables(struct caster_state *caster) {
	struct sourcetable *s;
	struct sourcetable *stmp;
	struct sourcetable *snew;

	struct sourcetableq newtables;

	TAILQ_INIT(&newtables);

	P_RWLOCK_WRLOCK(&caster->sourcetablestack.lock);

	TAILQ_FOREACH_SAFE(s, &caster->sourcetablestack.list, next, stmp) {
		P_RWLOCK_WRLOCK(&s->lock);
		if (s->local && s->filename) {
			logfmt(&caster->flog, "Reloading %s\n", s->filename);
			snew = sourcetable_read(s->filename);
			if (snew) {
				TAILQ_REMOVE(&caster->sourcetablestack.list, s, next);
				TAILQ_INSERT_TAIL(&newtables, snew, next);
				sourcetable_free_unlocked(s);
				/* Skip the unlock below! */
				continue;
			}
		}
		P_RWLOCK_UNLOCK(&s->lock);
	}
	TAILQ_CONCAT(&caster->sourcetablestack.list, &newtables, next);

	P_RWLOCK_UNLOCK(&caster->sourcetablestack.lock);
}

static void
caster_reload_auth(struct caster_state *caster) {
	logfmt(&caster->flog, "Reloading %s and %s\n", caster->config->host_auth_filename, caster->config->source_auth_filename);

	P_RWLOCK_WRLOCK(&caster->authlock);

	if (caster->config->host_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, caster->config->host_auth_filename);
		if (tmp != NULL) {
			auth_free(caster->host_auth);
			caster->host_auth = tmp;
		}
	}
	if (caster->config->source_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, caster->config->source_auth_filename);
		if (tmp != NULL) {
			auth_free(caster->source_auth);
			caster->source_auth = tmp;
		}
	}

	P_RWLOCK_UNLOCK(&caster->authlock);
}

void my_bufferevent_free(struct ntrip_state *this, struct bufferevent *bev) {
	if (!this->bev_freed) {
		ntrip_log(this, LOG_EDEBUG, "bufferevent_free %p\n", bev);
		bufferevent_free(bev);
		this->bev_freed = 1;
	} else
		ntrip_log(this, LOG_DEBUG, "double free for bufferevent %p\n", bev);
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *arg)
{
	struct caster_state *caster = arg;
	struct event_base *base = caster->base;
	struct bufferevent *bev;

	int sndbuf;
	socklen_t size_sndbuf = sizeof(sndbuf);

	struct ntrip_state *st = ntrip_new(caster, NULL, 0, NULL);
	if (st == NULL) {
		logfmt(&caster->flog, "Error constructing ntrip_state for a new connection!");
		event_base_loopbreak(base);
		return;
	}

	st->start = time(NULL);
	memcpy(&st->peeraddr, sa, socklen);
	st->remote = 1;
	sockaddr_ipstr(&st->peeraddr.generic, st->remote_addr, sizeof st->remote_addr);

	sndbuf = caster->config->backlog_socket;
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, size_sndbuf) < 0)
		ntrip_log(st, LOG_NOTICE, "setsockopt SO_SNDBUF %d failed\n", sndbuf);

	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &size_sndbuf) >= 0) {
		ntrip_log(st, LOG_INFO, "New connection, ntrip_state=%p sndbuf=%d\n", st, sndbuf);
	} else {
		size_sndbuf = -1;
		ntrip_log(st, LOG_INFO, "New connection, ntrip_state=%p\n", st);
	}

	st->state = NTRIP_WAIT_HTTP_METHOD;

#ifdef THREADS
	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
#else
	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
#endif

	if (bev == NULL) {
		ntrip_log(st, LOG_CRIT, "Error constructing bufferevent!");
		event_base_loopbreak(base);
		P_RWLOCK_WRLOCK(&st->lock);
		ntrip_free(st, "listener_cb");
		return;
	}
	st->bev = bev;
	// evbuffer_defer_callbacks(bufferevent_get_output(bev), st->caster->base);
#ifdef THREADS
	bufferevent_setcb(bev, ntripsrv_workers_readcb, ntripsrv_workers_writecb, ntripsrv_workers_eventcb, st);
#else
	bufferevent_setcb(bev, ntripsrv_readcb, ntripsrv_writecb, ntripsrv_eventcb, st);
#endif
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	struct timeval read_timeout = { st->caster->config->ntripsrv_default_read_timeout, 0 };
	struct timeval write_timeout = { st->caster->config->ntripsrv_default_write_timeout, 0 };
	bufferevent_set_timeouts(bev, &read_timeout, &write_timeout);
	ntrip_log(st, LOG_DEBUG, "ntrip_state=%p bev=%p\n", st, bev);
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data) {
	struct event_base *base = user_data;
	struct timeval delay = { 0, 100 };

	printf("Caught an interrupt signal; exiting cleanly in 100 ms.\n");

	event_base_loopexit(base, &delay);
}

static void
signalpipe_cb(evutil_socket_t sig, short events, void *user_data) {
	printf("Caught SIGPIPE\n");
}

static void
signalhup_cb(evutil_socket_t sig, short events, void *arg) {
	struct caster_state *caster = (struct caster_state *)arg;
	printf("Caught SIGHUP\n");
	caster_reload_sourcetables(caster);
	caster_reload_auth(caster);
}

static struct caster_state *caster = NULL;

static
void event_log_redirect(int severity, const char *msg) {
	if (caster != NULL)
		logfmt(&caster->flog, "%s\n", msg);
	else
		fprintf(stderr, "%s\n", msg);
}

static int caster_set_signals(struct caster_state *this) {
	this->signalint_event = evsignal_new(this->base, SIGINT, signal_cb, (void *)this->base);
	if (!this->signalint_event || event_add(this->signalint_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return -1;
	}

	this->signalpipe_event = evsignal_new(this->base, SIGPIPE, signalpipe_cb, (void *)this->base);
	if (!this->signalpipe_event || event_add(this->signalpipe_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return -1;
	}

	this->signalhup_event = evsignal_new(this->base, SIGHUP, signalhup_cb, (void *)this);
	if (!this->signalhup_event || event_add(this->signalhup_event, 0) < 0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return -1;
	}
	return 0;
}

/*
 * Start a sourcetable fetcher (proxy)
 */
static int caster_start_fetcher(struct caster_state *this) {
	if (!this->config->proxy_count)
		return 0;

	struct sourcetable_fetch_args *a = (struct sourcetable_fetch_args *)malloc(sizeof(struct sourcetable_fetch_args));
	this->sourcetable_fetcher = a;
	a->host = this->config->proxy[0].host;
	a->port = this->config->proxy[0].port;
	a->refresh_delay = this->config->proxy[0].table_refresh_delay;
	a->caster = this;
	a->sourcetable = NULL;
	a->sourcetable_cb = NULL;
	fetcher_sourcetable_get(a);
	return 0;
}

int caster_main(char *config_file) {

#if DEBUG_EVENT
	event_enable_debug_mode();
	event_enable_debug_logging(EVENT_DBG_ALL);
	event_set_log_callback(event_log_redirect);
#endif

#ifdef THREADS
	if (evthread_use_pthreads() < 0) {
		fprintf(stderr, "Could not initialize evthreads!\n");
		return 1;
	}
#endif

	struct config *config = config_parse(config_file);

	if (!config) {
		fprintf(stderr, "Can't parse configuration from %s\n", config_file);
		return 1;
	}

	caster = caster_new(config);
	if (!caster) {
		fprintf(stderr, "Can't allocate caster\n");
		return 1;
	}

	caster_reload_auth(caster);

#if 0
	/*** v4+v6 SOCKET NOT USED AT THIS TIME ***/

	int fds = socket(AF_INET6, SOCK_STREAM, 0);
	if (fds < 0) {
		perror("Can't create socket");
	}


	int v4v6 = 0;
	if (setsockopt(fds, IPPROTO_IPV6, IPV6_V6ONLY, &v4v6, sizeof v4v6) < 0) {
		perror("Can't make v6+v4 socket");
		return 1;
	}
	if (evutil_make_socket_nonblocking(fds) < 0) {
		fprintf(stderr, "Can't make socket non-blocking\n");
		return 1;
	}
	// evutil_socket_t s = event_get_fd(listener);
	// int v6only = 0;
	// setsockopt(0, IPV6CTL_V6ONLY, IPV6CTL_V6ONLY, &v6only, sizeof v6only);
#endif

	struct sourcetable *local_table = sourcetable_read(caster->config->sourcetable_filename);
	if (local_table == NULL) {
		fprintf(stderr, "Can't read local sourcetable.\n");
		return 1;
	}

	TAILQ_INSERT_TAIL(&caster->sourcetablestack.list, local_table, next);

	if (caster_listen(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (caster_set_signals(caster) < 0) {
		caster_free(caster);
		return 1;
	}

#ifdef THREADS
	if (jobs_start_threads(caster, NTHREADS) < 0) {
		caster_free(caster);
		fprintf(stderr, "Could not create threads!\n");
		return 1;
	}
#endif

	caster_start_fetcher(caster);

	event_base_dispatch(caster->base);

	caster_free(caster);
	return 0;
}
