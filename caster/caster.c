/*
 * NTRIP 1/2 caster
 */


#include "conf.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
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
#include "ip.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "util.h"
#include "sourcetable.h"
#include "fetcher_sourcetable.h"

#if DEBUG
  const char *malloc_conf = "junk:true,retain:false";
#else
  const char *malloc_conf = "retain:false";
#endif

static void caster_log(void *arg, const char *fmt, va_list ap);
static void caster_alog(void *arg, const char *fmt, va_list ap);
static int caster_start_fetchers(struct caster_state *this);
static void caster_reload_fetchers(struct caster_state *this);
static void caster_free_fetchers(struct caster_state *this);
static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *arg);

/*
 * Read user authentication file for the NTRIP server.
 */
static struct auth_entry *auth_parse(struct caster_state *caster, const char *filename) {
	struct parsed_file *p;
	p = file_parse(filename, 3, ":", 0);

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
		strfree((char *)p->key);
		strfree((char *)p->user);
		strfree((char *)p->password);
		p++;
	}
	free(this);
}

void caster_log_error(struct caster_state *this, char *orig) {
	char s[256];
	strerror_r(errno, s, sizeof s);
	logfmt(&this->flog, "%s: %s (%d)\n", orig, s, errno);
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
	this->sourcetable_fetchers = NULL;
	this->sourcetable_fetchers_count = 0;
	this->blocklist = NULL;


	P_RWLOCK_INIT(&this->livesources.lock, NULL);
	P_MUTEX_INIT(&this->livesources.delete_lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.free_lock, NULL);
	this->ntrips.next_id = 1;

	this->ntrips.ipcount = hash_table_new(509);

	// Used only for access to source_auth and host_auth
	P_RWLOCK_INIT(&this->configlock, NULL);

	P_RWLOCK_INIT(&this->sourcetablestack.lock, NULL);

	this->config = config;
	this->config_file = config_file;

	char *last_slash = strrchr(config_file, '/');
	if (last_slash) {
		this->config_dir = (char *)strmalloc(last_slash - config_file + 1);
		if (this->config_dir) {
			memcpy(this->config_dir, config_file, last_slash - config_file);
			this->config_dir[last_slash - config_file] = '\0';
		}
	} else
		this->config_dir = mystrdup(".");

	int current_dir = open(".", O_DIRECTORY);
	if (this->config_dir) chdir(this->config_dir);

	this->joblist = threads ? joblist_new(this) : NULL;
	int r1 = log_init(&this->flog, this->config->log, &caster_log, this);
	int r2 = log_init(&this->alog, this->config->access_log, &caster_alog, this);

	fchdir(current_dir);
	close(current_dir);

	if (r1 < 0 || r2 < 0 || !this->config_dir || (threads && this->joblist == NULL) || this->ntrips.ipcount == NULL) {
		if (this->joblist) joblist_free(this->joblist);
		if (r1 < 0) log_free(&this->flog);
		if (r2 < 0) log_free(&this->alog);
		if (this->ntrips.ipcount) hash_table_free(this->ntrips.ipcount);
		strfree(this->config_dir);
		free(this);
		return NULL;
	}

	this->base = base;
	this->dns_base = dns_base;
	TAILQ_INIT(&this->livesources.queue);
	TAILQ_INIT(&this->ntrips.queue);
	TAILQ_INIT(&this->ntrips.free_queue);
	this->ntrips.n = 0;
	this->ntrips.nfree = 0;
	TAILQ_INIT(&this->sourcetablestack.list);
	return this;
}

void caster_free(struct caster_state *this) {
	if (threads)
		jobs_stop_threads(this->joblist);

	if (this->signalpipe_event)
		event_free(this->signalpipe_event);
	if (this->signalhup_event)
		event_free(this->signalhup_event);
	if (this->signalint_event)
		event_free(this->signalint_event);

	for (int i = 0; i < this->config->bind_count; i++)
		if (this->listeners[i])
			evconnlistener_free(this->listeners[i]);
	free(this->listeners);
	free(this->socks);
	hash_table_free(this->ntrips.ipcount);

	caster_free_fetchers(this);

	auth_free(this->host_auth);
	auth_free(this->source_auth);
	if (this->blocklist)
		prefix_table_free(this->blocklist);

	evdns_base_free(this->dns_base, 1);
	event_base_free(this->base);

	P_RWLOCK_WRLOCK(&this->sourcetablestack.lock);
	struct sourcetable *s;
	while ((s = TAILQ_FIRST(&this->sourcetablestack.list))) {
		TAILQ_REMOVE_HEAD(&this->sourcetablestack.list, next);
		sourcetable_free(s);
	}
	P_RWLOCK_UNLOCK(&this->sourcetablestack.lock);

	if (this->joblist) joblist_free(this->joblist);
	P_RWLOCK_DESTROY(&this->sourcetablestack.lock);
	P_RWLOCK_DESTROY(&this->livesources.lock);
	P_MUTEX_DESTROY(&this->livesources.delete_lock);
	P_RWLOCK_DESTROY(&this->ntrips.lock);
	P_RWLOCK_DESTROY(&this->ntrips.free_lock);
	P_RWLOCK_DESTROY(&this->configlock);
	log_free(&this->flog);
	log_free(&this->alog);
	strfree(this->config_dir);
	config_free(this->config);
	libevent_global_shutdown();
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
		union sock *sin = this->socks+i;

		port = htons(this->config->bind[i].port);
		r = ip_convert(this->config->bind[i].ip, sin);
		if (!r) {
			fprintf(stderr, "Invalid IP %s\n", this->config->bind[i].ip);
			err = 1;
			continue;
		}
		if (sin->generic.sa_family == AF_INET)
			sin->v4.sin_port = port;
		else
			sin->v6.sin6_port = port;
		this->listeners[i] = evconnlistener_new_bind(this->base, listener_cb, this,
			LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, this->config->bind[i].queue_size,
			(struct sockaddr *)sin, sin->generic.sa_len);
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
	P_MUTEX_LOCK(&this->livesources.delete_lock);
	P_RWLOCK_WRLOCK(&this->livesources.lock);

	TAILQ_REMOVE(&this->livesources.queue, livesource, next);
	livesource_free(livesource);

	P_RWLOCK_UNLOCK(&this->livesources.lock);
	P_MUTEX_UNLOCK(&this->livesources.delete_lock);
}

static void
caster_reload_sourcetables(struct caster_state *caster) {
	struct sourcetable *s;
	struct sourcetable *stmp;

	struct sourcetable *local_table
		= sourcetable_read(caster->config->sourcetable_filename, caster->config->sourcetable_priority);

	P_RWLOCK_WRLOCK(&caster->sourcetablestack.lock);

	TAILQ_FOREACH_SAFE(s, &caster->sourcetablestack.list, next, stmp) {
		P_RWLOCK_WRLOCK(&s->lock);
		if (s->local && s->filename) {
			logfmt(&caster->flog, "Removing %s\n", s->filename);
			TAILQ_REMOVE(&caster->sourcetablestack.list, s, next);
			sourcetable_free_unlocked(s);
			/* Skip the unlock below! */
			continue;
		}
		P_RWLOCK_UNLOCK(&s->lock);
	}

	logfmt(&caster->flog, "Reloading %s\n", caster->config->sourcetable_filename);
	TAILQ_INSERT_TAIL(&caster->sourcetablestack.list, local_table, next);

	P_RWLOCK_UNLOCK(&caster->sourcetablestack.lock);
}

static void
caster_reopen_logs(struct caster_state *this) {
	log_reopen(&this->flog, this->config->log);
	log_reopen(&this->alog, this->config->access_log);
}

static void
caster_reload_auth(struct caster_state *caster) {
	logfmt(&caster->flog, "Reloading %s and %s\n", caster->config->host_auth_filename, caster->config->source_auth_filename);

	P_RWLOCK_WRLOCK(&caster->configlock);

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

	P_RWLOCK_UNLOCK(&caster->configlock);
}

static void
caster_reload_blocklist(struct caster_state *caster) {
	P_RWLOCK_WRLOCK(&caster->configlock);
	struct prefix_table *p;
	if (caster->blocklist) {
		prefix_table_free(caster->blocklist);
		caster->blocklist = NULL;
	}

	if (caster->config->blocklist_filename) {
		logfmt(&caster->flog, "Reloading %s\n", caster->config->blocklist_filename);
		p = prefix_table_new(caster->config->blocklist_filename);
		caster->blocklist = p;
	}
	P_RWLOCK_UNLOCK(&caster->configlock);
}

static void caster_reload_config(struct caster_state *this) {
	struct config *config;
	if (!(config = config_parse(this->config_file))) {
		fprintf(stderr, "Can't parse configuration from %s\n", this->config_file);
		return;
	}
	config_free(this->config);
	this->config = config;
}

/*
 * reload with chdir to allow relative paths in the configuration.
 */
static void caster_chdir_reload(struct caster_state *this, int reopen_logs) {
	int current_dir = open(".", O_DIRECTORY);
	chdir(this->config_dir);
	if (reopen_logs)
		caster_reopen_logs(this);
	caster_reload_sourcetables(this);
	caster_reload_auth(this);
	caster_reload_blocklist(this);
	fchdir(current_dir);
	close(current_dir);
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *arg)
{
	struct caster_state *caster = arg;
	struct event_base *base = caster->base;
	struct bufferevent *bev;

	if (threads)
		bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
	else
		bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	if (bev == NULL) {
		logfmt(&caster->flog, "Error constructing bufferevent!\n");
		close(fd);
		return;
	}

	struct ntrip_state *st = ntrip_new(caster, bev, NULL, 0, NULL);
	if (st == NULL) {
		logfmt(&caster->flog, "Error constructing ntrip_state for a new connection!\n");
		bufferevent_free(bev);
		close(fd);
		return;
	}

	ntrip_set_peeraddr(st, sa, socklen);

	st->state = NTRIP_WAIT_HTTP_METHOD;

	if (ntrip_register_check(st) < 0) {
		ntrip_deferred_free(st, "listener_cb");
		return;
	}

	ntrip_log(st, LOG_INFO, "New connection\n");

	// evbuffer_defer_callbacks(bufferevent_get_output(bev), st->caster->base);

	if (threads)
		bufferevent_setcb(bev, ntripsrv_workers_readcb, ntripsrv_workers_writecb, ntripsrv_workers_eventcb, st);
	else
		bufferevent_setcb(bev, ntripsrv_readcb, ntripsrv_writecb, ntripsrv_eventcb, st);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	struct timeval read_timeout = { st->caster->config->ntripsrv_default_read_timeout, 0 };
	struct timeval write_timeout = { st->caster->config->ntripsrv_default_write_timeout, 0 };
	bufferevent_set_timeouts(bev, &read_timeout, &write_timeout);
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
	printf("Reloading configuration\n");
	caster_reload_config(caster);
	/*
	 * TBD: listeners reload.
	 */
	caster_reload_fetchers(caster);
	caster_chdir_reload(caster, 1);
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
 * Start sourcetable fetchers (proxy)
 */
static int caster_start_fetchers(struct caster_state *this) {
	if (!this->config->proxy_count)
		return 0;

	struct sourcetable_fetch_args **fetchers = (struct sourcetable_fetch_args **)malloc(sizeof(struct sourcetable_fetch_args *)*this->config->proxy_count);

	this->sourcetable_fetchers = fetchers;
	this->sourcetable_fetchers_count = this->config->proxy_count;

	for (int i = 0; i < this->sourcetable_fetchers_count; i++) {
		fetchers[i] = fetcher_sourcetable_new(this,
			this->config->proxy[i].host,
			this->config->proxy[i].port,
			this->config->proxy[i].table_refresh_delay,
			this->config->proxy[i].priority);
		if (fetchers[i])
			fetcher_sourcetable_start(fetchers[i]);
	}

	return 0;
}

static void caster_reload_fetchers(struct caster_state *this) {
	if (!this->config->proxy_count) {
		caster_free_fetchers(this);
		return;
	}
	struct sourcetable_fetch_args **new_fetchers = (struct sourcetable_fetch_args **)malloc(sizeof(struct sourcetable_fetch_args *)*this->config->proxy_count);

	/*
	 * For each entry in the new config, recycle a similar entry in the old configuration.
	 */
	for (int i = 0; i < this->config->proxy_count; i++) {
		struct sourcetable_fetch_args *p = NULL;
		for (int j = 0; j < this->sourcetable_fetchers_count; j++) {
			if (this->sourcetable_fetchers[j] == NULL)
				/* Already cleared */
				continue;
			if (!strcmp(this->sourcetable_fetchers[j]->host, this->config->proxy[i].host)
			&& this->sourcetable_fetchers[j]->port == this->config->proxy[i].port) {
				p = this->sourcetable_fetchers[j];
				/* Found, clear in the old table */
				this->sourcetable_fetchers[j] = NULL;
				break;
			}
		}
		if (!p) {
			/* Not found, create */
			p = fetcher_sourcetable_new(this,
				this->config->proxy[i].host, this->config->proxy[i].port,
				this->config->proxy[i].table_refresh_delay,
				this->config->proxy[i].priority);
			fprintf(stderr, "New fetcher %s:%d\n", this->config->proxy[i].host, this->config->proxy[i].port);
		} else {
			fetcher_sourcetable_reload(p,
				this->config->proxy[i].table_refresh_delay,
				this->config->proxy[i].priority);
			fprintf(stderr, "Reusing fetcher %s:%d\n", this->config->proxy[i].host, this->config->proxy[i].port);
		}
		new_fetchers[i] = p;
	}
	/*
	 * Stop and free all remaining fetchers in the old configuration.
	 */
	for (int j = 0; j < this->sourcetable_fetchers_count; j++)
		if (this->sourcetable_fetchers[j]) {
			fprintf(stderr, "Stopping fetcher %s:%d\n", this->sourcetable_fetchers[j]->host, this->sourcetable_fetchers[j]->port);
			fetcher_sourcetable_free(this->sourcetable_fetchers[j]);
		}
	free(this->sourcetable_fetchers);
	this->sourcetable_fetchers_count = this->config->proxy_count;
	this->sourcetable_fetchers = new_fetchers;
}

static void caster_free_fetchers(struct caster_state *this) {
	struct sourcetable_fetch_args **a = this->sourcetable_fetchers;
	if (!a)
		return;
	for (int i = 0; i < this->sourcetable_fetchers_count; i++) {
		if (a[i])
			fetcher_sourcetable_free(a[i]);
	}
	free(a);
	this->sourcetable_fetchers = NULL;
	this->sourcetable_fetchers_count = 0;
}

int caster_main(char *config_file) {

#if DEBUG_EVENT
	event_enable_debug_mode();
	event_enable_debug_logging(EVENT_DBG_ALL);
	event_set_log_callback(event_log_redirect);
#endif

	if (threads && evthread_use_pthreads() < 0) {
		fprintf(stderr, "Could not initialize evthreads!\n");
		return 1;
	}

	struct config *config = config_parse(config_file);

	if (!config) {
		fprintf(stderr, "Can't parse configuration from %s\n", config_file);
		return 1;
	}

	caster = caster_new(config, config_file);
	if (!caster) {
		fprintf(stderr, "Can't allocate caster\n");
		return 1;
	}

	caster_chdir_reload(caster, 0);

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


	if (caster_listen(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (caster_set_signals(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (threads && jobs_start_threads(caster->joblist, nthreads) < 0) {
		caster_free(caster);
		fprintf(stderr, "Could not create threads!\n");
		return 1;
	}

	caster_start_fetchers(caster);

	event_base_dispatch(caster->base);

	caster_free(caster);
	return 0;
}
