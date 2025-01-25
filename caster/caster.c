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
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "caster.h"
#include "config.h"
#include "ip.h"
#include "jobs.h"
#include "livesource.h"
#include "log.h"
#include "ntrip_common.h"
#include "ntrip_task.h"
#include "ntripsrv.h"
#include "util.h"
#include "sourcetable.h"
#include "fetcher_sourcetable.h"

#if DEBUG
  const char *malloc_conf = "junk:true,retain:false";
#else
  const char *malloc_conf = "retain:false";
#endif

static void caster_log(void *arg, int level, const char *fmt, va_list ap);
static void caster_alog(void *arg, int level, const char *fmt, va_list ap);
static int caster_start_fetchers(struct caster_state *this);
static int caster_reload_fetchers(struct caster_state *this);
static void caster_free_fetchers(struct caster_state *this);
static void listener_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int socklen, void *arg);

/*
 * Read user authentication file for the NTRIP server.
 */
static struct auth_entry *auth_parse(struct caster_state *caster, const char *filename) {
	struct parsed_file *p;
	p = file_parse(filename, 3, ":", 0, &caster->flog);

	if (p == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Can't read or parse %s\n", filename);
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
	logfmt(&this->flog, LOG_ERR, "%s: %s (%d)\n", orig, s, errno);
}

static void
_caster_log(FILE *log, int level, const char *fmt, va_list ap) {
	char date[36];
	logdate(date, sizeof date);
	fputs(date, log);
	vfprintf(log, fmt, ap);
}

static void
caster_alog(void *arg, int dummy, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	_caster_log(this->alog.logfile, -1, fmt, ap);
}

static void
caster_log(void *arg, int level, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	if (level > this->config->log_level)
		return;
	_caster_log(this->flog.logfile, level, fmt, ap);
}

/*
 * Callback for OpenSSL's ERR_print_errors_cb()
 */

int
caster_tls_log_cb(const char *str, size_t len, void *u) {
	logfmt(&((struct caster_state *)u)->flog, LOG_ERR, "%s\n", str);
	// Undocumentend OpenSSL API: return >0 if ok, <=0 if failed
	return 1;
}

static struct caster_state *
caster_new(struct config *config, const char *config_file) {
	int err = 0;
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
	this->listeners_count = 0;
	this->sourcetable_fetchers = NULL;
	this->sourcetable_fetchers_count = 0;
	this->blocklist = NULL;

	this->ssl_client_ctx = SSL_CTX_new(TLS_client_method());
	if (this->ssl_client_ctx == NULL) {
		ERR_print_errors_cb(caster_tls_log_cb, this);
		return NULL;
	}
	SSL_CTX_set_verify(this->ssl_client_ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(this->ssl_client_ctx) != 1) {
		ERR_print_errors_cb(caster_tls_log_cb, this);
		return NULL;
	}

	P_RWLOCK_INIT(&this->livesources.lock, NULL);
	P_MUTEX_INIT(&this->livesources.delete_lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.free_lock, NULL);
	this->ntrips.next_id = 1;

	this->ntrips.ipcount = hash_table_new(509, NULL);

	// Used for access to source_auth, host_auth, blocklist and listener config
	P_RWLOCK_INIT(&this->configlock, NULL);

	P_RWLOCK_INIT(&this->sourcetablestack.lock, NULL);

	this->config = config;
	this->config_file = config_file;

	char *abs_config_path = realpath(config_file, NULL);
	if (abs_config_path == NULL) {
		fprintf(stderr, "Error: can't determine absolute path for config file %s\n", config_file);
		err = 1;
		this->config_dir = NULL;
	} else {
		char *last_slash = strrchr(abs_config_path, '/');
		if (last_slash) {
			if (last_slash == abs_config_path)
				last_slash[1] = '\0';
			else
				last_slash[0] = '\0';
			this->config_dir = abs_config_path;
		} else
			this->config_dir = mystrdup(".");
	}

	int current_dir = open(".", O_DIRECTORY);
	if (this->config_dir) chdir(this->config_dir);

	this->joblist = threads ? joblist_new(this) : NULL;
	int r1 = log_init(&this->flog, this->config->log, &caster_log, this);
	int r2 = log_init(&this->alog, this->config->access_log, &caster_alog, this);

	fchdir(current_dir);
	close(current_dir);

	if (err || r1 < 0 || r2 < 0 || !this->config_dir || (threads && this->joblist == NULL) || this->ntrips.ipcount == NULL) {
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

static void caster_free_listener(struct listener *this) {
	if (this->listener)
		evconnlistener_free(this->listener);
	if (this->tls && this->ssl_server_ctx)
		SSL_CTX_free(this->ssl_server_ctx);
	free(this);
}

static void caster_free_listeners(struct caster_state *this) {
	for (int i = 0; i < this->listeners_count; i++)
		caster_free_listener(this->listeners[i]);
	free(this->listeners);
	this->listeners = NULL;
	this->listeners_count = 0;
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

	caster_free_listeners(this);
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
 * Load TLS certificates from file paths.
 */
static int listener_load_certs(struct listener *this, char *tls_full_certificate_chain, char *tls_private_key) {
	if (SSL_CTX_use_certificate_chain_file(this->ssl_server_ctx, tls_full_certificate_chain) <= 0)
		return -1;
	if (SSL_CTX_use_PrivateKey_file(this->ssl_server_ctx, tls_private_key, SSL_FILETYPE_PEM) <= 0)
		return -1;
	if (!SSL_CTX_check_private_key(this->ssl_server_ctx)) {
		char ip[64];
		logfmt(&this->caster->flog, LOG_ERR, "Private key for %s does not match the certificate public key\n", ip_str_port(&this->sockaddr, ip, sizeof ip));
		return -1;
	}
	return 0;
}

/*
 * Set-up or update TLS server configuration.
 */
static int listener_setup_tls(struct listener *this, struct config_bind *config) {
	if (!this->ssl_server_ctx) {
		this->ssl_server_ctx = SSL_CTX_new(TLS_server_method());
		if (this->ssl_server_ctx == NULL) {
			ERR_print_errors_cb(caster_tls_log_cb, this->caster);
			return -1;
		}
	}
	if (listener_load_certs(this, config->tls_full_certificate_chain, config->tls_private_key) < 0) {
		ERR_print_errors_cb(caster_tls_log_cb, this->caster);
		SSL_CTX_free(this->ssl_server_ctx);
		this->ssl_server_ctx = NULL;
		return -1;
	}
	return 0;
}

/*
 * Configure a listening port for libevent.
 */
static int caster_start_listener(struct caster_state *this, struct config_bind *config, union sock *sin, struct listener *listener) {
	listener->listener = NULL;
	listener->sockaddr = *sin;
	listener->caster = this;
	int tls = config->tls;
	listener->tls = tls;
	listener->ssl_server_ctx = NULL;

	if (config->tls && config->tls_full_certificate_chain && config->tls_private_key) {
		if (listener_setup_tls(listener, config) < 0)
			return -1;
	}

	listener->listener = evconnlistener_new_bind(this->base, listener_cb, listener,
		LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, config->queue_size,
		(struct sockaddr *)sin, sin->generic.sa_len);
	if (!listener->listener) {
		logfmt(&this->flog, LOG_ERR, "Could not create a listener for %s:%d!\n", config->ip, config->port);
		return -1;
	}
	return 0;
}

/*
 * Reconfigure listening ports, reusing already existing sockets if possible.
 */
static int caster_reload_listeners(struct caster_state *this) {
	union sock sin;
	unsigned short port;
	int r, i;
	struct listener **new_listeners;
	char ip[64];

	P_RWLOCK_WRLOCK(&this->configlock);
	if (this->config->bind_count == 0) {
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.\n");
		if (this->listeners)
			caster_free_listeners(this);
		P_RWLOCK_UNLOCK(&this->configlock);
		return -1;
	}

	new_listeners = (struct listener **)malloc(sizeof(struct listener *)*this->config->bind_count);
	if (!new_listeners) {
		logfmt(&this->flog, LOG_CRIT, "Can't allocate listeners\n");
		if (this->listeners)
			caster_free_listeners(this);
		P_RWLOCK_UNLOCK(&this->configlock);
		return -1;
	}

	/*
	 * Create listening socket addresses.
	 * Create a libevent listener for each.
	 */
	int current_dir = open(".", O_DIRECTORY);
	chdir(this->config_dir);

	int nlisteners = 0;

	for (i = 0; i < this->config->bind_count; i++) {
		struct config_bind *config = this->config->bind + i;
		port = htons(config->port);
		r = ip_convert(config->ip, &sin);
		if (!r) {
			logfmt(&this->flog, LOG_ERR, "Invalid IP %s\n", this->config->bind[i].ip);
			continue;
		}
		if (sin.generic.sa_family == AF_INET)
			sin.v4.sin_port = port;
		else
			sin.v6.sin6_port = port;

		/*
		 * Try to find and recycle an existing listener entry
		 */
		struct listener *recycled_listener = NULL;
		int j;
		for (j = 0; j < this->listeners_count; j++) {
			if (this->listeners[j] && !ip_cmp(&sin, &this->listeners[j]->sockaddr)) {
				recycled_listener = this->listeners[j];
				break;
			}
		}
		if (recycled_listener) {
			if (config->tls && listener_setup_tls(recycled_listener, config) < 0) {
				logfmt(&this->flog, LOG_ERR, "Can't reuse listener %s: TLS setup failed\n", ip_str_port(&sin, ip, sizeof ip));
				recycled_listener = NULL;
			} else {
				if (recycled_listener->tls && !config->tls) {
					recycled_listener->tls = 0;
					SSL_CTX_free(recycled_listener->ssl_server_ctx);
				}
				logfmt(&this->flog, LOG_INFO, "Reusing listener %s\n", ip_str_port(&sin, ip, sizeof ip));
				new_listeners[nlisteners++] = recycled_listener;
				this->listeners[j] = NULL;
			}
		}
		if (!recycled_listener) {
			/*
			 * No reusable listener found, or reuse failed, start a new listener instance.
			 */
			struct listener *new_listener = (struct listener *)malloc(sizeof(struct listener));
			if (new_listener) {
				if (caster_start_listener(this, this->config->bind+i, &sin, new_listener) >= 0) {
					new_listeners[nlisteners++] = new_listener;
					logfmt(&this->flog, LOG_INFO, "Opening listener %s\n", ip_str_port(&sin, ip, sizeof ip));
				} else {
					logfmt(&this->flog, LOG_ERR, "Unable to open listener %s\n", ip_str_port(&sin, ip, sizeof ip));
					caster_free_listener(new_listener);
				}
			}
		}
	}
	fchdir(current_dir);
	close(current_dir);

	/*
	 * Drop remaining listening sockets we haven't reused.
	 */
	for (int j = 0; j < this->listeners_count; j++)
		if (this->listeners[j]) {
			logfmt(&this->flog, LOG_INFO, "Closing listener %s\n", ip_str_port(&this->listeners[j]->sockaddr, ip, sizeof ip));
			caster_free_listener(this->listeners[j]);
		}

	free(this->listeners);
	this->listeners = new_listeners;
	this->listeners_count = nlisteners;

	P_RWLOCK_UNLOCK(&this->configlock);

	if (this->listeners_count == 0) {
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.\n");
		return -1;
	}
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

static int
caster_reload_sourcetables(struct caster_state *caster) {
	int r = 0;
	struct sourcetable *s;
	struct sourcetable *stmp;

	struct sourcetable *local_table
		= sourcetable_read(caster->config->sourcetable_filename, caster->config->sourcetable_priority);

	if (local_table == NULL)
		r = -1;

	P_RWLOCK_WRLOCK(&caster->sourcetablestack.lock);

	TAILQ_FOREACH_SAFE(s, &caster->sourcetablestack.list, next, stmp) {
		P_RWLOCK_WRLOCK(&s->lock);
		if (s->local && s->filename) {
			logfmt(&caster->flog, LOG_INFO, "Removing %s\n", s->filename);
			TAILQ_REMOVE(&caster->sourcetablestack.list, s, next);
			sourcetable_free_unlocked(s);
			/* Skip the unlock below! */
			continue;
		}
		P_RWLOCK_UNLOCK(&s->lock);
	}

	logfmt(&caster->flog, LOG_INFO, "Reloading %s\n", caster->config->sourcetable_filename);
	TAILQ_INSERT_TAIL(&caster->sourcetablestack.list, local_table, next);

	P_RWLOCK_UNLOCK(&caster->sourcetablestack.lock);

	return r;
}

static int
caster_reopen_logs(struct caster_state *this) {
	int r = 0;
	if (log_reopen(&this->flog, this->config->log) < 0)
		r = -1;
	if (log_reopen(&this->alog, this->config->access_log) < 0)
		r = -1;
	return r;
}

static int
caster_reload_auth(struct caster_state *caster) {
	int r = 0;
	logfmt(&caster->flog, LOG_INFO, "Reloading %s and %s\n", caster->config->host_auth_filename, caster->config->source_auth_filename);

	P_RWLOCK_WRLOCK(&caster->configlock);

	if (caster->config->host_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, caster->config->host_auth_filename);
		if (tmp != NULL) {
			auth_free(caster->host_auth);
			caster->host_auth = tmp;
		} else
			r = -1;
	}
	if (caster->config->source_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, caster->config->source_auth_filename);
		if (tmp != NULL) {
			auth_free(caster->source_auth);
			caster->source_auth = tmp;
		} else
			r = -1;
	}

	P_RWLOCK_UNLOCK(&caster->configlock);
	return r;
}

static int
caster_reload_blocklist(struct caster_state *caster) {
	int r = 0;
	P_RWLOCK_WRLOCK(&caster->configlock);
	struct prefix_table *p;
	if (caster->blocklist) {
		prefix_table_free(caster->blocklist);
		caster->blocklist = NULL;
	}

	if (caster->config->blocklist_filename) {
		logfmt(&caster->flog, LOG_INFO, "Reloading %s\n", caster->config->blocklist_filename);
		p = prefix_table_new(caster->config->blocklist_filename, &caster->flog);
		caster->blocklist = p;
		if (p == NULL)
			r = -1;
	}
	P_RWLOCK_UNLOCK(&caster->configlock);
	return r;
}

static int caster_reload_config(struct caster_state *this) {
	struct config *config;
	if (!(config = config_parse(this->config_file))) {
		logfmt(&this->flog, LOG_ERR, "Can't parse configuration from %s\n", this->config_file);
		return -1;
	}
	config_free(this->config);
	this->config = config;
	return 0;
}

/*
 * reload with chdir to allow relative paths in the configuration.
 */
static int caster_chdir_reload(struct caster_state *this, int reopen_logs) {
	int r = 0;
	int current_dir = open(".", O_DIRECTORY);
	chdir(this->config_dir);
	if (reopen_logs && caster_reopen_logs(this) < 0)
		r = -1;
	if (caster_reload_sourcetables(this) < 0)
		r = -1;
	if (caster_reload_auth(this) < 0)
		r = -1;
	if (caster_reload_blocklist(this) < 0)
		r = -1;
	fchdir(current_dir);
	close(current_dir);
	return r;
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *arg)
{
	struct listener *listener_conf = arg;
	struct caster_state *caster = listener_conf->caster;
	struct event_base *base = caster->base;
	struct bufferevent *bev;
	SSL *ssl = NULL;

	P_RWLOCK_RDLOCK(&listener_conf->caster->configlock);
	if (listener_conf->tls) {
		ssl = SSL_new(listener_conf->ssl_server_ctx);
		if (ssl == NULL) {
			P_RWLOCK_UNLOCK(&listener_conf->caster->configlock);
			ERR_print_errors_cb(caster_tls_log_cb, caster);
			close(fd);
			return;
		}

		if (threads)
			bev = bufferevent_openssl_socket_new(caster->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_openssl_socket_new(caster->base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	} else {
		if (threads)
			bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_THREADSAFE);
		else
			bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	}
	P_RWLOCK_UNLOCK(&listener_conf->caster->configlock);

	if (bev == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Error constructing bufferevent!\n");
		close(fd);
		return;
	}

	struct ntrip_state *st = ntrip_new(caster, bev, NULL, 0, NULL);
	if (st == NULL) {
		logfmt(&caster->flog, LOG_ERR, "Error constructing ntrip_state for a new connection!\n");
		bufferevent_free(bev);
		close(fd);
		return;
	}

	st->ssl = ssl;
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

int caster_reload(struct caster_state *this) {
	int r = 0;
	if (caster_reload_config(this) < 0)
		r = -1;
	if (caster_reload_listeners(this) < 0)
		r = -1;
	if (caster_reload_fetchers(this) < 0)
		r = -1;
	if (caster_chdir_reload(this, 1) < 0)
		r = -1;
	return r;
}

static void
signalhup_cb(evutil_socket_t sig, short events, void *arg) {
	struct caster_state *caster = (struct caster_state *)arg;
	logfmt(&caster->flog, LOG_INFO, "Reloading configuration\n");
	caster_reload(caster);
}

static struct caster_state *caster = NULL;

static
void event_log_redirect(int severity, const char *msg) {
	if (caster != NULL)
		logfmt(&caster->flog, LOG_INFO, "%s\n", msg);
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
			this->config->proxy[i].tls,
			this->config->proxy[i].table_refresh_delay,
			this->config->proxy[i].priority);
		if (fetchers[i])
			fetcher_sourcetable_start(fetchers[i]);
	}

	return 0;
}

static int caster_reload_fetchers(struct caster_state *this) {
	int r = 0;
	if (!this->config->proxy_count) {
		caster_free_fetchers(this);
		return 0;
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
			if (!strcmp(this->sourcetable_fetchers[j]->task->host, this->config->proxy[i].host)
			&& this->sourcetable_fetchers[j]->task->port == this->config->proxy[i].port) {
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
				this->config->proxy[i].tls,
				this->config->proxy[i].table_refresh_delay,
				this->config->proxy[i].priority);
			if (p)
				logfmt(&this->flog, LOG_INFO, "New fetcher %s:%d\n", this->config->proxy[i].host, this->config->proxy[i].port);
			else {
				logfmt(&this->flog, LOG_ERR, "Can't start fetcher %s:%d\n", this->config->proxy[i].host, this->config->proxy[i].port);
				r = -1;
			}
		} else {
			fetcher_sourcetable_reload(p,
				this->config->proxy[i].table_refresh_delay,
				this->config->proxy[i].priority);
			logfmt(&this->flog, LOG_INFO, "Reusing fetcher %s:%d\n", this->config->proxy[i].host, this->config->proxy[i].port);
		}
		new_fetchers[i] = p;
	}
	/*
	 * Stop and free all remaining fetchers in the old configuration.
	 */
	for (int j = 0; j < this->sourcetable_fetchers_count; j++)
		if (this->sourcetable_fetchers[j]) {
			logfmt(&this->flog, LOG_INFO, "Stopping fetcher %s:%d\n", this->sourcetable_fetchers[j]->task->host, this->sourcetable_fetchers[j]->task->port);
			fetcher_sourcetable_free(this->sourcetable_fetchers[j]);
		}
	free(this->sourcetable_fetchers);
	this->sourcetable_fetchers_count = this->config->proxy_count;
	this->sourcetable_fetchers = new_fetchers;
	return r;
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
		logfmt(&caster->flog, LOG_ERR, "Can't make socket non-blocking\n");
		return 1;
	}
	// evutil_socket_t s = event_get_fd(listener);
	// int v6only = 0;
	// setsockopt(0, IPV6CTL_V6ONLY, IPV6CTL_V6ONLY, &v6only, sizeof v6only);
#endif

	if (caster_reload_listeners(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (caster_set_signals(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (threads && jobs_start_threads(caster->joblist, nthreads) < 0) {
		logfmt(&caster->flog, LOG_CRIT, "Could not create threads!\n");
		caster_free(caster);
		return 1;
	}

	caster_start_fetchers(caster);

	event_base_dispatch(caster->base);

	caster_free(caster);
	return 0;
}
