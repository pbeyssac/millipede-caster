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
#include <sys/time.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/listener.h>
#include <event2/event.h>
#include <event2/thread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "auth.h"
#include "caster.h"
#include "config.h"
#include "gelf.h"
#include "graylog_sender.h"
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

static void caster_log_cb(void *arg, struct gelf_entry *g, int level, const char *fmt, va_list ap);
static void caster_alog(void *arg, struct gelf_entry *g, int level, const char *fmt, va_list ap);
static int caster_reload_fetchers(struct caster_state *this, struct config *config);
static void caster_free_fetchers(struct caster_state *this);
static void caster_free_rtcm_filters(struct caster_state *caster);
static void listener_free(struct listener *this);
static void listener_incref(struct listener *this);
static void listener_decref(struct listener *this);

void caster_log_error(struct caster_state *this, char *orig) {
	char s[256];
	strerror_r(errno, s, sizeof s);
	logfmt(&this->flog, LOG_ERR, "%s: %s (%d)", orig, s, errno);
}

static void
_caster_log(struct caster_state *caster, struct gelf_entry *g, struct log *log, int level, const char *fmt, va_list ap) {
	char date[36];
	struct gelf_entry localg;
	int thread_id = threads?(long)pthread_getspecific(caster->thread_id):-1;

	if (g == NULL) {
		g = &localg;
		gelf_init(g, level, caster->hostname, thread_id);
	} else {
		g->hostname = caster->hostname;
		g->thread_id = thread_id;
	}

	logdate(date, sizeof date, &g->ts);

	char *msg;
	vasprintf(&msg, fmt, ap);

	if (level <= caster->log_level) {
		if (threads)
			logfmt_direct(log, "%s [%lu] %s\n", date, (long)pthread_getspecific(caster->thread_id), msg);
		else
			logfmt_direct(log, "%s %s\n", date, msg);
	}

	if (g->short_message == NULL)
		g->short_message = msg;
	else
		free(msg);

	if (level != -1 && !g->nograylog && level <= caster->graylog_log_level) {
		json_object *j = gelf_json(g);
		char *s = mystrdup(json_object_to_json_string(j));
		json_object_put(j);
		graylog_sender_queue(caster->graylog[0], s);
		strfree(s);
	}

	free(g->short_message);
	g->short_message = NULL;
}

/*
 * Caster access log.
 * level -1 => not sent to graylog.
 */
static void
caster_alog(void *arg, struct gelf_entry *g, int dummy, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	_caster_log(this, g, &this->alog, -1, fmt, ap);
}

static void
caster_log_cb(void *arg, struct gelf_entry *g, int level, const char *fmt, va_list ap) {
	struct caster_state *this = (struct caster_state *)arg;
	if (level <= this->log_level || level <= this->graylog_log_level)
		_caster_log(this, g, &this->flog, level, fmt, ap);
}

/*
 * Callback for OpenSSL's ERR_print_errors_cb()
 */

int
caster_tls_log_cb(const char *str, size_t len, void *u) {
	logfmt(&((struct caster_state *)u)->flog, LOG_ERR, "%s", str);
	// Undocumentend OpenSSL API: return >0 if ok, <=0 if failed
	return 1;
}

static struct caster_state *
caster_new(const char *config_file) {
	int err = 0;
	struct caster_state *this = (struct caster_state *)calloc(1, sizeof(struct caster_state));
	if (this == NULL)
		return this;

	gettimeofday(&this->start_date, NULL);

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

	gethostname(this->hostname, sizeof(this->hostname));
	this->livesources = livesource_table_new(this->hostname, &this->start_date);

	P_RWLOCK_INIT(&this->ntrips.lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.free_lock, NULL);
	P_RWLOCK_INIT(&this->rtcm_lock, NULL);
	this->ntrips.next_id = 1;

	P_RWLOCK_INIT(&this->quotalock, NULL);
	this->ntrips.ipcount = hash_table_new(509, NULL);

	// Used for access to source_auth, host_auth, blocklist and listener config
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	P_MUTEX_INIT(&this->configmtx, &attr);
	pthread_mutexattr_destroy(&attr);

	P_RWLOCK_INIT(&this->sourcetablestack.lock, NULL);

	atomic_init(&this->config, NULL);

	char *abs_config_path = realpath(config_file, NULL);
	if (abs_config_path == NULL) {
		fprintf(stderr, "Error: can't determine absolute path for config file %s\n", config_file);
		err = 1;
		this->config_dir = NULL;
		this->config_file = mystrdup(config_file);
		if (this->config_file == NULL)
			err = 1;
	} else {
		this->config_file = mystrdup(abs_config_path);
		if (this->config_file == NULL)
			err = 1;
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

	int r1 = log_init(&this->flog, NULL, &caster_log_cb, this);
	int r2 = log_init(&this->alog, NULL, &caster_alog, this);

	this->graylog = NULL;
	this->graylog_count = 0;
	this->syncers = NULL;
	this->syncers_count = 0;
	this->rtcm_filter = NULL;
	this->rtcm_filter_dict = NULL;

	fchdir(current_dir);
	close(current_dir);

	if (err || r1 < 0 || r2 < 0 || !this->config_dir
	    || (threads && this->joblist == NULL)
	    || this->ntrips.ipcount == NULL
	    || this->livesources == NULL) {
		if (this->joblist) joblist_free(this->joblist);
		if (r1 < 0) log_free(&this->flog);
		if (r2 < 0) log_free(&this->alog);
		if (this->ntrips.ipcount) hash_table_free(this->ntrips.ipcount);
		if (this->livesources) livesource_table_free(this->livesources);
		strfree(this->config_dir);
		free(this);
		return NULL;
	}

	this->base = base;
	this->dns_base = dns_base;
	TAILQ_INIT(&this->ntrips.queue);
	TAILQ_INIT(&this->ntrips.free_queue);
	this->ntrips.n = 0;
	this->ntrips.nfree = 0;
	this->rtcm_cache = hash_table_new(509, (void(*)(void *))rtcm_info_free);
	this->hostname[sizeof(this->hostname)-1] = '\0';
	TAILQ_INIT(&this->sourcetablestack.list);
	return this;
}

static void caster_free_listeners(struct caster_state *this) {
	for (int i = 0; i < this->listeners_count; i++)
		listener_decref(this->listeners[i]);
	free(this->listeners);
	this->listeners = NULL;
	this->listeners_count = 0;
}

static int caster_start_syncers(struct caster_state *this, struct config *config) {
	if (config->node_count == 0) {
		this->syncers_count = 0;
		return 0;
	}
	this->syncers_count = 1;
	this->syncers = (struct syncer **)malloc(sizeof(struct syncer *)*this->syncers_count);
	for (int i = 0; i < this->syncers_count; i++) {
		this->syncers[i] = syncer_new(this,
			config->node, config->node_count, "/adm/api/v1/sync", 0);
		for (int j = 0; j < config->node_count; j++)
			syncer_start(this->syncers[i], j);
	}
	return 0;
}

static void caster_free_syncers(struct caster_state *this) {
	if (this->syncers == NULL)
		return;
	for (int i = 0; i < this->syncers_count; i++)
		syncer_free(this->syncers[i]);
	free(this->syncers);
	this->syncers_count = 0;
	this->syncers = NULL;
}

static int caster_reload_syncers(struct caster_state *this, struct config *config) {
	caster_free_syncers(this);
	return caster_start_syncers(this, config);
}

static void caster_free_graylog(struct caster_state *this) {
	this->graylog_log_level = -1;
	for (int i = 0; i < this->graylog_count; i++)
		graylog_sender_free(this->graylog[i]);
	free(this->graylog);
	this->graylog = NULL;
	this->graylog_count = 0;
}

static int caster_reload_graylog(struct caster_state *this, struct config *config) {
	int r = 0;
	int i;

	/* The log system is currently hardocoded for graylog_count == 0 or 1 */

	struct graylog_sender **new_graylog = NULL;

	if (config->graylog_count) {
		new_graylog = (struct graylog_sender **)malloc(sizeof(struct graylog_sender *)*config->graylog_count);
		if (new_graylog == NULL)
			return -1;
	}

	for (i = 0; i < config->graylog_count; i++) {
		new_graylog[i] = graylog_sender_new(this,
			config->graylog[i].host,
			config->graylog[i].port,
			config->graylog[i].uri,
			config->graylog[i].tls,
			config->graylog[i].retry_delay,
			config->graylog[i].bulk_max_size,
			config->graylog[i].queue_max_size,
			config->graylog[i].authorization,
			config->graylog[i].drainfilename);
		if (!new_graylog[i]) {
			r = -1;
			break;
		}
		graylog_sender_start(new_graylog[i], 0);
	}
	if (r == -1) {
		for (int j = 0; i < j; j++)
			graylog_sender_free(new_graylog[j]);
		free(new_graylog);
	} else {
		caster_free_graylog(this);
		this->graylog = new_graylog;
		this->graylog_count = config->graylog_count;
	}
	return r;
}

void caster_free(struct caster_state *this) {
	/* Kill all connections */
	ntrip_drop_by_id(this, 0);

	/* Wait for the threads to finish their tasks */
	if (threads)
		jobs_stop_threads(this->joblist);

	caster_free_listeners(this);

	if (this->signalhup_event)
		event_free(this->signalhup_event);
	if (this->signalint_event)
		event_free(this->signalint_event);
	if (this->signalterm_event)
		event_free(this->signalterm_event);

	caster_free_fetchers(this);
	caster_free_syncers(this);
	caster_free_graylog(this);

	if (this->joblist) joblist_free(this->joblist);
	livesource_table_free(this->livesources);

	hash_table_free(this->ntrips.ipcount);
	hash_table_free(this->rtcm_cache);

	evdns_base_free(this->dns_base, 1);
	event_base_free(this->base);
	SSL_CTX_free(this->ssl_client_ctx);

	P_RWLOCK_WRLOCK(&this->sourcetablestack.lock);
	struct sourcetable *s;
	while ((s = TAILQ_FIRST(&this->sourcetablestack.list))) {
		TAILQ_REMOVE_HEAD(&this->sourcetablestack.list, next);
		sourcetable_free(s);
	}
	P_RWLOCK_UNLOCK(&this->sourcetablestack.lock);

	P_RWLOCK_DESTROY(&this->sourcetablestack.lock);
	P_RWLOCK_DESTROY(&this->quotalock);
	P_RWLOCK_DESTROY(&this->rtcm_lock);
	P_RWLOCK_DESTROY(&this->ntrips.lock);
	P_RWLOCK_DESTROY(&this->ntrips.free_lock);
	P_MUTEX_DESTROY(&this->configmtx);
	log_free(&this->flog);
	log_free(&this->alog);
	strfree(this->config_dir);
	strfree((char *)this->config_file);
	if (this->config) {
		config_decref(this->config);
	caster_free_rtcm_filters(this);
	libevent_global_shutdown();
	free(this);
}

/*
 * Load TLS certificates from file paths.
 */
static int listener_load_certs(struct listener *this, const char *tls_full_certificate_chain, const char *tls_private_key) {
	char *full_certificate_chain = joinpath(this->caster->config_dir, tls_full_certificate_chain);
	char *private_key = joinpath(this->caster->config_dir, tls_private_key);

	if (full_certificate_chain == NULL || private_key == NULL
		|| SSL_CTX_use_certificate_chain_file(this->ssl_server_ctx, full_certificate_chain) <= 0
		|| SSL_CTX_use_PrivateKey_file(this->ssl_server_ctx, private_key, SSL_FILETYPE_PEM) <= 0) {
		strfree(private_key);
		strfree(full_certificate_chain);
		return -1;
	}
	strfree(private_key);
	strfree(full_certificate_chain);

	if (!SSL_CTX_check_private_key(this->ssl_server_ctx)) {
		char ip[64];
		logfmt(&this->caster->flog, LOG_ERR, "Private key for %s does not match the certificate public key", ip_str_port(&this->sockaddr, ip, sizeof ip));
		return -1;
	}
	return 0;
}

static int tls_sni_callback(SSL *ssl, int *al, void *arg) {
	struct listener *listener = (struct listener *)arg;
	const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	logfmt(&listener->caster->flog, LOG_INFO, "SNI callback hostname %s", hostname);
	if (hostname == NULL || strcmp(hostname, listener->hostname))
		return SSL_TLSEXT_ERR_NOACK;
	return SSL_TLSEXT_ERR_OK;
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
		if (config->hostname) {
			this->hostname = mystrdup(config->hostname);
			if (this->hostname == NULL)
				return -1;
			/* Configure a SNI callback */
			SSL_CTX_set_tlsext_servername_callback(this->ssl_server_ctx, tls_sni_callback);
			SSL_CTX_set_tlsext_servername_arg(this->ssl_server_ctx, this);
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
static struct listener *listener_new(struct caster_state *this, struct config_bind *config, union sock *sin) {
	struct listener *listener = (struct listener *)malloc(sizeof(struct listener));

	if (listener == NULL)
		return NULL;

	listener->sockaddr = *sin;
	listener->caster = this;
	listener->tls = config->tls;
	listener->ssl_server_ctx = NULL;
	listener->hostname = NULL;
	atomic_init(&listener->refcnt, 1);

	if (config->tls && config->tls_full_certificate_chain && config->tls_private_key) {
		if (listener_setup_tls(listener, config) < 0) {
			free(listener);
			return NULL;
		}
	}

	listener->listener = evconnlistener_new_bind(this->base, ntripsrv_listener_cb, listener,
		LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, config->queue_size,
		(struct sockaddr *)sin, sin->generic.sa_family == AF_INET ? sizeof(sin->v4) : sizeof(sin->v6));
	if (!listener->listener) {
		logfmt(&this->flog, LOG_ERR, "Could not create a listener for %s:%d!", config->ip, config->port);
		free(listener);
		return NULL;
	}
	return listener;
}

static void listener_free(struct listener *this) {
	char ip[64];
	logfmt(&this->caster->flog, LOG_INFO, "Closing listener %s", ip_str_port(&this->sockaddr, ip, sizeof ip));
	if (this->listener)
		evconnlistener_free(this->listener);
	if (this->tls && this->ssl_server_ctx)
		SSL_CTX_free(this->ssl_server_ctx);
	free(this);
}

static void listener_incref(struct listener *this) {
	atomic_fetch_add(&this->refcnt, 1);
}

static void listener_decref(struct listener *this) {
	if (atomic_fetch_add_explicit(&this->refcnt, -1, memory_order_relaxed) == 1)
		listener_free(this);
}

/*
 * Configure/reconfigure listening ports, reusing already existing sockets if possible.
 */
static int caster_reload_listeners(struct caster_state *this, struct config *new_config) {
	union sock sin;
	unsigned short port;
	int r, i;
	struct listener **new_listeners;
	char ip[64];

	P_MUTEX_LOCK(&this->configmtx);
	if (new_config->bind_count == 0) {
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.");
		if (this->listeners)
			caster_free_listeners(this);
		P_MUTEX_UNLOCK(&this->configmtx);
		return -1;
	}

	new_listeners = (struct listener **)malloc(sizeof(struct listener *)*new_config->bind_count);
	if (!new_listeners) {
		logfmt(&this->flog, LOG_CRIT, "Can't allocate listeners");
		if (this->listeners)
			caster_free_listeners(this);
		P_MUTEX_UNLOCK(&this->configmtx);
		return -1;
	}

	/*
	 * Create listening socket addresses.
	 * Create a libevent listener for each.
	 */
	int current_dir = open(".", O_DIRECTORY);
	chdir(this->config_dir);

	int nlisteners = 0;

	for (i = 0; i < new_config->bind_count; i++) {
		struct config_bind *config = new_config->bind + i;
		port = htons(config->port);
		r = ip_convert(config->ip, &sin);
		if (r <= 0) {
			logfmt(&this->flog, LOG_ERR, "Invalid IP %s", new_config->bind[i].ip);
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
				logfmt(&this->flog, LOG_ERR, "Can't reuse listener %s: TLS setup failed", ip_str_port(&sin, ip, sizeof ip));
				recycled_listener = NULL;
			} else {
				if (recycled_listener->tls && !config->tls) {
					recycled_listener->tls = 0;
					SSL_CTX_free(recycled_listener->ssl_server_ctx);
				}
				logfmt(&this->flog, LOG_INFO, "Reusing listener %s", ip_str_port(&sin, ip, sizeof ip));
				new_listeners[nlisteners++] = recycled_listener;
				listener_incref(recycled_listener);
			}
		}
		if (!recycled_listener) {
			/*
			 * No reusable listener found, or reuse failed, start a new listener instance.
			 */
			struct listener *new_listener = listener_new(this, new_config->bind+i, &sin);
			if (new_listener != NULL) {
				new_listeners[nlisteners++] = new_listener;
				logfmt(&this->flog, LOG_INFO, "Opening listener %s", ip_str_port(&sin, ip, sizeof ip));
			} else {
				logfmt(&this->flog, LOG_ERR, "Unable to open listener %s", ip_str_port(&sin, ip, sizeof ip));
			}
		}
	}
	fchdir(current_dir);
	close(current_dir);

	/*
	 * Unreference former listeners
	 */
	for (int j = 0; j < this->listeners_count; j++)
		listener_decref(this->listeners[j]);

	free(this->listeners);
	this->listeners = new_listeners;
	this->listeners_count = nlisteners;

	P_MUTEX_UNLOCK(&this->configmtx);

	if (this->listeners_count == 0) {
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.");
		return -1;
	}
	return 0;
}

static int
caster_reload_sourcetables(struct caster_state *caster, struct config *config) {
	struct sourcetable *local_table
		= sourcetable_read(caster, config->sourcetable_filename, config->sourcetable_priority);

	if (local_table == NULL)
		return -1;

	stack_replace_local(caster, &caster->sourcetablestack, local_table);
	return 0;
}

static int
caster_reopen_logs(struct caster_state *this, struct config *config) {
	int r = 0;
	char *config_log = joinpath(this->config_dir, config->log);
	char *access_log = joinpath(this->config_dir, config->access_log);
	if (config_log == NULL || log_reopen(&this->flog, config_log) < 0)
		r = -1;
	if (access_log == NULL || log_reopen(&this->alog, access_log) < 0)
		r = -1;
	strfree(config_log);
	strfree(access_log);
	return r;
}

static int
caster_reload_auth(struct caster_state *caster, struct config *config) {
	int r = 0;
	logfmt(&caster->flog, LOG_INFO, "Reloading %s and %s", config->host_auth_filename, config->source_auth_filename);

	if (config->host_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, config->host_auth_filename);
		if (tmp != NULL) {
			config->host_auth = tmp;
		} else
			r = -1;
	}
	if (config->source_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, config->source_auth_filename);
		if (tmp != NULL) {
			config->source_auth = tmp;
		} else
			r = -1;
	}
	return r;
}

static int
caster_reload_blocklist(struct caster_state *caster, struct config *config) {
	int r = 0;
	struct prefix_table *p;

	if (config->blocklist_filename) {
		logfmt(&caster->flog, LOG_INFO, "Reloading %s", config->blocklist_filename);
		p = prefix_table_new();
		if (p == NULL)
			r = -1;
		else if (prefix_table_read(p, caster->config_dir, config->blocklist_filename, &caster->flog) < 0) {
			prefix_table_free(p);
			p = NULL;
			r = -1;
		}
		config->blocklist = p;
	}
	return r;
}

static void
caster_free_rtcm_filters(struct caster_state *caster) {
	if (caster->rtcm_filter_dict) {
		hash_table_free(caster->rtcm_filter_dict);
		caster->rtcm_filter_dict = NULL;
	}
	if (caster->rtcm_filter)
		rtcm_filter_free(caster->rtcm_filter);
	caster->rtcm_filter = NULL;
}

static int
caster_reload_rtcm_filters(struct caster_state *caster, struct config *config) {
	if (config->rtcm_filter_count == 0) {
		caster_free_rtcm_filters(caster);
		return 0;
	}
	if (config->rtcm_filter_count != 1) {
		caster_free_rtcm_filters(caster);
		return -1;
	}

	if (caster->rtcm_filter_dict)
		hash_table_free(caster->rtcm_filter_dict);
	caster->rtcm_filter_dict = hash_table_new(5, NULL);
	if (caster->rtcm_filter_dict == NULL)
		return -1;

	for (int i = 0; i < config->rtcm_filter_count; i++) {
		struct rtcm_filter *rtcm_filter;
		rtcm_filter = rtcm_filter_new(
			config->rtcm_filter[i].pass,
			config->rtcm_filter[i].convert_count ? config->rtcm_filter[i].convert[0].types : NULL,
			config->rtcm_filter[i].convert_count ? config->rtcm_filter[i].convert[0].conversion : 0
		);
		if (rtcm_filter == NULL) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse rtcm_filter configuration from %s", caster->config_file);
			return -1;
		}
		struct hash_table *h = rtcm_filter_dict_parse(rtcm_filter, config->rtcm_filter[i].apply);
		if (h == NULL) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse rtcm_filter configuration from %s", caster->config_file);
			rtcm_filter_free(rtcm_filter);
			return -1;
		}
		hash_table_update(caster->rtcm_filter_dict, h);
		hash_table_free(h);
		if (caster->rtcm_filter)
			rtcm_filter_free(caster->rtcm_filter);
		caster->rtcm_filter = rtcm_filter;
	}
	return 0;
}

static struct config *caster_reload_config(struct caster_state *this) {
	struct config *config;
	if (!(config = config_parse(this->config_file))) {
		if (this->config)
			logfmt(&this->flog, LOG_ERR, "Can't parse configuration from %s", this->config_file);
		else
			fprintf(stderr, "Can't parse configuration from %s\n", this->config_file);
		return NULL;
	}
	return config;
}

/*
 * reload with chdir to allow relative paths in the configuration.
 */
static int caster_chdir_reload(struct caster_state *this, struct config *config, int reopen_logs) {
	int r = 0;
	int current_dir = open(".", O_DIRECTORY);
	chdir(this->config_dir);
	if (reopen_logs && caster_reopen_logs(this, config) < 0)
		r = -1;
	if (caster_reload_sourcetables(this, config) < 0)
		r = -1;
	if (caster_reload_auth(this, config) < 0)
		r = -1;
	if (caster_reload_blocklist(this, config) < 0)
		r = -1;
	if (caster_reload_rtcm_filters(this, config) < 0)
		r = -1;
	fchdir(current_dir);
	close(current_dir);
	return r;
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data) {
	struct caster_signal_cb_info *info = user_data;
	struct timeval delay = { 0, 0 };

	printf("Caught %s signal; exiting.\n", info->signame);
	logfmt(&info->caster->flog, LOG_INFO, "Caught %s signal; exiting.", info->signame);
	event_base_loopexit(info->caster->base, &delay);
}

int caster_reload(struct caster_state *this) {
	struct config *config, *old_config;
	int r = 0;

	P_MUTEX_LOCK(&this->configmtx);
	this->graylog_log_level = -1;
	old_config = atomic_load(&this->config);
	if ((config = caster_reload_config(this)) == NULL) {
		r = -1;
		if (old_config == NULL) {
			// Incorrect new config and no former config:
			// abort all because we can't log more errors anyway.
			P_MUTEX_UNLOCK(&this->configmtx);
			return -1;
		}
	}

	if (old_config)
		config_decref(old_config);
	atomic_store(&this->config, config);

	this->log_level = config->log_level;
	if (caster_chdir_reload(this, config, 1) < 0)
		r = -1;
	if (caster_reload_graylog(this, config) < 0)
		r = -1;
	this->graylog_log_level = config->graylog_count > 0 ? config->graylog[0].log_level : -1;
	if (caster_reload_listeners(this, config) < 0)
		r = -1;
	if (caster_reload_fetchers(this, config) < 0)
		r = -1;
	if (caster_reload_syncers(this, config) < 0)
		r = -1;
	P_MUTEX_UNLOCK(&this->configmtx);
	return r;
}

static void
signalhup_cb(evutil_socket_t sig, short events, void *arg) {
	struct caster_state *caster = (struct caster_state *)arg;
	logfmt(&caster->flog, LOG_INFO, "Reloading configuration");
	caster_reload(caster);
}

static struct caster_state *caster = NULL;

static
void event_log_redirect(int severity, const char *msg) {
	if (caster != NULL)
		logfmt(&caster->flog, LOG_INFO, "%s", msg);
	else
		fprintf(stderr, "%s\n", msg);
}

static int caster_set_signals(struct caster_state *this) {
	this->sigint_info.caster = this;
	this->sigint_info.signame = "SIGINT";
	this->sigterm_info.signame = "SIGTERM";
	this->sigterm_info.caster = this;
	this->signalint_event = evsignal_new(this->base, SIGINT, signal_cb, (void *)&this->sigint_info);
	if (!this->signalint_event || event_add(this->signalint_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add SIGINT signal event!\n");
		return -1;
	}

	this->signalterm_event = evsignal_new(this->base, SIGTERM, signal_cb, (void *)&this->sigterm_info);
	if (!this->signalterm_event || event_add(this->signalterm_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add SIGTERM signal event!\n");
		return -1;
	}

	signal(SIGPIPE, SIG_IGN);

	this->signalhup_event = evsignal_new(this->base, SIGHUP, signalhup_cb, (void *)this);
	if (!this->signalhup_event || event_add(this->signalhup_event, 0) < 0) {
		fprintf(stderr, "Could not create/add SIGHUP signal event!\n");
		return -1;
	}
	return 0;
}

/*
 * Start/reload sourcetable fetchers (proxy)
 */
static int caster_reload_fetchers(struct caster_state *this, struct config *config) {
	int r = 0;
	struct sourcetable_fetch_args **new_fetchers;
	if (config->proxy_count)
		new_fetchers = (struct sourcetable_fetch_args **)malloc(sizeof(struct sourcetable_fetch_args *)*config->proxy_count);
	else
		new_fetchers = NULL;

	/*
	 * For each entry in the new config, recycle a similar entry in the old configuration.
	 */
	for (int i = 0; i < config->proxy_count; i++) {
		struct sourcetable_fetch_args *p = NULL;
		for (int j = 0; j < this->sourcetable_fetchers_count; j++) {
			if (this->sourcetable_fetchers[j] == NULL)
				/* Already cleared */
				continue;
			if (!strcmp(this->sourcetable_fetchers[j]->task->host, config->proxy[i].host)
			&& this->sourcetable_fetchers[j]->task->port == config->proxy[i].port) {
				p = this->sourcetable_fetchers[j];
				/* Found, clear in the old table */
				this->sourcetable_fetchers[j] = NULL;
				break;
			}
		}
		if (!p) {
			/* Not found, create */
			p = fetcher_sourcetable_new(this,
				config->proxy[i].host, config->proxy[i].port,
				config->proxy[i].tls,
				config->proxy[i].table_refresh_delay,
				config->proxy[i].priority);
			if (p) {
				logfmt(&this->flog, LOG_INFO, "New fetcher %s:%d", config->proxy[i].host, config->proxy[i].port);
				fetcher_sourcetable_start(p, 0);
			} else {
				logfmt(&this->flog, LOG_ERR, "Can't start fetcher %s:%d", config->proxy[i].host, config->proxy[i].port);
				r = -1;
			}
		} else {
			fetcher_sourcetable_reload(p,
				config->proxy[i].table_refresh_delay,
				config->proxy[i].priority);
			logfmt(&this->flog, LOG_INFO, "Reusing fetcher %s:%d", config->proxy[i].host, config->proxy[i].port);
		}
		new_fetchers[i] = p;
	}
	/*
	 * Stop and free all remaining fetchers in the old configuration.
	 */
	for (int j = 0; j < this->sourcetable_fetchers_count; j++)
		if (this->sourcetable_fetchers[j]) {
			logfmt(&this->flog, LOG_INFO, "Stopping fetcher %s:%d", this->sourcetable_fetchers[j]->task->host, this->sourcetable_fetchers[j]->task->port);
			fetcher_sourcetable_free(this->sourcetable_fetchers[j]);
		}
	free(this->sourcetable_fetchers);
	this->sourcetable_fetchers_count = config->proxy_count;
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

	caster = caster_new(config_file);
	if (!caster) {
		fprintf(stderr, "Can't allocate caster\n");
		return 1;
	}

	if (caster_reload(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (caster_set_signals(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (threads && jobs_start_threads(caster->joblist, nthreads) < 0) {
		logfmt(&caster->flog, LOG_CRIT, "Could not create threads!");
		caster_free(caster);
		return 1;
	}

	event_base_dispatch(caster->base);

	logfmt(&caster->flog, LOG_NOTICE, "Stopping caster");
	caster_free(caster);
	return 0;
}
