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
static int caster_reload_fetchers(struct caster_state *this, struct config *config,
	struct caster_dynconfig *olddyn, struct caster_dynconfig *newdyn);
static int caster_start_fetchers(struct caster_state *this, struct config *config, struct caster_dynconfig *newdyn);
static void dynconfig_free_fetchers(struct caster_dynconfig *this);
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

	if (level <= atomic_load(&caster->log_level)) {
		if (threads)
			logfmt_direct(log, "%s [%lu] %s\n", date, (long)pthread_getspecific(caster->thread_id), msg);
		else
			logfmt_direct(log, "%s %s\n", date, msg);
	}

	if (g->short_message == NULL)
		g->short_message = msg;
	else
		free(msg);

	if (level != -1 && !g->nograylog && level <= atomic_load(&caster->graylog_log_level)) {
		json_object *j = gelf_json(g);
		char *s = mystrdup(json_object_to_json_string(j));
		json_object_put(j);
		graylog_sender_queue(caster->config->dyn->graylog[0], s);
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
	if (level <= atomic_load(&this->log_level) || level <= atomic_load(&this->graylog_log_level))
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

static struct caster_dynconfig *dynconfig_new(struct caster_state *caster) {
	struct caster_dynconfig *this = (struct caster_dynconfig *)malloc(sizeof(struct caster_dynconfig));
	if (this == NULL)
		return NULL;
	this->listeners = NULL;
	this->listeners_count = 0;
	this->sourcetable_fetchers = NULL;
	this->sourcetable_fetchers_count = 0;
	this->graylog = NULL;
	this->graylog_count = 0;
	this->syncers = NULL;
	this->syncers_count = 0;
	this->rtcm_filter = NULL;
	this->rtcm_filter_dict = NULL;
	this->caster = caster;
	return this;
}

static void dynconfig_free_fetchers(struct caster_dynconfig *this) {
	struct sourcetable_fetch_args **a = this->sourcetable_fetchers;
	if (!a)
		return;
	for (int i = 0; i < this->sourcetable_fetchers_count; i++) {
		if (a[i]) {
			logfmt(&this->caster->flog, LOG_INFO, "Stopping fetcher %s:%d", a[i]->task->host, a[i]->task->port);
			fetcher_sourcetable_free(a[i]);
		}
	}
	free(a);
	this->sourcetable_fetchers = NULL;
	this->sourcetable_fetchers_count = 0;
}

static void
dynconfig_free_rtcm_filters(struct caster_dynconfig *dyn) {
	if (dyn->rtcm_filter_dict) {
		hash_table_free(dyn->rtcm_filter_dict);
		dyn->rtcm_filter_dict = NULL;
	}
	if (dyn->rtcm_filter)
		rtcm_filter_free(dyn->rtcm_filter);
	dyn->rtcm_filter = NULL;
}

static void
dynconfig_free_listeners(struct caster_dynconfig *dyn) {
	if (dyn->listeners == NULL)
		return;
	for (int i = 0; i < dyn->listeners_count; i++)
		listener_decref(dyn->listeners[i]);
	free(dyn->listeners);
	dyn->listeners = NULL;
	dyn->listeners_count = 0;
}

static void
dynconfig_free_graylog(struct caster_dynconfig *this) {
	if (this->graylog == NULL)
		return;
	for (int i = 0; i < this->graylog_count; i++) {
		if (this->graylog[i] != NULL) {
			graylog_sender_free(this->graylog[i]);
			this->graylog[i] = NULL;
		}
	}
	free(this->graylog);
	this->graylog = NULL;
	this->graylog_count = 0;
}

static void
dynconfig_free_syncers(struct caster_dynconfig *dyn) {
	if (dyn->syncers == NULL)
		return;
	for (int i = 0; i < dyn->syncers_count; i++) {
		if (dyn->syncers[i] != NULL) {
			syncer_free(dyn->syncers[i]);
			dyn->syncers[i] = NULL;
		}
	}
	free(dyn->syncers);
	dyn->syncers_count = 0;
	dyn->syncers = NULL;
}

static void
dynconfig_free(struct caster_dynconfig *this) {
	dynconfig_free_listeners(this);
	dynconfig_free_fetchers(this);
	dynconfig_free_rtcm_filters(this);
	dynconfig_free_syncers(this);
	dynconfig_free_graylog(this);
	free(this);
}

static void
dynconfig_free_callback(struct config *config) {
	dynconfig_free(config->dyn);
	config->dyn = NULL;
}

static struct caster_state *
caster_new(const char *config_file, int nbase) {
	int err = 0;
	struct caster_state *this = (struct caster_state *)calloc(1, sizeof(struct caster_state));
	if (this == NULL)
		return this;

	gettimeofday(&this->start_date, NULL);

	struct event_base *base;
	struct evdns_base *dns_base;

	this->base = (struct event_base **)calloc(nbase, sizeof(struct event_base *));
	if (this->base == NULL) {
		free(this);
		return NULL;
	}
	this->nbase = nbase;
	atomic_store(&this->basecounter, 0);
	for (int i = 0; i < this->nbase; i++) {
		base = event_base_new();
		if (!base) {
			err = 1;
			fprintf(stderr, "Could not initialize libevent!\n");
			break;
		}
		this->base[i] = base;
	}
	if (err) {
		for (int i = 0; i < this->nbase; i++)
			if (this->base[i] != NULL)
				event_base_free(this->base[i]);
		free(this->base);
		free(this);
		return NULL;
	}

	dns_base = evdns_base_new(this->base[0], 1);
	if (!dns_base) {
		fprintf(stderr, "Could not initialize dns_base!\n");
		return NULL;
	}

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
	this->nodes = nodes_new();

	P_RWLOCK_INIT(&this->ntrips.lock, NULL);
	P_RWLOCK_INIT(&this->ntrips.free_lock, NULL);
	P_RWLOCK_INIT(&this->rtcm_lock, NULL);
	this->ntrips.next_id = 1;

	P_RWLOCK_INIT(&this->quotalock, NULL);
	this->ntrips.ipcount = hash_table_new(509, NULL);

	// Used for access to config and reload serializing
	atomic_store(&this->config_gen, 1);
	P_RWLOCK_INIT(&this->configlock, NULL);
	P_MUTEX_INIT(&this->configreload, NULL);

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

	this->joblist = threads ? joblist_new(this) : NULL;

	int r1 = log_init(&this->flog, NULL, &caster_log_cb, this);
	int r2 = log_init(&this->alog, NULL, &caster_alog, this);

	if (err || r1 < 0 || r2 < 0 || !this->config_dir
	    || (threads && this->joblist == NULL)
	    || this->ntrips.ipcount == NULL
	    || this->livesources == NULL
		|| this->nodes == NULL) {
		if (this->joblist) joblist_free(this->joblist);
		if (r1 < 0) log_free(&this->flog);
		if (r2 < 0) log_free(&this->alog);
		if (this->ntrips.ipcount) hash_table_free(this->ntrips.ipcount);
		if (this->livesources) livesource_table_free(this->livesources);
		if (this->nodes) nodes_free(this->nodes);
		strfree(this->config_dir);
		free(this);
		return NULL;
	}

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

static int caster_reload_syncers(struct caster_state *this, struct config *config, struct caster_dynconfig *olddyn, struct caster_dynconfig *newdyn) {
	if (config->node_count == 0) {
		newdyn->syncers = NULL;
		newdyn->syncers_count = 0;
		return 0;
	}
	newdyn->syncers_count = 1;
	newdyn->syncers = (struct syncer **)calloc(sizeof(struct syncer *)*newdyn->syncers_count, 1);
	if (newdyn->syncers == NULL)
		return -1;

	if (olddyn != NULL && olddyn->syncers != NULL && olddyn->syncers_count == newdyn->syncers_count) {
		newdyn->syncers_count = olddyn->syncers_count;
		for (int i = 0; i < newdyn->syncers_count; i++) {
			newdyn->syncers[i] = olddyn->syncers[i];
			olddyn->syncers[i] = NULL;
		}
	} else {
		for (int i = 0; i < newdyn->syncers_count; i++) {
			newdyn->syncers[i] = syncer_new(this, config->node, config->node_count, "/adm/api/v1/sync", 0);
			if (newdyn->syncers[i] == NULL) {
				for (int j = 0; j < i; j++)
					syncer_free(newdyn->syncers[i]);
				free(newdyn->syncers);
				return -1;
			}
		}
	}

	for (int i = 0; i < newdyn->syncers_count; i++)
		syncer_reload(newdyn->syncers[i], config->node, config->node_count, "/adm/api/v1/sync", 0);
	return 0;
}

static int caster_start_syncers(struct caster_state *this, struct config *new_config, struct caster_dynconfig *dyn) {
	for (int i = 0; i < dyn->syncers_count; i++)
		syncer_start_all(dyn->syncers[i], new_config);
	return 0;
}

static int caster_reload_graylog(struct caster_state *this, struct config *new_config, struct caster_dynconfig *dyn) {
	int r = 0;
	int i;

	/* The log system is currently hardcoded for graylog_count == 0 or 1 */

	struct graylog_sender **new_graylog = NULL;

	if (new_config->graylog_count) {
		new_graylog = (struct graylog_sender **)malloc(sizeof(struct graylog_sender *)*new_config->graylog_count);
		if (new_graylog == NULL)
			return -1;
	}

	for (i = 0; i < new_config->graylog_count; i++)
		new_graylog[i] = NULL;

	for (i = 0; i < new_config->graylog_count; i++) {
		new_graylog[i] = graylog_sender_new(this,
			new_config->graylog[i].host,
			new_config->graylog[i].port,
			new_config->graylog[i].uri,
			new_config->graylog[i].tls,
			new_config->graylog[i].status_timeout,
			new_config->graylog[i].retry_delay,
			new_config->graylog[i].max_retry_delay,
			new_config->graylog[i].bulk_max_size,
			new_config->graylog[i].queue_max_size,
			new_config->graylog[i].authorization,
			new_config->graylog[i].drainfilename);
		if (!new_graylog[i]) {
			r = -1;
			break;
		}
	}
	if (r == -1) {
		for (i = 0; i < new_config->graylog_count; i++)
			if (new_graylog[i] != NULL)
				graylog_sender_free(new_graylog[i]);
		free(new_graylog);
	} else {
		dyn->graylog = new_graylog;
		dyn->graylog_count = new_config->graylog_count;
	}
	return r;
}

static int caster_start_graylog(struct caster_state *this, struct config *new_config, struct caster_dynconfig *dyn) {
	for (int i = 0; i < dyn->graylog_count; i++)
		graylog_sender_start_with_config(dyn->graylog[i], 0, new_config);
	return 0;
}

void caster_free(struct caster_state *this) {
	if (this->config) {
		/* Stop accepting incoming connections */
		dynconfig_free_listeners(this->config->dyn);

		/* Stop outgoing connections */
		dynconfig_free_fetchers(this->config->dyn);
		dynconfig_free_syncers(this->config->dyn);

		atomic_store(&this->graylog_log_level, -1);
		dynconfig_free_graylog(this->config->dyn);
	}

	/* Kill all remaining connections */
	ntrip_drop_by_id(this, 0);

	/* Wait for the threads to finish their tasks */
	if (threads)
		jobs_stop_threads(this->joblist);

	if (this->signalhup_event)
		event_free(this->signalhup_event);
	if (this->signalint_event)
		event_free(this->signalint_event);
	if (this->signalterm_event)
		event_free(this->signalterm_event);

	if (this->joblist) joblist_free(this->joblist);
	livesource_table_free(this->livesources);
	nodes_free(this->nodes);

	hash_table_free(this->ntrips.ipcount);
	hash_table_free(this->rtcm_cache);

	evdns_base_free(this->dns_base, 1);

	for (int i = 0; i < this->nbase; i++)
		event_base_free(this->base[i]);
	free(this->base);

	SSL_CTX_free(this->ssl_client_ctx);

	P_RWLOCK_WRLOCK(&this->sourcetablestack.lock);
	struct sourcetable *s;
	while ((s = TAILQ_FIRST(&this->sourcetablestack.list))) {
		TAILQ_REMOVE_HEAD(&this->sourcetablestack.list, next);
		sourcetable_decref(s);
	}
	P_RWLOCK_UNLOCK(&this->sourcetablestack.lock);

	P_RWLOCK_DESTROY(&this->sourcetablestack.lock);
	P_RWLOCK_DESTROY(&this->quotalock);
	P_RWLOCK_DESTROY(&this->rtcm_lock);
	P_RWLOCK_DESTROY(&this->ntrips.lock);
	P_RWLOCK_DESTROY(&this->ntrips.free_lock);
	P_RWLOCK_DESTROY(&this->configlock);
	P_MUTEX_DESTROY(&this->configreload);
	log_free(&this->flog);
	log_free(&this->alog);
	strfree(this->config_dir);
	strfree((char *)this->config_file);
	if (this->config)
		config_decref(this->config);
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

	listener->listener = evconnlistener_new_bind(caster_get_eventbase(this), ntripsrv_listener_cb, listener,
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
static int caster_reload_listeners(struct caster_state *this,
	struct config *new_config,
	struct caster_dynconfig *olddyn,
	struct caster_dynconfig *newdyn) {
	union sock sin;
	unsigned short port;
	int r, i;
	struct listener **new_listeners;
	char ip[64];

	if (new_config->bind_count == 0) {
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.");
		return -1;
	}

	new_listeners = (struct listener **)malloc(sizeof(struct listener *)*new_config->bind_count);
	if (!new_listeners) {
		logfmt(&this->flog, LOG_CRIT, "Can't allocate listeners");
		return -1;
	}

	/*
	 * Create listening socket addresses.
	 * Create a libevent listener for each.
	 */

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
		if (olddyn)
			for (j = 0; j < olddyn->listeners_count; j++)
				if (olddyn->listeners[j] && !ip_cmp(&sin, &olddyn->listeners[j]->sockaddr)) {
					recycled_listener = olddyn->listeners[j];
					listener_incref(recycled_listener);
					break;
				}
		if (recycled_listener) {
			if (config->tls && listener_setup_tls(recycled_listener, config) < 0) {
				logfmt(&this->flog, LOG_ERR, "Can't reuse listener %s: TLS setup failed", ip_str_port(&sin, ip, sizeof ip));
				listener_decref(recycled_listener);
				recycled_listener = NULL;
			} else {
				if (recycled_listener->tls && !config->tls) {
					recycled_listener->tls = 0;
					SSL_CTX_free(recycled_listener->ssl_server_ctx);
				}
				logfmt(&this->flog, LOG_INFO, "Reusing listener %s", ip_str_port(&sin, ip, sizeof ip));
				new_listeners[nlisteners++] = recycled_listener;
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

	if (nlisteners == 0) {
		free(new_listeners);
		logfmt(&this->flog, LOG_CRIT, "No configured ports to listen to, aborting.");
		return -1;
	}

	newdyn->listeners = new_listeners;
	newdyn->listeners_count = nlisteners;
	return 0;
}

static int
caster_reload_sourcetables(struct caster_state *caster, struct config *config) {
	struct sourcetable *local_table
		= sourcetable_read(caster, config->sourcetable_filename, config->sourcetable_priority);

	if (local_table == NULL)
		return -1;

	stack_replace_local(caster, &caster->sourcetablestack, local_table);
	sourcetable_decref(local_table);
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
caster_reload_auth(struct caster_state *caster, struct config *new_config) {
	int r = 0;
	logfmt(&caster->flog, LOG_INFO, "Reloading %s and %s", new_config->host_auth_filename, new_config->source_auth_filename);

	if (new_config->host_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, new_config->host_auth_filename);
		if (tmp != NULL) {
			new_config->host_auth = tmp;
		} else
			r = -1;
	}
	if (new_config->source_auth_filename) {
		struct auth_entry *tmp = auth_parse(caster, new_config->source_auth_filename);
		if (tmp != NULL) {
			new_config->source_auth = tmp;
		} else
			r = -1;
	}
	return r;
}

static int
caster_reload_blocklist(struct caster_state *caster, struct config *new_config) {
	int r = 0;
	struct prefix_table *p;

	if (new_config->blocklist_filename) {
		logfmt(&caster->flog, LOG_INFO, "Reloading %s", new_config->blocklist_filename);
		p = prefix_table_new();
		if (p == NULL)
			r = -1;
		else if (prefix_table_read(p, caster->config_dir, new_config->blocklist_filename, &caster->flog) < 0) {
			prefix_table_free(p);
			p = NULL;
			r = -1;
		}
		new_config->blocklist = p;
	}
	return r;
}

static int
caster_reload_rtcm_filters(struct caster_state *caster, struct config *new_config, struct caster_dynconfig *newdyn) {
	if (new_config->rtcm_filter_count == 0)
		return 0;
	if (new_config->rtcm_filter_count != 1)
		return -1;

	if (newdyn->rtcm_filter_dict)
		hash_table_free(newdyn->rtcm_filter_dict);
	newdyn->rtcm_filter_dict = hash_table_new(5, NULL);
	if (newdyn->rtcm_filter_dict == NULL)
		return -1;

	for (int i = 0; i < new_config->rtcm_filter_count; i++) {
		struct rtcm_filter *rtcm_filter;
		rtcm_filter = rtcm_filter_new(
			new_config->rtcm_filter[i].pass,
			new_config->rtcm_filter[i].convert_count ? new_config->rtcm_filter[i].convert[0].types : NULL,
			new_config->rtcm_filter[i].convert_count ? new_config->rtcm_filter[i].convert[0].conversion : 0
		);
		if (rtcm_filter == NULL) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse rtcm_filter configuration from %s", caster->config_file);
			return -1;
		}
		struct hash_table *h = rtcm_filter_dict_parse(rtcm_filter, new_config->rtcm_filter[i].apply);
		if (h == NULL) {
			logfmt(&caster->flog, LOG_ERR, "Can't parse rtcm_filter configuration from %s", caster->config_file);
			rtcm_filter_free(rtcm_filter);
			return -1;
		}
		hash_table_update(newdyn->rtcm_filter_dict, h);
		hash_table_free(h);
		if (newdyn->rtcm_filter)
			rtcm_filter_free(newdyn->rtcm_filter);
		newdyn->rtcm_filter = rtcm_filter;
	}
	return 0;
}

static struct config *caster_load_config(struct caster_state *this) {
	struct config *new_config;
	if (!(new_config = config_parse(this->config_file, atomic_fetch_add(&this->config_gen, 1)))) {
		if (this->config)
			logfmt(&this->flog, LOG_ERR, "Can't parse configuration from %s", this->config_file);
		else
			fprintf(stderr, "Can't parse configuration from %s\n", this->config_file);
		return NULL;
	}
	return new_config;
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data) {
	struct caster_signal_cb_info *info = user_data;
	struct timeval delay = { 0, 0 };

	printf("Caught %s signal; exiting.\n", info->signame);
	logfmt(&info->caster->flog, LOG_INFO, "Caught %s signal; exiting.", info->signame);

	for (int i = 0; i < info->caster->nbase; i++)
		event_base_loopexit(info->caster->base[i], &delay);
}

static int caster_start(struct caster_state *this, struct config *new_config, int lock) {
	int r = 0;
	if (lock)
		P_MUTEX_LOCK(&this->configreload);

	if (caster_start_fetchers(this, new_config, new_config->dyn) < 0)
		r = -1;
	if (caster_start_syncers(this, new_config, new_config->dyn) < 0)
		r = -1;
	if (caster_start_graylog(this, new_config, new_config->dyn) < 0)
		r = -1;
	else
		atomic_store(&this->graylog_log_level, new_config->graylog_count > 0 ? new_config->graylog[0].log_level : -1);

	if (lock)
		P_MUTEX_UNLOCK(&this->configreload);
	return r;
}

static int caster_load(struct caster_state *this, int restart) {
	struct config *new_config, *old_config;
	struct caster_dynconfig *olddyn;

	int r = 0;

	struct caster_dynconfig *newdyn = dynconfig_new(this);
	if (newdyn == NULL)
		return -1;

	new_config = caster_load_config(this);

	P_MUTEX_LOCK(&this->configreload);

	atomic_store(&this->graylog_log_level, -1);
	if (new_config == NULL) {
		P_MUTEX_UNLOCK(&this->configreload);
		dynconfig_free(newdyn);
		return -1;
	}
	new_config->dyn = newdyn;
	new_config->free_callback = dynconfig_free_callback;
	old_config = atomic_load(&this->config);
	olddyn = old_config?old_config->dyn:NULL;

	if (caster_reopen_logs(this, new_config) < 0)
		r = -1;
	if (caster_reload_sourcetables(this, new_config) < 0)
		r = -1;
	if (caster_reload_auth(this, new_config) < 0)
		r = -1;
	if (caster_reload_blocklist(this, new_config) < 0)
		r = -1;
	if (caster_reload_rtcm_filters(this, new_config, newdyn) < 0)
		r = -1;

	P_RWLOCK_WRLOCK(&this->configlock);
	atomic_store(&this->config, new_config);
	atomic_store(&this->log_level, new_config->log_level);
	atomic_store(&this->backlog_evbuffer, new_config->backlog_evbuffer);
	P_RWLOCK_UNLOCK(&this->configlock);

	if (caster_reload_graylog(this, new_config, newdyn) < 0)
		r = -1;
	if (caster_reload_listeners(this, new_config, olddyn, newdyn) < 0)
		r = -1;
	if (caster_reload_fetchers(this, new_config, olddyn, newdyn) < 0)
		r = -1;
	if (caster_reload_syncers(this, new_config, olddyn, newdyn) < 0)
		r = -1;

	if (old_config)
		config_decref(old_config);

	if (restart && caster_start(this, new_config, 0) < 0)
		r = -1;

	P_MUTEX_UNLOCK(&this->configreload);
	return r;
}

int caster_reload(struct caster_state *this) {
	return caster_load(this, 1);
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
	this->signalint_event = evsignal_new(caster_get_eventbase(this), SIGINT, signal_cb, (void *)&this->sigint_info);
	if (!this->signalint_event || event_add(this->signalint_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add SIGINT signal event!\n");
		return -1;
	}

	this->signalterm_event = evsignal_new(caster_get_eventbase(this), SIGTERM, signal_cb, (void *)&this->sigterm_info);
	if (!this->signalterm_event || event_add(this->signalterm_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add SIGTERM signal event!\n");
		return -1;
	}

	signal(SIGPIPE, SIG_IGN);

	this->signalhup_event = evsignal_new(caster_get_eventbase(this), SIGHUP, signalhup_cb, (void *)this);
	if (!this->signalhup_event || event_add(this->signalhup_event, 0) < 0) {
		fprintf(stderr, "Could not create/add SIGHUP signal event!\n");
		return -1;
	}
	return 0;
}

/*
 * Reload sourcetable fetchers
 */
static int caster_reload_fetchers(struct caster_state *this, struct config *new_config,
	struct caster_dynconfig *olddyn,
	struct caster_dynconfig *newdyn) {
	int r = 0;
	struct sourcetable_fetch_args **new_fetchers;
	if (new_config->proxy_count)
		new_fetchers = (struct sourcetable_fetch_args **)malloc(sizeof(struct sourcetable_fetch_args *)*new_config->proxy_count);
	else
		new_fetchers = NULL;

	/*
	 * For each entry in the new config, recycle a similar entry in the old configuration.
	 */
	for (int i = 0; i < new_config->proxy_count; i++) {
		struct sourcetable_fetch_args *p = NULL;
		if (olddyn)
			for (int j = 0; j < olddyn->sourcetable_fetchers_count; j++) {
				if (olddyn->sourcetable_fetchers[j] == NULL)
					/* Already cleared */
					continue;
				if (!strcmp(olddyn->sourcetable_fetchers[j]->task->host, new_config->proxy[i].host)
				&& olddyn->sourcetable_fetchers[j]->task->port == new_config->proxy[i].port) {
					p = olddyn->sourcetable_fetchers[j];
					/* Found, clear in the old table */
					olddyn->sourcetable_fetchers[j] = NULL;
					break;
				}
			}
		if (!p) {
			/* Not found, create */
			p = fetcher_sourcetable_new(this,
				new_config->proxy[i].host, new_config->proxy[i].port,
				new_config->proxy[i].tls,
				new_config->proxy[i].table_refresh_delay,
				new_config->proxy[i].priority,
				new_config);
		}
		new_fetchers[i] = p;
	}
	newdyn->sourcetable_fetchers_count = new_config->proxy_count;
	newdyn->sourcetable_fetchers = new_fetchers;
	return r;
}

/*
 * Start sourcetable fetchers
 */
static int caster_start_fetchers(struct caster_state *this, struct config *new_config, struct caster_dynconfig *newdyn) {
	int r = 0;
	for (int i = 0; i < newdyn->sourcetable_fetchers_count; i++) {
		struct sourcetable_fetch_args *p = newdyn->sourcetable_fetchers[i];
		if (p) {
			if (ntrip_task_get_state(p->task) == TASK_INIT) {
				logfmt(&this->flog, LOG_INFO, "New fetcher %s:%d", new_config->proxy[i].host, new_config->proxy[i].port);
				fetcher_sourcetable_start_with_config(p, 0, new_config);
			} else {
				fetcher_sourcetable_reload(p,
					new_config->proxy[i].table_refresh_delay,
					new_config->proxy[i].priority);
				logfmt(&this->flog, LOG_INFO, "Reusing fetcher %s:%d", new_config->proxy[i].host, new_config->proxy[i].port);
			}
		} else {
			logfmt(&this->flog, LOG_ERR, "Can't start fetcher %s:%d", new_config->proxy[i].host, new_config->proxy[i].port);
			r = -1;
		}
	}
	return r;
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

	int nbase, neventloops;

	nbase = (nthreads+3)/4;
	neventloops = nbase-1;

	caster = caster_new(config_file, nbase);
	if (!caster) {
		fprintf(stderr, "Can't allocate caster\n");
		return 1;
	}

	if (caster_set_signals(caster) < 0) {
		caster_free(caster);
		return 1;
	}

	if (caster_load(caster, 0) < 0) {
		caster_free(caster);
		return 1;
	}

	if (threads && jobs_start_threads(caster->joblist, nthreads, neventloops) < 0) {
		logfmt(&caster->flog, LOG_CRIT, "Could not create threads!");
		caster_free(caster);
		return 1;
	}

	/*
	 * Needs to be done after starting the threads, else caster_free()/ntrip_drop_by_id()
	 * may end up in an infinite loop.
	 */
	if (caster_start(caster, caster->config ,1)) {
		caster_free(caster);
		return 1;
	}

	event_base_dispatch(caster->base[0]);

	logfmt(&caster->flog, LOG_NOTICE, "Stopping caster");
	caster_free(caster);
	return 0;
}
