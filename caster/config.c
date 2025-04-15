#include <stdlib.h>
#include <string.h>

#include <cyaml/cyaml.h>

#include "ntrip_common.h"
#include "config.h"
#include "util.h"

/*
 * Amount of backlog (buffered data) allowed to a NTRIP client
 *
 * Split between:
 *	backlog_socket handled by the system
 *	backlog_evbuffer handled by event buffers, should be >0 to cope with bursts
 *
 * Packets in system buffers don't benefit from zero_copy, so it may be interesting
 * to queue as much as possible in the caster itself instead, but we risk losing
 * a bit of latency.
 */

/*
 * Compute from source rate.
 *
 * Not yet implemented.
 */
int backlog_delay = 60;

static struct config default_config = {
	.hysteresis_m = 500,
	.max_nearest_lookup_distance_m = 1000000,
	.nearest_base_count_target = 10,
	.min_nearest_recompute_interval = 10,
	.max_nearest_recompute_interval = 120,
	.min_nearest_recompute_pos_delta = 10,
	.idle_max_delay = 60,
	.reconnect_delay = 10,
	.min_raw_packet = 100,
	.max_raw_packet = 1450,
	.source_auth_filename = "source.auth",
	.host_auth_filename = "host.auth",
	.sourcetable_filename = "sourcetable.dat",
	.blocklist_filename = NULL,
	.sourcetable_priority = 90,
	.backlog_socket = 112*1024,
	.backlog_evbuffer = 16*1024,
	.sourcetable_fetch_timeout = 60,
	.on_demand_source_timeout = 60,
	.source_read_timeout = 60,
	.ntripcli_default_read_timeout = 60,
	.ntripcli_default_write_timeout = 60,
	.ntripsrv_default_read_timeout = 60,
	.ntripsrv_default_write_timeout = 60,
	.http_header_max_size = 8192,
	.http_content_length_max = 4000000,
	.access_log = "/var/log/millipede/access.log",
	.log = "/var/log/millipede/caster.log",
	.log_level = LOG_INFO,
	.admin_user = "admin",
	.disable_zero_copy = 0,
	.zero_copy = 1
};

static struct config_bind default_config_bind = {
	.port = 2101,
	.queue_size = 2000,
	.tls = 0,
	.tls_full_certificate_chain = NULL,
	.tls_private_key = NULL,
	.hostname = NULL
};

static struct config_proxy default_config_proxy = {
	.table_refresh_delay = 600,
	.priority = 20
};

static struct config_node default_config_node = {
	.port = 2443,
	.tls = 0,
	.queue_max_size = 4000000,
	.retry_delay = 30
};

static struct config_endpoint default_config_endpoint = {
	.port = 2443
};

static struct config_graylog default_config_graylog = {
	.bulk_max_size = 62000,
	.queue_max_size = 4000000,
	.retry_delay = 30,
	.port = 7777
};

static struct config_threads default_config_threads = {
	.stacksize = 500*1024
};

/*
 * YAML mapping from log level to integer values
 */
static const cyaml_strval_t log_level_strings[] = {
	{ "EMERG", LOG_EMERG },
	{ "ALERT", LOG_ALERT },
	{ "CRIT", LOG_CRIT },
	{ "ERR", LOG_ERR },
	{ "WARNING", LOG_WARNING },
	{ "NOTICE", LOG_NOTICE },
	{ "INFO", LOG_INFO },
	{ "DEBUG", LOG_DEBUG },
	{ "EDEBUG", LOG_EDEBUG },
};

static const cyaml_schema_field_t bind_fields_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"ip", CYAML_FLAG_POINTER, struct config_bind, ip, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"port", CYAML_FLAG_OPTIONAL, struct config_bind, port),
	CYAML_FIELD_INT(
		"queue_size", CYAML_FLAG_OPTIONAL, struct config_bind, queue_size),
	CYAML_FIELD_BOOL(
		"tls", CYAML_FLAG_OPTIONAL, struct config_bind, tls),
	CYAML_FIELD_STRING_PTR(
		"tls_full_certificate_chain", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_bind, tls_full_certificate_chain, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"tls_private_key", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_bind, tls_private_key, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"hostname", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_bind, hostname, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t bind_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_bind, bind_fields_schema),
};

static const cyaml_schema_field_t proxy_fields_schema[] = {
	CYAML_FIELD_INT(
		"table_refresh_delay", CYAML_FLAG_DEFAULT, struct config_proxy, table_refresh_delay),
	CYAML_FIELD_STRING_PTR(
		"host", CYAML_FLAG_POINTER, struct config_proxy, host, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"port", CYAML_FLAG_DEFAULT, struct config_proxy, port),
	CYAML_FIELD_INT(
		"priority", CYAML_FLAG_OPTIONAL, struct config_proxy, priority),
	CYAML_FIELD_BOOL(
		"tls", CYAML_FLAG_OPTIONAL, struct config_proxy, tls),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t proxy_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_proxy, proxy_fields_schema),
};

static const cyaml_schema_field_t node_fields_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"host", CYAML_FLAG_POINTER, struct config_node, host, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"port", CYAML_FLAG_DEFAULT, struct config_node, port),
	CYAML_FIELD_BOOL(
		"tls", CYAML_FLAG_OPTIONAL, struct config_node, tls),
	CYAML_FIELD_STRING_PTR(
		"authorization", CYAML_FLAG_POINTER, struct config_node, authorization, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"retry_delay", CYAML_FLAG_OPTIONAL, struct config_node, retry_delay),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t node_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_node, node_fields_schema),
};

static const cyaml_schema_field_t endpoint_fields_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"host", CYAML_FLAG_POINTER, struct config_endpoint, host, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"port", CYAML_FLAG_DEFAULT, struct config_endpoint, port),
	CYAML_FIELD_BOOL(
		"tls", CYAML_FLAG_OPTIONAL, struct config_endpoint, tls),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t endpoint_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_endpoint, endpoint_fields_schema),
};

static const cyaml_schema_field_t graylog_fields_schema[] = {
	CYAML_FIELD_INT(
		"retry_delay", CYAML_FLAG_OPTIONAL, struct config_graylog, retry_delay),
	CYAML_FIELD_INT(
		"bulk_max_size", CYAML_FLAG_OPTIONAL, struct config_graylog, bulk_max_size),
	CYAML_FIELD_INT(
		"queue_max_size", CYAML_FLAG_OPTIONAL, struct config_graylog, queue_max_size),
	CYAML_FIELD_STRING_PTR(
		"host", CYAML_FLAG_POINTER, struct config_graylog, host, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"port", CYAML_FLAG_DEFAULT, struct config_graylog, port),
	CYAML_FIELD_STRING_PTR(
		"uri", CYAML_FLAG_POINTER, struct config_graylog, uri, 0, CYAML_UNLIMITED),
	CYAML_FIELD_BOOL(
		"tls", CYAML_FLAG_OPTIONAL, struct config_graylog, tls),
	CYAML_FIELD_STRING_PTR(
		"authorization", CYAML_FLAG_POINTER, struct config_graylog, authorization, 0, CYAML_UNLIMITED),
	CYAML_FIELD_ENUM(
			"log_level", CYAML_FLAG_DEFAULT,
			struct config_graylog, log_level, log_level_strings,
			CYAML_ARRAY_LEN(log_level_strings)),
	CYAML_FIELD_STRING_PTR(
		"drainfile", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_graylog, drainfilename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t graylog_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_graylog, graylog_fields_schema),
};

static const cyaml_schema_field_t threads_fields_schema[] = {
	CYAML_FIELD_INT(
		"stacksize", CYAML_FLAG_OPTIONAL, struct config_threads, stacksize),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t threads_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_threads, threads_fields_schema),
};

static const cyaml_schema_field_t webroots_fields_schema[] = {
	CYAML_FIELD_STRING_PTR(
		"path", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_webroots, path, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"uri", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config_webroots, uri, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t webroots_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_webroots, webroots_fields_schema),
};

/* CYAML mapping schema fields array for the top level mapping. */
static const cyaml_schema_field_t top_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"listen", CYAML_FLAG_POINTER,
		struct config, bind, &bind_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_FLOAT(
		"hysteresis_m", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL, struct config, hysteresis_m),
	CYAML_FIELD_FLOAT(
		"max_nearest_lookup_distance_m", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL, struct config, max_nearest_lookup_distance_m),
	CYAML_FIELD_INT(
		"nearest_base_count_target", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL, struct config, nearest_base_count_target),
	CYAML_FIELD_SEQUENCE(
		"proxy", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, proxy, &proxy_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"node", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, node, &node_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"endpoint", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, endpoint, &endpoint_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"graylog", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, graylog, &graylog_schema, 0, 1),
	CYAML_FIELD_STRING_PTR(
		"source_auth_file", CYAML_FLAG_POINTER, struct config, source_auth_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"host_auth_file", CYAML_FLAG_POINTER, struct config, host_auth_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"blocklist_file", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config, blocklist_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"sourcetable_file", CYAML_FLAG_POINTER, struct config, sourcetable_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"sourcetable_priority", CYAML_FLAG_OPTIONAL, struct config, sourcetable_priority),
	CYAML_FIELD_INT(
		"backlog_socket", CYAML_FLAG_OPTIONAL, struct config, backlog_socket),
	CYAML_FIELD_INT(
		"backlog_evbuffer", CYAML_FLAG_OPTIONAL, struct config, backlog_evbuffer),
	CYAML_FIELD_INT(
		"sourcetable_fetch_timeout", CYAML_FLAG_OPTIONAL, struct config, sourcetable_fetch_timeout),
	CYAML_FIELD_INT(
		"on_demand_source_timeout", CYAML_FLAG_OPTIONAL, struct config, on_demand_source_timeout),
	CYAML_FIELD_INT(
		"idle_max_delay", CYAML_FLAG_OPTIONAL, struct config, idle_max_delay),
	CYAML_FIELD_INT(
		"source_read_timeout", CYAML_FLAG_OPTIONAL, struct config, source_read_timeout),
	CYAML_FIELD_INT(
		"ntripcli_default_read_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripcli_default_read_timeout),
	CYAML_FIELD_INT(
		"ntripcli_default_write_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripcli_default_write_timeout),
	CYAML_FIELD_INT(
		"ntripsrv_default_read_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripsrv_default_read_timeout),
	CYAML_FIELD_INT(
		"ntripsrv_default_write_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripsrv_default_write_timeout),
	CYAML_FIELD_INT(
		"http_header_max_size", CYAML_FLAG_OPTIONAL, struct config, http_header_max_size),
	CYAML_FIELD_INT(
		"http_content_length_max", CYAML_FLAG_OPTIONAL, struct config, http_content_length_max),
	CYAML_FIELD_STRING_PTR(
		"access_log", CYAML_FLAG_POINTER, struct config, access_log, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"log", CYAML_FLAG_POINTER, struct config, log, 0, CYAML_UNLIMITED),
	CYAML_FIELD_ENUM(
			"log_level", CYAML_FLAG_DEFAULT,
			struct config, log_level, log_level_strings,
			CYAML_ARRAY_LEN(log_level_strings)),
	CYAML_FIELD_STRING_PTR(
		"admin_user", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config, admin_user, 0, CYAML_UNLIMITED),
	CYAML_FIELD_SEQUENCE(
		"threads", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, threads, &threads_schema, 0, 1),
	CYAML_FIELD_SEQUENCE(
		"webroots", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, webroots, &webroots_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"syncer_auth", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL, struct config, syncer_auth, 0, CYAML_UNLIMITED),
	CYAML_FIELD_END
};

static const cyaml_schema_value_t top_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER,
		struct config, top_mapping_schema),
};

/*
 * Our CYAML config.
 */
static const cyaml_config_t cyaml_config = {
	.log_fn = cyaml_log,		/* Use the default logging function. */
	.mem_fn = cyaml_mem,		/* Use the default memory allocator. */
	.log_level = CYAML_LOG_WARNING,	/* Logging errors and warnings only. */
};

struct config *config_parse(const char *filename) {
	struct config *this;
	cyaml_err_t err;

	/* Load YAML file */
	err = cyaml_load_file(filename, &cyaml_config,
		&top_schema, (cyaml_data_t **)&this, NULL);
	if (err != CYAML_OK) {
		fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
		return NULL;
	}

#define	DEFAULT_ASSIGN(this, field)		{if (!(this)->field) {(this)->field = default_config.field;}}
#define	DEFAULT_ASSIGN_ARRAY(this, i, struct1, struct2, field)	{if (!(this)->struct1[i].field) {(this)->struct1[i].field = struct2.field;}}

	DEFAULT_ASSIGN(this, hysteresis_m);
	DEFAULT_ASSIGN(this, max_nearest_lookup_distance_m);
	DEFAULT_ASSIGN(this, nearest_base_count_target);
	DEFAULT_ASSIGN(this, min_nearest_recompute_interval);
	DEFAULT_ASSIGN(this, max_nearest_recompute_interval);
	DEFAULT_ASSIGN(this, min_nearest_recompute_pos_delta);
	DEFAULT_ASSIGN(this, idle_max_delay);
	DEFAULT_ASSIGN(this, reconnect_delay);
	DEFAULT_ASSIGN(this, max_raw_packet);
	DEFAULT_ASSIGN(this, on_demand_source_timeout);
	DEFAULT_ASSIGN(this, idle_max_delay);
	DEFAULT_ASSIGN(this, source_read_timeout);
	DEFAULT_ASSIGN(this, backlog_socket);
	DEFAULT_ASSIGN(this, backlog_evbuffer);
	DEFAULT_ASSIGN(this, ntripcli_default_read_timeout);
	DEFAULT_ASSIGN(this, ntripcli_default_write_timeout);
	DEFAULT_ASSIGN(this, ntripsrv_default_read_timeout);
	DEFAULT_ASSIGN(this, ntripsrv_default_write_timeout);
	DEFAULT_ASSIGN(this, access_log);
	DEFAULT_ASSIGN(this, log);
	DEFAULT_ASSIGN(this, log_level);
	DEFAULT_ASSIGN(this, admin_user);
	DEFAULT_ASSIGN(this, sourcetable_priority);
	DEFAULT_ASSIGN(this, sourcetable_fetch_timeout);
	DEFAULT_ASSIGN(this, http_header_max_size);
	DEFAULT_ASSIGN(this, http_content_length_max);

	// Undocumented
	DEFAULT_ASSIGN(this, disable_zero_copy);

	this->zero_copy = !this->disable_zero_copy;

	for (int i = 0; i < this->proxy_count; i++) {
		DEFAULT_ASSIGN_ARRAY(this, i, proxy, default_config_proxy, table_refresh_delay);
		DEFAULT_ASSIGN_ARRAY(this, i, proxy, default_config_proxy, port);
		DEFAULT_ASSIGN_ARRAY(this, i, proxy, default_config_proxy, priority);
	}

	for (int i = 0; i < this->node_count; i++) {
		DEFAULT_ASSIGN_ARRAY(this, i, node, default_config_node, port);
		DEFAULT_ASSIGN_ARRAY(this, i, node, default_config_node, queue_max_size);
		DEFAULT_ASSIGN_ARRAY(this, i, node, default_config_node, retry_delay);
	}

	for (int i = 0; i < this->endpoint_count; i++) {
		DEFAULT_ASSIGN_ARRAY(this, i, endpoint, default_config_endpoint, port);
	}

	for (int i = 0; i < this->graylog_count; i++) {
		DEFAULT_ASSIGN_ARRAY(this, i, graylog, default_config_graylog, retry_delay);
		DEFAULT_ASSIGN_ARRAY(this, i, graylog, default_config_graylog, port);
		DEFAULT_ASSIGN_ARRAY(this, i, graylog, default_config_graylog, bulk_max_size);
		DEFAULT_ASSIGN_ARRAY(this, i, graylog, default_config_graylog, queue_max_size);
	}

	for (int i = 0; i < this->bind_count; i++) {
		DEFAULT_ASSIGN_ARRAY(this, i, bind, default_config_bind, port);
		DEFAULT_ASSIGN_ARRAY(this, i, bind, default_config_bind, queue_size);
	}

	if (this->threads_count == 0) {
		this->threads = (struct config_threads *)malloc(sizeof(struct config_threads));
		if (this->threads == NULL) {
			config_free(this);
			return NULL;
		}
		this->threads[0] = default_config_threads;
		this->threads_count = 1;
	}
	for (int i = 0; i < this->threads_count; i++) {
		if (this->threads[i].stacksize == 0)
			this->threads[i].stacksize = default_config_threads.stacksize;
	}
	return this;
}

/*
 * Free everything in the config structure.
 * Best handled "by hand" here, as advised by the libcyaml documentation.
 *
 * cyaml_free() crashes if we let it do the job, possibly because of structure field order.
 */
void config_free(struct config *this) {
	for (int i = 0; i < this->bind_count; i++)
		free(this->bind[i].ip);
	free(this->bind);

	for (int i = 0; i < this->proxy_count; i++)
		free(this->proxy[i].host);
	free(this->proxy);
	free(this->threads);

	free((char *)this->host_auth_filename);
	free((char *)this->source_auth_filename);
	free((char *)this->blocklist_filename);
	free((char *)this->sourcetable_filename);
	free((char *)this->log);
	free((char *)this->access_log);
	free(this);
}
