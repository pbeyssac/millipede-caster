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
	.idle_max_delay = 60,
	.reconnect_delay = 10,
	.min_raw_packet = 100,
	.max_raw_packet = 1450,
	.source_auth_filename = "source.auth",
	.host_auth_filename = "host.auth",
	.sourcetable_filename = "sourcetable.dat",
	.backlog_socket = 112*1024,
	.backlog_evbuffer = 16*1024,
	.sourcetable_fetch_timeout = 60,
	.on_demand_source_timeout = 60,
	.source_read_timeout = 60,
	.ntripsrv_default_read_timeout = 60,
	.ntripsrv_default_write_timeout = 60,
	.access_log = "/var/log/millipede/access.log",
	.log = "/var/log/millipede/caster.log",
	.log_level = LOG_INFO,
	.admin_user = "admin",
	.disable_zero_copy = 0,
	.zero_copy = 1
};

static struct config_bind default_config_bind = {
	.port = 2101,
	.queue_size = 2000
};

static struct config_proxy default_config_proxy = {
	.table_refresh_delay = 600
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
	CYAML_FIELD_END
};

static const cyaml_schema_value_t proxy_schema = {
	CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT,
		struct config_proxy, proxy_fields_schema),
};

/* CYAML mapping schema fields array for the top level mapping. */
static const cyaml_schema_field_t top_mapping_schema[] = {
	CYAML_FIELD_SEQUENCE(
		"listen", CYAML_FLAG_POINTER,
		struct config, bind, &bind_schema, 0, CYAML_UNLIMITED),
	CYAML_FIELD_FLOAT(
		"hysteresis_m", CYAML_FLAG_DEFAULT|CYAML_FLAG_OPTIONAL, struct config, hysteresis_m),
	CYAML_FIELD_SEQUENCE(
		"proxy", CYAML_FLAG_POINTER|CYAML_FLAG_OPTIONAL,
		struct config, proxy, &proxy_schema, 0, 1),
	CYAML_FIELD_STRING_PTR(
		"source_auth_file", CYAML_FLAG_POINTER, struct config, source_auth_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"host_auth_file", CYAML_FLAG_POINTER, struct config, host_auth_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_STRING_PTR(
		"sourcetable_file", CYAML_FLAG_POINTER, struct config, sourcetable_filename, 0, CYAML_UNLIMITED),
	CYAML_FIELD_INT(
		"backlog_socket", CYAML_FLAG_OPTIONAL, struct config, backlog_socket),
	CYAML_FIELD_INT(
		"backlog_evbuffer", CYAML_FLAG_OPTIONAL, struct config, backlog_evbuffer),
	CYAML_FIELD_INT(
		"sourcetable_fetch_timeout", CYAML_FLAG_OPTIONAL, struct config, sourcetable_fetch_timeout),
	CYAML_FIELD_INT(
		"on_demand_source_timeout", CYAML_FLAG_OPTIONAL, struct config, on_demand_source_timeout),
	CYAML_FIELD_INT(
		"source_read_timeout", CYAML_FLAG_OPTIONAL, struct config, source_read_timeout),
	CYAML_FIELD_INT(
		"ntripsrv_default_read_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripsrv_default_read_timeout),
	CYAML_FIELD_INT(
		"ntripsrv_default_write_timeout", CYAML_FLAG_OPTIONAL, struct config, ntripsrv_default_write_timeout),
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

#define	DEFAULT_ASSIGN(this, field)	{if (!(this)->field) {(this)->field = default_config.field;}}

	DEFAULT_ASSIGN(this, hysteresis_m);
	DEFAULT_ASSIGN(this, idle_max_delay);
	DEFAULT_ASSIGN(this, reconnect_delay);
	DEFAULT_ASSIGN(this, max_raw_packet);
	DEFAULT_ASSIGN(this, on_demand_source_timeout);
	DEFAULT_ASSIGN(this, source_read_timeout);
	DEFAULT_ASSIGN(this, backlog_socket);
	DEFAULT_ASSIGN(this, backlog_evbuffer);
	DEFAULT_ASSIGN(this, ntripsrv_default_read_timeout);
	DEFAULT_ASSIGN(this, ntripsrv_default_write_timeout);
	DEFAULT_ASSIGN(this, access_log);
	DEFAULT_ASSIGN(this, log);
	DEFAULT_ASSIGN(this, log_level);
	DEFAULT_ASSIGN(this, admin_user);

	// Undocumented
	DEFAULT_ASSIGN(this, disable_zero_copy);

	this->zero_copy = !this->disable_zero_copy;

	for (int i = 0; i < this->proxy_count; i++) {
		if (this->proxy[i].table_refresh_delay == 0)
			this->proxy[i].table_refresh_delay = default_config_proxy.table_refresh_delay;
		if (this->proxy[i].port == 0)
			this->proxy[i].port = default_config_proxy.port;
	}

	for (int i = 0; i < this->bind_count; i++) {
		if (this->bind[i].port == 0)
			this->bind[i].port = default_config_bind.port;
		if (this->bind[i].queue_size == 0)
			this->bind[i].queue_size = default_config_bind.queue_size;
	}
	return this;
}

void config_free(struct config *this) {
	cyaml_err_t err;
	err = cyaml_free(&cyaml_config, &top_schema, this, 0);
	if (err != CYAML_OK)
		fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
}
