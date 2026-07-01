#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <json-c/json.h>
#include <json-c/json_tokener.h>

#include "caster.h"
#include "conf.h"
#include "log.h"
#include "ntrip_common.h"
#include "ntripsrv.h"
#include "rtcm.h"
#include "util.h"
#include "ws_log.h"

/*
 * Minimal RFC 6455 WebSocket implementation for the /api/v1/logs/ws endpoint.
 *
 * We implement just enough of the protocol to:
 *   - Complete the handshake (compute Sec-WebSocket-Accept)
 *   - Send text frames to the client (server→client, no mask)
 *   - Receive text/binary/close/ping/pong frames (client→server, masked)
 *
 * Frame format (RFC 6455 §5.2):
 *   byte 0: [FIN:1][RSV:3][opcode:4]
 *   byte 1: [MASK:1][payload_len:7]
 *   if payload_len == 126: 2 bytes (big-endian uint16) extended length
 *   if payload_len == 127: 8 bytes (big-endian uint64) extended length
 *   if MASK: 4 bytes masking key
 *   payload
 *
 * Opcodes:
 *   0x0 continuation, 0x1 text, 0x2 binary,
 *   0x8 close, 0x9 ping, 0xA pong
 *
 * Server-to-client frames are NOT masked (RFC 6455 §5.1).
 * Client-to-server frames MUST be masked; we unmask on receive.
 *
 * Scope of v1:
 *   This is a BIDIRECTIONAL COMMAND CHANNEL, not a log push channel.
 *   The client sends JSON commands (ping, reload, set_level, drop) and
 *   receives JSON replies. Real-time log push is handled by the existing
 *   /api/v1/logs/stream SSE endpoint, which is the right tool for that
 *   job (browser-native, no frame parsing needed).
 *
 *   Extending this endpoint to also push log entries as WS text frames
 *   would require adding a per-subscriber framing callback to
 *   log_stream.c so that writes go through ws_build_frame() instead of
 *   being written as raw SSE bytes. That's a larger refactor; deferred
 *   to a future PR.
 *
 * Threading: handle_logs_ws runs on a libevent worker thread. After
 * the handshake, the read callback is replaced with ws_log_read_cb
 * via bufferevent_setcb (thread-safe on a BEV_OPT_THREADSAFE bev).
 *
 * Cleanup:
 *   - The overridden read callback doesn't need explicit cleanup
 *     because it's tied to the bufferevent, which is freed with the
 *     st by the framework.
 *   - ws_log_state_cleanup() is currently a no-op, exposed so future
 *     per-state accounting has a place to live.
 */

/*
 * The RFC 6455 GUID used to compute Sec-WebSocket-Accept.
 */
static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/*
 * Opcodes.
 */
enum ws_opcode {
	WS_OPCODE_CONTINUATION = 0x0,
	WS_OPCODE_TEXT         = 0x1,
	WS_OPCODE_BINARY       = 0x2,
	WS_OPCODE_CLOSE        = 0x8,
	WS_OPCODE_PING         = 0x9,
	WS_OPCODE_PONG         = 0xA,
};

/*
 * Compute the Sec-WebSocket-Accept header value from the client's
 * Sec-WebSocket-Key. Returns a newly malloc'd base64 string (caller
 * frees), or NULL on failure.
 *
 * accept = base64( sha1( key || GUID ) )
 */
static char *ws_compute_accept(const char *key) {
	if (key == NULL)
		return NULL;
	size_t klen = strlen(key);
	size_t glen = sizeof(WS_GUID) - 1;
	size_t combined_len = klen + glen;
	char *combined = (char *)malloc(combined_len);
	if (combined == NULL)
		return NULL;
	memcpy(combined, key, klen);
	memcpy(combined + klen, WS_GUID, glen);

	unsigned char sha[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char *)combined, combined_len, sha);
	free(combined);

	/* b64encode from util.h adds a NUL terminator and uses malloc. */
	char *b64 = b64encode((const char *)sha, SHA_DIGEST_LENGTH, 1);
	return b64;
}

/*
 * Build a WebSocket frame (server→client, no mask) containing the
 * given payload with the given opcode.
 *
 * Returns a newly malloc'd buffer with the frame bytes; *out_len
 * receives the length. Returns NULL on failure.
 *
 * Frame layout:
 *   byte 0: 0x80 | opcode       (FIN=1)
 *   byte 1: 0 | payload_len    (MASK=0)
 *   if payload_len <= 125:   that's it for the header
 *   if payload_len <= 65535: 0x7e, then 2 bytes big-endian len
 *   else:                    0x7f, then 8 bytes big-endian len
 *   payload bytes
 */
static char *ws_build_frame(enum ws_opcode opcode, const char *payload, size_t len, size_t *out_len) {
	size_t header_len;
	char header[10];
	header[0] = (char)(0x80 | (opcode & 0x0F));
	if (len <= 125) {
		header[1] = (char)len;
		header_len = 2;
	} else if (len <= 65535) {
		header[1] = 0x7e;
		header[2] = (char)((len >> 8) & 0xFF);
		header[3] = (char)(len & 0xFF);
		header_len = 4;
	} else {
		header[1] = 0x7f;
		uint64_t l = (uint64_t)len;
		for (int i = 0; i < 8; i++)
			header[2 + i] = (char)((l >> (56 - 8*i)) & 0xFF);
		header_len = 10;
	}

	char *frame = (char *)malloc(header_len + len);
	if (frame == NULL)
		return NULL;
	memcpy(frame, header, header_len);
	if (len)
		memcpy(frame + header_len, payload, len);
	*out_len = header_len + len;
	return frame;
}

/*
 * Send a text frame with the given string payload (must be NUL-terminated).
 * Returns 0 on success, -1 on failure.
 */
static int ws_send_text(struct bufferevent *bev, const char *s) {
	size_t len = strlen(s);
	size_t frame_len = 0;
	char *frame = ws_build_frame(WS_OPCODE_TEXT, s, len, &frame_len);
	if (frame == NULL)
		return -1;
	struct evbuffer *out = bufferevent_get_output(bev);
	int r = evbuffer_add(out, frame, frame_len);
	free(frame);
	return r;
}

/*
 * Send a JSON object as a text frame and put it.
 */
static int ws_send_json(struct bufferevent *bev, json_object *j) {
	const char *s = json_object_to_json_string(j);
	int r = ws_send_text(bev, s);
	return r;
}

/*
 * Send a WebSocket close frame (opcode 0x8) with no payload, then
 * shut down the connection. RFC 6455 §5.5.1: server may close
 * immediately after sending close, or wait for the client's close
 * echo — we opt for immediate close to keep the implementation simple.
 */
static void ws_send_close(struct bufferevent *bev) {
	size_t frame_len = 0;
	char *frame = ws_build_frame(WS_OPCODE_CLOSE, NULL, 0, &frame_len);
	if (frame) {
		struct evbuffer *out = bufferevent_get_output(bev);
		evbuffer_add(out, frame, frame_len);
		free(frame);
	}
}

/*
 * Parse a single WebSocket frame from the input buffer.
 *
 * On success: returns the number of bytes consumed (frame header +
 * payload), sets *out_opcode, *out_fin, allocates *out_payload (caller
 * frees) with a NUL-terminated unmasked copy of the payload, and sets
 * *out_payload_len to the payload length (excluding the NUL).
 *
 * On incomplete frame: returns 0, leaves *out_* untouched. Caller
 * should wait for more data.
 *
 * On parse error (e.g. invalid length, masked server frame — which
 * we don't enforce, but we DO enforce client masking): returns -1.
 */
static ssize_t ws_parse_frame(const unsigned char *data, size_t len,
			      int *out_fin, int *out_opcode,
			      char **out_payload, size_t *out_payload_len) {
	if (len < 2)
		return 0;
	int fin = (data[0] >> 7) & 0x01;
	int opcode = data[0] & 0x0F;
	int masked = (data[1] >> 7) & 0x01;
	size_t payload_len = (size_t)(data[1] & 0x7F);
	size_t header_len = 2;

	if (payload_len == 126) {
		if (len < 4)
			return 0;
		payload_len = ((size_t)data[2] << 8) | (size_t)data[3];
		header_len = 4;
	} else if (payload_len == 127) {
		if (len < 10)
			return 0;
		/* RFC 6455 §5.1: high bit of uint64 MUST be 0 */
		if (data[2] & 0x80)
			return -1;
		uint64_t l = 0;
		for (int i = 0; i < 8; i++)
			l = (l << 8) | (uint64_t)data[2 + i];
		/* Refuse frames larger than 16 MiB to avoid DoS */
		if (l > 16ULL * 1024 * 1024)
			return -1;
		payload_len = (size_t)l;
		header_len = 10;
	}

	/* RFC 6455 §5.1: client→server frames MUST be masked. */
	if (!masked)
		return -1;

	size_t mask_len = 4;
	size_t total = header_len + mask_len + payload_len;
	if (len < total)
		return 0;

	const unsigned char *mask = data + header_len;
	const unsigned char *payload = data + header_len + mask_len;

	char *out = (char *)malloc(payload_len + 1);
	if (out == NULL)
		return -1;
	for (size_t i = 0; i < payload_len; i++)
		out[i] = (char)(payload[i] ^ mask[i % 4]);
	out[payload_len] = '\0';

	*out_fin = fin;
	*out_opcode = opcode;
	*out_payload = out;
	*out_payload_len = payload_len;
	return (ssize_t)total;
}

/*
 * Dispatch a single JSON command received over the WebSocket.
 * Replies synchronously on the same bev.
 */
static void ws_handle_command(struct ntrip_state *st, const char *payload, size_t payload_len) {
	struct bufferevent *bev = st->bev;
	struct json_tokener *tok = json_tokener_new();
	json_object *cmd = json_tokener_parse_ex(tok, payload, (int)payload_len);
	enum json_tokener_error jerr = json_tokener_get_error(tok);
	json_tokener_free(tok);

	if (jerr != json_tokener_success || cmd == NULL) {
		json_object *err = json_object_new_object();
		json_object_object_add_ex(err, "type", json_object_new_string("error"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(err, "message", json_object_new_string("invalid JSON"), JSON_C_CONSTANT_NEW);
		ws_send_json(bev, err);
		json_object_put(err);
		if (cmd)
			json_object_put(cmd);
		return;
	}

	const char *subcmd = json_object_get_string(json_object_object_get(cmd, "cmd"));
	json_object *reply = json_object_new_object();

	if (subcmd == NULL) {
		json_object_object_add_ex(reply, "type", json_object_new_string("error"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(reply, "message", json_object_new_string("missing 'cmd' field"), JSON_C_CONSTANT_NEW);
	} else if (!strcmp(subcmd, "ping")) {
		json_object_object_add_ex(reply, "type", json_object_new_string("pong"), JSON_C_CONSTANT_NEW);
	} else if (!strcmp(subcmd, "subscribe")) {
		/* Already subscribed on handshake — just acknowledge. */
		json_object_object_add_ex(reply, "type", json_object_new_string("subscribed"), JSON_C_CONSTANT_NEW);
	} else if (!strcmp(subcmd, "reload")) {
		int r = caster_reload(st->caster);
		json_object_object_add_ex(reply, "type", json_object_new_string("reload"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(reply, "result", json_object_new_int(r), JSON_C_CONSTANT_NEW);
	} else if (!strcmp(subcmd, "drop")) {
		json_object *jid = json_object_object_get(cmd, "id");
		long long id = -1;
		if (jid && json_object_is_type(jid, json_type_int))
			id = json_object_get_int64(jid);
		int r = (id >= 0) ? ntrip_drop_by_id(st->caster, id) : 0;
		json_object_object_add_ex(reply, "type", json_object_new_string("drop"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(reply, "result", json_object_new_int(r), JSON_C_CONSTANT_NEW);
	} else if (!strcmp(subcmd, "set_level")) {
		const char *lvl = json_object_get_string(json_object_object_get(cmd, "level"));
		int ok = 0;
		if (lvl) {
			int syslog_lvl = -1;
			if      (!strcasecmp(lvl, "EMERG"))   syslog_lvl = LOG_EMERG;
			else if (!strcasecmp(lvl, "ALERT"))   syslog_lvl = LOG_ALERT;
			else if (!strcasecmp(lvl, "CRIT"))    syslog_lvl = LOG_CRIT;
			else if (!strcasecmp(lvl, "ERR"))     syslog_lvl = LOG_ERR;
			else if (!strcasecmp(lvl, "WARNING")) syslog_lvl = LOG_WARNING;
			else if (!strcasecmp(lvl, "NOTICE"))  syslog_lvl = LOG_NOTICE;
			else if (!strcasecmp(lvl, "INFO"))    syslog_lvl = LOG_INFO;
			else if (!strcasecmp(lvl, "DEBUG"))   syslog_lvl = LOG_DEBUG;
			else if (!strcasecmp(lvl, "EDEBUG"))  syslog_lvl = 8;
			if (syslog_lvl >= 0) {
				atomic_store(&st->caster->flog.max_log_level, syslog_lvl);
				ok = 1;
			}
		}
		json_object_object_add_ex(reply, "type", json_object_new_string("set_level"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(reply, "ok", json_object_new_boolean(ok), JSON_C_CONSTANT_NEW);
	} else {
		json_object_object_add_ex(reply, "type", json_object_new_string("error"), JSON_C_CONSTANT_NEW);
		json_object_object_add_ex(reply, "message",
			json_object_new_string("unknown command"), JSON_C_CONSTANT_NEW);
	}

	ws_send_json(bev, reply);
	json_object_put(reply);
	json_object_put(cmd);
}

/*
 * Read callback for the WebSocket connection.
 * Invoked by libevent after we override the read cb in handle_logs_ws.
 *
 * Loops over the input buffer, parsing one frame at a time. For each
 * text frame, dispatch the JSON command. For close frames, send a
 * close echo and tear down the connection. For ping frames, send a
 * pong. For pong frames, ignore.
 *
 * Continuation frames (opcode 0x0) are not yet supported — we treat
 * them as a parse error since all our commands are small JSON objects
 * that fit in a single frame.
 */
void ws_log_read_cb(struct bufferevent *bev, void *arg) {
	struct ntrip_state *st = (struct ntrip_state *)arg;
	if (st == NULL)
		return;

	struct evbuffer *input = bufferevent_get_input(bev);
	size_t available = evbuffer_get_length(input);
	if (available == 0)
		return;

	/* Pull the entire available buffer into a contiguous scratch area.
	 * evbuffer_pullup doesn't drain, just linearizes. */
	unsigned char *data = evbuffer_pullup(input, available);
	if (data == NULL)
		return;

	size_t consumed = 0;
	while (consumed < available) {
		int fin = 0, opcode = 0;
		char *payload = NULL;
		size_t payload_len = 0;
		ssize_t n = ws_parse_frame(data + consumed, available - consumed,
					   &fin, &opcode, &payload, &payload_len);
		if (n < 0) {
			/* Parse error — close the connection. */
			ntrip_log(st, LOG_NOTICE, "ws: frame parse error, closing");
			ws_send_close(bev);
			ntrip_set_state(st, NTRIP_WAIT_CLOSE);
			break;
		}
		if (n == 0) {
			/* Incomplete frame — wait for more data. */
			break;
		}

		switch (opcode) {
		case WS_OPCODE_TEXT:
			ws_handle_command(st, payload, payload_len);
			break;
		case WS_OPCODE_PING: {
			/* Echo as pong. */
			size_t fl = 0;
			char *f = ws_build_frame(WS_OPCODE_PONG, payload, payload_len, &fl);
			if (f) {
				struct evbuffer *out = bufferevent_get_output(bev);
				evbuffer_add(out, f, fl);
				free(f);
			}
			break;
		}
		case WS_OPCODE_PONG:
			/* Ignore — clients send pongs in response to our pings,
			 * but we don't currently send pings. */
			break;
		case WS_OPCODE_CLOSE:
			ntrip_log(st, LOG_DEBUG, "ws: client sent close");
			ws_send_close(bev);
			ntrip_set_state(st, NTRIP_WAIT_CLOSE);
			free(payload);
			consumed += (size_t)n;
			goto done;
		default:
			/* Continuation (0x0) or binary (0x2): not supported. */
			ntrip_log(st, LOG_NOTICE, "ws: unsupported opcode 0x%x", opcode);
			ws_send_close(bev);
			ntrip_set_state(st, NTRIP_WAIT_CLOSE);
			free(payload);
			consumed += (size_t)n;
			goto done;
		}
		free(payload);
		consumed += (size_t)n;
	}

done:
	if (consumed > 0)
		evbuffer_drain(input, consumed);
}

/*
 * Hook called from ntrip_free to clean up any WebSocket-specific state.
 *
 * Currently a no-op: the log_stream subscription is already cleaned up
 * by the SSE cleanup path (which uses the same log_stream_sub field),
 * and the overridden read callback is tied to the bev which is freed
 * by the framework. We expose this function so that future cleanup
 * hooks (e.g. accounting, metrics) have a clear place to live.
 */
void ws_log_state_cleanup(struct ntrip_state *st) {
	(void)st;
}

/*
 * Handle GET /api/v1/logs/ws.
 *
 * Performs the WebSocket handshake and upgrades the connection to a
 * bidirectional log stream + remote control channel.
 */
int handle_logs_ws(struct ntrip_state *st, struct evkeyvalq *headers) {
	(void)headers;  /* response headers are written directly to the bev */

	struct evbuffer *output = bufferevent_get_output(st->bev);

	if (st->sec_websocket_key == NULL) {
		/* The client didn't send a Sec-WebSocket-Key header —
		 * they're not actually trying to upgrade. Reply with a
		 * 400 so they know what's expected. */
		evbuffer_add_printf(output,
			"HTTP/1.1 400 Bad Request\r\n"
			"Content-Type: text/plain; charset=utf-8\r\n"
			"Connection: close\r\n"
			"\r\n"
			"This endpoint requires a WebSocket upgrade "
			"(Sec-WebSocket-Key header missing).\r\n");
		ntrip_set_state(st, NTRIP_WAIT_CLOSE);
		return -1;
	}

	char *accept_value = ws_compute_accept(st->sec_websocket_key);
	if (accept_value == NULL) {
		evbuffer_add_printf(output,
			"HTTP/1.1 500 Internal Server Error\r\n"
			"Connection: close\r\n"
			"\r\n");
		ntrip_set_state(st, NTRIP_WAIT_CLOSE);
		return -1;
	}

	/* Send the 101 Switching Protocols response. */
	evbuffer_add_printf(output,
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"\r\n",
		accept_value);
	free(accept_value);

	/* Send a hello text frame so the client knows the upgrade worked.
	 * The bidirectional command channel is now open: subsequent
	 * reads from the bev will go to ws_log_read_cb. */
	const char *hello = "{\"type\":\"hello\",\"message\":\"WebSocket command channel connected\"}";
	ws_send_text(st->bev, hello);

	/* Override the read callback so incoming frames are dispatched to
	 * ws_log_read_cb instead of the HTTP parser. We keep the event
	 * callback (ntripsrv_eventcb) so EOF/error still triggers
	 * ntrip_free. The write callback can be NULL since we don't
	 * need to be notified of write completions. */
	bufferevent_setcb(st->bev, ws_log_read_cb, NULL, ntripsrv_eventcb, st);

	/* Transition to idle state — the connection stays open until
	 * either side closes it. */
	ntrip_set_state(st, NTRIP_IDLE_CLIENT);
	st->connection_keepalive = 0;

	return 0;
}
