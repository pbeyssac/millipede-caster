#ifndef __WS_LOG_H__
#define __WS_LOG_H__

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "ntrip_common.h"

/*
 * Bidirectional WebSocket endpoint for real-time log streaming + remote control.
 *
 * Endpoint: GET /api/v1/logs/ws
 * Auth:     same as the rest of /api/v1/ (HTTP Basic / Bearer / ?token=)
 *
 * After the WebSocket handshake (HTTP 101 Switching Protocols), the
 * bufferevent is subscribed to the same log_stream used by the SSE
 * endpoint (/api/v1/logs/stream). New log entries are pushed to the
 * client as WebSocket text frames containing a JSON object with the
 * same shape as the SSE "data:" payload.
 *
 * The client may send text frames containing JSON commands:
 *   {"cmd":"ping"}                            -> replies {"type":"pong"}
 *   {"cmd":"reload"}                          -> triggers a config reload,
 *                                                replies {"type":"reload","result":<n>}
 *   {"cmd":"set_level","level":"DEBUG"}       -> changes the runtime log level,
 *                                                replies {"type":"set_level","ok":<bool>}
 *   {"cmd":"drop","id":<int>}                 -> drops the connection with that id,
 *                                                replies {"type":"drop","result":<n>}
 *   {"cmd":"subscribe"}                       -> no-op (already subscribed on connect);
 *                                                replies {"type":"subscribed"}
 *
 * Unrecognised commands produce {"type":"error","message":"..."}.
 *
 * The WebSocket implementation is intentionally minimal: it handles
 * RFC 6455 framing for the subset we need (text frames, ping/pong,
 * close), without depending on any external WebSocket library.
 *
 * Returns 0 on success (connection kept open and hijacked), -1 on
 * failure (caller should set *err appropriately).
 */
int handle_logs_ws(struct ntrip_state *st, struct evkeyvalq *headers);

/*
 * Read-side callback: invoked by libevent when bytes arrive on the
 * bufferevent. Parses incoming WebSocket frames and dispatches the
 * embedded JSON commands.
 *
 * Public only so it can be referenced from the dispatcher in
 * ntrip_common.c (where the per-state read callback is set).
 */
void ws_log_read_cb(struct bufferevent *bev, void *arg);

/*
 * Per-state cleanup (called from ntrip_free via the same hook used
 * for the SSE subscriber). Safe to call with a NULL handle.
 */
void ws_log_state_cleanup(struct ntrip_state *st);

#endif /* __WS_LOG_H__ */
