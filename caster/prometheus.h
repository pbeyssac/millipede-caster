#ifndef __PROMETHEUS_H__
#define __PROMETHEUS_H__

#include "caster.h"
#include "request.h"

/*
 * Prometheus metrics exporter.
 *
 * Exposes a snapshot of caster internal state in the Prometheus text
 * exposition format (version 0.0.4) at the /api/v1/metrics endpoint.
 *
 * Returned metrics:
 *
 *   millipede_uptime_seconds               gauge
 *   millipede_connections_total{type=...}   gauge   (active source/client/other)
 *   millipede_received_bytes_total         counter (sum across all ntrip_state)
 *   millipede_sent_bytes_total             counter
 *   millipede_mountpoints                  gauge   (active livesources)
 *   millipede_log_stream_subscribers       gauge
 *   millipede_rtcm_packets_total{mountpoint,type}  counter (from rtcm_freq)
 *   millipede_rtcm_rate_hz{mountpoint,type}        gauge
 *
 * Auth: same as the rest of /api/v1/ (HTTP Basic / Bearer / ?token=).
 *
 * The output is dynamically allocated and owned by the returned mime_content
 * (use_strfree=1, so mime_free() will free it).
 */
struct mime_content *prometheus_metrics_text(struct caster_state *caster, struct request *req);

#endif /* __PROMETHEUS_H__ */
