# Grafana dashboard for millipede-caster

This directory contains a pre-built Grafana dashboard JSON model that
consumes the caster's REST API:

- **Live sessions table** — fetches `/api/v1/net` and shows every active
  source / client with bytes in/out and start time.
- **Total sessions stat** — KPI from the same endpoint.
- **RTCM message rates bar gauge** — fetches `/api/v1/rtcm/frequencies`
  and shows one bar per mountpoint / RTCM type, color-coded by rate
  (green ≥ 0.9× expected, yellow ≥ 0.5×, red below).
- **RTCM anomaly detector table** — same data, formatted to highlight
  degraded or missing messages.

## Setup

### 1. Install the Infinity data source plugin

The dashboard uses the [Infinity](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/)
plugin to fetch JSON from HTTP endpoints without needing a backend
storage (the caster data is already in memory, no time-series DB
required).

```sh
grafana-cli plugins install yesoreyeram-infinity-datasource
# Restart Grafana
```

### 2. Import the dashboard

In Grafana:

1. Go to **Dashboards → New → Import**.
2. Upload `millipede-caster-dashboard.json` (or paste its contents).
3. When prompted for the Infinity data source, select (or create) one
   pointing at any URL — the actual URL is overridden per-panel from
   the `$base_url` template variable.

### 3. Configure the variables

After import, open the dashboard settings → **Variables**:

| Variable       | Default                          | Description |
|----------------|----------------------------------|-------------|
| `base_url`     | `http://localhost:2101`          | Base URL of the caster (no trailing slash). For remote deployments, point this at your production caster. |
| `auth_header`  | `Basic YWRtaW46YWRtaW4=`         | HTTP Authorization header value. Default is `admin:admin` base64-encoded. For Bearer token auth (recommended for production), use `Bearer <your-token>` instead. |

To generate a base64-encoded Basic auth header:
```sh
echo -n 'admin:yourpassword' | base64
```

To generate a strong bearer token (recommended):
```sh
openssl rand -hex 32
# Then set admin_token in caster.yaml and use "Bearer <that-token>" here
```

### 4. Configure the refresh rate

The dashboard defaults to a 5s refresh. The `/api/v1/rtcm/frequencies`
endpoint is cheap (in-memory hash table read), so even 1s refresh is
fine for a caster with ~100 sources.

## Alerting

To set up alerts on RTCM anomalies:

1. Edit the **RTCM anomaly detector** panel.
2. Add an alert rule:
   - **When** `last()` of `rate_hz` for any mountpoint/type is `< 0.5`
   - **For** `30s`
   - **Then** notify your contact point (Slack, email, etc.)

This will fire when a base stops emitting a critical RTCM message
(e.g. 1074 GPS MSM4) for more than 30 seconds.

## Alternative: Prometheus scrape

If you prefer Prometheus over the Infinity plugin, you can run a small
scrape script that converts `/api/v1/rtcm/frequencies` to the Prometheus
text exposition format. See `prometheus_exporter.py` (TODO — not yet
implemented in this PR).

## Compatibility

- Tested with Grafana 10.0+ and Infinity plugin 2.0+.
- The dashboard uses only standard panel types (stat, table, bar gauge,
  time series) — no custom plugins beyond Infinity.
