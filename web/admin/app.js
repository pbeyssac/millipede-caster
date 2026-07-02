/*
 * Millipede Caster — admin UI
 * Vanilla JS, no framework, no build chain.
 *
 * All API calls go to /adm/api/v1/* with HTTP Basic auth.
 * The SSE log stream is at /adm/api/v1/logs/stream (query-string auth
 * because EventSource cannot set custom headers).
 */

const App = (() => {
  const STORAGE_KEY = 'millipede_caster_auth';
  let auth = null;          // { user, pass, b64 }
  let currentView = 'dashboard';
  let refreshTimer = null;
  let logStream = null;
  let logBuffer = [];
  let map = null;           // Leaflet map instance
  let mapMarkers = null;    // Layer group for markers
  let mapLiveSet = new Set(); // Mountpoints currently connected
  const LOG_BUFFER_MAX = 5000;

  // ---- Utilities ----
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  function fmtBytes(n) {
    if (n == null) return '—';
    if (n < 1024) return n + ' B';
    if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
    if (n < 1024*1024*1024) return (n/1024/1024).toFixed(1) + ' MB';
    return (n/1024/1024/1024).toFixed(2) + ' GB';
  }
  function fmtNum(n) { return (n ?? 0).toLocaleString(); }
  function fmtUptime(startedIso) {
    if (!startedIso) return '—';
    const started = new Date(startedIso);
    const diff = Date.now() - started.getTime();
    if (diff < 0) return '—';
    const s = Math.floor(diff / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (h > 0) return h + 'h ' + m + 'm';
    if (m > 0) return m + 'm ' + (s % 60) + 's';
    return s + 's';
  }
  function fmtTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleTimeString();
  }
  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c =>
      ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // ---- API client ----
  async function apiGet(path) {
    const r = await fetch('/adm' + path, {
      headers: { 'Authorization': 'Basic ' + auth.b64 }
    });
    if (r.status === 401) {
      App.logout('Authentication failed.');
      throw new Error('401');
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }
  async function apiPost(path, body) {
    const opts = {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + auth.b64,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    };
    if (body) opts.body = body;
    const r = await fetch('/adm' + path, opts);
    if (r.status === 401) { App.logout('Authentication failed.'); throw new Error('401'); }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  // ---- Login / Logout ----
  function init() {
    const saved = sessionStorage.getItem(STORAGE_KEY);
    if (saved) {
      try { auth = JSON.parse(saved); showApp(); return; } catch {}
    }
    showLogin();
  }

  function showLogin() {
    $('#login-overlay').hidden = false;
    $('#app').hidden = true;
    $('#login-user').focus();
    $('#login-form').addEventListener('submit', onLoginSubmit);
  }

  async function onLoginSubmit(e) {
    e.preventDefault();
    const user = $('#login-user').value;
    const pass = $('#login-pass').value;
    const b64 = btoa(user + ':' + pass);
    auth = { user, pass, b64 };
    // Test credentials by calling a lightweight endpoint
    try {
      await apiGet('/api/v1/mem');
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(auth));
      showApp();
    } catch (err) {
      $('#login-error').textContent = 'Invalid credentials or caster not reachable.';
      $('#login-error').hidden = false;
      auth = null;
    }
  }

  function showApp() {
    $('#login-overlay').hidden = true;
    $('#app').hidden = false;
    $('#user-display').textContent = auth.user;
    $('#logout').addEventListener('click', () => App.logout());
    $$('#app nav button').forEach(btn => {
      btn.addEventListener('click', () => switchView(btn.dataset.view));
    });

    // Bind toolbar actions
    $('#reload-sources').addEventListener('click', refreshSources);
    $('#reload-clients').addEventListener('click', refreshClients);
    $('#logs-clear').addEventListener('click', clearLogs);
    $('#logs-filter').addEventListener('input', renderLogs);
    $('#rtcm-filter').addEventListener('input', refreshRtcm);
    $('#rtcm-anomalies-only').addEventListener('change', refreshRtcm);
    $('#map-refresh').addEventListener('click', refreshMap);

    switchView('dashboard');
  }

  function logout(msg) {
    sessionStorage.removeItem(STORAGE_KEY);
    if (logStream) { logStream.close(); logStream = null; }
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
    auth = null;
    $('#login-error').textContent = msg || '';
    $('#login-error').hidden = !msg;
    $('#login-pass').value = '';
    showLogin();
  }

  // ---- View switching ----
  function switchView(view) {
    currentView = view;
    $$('#app nav button').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    $$('.view').forEach(v => v.classList.remove('active'));
    $('#view-' + view).classList.add('active');

    // Stop any per-view refresh
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
    if (logStream) { logStream.close(); logStream = null; }

    // Start the right refresh for the new view
    if (view === 'dashboard') { refreshDashboard(); refreshTimer = setInterval(refreshDashboard, 5000); }
    else if (view === 'sources') { refreshSources(); refreshTimer = setInterval(refreshSources, 5000); }
    else if (view === 'clients') { refreshClients(); refreshTimer = setInterval(refreshClients, 5000); }
    else if (view === 'map') { initMap(); refreshMap(); refreshTimer = setInterval(refreshMap, 15000); }
    else if (view === 'rtcm') { refreshRtcm(); refreshTimer = setInterval(refreshRtcm, 5000); }
    else if (view === 'logs') { startLogStream(); }
  }

  // ---- Dashboard ----
  async function refreshDashboard() {
    try {
      const data = await apiGet('/api/v1/net');
      const sessions = Object.values(data);
      const sources = sessions.filter(s => s.type === 'source' || s.type === 'source_fetcher');
      const clients = sessions.filter(s => s.type === 'client');
      const bytesIn = sources.reduce((a, s) => a + (s.received_bytes || 0), 0);
      const bytesOut = clients.reduce((a, s) => a + (s.sent_bytes || 0), 0);
      // Find oldest session start for uptime
      let oldest = null;
      for (const s of sessions) {
        const start = s.start ? s.start.replace(' ', 'T') + 'Z' : null;
        if (start) {
          const t = new Date(start).getTime();
          if (!oldest || t < oldest) oldest = t;
        }
      }

      $('#kpi-sources').textContent = sources.length;
      $('#kpi-clients').textContent = clients.length;
      $('#kpi-bytes-in').textContent = fmtBytes(bytesIn);
      $('#kpi-bytes-out').textContent = fmtBytes(bytesOut);
      $('#kpi-uptime').textContent = oldest ? fmtUptime(new Date(oldest).toISOString()) : '—';

      // Source table
      const tbody = $('#dashboard-sources tbody');
      tbody.innerHTML = sources.map(s => `
        <tr>
          <td class="mono">${escapeHtml(s.mountpoint || '—')}</td>
          <td class="mono">${escapeHtml(s.ip || '—')}:${s.port || '—'}</td>
          <td class="num">${fmtBytes(s.received_bytes)}</td>
          <td>${fmtTime(s.start ? s.start.replace(' ','T')+'Z' : null)}</td>
        </tr>
      `).join('') || '<tr><td colspan="4" class="hint">No active source.</td></tr>';
    } catch (err) {
      console.error('refreshDashboard', err);
    }
  }

  // ---- Sources ----
  async function refreshSources() {
    try {
      const data = await apiGet('/api/v1/net');
      const sessions = Object.values(data);
      const sources = sessions.filter(s => s.type === 'source' || s.type === 'source_fetcher');
      $('#sources-hint').textContent = `${sources.length} source(s) · updated ${new Date().toLocaleTimeString()}`;
      const tbody = $('#sources-table tbody');
      tbody.innerHTML = sources.map(s => `
        <tr>
          <td class="mono">${s.id}</td>
          <td class="mono">${escapeHtml(s.mountpoint || '—')}</td>
          <td class="mono">${escapeHtml(s.ip || '—')}:${s.port || '—'}</td>
          <td class="num">${fmtBytes(s.received_bytes)}</td>
          <td class="num">${fmtBytes(s.sent_bytes)}</td>
          <td>${escapeHtml(s.user_agent || '—')}</td>
          <td>${fmtTime(s.start ? s.start.replace(' ','T')+'Z' : null)}</td>
          <td><button class="drop-btn" data-id="${s.id}">Drop</button></td>
        </tr>
      `).join('') || '<tr><td colspan="8" class="hint">No active source.</td></tr>';
      // Bind drop buttons
      tbody.querySelectorAll('.drop-btn').forEach(b =>
        b.addEventListener('click', () => dropSession(b.dataset.id)));
    } catch (err) {
      console.error('refreshSources', err);
      $('#sources-hint').textContent = 'Error: ' + err.message;
    }
  }

  // ---- Clients ----
  async function refreshClients() {
    try {
      const data = await apiGet('/api/v1/net');
      const sessions = Object.values(data);
      const clients = sessions.filter(s => s.type === 'client');
      $('#clients-hint').textContent = `${clients.length} client(s) · updated ${new Date().toLocaleTimeString()}`;
      const tbody = $('#clients-table tbody');
      tbody.innerHTML = clients.map(s => `
        <tr>
          <td class="mono">${s.id}</td>
          <td class="mono">${escapeHtml(s.ip || '—')}:${s.port || '—'}</td>
          <td class="mono">${escapeHtml(s.mountpoint || '—')}</td>
          <td class="num">${fmtBytes(s.sent_bytes)}</td>
          <td>${escapeHtml(s.user_agent || '—')}</td>
          <td>${fmtTime(s.start ? s.start.replace(' ','T')+'Z' : null)}</td>
          <td><button class="drop-btn" data-id="${s.id}">Drop</button></td>
        </tr>
      `).join('') || '<tr><td colspan="7" class="hint">No active client.</td></tr>';
      tbody.querySelectorAll('.drop-btn').forEach(b =>
        b.addEventListener('click', () => dropSession(b.dataset.id)));
    } catch (err) {
      console.error('refreshClients', err);
      $('#clients-hint').textContent = 'Error: ' + err.message;
    }
  }

  async function dropSession(id) {
    if (!confirm('Drop session ' + id + '?')) return;
    try {
      await apiPost('/api/v1/drop?id=' + encodeURIComponent(id));
      // Refresh the current view
      if (currentView === 'sources') refreshSources();
      else if (currentView === 'clients') refreshClients();
    } catch (err) {
      alert('Drop failed: ' + err.message);
    }
  }

  // ---- RTCM ----
  // Expected RTCM rates (Hz) per type. NULL = not expected (won't flag as anomaly).
  const RTCM_EXPECTED = {
    1005: 0.1,  // Station position (once every 10s)
    1006: 0.1,
    1008: 0.1,
    1019: 1/30, // Ephemeris (every 30s)
    1020: 1/30,
    1042: 1/30,
    1045: 1/30,
    1046: 1/30,
    1074: 1.0,  // MSM4 GPS
    1084: 1.0,  // MSM4 GLONASS
    1094: 1.0,  // MSM4 Galileo
    1104: 1.0,  // MSM4 SBAS
    1114: 1.0,  // MSM4 QZSS
    1124: 1.0,  // MSM4 BeiDou
    1230: 1.0,  // GLONASS code biases
  };

  async function refreshRtcm() {
    try {
      const data = await apiGet('/api/v1/rtcm/frequencies');
      const filter = $('#rtcm-filter').value.toLowerCase().trim();
      const anomaliesOnly = $('#rtcm-anomalies-only').checked;

      const rows = [];
      for (const [mp, types] of Object.entries(data)) {
        if (filter && !mp.toLowerCase().includes(filter)) continue;
        for (const [type, info] of Object.entries(types)) {
          const typeNum = parseInt(type, 10);
          const expected = RTCM_EXPECTED[typeNum];
          let state = 'ok', stateText = 'OK';
          if (expected != null) {
            const ratio = info.rate_hz / expected;
            if (info.total === 0) { state = 'muted'; stateText = '—'; }
            else if (ratio < 0.5) { state = 'err'; stateText = `low (exp ${expected}Hz)`; }
            else if (ratio < 0.9) { state = 'warn'; stateText = `degraded (exp ${expected}Hz)`; }
          } else {
            state = 'muted'; stateText = 'unknown';
          }
          if (anomaliesOnly && state !== 'err' && state !== 'warn') continue;
          rows.push({ mp, type, info, state, stateText });
        }
      }
      rows.sort((a, b) => a.mp.localeCompare(b.mp) || a.type - b.type);

      $('#rtcm-hint').textContent = `${rows.length} row(s) · updated ${new Date().toLocaleTimeString()}`;
      const tbody = $('#rtcm-table tbody');
      tbody.innerHTML = rows.map(r => `
        <tr>
          <td class="mono">${escapeHtml(r.mp)}</td>
          <td class="mono">${r.type}</td>
          <td class="num">${r.info.rate_hz.toFixed(3)}</td>
          <td class="num">${fmtNum(r.info.total)}</td>
          <td>${fmtTime(r.info.first_seen)}</td>
          <td>${fmtTime(r.info.last_seen)}</td>
          <td><span class="badge badge-${r.state}">${escapeHtml(r.stateText)}</span></td>
        </tr>
      `).join('') || '<tr><td colspan="7" class="hint">No RTCM traffic recorded yet.</td></tr>';
    } catch (err) {
      console.error('refreshRtcm', err);
      $('#rtcm-hint').textContent = 'Error: ' + err.message;
    }
  }

  // ---- Map (Leaflet) ----
  function initMap() {
    if (map !== null) {
      // Already initialized — make sure it's sized correctly (Leaflet
      // sometimes misses the container size after being hidden).
      setTimeout(() => map.invalidateSize(), 100);
      return;
    }
    if (typeof L === 'undefined') {
      $('#map-hint').textContent = 'Leaflet library failed to load.';
      return;
    }
    map = L.map('leaflet-map', {
      center: [46.6, 2.4],   // Default: France centroid
      zoom: 5,
      preferCanvas: true,
    });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap contributors',
    }).addTo(map);
    mapMarkers = L.layerGroup().addTo(map);
    setTimeout(() => map.invalidateSize(), 100);
  }

  async function refreshMap() {
    if (!map) return;
    try {
      // Fetch sourcetable list and live sessions in parallel
      const [tables, sessions] = await Promise.all([
        apiGet('/api/v1/sourcetables'),
        apiGet('/api/v1/net').catch(() => ({})),
      ]);

      // Build set of currently-live mountpoints
      const liveSet = new Set();
      for (const s of Object.values(sessions)) {
        if ((s.type === 'source' || s.type === 'source_fetcher') && s.mountpoint) {
          liveSet.add(s.mountpoint);
        }
      }
      mapLiveSet = liveSet;

      // Clear existing markers
      mapMarkers.clearLayers();

      let count = 0;
      const bounds = [];
      for (const st of tables) {
        const mps = st.mountpoints || {};
        for (const [mp, info] of Object.entries(mps)) {
          // Skip entries with no usable coordinates
          if (info.lat == null || info.lon == null) continue;
          if (!isFinite(info.lat) || !isFinite(info.lon)) continue;
          // Skip the (0,0) placeholder that some bases send when no fix
          if (info.lat === 0 && info.lon === 0) continue;

          const live = liveSet.has(mp);
          const marker = L.circleMarker([info.lat, info.lon], {
            radius: live ? 8 : 5,
            color: live ? '#0a7' : '#888',
            fillColor: live ? '#0d8' : '#aaa',
            fillOpacity: 0.85,
            weight: 2,
          });
          const popupHtml = `
            <div class="map-popup">
              <div class="mp-name">${escapeHtml(mp)}</div>
              <div class="mp-meta">
                <span class="badge badge-${live ? 'ok' : 'muted'}">${live ? 'LIVE' : 'offline'}</span>
                <span class="mp-coords">${info.lat.toFixed(5)}, ${info.lon.toFixed(5)}</span>
              </div>
              <div class="mp-host">via ${escapeHtml(st.host)}:${st.port}</div>
              ${info.virtual ? '<div class="mp-virtual">virtual</div>' : ''}
              <pre class="mp-str">${escapeHtml(info.str || '')}</pre>
            </div>`;
          marker.bindPopup(popupHtml);
          marker.addTo(mapMarkers);
          bounds.push([info.lat, info.lon]);
          count++;
        }
      }

      // Auto-fit bounds if requested
      if ($('#map-autofit').checked && bounds.length > 0) {
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 12 });
      }

      const liveCount = [...liveSet].filter(mp => true).length;
      $('#map-hint').textContent = `${count} mountpoint(s) on map · ${liveCount} live · updated ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      console.error('refreshMap', err);
      $('#map-hint').textContent = 'Error: ' + err.message;
    }
  }

  // ---- Logs (SSE) ----
  function startLogStream() {
    if (logStream) logStream.close();
    $('#logs-status').textContent = 'connecting…';
    $('#logs-status').className = 'status';

    // EventSource cannot set custom headers, so we have to pass auth
    // in the URL query string. Prefer ?token= if the server has an
    // admin_token configured (more secure: the token doesn't appear
    // in browser password managers / form history the way Basic
    // credentials do). Fall back to user/password if not.
    //
    // We try the token first by issuing a HEAD /api/v1/mem with
    // Bearer auth; if the server responds 401 with a Bearer realm
    // advertised, we know token auth is configured but our user-
    // supplied token is wrong (or there isn't one). If 200, we use
    // the same token for SSE.
    //
    // For simplicity, we always include both forms in the SSE URL:
    //   ?token=<pass>&user=<user>&password=<pass>
    // The server tries them in order: Bearer first, then Basic.
    const params = new URLSearchParams();
    params.set('user', auth.user);
    params.set('password', auth.pass);
    // Also include the password as a token — if the server has
    // admin_token == password (common in dev), this Just Works.
    // In production the user would log in with the token directly.
    params.set('token', auth.pass);
    const url = `/adm/api/v1/logs/stream?${params.toString()}`;
    logStream = new EventSource(url);

    logStream.addEventListener('hello', (e) => {
      $('#logs-status').textContent = 'live';
      $('#logs-status').className = 'status live';
    });
    logStream.addEventListener('log', (e) => {
      try {
        const entry = JSON.parse(e.data);
        logBuffer.push(entry);
        if (logBuffer.length > LOG_BUFFER_MAX) logBuffer.shift();
        renderLogs();
      } catch (err) { console.error('bad SSE data', err); }
    });
    logStream.addEventListener('error', (e) => {
      $('#logs-status').textContent = 'disconnected';
      $('#logs-status').className = 'status error';
    });
  }

  function clearLogs() {
    logBuffer = [];
    renderLogs();
  }

  function renderLogs() {
    const filter = $('#logs-filter').value.toLowerCase();
    const out = $('#logs-output');
    const lines = logBuffer
      .filter(e => !filter ||
        (e.message || '').toLowerCase().includes(filter) ||
        (e.level || '').toLowerCase().includes(filter))
      .map(e => `<span class="log-line"><span class="ts">${e.ts ? e.ts.replace('T',' ').replace('Z','') : ''}</span> <span class="level ${e.level || ''}">${escapeHtml(e.level || '')}</span> <span class="msg">${escapeHtml(e.message || '')}</span></span>`)
      .join('\n');
    out.innerHTML = lines || '<span class="hint">No log entries match the filter.</span>';

    // Auto-scroll
    if ($('#logs-autoscroll').checked && !$('#logs-pause').checked) {
      out.scrollTop = out.scrollHeight;
    }
    $('#logs-hint').textContent = logBuffer.length + ' lines buffered';
  }

  return { init, logout };
})();

document.addEventListener('DOMContentLoaded', App.init);
