let typeChart, timeChart;
const REFRESH_MS = 8000; // 8 seconds

async function fetchMeta() {
  const res = await fetch('/api/meta');
  return res.json();
}

async function fetchLogs(params = {}) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch('/api/logs?' + qs);
  return res.json();
}

async function fetchAlerts() {
  const r = await fetch('/api/alerts');
  return r.json();
}

function updateSummary(logs, alerts) {
  document.getElementById('totalEvents').innerHTML = `${logs.length}<br><small>Total Events</small>`;
  document.getElementById('criticalAlerts').innerHTML = `${alerts.length}<br><small>Current Alerts</small>`;
  const unique = new Set(logs.map(l => l.source));
  document.getElementById('uniqueSources').innerHTML = `${unique.size}<br><small>Unique Sources</small>`;
}

function buildTable(logs) {
  const tbody = document.querySelector('#logTable tbody');
  tbody.innerHTML = logs.map(l => `
    <tr>
      <td>${l.timestamp}</td>
      <td>${l.source||''}</td>
      <td>${l.event_type||''}</td>
      <td>${l.severity||''}</td>
      <td>${l.message||''}</td>
      <td>${l.src_ip||''}</td>
    </tr>
  `).join('');
}

function buildAlerts(alerts) {
  const box = document.getElementById('alertCards');
  box.innerHTML = alerts.map(a => `
    <div class="alert-card ${a.severity.toLowerCase()}">
      <strong>${a.severity}</strong> — ${a.rule} <div class="msg">${a.message}</div>
      <small>${a.created_at}</small>
    </div>
  `).join('');
}

function buildCharts(logs) {
  // type distribution
  const counts = {};
  logs.forEach(l => { counts[l.event_type] = (counts[l.event_type]||0) + 1 });
  const labels = Object.keys(counts);
  const data = Object.values(counts);
  const ctx = document.getElementById('typeChart').getContext('2d');
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(ctx, {
    type: 'pie',
    data: { labels, datasets: [{ data }] },
  });

  // events over time (by minute)
  const times = {};
  logs.forEach(l => {
    const t = new Date(l.timestamp).toISOString().slice(0,16);
    times[t] = (times[t]||0) + 1;
  });
  const tlabels = Object.keys(times).sort();
  const tdata = tlabels.map(k => times[k]);
  const ctx2 = document.getElementById('timeChart').getContext('2d');
  if (timeChart) timeChart.destroy();
  timeChart = new Chart(ctx2, {
    type: 'line',
    data: { labels: tlabels, datasets: [{ label: 'Events', data: tdata, tension:0.3 }] },
  });
}

function plotMap(logs) {
  // map init if not exists
  if (!window._map) {
    window._map = L.map('mapid').setView([20,0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; OpenStreetMap contributors'
    }).addTo(window._map);
    window._markers = [];
  }
  // clear markers
  window._markers.forEach(m => window._map.removeLayer(m));
  window._markers = [];
  logs.forEach(l => {
    if (l.lat && l.lon) {
      const m = L.circleMarker([l.lat, l.lon], { radius:6 }).addTo(window._map)
        .bindPopup(`<strong>${l.src_ip||'IP'}</strong><br>${l.source||''}<br>${l.event_type||''}`);
      window._markers.push(m);
    }
  });
}

async function refresh() {
  const params = {};
  const q = document.getElementById('search').value;
  if (q) params.q = q;
  const source = document.getElementById('filterSource').value;
  if (source) params.source = source;
  const evtype = document.getElementById('filterType').value;
  if (evtype) params.event_type = evtype;
  const severity = document.getElementById('filterSeverity').value;
  if (severity) params.severity = severity;

  const [logs, alerts] = await Promise.all([fetchLogs(params), fetchAlerts()]);
  updateSummary(logs, alerts);
  buildTable(logs);
  buildAlerts(alerts);
  buildCharts(logs);
  plotMap(logs);
}

async function populateFilters() {
  const meta = await fetchMeta();
  const s = document.getElementById('filterSource');
  meta.sources.forEach(src => s.insertAdjacentHTML('beforeend', `<option>${src}</option>`));
  const t = document.getElementById('filterType');
  meta.event_types.forEach(tt => t.insertAdjacentHTML('beforeend', `<option>${tt}</option>`));
}

document.getElementById('applyFilters').addEventListener('click', e => { e.preventDefault(); refresh(); });
document.getElementById('search').addEventListener('keyup', e => { if (e.key === 'Enter') refresh(); });

// upload form
document.getElementById('uploadForm').addEventListener('submit', async function(e){
  e.preventDefault();
  const f = document.getElementById('fileInput').files[0];
  if (!f) { alert('Choose a file'); return; }
  const fd = new FormData();
  fd.append('file', f);
  const res = await fetch('/api/upload', { method:'POST', body: fd });
  if (res.ok) { alert('Uploaded'); refresh(); } else { alert('Upload failed'); }
});

// initial load
(async function(){
  await populateFilters();
  await refresh();
  setInterval(refresh, REFRESH_MS);

  // optional: allow drag-drop or simulate ingestion by POSTing to /api/ingest
})();


