/* main.js — Render-ready, robust SIEM Dashboard */
let typeChart, timeChart;
const REFRESH_MS = 8000;
const MAX_LOG_RETRIES = 3;
const LOG_RETRY_DELAY = 1500;

function ensureBanner() {
  let b = document.getElementById('__siem_status_banner');
  if (!b) {
    b = document.createElement('div');
    b.id = '__siem_status_banner';
    b.style = 'position:fixed;right:12px;top:12px;z-index:9999;padding:8px 12px;border-radius:6px;background:#222;color:#fff;font-family:system-ui;opacity:0.9';
    document.body.appendChild(b);
  }
  return b;
}
function bannerSet(text, bg = '#222') {
  const b = ensureBanner();
  b.textContent = text;
  b.style.background = bg;
}

// Diagnostic fetch
async function diagFetch(url, opts = {}) {
  console.debug('[diagFetch] url=', url, 'opts=', opts);
  try {
    const res = await fetch(url, { cache: 'no-store', ...opts });
    const ct = res.headers.get('content-type') || '';
    let body = null;
    if (ct.includes('application/json')) body = await res.clone().json().catch(()=>null);
    else body = await res.clone().text().catch(()=>null);
    console.debug('[diagFetch] response:', { url, status: res.status, ok: res.ok, bodyPreview: Array.isArray(body)?body.slice(0,3):body });
    return { ok: res.ok, status: res.status, body, res };
  } catch (err) {
    console.warn('[diagFetch] network error:', url, err);
    return { ok:false, status:0, body:null, error:err };
  }
}

// Safe fetch JSON
async function safeFetchJson(path) {
  const out = await diagFetch(path);
  if (!out.ok) throw new Error(`Fetch ${path} failed (status ${out.status})`);
  return out.body;
}

// Optional health check
async function fetchHealth() {
  try {
    const h = await safeFetchJson('/health');
    console.info('[health]', h);
    bannerSet('Server: ' + (h.version || 'unknown'), '#2b7a78');
    return h;
  } catch(e) {
    console.warn('health check failed', e);
    bannerSet('Server status unknown', '#a03');
    return null;
  }
}

// API helpers
async function fetchMeta() {
  try { return await safeFetchJson('/api/meta'); }
  catch(e){ console.warn('fetchMeta failed', e); return {sources:[], event_types:[]}; }
}
async function fetchAlerts() {
  try { return await safeFetchJson('/api/alerts') || []; }
  catch(e){ console.warn('fetchAlerts failed', e); return []; }
}
async function fetchLogsWithRetry(params={}, retries=0) {
  const qs = new URLSearchParams(params).toString();
  const url = '/api/logs' + (qs ? '?' + qs : '');
  const out = await diagFetch(url);
  if (out.ok) return out.body || [];
  if (retries < MAX_LOG_RETRIES) {
    await new Promise(r => setTimeout(r, LOG_RETRY_DELAY));
    return fetchLogsWithRetry(params, retries+1);
  }
  bannerSet('Logs fetch failed', '#a03');
  console.error('fetchLogs final failure:', out);
  return [];
}

// UI updates
function updateSummary(logs, alerts) {
  document.getElementById('totalEvents').innerHTML = `${logs.length}<br><small>Total Events</small>`;
  document.getElementById('criticalAlerts').innerHTML = `${alerts.length}<br><small>Current Alerts</small>`;
  const unique = new Set(logs.map(l=>l.source));
  document.getElementById('uniqueSources').innerHTML = `${unique.size}<br><small>Unique Sources</small>`;
}

function buildTable(logs) {
  const tbody = document.querySelector('#logTable tbody');
  if(!tbody) return;
  tbody.innerHTML = logs.map(l=>`
    <tr>
      <td>${l.timestamp||''}</td>
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
  if(!box) return;
  box.innerHTML = alerts.map(a=>`
    <div class="alert-card ${(a.severity||'').toLowerCase()}">
      <strong>${a.severity||''}</strong> — ${a.rule||''}
      <div class="msg">${a.message||''}</div>
      <small>${a.created_at||''}</small>
    </div>
  `).join('');
}

function buildCharts(logs) {
  if(!logs||logs.length===0){
    if(typeChart){ try{ typeChart.destroy(); }catch(e){}; typeChart=null; }
    if(timeChart){ try{ timeChart.destroy(); }catch(e){}; timeChart=null; }
    return;
  }

  const counts={};
  logs.forEach(l=>{ const k=l.event_type||'Unknown'; counts[k]=(counts[k]||0)+1; });
  const labels = Object.keys(counts);
  const data = Object.values(counts);
  const ctx = document.getElementById('typeChart')?.getContext('2d');
  if(ctx){ if(typeChart) try{typeChart.destroy();}catch(e){} typeChart=new Chart(ctx,{type:'pie',data:{labels,datasets:[{data}]}}); }

  const times={};
  logs.forEach(l=>{ try{ const t=new Date(l.timestamp).toISOString().slice(0,16); times[t]=(times[t]||0)+1; }catch(e){} });
  const tlabels = Object.keys(times).sort();
  const tdata = tlabels.map(k=>times[k]);
  const ctx2 = document.getElementById('timeChart')?.getContext('2d');
  if(ctx2){ if(timeChart) try{timeChart.destroy();}catch(e){} timeChart=new Chart(ctx2,{type:'line',data:{labels:tlabels,datasets:[{label:'Events',data:tdata,tension:0.3}]}}); }
}

function plotMap(logs){
  if(!window._map){
    try{
      window._map=L.map('mapid').setView([20,0],2);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
        attribution:'&copy; OpenStreetMap contributors'
      }).addTo(window._map);
      window._markers=[];
    }catch(e){console.warn('Leaflet init failed', e); return;}
  }
  (window._markers||[]).forEach(m=>window._map.removeLayer(m));
  window._markers=[];
  logs.forEach(l=>{
    if(l.lat && l.lon){
      try{
        const m = L.circleMarker([l.lat,l.lon],{radius:6}).addTo(window._map)
          .bindPopup(`<strong>${l.src_ip||'IP'}</strong><br>${l.source||''}<br>${l.event_type||''}`);
        window._markers.push(m);
      }catch(e){console.warn('marker failed', e);}
    }
  });
}

// Main refresh
async function refresh(){
  bannerSet('Fetching...', '#226');
  const params={};
  const q = document.getElementById('search')?.value; if(q) params.q=q;
  const source=document.getElementById('filterSource')?.value; if(source) params.source=source;
  const evtype=document.getElementById('filterType')?.value; if(evtype) params.event_type=evtype;
  const severity=document.getElementById('filterSeverity')?.value; if(severity) params.severity=severity;

  try{
    const [logs,alerts] = await Promise.all([fetchLogsWithRetry(params), fetchAlerts()]);
    console.info('refresh got',{logsCount:logs.length,alertsCount:alerts.length});
    if(logs.length===0) bannerSet('No logs (empty database)', '#b87300');
    else bannerSet(`${logs.length} logs • ${alerts.length} alerts`, '#2b7a78');

    updateSummary(logs,alerts);
    buildTable(logs);
    buildAlerts(alerts);
    buildCharts(logs);
    plotMap(logs);
  }catch(e){
    console.error('refresh failed', e);
    bannerSet('Refresh failed','#a03');
  }
}

// Filters population
async function populateFilters(){
  try{
    const meta = await fetchMeta();
    const s=document.getElementById('filterSource');
    const t=document.getElementById('filterType');
    if(s){ s.innerHTML="<option value=''>All sources</option>"; (meta.sources||[]).forEach(src=>s.insertAdjacentHTML('beforeend',`<option>${src}</option>`)); }
    if(t){ t.innerHTML="<option value=''>All types</option>"; (meta.event_types||[]).forEach(tt=>t.insertAdjacentHTML('beforeend',`<option>${tt}</option>`)); }
  }catch(e){ console.warn('populateFilters failed',e);}
}

// Events
document.getElementById('applyFilters')?.addEventListener('click', e=>{ e.preventDefault(); refresh(); });
document.getElementById('search')?.addEventListener('keyup', e=>{ if(e.key==='Enter') refresh(); });

document.getElementById('uploadForm')?.addEventListener('submit', async function(e){
  e.preventDefault();
  const f=document.getElementById('fileInput')?.files[0];
  if(!f){ alert('Choose a file'); return; }
  const fd=new FormData();
  fd.append('file', f);
  try{
    const r = await fetch('/api/upload',{method:'POST',body:fd});
    if(r.ok){ alert('Uploaded'); }
    else { const txt = await r.text().catch(()=>null); alert('Upload failed: '+r.status+' '+txt); }
  }catch(err){ alert('Upload error: '+err.message); }
  refresh();
});

// Startup
(async function init(){
  console.log('SIEM main.js starting — checking server health...');
  await fetchHealth();
  await populateFilters();
  await refresh();
  setInterval(async ()=>{
    try{ await refresh(); }catch(e){ console.warn('background refresh failed',e);}
    if(Math.random()<0.12) try{ await populateFilters(); }catch(){}
  }, REFRESH_MS);
})();
