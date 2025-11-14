let typeChart, timeChart;
const REFRESH_MS = 8000; // 8 seconds

// ---------- API HELPERS ----------
async function safeFetch(url) {
  try {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error("Bad response " + r.status);
    return r.json();
  } catch (e) {
    console.warn("Fetch failed:", url, e);
    return [];
  }
}

async function fetchMeta() {
  return safeFetch("/api/meta");
}

async function fetchLogs(params = {}) {
  const qs = new URLSearchParams(params).toString();
  return safeFetch("/api/logs?" + qs);
}

async function fetchAlerts() {
  return safeFetch("/api/alerts");
}

// ---------- UI UPDATE FUNCTIONS ----------
function updateSummary(logs, alerts) {
  document.getElementById("totalEvents").innerHTML =
    `${logs.length}<br><small>Total Events</small>`;
  document.getElementById("criticalAlerts").innerHTML =
    `${alerts.length}<br><small>Current Alerts</small>`;
  const unique = new Set(logs.map(l => l.source));
  document.getElementById("uniqueSources").innerHTML =
    `${unique.size}<br><small>Unique Sources</small>`;
}

function buildTable(logs) {
  const tbody = document.querySelector("#logTable tbody");
  tbody.innerHTML = logs
    .map(
      l => `
    <tr>
      <td>${l.timestamp || ""}</td>
      <td>${l.source || ""}</td>
      <td>${l.event_type || ""}</td>
      <td>${l.severity || ""}</td>
      <td>${l.message || ""}</td>
      <td>${l.src_ip || ""}</td>
    </tr>
  `
    )
    .join("");
}

function buildAlerts(alerts) {
  const box = document.getElementById("alertCards");
  box.innerHTML = alerts
    .map(
      a => `
    <div class="alert-card ${a.severity?.toLowerCase() || ""}">
      <strong>${a.severity}</strong> — ${a.rule}
      <div class="msg">${a.message}</div>
      <small>${a.created_at}</small>
    </div>
  `
    )
    .join("");
}

function buildCharts(logs) {
  // Prevent crashing if empty
  if (!logs || logs.length === 0) {
    if (typeChart) typeChart.destroy();
    if (timeChart) timeChart.destroy();
    return;
  }

  // ----- TYPE DISTRIBUTION -----
  const counts = {};
  logs.forEach(l => {
    const k = l.event_type || "Unknown";
    counts[k] = (counts[k] || 0) + 1;
  });

  const labels = Object.keys(counts);
  const data = Object.values(counts);

  const ctx = document.getElementById("typeChart").getContext("2d");
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels,
      datasets: [{ data }]
    }
  });

  // ----- EVENTS OVER TIME -----
  const times = {};
  logs.forEach(l => {
    const t = new Date(l.timestamp).toISOString().slice(0, 16);
    times[t] = (times[t] || 0) + 1;
  });

  const tlabels = Object.keys(times).sort();
  const tdata = tlabels.map(k => times[k]);

  const ctx2 = document.getElementById("timeChart").getContext("2d");
  if (timeChart) timeChart.destroy();
  timeChart = new Chart(ctx2, {
    type: "line",
    data: {
      labels: tlabels,
      datasets: [
        {
          label: "Events",
          data: tdata,
          tension: 0.3
        }
      ]
    }
  });
}

// ---------- MAP ----------
function plotMap(logs) {
  if (!window._map) {
    window._map = L.map("mapid").setView([20, 0], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap contributors"
    }).addTo(window._map);
    window._markers = [];
  }

  // Clear old markers
  window._markers.forEach(m => window._map.removeLayer(m));
  window._markers = [];

  logs.forEach(l => {
    if (l.lat && l.lon) {
      const m = L.circleMarker([l.lat, l.lon], { radius: 6 })
        .addTo(window._map)
        .bindPopup(
          `<strong>${l.src_ip || "IP"}</strong><br>${l.source || ""}<br>${l.event_type || ""}`
        );
      window._markers.push(m);
    }
  });
}

// ---------- DATA REFRESH ----------
async function refresh() {
  const params = {};

  const q = document.getElementById("search").value;
  if (q) params.q = q;

  const source = document.getElementById("filterSource").value;
  if (source) params.source = source;

  const evtype = document.getElementById("filterType").value;
  if (evtype) params.event_type = evtype;

  const severity = document.getElementById("filterSeverity").value;
  if (severity) params.severity = severity;

  const [logs, alerts] = await Promise.all([fetchLogs(params), fetchAlerts()]);

  updateSummary(logs, alerts);
  buildTable(logs);
  buildAlerts(alerts);
  buildCharts(logs);
  plotMap(logs);
}

// ---------- FILTER POPULATION ----------
async function populateFilters() {
  const meta = await fetchMeta();

  const s = document.getElementById("filterSource");
  const t = document.getElementById("filterType");

  // prevent duplicates when auto-refresh happens
  s.innerHTML = "<option value=''>All</option>";
  t.innerHTML = "<option value=''>All</option>";

  meta.sources.forEach(src =>
    s.insertAdjacentHTML("beforeend", `<option>${src}</option>`)
  );
  meta.event_types.forEach(tt =>
    t.insertAdjacentHTML("beforeend", `<option>${tt}</option>`)
  );
}

// ---------- EVENT LISTENERS ----------
document.getElementById("applyFilters").addEventListener("click", e => {
  e.preventDefault();
  refresh();
});

document.getElementById("search").addEventListener("keyup", e => {
  if (e.key === "Enter") refresh();
});

// upload form
document.getElementById("uploadForm").addEventListener("submit", async function (e) {
  e.preventDefault();
  const f = document.getElementById("fileInput").files[0];
  if (!f) return alert("Choose a file");

  const fd = new FormData();
  fd.append("file", f);

  const res = await fetch("/api/upload", { method: "POST", body: fd });
  if (res.ok) alert("Uploaded");
  else alert("Upload failed");

  refresh();
});

// ---------- INITIAL LOAD ----------
(async function () {
  await populateFilters();
  await refresh();
  setInterval(refresh, REFRESH_MS);
})();
