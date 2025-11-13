async function loadLogs() {
  const res = await fetch('/api/logs');
  const logs = await res.json();

  // Update table
  const tableBody = document.querySelector('#logTable tbody');
  tableBody.innerHTML = logs.map(log => `
    <tr>
      <td>${log.timestamp}</td>
      <td>${log.source}</td>
      <td>${log.event_type}</td>
      <td>${log.severity}</td>
    </tr>
  `).join('');

  // Summary
  document.getElementById('totalEvents').innerHTML = `${logs.length}<br><small>Total Events</small>`;
  document.getElementById('criticalAlerts').innerHTML = `${logs.filter(l => l.severity === 'Critical').length}<br><small>Critical Alerts</small>`;
  const uniqueSources = new Set(logs.map(l => l.source));
  document.getElementById('uniqueSources').innerHTML = `${uniqueSources.size}<br><small>Unique Sources</small>`;

  // Chart
  const ctx = document.getElementById('eventChart');
  const typeCount = {};
  logs.forEach(l => typeCount[l.event_type] = (typeCount[l.event_type] || 0) + 1);

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: Object.keys(typeCount),
      datasets: [{
        label: 'Event Types',
        data: Object.values(typeCount)
      }]
    }
  });
}

loadLogs();
