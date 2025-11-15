# SIEM Dashboard

A modern, dark-themed **Security Information and Event Management (SIEM) Dashboard** built with **Flask, SQLite, Chart.js, and Leaflet.js**.  
This dashboard allows you to visualize logs, alerts, geo-IP data, and system metrics in real-time, with simulated traffic for demonstration purposes.

---

## 🌐 Live Demo

Check out the fully deployed dashboard here:  
[![Live Dashboard](https://img.shields.io/badge/Live-Dashboard-blue)](https://siem-dashboard-3q1v.onrender.com/)

---

## 🚀 Features

### Core Features
- **Real-time Log Visualization:** View incoming logs and filter by source, event type, severity, or search terms.
- **Alerts Engine:** Automatic generation of alerts for critical events, port scans, and brute-force attempts.
- **Interactive Charts:** 
  - Pie chart of event types.
  - Line chart of event activity over time.
- **GeoIP Mapping:** Visualize the origin of events on a world map using **Leaflet.js**.
- **Dashboard Cards:** Quick stats for total events, unique sources, and current alerts.

### Additional Enhancements
- **User Authentication:** Login required to access the dashboard.
- **Dark Modern Theme:** Sleek UI for easy readability.
- **File Uploads:** Upload JSON or CSV log files to populate the dashboard.
- **Filter & Search:** Filter logs dynamically or search for specific IPs, sources, or events.
- **Simulated Traffic:** Auto-seeding demo logs for testing and demonstration.
- **Responsive Layout:** Works across desktops and tablets.

### Marketable Upgrades Implemented
1. **User login authentication**  
2. **Auto-seed demo traffic for simulation**  
3. **Alerts cards with severity coloring**  
4. **Interactive GeoIP world map**  
5. **Real-time charts for event trends**  
6. **Live dashboard status banner**  
7. **Customizable filters and search**  
8. **Responsive dark-modern UI**  
9. **Upload logs via JSON or CSV files**

---

## 🛠️ Tech Stack

- **Backend:** Python, Flask  
- **Database:** SQLite  
- **Frontend:** HTML, CSS (dark theme), JavaScript  
- **Charts & Visualizations:** Chart.js, Leaflet.js  
- **Deployment:** Render

---

### ▶️ Run Locally
```bash
git clone https://github.com/<yourusername>/siem-dashboard-demo.git
cd siem-dashboard-demo
pip install flask
python app.py
```
