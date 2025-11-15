from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, g
import json, os, sqlite3, csv, io, datetime, threading, random, time
from werkzeug.utils import secure_filename

# ===============================================================
# CONFIG — Render-aware database + uploads folder
# ===============================================================

IS_RENDER = os.environ.get("RENDER")

if IS_RENDER:
    DATABASE = "/tmp/siem.db"
    UPLOAD_FOLDER = "/tmp/uploads"
else:
    DATABASE = "siem.db"
    UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {"json", "csv"}
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ===============================================================
# DB HELPERS (Flask request-context) + thread-safe connector fn
# ===============================================================

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def thread_db_conn():
    # background threads must create their own connection
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ===============================================================
# INIT DB (create/alter tables as needed)
# ===============================================================

def init_db():
    conn = thread_db_conn()
    cur = conn.cursor()

    # base logs table (ensure country column exists)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            src_ip TEXT,
            lat REAL,
            lon REAL,
            country TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            created_at TEXT,
            rule TEXT,
            severity TEXT,
            message TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            pw TEXT
        )
    """)

    # packets table for live packet feed
    cur.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            proto TEXT,
            dst_port INTEGER,
            length INTEGER
        )
    """)

    # threat intel table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            tag TEXT
        )
    """)

    # default user
    cur.execute("SELECT COUNT(*) AS c FROM users")
    row = cur.fetchone()
    if not row or row["c"] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)", ("analyst", "password"))

    conn.commit()
    conn.close()

# initialize DB at import time (idempotent)
init_db()

# ===============================================================
# Utilities: helper accessors
# ===============================================================

def _value(row, key):
    try:
        return row[key]
    except Exception:
        try:
            return row.get(key)
        except Exception:
            return None

def now_ts():
    return datetime.datetime.utcnow().isoformat() + "Z"

# ===============================================================
# RULES ENGINE (detection)
# ===============================================================

def run_detection_on_log(conn, log_id):
    """
    Accepts a connection and log_id. Runs a few heuristic detection rules:
      - Critical severity propagation
      - Brute-force: 5+ failed-login-like events from same src_ip within 2 minutes
      - Port-scan: many distinct dst_ports observed in packets for same src_ip in short window
    Inserts alerts into alerts table.
    """
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
    row = cur.fetchone()
    if not row:
        return

    severity = (row["severity"] or "").lower()
    evtype = (row["event_type"] or "").lower()
    src_ip = row["src_ip"]

    # Immediate critical
    if severity == "critical":
        cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                    (log_id, now_ts(), "critical_sev", "Critical", f"Critical event: {evtype} from {src_ip}"))

    # Brute force heuristic: count logs same src_ip with 'failed' or 'login' in event_type in last 2 minutes
    if src_ip:
        window = (datetime.datetime.utcnow() - datetime.timedelta(minutes=2)).isoformat() + "Z"
        cur.execute("SELECT COUNT(*) AS c FROM logs WHERE src_ip = ? AND timestamp >= ? AND (event_type LIKE '%fail%' OR event_type LIKE '%login%')",
                    (src_ip, window))
        cnt_row = cur.fetchone()
        cnt = cnt_row["c"] if cnt_row else 0
        if cnt >= 5:
            cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                        (log_id, now_ts(), "brute_force", "Medium", f"{cnt} failed/login events from {src_ip} in 2 minutes"))

    # Port scan heuristic: in packets table count distinct dst_port from src_ip in last 60s
    if src_ip:
        window_pkt = (datetime.datetime.utcnow() - datetime.timedelta(seconds=60)).isoformat() + "Z"
        cur.execute("SELECT COUNT(DISTINCT dst_port) AS pcount FROM packets WHERE src_ip = ? AND timestamp >= ?", (src_ip, window_pkt))
        p_row = cur.fetchone()
        pcount = p_row["pcount"] if p_row else 0
        if pcount >= 10:
            cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                        (log_id, now_ts(), "port_scan", "High", f"Port scan: {pcount} distinct dst ports from {src_ip} in 60s"))

    conn.commit()

# ===============================================================
# BACKGROUND GENERATOR (Method A) — produces logs + packets and runs detection
# ===============================================================

GENERATOR_RUNNING = False
GENERATOR_LOCK = threading.Lock()

SAMPLE_SOURCES = ["Firewall", "Web Server", "IDS", "Auth", "Proxy", "VPN", "Mail"]
SAMPLE_EVENTS = ["Port Scan", "Failed Login", "Malware Detected", "Anomaly", "Suspicious Connection", "Login Success"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

# sample geo points (lat, lon, country)
SAMPLE_LOCS = [
    (37.7749, -122.4194, "US"),
    (40.7128, -74.0060, "US"),
    (51.5074, -0.1278, "GB"),
    (48.8566, 2.3522, "FR"),
    (35.6895, 139.6917, "JP"),
    (28.6139, 77.2090, "IN"),
    (-33.8688, 151.2093, "AU"),
    (52.5200, 13.4050, "DE"),
]

MALICIOUS_IPS_SAMPLE = [
    "203.0.113.4",
    "198.51.100.10",
    "192.0.2.45"
]

def seed_threat_intel_if_empty():
    conn = thread_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM threat_intel")
    r = cur.fetchone()
    if not r or r["c"] == 0:
        for ip in MALICIOUS_IPS_SAMPLE:
            cur.execute("INSERT OR IGNORE INTO threat_intel (ip, tag) VALUES (?, ?)", (ip, "demo-malicious"))
    conn.commit()
    conn.close()

def bg_generator_loop():
    """
    Background loop that inserts random packets & logs and runs detection.
    """
    conn = thread_db_conn()
    cur = conn.cursor()
    seed_threat_intel_if_empty()

    while True:
        try:
            # create a packet burst (simulate network traffic)
            src_ip = f"198.51.{random.randint(0,255)}.{random.randint(1,254)}"
            dst_ip = f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
            proto = random.choice(["TCP", "UDP", "ICMP"])
            dst_port = random.choice([22, 80, 443, 8080, 3306, random.randint(1024, 65000)])
            length = random.randint(40, 1500)
            ts = now_ts()

            cur.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, proto, dst_port, length) VALUES (?, ?, ?, ?, ?, ?)",
                        (ts, src_ip, dst_ip, proto, dst_port, length))
            conn.commit()

            # occasionally create a "log" related to traffic
            if random.random() < 0.5:
                loc = random.choice(SAMPLE_LOCS)
                event_type = random.choice(SAMPLE_EVENTS)
                severity = random.choices(SEVERITIES, weights=[0.6,0.25,0.1,0.05])[0]
                source = random.choice(SAMPLE_SOURCES)
                message = f"{event_type} observed (demo)"
                ts_log = now_ts()
                cur.execute("""INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon, country)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (ts_log, source, event_type, severity, message, src_ip, loc[0], loc[1], loc[2]))
                conn.commit()
                log_id = cur.lastrowid

                # run detection on this newly created log
                run_detection_on_log(conn, log_id)

            # occasionally inject a truly malicious IP from sample to trigger alerts
            if random.random() < 0.08:
                bad = random.choice(MALICIOUS_IPS_SAMPLE)
                loc = random.choice(SAMPLE_LOCS)
                cur.execute("""INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon, country)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (now_ts(), "ThreatFeed", "KnownBadIPTraffic", "High", "Traffic from known malicious IP", bad, loc[0], loc[1], loc[2]))
                conn.commit()
                lid = cur.lastrowid
                run_detection_on_log(conn, lid)

            # port-scan burst simulation: many packets to different ports from same IP
            if random.random() < 0.06:
                port_scanner = f"203.0.{random.randint(0,255)}.{random.randint(1,254)}"
                for p in range(15):  # 15 packets to different ports quickly
                    cur.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, proto, dst_port, length) VALUES (?, ?, ?, ?, ?, ?)",
                                (now_ts(), port_scanner, dst_ip, "TCP", 1000 + p, random.randint(40, 200)))
                conn.commit()

            # short randomized sleep to simulate arrival rate
            time.sleep(random.uniform(0.6, 2.5))
        except Exception as e:
            # log error to stdout but keep generator alive
            print("Generator error:", e)
            time.sleep(1)

def ensure_generator_running():
    global GENERATOR_RUNNING
    with GENERATOR_LOCK:
        if not GENERATOR_RUNNING:
            t = threading.Thread(target=bg_generator_loop, daemon=True)
            t.start()
            GENERATOR_RUNNING = True

# ===============================================================
# ROUTES / API
# ===============================================================

@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")

        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username = ? AND pw = ?", (user, pw))
        row = cur.fetchone()

        if row:
            session["user"] = user
            # start generator when user logs in (safe to start here once)
            ensure_generator_running()
            return redirect(url_for("index"))

        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "version": os.environ.get("RENDER_GIT_COMMIT", "local"),
        "db_path": DATABASE
    })

# --- Logs endpoint (unchanged semantics)
@app.route("/api/logs")
def api_logs():
    limit = int(request.args.get("limit", 200))
    filter_q = []
    params = []

    severity = request.args.get("severity")
    source = request.args.get("source")
    event_type = request.args.get("event_type")
    q = request.args.get("q")

    if severity:
        filter_q.append("severity = ?")
        params.append(severity)
    if source:
        filter_q.append("source = ?")
        params.append(source)
    if event_type:
        filter_q.append("event_type = ?")
        params.append(event_type)
    if q:
        filter_q.append("(message LIKE ? OR src_ip LIKE ? OR event_type LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    where = "WHERE " + " AND ".join(filter_q) if filter_q else ""

    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM logs {where} ORDER BY id DESC LIMIT ?", (*params, limit))

    return jsonify([dict(r) for r in cur.fetchall()])

# --- Alerts endpoint
@app.route("/api/alerts")
def api_alerts():
    cur = get_db().cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    return jsonify([dict(r) for r in cur.fetchall()])

# --- Packets endpoint (for live packet feed)
@app.route("/api/packets")
def api_packets():
    limit = int(request.args.get("limit", 100))
    cur = get_db().cursor()
    cur.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
    return jsonify([dict(r) for r in cur.fetchall()])

# --- Threat intel endpoints
@app.route("/api/threats")
def api_threats():
    cur = get_db().cursor()
    cur.execute("SELECT ip, tag FROM threat_intel ORDER BY id DESC LIMIT 200")
    return jsonify([dict(r) for r in cur.fetchall()])

@app.route("/api/threat-check")
def api_threat_check():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "missing ip"}), 400
    cur = get_db().cursor()
    cur.execute("SELECT tag FROM threat_intel WHERE ip = ?", (ip,))
    r = cur.fetchone()
    return jsonify({"ip": ip, "malicious": bool(r), "tag": r["tag"] if r else None})

# --- Upload endpoint (unchanged)
def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f = request.files["file"]
    fname = secure_filename(f.filename)

    if not allowed_file(fname):
        return jsonify({"error": "Invalid file type"}), 400

    path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
    f.save(path)

    inserted = []
    conn = get_db()
    cur = conn.cursor()

    # JSON
    if fname.lower().endswith(".json"):
        with open(path) as fh:
            data = json.load(fh)
            if not isinstance(data, list):
                data = [data]
        rows = data
    # CSV
    else:
        txt = io.StringIO(open(path).read())
        rows = list(csv.DictReader(txt))

    for r in rows:
        ts = r.get("timestamp") or datetime.datetime.utcnow().isoformat() + "Z"
        cur.execute("""INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon, country)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ts, r.get("source"), r.get("event_type"), r.get("severity"),
                     r.get("message"), r.get("src_ip"), r.get("lat"), r.get("lon"), r.get("country")))
        log_id = cur.lastrowid
        conn.commit()
        # run detection
        run_detection_on_log(conn, log_id)
        inserted.append(log_id)

    return jsonify({"inserted": inserted})

# --- Meta filters
@app.route("/api/meta")
def api_meta():
    cur = get_db().cursor()
    cur.execute("SELECT DISTINCT source FROM logs")
    sources = [r["source"] for r in cur.fetchall() if r["source"]]
    cur.execute("SELECT DISTINCT event_type FROM logs")
    types = [r["event_type"] for r in cur.fetchall() if r["event_type"]]
    return jsonify({"sources": sources, "event_types": types})

# --- Analytics endpoint
@app.route("/api/analytics")
def api_analytics():
    cur = get_db().cursor()
    # alerts per hour (last 24 hours)
    cur.execute("""
        SELECT substr(created_at,1,13) AS hour, COUNT(*) AS c
        FROM alerts
        WHERE created_at >= datetime('now', '-24 hours')
        GROUP BY hour ORDER BY hour
    """)
    per_hour = [{ "hour": r["hour"], "count": r["c"] } for r in cur.fetchall()]

    # severity distribution
    cur.execute("SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity")
    severity_dist = [{ "severity": r["severity"], "count": r["c"] } for r in cur.fetchall()]

    # alerts by type (rule)
    cur.execute("SELECT rule, COUNT(*) AS c FROM alerts GROUP BY rule")
    by_rule = [{ "rule": r["rule"], "count": r["c"] } for r in cur.fetchall()]

    # top countries from logs
    cur.execute("SELECT country, COUNT(*) AS c FROM logs WHERE country IS NOT NULL GROUP BY country ORDER BY c DESC LIMIT 10")
    top_countries = [{ "country": r["country"], "count": r["c"] } for r in cur.fetchall()]

    return jsonify({
        "alerts_per_hour": per_hour,
        "severity_distribution": severity_dist,
        "alerts_by_rule": by_rule,
        "top_countries": top_countries
    })

# ===============================================================
# AUTO SEED + generator start (run-once)
# ===============================================================

seed_done = False

def seed_demo():
    conn = thread_db_conn()
    cur = conn.cursor()
    demo = [
        ("2025-11-14T00:00:00Z", "Firewall", "Port Scan", "High", "Scan detected", "203.0.113.4", 37.77, -122.41, "US"),
        ("2025-11-14T00:05:00Z", "Web Server", "Failed Login", "Medium", "Failed login admin", "198.51.100.10", 40.71, -74.00, "US"),
        ("2025-11-14T00:10:00Z", "IDS", "Malware Detected", "Critical", "Malware match", "192.0.2.45", 51.50, -0.12, "GB"),
    ]
    for row in demo:
        cur.execute("""INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon, country)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", row)
        lid = cur.lastrowid
        conn.commit()
        run_detection_on_log(conn, lid)

    # add sample threat intel if empty
    seed_threat_intel_if_empty()
    conn.close()

def maybe_seed():
    conn = thread_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM logs")
    r = cur.fetchone()
    cnt = r["c"] if r else 0
    if cnt == 0:
        print("⚠️ Seeding demo logs (Flask 3 compatible)")
        seed_demo()
    conn.close()

@app.before_request
def run_seed_once():
    global seed_done
    if not seed_done:
        try:
            maybe_seed()
            ensure_generator_running()
        except Exception as e:
            print("Seed error:", e)
        seed_done = True

# ===============================================================
# START SERVER
# ===============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # ensure threat intel seeded on local startup too
    seed_threat_intel_if_empty()
    ensure_generator_running()
    app.run(host="0.0.0.0", port=port, debug=True)
