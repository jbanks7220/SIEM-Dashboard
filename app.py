from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, g
import json, os, sqlite3, csv, io, datetime
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
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY

# ===============================================================
# DB HELPERS
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

def init_db():
    conn = get_db()
    cur = conn.cursor()

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
            lon REAL
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

    # default login
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)",
                    ("analyst", "password"))

    conn.commit()

with app.app_context():
    init_db()

# ===============================================================
# RULES ENGINE — alert generator
# ===============================================================

def _value(row, key):
    try:
        return row[key]
    except:
        return None

def generate_alerts_for_log(log_id, row):
    conn = get_db()
    cur = conn.cursor()

    severity = (_value(row, "severity") or "").lower()
    event_type = (_value(row, "event_type") or "").lower()
    src_ip = _value(row, "src_ip")

    now = datetime.datetime.utcnow().isoformat()

    # critical severity
    if severity == "critical":
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, 'critical_sev', 'Critical', ?)
        """, (log_id, now, f"Critical event: {event_type} from {src_ip}"))

    # port scan
    if "scan" in event_type:
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, 'port_scan', 'High', ?)
        """, (log_id, now, f"Port scan detected from {src_ip}"))

    # brute-force (5 events / 10 minutes)
    if src_ip:
        window = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat()
        cur.execute("SELECT COUNT(*) AS c FROM logs WHERE src_ip = ? AND timestamp >= ?", (src_ip, window))
        count = cur.fetchone()["c"]

        if count >= 5:
            cur.execute("""
                INSERT INTO alerts (log_id, created_at, rule, severity, message)
                VALUES (?, ?, 'brute_force', 'Medium', ?)
            """, (log_id, now, f"{count} events from {src_ip} in last 10 minutes"))

    conn.commit()

# ===============================================================
# ROUTES
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
            return redirect(url_for("index"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ===============================================================
# HEALTH CHECK
# ===============================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "version": os.environ.get("RENDER_GIT_COMMIT", "local"),
        "db_path": DATABASE
    })

# ===============================================================
# API: LOGS
# ===============================================================

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

# ===============================================================
# API: ALERTS
# ===============================================================

@app.route("/api/alerts")
def api_alerts():
    cur = get_db().cursor()
    cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    return jsonify([dict(r) for r in cur.fetchall()])

# ===============================================================
# API: UPLOAD (JSON, CSV)
# ===============================================================

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

    # Insert + alert generation
    for r in rows:
        ts = r.get("timestamp") or datetime.datetime.utcnow().isoformat()

        cur.execute("""
            INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts, r.get("source"), r.get("event_type"), r.get("severity"),
            r.get("message"), r.get("src_ip"), r.get("lat"), r.get("lon")
        ))

        log_id = cur.lastrowid
        conn.commit()

        c2 = conn.cursor()
        c2.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
        row = c2.fetchone()

        generate_alerts_for_log(log_id, row)
        inserted.append(log_id)

    return jsonify({"inserted": inserted})

# ===============================================================
# META FILTERS
# ===============================================================

@app.route("/api/meta")
def api_meta():
    cur = get_db().cursor()

    cur.execute("SELECT DISTINCT source FROM logs")
    sources = [r["source"] for r in cur.fetchall() if r["source"]]

    cur.execute("SELECT DISTINCT event_type FROM logs")
    types = [r["event_type"] for r in cur.fetchall() if r["event_type"]]

    return jsonify({"sources": sources, "event_types": types})

# ===============================================================
# AUTO-SEED (Render deploys)
# ===============================================================

def seed_demo():
    demo = [
        ("2025-11-14T00:00:00Z", "Firewall", "Port Scan", "High", "Scan detected", "203.0.113.4", 37.77, -122.41),
        ("2025-11-14T00:05:00Z", "Web Server", "Failed Login", "Medium", "Failed login admin", "198.51.100.10", 40.71, -74.00),
        ("2025-11-14T00:10:00Z", "IDS", "Malware Detected", "Critical", "Malware match", "192.0.2.45", 51.50, -0.12),
    ]
    conn = get_db()
    cur = conn.cursor()
    for row in demo:
        cur.execute("""
            INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
            VALUES (?,?,?,?,?,?,?,?)
        """, row)
        log_id = cur.lastrowid
        conn.commit()
        c2 = conn.cursor()
        c2.execute("SELECT * FROM logs WHERE id=?", (log_id,))
        r = c2.fetchone()
        generate_alerts_for_log(log_id,r)

def maybe_seed():
    with app.app_context():
        cur = get_db().cursor()
        cur.execute("SELECT COUNT(*) AS c FROM logs")
        if cur.fetchone()["c"] == 0:
            print("⚠️ Seeding demo logs (Render)")
            seed_demo()

# Flask 3 replacement for before_first_request
@app.before_serving
def before_serving_func():
    maybe_seed()

# ===============================================================
# START SERVER
# ===============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
