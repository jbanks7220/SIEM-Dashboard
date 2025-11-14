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
        # ensure we use absolute path for safety
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Create required tables."""
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

    # Default login
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)",
                    ("analyst", "password"))

    conn.commit()


with app.app_context():
    init_db()


# ===============================================================
# RULES ENGINE (alerts) — robust to Row or dict
# ===============================================================
def _value(row_or_dict, key):
    """Safe accessor that works for sqlite3.Row and dict-like inputs."""
    try:
        return row_or_dict[key]
    except Exception:
        try:
            return row_or_dict.get(key)  # if it's a dict
        except Exception:
            return None


def generate_alerts_for_log(log_id, log_row):
    """
    log_row can be a sqlite3.Row or a dict. This function will
    insert alerts based on simple rules.
    """
    conn = get_db()
    cur = conn.cursor()

    severity = (_value(log_row, "severity") or "").lower()
    event_type = (_value(log_row, "event_type") or "")
    src_ip = _value(log_row, "src_ip")

    # -- Critical severity rule
    if severity == "critical":
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.datetime.utcnow().isoformat() if hasattr(datetime, "datetime") else datetime.datetime.utcnow().isoformat(),
            "critical_sev",
            "Critical",
            f"Critical event: {event_type} from {src_ip}"
        ))

    # -- Port scan rule
    if event_type and "scan" in event_type.lower():
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.datetime.utcnow().isoformat() if hasattr(datetime, "datetime") else datetime.datetime.utcnow().isoformat(),
            "port_scan",
            "High",
            f"Port scan detected from {src_ip}"
        ))

    # -- Brute-force heuristic (5+ events in last 10 minutes)
    if src_ip:
        window_start = (datetime.datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat() if hasattr(datetime, "datetime") else (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat()
        # Note: timestamps must be ISO strings in the logs for this to work reliably
        cur.execute("SELECT COUNT(*) AS c FROM logs WHERE src_ip = ? AND timestamp >= ?", (src_ip, window_start))
        count_row = cur.fetchone()
        c = count_row["c"] if count_row and "c" in count_row.keys() else (count_row[0] if count_row else 0)

        if c >= 5:
            cur.execute("""
                INSERT INTO alerts (log_id, created_at, rule, severity, message)
                VALUES (?, ?, ?, ?, ?)
            """, (
                log_id,
                datetime.datetime.datetime.utcnow().isoformat() if hasattr(datetime, "datetime") else datetime.datetime.utcnow().isoformat(),
                "brute_force",
                "Medium",
                f"{c} events from {src_ip} in last 10 minutes"
            ))

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
        username = request.form.get("username")
        pw = request.form.get("password")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ? AND pw = ?", (username, pw))
        row = cur.fetchone()

        if row:
            session["user"] = username
            return redirect(url_for("index"))

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# health route to confirm Render is running latest code
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "render_commit": os.environ.get("RENDER_GIT_COMMIT", "unknown"),
        "database": DATABASE,
    })


# ===============================================================
# API: LOGS
# ===============================================================
@app.route("/api/logs", methods=["GET"])
def api_get_logs():
    severity = request.args.get("severity")
    source = request.args.get("source")
    event_type = request.args.get("event_type")
    q = request.args.get("q")
    limit = int(request.args.get("limit", 200))

    conn = get_db()
    cur = conn.cursor()

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if source:
        query += " AND source = ?"
        params.append(source)

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)

    if q:
        query += " AND (message LIKE ? OR src_ip LIKE ? OR event_type LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)


# ===============================================================
# API: ALERTS
# ===============================================================
@app.route("/api/alerts", methods=["GET"])
def api_get_alerts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)


# ===============================================================
# API: UPLOAD LOGS (JSON + CSV)
# ===============================================================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(f.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(f.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(path)

    inserted = []
    conn = get_db()
    cur = conn.cursor()

    # JSON
    if filename.lower().endswith(".json"):
        with open(path) as fh:
            data = json.load(fh)
            items = data if isinstance(data, list) else [data]

            for it in items:
                timestamp = it.get("timestamp") or datetime.datetime.utcnow().isoformat()

                cur.execute("""
                    INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, it.get("source"), it.get("event_type"), it.get("severity"),
                    it.get("message"), it.get("src_ip"), it.get("lat"), it.get("lon")
                ))

                log_id = cur.lastrowid
                conn.commit()

                # fetch the DB row to pass to the rules engine (safer)
                cur2 = conn.cursor()
                cur2.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
                row = cur2.fetchone()
                generate_alerts_for_log(log_id, row)

                inserted.append(log_id)

    # CSV
    else:
        stream = io.StringIO(open(path, "r").read())
        reader = csv.DictReader(stream)

        for it in reader:
            timestamp = it.get("timestamp") or datetime.datetime.utcnow().isoformat()

            cur.execute("""
                INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, it.get("source"), it.get("event_type"), it.get("severity"),
                it.get("message"), it.get("src_ip"), it.get("lat"), it.get("lon")
            ))

            log_id = cur.lastrowid
            conn.commit()

            cur2 = conn.cursor()
            cur2.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
            row = cur2.fetchone()
            generate_alerts_for_log(log_id, row)

            inserted.append(log_id)

    return jsonify({"inserted": inserted}), 201


# ===============================================================
# API: META (filters)
# ===============================================================
@app.route("/api/meta", methods=["GET"])
def api_meta():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT source FROM logs")
    sources = [r["source"] for r in cur.fetchall() if r["source"]]

    cur.execute("SELECT DISTINCT event_type FROM logs")
    types = [r["event_type"] for r in cur.fetchall() if r["event_type"]]

    return jsonify({"sources": sources, "event_types": types})


# ===============================================================
# AUTO-SEED (Render-friendly)
# ===============================================================
def seed_render_demo():
    conn = get_db()
    cur = conn.cursor()
    demo = [
        ("2025-11-14T00:00:00Z", "Firewall", "Port Scan", "High", "Scan detected", "203.0.113.4", 37.7749, -122.4194),
        ("2025-11-14T00:05:00Z", "Web Server", "Failed Login", "Medium", "Failed login for admin", "198.51.100.10", 40.7128, -74.0060),
        ("2025-11-14T00:06:00Z", "Web Server", "Failed Login", "Medium", "Failed login for admin", "198.51.100.10", 40.7128, -74.0060),
        ("2025-11-14T00:07:00Z", "Web Server", "Failed Login", "Medium", "Failed login for admin", "198.51.100.10", 40.7128, -74.0060),
        ("2025-11-14T00:08:00Z", "Web Server", "Failed Login", "Medium", "Failed login for admin", "198.51.100.10", 40.7128, -74.0060),
        ("2025-11-14T00:09:00Z", "Web Server", "Failed Login", "Medium", "Failed login for admin", "198.51.100.10", 40.7128, -74.0060),
        ("2025-11-14T00:10:00Z", "IDS", "Malware Detected", "Critical", "Malware signature match", "192.0.2.45", 51.5074, -0.1278)
    ]
    for row in demo:
        cur.execute("""
            INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, row)
        log_id = cur.lastrowid
        conn.commit()
        # generate alerts for seeded rows
        cur2 = conn.cursor()
        cur2.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
        r = cur2.fetchone()
        generate_alerts_for_log(log_id, r)


@app.before_first_request
def ensure_seed_on_render():
    # if DB empty, seed it (Render file system starts empty each deploy)
    cur = get_db().cursor()
    cur.execute("SELECT COUNT(*) as c FROM logs")
    row = cur.fetchone()
    count = row["c"] if row and "c" in row.keys() else (row[0] if row else 0)
    if count == 0:
        print("⚠️ No logs found — seeding demo data (Render environment).")
        seed_render_demo()
        print("⚠️ Demo data seeded.")


# ===============================================================
# START SERVER
# ===============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
