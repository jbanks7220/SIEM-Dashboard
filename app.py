from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import json, os, sqlite3, csv, io, datetime
from werkzeug.utils import secure_filename
import sqlite3
from flask import g

# config
DATABASE = 'data/siem.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json', 'csv'}
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')

os.makedirs('data', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY

# -----------------------
# DB helpers
# -----------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
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
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            created_at TEXT,
            rule TEXT,
            severity TEXT,
            message TEXT
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            pw TEXT
        )
    ''')
    # add a demo user if none exists
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()['c'] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)", ('analyst', 'password'))
    conn.commit()
    conn.close()

# call init on startup
init_db()

# -----------------------
# Alert rules engine
# -----------------------
def generate_alerts_for_log(log_id, log_row):
    """
    Simple rule engine. For demo purposes only.
    - Rule 1: More than 5 failed logins from same src_ip within last 10 minutes -> Medium
    - Rule 2: severity == 'Critical' -> Critical alert
    - Rule 3: Port Scan event_type -> High
    """
    conn = get_db()
    cur = conn.cursor()

    # Rule: immediate critical severity propagation
    if log_row['severity'] and log_row['severity'].lower() == 'critical':
        cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                    (log_id, datetime.datetime.utcnow().isoformat(), 'critical_sev', 'Critical',
                     f"Critical event: {log_row['event_type']} from {log_row['src_ip']}"))
    
    # Rule: port scan
    if log_row['event_type'] and 'scan' in log_row['event_type'].lower():
        cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                    (log_id, datetime.datetime.utcnow().isoformat(), 'port_scan', 'High',
                     f"Port scan detected from {log_row['src_ip']}"))

    # Rule: brute force heuristic
    src_ip = log_row['src_ip']
    if src_ip:
        window_start = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat()
        cur.execute("SELECT COUNT(*) as c FROM logs WHERE src_ip = ? AND timestamp >= ?", (src_ip, window_start))
        c = cur.fetchone()['c']
        if c >= 5:
            cur.execute("INSERT INTO alerts (log_id, created_at, rule, severity, message) VALUES (?, ?, ?, ?, ?)",
                        (log_id, datetime.datetime.utcnow().isoformat(), 'brute_force', 'Medium',
                         f"Suspicious activity: {c} events from {src_ip} in last 10 minutes"))

    conn.commit()
    conn.close()

# -----------------------
# Utility
# -----------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -----------------------
# Routes: UI
# -----------------------
@app.route('/')
def index():
    if not session.get('user'):
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        pw = request.form.get('password')
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ? AND pw = ?", (username, pw))
        row = cur.fetchone()
        conn.close()
        if row:
            session['user'] = username
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# -----------------------
# API Endpoints
# -----------------------
@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    # filters: severity, source, event_type, q (search), limit
    severity = request.args.get('severity')
    source = request.args.get('source')
    event_type = request.args.get('event_type')
    q = request.args.get('q')
    limit = int(request.args.get('limit', 200))

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
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """
    Accepts a single JSON log object or array of objects:
    {
      "timestamp":"2025-11-13T01:00:00",
      "source":"Firewall",
      "event_type":"Port Scan",
      "severity":"High",
      "message":"scan detected",
      "src_ip":"1.2.3.4",
      "lat": ...,
      "lon": ...
    }
    """
    payload = request.get_json(force=True)
    items = payload if isinstance(payload, list) else [payload]

    conn = get_db()
    cur = conn.cursor()
    inserted = []
    for it in items:
        timestamp = it.get('timestamp') or datetime.datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, it.get('source'), it.get('event_type'), it.get('severity'), it.get('message'), it.get('src_ip'), it.get('lat'), it.get('lon'))
        )
        log_id = cur.lastrowid
        conn.commit()
        # generate alerts
        cur2 = conn.cursor()
        cur2.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
        row = cur2.fetchone()
        generate_alerts_for_log(log_id, row)
        inserted.append(log_id)
    conn.close()
    return jsonify({"inserted": inserted}), 201

@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"error": "Empty filename"}), 400
    if not allowed_file(f.filename):
        return jsonify({"error": "File type not allowed"}), 400

    filename = secure_filename(f.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(path)

    # parse file into logs and insert
    inserted = []
    conn = get_db()
    cur = conn.cursor()
    if filename.lower().endswith('.json'):
        with open(path) as fh:
            data = json.load(fh)
            items = data if isinstance(data, list) else [data]
            for it in items:
                timestamp = it.get('timestamp') or datetime.datetime.utcnow().isoformat()
                cur.execute(
                    "INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, it.get('source'), it.get('event_type'), it.get('severity'), it.get('message'), it.get('src_ip'), it.get('lat'), it.get('lon'))
                )
                log_id = cur.lastrowid
                conn.commit()
                generate_alerts_for_log(log_id, it)
                inserted.append(log_id)
    else:  # CSV
        stream = io.StringIO(open(path, 'r').read())
        reader = csv.DictReader(stream)
        for it in reader:
            timestamp = it.get('timestamp') or datetime.datetime.utcnow().isoformat()
            cur.execute(
                "INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (timestamp, it.get('source'), it.get('event_type'), it.get('severity'), it.get('message'), it.get('src_ip'), it.get('lat'), it.get('lon'))
            )
            log_id = cur.lastrowid
            conn.commit()
            generate_alerts_for_log(log_id, it)
            inserted.append(log_id)
    conn.close()
    return jsonify({"inserted": inserted}), 201

# serve a simple API to list sources & types for filters
@app.route('/api/meta', methods=['GET'])
def api_meta():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT source FROM logs")
    sources = [r['source'] for r in cur.fetchall() if r['source']]
    cur.execute("SELECT DISTINCT event_type FROM logs")
    types = [r['event_type'] for r in cur.fetchall() if r['event_type']]
    conn.close()
    return jsonify({"sources": sources, "event_types": types})

DATABASE = 'siem.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# -----------------------
# Run
# -----------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)


