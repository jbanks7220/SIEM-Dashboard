from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, g
import json, os, sqlite3, csv, io, datetime
from werkzeug.utils import secure_filename

# -----------------------
# Config
# -----------------------
DATABASE = 'siem.db'   # single consistent DB file
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json', 'csv'}
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')

os.makedirs('uploads', exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY


# -----------------------
# DB Helpers (single correct version)
# -----------------------
def get_db():
    """Return a SQLite connection, reuse per-request."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Create required tables if missing."""
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

    # Default demo user
    cur.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()['c'] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)", ('analyst', 'password'))

    conn.commit()


# Run DB initialization
with app.app_context():
    init_db()


# -----------------------
# Rules Engine
# -----------------------
def generate_alerts_for_log(log_id, log_row):
    conn = get_db()
    cur = conn.cursor()

    # Rule: critical severity
    if log_row['severity'] and log_row['severity'].lower() == 'critical':
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.utcnow().isoformat(),
            'critical_sev',
            'Critical',
            f"Critical event: {log_row['event_type']} from {log_row['src_ip']}"
        ))

    # Rule: port scan
    if log_row['event_type'] and 'scan' in log_row['event_type'].lower():
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.utcnow().isoformat(),
            'port_scan',
            'High',
            f"Port scan detected from {log_row['src_ip']}"
        ))

    # Rule: brute force heuristic
    src_ip = log_row['src_ip']
    if src_ip:
        window_start = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat()
        cur.execute("SELECT COUNT(*) as c FROM logs WHERE src_ip = ? AND timestamp >= ?", (src_ip, window_start))
        c = cur.fetchone()['c']
        if c >= 5:
            cur.execute("""
                INSERT INTO alerts (log_id, created_at, rule, severity, message)
                VALUES (?, ?, ?, ?, ?)
            """, (
                log_id,
                datetime.datetime.utcnow().isoformat(),
                'brute_force',
                'Medium',
                f"Suspicious activity: {c} events from {src_ip} in last 10 minutes"
            ))

    conn.commit()


# -----------------------
# Routes
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
# API: Logs
# -----------------------
@app.route('/api/logs', methods=['GET'])
def api_get_logs():
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
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)


# -----------------------
# API: Alerts
# -----------------------
@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    return jsonify(rows)


# -----------------------
# API: Upload Logs
# -----------------------
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

    inserted = []
    conn = get_db()
    cur = conn.cursor()

    # JSON parsing
    if filename.lower().endswith('.json'):
        with open(path) as fh:
            data = json.load(fh)
            items = data if isinstance(data, list) else [data]

            for it in items:
                timestamp = it.get('timestamp') or datetime.datetime.utcnow().isoformat()
                cur.execute("""
                    INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, it.get('source'), it.get('event_type'), it.get('severity'),
                    it.get('message'), it.get('src_ip'), it.get('lat'), it.get('lon')
                ))
                log_id = cur.lastrowid
                conn.commit()
                generate_alerts_for_log(log_id, it)
                inserted.append(log_id)

    else:  # CSV parsing
        stream = io.StringIO(open(path, 'r').read())
        reader = csv.DictReader(stream)

        for it in reader:
            timestamp = it.get('timestamp') or datetime.datetime.utcnow().isoformat()
            cur.execute("""
                INSERT INTO logs (timestamp, source, event_type, severity, message, src_ip, lat, lon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp, it.get('source'), it.get('event_type'), it.get('severity'),
                it.get('message'), it.get('src_ip'), it.get('lat'), it.get('lon')
            ))
            log_id = cur.lastrowid
            conn.commit()
            generate_alerts_for_log(log_id, it)
            inserted.append(log_id)

    return jsonify({"inserted": inserted}), 201


# -----------------------
# API: Metadata for filters
# -----------------------
@app.route('/api/meta', methods=['GET'])
def api_meta():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT DISTINCT source FROM logs")
    sources = [r['source'] for r in cur.fetchall() if r['source']]

    cur.execute("SELECT DISTINCT event_type FROM logs")
    types = [r['event_type'] for r in cur.fetchall() if r['event_type']]

    return jsonify({"sources": sources, "event_types": types})


# -----------------------
# Run
# -----------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

