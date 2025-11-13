from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, session, flash, g
)
import json, os, sqlite3, csv, io, datetime
from werkzeug.utils import secure_filename

# -------------------------------------------------
# Config
# -------------------------------------------------
DATABASE = 'siem.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'json', 'csv'}
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = SECRET_KEY


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    """Return a SQLite connection and reuse within this request."""
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


# -------------------------------------------------
# Init tables if missing
# (Matches your init_db.py)
# -------------------------------------------------
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

    # Default user
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()['c'] == 0:
        cur.execute("INSERT INTO users (username, pw) VALUES (?, ?)", ("analyst", "password"))

    conn.commit()


with app.app_context():
    init_db()


# -------------------------------------------------
# Alert Rules
# -------------------------------------------------
def generate_alerts_for_log(log_id, log_row):
    """log_row MUST be a SQLite row with the correct fields"""
    conn = get_db()
    cur = conn.cursor()

    # --- Rule: Critical severity
    if log_row['severity'] and log_row['severity'].lower() == "critical":
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.utcnow().isoformat(),
            "critical_sev",
            "Critical",
            f"Critical event: {log_row['event_type']} from {log_row['src_ip']}"
        ))

    # --- Rule: event type contains "scan"
    if log_row['event_type'] and "scan" in log_row['event_type'].lower():
        cur.execute("""
            INSERT INTO alerts (log_id, created_at, rule, severity, message)
            VALUES (?, ?, ?, ?, ?)
        """, (
            log_id,
            datetime.datetime.utcnow().isoformat(),
            "port_scan",
            "High",
            f"Port scan detected from {log_row['src_ip']}"
        ))

    # --- Rule: brute forc
