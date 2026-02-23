import asyncio
import threading
import hashlib
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect
import sqlite3
import os
import aioping
import requests
import time

# ---- TIMEZONE ----
os.environ["TZ"] = "Asia/Jakarta"
time.tzset()

DB = "data/monitor.db"
CHECK_INTERVAL = 5
FAIL_THRESHOLD = 3

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

app = Flask(__name__)
app.secret_key = "iamtheborg"


# ---------------- DATABASE ----------------

def get_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        monitor_type TEXT,
        monitor_port TEXT,
        status TEXT DEFAULT 'Online',
        last_down TEXT,
        fail_count INTEGER DEFAULT 0,
        maintenance INTEGER DEFAULT 0,
        last_latency REAL DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        monitor_detail TEXT,
        down_time TEXT,
        up_time TEXT,
        duration TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS latency_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id INTEGER,
        latency REAL,
        timestamp TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    )
    """)

    if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        pwd = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users VALUES (?,?,?)", ("admin", pwd, "admin"))

    if not c.execute("SELECT 1 FROM users WHERE username='viewer'").fetchone():
        pwd = hashlib.sha256("viewer123".encode()).hexdigest()
        c.execute("INSERT INTO users VALUES (?,?,?)", ("viewer", pwd, "viewer"))

    conn.commit()
    conn.close()


init_db()


# ---------------- TELEGRAM ----------------

def send_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": msg},
            timeout=5
        )
    except:
        pass


# ---------------- ROUTES ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = hashlib.sha256(request.form["password"].encode()).hexdigest()

        conn = get_db()
        user = conn.execute(
            "SELECT role FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session["user"] = username
            session["role"] = user["role"]
            return redirect("/")

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
def index():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")


@app.route("/add", methods=["POST"])
def add():
    if session.get("role") != "admin":
        return "Forbidden", 403

    name = request.form.get("name")
    mtype = request.form.get("monitor_type")
    port = request.form.get("monitor_port")

    conn = get_db()
    conn.execute(
        "INSERT INTO targets (name,monitor_type,monitor_port) VALUES (?,?,?)",
        (name, mtype, port)
    )
    conn.commit()
    conn.close()

    detail = f"{mtype.upper()}:{port}" if mtype == "tcp" else "ICMP"
    send_telegram(f"➕ MONITOR ADDED\nHost: {name}\nCheck: {detail}")

    return jsonify({"status": "ok"})


@app.route("/remove/<int:id>", methods=["POST"])
def remove(id):
    if session.get("role") != "admin":
        return "Forbidden", 403

    conn = get_db()
    row = conn.execute("SELECT * FROM targets WHERE id=?", (id,)).fetchone()
    if row:
        detail = f"{row['monitor_type'].upper()}:{row['monitor_port']}" if row["monitor_type"] == "tcp" else "ICMP"
        send_telegram(f"➖ MONITOR REMOVED\nHost: {row['name']}\nCheck: {detail}")
        conn.execute("DELETE FROM targets WHERE id=?", (id,))
        conn.commit()

    conn.close()
    return jsonify({"status": "ok"})


@app.route("/toggle_maintenance/<int:id>", methods=["POST"])
def toggle_maintenance(id):
    if session.get("role") != "admin":
        return "Forbidden", 403

    conn = get_db()
    row = conn.execute("SELECT maintenance FROM targets WHERE id=?", (id,)).fetchone()

    if row:
        new_value = 0 if row["maintenance"] == 1 else 1
        conn.execute("UPDATE targets SET maintenance=? WHERE id=?", (new_value, id))
        conn.commit()

    conn.close()
    return jsonify({"status": "ok"})


@app.route("/status")
def status():
    conn = get_db()
    rows = conn.execute("SELECT * FROM targets").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/incidents")
def incidents():
    conn = get_db()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/clear_incidents", methods=["POST"])
def clear_incidents():
    if session.get("role") != "admin":
        return "Forbidden", 403
    conn = get_db()
    conn.execute("DELETE FROM incidents")
    conn.commit()
    conn.close()
    return jsonify({"status": "cleared"})


# ---------------- MONITOR LOOP ----------------

async def check_icmp(host):
    try:
        latency = await aioping.ping(host, timeout=2)
        return True, round(latency * 1000, 2)
    except:
        return False, 0


async def check_tcp(host, port):
    try:
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.close()
        await writer.wait_closed()
        return True, 0
    except:
        return False, 0


async def monitor_loop():
    while True:
        conn = get_db()
        c = conn.cursor()
        targets = c.execute("SELECT * FROM targets").fetchall()

        for t in targets:

            detail = f"TCP:{t['monitor_port']}" if t["monitor_type"] == "tcp" else "ICMP"

            if t["monitor_type"] == "tcp":
                status, latency = await check_tcp(t["name"], t["monitor_port"])
            else:
                status, latency = await check_icmp(t["name"])

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if status:
                if t["status"] == "Offline":
                    duration = "-"
                    if t["last_down"]:
                        down_time = datetime.strptime(t["last_down"], "%Y-%m-%d %H:%M:%S")
                        duration = str(datetime.now() - down_time)

                    if t["maintenance"] == 0:
                        send_telegram(f"🟢 BACK ONLINE\nHost: {t['name']}\nCheck: {detail}\nDuration: {duration}")

                    c.execute("""
                        INSERT INTO incidents (target, monitor_detail, down_time, up_time, duration)
                        VALUES (?,?,?,?,?)
                    """, (t["name"], detail, t["last_down"], now, duration))

                c.execute("""
                    UPDATE targets SET
                    status='Online',
                    fail_count=0,
                    last_down=NULL,
                    last_latency=?
                    WHERE id=?
                """, (latency, t["id"]))

            else:
                fail = t["fail_count"] + 1

                if fail >= FAIL_THRESHOLD:
                    if t["status"] != "Offline":
                        if t["maintenance"] == 0:
                            send_telegram(f"🔴 HOST DOWN\nHost: {t['name']}\nCheck: {detail}")
                        c.execute("""
                            UPDATE targets SET
                            status='Offline',
                            last_down=?,
                            fail_count=?
                            WHERE id=?
                        """, (now, fail, t["id"]))
                else:
                    c.execute("UPDATE targets SET fail_count=? WHERE id=?", (fail, t["id"]))

        conn.commit()
        conn.close()
        await asyncio.sleep(CHECK_INTERVAL)


def start_monitor():
    asyncio.run(monitor_loop())


threading.Thread(target=start_monitor, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
