import random
import datetime
import time
import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "zero_trust_secret"
CORS(app)

LOCK_TIME = 60        # seconds
MAX_ATTEMPTS = 3

# ---------- DATABASE ----------
def get_db():
    return sqlite3.connect("database.db")

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_risk(event, level):
    print("✅ LOGGING RISK:", event, level)  # DEBUG (VERY IMPORTANT)
    with open("security.log", "a") as f:
        f.write(f"{datetime.datetime.now()} | {event} | {level}\n")


# ---------- ROUTES ----------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    data = request.json
    email = data["email"]
    password = generate_password_hash(data["password"])

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, password)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except:
        return jsonify({"success": False, "message": "User already exists"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.json
    email = data["email"]
    password = data["password"]

    # 🔐 CHECK IF ACCOUNT IS LOCKED
    if session.get("lock_until"):
        remaining = int(session["lock_until"] - time.time())
        if remaining > 0:
            return jsonify({
                "locked": True,
                "reason": "Multiple wrong password failure",
                "remaining": remaining
            })
        else:
            # Lock expired
            session.pop("lock_until")
            session["attempts"] = 0

    # 🔐 VERIFY USER
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session["attempts"] = 0

        session["user"] = email
        session["ip"] = request.remote_addr
        session["agent"] = request.headers.get("User-Agent")
        session["login_time"] = time.time()

        # Clear old logs for new session
        open("security.log", "w").close()

        otp = random.randint(100000, 999999)
        session["otp"] = str(otp)
        session["verified"] = False

        print("OTP:", otp)
        return jsonify({"otp_required": True})

    # ❌ WRONG PASSWORD
    session["attempts"] = session.get("attempts", 0) + 1
    log_risk("FAILED_LOGIN", "HIGH")

    if session["attempts"] >= 3:
        session["lock_until"] = time.time() + 60

    # 🔴 THIS IS THE MISSING PIECE
        log_risk("ACCOUNT_LOCKED", "HIGH")

        return jsonify({
            "locked": True,
            "reason": "Multiple wrong password failure",
            "remaining": 60
    })


    return jsonify({
        "success": False,
        "message": "Invalid password"
    })

@app.route("/otp")
def otp():
    if "otp" not in session:
        return redirect(url_for("login"))
    return render_template("otp.html")

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json

    if session.get("otp") == data["otp"]:
        session.pop("otp")
        session["verified"] = True
        return jsonify({"success": True})

    log_risk("FAILED_OTP", "HIGH")
    return jsonify({"success": False})

@app.route("/dashboard")
def dashboard():
    if "user" not in session or not session.get("verified"):
        return redirect(url_for("login"))

    if session.get("ip") != request.remote_addr:
        log_risk("NEW_IP", "HIGH")
        session.clear()
        return redirect(url_for("login"))

    if session.get("agent") != request.headers.get("User-Agent"):
        log_risk("NEW_DEVICE", "MEDIUM")
        session.clear()
        return redirect(url_for("login"))

    if time.time() - session.get("login_time", 0) > 300:
        log_risk("SESSION_EXPIRED", "MEDIUM")
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=session["user"])

@app.route("/security")
def security_dashboard():
    try:
        with open("security.log") as f:
            risks = f.readlines()
    except:
        risks = []
    return render_template("security.html", risks=risks)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/risk-analytics")
def risk_analytics():
    high_risks = []
    medium_risks = []
    low_risks = []

    has_failed_login = False
    has_failed_otp = False
    has_account_locked = False
    has_new_device = False
    has_session_expired = False

    try:
        with open("security.log", "r") as f:
            logs = f.readlines()
    except:
        logs = []

    for line in logs:
        if "FAILED_LOGIN" in line:
            has_failed_login = True

        if "FAILED_OTP" in line:
            has_failed_otp = True

        if "ACCOUNT_LOCKED" in line:
            has_account_locked = True

        if "NEW_DEVICE" in line:
            has_new_device = True

        if "SESSION_EXPIRED" in line:
            has_session_expired = True

    # 🔴 HIGH RISK (SEVERITY BASED)
    if has_failed_login:
        high_risks.append("Multiple incorrect password attempts detected")

    if has_failed_otp:
        high_risks.append("OTP verification failed")

    if has_account_locked:
        high_risks.append("Account temporarily locked due to brute-force attack")

    # 🟡 MEDIUM RISK
    if has_new_device:
        medium_risks.append("Login from a new device or browser")

    if has_session_expired:
        medium_risks.append("Session expired due to inactivity")

    # 🟢 LOW RISK
    if not high_risks and not medium_risks:
        low_risks.append("Normal login activity detected")

    return render_template(
        "risk_analytics.html",
        high=1 if high_risks else 0,
        medium=1 if medium_risks else 0,
        low=1 if low_risks else 0,
        high_risks=high_risks,
        medium_risks=medium_risks,
        low_risks=low_risks
    )

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
