from flask import Flask, render_template, request, redirect, url_for, session, flash
import json, os, random, time, bcrypt
from datetime import datetime
from ml_engine import predict_risk

app = Flask(__name__)
app.secret_key = "cs-project-demo-key-2026"

import shutil

def get_file_path(filename):
    if os.environ.get("VERCEL") == "1":
        tmp_path = os.path.join("/tmp", filename)
        if filename == "users.json" and not os.path.exists(tmp_path):
            original = os.path.join(os.path.dirname(__file__), filename)
            if os.path.exists(original):
                try:
                    shutil.copy(original, tmp_path)
                except Exception:
                    pass
        return tmp_path
    return filename

USERS_FILE    = get_file_path("users.json")
OTP_FILE      = get_file_path("otp_store.json")
LOG_FILE      = get_file_path("login_log.json")
BLOCK_THRESHOLD = 5
BLOCK_DURATION  = 60   # seconds

login_tracker = {}   # in-memory per session

# ─── helpers ────────────────────────────────────────────────────────────────

def load_json(path, default):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def generate_otp():
    return str(random.randint(100000, 999999))

def is_unusual_hour():
    h = datetime.now().hour
    unusual = 1 if h < 5 else 0
    print(f"[DEBUG CLOCK] Checked hour: {h} | Unusual hour flag: {unusual}")
    return unusual

def init_tracker(username):
    if username not in login_tracker:
        login_tracker[username] = {
            "failed_attempts": 0,
            "last_attempt_time": 0,
            "blocked_until": 0,
        }

def extract_features(username, device_id, password_correct):
    init_tracker(username)
    t = login_tracker[username]
    now = time.time()
    users = load_json(USERS_FILE, {})

    short_interval  = 1 if (now - t["last_attempt_time"]) < 5 else 0
    unusual_hour    = is_unusual_hour()
    known = users.get(username, {}).get("known_device")
    unknown_device  = 0 if (known and device_id == known) else 1

    features = {
        "failed_attempts": t["failed_attempts"],
        "short_interval":  short_interval,
        "unknown_device":  unknown_device,
        "unusual_hour":    unusual_hour,
        "password_match":  1 if password_correct else 0,
    }
    t["last_attempt_time"] = now
    return features

def append_log(entry):
    logs = load_json(LOG_FILE, [])
    entry["id"] = len(logs) + 1
    entry["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append(entry)
    save_json(LOG_FILE, logs)

def verify_password(stored_hash, entered):
    """Supports both bcrypt hashes and plain-text (demo fallback)."""
    if stored_hash.startswith("$2b$"):
        return bcrypt.checkpw(entered.encode(), stored_hash.encode())
    return stored_hash == entered   # plain-text fallback

# ─── routes ─────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        device_id = request.form.get("device_id", "unknown")
        ip        = request.remote_addr

        users = load_json(USERS_FILE, {})
        init_tracker(username)
        t = login_tracker[username]

        # ── check block ──
        if time.time() < t["blocked_until"]:
            remaining = int(t["blocked_until"] - time.time())
            return render_template("blocked.html", remaining=remaining, username=username)

        # ── verify password ──
        user_data = users.get(username)
        password_correct = False
        if user_data:
            password_correct = verify_password(user_data.get("password", ""), password)

        features = extract_features(username, device_id, password_correct)
        risk_int, confidence, risk_level, rule_score = predict_risk(features)

        # ── wrong password ──
        if not password_correct:
            t["failed_attempts"] += 1
            append_log({
                **features, "username": username, "device_id": device_id,
                "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
                "ml_confidence": confidence, "action": "denied", "outcome": "wrong_password"
            })
            if t["failed_attempts"] >= BLOCK_THRESHOLD:
                t["blocked_until"] = time.time() + BLOCK_DURATION
                append_log({
                    **features, "username": username, "device_id": device_id,
                    "ip": ip, "risk_level": "high", "rule_score": rule_score,
                    "ml_confidence": confidence, "action": "blocked", "outcome": "threshold_exceeded"
                })
                return render_template("blocked.html", remaining=BLOCK_DURATION, username=username)
            flash(f"Invalid credentials. Risk: {risk_level.upper()} | Score: {rule_score} | Attempt {t['failed_attempts']}/{BLOCK_THRESHOLD}", "error")
            return redirect(url_for("login"))

        # ── correct password ──
        t["failed_attempts"] = 0

        # Update known_device on first login
        if not users[username].get("known_device"):
            users[username]["known_device"] = device_id
            save_json(USERS_FILE, users)
            features["unknown_device"] = 0   # update after registration
            risk_int, confidence, risk_level, rule_score = predict_risk(features)

        # ── high risk → block ──
        if risk_level == "high":
            t["blocked_until"] = time.time() + BLOCK_DURATION
            append_log({
                **features, "username": username, "device_id": device_id,
                "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
                "ml_confidence": confidence, "action": "blocked", "outcome": "high_risk"
            })
            return render_template("blocked.html", remaining=BLOCK_DURATION, username=username)

        # ── medium risk → delay ──
        if risk_level == "medium":
            time.sleep(3)

        # ── generate OTP ──
        otp = generate_otp()
        otp_store = load_json(OTP_FILE, {})
        otp_store[username] = {"otp": otp, "expires": time.time() + 300}
        save_json(OTP_FILE, otp_store)

        session["username"]   = username
        session["risk_level"] = risk_level
        session["rule_score"] = rule_score
        session["confidence"] = confidence
        session["device_id"]  = device_id
        session["demo_otp"]   = otp   # shown on OTP page for demo

        append_log({
            **features, "username": username, "device_id": device_id,
            "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
            "ml_confidence": confidence, "action": "otp_sent", "outcome": "pending_mfa"
        })
        print(f"[DEMO OTP for {username}]: {otp}")
        return redirect(url_for("otp_page"))

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_page():
    if "username" not in session:
        return redirect(url_for("login"))

    username   = session["username"]
    risk_level = session.get("risk_level", "low")
    rule_score = session.get("rule_score", 0)
    confidence = session.get("confidence", 0)
    demo_otp   = session.get("demo_otp", "------")

    if request.method == "POST":
        entered   = request.form.get("otp", "").strip()
        otp_store = load_json(OTP_FILE, {})
        record    = otp_store.get(username, {})
        correct   = record.get("otp")
        expires   = record.get("expires", 0)

        if time.time() > expires:
            flash("OTP expired. Please log in again.", "error")
            session.clear()
            return redirect(url_for("login"))

        if entered == correct:
            otp_store.pop(username, None)
            save_json(OTP_FILE, otp_store)
            append_log({
                "username": username, "device_id": session.get("device_id"),
                "ip": request.remote_addr, "risk_level": risk_level,
                "rule_score": rule_score, "ml_confidence": confidence,
                "action": "otp_verified", "outcome": "access_granted",
                "failed_attempts": 0, "short_interval": 0,
                "unknown_device": 0, "unusual_hour": 0, "password_match": 1,
            })
            session["authenticated"] = True
            return redirect(url_for("success"))

        append_log({
            "username": username, "device_id": session.get("device_id"),
            "ip": request.remote_addr, "risk_level": risk_level,
            "rule_score": rule_score, "ml_confidence": confidence,
            "action": "otp_failed", "outcome": "wrong_otp",
            "failed_attempts": 0, "short_interval": 0,
            "unknown_device": 0, "unusual_hour": 0, "password_match": 1,
        })
        flash("Incorrect OTP. Please try again.", "error")

    return render_template("otp.html",
        username=username, risk_level=risk_level,
        rule_score=rule_score, confidence=confidence, demo_otp=demo_otp)


@app.route("/success")
def success():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("success.html",
        username=session.get("username"),
        risk_level=session.get("risk_level", "low"),
        rule_score=session.get("rule_score", 0),
        confidence=session.get("confidence", 0))


@app.route("/logs")
def logs():
    all_logs = load_json(LOG_FILE, [])
    all_logs.reverse()   # newest first
    return render_template("logs.html", logs=all_logs)


@app.route("/clear-logs", methods=["POST"])
def clear_logs():
    save_json(LOG_FILE, [])
    flash("Logs cleared.", "info")
    return redirect(url_for("logs"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Pre-train ML model on startup
    from ml_engine import load_model
    load_model()
    print("[App] Starting SecureAuth demo server...")
    app.run(debug=True, port=5000)
