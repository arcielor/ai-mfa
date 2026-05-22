from flask import Flask, render_template, request, redirect, url_for, session, flash, has_request_context
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

def is_unusual_hour(client_hour=None):
    if client_hour is not None:
        try:
            h = int(client_hour)
        except (TypeError, ValueError):
            h = datetime.now().hour
    else:
        h = datetime.now().hour
    unusual = 1 if h < 5 else 0
    print(f"[DEBUG CLOCK] Checked hour: {h} | Unusual hour flag: {unusual}")
    return unusual


import urllib.request

def check_ip_risk(ip, known_country):
    if not ip or ip in ["127.0.0.1", "localhost", "::1"] or ip.startswith("192.168.") or ip.startswith("10."):
        return 0, 0, "Local"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,proxy,hosting"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                is_anonymous = 1 if (data.get("proxy", False) or data.get("hosting", False)) else 0
                country = data.get("country", "Unknown")
                is_unusual = 1 if (known_country and country != "Unknown" and known_country != "Unknown" and known_country != "Local" and country != known_country) else 0
                return is_unusual, is_anonymous, country
    except Exception as e:
        print(f"[IP API error]: {e}")
    return 0, 0, "Unknown"

def init_tracker(username):
    if username not in login_tracker:
        login_tracker[username] = {
            "failed_attempts": 0,
            "last_attempt_time": 0,
            "blocked_until": 0,
        }

def extract_features(username, device_id, password_correct, client_hour=None, unusual_location=0, anonymous_ip=0):
    init_tracker(username)
    t = login_tracker[username]
    now = time.time()
    users = load_json(USERS_FILE, {})

    short_interval  = 1 if (now - t["last_attempt_time"]) < 5 else 0
    unusual_hour    = is_unusual_hour(client_hour)
    known = users.get(username, {}).get("known_device")
    unknown_device  = 0 if (known and device_id == known) else 1

    features = {
        "failed_attempts": t["failed_attempts"],
        "short_interval":  short_interval,
        "unknown_device":  unknown_device,
        "unusual_hour":    unusual_hour,
        "password_match":  1 if password_correct else 0,
        "otp_resends": session.get("resend_count", 0),
        "unusual_location": unusual_location,
        "anonymous_ip": anonymous_ip
    }
    t["last_attempt_time"] = now
    return features

def append_log(entry):
    logs = load_json(LOG_FILE, [])
    entry["id"] = len(logs) + 1
    if has_request_context() and session.get("client_time"):
        entry["timestamp"] = session.get("client_time")
    else:
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
        client_hour = request.form.get("client_hour")
        client_time = request.form.get("client_time")
        spoofed_ip  = request.form.get("spoofed_ip", "").strip()
        ip          = spoofed_ip if spoofed_ip else request.remote_addr

        if client_time:
            session["client_time"] = client_time

        # ── reCAPTCHA verification ──
        show_recaptcha = True
        if show_recaptcha:
            recaptcha_response = request.form.get("g-recaptcha-response")
            if not recaptcha_response:
                flash("Please complete the reCAPTCHA verification.", "error")
                return redirect(url_for("login"))
            
            # Verify against Google reCAPTCHA siteverify API
            import urllib.request, urllib.parse
            import json
            
            secret_key = "6LedwPMsAAAAABN5dk3-A1TsHwg0OFqjXpDl4F7d" # User-supplied reCAPTCHA secret key
            url = "https://www.google.com/recaptcha/api/siteverify"
            data = urllib.parse.urlencode({
                "secret": secret_key,
                "response": recaptcha_response,
                "remoteip": ip
            }).encode("utf-8")
            
            try:
                req = urllib.request.Request(url, data=data, method="POST")
                with urllib.request.urlopen(req) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    
                if not res_data.get("success"):
                    session["failed_attempts"] = session.get("failed_attempts", 0) + 1
                    append_log({
                        "failed_attempts": session.get("failed_attempts", 0),
                        "short_interval": 0,
                        "unknown_device": 1,
                        "unusual_hour": 0,
                        "password_match": 0,
                        "username": username,
                        "device_id": device_id,
                        "ip": ip,
                        "risk_level": "medium",
                        "rule_score": 0,
                        "ml_confidence": 0.0,
                        "action": "blocked",
                        "outcome": "recaptcha_failed"
                    })
                    flash("reCAPTCHA verification failed. Please try again.", "error")
                    return redirect(url_for("login"))
            except Exception as e:
                print(f"[ERROR] reCAPTCHA verification exception: {e}")
                flash("An error occurred during reCAPTCHA verification. Please try again.", "error")
                return redirect(url_for("login"))

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
        known_country = None
        if user_data:
            password_correct = verify_password(user_data.get("password", ""), password)
            known_country = user_data.get("known_country")

        unusual_location, anonymous_ip, current_country = check_ip_risk(ip, known_country)
        features = extract_features(username, device_id, password_correct, client_hour, unusual_location, anonymous_ip)
        risk_int, confidence, risk_level, rule_score = predict_risk(features)

        # ── wrong password ──
        if not password_correct:
            t["failed_attempts"] += 1
            session["failed_attempts"] = session.get("failed_attempts", 0) + 1
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
                
            if t["failed_attempts"] >= 3:
                session["temp_username"] = username
                session["pending_fallback_otp"] = True
                return render_template("login.html", show_recaptcha=show_recaptcha, fallback_otp=True, failed_attempts=t["failed_attempts"], threshold=BLOCK_THRESHOLD)
                
            flash(f"Invalid credentials. Risk: {risk_level.upper()} | Attempt {t['failed_attempts']}/{BLOCK_THRESHOLD}", "error")
            return redirect(url_for("login"))

        # correct password 
        prev_failed_attempts = t["failed_attempts"]
        t["failed_attempts"] = 0
        session["failed_attempts"] = 0

        # Update known_device and known_country on first login
        updated_users = False
        if not users[username].get("known_device"):
            users[username]["known_device"] = device_id
            features["unknown_device"] = 0   # update after registration
            updated_users = True
        
        if not users[username].get("known_country") and current_country not in ["Local", "Unknown"]:
            users[username]["known_country"] = current_country
            features["unusual_location"] = 0
            updated_users = True

        # ── high risk → block
        if risk_level == "high":
            t["blocked_until"] = time.time() + BLOCK_DURATION
            append_log({
                **features, "username": username, "device_id": device_id,
                "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
                "ml_confidence": confidence, "action": "blocked", "outcome": "high_risk"
            })
            return render_template("blocked.html", remaining=BLOCK_DURATION, username=username)

        # ── Anomaly Check ──
        anomaly_msg = None
        if features["unknown_device"] == 1 or features.get("unusual_location") == 1 or features.get("anonymous_ip") == 1 or features.get("unusual_hour") == 1:
            anomaly_msg = "Unusual behaviour detected."

        if anomaly_msg:
            session["temp_username"] = username
            session["pending_anomaly_confirm"] = True
            session["temp_device_id"] = device_id
            session["temp_risk_level"] = risk_level
            session["temp_rule_score"] = rule_score
            session["temp_confidence"] = confidence
            session["temp_features"] = features
            return render_template("login.html", show_recaptcha=show_recaptcha, anomaly_msg=anomaly_msg)

        # ── Normal & Correct Bypass ──
        if risk_level == "low" and prev_failed_attempts < 3:
            session["username"] = username
            session["risk_level"] = risk_level
            session["rule_score"] = rule_score
            session["confidence"] = confidence
            session["device_id"] = device_id
            session["authenticated"] = True
            session["auth_method"] = "password_only"
            append_log({
                **features, "username": username, "device_id": device_id,
                "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
                "ml_confidence": confidence, "action": "otp_bypassed", "outcome": "access_granted"
            })
            return redirect(url_for("success"))

        # ── medium risk → delay ──
        if risk_level == "medium":
            time.sleep(3)

        # ── generate OTP ──
        otp = generate_otp()
        otp_store = load_json(OTP_FILE, {})
        otp_store[username] = {"otp": otp, "expires": time.time() + 15}
        save_json(OTP_FILE, otp_store)

        session["username"]     = username
        session["risk_level"]   = risk_level
        session["rule_score"]   = rule_score
        session["confidence"]   = confidence
        session["device_id"]    = device_id
        session["demo_otp"]     = otp   # shown on OTP page for demo
        session["resend_count"] = 0
        session["unusual_location"] = unusual_location
        session["anonymous_ip"] = anonymous_ip
        session["features"] = features

        append_log({
            **features, "username": username, "device_id": device_id,
            "ip": ip, "risk_level": risk_level, "rule_score": rule_score,
            "ml_confidence": confidence, "action": "otp_sent", "outcome": "pending_mfa"
        })
        print(f"[DEMO OTP for {username}]: {otp}")
        return redirect(url_for("otp_page"))

    show_recaptcha = True
    return render_template("login.html", show_recaptcha=show_recaptcha)


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
            
            outcome = "access_granted_passwordless" if session.get("passwordless_fallback") else "access_granted"
            append_log({
                "username": username, "device_id": session.get("device_id"),
                "ip": request.remote_addr, "risk_level": risk_level,
                "rule_score": rule_score, "ml_confidence": confidence,
                "action": "otp_verified", "outcome": outcome,
                "failed_attempts": 0, "short_interval": 0,
                "unknown_device": 0, "unusual_hour": 0, "password_match": 1,
            })
            
            # Update device if it was unknown_device confirmation
            if session.get("pending_anomaly_confirm"):
                if session.get("device_id") != "unknown":
                    users = load_json(USERS_FILE, {})
                    if username in users:
                        users[username]["known_device"] = session.get("device_id")
                        save_json(USERS_FILE, users)
                session.pop("pending_anomaly_confirm", None)
            
            is_fallback = session.get("passwordless_fallback")
            session["auth_method"] = "otp_only" if is_fallback else "password_and_otp"
            
            session.pop("passwordless_fallback", None)
            session.pop("pending_fallback_otp", None)
            session.pop("temp_username", None)
                
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

    otp_store = load_json(OTP_FILE, {})
    record = otp_store.get(username, {})
    expires = record.get("expires", 0)
    remaining_seconds = int(max(0, expires - time.time()))
    resend_count = session.get("resend_count", 0)

    return render_template("otp.html",
        username=username, risk_level=risk_level,
        rule_score=rule_score, confidence=confidence, demo_otp=demo_otp,
        remaining_seconds=remaining_seconds, resend_count=resend_count)

@app.route("/send-device-otp", methods=["POST", "GET"])
def send_device_otp():
    username = session.get("temp_username")
    if not username:
        return redirect(url_for("login"))
    
    is_fallback = session.get("pending_fallback_otp")
    is_anomaly = session.get("pending_anomaly_confirm")
    
    if not (is_fallback or is_anomaly):
        return redirect(url_for("login"))
        
    otp = generate_otp()
    otp_store = load_json(OTP_FILE, {})
    otp_store[username] = {"otp": otp, "expires": time.time() + 15}
    save_json(OTP_FILE, otp_store)
    
    session["username"] = username
    session["demo_otp"] = otp
    session["resend_count"] = 0
    session["passwordless_fallback"] = True if is_fallback else False
    
    if is_anomaly:
        session["risk_level"] = session.get("temp_risk_level", "medium")
        session["rule_score"] = session.get("temp_rule_score", 0)
        session["confidence"] = session.get("temp_confidence", 0)
        session["device_id"] = session.get("temp_device_id", "unknown")
        
        features = session.get("temp_features", {})
        session["features"] = features
        append_log({
            **features, "username": username, "device_id": session.get("device_id"),
            "ip": request.remote_addr, "risk_level": session.get("risk_level"), 
            "rule_score": session.get("rule_score"), "ml_confidence": session.get("confidence"), 
            "action": "otp_sent", "outcome": "device_confirm_pending"
        })
    else:
        # Fallback case
        session["risk_level"] = "medium"
        session["features"] = {"failed_attempts": 3, "password_match": 0}
        append_log({
            "username": username, "ip": request.remote_addr,
            "action": "otp_sent", "outcome": "passwordless_fallback_pending",
            "risk_level": "medium", "rule_score": 0, "ml_confidence": 0
        })

    print(f"[DEMO OTP for {username}]: {otp}")
    return redirect(url_for("otp_page"))

@app.route("/resend-otp")
def resend_otp():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    resend_count = session.get("resend_count", 0)

    if resend_count >= 2:
        init_tracker(username)
        t = login_tracker[username]
        t["blocked_until"] = time.time() + BLOCK_DURATION
        
        features = session.get("features", {})
        append_log({
            **features, "username": username, "device_id": session.get("device_id"),
            "ip": request.remote_addr, "risk_level": "high",
            "rule_score": session.get("rule_score", 0), "ml_confidence": session.get("confidence", 0),
            "action": "blocked", "outcome": "resend_limit_exceeded"
        })
        session.clear()
        return render_template("blocked.html", remaining=BLOCK_DURATION, username=username)

    # Increment resend count
    resend_count += 1
    session["resend_count"] = resend_count

    # Generate new 15-second OTP
    otp = generate_otp()
    otp_store = load_json(OTP_FILE, {})
    otp_store[username] = {"otp": otp, "expires": time.time() + 15}
    save_json(OTP_FILE, otp_store)

    session["demo_otp"] = otp

    # Re-evaluate threat risk after resend , block if high risk
    features = extract_features(username, session.get("device_id"), True, None, session.get("unusual_location", 0), session.get("anonymous_ip", 0))
    risk_int, confidence, risk_level, rule_score = predict_risk(features)

    session["risk_level"] = risk_level
    session["rule_score"] = rule_score
    session["confidence"] = confidence

    if risk_level == "high":
        init_tracker(username)
        t = login_tracker[username]
        t["blocked_until"] = time.time() + BLOCK_DURATION
        append_log({
            **features, "username": username, "device_id": session.get("device_id"),
            "ip": request.remote_addr, "risk_level": risk_level,
            "rule_score": rule_score, "ml_confidence": confidence,
            "action": "blocked", "outcome": "high_risk_on_resend"
        })
        # Clear OTP and session state
        otp_store = load_json(OTP_FILE, {})
        otp_store.pop(username, None)
        save_json(OTP_FILE, otp_store)
        return render_template("blocked.html", remaining=BLOCK_DURATION, username=username)

    # ── medium risk → delay ──
    if risk_level == "medium":
        time.sleep(3)

    append_log({
        **features, "username": username, "device_id": session.get("device_id"),
        "ip": request.remote_addr, "risk_level": risk_level,
        "rule_score": rule_score, "ml_confidence": confidence,
        "action": "otp_resent", "outcome": f"resend_{resend_count}_of_2"
    })

    flash(f"A new OTP has been generated! (Resend {resend_count}/2)", "success")
    return redirect(url_for("otp_page"))


@app.route("/success")
def success():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("success.html",
        username=session.get("username"),
        risk_level=session.get("risk_level", "low"),
        rule_score=session.get("rule_score", 0),
        confidence=session.get("confidence", 0),
        auth_method=session.get("auth_method", "password_and_otp"),
        features=session.get("features", {}))


@app.route("/logs")
def logs():
    all_logs = load_json(LOG_FILE, [])
    all_logs.reverse()   # newest first
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    total_pages = (len(all_logs) + per_page - 1) // per_page
    if total_pages == 0:
        total_pages = 1
    if page < 1:
        page = 1
    elif page > total_pages:
        page = total_pages
        
    start = (page - 1) * per_page
    end = start + per_page
    paginated_logs = all_logs[start:end]
    
    # Passing total logs for the summary cards
    return render_template("logs.html", logs=paginated_logs, all_logs=all_logs, page=page, total_pages=total_pages)


@app.route("/clear-logs", methods=["POST"])
def clear_logs():
    save_json(LOG_FILE, [])
    flash("Logs cleared.", "info")
    return redirect(url_for("logs"))


@app.route("/logout")
def logout():
    session.clear()
    login_tracker.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # Pre-train ML model on startup
    from ml_engine import load_model
    load_model()
    print("[App] Starting SecureAuth demo server...")
    app.run(debug=True, port=5000)
