from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging
import requests
import numpy as np
import time
from datetime import datetime
from collections import deque, defaultdict
import threading
import json

# -----------------------------
# EmailJS Configuration
# -----------------------------
EMAILJS_SERVICE_ID = "service_wawooy6"
EMAILJS_TEMPLATE_ID = "template_4cvg4tr"
EMAILJS_PUBLIC_KEY = "1Uk51k97xnllFFRr5"
EMAILJS_PRIVATE_KEY = "CMLaeyW5Xkh15xSEbgBEq"
EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send"
ADMIN_EMAIL = "gauhith.1si22ad016@gmail.com"

# -----------------------------
# Victim Firewall Endpoint
# -----------------------------
VICTIM_BLOCK_URL = "http://localhost:8000/api/block_ip"

# -----------------------------
# Logging Setup
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")
log = logging.getLogger("detector")

app = Flask(__name__, template_folder="templates")
CORS(app)

# -----------------------------
# Runtime State
# -----------------------------
ACTIVE_IP_WINDOW_SEC = 10
MAX_HISTORY = 200

traffic_history = deque(maxlen=MAX_HISTORY)
detection_history = deque(maxlen=MAX_HISTORY)
attack_log = []

current_stats = {
    "packets_per_sec": 0,
    "bytes_per_sec": 0,
    "unique_src_ips": 0,
    "src_ip_entropy": 0,
    "status": "Normal",
    "confidence": 0,
    "alerts": 0,
    "malicious_ips": []
}

_active_ip_events = deque()
_active_lock = threading.Lock()

_blacklisted = {}
_blacklist_lock = threading.Lock()

# -----------------------------
# Helper Functions
# -----------------------------
def send_attack_email(attack_type, confidence, ips, timestamp):
    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_PUBLIC_KEY,
        "accessToken": EMAILJS_PRIVATE_KEY,
        "template_params": {
            "admin_email": ADMIN_EMAIL,
            "attack_type": attack_type,
            "confidence": f"{confidence:.1f}%",
            "malicious_ips": ", ".join(ips) if ips else "Unknown",
            "timestamp": timestamp
        }
    }

    try:
        response = requests.post(EMAILJS_URL, json=payload, timeout=5)
        print("[EMAIL RAW]:", response.status_code, response.text)
    except Exception as e:
        print("[EMAIL ERROR]", e)


def to_number(v):
    if isinstance(v, (np.float32, np.float64)): return float(v)
    if isinstance(v, (np.int32, np.int64)): return int(v)
    return v

def safe(data, key, default=0.0):
    try: return float(data.get(key, default))
    except: return float(default)

# -----------------------------
# Mitigation Function
# -----------------------------
def block_ip(ip):
    try:
        with _blacklist_lock:
            if ip in _blacklisted:
                return False

            response = requests.post(VICTIM_BLOCK_URL, json={"ip": ip}, timeout=5)

            if response.status_code == 200:
                _blacklisted[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.warning(f"[MITIGATION] Blocked IP: {ip}")
                return True

            log.error(f"[MITIGATION ERROR] Victim refused block: {response.text}")
            return False
    except Exception as e:
        log.error(f"[MITIGATION ERROR] Failed blocking {ip} -> {str(e)}")
        return False


def auto_mitigate(ips):
    for ip in ips:
        block_ip(ip)

# -----------------------------
# Detection Logic
# -----------------------------
def detect_attack(f):
    pps = safe(f, "packets_per_sec")
    uniq = int(safe(f, "unique_src_ips"))
    ent = safe(f, "src_ip_entropy")
    bps = safe(f, "bytes_per_sec")
    conr = safe(f, "connection_rate")
    ips = list(f.get("source_ips") or [])

    if pps > 40:
        return True, min(99.9, 40 + pps * 1.1), "HTTP Flood", ips

    if uniq >= 5 or ent > 1.0:
        return True, min(99.9, 50 + uniq * 8 + ent * 12), "Botnet Flood", ips

    if bps > 80000:
        return True, min(99.9, 30 + bps / 2000), "Bandwidth Flood", ips

    if conr > 40:
        return True, min(99.9, 35 + conr * 1.2), "Connection Flood", ips

    return False, 0.0, "Normal", []


# -----------------------------
# API: Telemetry Ingest
# -----------------------------
@app.route("/api/ingest", methods=["POST"])
def ingest():
    try:
        data = request.get_json(force=True) or {}
        data = {k: to_number(v) for k, v in data.items()}

        is_attack, conf, atk_type, bad_ips = detect_attack(data)

        current_stats.update({
            "packets_per_sec": data.get("packets_per_sec", 0),
            "bytes_per_sec": data.get("bytes_per_sec", 0),
            "unique_src_ips": data.get("unique_src_ips", 0),
            "src_ip_entropy": data.get("src_ip_entropy", 0),
            "status": atk_type,
            "confidence": conf,
            "malicious_ips": bad_ips
        })

        detection_history.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "is_attack": is_attack,
            "type": atk_type,
            "confidence": f"{conf:.1f}%",
            "packets_per_sec": int(data.get("packets_per_sec", 0)),
            "ips": bad_ips
        })

        traffic_history.append(float(data.get("packets_per_sec", 0)))

        if is_attack:
            attack_log.append(detection_history[-1])
            current_stats["alerts"] += 1

            log.warning(f"[DETECT] {atk_type} | {conf:.1f}% | IPs={bad_ips}")

            send_attack_email(atk_type, conf, bad_ips, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # AUTO MITIGATION HERE
            auto_mitigate(bad_ips)

        return jsonify({"detected": is_attack, "attack_type": atk_type, "confidence": conf, "malicious_ips": bad_ips})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Manual Mitigation Endpoint
# -----------------------------
@app.route("/api/mitigate", methods=["POST"])
def trigger_mitigation():
    ips = current_stats.get("malicious_ips", [])

    if not ips:
        return jsonify({"ok": False, "message": "No malicious IPs detected."}), 400

    blocked = []
    already = []

    for ip in ips:
        if ip in _blacklisted:
            already.append(ip)
        elif block_ip(ip):
            blocked.append(ip)

    return jsonify({
        "ok": True,
        "blocked": blocked,
        "already_blocked": already,
        "total_blacklisted": list(_blacklisted.keys())
    })


# -----------------------------
# Stats Endpoint
# -----------------------------
@app.route("/api/stats")
def stats():
    return jsonify({
        "current": current_stats,
        "traffic_history": list(traffic_history),
        "detection_history": list(detection_history),
        "attack_log": list(attack_log),
        "blacklisted_ips": [{"ip": ip, "blocked_at": ts} for ip, ts in _blacklisted.items()]
    })


# -----------------------------
# Reset
# -----------------------------
@app.route("/api/reset", methods=["POST"])
def reset_system():
    traffic_history.clear()
    detection_history.clear()
    attack_log.clear()
    _blacklisted.clear()

    current_stats.update({
        "packets_per_sec": 0,
        "bytes_per_sec": 0,
        "unique_src_ips": 0,
        "src_ip_entropy": 0,
        "status": "Normal",
        "confidence": 0,
        "alerts": 0,
        "malicious_ips": []
    })

    log.info("[RESET] System reset")
    return jsonify({"reset": True})


@app.route("/")
def index():
    return render_template("dashboard.html")


if __name__ == "__main__":
    log.info("[START] Detector Running on :5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
