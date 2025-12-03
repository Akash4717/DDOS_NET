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
# EmailJS Configuration (YOUR VALUES)
# -----------------------------
EMAILJS_SERVICE_ID = "service_99rn43g"
EMAILJS_TEMPLATE_ID = "template_4atsdzr"
EMAILJS_PUBLIC_KEY = "1HCnPuklMltcd3-I_"
EMAILJS_PRIVATE_KEY = "L37XzDr-iJ36dAuyfrTIm"
EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send"
ADMIN_EMAIL = "akash.1si22ad001@gmail.com"


# -----------------------------
# Email Send Function (STRICT MODE FINAL WORKING)
# -----------------------------
def send_attack_email(attack_type, confidence, ips, timestamp):
    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_PUBLIC_KEY,       # MUST be public key
        "accessToken": EMAILJS_PRIVATE_KEY,  # MUST be private key
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


# -----------------------------
# Logging / Flask Setup
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")
log = logging.getLogger("detector")

app = Flask(__name__, template_folder="templates")
CORS(app)

# -----------------------------
# System Runtime State
# -----------------------------
VICTIM_BLOCK_URL = "http://localhost:8000/api/block_ip"
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
def to_number(v):
    if isinstance(v, (np.float32, np.float64)): return float(v)
    if isinstance(v, (np.int32, np.int64)): return int(v)
    return v

def safe(data, key, default=0.0):
    try: return float(data.get(key, default))
    except: return float(default)

def record_active_ips(ips):
    ts = time.time()
    with _active_lock:
        _active_ip_events.append((ts, ips))
        cutoff = ts - ACTIVE_IP_WINDOW_SEC
        while _active_ip_events and _active_ip_events[0][0] < cutoff:
            _active_ip_events.popleft()

def get_active_ips():
    cutoff = time.time() - ACTIVE_IP_WINDOW_SEC
    counts = defaultdict(int)

    with _active_lock:
        for ts, iplist in _active_ip_events:
            if ts >= cutoff:
                for ip in iplist:
                    counts[ip] += 1

    return sorted(counts.items(), key=lambda x: -x[1])


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

        return jsonify({"detected": is_attack, "attack_type": atk_type, "confidence": conf, "malicious_ips": bad_ips})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# API: Manual Test Email Button
# -----------------------------
@app.route("/api/send_alert", methods=["POST"])
def manual_alert():
    send_attack_email("Manual Trigger", 100, ["N/A"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return jsonify({"ok": True, "message": "Email sent"})


# -----------------------------
# API: Stats for Dashboard
# -----------------------------
@app.route("/api/stats")
def stats():
    return jsonify({
        "current": current_stats,
        "traffic_history": list(traffic_history),
        "detection_history": list(detection_history),
        "attack_log": list(attack_log),
        "active_ips": [{"ip": ip, "count": cnt} for ip, cnt in get_active_ips()],
        "blacklisted_ips": []
    })


# -----------------------------
# API: RESET Button
# -----------------------------
@app.route("/api/reset", methods=["POST"])
def reset_system():
    traffic_history.clear()
    detection_history.clear()
    attack_log.clear()

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

    with _active_lock:
        _active_ip_events.clear()

    log.info("[RESET] System reset from dashboard")
    return jsonify({"reset": True})


# -----------------------------
# UI Route
# -----------------------------
@app.route("/")
def index():
    return render_template("dashboard.html")


# -----------------------------
# Run Server
# -----------------------------
if __name__ == "__main__":
    log.info("[START] Detector listening on :5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
