"""
Detector — FINAL VERSION (Compatible with your clean victim.py)
---------------------------------------------------------------
- Receives telemetry from victim.py (/api/ingest)
- Detects HTTP flood, connection flood, botnet attack
- Tracks active IPs (sliding window)
- Supports mitigation → blacklists malicious IPs
- Sends block command back to victim at /api/block_ip
- Exposes stats for the dashboard
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging
import requests
import numpy as np
import time
from datetime import datetime
from collections import deque, defaultdict
import threading

# -----------------------------
# Initialize
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")
log = logging.getLogger("detector")

app = Flask(__name__, template_folder="templates")
CORS(app)

# -----------------------------
# Configuration
# -----------------------------
VICTIM_BLOCK_URL = "http://localhost:8000/api/block_ip"
ACTIVE_IP_WINDOW_SEC = 10
MAX_HISTORY = 200

# -----------------------------
# State
# -----------------------------
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

# active IP window
_active_ip_events = deque()
_active_lock = threading.Lock()

# local blacklist (detector-side)
_blacklisted = {}
_blacklist_lock = threading.Lock()


# -----------------------------
# Helpers
# -----------------------------
def to_number(v):
    if isinstance(v, (np.float32, np.float64)):
        return float(v)
    if isinstance(v, (np.int32, np.int64)):
        return int(v)
    return v

def safe(d, key, default=0.0):
    try:
        return float(d.get(key, default))
    except:
        return float(default)

def record_active_ips(ips):
    ts = time.time()
    with _active_lock:
        _active_ip_events.append((ts, ips))
        # remove old
        cutoff = ts - ACTIVE_IP_WINDOW_SEC
        while _active_ip_events and _active_ip_events[0][0] < cutoff:
            _active_ip_events.popleft()

def get_active_ips():
    cutoff = time.time() - ACTIVE_IP_WINDOW_SEC
    counts = defaultdict(int)

    with _active_lock:
        events = list(_active_ip_events)

    for ts, iplist in events:
        if ts < cutoff:
            continue
        for ip in iplist:
            counts[ip] += 1

    # sort by frequency
    return sorted(counts.items(), key=lambda x: -x[1])


# -----------------------------
# Detection Logic (RAW PPS from victim.py)
# -----------------------------
def detect_attack(f):
    """
    RAW thresholds based on clean victim.py metrics.
    Returns: (is_attack, confidence, type, malicious_ips)
    """
    pps = safe(f, "packets_per_sec")
    uniq = int(safe(f, "unique_src_ips"))
    ent = safe(f, "src_ip_entropy")
    bps = safe(f, "bytes_per_sec")
    conr = safe(f, "connection_rate")
    ips = list(f.get("source_ips") or [])

    # --- HTTP Flood ---
    if pps > 40:
        conf = min(99.9, 40 + pps * 1.1)
        return True, conf, "HTTP Flood", ips

    # --- Botnet Multi-IP Flood ---
    if uniq >= 5 or ent > 1.0:
        conf = min(99.9, 50 + uniq * 8 + ent * 12)
        return True, conf, "Botnet Flood", ips

    # --- Bandwidth Flood ---
    if bps > 80_000:  # 80 KB/s
        conf = min(99.9, 30 + bps / 2000)
        return True, conf, "Bandwidth Flood", ips

    # --- Connection Flood ---
    if conr > 40:
        conf = min(99.9, 35 + conr * 1.2)
        return True, conf, "Connection Flood", ips

    return False, 0.0, "Normal", []


# -----------------------------
# Ingest Telemetry
# -----------------------------
@app.route("/api/ingest", methods=["POST"])
def ingest():
    try:
        data = request.get_json(force=True) or {}
        data = {k: to_number(v) for k, v in data.items()}

        pps = data.get("packets_per_sec", 0)
        uniq = data.get("unique_src_ips", 0)
        ips = data.get("source_ips", [])

        log.info(f"[INGEST] PPS={pps} UNIQ={uniq} IPs={ips}")

        # add active IP sightings
        if ips:
            record_active_ips(ips)

        # run detection
        is_attack, conf, atk_type, bad_ips = detect_attack(data)

        # update current stats
        current_stats.update({
            "packets_per_sec": pps,
            "bytes_per_sec": data.get("bytes_per_sec", 0),
            "unique_src_ips": uniq,
            "src_ip_entropy": data.get("src_ip_entropy", 0),
            "status": atk_type,
            "confidence": conf,
            "malicious_ips": bad_ips
        })

        # update history
        detection_history.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "is_attack": is_attack,
            "type": atk_type,
            "confidence": f"{conf:.1f}%",
            "packets_per_sec": int(pps),
            "ips": bad_ips
        })

        traffic_history.append(float(pps))

        if is_attack:
            current_stats["alerts"] += 1
            attack_log.append(detection_history[-1])
            log.warning(f"[DETECT] {atk_type} | {conf:.1f}% | IPs={bad_ips}")

        return jsonify({
            "detected": is_attack,
            "attack_type": atk_type,
            "confidence": f"{conf:.1f}%",
            "malicious_ips": bad_ips
        })

    except Exception as e:
        log.exception("error ingesting telemetry")
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Stats for Dashboard
# -----------------------------
@app.route("/api/stats")
def stats():
    active = [{"ip": ip, "count": cnt} for ip, cnt in get_active_ips()]

    with _blacklist_lock:
        blk = [{"ip": ip, "since": info["since"], "reason": info["reason"]} for ip, info in _blacklisted.items()]

    return jsonify({
        "current": current_stats,
        "traffic_history": list(traffic_history),
        "detection_history": list(detection_history),
        "attack_log": list(attack_log),
        "active_ips": active,
        "blacklisted_ips": blk
    })


# -----------------------------
# Reset System
# -----------------------------
@app.route("/api/reset", methods=["POST"])
def reset():
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

    with _blacklist_lock:
        _blacklisted.clear()

    log.info("[RESET] System reset")
    return jsonify({"reset": True})


# -----------------------------
# Mitigation → block at victim
# -----------------------------
@app.route("/api/trigger_mitigation", methods=["POST"])
def trigger_mitigation():
    try:
        data = request.get_json(force=True) or {}
        action = data.get("action", "").lower()

        if action == "mitigate":
            # take currently malicious ips
            bad_ips = list(current_stats.get("malicious_ips") or [])
            added = []

            with _blacklist_lock:
                for ip in bad_ips:
                    if ip not in _blacklisted:
                        _blacklisted[ip] = {
                            "since": datetime.utcnow().isoformat() + "Z",
                            "reason": "auto-block"
                        }
                        added.append(ip)

            # inform victim to block
            for ip in added:
                try:
                    requests.post(VICTIM_BLOCK_URL, json={"ip": ip}, timeout=2)
                    log.warning(f"[MITIGATE] Victim blocked {ip}")
                except:
                    log.error(f"[MITIGATE] Failed to contact victim for {ip}")

            return jsonify({"ok": True, "blocked": added})

        elif action == "clear_blacklist":
            with _blacklist_lock:
                _blacklisted.clear()
            return jsonify({"ok": True})

        else:
            return jsonify({"ok": False, "error": "unknown action"}), 400

    except Exception as e:
        log.exception("mitigation failed")
        return jsonify({"ok": False, "error": str(e)})


# -----------------------------
# Startup
# -----------------------------
if __name__ == "__main__":
    log.info("[START] Detector listening on :5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
