"""
victim.py — CLEAN + REAL BLOCKING
---------------------------------
Counts ALL requests
Sends telemetry to detector
Supports REAL IP blocking via /api/block_ip from detector
"""

from flask import Flask, request, send_from_directory, jsonify
from collections import defaultdict, deque
import threading
import time
import requests
import math
import os
import logging

# ---------- CONFIG ----------
DETECTOR_URL = "http://localhost:5000/api/ingest"
AGG_INTERVAL = 1.0
MAX_HISTORY = 5000

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8000
# ----------------------------

app = Flask(__name__)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [VICTIM] %(message)s")

# Thread-safe counters
lock = threading.Lock()
packet_sizes = deque(maxlen=MAX_HISTORY)
src_ip_counts = defaultdict(int)

# ⚠️ REAL BLOCKLIST
blocked_ips = set()
blocked_lock = threading.Lock()


# --------------------------------------------------------
#  BLOCKING ENDPOINT (CALLED BY DETECTOR)
# --------------------------------------------------------
@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json(force=True)
    ip = data.get("ip")

    if not ip:
        return jsonify({"ok": False, "error": "no ip"}), 400

    with blocked_lock:
        blocked_ips.add(ip)

    logging.warning(f"[BLOCK] Now blocking IP: {ip}")

    return jsonify({"ok": True, "blocked": ip})


# --------------------------------------------------------
#  HELPER FUNCTIONS
# --------------------------------------------------------
def calc_entropy(counts):
    total = sum(counts.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for v in counts.values():
        p = v / total
        ent -= p * math.log(p, 2)
    return ent


def snapshot_and_reset():
    with lock:
        packets = len(packet_sizes)
        bytes_sum = sum(packet_sizes)
        ip_copy = dict(src_ip_counts)

        packet_sizes.clear()
        src_ip_counts.clear()

    return packets, bytes_sum, ip_copy


# --------------------------------------------------------
#  AGGREGATOR THREAD
# --------------------------------------------------------
def aggregator():
    while True:
        time.sleep(AGG_INTERVAL)

        packets, bytes_sum, src_ips = snapshot_and_reset()

        pps = packets / AGG_INTERVAL
        bps = bytes_sum / AGG_INTERVAL
        uniq = len(src_ips)
        ent = calc_entropy(src_ips)

        logging.info(f"[AGG] PPS={pps:.1f} BPS={bps:.1f} UNIQ={uniq} ENTROPY={ent:.2f}")

        telemetry = {
            "packets_per_sec": pps,
            "bytes_per_sec": bps,
            "unique_src_ips": uniq,
            "src_ip_entropy": ent,
            "source_ips": list(src_ips.keys()),
            "avg_packet_size": (bytes_sum / packets) if packets else 0.0,
            "connection_rate": pps
        }

        try:
            requests.post(DETECTOR_URL, json=telemetry, timeout=2)
        except Exception as e:
            logging.warning(f"[AGG] Failed to send telemetry: {e}")


threading.Thread(target=aggregator, daemon=True).start()


# --------------------------------------------------------
#  MAIN TRAFFIC HANDLER
# --------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "HEAD", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "HEAD", "OPTIONS"])
def count_all(path):

    remote_ip = request.remote_addr or "unknown"

    # ============================
    # REAL BLOCKING HERE
    # ============================
    with blocked_lock:
        if remote_ip in blocked_ips:
            logging.warning(f"[BLOCKED REQUEST] {remote_ip} attempted access")
            return ("FORBIDDEN — IP BLOCKED BY MITIGATION", 403)

    try:
        size = int(request.headers.get("Content-Length") or 0)
    except:
        size = 0

    # count traffic
    with lock:
        packet_sizes.append(size)
        src_ip_counts[remote_ip] += 1

    # serve simple homepage
    if request.method == "GET" and path == "":
        if not os.path.exists("victim.html"):
            with open("victim.html", "w") as f:
                f.write("<h1>Victim Server</h1>")
        return send_from_directory(".", "victim.html")

    return ("OK", 200)


# --------------------------------------------------------
#  START SERVER
# --------------------------------------------------------
if __name__ == "__main__":
    logging.info(f"[START] Victim listening on http://{LISTEN_HOST}:{LISTEN_PORT}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)
