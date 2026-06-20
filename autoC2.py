import socket
import time
import random
import threading

# ── CONFIG ────────────────────────────────────────────────────────────────────
TARGET_IP   = "127.0.0.1"   # loopback — stays on your machine
TARGET_PORT = 4444           # in SUSPICIOUS_PORTS list — will trigger instantly
INTERVAL    = 5.0            # beacon every 5 seconds
JITTER      = 0.05           # tiny jitter — looks robotic
PACKETS     = 60             # enough to clear pkt_count gate

def fake_c2_beacon():
    print(f"[*] Starting fake C2 beacon to {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Sending {PACKETS} beacons every {INTERVAL}s — run app.py and capture on loopback")

    sent = 0
    while sent < PACKETS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((TARGET_IP, TARGET_PORT))
            sock.send(b"BEACON\x00" * 8)   # small fixed payload
            time.sleep(0.01)
            sock.close()
        except Exception:
            pass  # listener might not be up, that's fine — packet still goes out

        sent += 1
        print(f"  [{sent}/{PACKETS}] Beacon sent")
        time.sleep(INTERVAL + random.uniform(-JITTER, JITTER))

    print("[+] Simulation complete.")

# ── Run a listener so connections actually complete ───────────────────────────
def fake_c2_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TARGET_PORT))
    srv.listen(10)
    while True:
        try:
            conn, _ = srv.accept()
            conn.send(b"ACK\x00" * 4)
            conn.close()
        except Exception:
            break

if __name__ == "__main__":
    t = threading.Thread(target=fake_c2_listener, daemon=True)
    t.start()
    time.sleep(0.5)
    fake_c2_beacon()