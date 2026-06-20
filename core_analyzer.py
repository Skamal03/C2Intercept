import os
import pickle
import numpy as np
from collections import defaultdict
from sklearn.ensemble import RandomForestClassifier

FEATURE_COLUMNS = [
    "outbound_variance",
    "inbound_variance",
    "pkt_count",
    "byte_count",
    "avg_pkt_size",
    "duration"
]

# Ports too common to flag — includes RDP, MySQL, WinRM now
WHITELIST_PORTS = {'80', '443', '53', '123', '67', '68', '3389', '3306', '5985', '5986'}

# Known bad ports — always suspicious context
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9001, 6666, 1234}


class C2Detector:
    def __init__(self):
        self.model_path  = "models/c2_random_forest.pkl"
        self.model       = None
        self.tshark_path = r"C:\Users\ROARSCHACH\Downloads\Installs\Wireshark\tshark.exe"
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                print("[+] Model loaded from disk.")
            except Exception as e:
                print(f"[-] Model load failed: {e}. Training fallback.")
                self._train_fallback_model()
        else:
            print("[!] No model file found. Training fallback.")
            self._train_fallback_model()

    def _train_fallback_model(self):
        X = np.array([
            [0.000001, 0.000002, 120, 7200,   60.0, 300.0],
            [0.000100, 0.000050, 100, 4000,   40.0, 360.0],
            [0.004000, 0.002000,  90, 5400,   60.0, 270.0],
            [0.000500, 99.00000, 150, 90000, 600.0, 300.0],
            [0.000020, 0.000010, 200, 6000,   30.0, 600.0],
            [0.001000, 0.000500,  80, 3200,   40.0,  60.0],
            [5.500000,  8.200000, 200, 280000, 1400.0,  45.0],
            [9.230000,  6.100000, 180, 252000, 1400.0,  30.0],
            [12.45000, 15.30000,  500, 700000, 1400.0, 120.0],
            [1.800000,  2.900000, 400, 560000, 1400.0,  20.0],
            [0.050000,  0.080000,  10,    600,   60.0,   2.0],
            [99.00000, 99.00000,   30, 600000, 20000.0, 900.0],
        ])
        y = np.array([1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0])

        self.model = RandomForestClassifier(
            n_estimators=200, max_depth=8, min_samples_leaf=2,
            class_weight="balanced", random_state=42
        )
        self.model.fit(X, y)

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)
        print("[+] Fallback model trained and saved.")

    def group_into_flows(self, packet_buffer):
        flows = defaultdict(list)
        for pkt in packet_buffer:
            key = (pkt['src'], pkt['dst'], pkt['dport'])
            flows[key].append(pkt)
        return flows

    def extract_flow_features(self, flow_packets):
        if len(flow_packets) < 5:
            return None, None

        src_ips    = [p['src'] for p in flow_packets]
        local_host = max(set(src_ips), key=src_ips.count)

        outbound_times = sorted(p['time'] for p in flow_packets if p['src'] == local_host)
        inbound_times  = sorted(p['time'] for p in flow_packets if p['src'] != local_host)

        outbound_variance = float(np.var(np.diff(outbound_times))) if len(outbound_times) > 2 else 99.0
        inbound_variance  = float(np.var(np.diff(inbound_times)))  if len(inbound_times)  > 2 else 99.0

        all_times  = [p['time'] for p in flow_packets]
        pkt_count  = len(flow_packets)
        byte_count = sum(p['size'] for p in flow_packets)
        avg_size   = byte_count / pkt_count if pkt_count > 0 else 0.0
        duration   = max(all_times) - min(all_times) if len(all_times) > 1 else 0.0

        features = [outbound_variance, inbound_variance,
                    float(pkt_count), float(byte_count), avg_size, duration]

        metadata = {
            'src':   flow_packets[0]['src'],
            'dst':   flow_packets[0]['dst'],
            'sport': flow_packets[0]['sport'],
            'dport': flow_packets[0]['dport'],
        }
        return features, metadata

    def predict_flow(self, features, metadata):
        if self.model is None:
            return None

        src_port     = str(metadata['sport'])
        dst_port     = str(metadata['dport'])
        dst_port_int = int(metadata['dport'])
        src_port_int = int(metadata['sport'])

        pkt_count  = features[2]
        byte_count = features[3]
        duration   = features[5]

        # ── Gate 1: minimum flow size — anything smaller is just a
        #   normal handshake or a single request, not beaconing
        if pkt_count < 20 or duration < 10.0:
            return None

        # ── Gate 2: skip if both ports are whitelisted AND it looks
        #   like normal browsing (high bytes or very short session)
        both_ports_common = (src_port in WHITELIST_PORTS and dst_port in WHITELIST_PORTS)
        looks_like_browse = (byte_count > 50000 or duration < 5.0)
        if both_ports_common and looks_like_browse:
            return None

        # ── ML prediction ─────────────────────────────────────────────
        feat_arr      = np.array([features])
        prediction    = self.model.predict(feat_arr)[0]
        probabilities = self.model.predict_proba(feat_arr)[0]
        confidence_raw = probabilities[1]

        # ── Heuristics — only targeted, not broad ─────────────────────
        uses_bad_port = (dst_port_int in SUSPICIOUS_PORTS or src_port_int in SUSPICIOUS_PORTS)

        port_not_standard = (src_port not in WHITELIST_PORTS and dst_port not in WHITELIST_PORTS)
        # Tightened from 0.005 to 0.001 — only truly robotic timing
        beaconing_rhythm  = (features[0] <= 0.001) and port_not_standard

        heartbeat_pattern = (
            features[4] < 100.0 and
            pkt_count > 50 and
            duration > 30.0
        )

        is_heuristic_hit = uses_bad_port or beaconing_rhythm or heartbeat_pattern

        # ── Decision ──────────────────────────────────────────────────
        if prediction == 1 or is_heuristic_hit:
            if is_heuristic_hit:
                final_confidence = max(confidence_raw, 0.75)
            else:
                final_confidence = confidence_raw

            if uses_bad_port:
                reason = f"Traffic on known C2 port ({dst_port_int if dst_port_int in SUSPICIOUS_PORTS else src_port_int}). High-risk channel."
            elif beaconing_rhythm:
                reason = (
                    f"Outbound inter-packet variance ({features[0]:.6f}) indicates robotic "
                    f"periodic scheduling on non-standard ports {src_port}/{dst_port}."
                )
            elif heartbeat_pattern:
                reason = (
                    f"Heartbeat pattern — {int(pkt_count)} packets, avg size {features[4]:.1f}B "
                    f"over {duration:.1f}s. Consistent with C2 keep-alive."
                )
            else:
                reason = (
                    f"ML classifier flagged flow [{features[0]:.5f} out-var, "
                    f"{int(pkt_count)} pkts, {int(byte_count)}B, {duration:.1f}s]."
                )

            return {
                'src':        metadata['src'],
                'dst':        metadata['dst'],
                'sport':      metadata['sport'],
                'dport':      metadata['dport'],
                'confidence': f"{final_confidence * 100:.2f}%",
                'reason':     reason,
                'pkt_count':  int(pkt_count),
                'byte_count': int(byte_count),
            }

        return None

    def analyze_buffer(self, packet_buffer):
        alerts = []
        flows = self.group_into_flows(packet_buffer)
        seen_pairs = set()  # track (a, b) so we don't alert both directions

        for flow_key, flow_pkts in flows.items():
            src, dst, dport = flow_key

            # Skip if we already alerted the reverse direction
            reverse = (dst, src)
            if (dst, src) in seen_pairs or (src, dst) in seen_pairs:
                continue

            features, metadata = self.extract_flow_features(flow_pkts)
            if features is None:
                continue

            result = self.predict_flow(features, metadata)
            if result:
                seen_pairs.add((src, dst))
                alerts.append(result)

        return alerts