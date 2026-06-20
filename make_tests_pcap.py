from scapy.all import IP, TCP, Raw, wrpcap
import time
import random
import os

print("[*] Generating test PCAPs...")

# ── CLEAN TRAFFIC — variable sizes, human timing ──────────────────────────────
clean_packets = []
current_time  = time.time()
client = "192.168.1.50"
server = "142.250.190.46"

for _ in range(60):
    current_time += random.uniform(0.5, 8.5)
    # Variable payload sizes like real HTTPS
    payload_size = random.randint(200, 1400)
    pkt_out = IP(src=client, dst=server) / TCP(sport=51234, dport=443) / Raw(b"X" * payload_size)
    pkt_out.time = current_time
    clean_packets.append(pkt_out)

    current_time += random.uniform(0.01, 0.15)
    resp_size = random.randint(500, 1400)
    pkt_in = IP(src=server, dst=client) / TCP(sport=443, dport=51234) / Raw(b"X" * resp_size)
    pkt_in.time = current_time
    clean_packets.append(pkt_in)

wrpcap("sample_clean_traffic.pcap", clean_packets)
print(f"[+] Clean PCAP: {len(clean_packets)} packets, "
      f"duration {clean_packets[-1].time - clean_packets[0].time:.1f}s")

# ── C2 BEACONING — rigid timing, port 4444, small packets ────────────────────
c2_packets   = []
current_time = time.time()
attacker     = "185.220.101.5"
victim       = "192.168.1.99"

for i in range(80):
    current_time += 30.0 + random.uniform(-0.05, 0.05)
    # Small fixed-size keep-alive typical of RAT beaconing
    pkt_out = IP(src=victim, dst=attacker) / TCP(sport=49152, dport=4444) / Raw(b"X" * 60)
    pkt_out.time = current_time
    c2_packets.append(pkt_out)

    current_time += random.uniform(0.005, 0.020)
    pkt_in = IP(src=attacker, dst=victim) / TCP(sport=4444, dport=49152) / Raw(b"X" * 60)
    pkt_in.time = current_time
    c2_packets.append(pkt_in)

wrpcap("sample_c2_malware.pcap", c2_packets)
print(f"[+] C2 PCAP: {len(c2_packets)} packets, "
      f"duration {c2_packets[-1].time - c2_packets[0].time:.1f}s")
print(f"[*] Files saved to: {os.getcwd()}")