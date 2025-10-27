# Packet sniffing will be implemented here
#!/usr/bin/env python3
"""
PINSS Phase 1: Packet Capture Layer
Captures live packets and stores protocol features for later analysis.
"""

import os
import time
import csv
import pandas as pd
from scapy.all import sniff, ARP, IP, TCP, UDP, DNS, BOOTP, DHCP, Ether

# === CONFIG ===
SAVE_EVERY = 50
OUT_CSV = os.path.join(os.path.dirname(__file__), "../data/raw_packets/captured_packets.csv")
cols = [
    "ts", "pkt_no", "eth_src", "eth_dst", "eth_type",
    "ip_src", "ip_dst", "ip_proto",
    "tcp_flags", "tcp_sport", "tcp_dport",
    "udp_len", "udp_sport", "udp_dport",
    "arp_op", "arp_psrc", "arp_pdst", "arp_hwsrc", "arp_hwdst",
    "dhcp_msgtype", "dhcp_server_id", "dhcp_yiaddr",
    "dns_qname", "dns_qtype", "dns_ans"
]

# === Helpers ===
pkt_counter = 0
buffer = []

if not os.path.exists(OUT_CSV):
    with open(OUT_CSV, "w", newline="") as f:
        csv.writer(f).writerow(cols)


def extract_features(pkt):
    """Extract relevant features from each packet."""
    global pkt_counter
    pkt_counter += 1
    ts = time.time()
    row = dict.fromkeys(cols, None)
    row["ts"] = ts
    row["pkt_no"] = pkt_counter

    # Ethernet
    if pkt.haslayer(Ether):
        row["eth_src"] = pkt[Ether].src
        row["eth_dst"] = pkt[Ether].dst
        row["eth_type"] = hex(pkt[Ether].type)

    # ARP
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        row.update({
            "arp_op": a.op,
            "arp_psrc": a.psrc,
            "arp_pdst": a.pdst,
            "arp_hwsrc": a.hwsrc,
            "arp_hwdst": a.hwdst
        })

    # IP
    if pkt.haslayer(IP):
        i = pkt[IP]
        row.update({
            "ip_src": i.src,
            "ip_dst": i.dst,
            "ip_proto": i.proto
        })
        # TCP
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            row.update({
                "tcp_flags": str(t.flags),
                "tcp_sport": t.sport,
                "tcp_dport": t.dport
            })
        # UDP
        if pkt.haslayer(UDP):
            u = pkt[UDP]
            row.update({
                "udp_len": len(u),
                "udp_sport": u.sport,
                "udp_dport": u.dport
            })

    # DHCP
    if pkt.haslayer(BOOTP):
        b = pkt[BOOTP]
        row["dhcp_yiaddr"] = getattr(b, "yiaddr", None)
        if pkt.haslayer(DHCP):
            try:
                for k, v in pkt[DHCP].options:
                    if k == "message-type":
                        row["dhcp_msgtype"] = int(v)
                    elif k == "server_id":
                        row["dhcp_server_id"] = v
            except Exception:
                pass

    # DNS
    if pkt.haslayer(DNS):
        d = pkt[DNS]
        try:
            if d.qdcount > 0 and d.qd:
                qname = d.qd.qname.decode() if isinstance(d.qd.qname, bytes) else d.qd.qname
                row["dns_qname"] = qname
                row["dns_qtype"] = d.qd.qtype
            if d.ancount > 0 and d.an:
                row["dns_ans"] = getattr(d.an, "rdata", None)
        except Exception:
            pass

    return [row.get(c) for c in cols]


def flush_to_csv(buf):
    with open(OUT_CSV, "a", newline="") as f:
        csv.writer(f).writerows(buf)


def pkt_callback(pkt):
    global buffer
    try:
        buffer.append(extract_features(pkt))
        if len(buffer) % 5 == 0:
            df = pd.DataFrame(buffer[-3:], columns=cols)
            print(df[["ts", "ip_src", "ip_dst", "arp_op", "dhcp_msgtype", "dns_qname"]].to_string(index=False))
        if len(buffer) >= SAVE_EVERY:
            flush_to_csv(buffer)
            print(f"[+] Saved {len(buffer)} rows to {OUT_CSV}")
            buffer = []
    except Exception as e:
        print("Error:", e)


def main():
    print("[PINSS] Phase 1: Starting live capture (CTRL+C to stop)...")
    try:
        sniff(prn=pkt_callback, store=False)
    except KeyboardInterrupt:
        print("\nStopping capture...")
        if buffer:
            flush_to_csv(buffer)
            print(f"[+] Saved remaining {len(buffer)} packets.")
        print("[PINSS] Capture complete.")


if __name__ == "__main__":
    main()
