"""
Phase 3 (refined for Phase 7): Rule-Based Detection (returns alerts, no direct mitigation)
Each detect_... function returns either None or an alert dict:
{
  "threat": "<type>",
  "message": "<human message>",
  "ips": [list of ip strings]   # optional
}
"""

import pandas as pd
import os
from collections import defaultdict

PROCESSED_PATH = os.path.join(os.path.dirname(__file__), "../data/processed/processed_features.csv")

def detect_rogue_dhcp(df):
    dhcp_servers = df[df["dhcp_server_id"] != "None"]["dhcp_server_id"].unique()
    if len(dhcp_servers) > 1:
        return {
            "threat": "rogue_dhcp",
            "message": f"Rogue DHCP detected. DHCP servers: {list(dhcp_servers)}",
            "ips": list(dhcp_servers)
        }
    return None

def detect_arp_spoof(df):
    ip_mac_map = defaultdict(set)
    for _, row in df[df["arp_psrc"] != "None"].iterrows():
        ip_mac_map[row["arp_psrc"]].add(row["arp_hwsrc"])

    attackers = [ip for ip, macs in ip_mac_map.items() if len(macs) > 1]
    if attackers:
        return {
            "threat": "arp_spoof",
            "message": f"ARP spoofing suspected for IPs: {attackers}",
            "ips": attackers
        }
    return None

def detect_dns_spoof(df):
    dns_map = defaultdict(set)
    for _, row in df[df["dns_qname"] != "None"].iterrows():
        dns_map[row["dns_qname"]].add(row["dns_ans"])

    suspicious = {q: ips for q, ips in dns_map.items() if len(ips) > 1 and "None" not in ips}
    if suspicious:
        for q, ips in suspicious.items():
            return {
                "threat": "dns_spoof",
                "message": f"DNS spoofing suspected for domain {q}, IPs: {list(ips)}",
                "domain": q,
                "ips": list(ips)
            }
    return None

def detect_syn_flood(df, threshold=50):
    if "tcp_syn" not in df.columns:
        return None
    syn_counts = df[df["tcp_syn"] == 1]["ip_src"].value_counts()
    offenders = syn_counts[syn_counts > threshold].index.tolist()
    if offenders:
        return {
            "threat": "syn_flood",
            "message": f"Possible SYN flood from IPs: {offenders}",
            "ips": offenders
        }
    return None

def run_all_detectors(df, syn_threshold=50):
    """
    Run all detectors on provided DataFrame.
    Returns a list of alert dicts (may be empty).
    """
    alerts = []
    for fn in (detect_rogue_dhcp, detect_arp_spoof, detect_dns_spoof, lambda d: detect_syn_flood(d, syn_threshold)):
        try:
            a = fn(df)
            if a:
                alerts.append(a)
        except Exception:
            continue
    return alerts
