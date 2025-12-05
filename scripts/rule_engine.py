"""
PINSS Rule Engine (Phase 7 – Stable)
- All threat detectors return alert dictionaries
- Cooldown prevents repeated detections every few seconds
"""

import pandas as pd
import time
from collections import defaultdict
import os

PROCESSED_PATH = os.path.join(os.path.dirname(__file__), "../data/processed/processed_features.csv")

# === Domain Whitelist (for DNS Spoof false-positives) ===
DNS_WHITELIST = [
    "visualstudio.com",
    "microsoft.com",
    "windows.com",
    "office.com",
    "live.com",
    "trafficmanager.net",
    "akadns.net",
    "akamaiedge.net",
    "icloud.com",
    "google.com",
    "gvt1.com",
]

def is_whitelisted(domain):
    """Return True if domain belongs to major safe providers."""
    if not isinstance(domain, str):
        return False
    return any(w in domain.lower() for w in DNS_WHITELIST)

# === GLOBAL threat cooldown tracking ===
DETECTION_COOLDOWN = 10  # seconds

# Cache dictionaries to store last detection timestamp for each threat type
last_detect_arp = {}
last_detect_dns = {}
last_detect_dhcp = {}
last_detect_syn = {}


# -----------------------------------------------------------
# DHCP ROGUE DETECTION
# -----------------------------------------------------------
def detect_rogue_dhcp(df):
    dhcp_servers = df[df["dhcp_server_id"] != "None"]["dhcp_server_id"].unique()

    if len(dhcp_servers) > 1:
        now = time.time()
        key = "rogue_dhcp"

        if key not in last_detect_dhcp or now - last_detect_dhcp[key] > DETECTION_COOLDOWN:
            last_detect_dhcp[key] = now

            return {
                "threat": "rogue_dhcp",
                "message": f"Rogue DHCP detected. DHCP servers: {list(dhcp_servers)}",
                "ips": list(dhcp_servers)
            }

    return None


# -----------------------------------------------------------
# ARP SPOOF DETECTION (with cooldown)
# -----------------------------------------------------------
def detect_arp_spoof(df):
    ip_mac_map = defaultdict(set)

    for _, row in df[df["arp_psrc"] != "None"].iterrows():
        ip_mac_map[row["arp_psrc"]].add(row["arp_hwsrc"])

    attackers = [ip for ip, macs in ip_mac_map.items() if len(macs) > 1]

    if attackers:
        now = time.time()
        new_attackers = []

        for ip in attackers:
            if ip not in last_detect_arp or now - last_detect_arp[ip] > DETECTION_COOLDOWN:
                last_detect_arp[ip] = now
                new_attackers.append(ip)

        if new_attackers:
            return {
                "threat": "arp_spoof",
                "message": f"ARP spoofing suspected for IPs: {new_attackers}",
                "ips": new_attackers
            }

    return None


# -----------------------------------------------------------
# DNS SPOOF DETECTION (with whitelist + cooldown)
# -----------------------------------------------------------
def detect_dns_spoof(df):
    dns_map = defaultdict(set)

    for _, row in df[df["dns_qname"] != "None"].iterrows():

        domain = row["dns_qname"]

        # Skip safe domains
        if is_whitelisted(domain):
            continue

        ans = row["dns_ans"]
        dns_map[domain].add(ans)

    for domain, answers in dns_map.items():
        clean_answers = {a for a in answers if a not in [None, "None", b'', "b''"]}

        if len(clean_answers) > 1:  # SPOOF DETECTED
            now = time.time()

            if domain not in last_detect_dns or now - last_detect_dns[domain] > DETECTION_COOLDOWN:
                last_detect_dns[domain] = now

                return {
                    "threat": "dns_spoof",
                    "message": f"DNS spoofing suspected for domain {domain}, IPs: {list(clean_answers)}",
                    "domain": domain,
                    "ips": list(clean_answers)
                }

    return None


# -----------------------------------------------------------
# SYN FLOOD DETECTION (with cooldown)
# -----------------------------------------------------------
def detect_syn_flood(df, threshold=50):
    if "tcp_syn" not in df.columns:
        return None

    syn_counts = df[df["tcp_syn"] == 1]["ip_src"].value_counts()
    offenders = syn_counts[syn_counts > threshold].index.tolist()

    if offenders:
        now = time.time()
        new_offenders = []

        for ip in offenders:
            if ip not in last_detect_syn or now - last_detect_syn[ip] > DETECTION_COOLDOWN:
                last_detect_syn[ip] = now
                new_offenders.append(ip)

        if new_offenders:
            return {
                "threat": "syn_flood",
                "message": f"Possible SYN flood from IPs: {new_offenders}",
                "ips": new_offenders
            }

    return None


# -----------------------------------------------------------
# MAIN DETECTOR RUNNER
# -----------------------------------------------------------
def run_all_detectors(df, syn_threshold=50):
    alerts = []

    for fn in (
        detect_rogue_dhcp,
        detect_arp_spoof,
        detect_dns_spoof,
        lambda d: detect_syn_flood(d, syn_threshold),
    ):
        try:
            result = fn(df)
            if result:
                alerts.append(result)
        except Exception:
            continue

    return alerts
