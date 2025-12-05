#!/usr/bin/env python3
"""
PINSS Phase 7 (Improved): Real-Time Engine with Stable ML Detection
- Rule-based detection remains first layer
- ML anomaly detection is secondary
- Dashboard added for real-time monitoring
"""

import time
import os
import pandas as pd
from scapy.all import sniff
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)

from scripts.packet_sniffer import extract_features
from scripts.feature_extractor import normalize_tcp_flags, normalize_arp_op
from scripts.rule_engine import run_all_detectors
from scripts.mitigation_engine import (
    mitigate_arp_spoof,
    mitigate_syn_attack,
    mitigate_dns_spoof,
    log_threat
)
from scripts.ml_detector import load_model, FEATURE_COLUMNS


print("🤖 Loading ML model...")
model = load_model()
print("✅ ML model loaded successfully!")

# ------------------------------
# Dashboard State
# ------------------------------
dashboard = {
    "packets": 0,
    "threats": 0,
    "last_threat": "None",
    "last_ip": "None",
    "firewall_blocks": 0
}

def print_dashboard():
    print("===== PINSS DASHBOARD =====")
    print(f"Packets captured: {dashboard['packets']}")
    print(f"Threats detected: {dashboard['threats']}")
    print(f"Last threat: {dashboard['last_threat']} ({dashboard['last_ip']})")
    print(f"Firewall blocks: {dashboard['firewall_blocks']} active rules")
    print("==========================\n")


# ------------------------------
# Configuration
# ------------------------------
DETECTION_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 10.0
WINDOW_SIZE = 200
ML_THRESHOLD = -0.10

packet_window = []
last_detection_time = time.time()
last_heartbeat_time = time.time()

# Prevent repeated alerts
last_alert_signature = None



# ------------------------------
# MAIN PACKET MONITOR FUNCTION
# ------------------------------
def live_monitor(pkt):
    global packet_window, last_detection_time, last_heartbeat_time, last_alert_signature

    features = extract_features(pkt)
    dashboard["packets"] += 1

    df_pkt = pd.DataFrame([features], columns=[
        "ts", "pkt_no", "eth_src", "eth_dst", "eth_type",
        "ip_src", "ip_dst", "ip_proto",
        "tcp_flags", "tcp_sport", "tcp_dport",
        "udp_len", "udp_sport", "udp_dport",
        "arp_op", "arp_psrc", "arp_pdst", "arp_hwsrc", "arp_hwdst",
        "dhcp_msgtype", "dhcp_server_id", "dhcp_yiaddr",
        "dns_qname", "dns_qtype", "dns_ans"
    ])

    df_pkt["tcp_syn"] = df_pkt["tcp_flags"].apply(normalize_tcp_flags)
    df_pkt["arp_op"] = df_pkt["arp_op"].apply(normalize_arp_op)

    packet_window.append(df_pkt)
    if len(packet_window) > WINDOW_SIZE:
        packet_window.pop(0)

    # ---------------------
    # Run detection every interval
    # ---------------------
    if time.time() - last_detection_time >= DETECTION_INTERVAL:
        last_detection_time = time.time()
        df_window = pd.concat(packet_window, ignore_index=True)

        # RULE DETECTION
        alerts = run_all_detectors(df_window)

        if alerts:
            for alert in alerts:
                
                sig = f"{alert['threat']}-{alert.get('ips')}"
                if sig == last_alert_signature:
                    return  # Skip duplicate alerts

                last_alert_signature = sig

                dashboard["threats"] += 1
                dashboard["last_threat"] = alert["threat"]

                attacker_ips = alert.get("ips", [])
                dashboard["last_ip"] = attacker_ips[0] if attacker_ips else "Unknown"

                print(f"🚨 RULE DETECTION: {alert['message']}")

                # Apply mitigation
                if alert["threat"] == "arp_spoof":
                    mitigate_arp_spoof(attacker_ips)
                    dashboard["firewall_blocks"] += len(attacker_ips)

                elif alert["threat"] == "syn_flood":
                    mitigate_syn_attack(attacker_ips)
                    dashboard["firewall_blocks"] += len(attacker_ips)

                elif alert["threat"] == "dns_spoof":
                    mitigate_dns_spoof(alert["domain"], alert["ips"])

            # 🔥 IMPORTANT: Reset window to prevent repeated detection
            packet_window.clear()

            
            time.sleep(2)
            print_dashboard()
            return

        # ---------------------
        # ML ANOMALY DETECTION
        # ---------------------
        sample = df_pkt[FEATURE_COLUMNS].infer_objects(copy=False).fillna(0)
        anomaly_score = model.decision_function(sample)[0]

        if anomaly_score < ML_THRESHOLD:
            ip = df_pkt["ip_src"].iloc[0]

            if ip != "None":
                dashboard["threats"] += 1
                dashboard["last_threat"] = "ML_Anomaly"
                dashboard["last_ip"] = ip

                print(f"⚠️ ML Anomaly Detected (score={anomaly_score:.4f}) | Source: {ip}")

                mitigate_arp_spoof([ip])
                dashboard["firewall_blocks"] += 1
                log_threat("ML Anomaly", ip, "Blocked via ML", f"Score={anomaly_score}")

                packet_window.clear()
            else:
                log_threat("ML Anomaly", "Unknown", "Logged only", f"Score={anomaly_score}")

        else:
            if time.time() - last_heartbeat_time >= HEARTBEAT_INTERVAL:
                last_heartbeat_time = time.time()
                print("✅ System Normal (No threats detected)")

        print_dashboard()



# ------------------------------
# START ENGINE
# ------------------------------
try:
    print("🚀 PINSS + ML Real-Time Defense Engine Activated! (Press CTRL+C to stop)")
    sniff(prn=live_monitor, store=False)

except KeyboardInterrupt:
    print("\n🛑 Stopping PINSS AI-Powered Engine...")
    print("Goodbye!")
