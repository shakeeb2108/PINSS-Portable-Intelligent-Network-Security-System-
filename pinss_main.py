#!/usr/bin/env python3
"""
PINSS Phase 7 (Improved): Real-Time Engine with Stable ML Detection
- Rule-based detection remains first layer
- ML acts as secondary defense but will only block when ip_src is valid
- ML anomalies are scored and compared against threshold
"""

import time
import pandas as pd
from scapy.all import sniff

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

# Load trained ML model
print("🤖 Loading ML model...")
model = load_model()
print("✅ ML model loaded successfully!")

# Configuration
DETECTION_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 10.0
WINDOW_SIZE = 200
ML_THRESHOLD = -0.10  # Lower = more anomalous. Adjust as necessary.

packet_window = []
last_detection_time = time.time()
last_heartbeat_time = time.time()

def live_monitor(pkt):
    global packet_window, last_detection_time, last_heartbeat_time

    # Extract features per packet
    features = extract_features(pkt)
    df_pkt = pd.DataFrame([features], columns=[
        "ts", "pkt_no", "eth_src", "eth_dst", "eth_type",
        "ip_src", "ip_dst", "ip_proto",
        "tcp_flags", "tcp_sport", "tcp_dport",
        "udp_len", "udp_sport", "udp_dport",
        "arp_op", "arp_psrc", "arp_pdst", "arp_hwsrc", "arp_hwdst",
        "dhcp_msgtype", "dhcp_server_id", "dhcp_yiaddr",
        "dns_qname", "dns_qtype", "dns_ans"
    ])

    # Normalize features for ML
    df_pkt["tcp_syn"] = df_pkt["tcp_flags"].apply(normalize_tcp_flags)
    df_pkt["arp_op"] = df_pkt["arp_op"].apply(normalize_arp_op)

    # Sliding window buffer
    packet_window.append(df_pkt)
    if len(packet_window) > WINDOW_SIZE:
        packet_window.pop(0)

    # Run detection every interval
    if time.time() - last_detection_time >= DETECTION_INTERVAL:
        last_detection_time = time.time()
        df_window = pd.concat(packet_window, ignore_index=True)

        # ✅ Rule-based detection
        alerts = run_all_detectors(df_window)
        if alerts:
            for alert in alerts:
                print(f"🚨 RULE DETECTION: {alert['message']}")
                attacker_ips = alert.get("ips", [])
                
                if alert["threat"] == "arp_spoof":
                    mitigate_arp_spoof(attacker_ips)
                elif alert["threat"] == "syn_flood":
                    mitigate_syn_attack(attacker_ips)
                elif alert["threat"] == "dns_spoof":
                    mitigate_dns_spoof(alert["domain"], alert["ips"])
            return  # Skip ML check if a rule triggered

        # ✅ ML anomaly detection (only if no rule triggered)
        sample = df_pkt[FEATURE_COLUMNS].infer_objects(copy=False).fillna(0)
        anomaly_score = model.decision_function(sample)[0]  # score < 0 = anomaly

        if anomaly_score < ML_THRESHOLD:
            ip = df_pkt["ip_src"].iloc[0]

            if ip and ip != "None":
                print(f"⚠️ ML Anomaly Detected (score={anomaly_score:.4f}) | Source: {ip}")
                log_threat("ML Anomaly", ip, "Blocked via ML", f"Score={anomaly_score}")
                mitigate_arp_spoof([ip])  # Reusing ARP spoof mitigation for generic blocking
            else:
                print(f"⚠️ ML Anomaly Detected but IP is invalid (score={anomaly_score:.4f})")
                log_threat("ML Anomaly", "Unknown", "Logged only", f"Score={anomaly_score}")
        else:
            # Print "System Normal" at intervals
            if time.time() - last_heartbeat_time >= HEARTBEAT_INTERVAL:
                last_heartbeat_time = time.time()
                print("✅ System Normal (No threats detected)")

try:
    print("🚀 PINSS + ML Real-Time Defense Engine Activated! (Press CTRL+C to stop)")
    sniff(prn=live_monitor, store=False)
except KeyboardInterrupt:
    print("🛑 Stopping PINSS AI-Powered Engine...")
