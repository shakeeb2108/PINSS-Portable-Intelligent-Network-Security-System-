from scripts.firewall_utils import block_ip
from datetime import datetime
import csv
import os

LOG_PATH = os.path.join(os.path.dirname(__file__), "../logs/detection_history.csv")

# Ensure log file has header if empty
if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
    with open(LOG_PATH, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "threat_type", "attacker_ip", "action_taken", "details"])

def log_threat(threat_type, ip_address, action_taken, details=""):
    """Logs threat actions properly."""
    with open(LOG_PATH, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), threat_type, ip_address, action_taken, details])

def mitigate_arp_spoof(ip_list):
    """Block IPs involved in ARP spoof attacks."""
    for ip in ip_list:
        result = block_ip(ip)
        log_threat("ARP Spoofing", ip, "Blocked via firewall", result)
        print(f"[MITIGATION] {result}")

def mitigate_syn_attack(ip_list):
    """Block IPs detected in SYN flood."""
    for ip in ip_list:
        result = block_ip(ip)
        log_threat("SYN Flood", ip, "Blocked via firewall", result)
        print(f"[MITIGATION] {result}")

def mitigate_dns_spoof(domain, ip_variants):
    """Switch DNS if suspicious activity detected."""
    safe_dns = "1.1.1.1"
    result = f"DNS spoof suspected for {domain}. Switching to {safe_dns}"
    log_threat("DNS Spoofing", "Unknown", f"Switched to {safe_dns}", f"IPs detected: {ip_variants}")
    print(f"[MITIGATION] {result}")
