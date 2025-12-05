from scripts.firewall_utils import block_ip
from datetime import datetime
import csv
import os
from scripts.report_generator import generate_pdf_report

LOG_PATH = os.path.join(os.path.dirname(__file__), "../logs/detection_history.csv")

# Ensure CSV exists
if not os.path.exists(LOG_PATH) or os.path.getsize(LOG_PATH) == 0:
    with open(LOG_PATH, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "threat_type", "attacker_ip", "action_taken", "details"])


def log_threat(threat_type, ip_address, action_taken, details=""):
    with open(LOG_PATH, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.now(), threat_type, ip_address, action_taken, details])


# Prevent duplicate blocks
mitigated_ips = set()


def _print_firewall_status():
    print("\n[FIREWALL STATUS - TOP RULES]")
    os.system("sudo iptables -L -n | head -20")
    print("---------------------------------------------------\n")


# -------------------------------------------------------------------
# ARP SPOOF MITIGATION (with forced PDF generation)
# -------------------------------------------------------------------
def mitigate_arp_spoof(ip_list):
    for ip in ip_list:

        action = ""
        details = ""

        # Router protection (no block, but still generate PDF)
        if ip == "192.168.1.1":
            action = "Skipped blocking (Gateway IP)"
            details = "Gateway detected, firewall rule not applied"
            print("[WARNING] Skipping gateway 192.168.1.1 — not blocking router.")

        # IP already blocked earlier
        elif ip in mitigated_ips:
            action = "Already mitigated earlier"
            details = f"Duplicate block prevented for {ip}"
            print(f"[INFO] IP {ip} already mitigated earlier. Skipping duplicate block.")

        else:
            # Perform actual firewall block
            mitigated_ips.add(ip)
            details = block_ip(ip)
            action = "Blocked via firewall"
            print(f"[MITIGATION - ARP SPOOF] {details}")

        # Log threat + Always generate PDF
        log_threat("ARP Spoofing", ip, action, details)
        pdf = generate_pdf_report(
            threat_type="ARP Spoofing",
            ip=ip,
            action_taken=action,
            details=details,
            dashboard_stats=None
        )
        print(f"[REPORT] PDF generated: {pdf}")

    _print_firewall_status()
    print("[LOGGED] Event stored in detection_history.csv\n")


# -------------------------------------------------------------------
# SYN FLOOD MITIGATION (always generate PDF)
# -------------------------------------------------------------------
def mitigate_syn_attack(ip_list):
    for ip in ip_list:

        if ip in mitigated_ips:
            action = "Already mitigated earlier"
            details = f"Duplicate block prevented for {ip}"
            print(f"[INFO] IP {ip} already blocked. Skipping.")
        else:
            mitigated_ips.add(ip)
            details = block_ip(ip)
            action = "Blocked via firewall"
            print(f"[MITIGATION - SYN FLOOD] {details}")

        # Always generate PDF
        log_threat("SYN Flood", ip, action, details)
        pdf = generate_pdf_report(
            threat_type="SYN Flood",
            ip=ip,
            action_taken=action,
            details=details,
            dashboard_stats=None
        )
        print(f"[REPORT] PDF generated: {pdf}")

    _print_firewall_status()
    print("[LOGGED] Event stored in detection_history.csv\n")


# -------------------------------------------------------------------
# DNS SPOOF MITIGATION (always generate PDF)
# -------------------------------------------------------------------
def mitigate_dns_spoof(domain, ip_variants):
    safe_dns = "1.1.1.1"
    details = f"DNS spoof suspected for {domain}. Switching DNS to {safe_dns}"

    print(f"[MITIGATION - DNS SPOOF] {details}")

    log_threat("DNS Spoofing", "Unknown", f"DNS switched to {safe_dns}", f"IPs: {ip_variants}")

    # Always generate PDF
    pdf = generate_pdf_report(
        threat_type="DNS Spoofing",
        ip="Unknown",
        action_taken=f"DNS switched to {safe_dns}",
        details=details,
        dashboard_stats=None
    )
    print(f"[REPORT] PDF generated: {pdf}")

    _print_firewall_status()
    print("[LOGGED] Event stored in detection_history.csv\n")
