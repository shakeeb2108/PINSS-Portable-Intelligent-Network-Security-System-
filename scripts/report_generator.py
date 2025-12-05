from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, yellow, green, blue, black
import os
from datetime import datetime

# Save inside /reports folder
REPORT_DIR = os.path.join(os.path.dirname(__file__), "../reports")
os.makedirs(REPORT_DIR, exist_ok=True)


# ============================
# 1. SEVERITY MAPPING
# ============================
SEVERITY_MAP = {
    "ARP Spoofing": ("High", red),
    "SYN Attack": ("High", red),
    "DNS Spoofing": ("Critical", red),
    "ML Anomaly": ("Medium", yellow),
    "Rogue DHCP": ("Critical", red)
}

# ============================
# 2. MITRE ATT&CK MAPPING
# ============================
MITRE_MAP = {
    "ARP Spoofing": ("Credential Access", "T1557.002 - ARP Cache Poisoning"),
    "DNS Spoofing": ("Discovery / Impersonation", "T1557.001 - DNS Poisoning"),
    "SYN Attack": ("Impact / DoS", "T1499 - Network DoS"),
    "ML Anomaly": ("Anomaly Detection", "Unknown - Behavioral anomaly"),
    "Rogue DHCP": ("Initial Access", "T1542 - Rogue DHCP Server")
}

# ============================
# 3. RECOMMENDATIONS
# ============================
RECOMMENDATIONS = {
    "ARP Spoofing": [
        "Enable Dynamic ARP Inspection (DAI) on switches.",
        "Use static ARP entries for gateway.",
        "Monitor sudden MAC-IP changes."
    ],
    "DNS Spoofing": [
        "Switch to DNSSEC or secure DNS resolvers.",
        "Use encrypted DNS (DoH/DoT).",
        "Block unknown DNS replies with strange IP variations."
    ],
    "SYN Attack": [
        "Enable SYN cookies.",
        "Rate-limit incoming TCP SYN packets.",
        "Use firewall DoS protection features."
    ],
    "Rogue DHCP": [
        "Enable DHCP Snooping on switches.",
        "Allow DHCP responses only from trusted interfaces.",
        "Block unknown DHCP servers."
    ],
    "ML Anomaly": [
        "Check system behavior manually.",
        "Inspect logs for unusual traffic.",
        "Enable stricter ML threshold in PINSS config."
    ]
}



# ============================
# MAIN PDF GENERATION FUNCTION
# ============================
def generate_pdf_report(threat_type, ip, action_taken, details="", dashboard_stats=None, extra_info=None):
    """
    Generates a complete SOC-grade PDF report.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{timestamp}_{threat_type}_report.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    c = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4

    # --------------------------
    # HEADER
    # --------------------------
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(blue)
    c.drawString(50, height - 50, "PINSS Security Incident Report")
    c.setFillColor(black)

    # --------------------------
    # BASIC DETAILS
    # --------------------------
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 90, "Incident Summary")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 120, f"Timestamp: {timestamp}")
    c.drawString(50, height - 140, f"Threat Type: {threat_type}")
    c.drawString(50, height - 160, f"Attacker IP: {ip}")
    c.drawString(50, height - 180, f"Action Taken: {action_taken}")
    c.drawString(50, height - 200, f"Details: {details}")

    # --------------------------
    # SEVERITY LEVEL
    # --------------------------
    severity, color = SEVERITY_MAP.get(threat_type, ("Unknown", black))

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 240, "Severity Level:")
    c.setFillColor(color)
    c.drawString(180, height - 240, severity)
    c.setFillColor(black)

    # --------------------------
    # MITRE ATT&CK MAPPING
    # --------------------------
    mitre_tactic, mitre_technique = MITRE_MAP.get(threat_type, ("Unknown", "Unknown"))

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 280, "MITRE ATT&CK Mapping")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 300, f"Tactic: {mitre_tactic}")
    c.drawString(50, height - 320, f"Technique: {mitre_technique}")

    # --------------------------
    # SYSTEM SNAPSHOT (OPTIONAL)
    # --------------------------
    if dashboard_stats:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 360, "System Status at Detection")

        c.setFont("Helvetica", 12)
        c.drawString(50, height - 380, f"Packets Captured: {dashboard_stats['packets']}")
        c.drawString(50, height - 400, f"Total Threats: {dashboard_stats['threats']}")
        c.drawString(50, height - 420, f"Firewall Rules Active: {dashboard_stats['firewall_blocks']}")

    # --------------------------
    # RECOMMENDATIONS SECTION
    # --------------------------
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 460, "Security Recommendations")

    y = height - 480
    c.setFont("Helvetica", 12)

    for rec in RECOMMENDATIONS.get(threat_type, ["No recommendations available."]):
        c.drawString(50, y, f"- {rec}")
        y -= 20

    # --------------------------
    # FOOTER
    # --------------------------
    c.setFont("Helvetica-Oblique", 10)
    c.drawString(50, 40, "Generated by PINSS — AI-Powered Decentralized Framework for Portable & Autonomous Network Threat Detection")

    c.save()
    return filepath
