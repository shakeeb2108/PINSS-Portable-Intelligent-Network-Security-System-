# Wrapper for iptables/netsh
import subprocess
import platform

def block_ip(ip_address):
    """Blocks an IP using appropriate OS firewall commands."""
    if platform.system() == "Linux":
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    elif platform.system() == "Windows":
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Block_{ip_address}", "dir=in", "action=block", f"remoteip={ip_address}"]
    else:
        return f"❌ Unsupported OS for firewall command."

    try:
        subprocess.run(cmd, check=True)
        return f"✅ Successfully blocked IP: {ip_address}"
    except Exception as e:
        return f"⚠ Error blocking IP {ip_address}: {e}"
