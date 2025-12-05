import subprocess

def block_ip(ip):
    """
    Blocks an IP using iptables DROP rule.
    Returns a readable message about the action.
    """

    try:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

        # Capture output and error
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return f"Firewall rule added: DROP all traffic from {ip}"

        else:
            return f"iptables error ({result.returncode}): {result.stderr.strip()}"

    except Exception as e:
        return f"Exception occurred while blocking {ip}: {e}"
