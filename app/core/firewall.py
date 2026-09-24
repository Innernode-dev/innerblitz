import subprocess
import logging
from typing import Tuple

logger = logging.getLogger("innerblitz.firewall")

def configure_port_hopping(range_str: str, target_port: int, enable: bool = True) -> Tuple[bool, str]:
    """
    Setup or remove iptables NAT REDIRECT rule for UDP port hopping.
    range_str format: '20000:50000' or '20000-50000'
    """
    clean_range = range_str.replace("-", ":")
    action = "-A" if enable else "-D"
    
    cmd = [
        "iptables", "-t", "nat", action, "PREROUTING",
        "-p", "udp", "--dport", clean_range,
        "-j", "REDIRECT", "--to-ports", str(target_port)
    ]
    try:
        # If enabling, first try to remove existing identical rule to prevent duplicate rules
        if enable:
            del_cmd = ["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", clean_range, "-j", "REDIRECT", "--to-ports", str(target_port)]
            subprocess.run(del_cmd, capture_output=True, timeout=5)

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            logger.info(f"Port hopping iptables rule {'applied' if enable else 'removed'}: UDP {clean_range} -> {target_port}")
            return True, "Success"
        else:
            return False, res.stderr or "iptables failed"
    except FileNotFoundError:
        return False, "iptables command not found"
    except Exception as e:
        return False, str(e)

def flush_port_hopping() -> Tuple[bool, str]:
    """
    Safely find and remove all UDP REDIRECT port hopping rules from iptables PREROUTING table.
    """
    try:
        res = subprocess.run(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode != 0:
            return False, res.stderr or "Failed to list iptables rules"
        
        # Parse lines in reverse order to delete without changing subsequent line numbers
        lines = res.stdout.splitlines()
        deleted_count = 0
        for line in reversed(lines):
            if "REDIRECT" in line and "udp" in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    num = parts[0]
                    subprocess.run(
                        ["iptables", "-t", "nat", "-D", "PREROUTING", num],
                        capture_output=True, timeout=5
                    )
                    deleted_count += 1
        
        logger.info(f"Flushed {deleted_count} port hopping iptables rules.")
        return True, f"Flushed {deleted_count} rules"
    except FileNotFoundError:
        return False, "iptables not found"
    except Exception as e:
        return False, str(e)

def open_firewall_port(port: int, protocol: str = "tcp") -> Tuple[bool, str]:
    """
    Ensure port and protocol are opened in local firewall (ufw, iptables, ip6tables, firewalld).
    Handles environments without firewalls gracefully without throwing errors.
    """
    proto = protocol.lower()
    port_str = str(port)
    success = False
    details = []

    # 1. Try ufw if active
    try:
        res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            ufw_res = subprocess.run(["ufw", "allow", f"{port_str}/{proto}"], capture_output=True, text=True, timeout=5)
            if ufw_res.returncode == 0:
                details.append("ufw:allowed")
                success = True
    except Exception:
        pass

    # 2. Try iptables
    try:
        chk = subprocess.run(
            ["iptables", "-C", "INPUT", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
            capture_output=True, timeout=3
        )
        if chk.returncode != 0:
            ins = subprocess.run(
                ["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
                capture_output=True, text=True, timeout=5
            )
            if ins.returncode == 0:
                details.append("iptables:inserted")
                success = True
        else:
            details.append("iptables:exists")
            success = True
    except Exception:
        pass

    # 3. Try ip6tables
    try:
        chk6 = subprocess.run(
            ["ip6tables", "-C", "INPUT", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
            capture_output=True, timeout=3
        )
        if chk6.returncode != 0:
            ins6 = subprocess.run(
                ["ip6tables", "-I", "INPUT", "1", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
                capture_output=True, text=True, timeout=5
            )
            if ins6.returncode == 0:
                details.append("ip6tables:inserted")
        else:
            details.append("ip6tables:exists")
    except Exception:
        pass

    # 4. Try firewalld
    try:
        chk_fwd = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=3)
        if chk_fwd.returncode == 0 and "running" in chk_fwd.stdout:
            subprocess.run(["firewall-cmd", f"--add-port={port_str}/{proto}", "--permanent"], capture_output=True, timeout=5)
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=5)
            details.append("firewalld:allowed")
            success = True
    except Exception:
        pass

    msg = ", ".join(details) if details else "skipped_or_failed"
    logger.info(f"Firewall hole punching for {port_str}/{proto}: {msg}")
    return success, msg


