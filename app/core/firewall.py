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
