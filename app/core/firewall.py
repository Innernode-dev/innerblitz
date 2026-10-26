import subprocess
import logging
from typing import Tuple

logger = logging.getLogger("innerblitz.firewall")

HOPPING_CHAIN = "INNERBLITZ_HOPPING"
NFT_TABLE = "innerblitz_nat"
NFT_CHAIN = "prerouting"

def _configure_port_hopping_iptables(clean_range: str, target_port: int, enable: bool) -> Tuple[bool, str]:
    try:
        # Ensure dedicated chain exists
        subprocess.run(["iptables", "-t", "nat", "-N", HOPPING_CHAIN], capture_output=True, timeout=5)

        # Ensure jump rule exists from PREROUTING to HOPPING_CHAIN
        chk_jump = subprocess.run(
            ["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "-j", HOPPING_CHAIN],
            capture_output=True, timeout=3
        )
        if chk_jump.returncode != 0:
            subprocess.run(
                ["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-p", "udp", "-j", HOPPING_CHAIN],
                capture_output=True, timeout=5
            )

        # Flush dedicated chain to avoid duplicate rules
        subprocess.run(["iptables", "-t", "nat", "-F", HOPPING_CHAIN], capture_output=True, timeout=5)

        if enable:
            add_cmd = [
                "iptables", "-t", "nat", "-A", HOPPING_CHAIN,
                "-p", "udp", "--dport", clean_range,
                "-j", "REDIRECT", "--to-ports", str(target_port)
            ]
            res = subprocess.run(add_cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                logger.info(f"Port hopping iptables rule applied in {HOPPING_CHAIN}: UDP {clean_range} -> {target_port}")
                return True, "Success"
            else:
                return False, res.stderr or "iptables failed to add redirect"
        else:
            # When disabled, flush chain and remove jump
            subprocess.run(["iptables", "-t", "nat", "-F", HOPPING_CHAIN], capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "-j", HOPPING_CHAIN], capture_output=True, timeout=5)
            subprocess.run(["iptables", "-t", "nat", "-X", HOPPING_CHAIN], capture_output=True, timeout=5)
            logger.info(f"Port hopping iptables rule removed and chain {HOPPING_CHAIN} flushed")
            return True, "Success"
    except FileNotFoundError:
        return False, "iptables command not found"
    except Exception as e:
        return False, str(e)

def _configure_port_hopping_nft(clean_range: str, target_port: int, enable: bool) -> Tuple[bool, str]:
    nft_range = clean_range.replace(":", "-")
    try:
        if enable:
            subprocess.run(["nft", "add", "table", "ip", NFT_TABLE], capture_output=True, timeout=5)
            subprocess.run(
                ["nft", "add", "chain", "ip", NFT_TABLE, NFT_CHAIN, "{ type nat hook prerouting priority -100 ; }"],
                capture_output=True, timeout=5
            )
            subprocess.run(["nft", "flush", "chain", "ip", NFT_TABLE, NFT_CHAIN], capture_output=True, timeout=5)
            rule_cmd = [
                "nft", "add", "rule", "ip", NFT_TABLE, NFT_CHAIN,
                "udp", "dport", nft_range, "redirect", "to", str(target_port)
            ]
            res = subprocess.run(rule_cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                logger.info(f"Port hopping nftables rule applied: UDP {nft_range} -> {target_port}")
                return True, "Success"
            return False, res.stderr or "nftables failed to add redirect"
        else:
            subprocess.run(["nft", "delete", "table", "ip", NFT_TABLE], capture_output=True, timeout=5)
            logger.info(f"Port hopping nftables table {NFT_TABLE} removed")
            return True, "Success"
    except FileNotFoundError:
        return False, "nft command not found"
    except Exception as e:
        return False, str(e)

def configure_port_hopping(range_str: str, target_port: int, enable: bool = True) -> Tuple[bool, str]:
    """
    Setup or remove iptables/nftables NAT REDIRECT rule for UDP port hopping
    using the dedicated INNERBLITZ_HOPPING chain.
    range_str format: '20000:50000' or '20000-50000'
    """
    clean_range = "".join(range_str.split()).replace("-", ":")
    
    # Try iptables first
    try:
        ok, msg = _configure_port_hopping_iptables(clean_range, target_port, enable)
        if ok or "iptables command not found" not in msg:
            return ok, msg
    except Exception:
        pass

    # Fallback to nftables
    try:
        return _configure_port_hopping_nft(clean_range, target_port, enable)
    except FileNotFoundError:
        return False, "iptables command not found"
    except Exception as e:
        return False, str(e)

def flush_port_hopping() -> Tuple[bool, str]:
    """
    Safely find and remove all UDP REDIRECT port hopping rules from iptables/nftables.
    Flushes and deletes the dedicated INNERBLITZ_HOPPING chain.
    """
    flushed_any = False
    errors = []

    # 1. Try iptables
    try:
        subprocess.run(["iptables", "-t", "nat", "-F", HOPPING_CHAIN], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "-j", HOPPING_CHAIN], capture_output=True, timeout=5)
        subprocess.run(["iptables", "-t", "nat", "-X", HOPPING_CHAIN], capture_output=True, timeout=5)

        # Also cleanup any legacy direct PREROUTING rules
        res = subprocess.run(
            ["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            for line in reversed(lines):
                if "REDIRECT" in line and "udp" in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        subprocess.run(
                            ["iptables", "-t", "nat", "-D", "PREROUTING", parts[0]],
                            capture_output=True, timeout=5
                        )
        flushed_any = True
    except FileNotFoundError:
        pass
    except Exception as e:
        errors.append(f"iptables: {e}")

    # 2. Try nftables
    try:
        subprocess.run(["nft", "delete", "table", "ip", NFT_TABLE], capture_output=True, timeout=5)
        flushed_any = True
    except FileNotFoundError:
        pass
    except Exception as e:
        errors.append(f"nftables: {e}")

    if not flushed_any and not errors:
        return False, "iptables not found"

    if errors:
        return False, "; ".join(errors)

    logger.info(f"Flushed {HOPPING_CHAIN} port hopping rules.")
    return True, f"Flushed {HOPPING_CHAIN} rules"

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

def close_firewall_port(port: int, protocol: str = "tcp") -> Tuple[bool, str]:
    """
    Remove allow rule for port/proto in ufw, iptables, ip6tables, firewalld.
    """
    proto = protocol.lower()
    port_str = str(port)
    details = []

    # 1. ufw delete
    try:
        res = subprocess.run(["ufw", "delete", "allow", f"{port_str}/{proto}"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            details.append("ufw:deleted")
    except Exception:
        pass

    # 2. iptables delete
    try:
        del_res = subprocess.run(
            ["iptables", "-D", "INPUT", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=3
        )
        if del_res.returncode == 0:
            details.append("iptables:deleted")
    except Exception:
        pass

    # 3. ip6tables delete
    try:
        del6_res = subprocess.run(
            ["ip6tables", "-D", "INPUT", "-p", proto, "--dport", port_str, "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=3
        )
        if del6_res.returncode == 0:
            details.append("ip6tables:deleted")
    except Exception:
        pass

    # 4. firewalld remove
    try:
        chk_fwd = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=3)
        if chk_fwd.returncode == 0 and "running" in chk_fwd.stdout:
            subprocess.run(["firewall-cmd", f"--remove-port={port_str}/{proto}", "--permanent"], capture_output=True, timeout=5)
            subprocess.run(["firewall-cmd", "--reload"], capture_output=True, timeout=5)
            details.append("firewalld:removed")
    except Exception:
        pass

    msg = ", ".join(details) if details else "rule_removed_or_not_present"
    logger.info(f"Firewall close port {port_str}/{proto}: {msg}")
    return True, msg

def ensure_firewall_permissive() -> Tuple[bool, str]:
    """
    Ensure the server firewall default policy does not drop or restrict other ports.
    Sets INPUT, FORWARD, and OUTPUT default policy to ACCEPT.
    Everything is open from restrictions by default.
    """
    try:
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], capture_output=True, timeout=3)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], capture_output=True, timeout=3)
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], capture_output=True, timeout=3)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], capture_output=True, timeout=3)
        subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], capture_output=True, timeout=3)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], capture_output=True, timeout=3)
        return True, "Firewall policy set to permissive (ACCEPT all)"
    except Exception as e:
        return False, str(e)



