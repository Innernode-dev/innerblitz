import os
import ipaddress
import hashlib
import base64
import logging
import datetime
from pathlib import Path
from typing import Tuple, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from app.config import settings

logger = logging.getLogger("innerblitz.cert")

def generate_self_signed_cert(
    server_ip_or_domain: str, 
    cert_path: Optional[str] = None, 
    key_path: Optional[str] = None,
    valid_days: int = 3650
) -> Tuple[str, str, str]:
    """
    Generate an Elliptic Curve (ECDSA prime256v1) self-signed certificate
    with Subject Alternative Name (SAN) supporting either an IP address or domain.
    Returns: (cert_path, key_path, sha256_fingerprint)
    """
    cert_file = cert_path or settings.CERT_PATH
    key_file = key_path or settings.KEY_PATH

    Path(cert_file).parent.mkdir(parents=True, exist_ok=True)
    Path(key_file).parent.mkdir(parents=True, exist_ok=True)

    # 1. Generate EC Private Key (prime256v1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 2. Build Subject & Issuer
    common_name = server_ip_or_domain.strip() if server_ip_or_domain else "127.0.0.1"
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "InnerBlitz Secure Proxy"),
    ])

    # 3. Add SAN (Subject Alternative Name) for IP or DNS
    san_entries = []
    try:
        ip_obj = ipaddress.ip_address(common_name)
        san_entries.append(x509.IPAddress(ip_obj))
    except ValueError:
        san_entries.append(x509.DNSName(common_name))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    cert = cert_builder.sign(private_key, hashes.SHA256())

    # 4. Serialize and write key and cert to disk
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    with open(key_file, "wb") as f:
        f.write(key_pem)
    with open(cert_file, "wb") as f:
        f.write(cert_pem)

    # Secure permissions (read/write for owner only)
    try:
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
    except Exception:
        pass

    # 5. Compute SHA256 fingerprint (in hex format accepted by Hysteria 2 clients)
    sha256_hex = cert.fingerprint(hashes.SHA256()).hex()
    logger.info(f"Generated self-signed TLS certificate for {common_name}. SHA256: {sha256_hex}")

    return cert_file, key_file, sha256_hex

def get_certificate_sha256(cert_path: Optional[str] = None) -> str:
    """Read an existing certificate and return its SHA-256 fingerprint in hex."""
    target_path = cert_path or settings.CERT_PATH
    if not os.path.exists(target_path):
        return ""
    try:
        with open(target_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception as e:
        logger.error(f"Failed to read certificate {target_path}: {e}")
        return ""

def generate_panel_cert(
    server_ip_or_domain: str, 
    valid_days: int = 6
) -> Tuple[str, str, str]:
    """
    Generate or renew the 6-day self-signed IP/domain certificate for the Web Panel.
    Defaults to 6-day validity for automated rotation.
    """
    cert_p, key_p, sha = generate_self_signed_cert(
        server_ip_or_domain=server_ip_or_domain,
        cert_path=settings.PANEL_CERT_PATH,
        key_path=settings.PANEL_KEY_PATH,
        valid_days=valid_days
    )
    logger.info(f"Generated Web Panel certificate (validity: {valid_days} days) at {cert_p}")
    return cert_p, key_p, sha

def get_cert_info(cert_path: Optional[str] = None) -> dict:
    """
    Inspect a PEM certificate and return its validity period, days remaining,
    Common Name, SANs, and SHA-256 fingerprint.
    """
    target_path = cert_path or settings.PANEL_CERT_PATH
    if not os.path.exists(target_path):
        return {"exists": False, "days_left": 0.0, "hours_left": 0.0, "is_expired": True}
    try:
        with open(target_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        if hasattr(cert, "not_valid_after_utc"):
            expiry = cert.not_valid_after_utc
        else:
            expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            
        delta_sec = (expiry - now).total_seconds()
        days_left = max(0.0, round(delta_sec / 86400.0, 1))
        hours_left = max(0.0, round(delta_sec / 3600.0, 1))
        
        cn = ""
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                cn = attr.value
                break
                
        return {
            "exists": True,
            "common_name": cn,
            "expiry_iso": expiry.isoformat(),
            "days_left": days_left,
            "hours_left": hours_left,
            "is_expired": delta_sec <= 0,
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "cert_path": target_path
        }
    except Exception as e:
        logger.error(f"Error inspecting cert {target_path}: {e}")
        return {"exists": False, "days_left": 0.0, "hours_left": 0.0, "is_expired": True, "error": str(e)}

def check_and_renew_panel_cert(server_ip_or_domain: str, min_days_left: float = 1.0) -> bool:
    """
    Check if the 6-day panel certificate needs rotation, and regenerate it if needed.
    Returns True if the certificate was renewed, False if still valid.
    """
    info = get_cert_info(settings.PANEL_CERT_PATH)
    if not info.get("exists") or info.get("is_expired") or info.get("days_left", 0.0) <= min_days_left:
        generate_panel_cert(server_ip_or_domain, valid_days=6)
        return True
    return False

