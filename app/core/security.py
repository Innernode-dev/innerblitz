import bcrypt
import pyotp
import secrets
from typing import Optional

def hash_password(password: str) -> str:
    """Hash a password securely using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def timing_safe_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def generate_totp_secret() -> str:
    """Generate a random Base32 secret for TOTP (Google Authenticator)."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str = "admin", issuer: str = "InnerBlitz") -> str:
    """Return standard otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code with 1-step window to accommodate clock drift."""
    if not secret or not code:
        return False
    clean_code = code.strip().replace(" ", "")
    totp = pyotp.TOTP(secret)
    return totp.verify(clean_code, valid_window=1)

def generate_session_id() -> str:
    """Generate a cryptographically secure random session ID."""
    return secrets.token_urlsafe(32)

def generate_secret_path(min_length: int = 12, max_length: int = 16) -> str:
    """Generate a high-entropy random URL-safe secret directory path (12-16 alphanumeric chars, e.g. bdjs74xhdg37)."""
    length = secrets.randbelow(max_length - min_length + 1) + min_length
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))
