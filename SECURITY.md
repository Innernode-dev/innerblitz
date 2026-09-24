# Security Policy — InnerBlitz

The **InnerNode** team takes the security of **InnerBlitz** and the Hysteria 2 proxy infrastructure very seriously. We are committed to ensuring the privacy, anonymity, and integrity of all node operators and connected clients.

---

## 🛡️ Supported Versions

We actively provide security patches and updates for the following versions:

| Version | Supported | Status |
| :--- | :---: | :--- |
| **InnerBlitz 2.x** | :white_check_mark: | **Active Support (Recommended)** |
| Blitz 1.x (Legacy) | :x: | End of Life (Deprecated) |

Users and operators are strongly encouraged to maintain their installations on the latest `main` release using:
```bash
blitz -> [9] Обновить InnerBlitz
# или
bash <(curl -fsSL https://raw.githubusercontent.com/Innernode-dev/innerblitz/main/upgrade.sh)
```

---

## 🔒 Security Architecture & Defensive Principles

InnerBlitz is engineered from the ground up for high-threat censorship and hostile network environments:

1. **Anti-DPI & Anti-Censorship Camouflage:**
   * **Stealth Ports:** The management panel runs on dynamic non-standard ports (`20000–60000`) rather than standard ports probed by ISP scanners (`8080`, `443`, `80`).
   * **Secret Directory Path:** Management endpoints are concealed behind custom secret URL paths (e.g. `/node-xxxx`). Standard `/login` endpoints are hidden from unauthorized crawlers.
   * **Decoy Camouflage:** All root (`/`) and unauthorized probes receive a realistic decoy website (Nginx default, telemetry node, API docs, or 404 blackhole) with masked `Server: nginx/1.24.0 (Ubuntu)` headers, neutralizing automated scanner fingerprinting.

2. **Cryptographic Protection & IP SAN Certificates:**
   * Automated generation of ECDSA P-256 certificates with direct IP Subject Alternative Names.
   * Generation and client verification of `pinSHA256` fingerprints, eliminating Man-In-The-Middle (MITM) risks even without a publicly registered domain.
   * Salamander Obfs obfuscates QUIC handshake packets into random high-entropy noise.

3. **Authentication & Privilege Isolation:**
   * Passwords are salted and hashed using `bcrypt` (12 rounds).
   * Constant-time comparison (`secrets.compare_digest`) is used across all authentication tokens and subcription portals to prevent timing attacks.
   * Rate limiting and cooldown mechanisms protect all login endpoints against brute-force attacks.
   * Multi-Factor Authentication: RFC 6238 TOTP (Google Authenticator, Aegis, 2FAS) and direct Telegram OTP challenge-response.

4. **Zero-AVX Local Data Isolation:**
   * Replaced external database daemons with embedded SQLite in Write-Ahead Logging (`WAL`) mode.
   * No exposed database ports (e.g., 27017 or 3306), running strictly within root-restricted filesystem permissions (`/etc/hysteria`).

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or potential threat in InnerBlitz, **please do not open a public GitHub issue**.

### Preferred Reporting Channels:

1. **GitHub Security Advisories (Recommended):**  
   Open a private report via [GitHub Private Vulnerability Reporting](https://github.com/Innernode-dev/innerblitz/security/advisories/new).

2. **Email Disclosure:**  
   Send an encrypted or detailed report to: **`security@innernode.dev`**

### What to include:
* A detailed description of the vulnerability and its potential impact (e.g., panel bypass, unauthenticated RCE, memory leak, DPI fingerpriting vector).
* Step-by-step instructions or Proof of Concept (PoC) to reproduce the behavior.
* Affected operating system versions and environment details.
* Any suggested fixes or temporary mitigations.

---

## ⏱️ Vulnerability Handling Process

1. **Triage:** We will acknowledge receipt of your vulnerability report within **24–48 hours**.
2. **Assessment:** Our engineering team will analyze the severity and impact under CVSS standards.
3. **Patch Development:** A fix will be developed in a private branch and tested across Ubuntu/Debian environments.
4. **Coordinated Release:** A patch will be deployed to the `main` branch, accompanied by an advisory release note with appropriate credit to the reporter.

Thank you for helping keep **InnerBlitz** and the privacy community safe!
