# TEST_READY — InnerBlitz Hysteria 2 Opaque-Box E2E Test Suite

## Executive Summary
- **Test Suite Status**: **READY** (100% Operational)
- **Total Automated Tests**: **269 Tests**
- **Test Results**: **269 Passed, 0 Failures, 0 Errors, 0 Flaky**
- **Execution Target**: Python 3.10+ (Tested on Python 3.13.0 on win32)
- **Framework**: Standard Python `unittest` with Starlette / FastAPI test harness, requiring zero external test runners while maintaining full compatibility with `pytest`.
- **Isolation Guarantee**: 100% hermetic isolation per test via temporary sandboxes (`tempfile.mkdtemp`), zero side-effects on host machine, and clean teardown.

---

## Runner Commands

### 1. Execute Full Test Suite (All Tiers)
```bash
python tests/e2e/runner.py
```
*(Alternative via standard unittest discovery)*:
```bash
python -m unittest discover -s tests/e2e -p "test_*.py" -v
```
*(Alternative via pytest, if installed)*:
```bash
pytest tests/e2e -v
```

### 2. Execute by Specific Tier
```bash
# Tier 1: Feature Coverage (≥5 tests per feature for F1-F21) — 105 tests
python tests/e2e/runner.py --tier 1

# Tier 2: Boundary & Corner Cases (≥5 per feature) — 105 tests
python tests/e2e/runner.py --tier 2

# Tier 3: Cross-Feature Combinations (pairwise interactions) — 28 tests
python tests/e2e/runner.py --tier 3

# Tier 4: Real-World Scenarios (complete workflows) — 5 workflows
python tests/e2e/runner.py --tier 4
```

---

## 4-Tier Test Breakdown & Verification Matrix

| Tier | Category | Tests | Status | Scope / Highlights |
|---|---|:---:|:---:|---|
| **Tier 1** | **Feature Coverage** | **105** | ✅ PASS | Systematic opaque-box verification of all 21 cataloged features (F1–F21) from Requirements R1–R6. ≥5 tests per feature. |
| **Tier 2** | **Boundary & Corner Cases** | **105** | ✅ PASS | Extreme ranges, empty inputs, non-numeric strings, punycode/IDN domains, YAML corruptions, zero/unlimited limits, injection strings, non-interactive shell flags. |
| **Tier 3** | **Cross-Feature Combinations** | **28** | ✅ PASS | Pairwise interactions: WARP outbounds + RU direct/warp/block; Port Hopping + Sniffing; TLS modes (ACME/Self-Signed) + Port Hopping; Decoy camouflage + custom secret path; Subscriptions + Quota limits. |
| **Tier 4** | **Real-World Scenarios** | **5** | ✅ PASS | Complete operational workflows: Admin onboarding & stealth lockdown; Client lifecycle with quota rejection & re-authorization; WARP egress policy switch; Multi-client profile distribution; Port hopping dynamic range lifecycle. |
| **Unit/M1** | **Integrated WARP Module** | **26** | ✅ PASS | Integrated M1 WARP lifecycle, process manager ring buffer, and REST endpoints. |
| **TOTAL** | **Comprehensive Suite** | **269** | ✅ PASS | **100% Verified Clean Run (114.0s execution time)** |

---

## Verified Feature Inventory (Requirements R1–R6)

1. **R1 / F1–F4: WARP Lifecycle & Diagnostics**
   - Active WireGuard (`warp`, `wgcf`) and SOCKS5 (`127.0.0.1:40000`) detection.
   - Idempotent connection reuse without duplicate daemons or processes.
   - Automated 1-click installer contract and execution logging.
   - Cloudflare trace diagnostics parser (`cloudflare.com/cdn-cgi/trace`) for IP, colo, and status (`warp=on|plus|off`).
2. **R2 / F5–F10: Visual Routing Engine & Config Generation**
   - Graphical rule builder and settings API persistence.
   - Global Outbound Switch (Direct server IP vs Cloudflare WARP IP).
   - RU Traffic 3-way routing selector (`geosite:ru`, `geoip:ru`: Direct, WARP, Block).
   - Service preset rules (OpenAI, Discord, YouTube, Telegram, Netflix, Ads, Windows Spy).
   - Dynamic Hysteria 2 YAML generation with valid `listen`, `tls`, `quic`, `bandwidth`, `auth`, `outbounds`, `acl.inline`.
   - Config syntax validation, atomic backup preservation, and error rollback.
3. **R3 / F11–F12: Sniffing & Port Hopping Management**
   - Sniffing controls (`sniff.enable`, `sniff.timeout`, `sniff.rewriteDomain`).
   - Port hopping UDP range parsing (`20000-50000` / `20000:50000`), iptables PREROUTING redirection, and clean flush routines.
4. **R4 / F13–F15: Client Subscriptions & Multi-Client Portal**
   - Sing-box v1.10+ JSON profile generation with TUN inbound, outbounds, and client split routing.
   - Clash Meta / Mihomo YAML profile with proxy groups and routing rules.
   - Client Web Portal (`/portal/{token}`) with live data usage gauges, QR codes, and 1-click import URI schemes (`hiddify://`, `clash://`, `sing-box://`, `hy2://`).
   - Subscription-Userinfo headers formatting (`upload`, `download`, `total`, `expire`).
5. **R5 / F16–F17: Human-Crafted Zinc/Slate UI & Responsive Design**
   - Clean Zinc/Slate dark theme templates (`settings.html`, `index.html`, `client_portal.html`, `login.html`, `decoy.html`).
   - Responsive viewport, touch-friendly interactive targets, and mobile layout.
6. **R6 / F18–F20: Security Hardening, Deployment Scripts & GitHub Hygiene**
   - Stealth URL path routing (`/{secret_path}`) and anti-scanner Decoy site camouflage on `/`.
   - Brute-force rate limiting and 2FA TOTP verification (RFC 6238).
   - Shell deployment scripts (`install.sh`, `menu.sh`, `upgrade.sh`, `uninstall.sh`).
   - Clean git hygiene, bilingual `README.md` (Russian & English), and GPL-3.0 licensing.
7. **F21: Opaque-Box E2E Test Harness**
   - Hermetic test sandbox, isolated temporary database fixtures, automated assertions, and comprehensive runner.
