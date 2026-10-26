# TEST_INFRA — InnerBlitz Hysteria 2 Opaque-Box E2E Testing Framework

## 1. Test Philosophy & Principles

The InnerBlitz Hysteria 2 Next-Gen Panel End-to-End (E2E) Test Suite is designed according to **opaque-box (black-box)** testing principles:
- **Specification-Driven**: Every test case validates observable external behaviors against the requirements documented in `ORIGINAL_REQUEST.md` (R1-R6) and `PROJECT.md` (Features F1-F21), rather than coupling to internal implementation details.
- **Strict Independence & Isolation**: Every test sets up its own isolated temporary environment (`tempfile.mkdtemp`), overriding database storage, configuration directories, and socket bindings so that test runs never mutate the host system or depend on test execution order.
- **Deterministic & Repeatable**: Tests eliminate flaky behavior by using isolated SQLite WAL-mode databases, synthetic mock trace responses, deterministic time fixtures, and clean resource teardown.
- **Progressive Testability**: The test harness is designed to test modules as they are delivered across milestones (M1-M6). Features currently under active development (e.g. M1 WARP lifecycle) have full contract verification tests that adaptively execute against implementation code when present, or verify contract requirements against formal specification vectors.
- **Adversarial & Boundary Verification**: Includes systematic boundary value analysis (BVA), malformed and injection payloads, unicode edge cases, extreme port ranges, and recovery/rollback scenarios.

---

## 2. Test Architecture

The testing framework is structured into modular layers inside `tests/e2e/`:

```
tests/e2e/
├── __init__.py                     # Package marker
├── harness.py                      # Test harness: isolated sandbox, DB fixtures, API TestClient
├── runner.py                       # Standalone CLI test runner (supports all tiers & filters)
├── test_tier1_feature_coverage.py  # Tier 1: Feature Coverage (≥5 tests per feature for F1-F21)
├── test_tier2_boundary_corner.py   # Tier 2: Boundary & Corner Cases (≥5 tests per feature)
├── test_tier3_cross_feature.py     # Tier 3: Cross-Feature Combinations (pairwise interactions)
└── test_tier4_real_world.py        # Tier 4: Real-World Scenarios (multi-step operational workflows)
```

### Components:
1. **Isolated Sandbox (`harness.IsolatedTestEnvironment`)**:
   - Creates a temporary working directory.
   - Redirects `INNERBLITZ_DIR` to ensure SQLite DB, `config.yaml`, and certificates remain completely isolated.
   - Initializes database tables via `init_db()` and cleans up on exit (`shutil.rmtree`).
2. **API Test Client (`harness.create_test_client`)**:
   - Provides a Starlette `TestClient` bound to the FastAPI application.
   - Handles session cookie authentication for protected `/api/*` endpoints.
3. **Spec Oracle & Contract Helpers (`harness.ContractOracle`)**:
   - Verifies formal interface contracts specified in `PROJECT.md § Interface Contracts` for `app.core.warp`, `app.core.hysteria`, and `app.core.subscription`.

---

## 3. Runner Commands

The test suite requires zero external testing dependencies beyond standard Python, while remaining 100% compatible with `pytest`.

### Running with Python Built-In Runner
```bash
# Run all E2E tests across all 4 tiers
python tests/e2e/runner.py

# Run with verbose output
python tests/e2e/runner.py -v

# Run a specific tier
python tests/e2e/runner.py --tier 1
python tests/e2e/runner.py --tier 2
python tests/e2e/runner.py --tier 3
python tests/e2e/runner.py --tier 4

# Run via standard unittest discovery
python -m unittest discover -s tests/e2e -p "test_*.py" -v
```

### Running with Pytest (if installed)
```bash
pytest tests/e2e -v
```

---

## 4. 4-Tier Coverage Checklist (Features F1 - F21)

| Feature | Description | Tier 1 (Coverage) | Tier 2 (Boundaries) | Tier 3 (Cross-Feature) | Tier 4 (Real-World) |
|---|---|---|---|---|---|
| **F1** | Active WARP Detection | ✅ 5+ tests | ✅ 5+ tests | ✅ Pairwise WARP + RU | ✅ Scenario 3 |
| **F2** | Existing WARP Reuse | ✅ 5+ tests | ✅ 5+ tests | ✅ Pairwise WARP + PortHop | ✅ Scenario 3 |
| **F3** | 1-Click WARP Installer | ✅ 5+ tests | ✅ 5+ tests | ✅ Pairwise Install + Egress | ✅ Scenario 3 |
| **F4** | WARP Diagnostics | ✅ 5+ tests | ✅ 5+ tests | ✅ Trace schema verification | ✅ Scenario 3 |
| **F5** | Visual Routing Builder | ✅ 5+ tests | ✅ 5+ tests | ✅ Pairwise Rule + YAML | ✅ Scenario 3 |
| **F6** | Global Outbound Switch | ✅ 5+ tests | ✅ 5+ tests | ✅ Outbound fallback priority | ✅ Scenario 3 |
| **F7** | RU Traffic Rule Engine | ✅ 5+ tests | ✅ 5+ tests | ✅ 3-way RU (Direct/WARP/Block) | ✅ Scenario 3 |
| **F8** | Service Preset Rules | ✅ 5+ tests | ✅ 5+ tests | ✅ OpenAI, Ads, Spy presets | ✅ Scenario 3 |
| **F9** | Dynamic Hysteria Config | ✅ 5+ tests | ✅ 5+ tests | ✅ YAML sections validation | ✅ Scenario 5 |
| **F10** | Config Syntax Validation | ✅ 5+ tests | ✅ 5+ tests | ✅ Rollback & backup check | ✅ Scenario 5 |
| **F11** | Sniffing Visual Controls | ✅ 5+ tests | ✅ 5+ tests | ✅ Sniffing + Port Hopping | ✅ Scenario 3 |
| **F12** | Port Hopping & Persistence | ✅ 5+ tests | ✅ 5+ tests | ✅ Range formatting & iptables | ✅ Scenario 2 |
| **F13** | Sing-box v1.10+ Profile | ✅ 5+ tests | ✅ 5+ tests | ✅ Profile + Split Routing | ✅ Scenario 2 |
| **F14** | Clash Meta / Mihomo Sub | ✅ 5+ tests | ✅ 5+ tests | ✅ Clash proxy groups + rules | ✅ Scenario 2 |
| **F15** | Multi-Client Portal | ✅ 5+ tests | ✅ 5+ tests | ✅ Portal + QR code + DeepLink | ✅ Scenario 2 |
| **F16** | Human-Crafted Zinc/Slate UI | ✅ 5+ tests | ✅ 5+ tests | ✅ Templates rendering & CSS | ✅ Scenario 1 |
| **F17** | Responsive Mobile Layout | ✅ 5+ tests | ✅ 5+ tests | ✅ Viewport, touch targets | ✅ Scenario 1 |
| **F18** | Security & Stealth Hardening | ✅ 5+ tests | ✅ 5+ tests | ✅ Decoy + Secret Path + 2FA | ✅ Scenario 4 |
| **F19** | Deployment Scripts Modernization | ✅ 5+ tests | ✅ 5+ tests | ✅ Script syntax & flags | ✅ Scenario 1 |
| **F20** | GitHub Release & Hygiene | ✅ 5+ tests | ✅ 5+ tests | ✅ Bilingual docs & repo clean | ✅ Scenario 1 |
| **F21** | Opaque-Box E2E Test Suite | ✅ 5+ tests | ✅ 5+ tests | ✅ Framework self-verification | ✅ All Scenarios |

---

## 5. Pass/Fail Criteria & Error Escalation

1. **Pass**:
   - All assertions evaluate to true.
   - All contract return signatures match specification schemas.
   - All responses return expected HTTP status codes and headers.
   - Dynamic YAML configurations successfully parse without syntax errors.
2. **Skip**:
   - Features tagged to subsequent milestones (e.g. M1 warp module when executed in pre-merge state) are cleanly reported as skipped with explanatory reasons, maintaining continuous test execution.
3. **Escalation Protocol**:
   - Any failure in existing production code is captured with reproduction vectors and escalated directly to the responsible milestone specialist.
