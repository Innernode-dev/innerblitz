import sys
import os
import argparse
import unittest
import time
from pathlib import Path

# Ensure Blitz-main is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def build_suite(tier: int = 0, pattern: str = "test_*.py") -> unittest.TestSuite:
    """Build the test suite filtered by tier or pattern."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    tier_map = {
        1: [
            "tests.e2e.test_tier1_feature_coverage",
            "tests.api.test_client_crud_quotas"
        ],
        2: [
            "tests.e2e.test_tier2_boundary_corner",
            "tests.api.test_custom_routing",
            "tests.api.test_advanced_config_validation"
        ],
        3: [
            "tests.e2e.test_tier3_cross_feature",
            "tests.integration.test_ui_flows"
        ],
        4: [
            "tests.e2e.test_tier4_real_world"
        ],
    }

    if tier in tier_map:
        module_names = tier_map[tier]
        for module_name in module_names:
            try:
                mod_suite = loader.loadTestsFromName(module_name)
                suite.addTests(mod_suite)
            except Exception as e:
                print(f"Error loading {module_name}: {e}", file=sys.stderr)
    else:
        # Load all tiers and sub-packages (api, integration, e2e)
        tests_root = Path(__file__).resolve().parent.parent
        for sub_name in ["api", "integration", "e2e"]:
            sub_dir = tests_root / sub_name
            if sub_dir.is_dir():
                discovered = loader.discover(
                    start_dir=str(sub_dir),
                    pattern=pattern,
                    top_level_dir=str(REPO_ROOT)
                )
                suite.addTests(discovered)

    return suite


def main():
    parser = argparse.ArgumentParser(description="InnerBlitz Hysteria 2 Opaque-Box E2E Test Runner")
    parser.add_argument("--tier", "-t", type=int, choices=[1, 2, 3, 4], default=0, help="Run only tests from specified tier (1, 2, 3, 4)")
    parser.add_argument("--verbose", "-v", action="store_true", default=True, help="Verbose test results")
    parser.add_argument("--failfast", "-f", action="store_true", default=False, help="Stop on first failure")
    args = parser.parse_args()

    print("=" * 70)
    print("InnerBlitz Hysteria 2 Next-Gen Panel — Opaque-Box E2E Test Suite")
    print(f"Target: {'All Tiers (Tiers 1-4)' if args.tier == 0 else f'Tier {args.tier}'}")
    print(f"Python: {sys.version.split()[0]} on {sys.platform}")
    print("=" * 70)

    start_time = time.time()
    suite = build_suite(tier=args.tier)
    test_count = suite.countTestCases()
    print(f"Discovered {test_count} automated test cases.")

    runner = unittest.TextTestRunner(
        verbosity=2 if args.verbose else 1,
        failfast=args.failfast
    )
    result = runner.run(suite)
    duration = time.time() - start_time

    print("\n" + "=" * 70)
    print("E2E TEST EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Total Tests Run : {result.testsRun}")
    print(f"Passed          : {result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)}")
    print(f"Skipped         : {len(result.skipped)}")
    print(f"Failures        : {len(result.failures)}")
    print(f"Errors          : {len(result.errors)}")
    print(f"Duration        : {duration:.2f}s")
    print("=" * 70)

    if result.wasSuccessful():
        print("RESULT: SUCCESS — All executed tests passed cleanly.")
        sys.exit(0)
    else:
        print("RESULT: FAILURE — One or more tests failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
