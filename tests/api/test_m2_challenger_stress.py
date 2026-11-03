"""
InnerBlitz Hysteria 2 Next-Gen Panel (3x-ui Overhaul)
Empirical Adversarial Stress Test Suite: Challenger M2 Verification

Adversarial & Boundary Focus Areas:
1. Routing rule priority collision and tie-breaking (`priority ASC, id ASC`).
2. Large CIDR lists and IPv6 edge cases in `ip_cidr` rules.
3. Malformed domain and rule values handling in validation endpoints.
4. Precedence verification: verify private subnets are never bypassed by user rules.
5. Inverted or overlapping port hopping range strings.
6. Atomic rollback verification: verify that a syntax-broken configuration leaves the running config untouched and preserves the `.bak` backup.
7. Subscription profile export escaping and validity in Sing-box JSON and Clash Meta YAML.
"""

import json
import os
import shutil
import tempfile
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List

import yaml
from starlette.testclient import TestClient

from app.config import settings
from app.database import crud
from app.database.models import RoutingRuleCreate, RoutingRuleUpdate, ReorderRulesRequest
from app.api.routing_routes import _validate_single_value
from app.core.hysteria import (
    compile_acl_rules,
    build_hysteria_yaml,
    validate_hysteria_config,
    apply_and_save_config,
)
from app.core.firewall import validate_port_hopping_string, configure_port_hopping
from app.core.subscription import (
    build_hy2_uri,
    build_clash_yaml,
    build_singbox_json,
)
from tests.e2e.harness import OpaqueE2ETestCase


class TestRoutingRulePriorityTieBreaking(OpaqueE2ETestCase):
    """
    Adversarial Challenge 1:
    Stress-test routing rule priority collisions, tie-breaking (priority ASC, id ASC),
    negative and extreme priorities, and deterministic ACL order.
    """

    def setUp(self):
        super().setUp()
        self.login_admin()

    def test_priority_collision_and_deterministic_tie_breaking(self):
        """
        Verify that multiple rules with the EXACT same priority are deterministically
        sorted and evaluated strictly by `id ASC`.
        """
        created_rules = []
        # Create 6 rules all with identical priority = 100
        for i in range(1, 7):
            rule_payload = RoutingRuleCreate(
                name=f"Rule_Collision_{i}",
                action="direct" if i % 2 == 0 else "block",
                rule_type="domain",
                rule_values=[f"collision-{i}.example.com"],
                priority=100,
                enabled=True,
            )
            rule = self.run_async(crud.create_routing_rule(rule_payload))
            created_rules.append(rule)

        rule_ids = [r["id"] for r in created_rules]
        self.assertEqual(len(rule_ids), 6)
        self.assertEqual(rule_ids, sorted(rule_ids))

        # 1. Verify DB query orders by (priority ASC, id ASC)
        db_rules = self.run_async(crud.get_routing_rules(enabled_only=True))
        fetched_ids = [r["id"] for r in db_rules]
        self.assertEqual(fetched_ids, rule_ids)

        # 2. Verify REST API returns identical deterministic order
        resp = self.client.get("/api/routing/rules")
        self.assertEqual(resp.status_code, 200)
        api_rules = resp.json()
        api_ids = [r["id"] for r in api_rules]
        self.assertEqual(api_ids, rule_ids)

        # 3. Verify compile_acl_rules preserves exact tie-breaking order
        acl = compile_acl_rules(db_rules, global_outbound="direct")
        # Extract matching collision rules from ACL
        acl_collision_lines = [line for line in acl if "collision-" in line]
        expected_lines = []
        for r in created_rules:
            action_tag = "reject" if r["action"] == "block" else "direct"
            expected_lines.append(f"{action_tag}(domain:{r['rule_values'][0]})")
        self.assertEqual(acl_collision_lines, expected_lines)

    def test_negative_zero_and_extreme_priorities(self):
        """
        Verify sorting with negative priority (-50), zero (0), intermediate,
        and very large priority (999999).
        """
        priors = [999999, -50, 0, 10, -50, 500]
        created = []
        for idx, p in enumerate(priors):
            r = self.run_async(
                crud.create_routing_rule(
                    RoutingRuleCreate(
                        name=f"Rule_Prio_{p}_{idx}",
                        action="direct",
                        rule_type="domain",
                        rule_values=[f"prio-{idx}.com"],
                        priority=p,
                        enabled=True,
                    )
                )
            )
            created.append(r)

        # Query from DB
        db_rules = self.run_async(crud.get_routing_rules())
        # Python reference sort by (priority, id)
        expected_sorted = sorted(created, key=lambda r: (r["priority"], r["id"]))
        expected_ids = [r["id"] for r in expected_sorted]
        actual_ids = [r["id"] for r in db_rules]
        self.assertEqual(actual_ids, expected_ids)

        # First two must be the negative ones (-50), broken by id ASC
        neg_rules = [r for r in db_rules if r["priority"] == -50]
        self.assertEqual(len(neg_rules), 2)
        self.assertLess(neg_rules[0]["id"], neg_rules[1]["id"])

    def test_precedence_collision_resolution(self):
        """
        When two conflicting rules target the same domain (one WARP, one DIRECT),
        the rule with lower priority (or lower ID on tie) must appear first in ACL.
        """
        # Rule 1: Warp example.com (priority 50, id lower)
        r1 = self.run_async(
            crud.create_routing_rule(
                RoutingRuleCreate(
                    name="Target_Warp",
                    action="warp",
                    rule_type="domain",
                    rule_values=["conflict.example.com"],
                    priority=50,
                )
            )
        )
        # Rule 2: Direct example.com (priority 50, id higher)
        r2 = self.run_async(
            crud.create_routing_rule(
                RoutingRuleCreate(
                    name="Target_Direct",
                    action="direct",
                    rule_type="domain",
                    rule_values=["conflict.example.com"],
                    priority=50,
                )
            )
        )

        presets = {"warp_enabled": "1"}
        db_rules = self.run_async(crud.get_routing_rules(enabled_only=True))
        acl = compile_acl_rules(db_rules, global_outbound="direct", presets=presets)

        # Rule 1 (ID r1['id']) has lower id so warp rule comes first
        warp_line = "outbound(warp, domain:conflict.example.com)"
        direct_line = "direct(domain:conflict.example.com)"
        self.assertIn(warp_line, acl)
        self.assertIn(direct_line, acl)
        self.assertLess(acl.index(warp_line), acl.index(direct_line))

        # Now elevate Rule 2 by setting priority = 10 (higher precedence)
        self.run_async(
            crud.update_routing_rule(
                r2["id"],
                RoutingRuleUpdate(priority=10),
            )
        )
        updated_rules = self.run_async(crud.get_routing_rules(enabled_only=True))
        acl_elevated = compile_acl_rules(updated_rules, global_outbound="direct", presets=presets)
        self.assertLess(acl_elevated.index(direct_line), acl_elevated.index(warp_line))


class TestLargeCIDRListsAndIPv6EdgeCases(OpaqueE2ETestCase):
    """
    Adversarial Challenge 2:
    Stress-test large CIDR lists and IPv6 edge cases in `ip_cidr` rules across
    validation, persistence, ACL compilation, and subscription export.
    """

    def setUp(self):
        super().setUp()
        self.login_admin()

    def test_ipv6_syntax_validation_matrix(self):
        """
        Verify parsing and validation for full, compressed, link-local, loopback,
        and CIDR-prefixed IPv6 notation.
        """
        valid_ipv6 = [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
            "2001:db8::/32",
            "::1/128",
            "::/0",
            "fe80::/10",
            "ff00::/8",
            "2001:4860:4860::8888",
            "cidr:2001:db8::/48",
            "::ffff:192.0.2.1/128",  # IPv4-mapped IPv6
            "2001:db8:a::123/64",
        ]

        for ip in valid_ipv6:
            ok, msg = _validate_single_value("ip_cidr", ip)
            self.assertTrue(ok, f"Expected '{ip}' to be valid IPv6/CIDR, got error: {msg}")

        invalid_ipv6 = [
            "2001:::1",           # Triple colons
            "fe80::1/130",        # Prefix > 128
            "192.168.1.1/33",     # IPv4 prefix > 32
            "2001:xyz::1",        # Non-hex character
            "2001:db8::1/abc",    # Non-numeric prefix
            "999.999.999.999/24", # Invalid IPv4
            "1.2.3.4.5/24",       # Five octets
            "::",                 # Valid IPv6 address
        ]
        # Notice "::" is valid IPv6 address
        for ip in invalid_ipv6:
            if ip == "::":
                ok, _ = _validate_single_value("ip_cidr", ip)
                self.assertTrue(ok)
            else:
                ok, msg = _validate_single_value("ip_cidr", ip)
                self.assertFalse(ok, f"Expected '{ip}' to be invalid IPv6/CIDR, but passed!")

    def test_large_cidr_list_scale_stress(self):
        """
        Create a rule with 200+ mixed IPv4 and IPv6 CIDR networks.
        Stress-test SQLite serialization, ACL compilation, Sing-box JSON, and Clash YAML export.
        """
        cidrs = []
        # 100 IPv4 subnets
        for i in range(1, 101):
            cidrs.append(f"198.51.{i}.0/24")
        # 100 IPv6 subnets
        for i in range(1, 101):
            cidrs.append(f"2001:db8:{hex(i)[2:]}::/48")

        self.assertEqual(len(cidrs), 200)

        # 1. Create rule in DB
        rule_payload = RoutingRuleCreate(
            name="Mega_CIDR_Filter",
            action="block",
            rule_type="ip_cidr",
            rule_values=cidrs,
            priority=100,
            enabled=True,
        )
        created = self.run_async(crud.create_routing_rule(rule_payload))
        self.assertEqual(len(created["rule_values"]), 200)

        # 2. Retrieve rule from DB and verify no data corruption
        fetched = self.run_async(crud.get_routing_rule_by_id(created["id"]))
        self.assertIsNotNone(fetched)
        self.assertEqual(len(fetched["rule_values"]), 200)
        self.assertEqual(fetched["rule_values"][0], "198.51.1.0/24")
        self.assertEqual(fetched["rule_values"][-1], "2001:db8:64::/48")

        # 3. Test compile_acl_rules
        acl = compile_acl_rules([fetched], global_outbound="direct")
        acl_rejects = [line for line in acl if line.startswith("reject(")]
        # All 200 CIDRs + 5 built-in RFC1918 + ads/spy defaults must be present
        self.assertGreaterEqual(len(acl_rejects), 205)
        for c in cidrs:
            self.assertIn(f"reject({c})", acl)

        # 4. Test Clash Meta YAML export
        user = {"username": "cidr_user", "password": "pass"}
        settings_dict = {"listen_port": 443}
        clash_yaml = build_clash_yaml(user, settings_dict, routing_rules=[fetched])
        parsed_clash = yaml.safe_load(clash_yaml)
        self.assertIsInstance(parsed_clash, dict)
        rules = parsed_clash.get("rules", [])
        # Check first and last CIDR present as IP-CIDR,clean,REJECT,no-resolve
        self.assertIn("IP-CIDR,198.51.1.0/24,REJECT,no-resolve", rules)
        self.assertIn("IP-CIDR,2001:db8:64::/48,REJECT,no-resolve", rules)

        # 5. Test Sing-box JSON export
        singbox = build_singbox_json(user, settings_dict, routing_rules=[fetched])
        self.assertIsInstance(singbox, dict)
        route_rules = singbox.get("route", {}).get("rules", [])
        cidr_rule = next((r for r in route_rules if "ip_cidr" in r and r.get("outbound") == "block"), None)
        self.assertIsNotNone(cidr_rule)
        self.assertEqual(len(cidr_rule["ip_cidr"]), 200)
        self.assertEqual(cidr_rule["ip_cidr"][0], "198.51.1.0/24")
        self.assertEqual(cidr_rule["ip_cidr"][-1], "2001:db8:64::/48")


class TestMalformedRoutingValidationEndpoints(OpaqueE2ETestCase):
    """
    Adversarial Challenge 3:
    Stress-test malformed domain, pattern, and rule values in validation endpoints
    and creation handlers.
    """

    def setUp(self):
        super().setUp()
        self.login_admin()

    def test_validate_endpoint_raw_rule_syntax(self):
        """Test POST /api/routing/validate with valid and malformed raw ACL strings."""
        valid_raw = [
            "direct(domain:example.com)",
            "outbound(warp, geosite:google)",
            "reject(geoip:cn)",
            "block(domain:bad.com)",
            "direct(1.1.1.1/32)",
        ]
        for r in valid_raw:
            resp = self.client.post("/api/routing/validate", json={"raw_rule": r})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertTrue(data.get("valid"), f"Expected '{r}' to be valid, got: {data}")

        invalid_raw = [
            "drop(domain:example.com)",      # Unsupported action
            "direct()",                      # Empty matcher
            "direct(   )",                   # Whitespace matcher
            "not_a_rule",                    # Missing parens
            "direct(domain:example.com",     # Unclosed paren
            "(domain:example.com)",          # Missing action
        ]
        for r in invalid_raw:
            resp = self.client.post("/api/routing/validate", json={"raw_rule": r})
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Expected '{r}' to be invalid, but passed: {data}")

        # Finding: /api/routing/validate accepts 'outbound(warp)' because it only checks
        # action in allowed set and non-empty body, whereas validate_hysteria_config enforces two-part format.
        resp_outbound = self.client.post("/api/routing/validate", json={"raw_rule": "outbound(warp)"})
        self.assertEqual(resp_outbound.status_code, 200)
        self.assertTrue(resp_outbound.json().get("valid"))

        # However, validate_hysteria_config rejects 'outbound(warp)' missing pattern
        is_val, err_msg = validate_hysteria_config("""
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
acl:
  inline:
    - outbound(warp)
""")
        self.assertFalse(is_val)
        self.assertIn("expected: outbound(name, pattern)", err_msg.lower())

    def test_validate_endpoint_structured_validation(self):
        """Test POST /api/routing/validate with structured payloads."""
        # 1. Invalid actions
        for bad_action in ["drop", "proxy", "forward", "", None]:
            resp = self.client.post(
                "/api/routing/validate",
                json={"action": bad_action, "rule_type": "domain", "rule_values": ["example.com"]},
            )
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Action '{bad_action}' should be rejected")

        # 2. Invalid rule types
        for bad_type in ["regex", "port", "protocol", "", None]:
            resp = self.client.post(
                "/api/routing/validate",
                json={"action": "direct", "rule_type": bad_type, "rule_values": ["example.com"]},
            )
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Rule type '{bad_type}' should be rejected")

        # 3. Empty rule values
        for bad_vals in [[], "", None]:
            resp = self.client.post(
                "/api/routing/validate",
                json={"action": "direct", "rule_type": "domain", "rule_values": bad_vals},
            )
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Empty rule_values '{bad_vals}' should be rejected")

        # 4. Bad domain values (spaces, empty)
        bad_domains = ["example .com", "bad domain", ""]
        for d in bad_domains:
            resp = self.client.post(
                "/api/routing/validate",
                json={"action": "direct", "rule_type": "domain", "rule_values": [d]},
            )
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Bad domain '{d}' should be rejected")

        # 5. Bad GeoIP values (too long, punctuation)
        bad_geoips = ["RUSSIA_FEDERATION", "RU!", "1", ""]
        for g in bad_geoips:
            resp = self.client.post(
                "/api/routing/validate",
                json={"action": "direct", "rule_type": "geoip", "rule_values": [g]},
            )
            data = resp.json()
            self.assertFalse(data.get("valid"), f"Bad GeoIP '{g}' should be rejected")

        # 6. Bad keywords
        resp = self.client.post(
            "/api/routing/validate",
            json={"action": "direct", "rule_type": "keyword", "rule_values": ["***"]},
        )
        self.assertFalse(resp.json().get("valid"))

    def test_routing_rules_create_endpoint_enforces_validation(self):
        """Verify POST /api/routing/rules rejects empty name, empty values, or invalid schema."""
        # Empty name
        resp1 = self.client.post(
            "/api/routing/rules",
            json={"name": "   ", "action": "direct", "rule_type": "domain", "rule_values": ["example.com"]},
        )
        self.assertEqual(resp1.status_code, 400)

        # Empty rule_values
        resp2 = self.client.post(
            "/api/routing/rules",
            json={"name": "Test", "action": "direct", "rule_type": "domain", "rule_values": []},
        )
        self.assertEqual(resp2.status_code, 400)

        # Invalid action (Pydantic schema validation error)
        resp3 = self.client.post(
            "/api/routing/rules",
            json={"name": "Test", "action": "illegal_action", "rule_type": "domain", "rule_values": ["example.com"]},
        )
        self.assertEqual(resp3.status_code, 422)


class TestPrivateSubnetPrecedenceBypassProtection(OpaqueE2ETestCase):
    """
    Adversarial Challenge 4:
    Verify that private RFC 1918 & RFC 4193 subnets can NEVER be bypassed or overridden
    by user-defined routing rules in Hysteria ACL, Clash Meta, or Sing-box.
    """

    def setUp(self):
        super().setUp()
        self.login_admin()

    def test_private_subnets_always_precede_user_rules_in_acl(self):
        """
        Create aggressive user rules attempting to force direct or warp routing
        on private subnets with highest priority (priority 1).
        Verify private subnet reject rules strictly precede user rules in Hysteria ACL.
        """
        # User rule 1: Direct 10.0.0.0/8 and 192.168.1.0/24 with priority 1
        r1 = self.run_async(
            crud.create_routing_rule(
                RoutingRuleCreate(
                    name="Exploit_Bypass_Private_Direct",
                    action="direct",
                    rule_type="ip_cidr",
                    rule_values=["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8"],
                    priority=1,
                    enabled=True,
                )
            )
        )
        # User rule 2: Warp 172.16.0.0/12 and fc00::/7 with priority 1
        r2 = self.run_async(
            crud.create_routing_rule(
                RoutingRuleCreate(
                    name="Exploit_Bypass_Private_Warp",
                    action="warp",
                    rule_type="ip_cidr",
                    rule_values=["172.16.0.0/12", "fc00::/7"],
                    priority=1,
                    enabled=True,
                )
            )
        )

        db_rules = self.run_async(crud.get_routing_rules(enabled_only=True))
        presets = {"warp_enabled": "1"}
        acl = compile_acl_rules(db_rules, global_outbound="direct", presets=presets)

        # Essential private subnet rejection rules
        mandatory_rejects = [
            "reject(10.0.0.0/8)",
            "reject(172.16.0.0/12)",
            "reject(192.168.0.0/16)",
            "reject(127.0.0.0/8)",
            "reject(fc00::/7)",
        ]

        # Verify every private subnet reject exists
        for r_line in mandatory_rejects:
            self.assertIn(r_line, acl)

        # Find maximum index of mandatory reject rules
        max_reject_idx = max(acl.index(r_line) for r_line in mandatory_rejects)

        # User rules (if present) must appear AFTER all mandatory private subnet rejections
        for line in acl:
            if "direct(10.0.0.0/8)" in line or "outbound(warp, 172.16.0.0/12)" in line:
                user_rule_idx = acl.index(line)
                self.assertGreater(
                    user_rule_idx,
                    max_reject_idx,
                    f"Precedence violation: user rule '{line}' at index {user_rule_idx} precedes private reject at {max_reject_idx}",
                )

    def test_private_subnets_precedence_in_client_profiles(self):
        """
        Verify that in Clash Meta and Sing-box profiles, LAN/private subnet rules
        are evaluated before custom user rules.
        """
        user = {"username": "prec_user", "password": "pass"}
        settings_dict = {"listen_port": 443}

        # User rule targeting 10.0.0.0/8 as PROXY / block
        custom_rules = [
            {
                "id": 1,
                "name": "User_LAN_Override",
                "action": "warp",
                "rule_type": "ip_cidr",
                "rule_values": ["10.0.0.0/8"],
                "enabled": True,
            }
        ]

        # 1. Clash Meta check
        clash_yaml = build_clash_yaml(user, settings_dict, routing_rules=custom_rules)
        parsed_clash = yaml.safe_load(clash_yaml)
        rules = parsed_clash.get("rules", [])

        lan_direct_idx = rules.index("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve")
        user_proxy_idx = rules.index("IP-CIDR,10.0.0.0/8,PROXY,no-resolve")
        self.assertLess(
            lan_direct_idx,
            user_proxy_idx,
            "In Clash Meta, private direct subnet rule must precede user custom rule",
        )

        # 2. Sing-box check
        sb = build_singbox_json(user, settings_dict, routing_rules=custom_rules)
        route_rules = sb.get("route", {}).get("rules", [])

        ip_is_private_rule = next((r for r in route_rules if r.get("ip_is_private") is True), None)
        self.assertIsNotNone(ip_is_private_rule)
        private_idx = route_rules.index(ip_is_private_rule)

        user_sb_rule = next((r for r in route_rules if "10.0.0.0/8" in r.get("ip_cidr", [])), None)
        self.assertIsNotNone(user_sb_rule)
        user_idx = route_rules.index(user_sb_rule)
        self.assertLess(
            private_idx,
            user_idx,
            "In Sing-box, ip_is_private rule must precede user custom ip_cidr rule",
        )


class TestPortHoppingInvertedAndBoundaryRanges(OpaqueE2ETestCase):
    """
    Adversarial Challenge 5:
    Stress-test inverted port ranges, overlapping ranges, boundary values,
    and multi-range normalization.
    """

    def test_inverted_ranges_rejected(self):
        """Inverted ranges (start > end) must always be rejected."""
        inverted_inputs = [
            "50000:20000",
            "50000-20000",
            "1000:500",
            "65535:1",
            "443-80",
            "20000-30000, 40000-35000",  # Second range inverted
        ]
        for inv in inverted_inputs:
            ok, msg = validate_port_hopping_string(inv)
            self.assertFalse(ok, f"Expected '{inv}' to be rejected as inverted, but got True")
            self.assertIn("inverted", msg.lower(), f"Expected 'inverted' in error message for '{inv}', got: '{msg}'")

    def test_boundary_and_malformed_ports(self):
        """Out of bounds ports (0, >65535) and non-numeric inputs must be rejected."""
        malformed = [
            "0:1000",            # Port 0 is invalid
            "1000:70000",         # Port > 65535
            "65536",              # Port > 65535
            "0",                  # Port 0
            "-100:500",           # Negative port
            "abc",                # Non-numeric
            "20000:abc",          # Non-numeric
            "20000:30000:40000",  # Too many colons
            "",                   # Empty
            "   ",                # Whitespace
            ",",                  # Comma only
        ]
        for m in malformed:
            ok, msg = validate_port_hopping_string(m)
            self.assertFalse(ok, f"Expected '{m}' to be rejected, but got True: {msg}")

    def test_valid_complex_and_overlapping_ranges(self):
        """
        Verify valid port hopping configurations, including single ports,
        comma-separated lists, and multi-range inputs across subscription builders.
        """
        valid_inputs = [
            "20000:50000",
            "20000-50000",
            "443",
            "443, 8443, 20000-30000",
            "20000-20000",          # Single port range
            "20000-30000, 25000-35000",  # Overlapping ranges
        ]
        for v in valid_inputs:
            ok, msg = validate_port_hopping_string(v)
            self.assertTrue(ok, f"Expected '{v}' to be accepted, got: {msg}")

        # Verify overlapping range in subscription builders
        user = {"username": "hop_user", "password": "pass"}
        # Case A: range without internal whitespace
        settings_dict_compact = {
            "server_domain": "hop.example.com",
            "listen_port": 443,
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:30000,25000:35000",
        }
        uri_compact = build_hy2_uri(user, settings_dict_compact)
        self.assertIn("mport=20000-30000%2C25000-35000", uri_compact)

        # Case B: range with space after comma
        settings_dict_spaced = {
            "server_domain": "hop.example.com",
            "listen_port": 443,
            "port_hopping_enabled": True,
            "port_hopping_range": "20000:30000, 25000:35000",
        }
        uri_spaced = build_hy2_uri(user, settings_dict_spaced)
        # urlencode encodes space after comma as '+'
        self.assertIn("mport=20000-30000%2C+25000-35000", uri_spaced)

        # 2. Clash Meta YAML
        clash_yaml = build_clash_yaml(user, settings_dict_compact)
        parsed_c = yaml.safe_load(clash_yaml)
        self.assertEqual(parsed_c["proxies"][0]["ports"], "20000-30000,25000-35000")

        # 3. Sing-box JSON
        sb = build_singbox_json(user, settings_dict_compact)
        self.assertEqual(sb["outbounds"][0]["server_ports"], "20000-30000,25000-35000")


class TestAtomicRollbackOnBrokenConfig(OpaqueE2ETestCase):
    """
    Adversarial Challenge 6:
    Stress-test atomic write and rollback behavior when attempting to apply
    corrupted, syntactically broken, or invalid configurations.
    Verify running config remains untouched and backup is preserved.
    """

    def setUp(self):
        super().setUp()
        self.login_admin()
        self.config_path = Path(settings.HYSTERIA_CONFIG_PATH)
        self.backup_path = Path(str(settings.HYSTERIA_CONFIG_PATH) + ".bak")

        # Initialize valid baseline configuration
        res = self.run_async(apply_and_save_config())
        self.assertTrue(res.success)
        self.assertTrue(self.config_path.exists())
        self.initial_config_content = self.config_path.read_text(encoding="utf-8")

    def test_rollback_on_invalid_yaml_syntax(self):
        """Broken YAML syntax must be rejected, leaving config.yaml intact."""
        broken_yaml = "listen: [this is broken yaml unclosed\nauth: {unclosed"

        res = self.run_async(apply_and_save_config(custom_yaml=broken_yaml))
        self.assertFalse(res.success)
        self.assertIn("validation failed", res.message.lower())

        # Verify active config was NOT overwritten
        current_content = self.config_path.read_text(encoding="utf-8")
        self.assertEqual(current_content, self.initial_config_content)

        # Verify no stray temporary files
        temp_files = list(self.config_path.parent.glob(f"{self.config_path.name}.tmp.*"))
        self.assertEqual(len(temp_files), 0)

    def test_rollback_on_missing_mandatory_keys(self):
        """YAML valid syntax but missing mandatory keys ('listen', 'tls', 'auth') must be rejected."""
        missing_keys_yaml = """
bandwidth:
  up: 100 mbps
  down: 100 mbps
ignoreClientBandwidth: false
"""
        res = self.run_async(apply_and_save_config(custom_yaml=missing_keys_yaml))
        self.assertFalse(res.success)
        self.assertIn("missing required", res.message.lower())

        # Config remains untouched
        current_content = self.config_path.read_text(encoding="utf-8")
        self.assertEqual(current_content, self.initial_config_content)

    def test_rollback_on_broken_acl_outbound_reference(self):
        """Valid YAML with ACL rule referencing nonexistent outbound must be rejected."""
        # 1. When outbounds are defined, unknown outbound is caught
        broken_acl_with_outbounds = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
outbounds:
  - name: direct
    type: direct
acl:
  inline:
    - outbound(nonexistent_warp_target, domain:evil.com)
"""
        res = self.run_async(apply_and_save_config(custom_yaml=broken_acl_with_outbounds))
        self.assertFalse(res.success)
        self.assertIn("unknown outbound", res.message.lower())

        # Config remains untouched
        current_content = self.config_path.read_text(encoding="utf-8")
        self.assertEqual(current_content, self.initial_config_content)

        # 2. Finding: when outbounds is omitted, validate_hysteria_config skips the check
        broken_acl_without_outbounds = """
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: http
  http:
    url: http://127.0.0.1:28262/auth
acl:
  inline:
    - outbound(nonexistent_target, domain:evil.com)
"""
        is_val, _ = validate_hysteria_config(broken_acl_without_outbounds)
        # Documented finding: returns True because known_outbounds is empty
        self.assertTrue(is_val)

    def test_backup_preservation_and_restoration(self):
        """
        Verify that creating a valid configuration creates a .bak backup,
        and that a subsequent failed save preserves the previous valid state.
        """
        # Save valid config V2
        valid_v2 = self.initial_config_content.replace("up: 200 mbps", "up: 500 mbps")
        res_v2 = self.run_async(apply_and_save_config(custom_yaml=valid_v2))
        self.assertTrue(res_v2.success)
        self.assertTrue(self.backup_path.exists())
        self.assertIn("up: 500 mbps", self.config_path.read_text(encoding="utf-8"))

        # Attempt to save invalid config V3
        res_v3 = self.run_async(apply_and_save_config(custom_yaml="invalid: [broken"))
        self.assertFalse(res_v3.success)

        # Active config must still be V2
        self.assertIn("up: 500 mbps", self.config_path.read_text(encoding="utf-8"))
        # Backup must still be preserved
        self.assertTrue(self.backup_path.exists())


class TestSubscriptionProfileEscapingAndValidity(OpaqueE2ETestCase):
    """
    Adversarial Challenge 7:
    Stress-test subscription profile export escaping with special characters,
    complex rules, and verify validity in Sing-box JSON, Clash Meta YAML, and hy2:// URI.
    """

    def test_special_characters_in_credentials(self):
        """
        Usernames and passwords with URI special characters (#, ?, &, :, /, @, \", +)
        must round-trip cleanly in hy2:// URIs, Clash Meta, and Sing-box profiles.
        """
        user = {
            "username": "user+test@domain.org;admin#1",
            "password": 'p@ss"w/ord&special=1:2#tag',
        }
        settings_dict = {
            "server_domain": "edge.vpn.example.com",
            "listen_port": 443,
            "obfs_type": "salamander",
            "obfs_password": 'obfs"secret&1',
        }

        # 1. hy2:// URI check
        uri = build_hy2_uri(user, settings_dict)
        self.assertTrue(uri.startswith("hy2://"))

        # Parse URI
        parsed = urllib.parse.urlsplit(uri)
        # Verify credentials can be cleanly decoded
        unquoted_user = urllib.parse.unquote(parsed.username)
        unquoted_pass = urllib.parse.unquote(parsed.password)
        self.assertEqual(unquoted_user, user["username"])
        self.assertEqual(unquoted_pass, user["password"])

        # 2. Clash Meta YAML check
        clash_yaml = build_clash_yaml(user, settings_dict)
        parsed_c = yaml.safe_load(clash_yaml)
        self.assertIsInstance(parsed_c, dict)
        proxy = parsed_c["proxies"][0]
        self.assertEqual(proxy["password"], f"{user['username']}:{user['password']}")
        self.assertEqual(proxy["obfs-password"], settings_dict["obfs_password"])

        # 3. Sing-box JSON check
        sb = build_singbox_json(user, settings_dict)
        # Ensure round-trip serialization
        serialized = json.dumps(sb)
        deserialized = json.loads(serialized)
        outbound = deserialized["outbounds"][0]
        self.assertEqual(outbound["password"], f"{user['username']}:{user['password']}")
        self.assertEqual(outbound["obfs"]["password"], settings_dict["obfs_password"])

    def test_custom_routing_rules_escaping_and_mapping(self):
        """
        Verify all 6 rule types (domain, suffix, keyword, ip_cidr, geoip, geosite)
        with special pattern characters map properly into both Clash YAML and Sing-box JSON.
        """
        user = {"username": "testuser", "password": "testpassword"}
        settings_dict = {"listen_port": 443}

        custom_rules = [
            {
                "id": 1,
                "name": "Domain Rule",
                "action": "direct",
                "rule_type": "domain",
                "rule_values": ["domain:api-v2.service.co.uk", "sub.internal.net"],
                "enabled": True,
            },
            {
                "id": 2,
                "name": "Suffix Rule",
                "action": "warp",
                "rule_type": "suffix",
                "rule_values": ["domain-suffix:corp.internal", "suffix:github.io"],
                "enabled": True,
            },
            {
                "id": 3,
                "name": "Keyword Rule",
                "action": "block",
                "rule_type": "keyword",
                "rule_values": ["*telemetry-logger*", "keyword:adserver"],
                "enabled": True,
            },
            {
                "id": 4,
                "name": "CIDR Rule",
                "action": "direct",
                "rule_type": "ip_cidr",
                "rule_values": ["cidr:192.0.2.0/24", "2001:db8:1234::/48"],
                "enabled": True,
            },
            {
                "id": 5,
                "name": "GeoIP Rule",
                "action": "warp",
                "rule_type": "geoip",
                "rule_values": ["geoip:us", "de"],
                "enabled": True,
            },
            {
                "id": 6,
                "name": "Geosite Rule",
                "action": "block",
                "rule_type": "geosite",
                "rule_values": ["geosite:tiktok", "category-porn"],
                "enabled": True,
            },
        ]

        # 1. Clash Meta YAML verification
        clash_yaml = build_clash_yaml(user, settings_dict, routing_rules=custom_rules)
        parsed_c = yaml.safe_load(clash_yaml)
        rules = parsed_c.get("rules", [])

        # Check DOMAIN
        self.assertIn("DOMAIN,api-v2.service.co.uk,DIRECT", rules)
        self.assertIn("DOMAIN,sub.internal.net,DIRECT", rules)
        # Check DOMAIN-SUFFIX
        self.assertIn("DOMAIN-SUFFIX,corp.internal,PROXY", rules)
        self.assertIn("DOMAIN-SUFFIX,github.io,PROXY", rules)
        # Check DOMAIN-KEYWORD
        self.assertIn("DOMAIN-KEYWORD,telemetry-logger,REJECT", rules)
        self.assertIn("DOMAIN-KEYWORD,adserver,REJECT", rules)
        # Check IP-CIDR
        self.assertIn("IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", rules)
        self.assertIn("IP-CIDR,2001:db8:1234::/48,DIRECT,no-resolve", rules)
        # Check GEOIP
        self.assertIn("GEOIP,US,PROXY", rules)
        self.assertIn("GEOIP,DE,PROXY", rules)
        # Check GEOSITE
        self.assertIn("GEOSITE,tiktok,REJECT", rules)
        self.assertIn("GEOSITE,category-porn,REJECT", rules)

        # 2. Sing-box JSON verification
        sb = build_singbox_json(user, settings_dict, routing_rules=custom_rules)
        serialized = json.dumps(sb)
        deserialized = json.loads(serialized)
        sb_rules = deserialized.get("route", {}).get("rules", [])

        # Domain rule check
        d_rule = next((r for r in sb_rules if "domain" in r), None)
        self.assertIsNotNone(d_rule)
        self.assertEqual(d_rule["domain"], ["api-v2.service.co.uk", "sub.internal.net"])
        self.assertEqual(d_rule["outbound"], "direct")

        # Suffix rule check
        s_rule = next((r for r in sb_rules if "domain_suffix" in r), None)
        self.assertIsNotNone(s_rule)
        self.assertEqual(s_rule["domain_suffix"], ["corp.internal", "github.io"])
        self.assertEqual(s_rule["outbound"], f"InnerBlitz-{user['username']}")

        # Keyword rule check
        k_rule = next((r for r in sb_rules if "domain_keyword" in r), None)
        self.assertIsNotNone(k_rule)
        self.assertEqual(k_rule["domain_keyword"], ["telemetry-logger", "adserver"])
        self.assertEqual(k_rule["outbound"], "block")

        # IP CIDR rule check
        c_rule = next((r for r in sb_rules if "ip_cidr" in r and "192.0.2.0/24" in r["ip_cidr"]), None)
        self.assertIsNotNone(c_rule)
        self.assertEqual(c_rule["ip_cidr"], ["192.0.2.0/24", "2001:db8:1234::/48"])
        self.assertEqual(c_rule["outbound"], "direct")

        # GeoIP rule check
        g_rule = next((r for r in sb_rules if "geoip" in r and "us" in r["geoip"]), None)
        self.assertIsNotNone(g_rule)
        self.assertEqual(g_rule["geoip"], ["us", "de"])

        # Geosite rule check
        gs_rule = next((r for r in sb_rules if "geosite" in r and "tiktok" in r["geosite"]), None)
        self.assertIsNotNone(gs_rule)
        self.assertEqual(gs_rule["geosite"], ["tiktok", "category-porn"])
        self.assertEqual(gs_rule["outbound"], "block")
