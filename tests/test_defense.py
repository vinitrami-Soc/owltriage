import pytest

from triage.defense import BlockRule, parse_allowlist, plan_blocks, render_script
from triage.detectors import Finding


def finding(ip, severity="high", block="inbound", rule="BAD_IP_MATCH"):
    return Finding(rule, severity, "test", ip=ip, block=block)


def test_commands_for_ipv4_ipv6_and_outbound():
    rules, _ = plan_blocks([finding("203.0.113.5"), finding("2001:db8::bad"),
                            finding("203.0.113.99", block="outbound")])
    assert [r.command() for r in rules] == [
        "iptables -A INPUT -s 203.0.113.5 -j DROP",
        "ip6tables -A INPUT -s 2001:db8::bad -j DROP",
        "iptables -A OUTPUT -d 203.0.113.99 -j DROP",
    ]


def test_duplicate_findings_become_one_rule_with_all_reasons():
    rules, _ = plan_blocks([finding("203.0.113.5", rule="SSH_BRUTE_FORCE"),
                            finding("203.0.113.5", rule="COMPROMISE_SUSPECTED")])
    assert len(rules) == 1
    assert rules[0].reasons == ["SSH_BRUTE_FORCE", "COMPROMISE_SUSPECTED"]


def test_allowlist_loopback_and_low_severity_are_never_blocked():
    allow = parse_allowlist(["192.168.1.0/24"])
    rules, skipped = plan_blocks([finding("192.168.1.10"), finding("127.0.0.1"),
                                  finding("203.0.113.7", severity="low")], allow)
    assert rules == []
    assert dict(skipped) == {"192.168.1.10": "allowlisted", "127.0.0.1": "special-purpose address"}


def test_non_ip_text_never_reaches_a_shell_command():
    rules, _ = plan_blocks([finding("1.2.3.4; rm -rf /"), finding("$(reboot)")])
    assert rules == []


def test_bad_allowlist_entry_raises():
    with pytest.raises(ValueError):
        parse_allowlist(["not-a-network"])


def test_script_is_idempotent_and_has_undo():
    script = render_script([BlockRule("203.0.113.5", "inbound", ["SSH_BRUTE_FORCE"])])
    assert "iptables -C INPUT -s 203.0.113.5 -j DROP 2>/dev/null || iptables -A INPUT -s 203.0.113.5 -j DROP" in script
    assert "# iptables -D INPUT -s 203.0.113.5 -j DROP" in script
