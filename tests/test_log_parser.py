from triage.log_parser import extract_ips, normalize_ip, parse_line, url_decode


def test_failed_password_for_invalid_user():
    ev = parse_line("Nov  9 03:05:04 web01 sshd[2388]: Failed password for invalid user oracle "
                    "from 198.51.100.23 port 40122 ssh2")
    assert ev.kind == "ssh_failed"
    assert ev.user == "oracle"
    assert ev.ip == "198.51.100.23"
    assert ev.timestamp == "Nov  9 03:05:04"


def test_accepted_publickey_with_fingerprint():
    ev = parse_line("Nov  9 03:00:14 web01 sshd[2301]: Accepted publickey for sysadmin from 192.168.1.10 "
                    "port 51022 ssh2: ED25519 SHA256:Su4WsgeKmBGbCkmnb6SDo2pV61hNFvG4R/kXSSR7+f4")
    assert (ev.kind, ev.user, ev.ip) == ("ssh_accepted", "sysadmin", "192.168.1.10")


def test_syslog_repeated_message_is_counted():
    ev = parse_line("Nov  9 03:11:55 web01 sshd[2410]: message repeated 3 times: "
                    "[ Failed password for root from 203.0.113.5 port 52314 ssh2]")
    assert (ev.kind, ev.user, ev.repeat) == ("ssh_failed", "root", 3)


def test_crafted_username_cannot_spoof_the_source_ip():
    # ssh 'x from 192.0.2.1 port 22'@server  -> attacker text sits inside the log line
    ev = parse_line("Nov  9 03:00:00 web01 sshd[1]: Failed password for invalid user x from 192.0.2.1 port 22 "
                    "from 203.0.113.5 port 5555 ssh2")
    assert ev.ip == "203.0.113.5"


def test_only_valid_ipv4_addresses_are_extracted():
    text = "bad 999.10.10.10, version 1.2.3.4.5, good 10.0.0.1 and 10.0.0.1 again"
    assert extract_ips(text) == ["10.0.0.1"]


def test_ip_normalization():
    assert normalize_ip("2001:DB8::1") == "2001:db8::1"
    assert normalize_ip("::ffff:192.0.2.5") == "192.0.2.5"
    assert normalize_ip("[2001:db8::2]") == "2001:db8::2"
    assert normalize_ip("not-an-ip") is None


def test_access_log_line_is_decoded():
    ev = parse_line('203.0.113.50 - - [09/Nov/2026:03:16:01 +0000] "GET /p.php?id=1%27%20OR%20%271%27%3D%271 '
                    'HTTP/1.1" 200 9001 "-" "sqlmap/1.8"')
    assert ev.kind == "http_request"
    assert ev.ip == "203.0.113.50"
    assert ev.path == "/p.php?id=1' OR '1'='1"
    assert ev.status == 200
    assert ev.user_agent == "sqlmap/1.8"


def test_double_url_encoding_is_unwrapped():
    assert url_decode("%2527") == "'"
    assert url_decode("a+b") == "a+b"  # '+' kept: it is also a base64 character
