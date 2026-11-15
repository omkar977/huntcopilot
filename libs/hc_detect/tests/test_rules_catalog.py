"""The 10 rules of Section 8: one positive and one negative event list each, fixture and hard negatives."""
import json
import time

import pytest

from hc_detect.engine import evaluate, evaluate_rules
from hc_detect.loader import load_rules

from .helpers import auth, dns, fixtures_dir, file_ev, load_sample, net, proc

RULES = {r.id: r for r in load_rules()}
ENC = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAGgAdQBuAHQALQBkAGUAbQBvACkA"


def fired(rule_id, events):
    return evaluate(RULES[rule_id], events)


def test_all_ten_rules_load_with_spec_metadata():
    assert sorted(RULES) == [f"HC-{i:03d}" for i in range(1, 11)]
    assert RULES["HC-001"].severity == 4 and RULES["HC-001"].mitre.techniques == ["T1566.001", "T1059.001"]
    assert RULES["HC-007"].severity == 5 and RULES["HC-008"].mitre.techniques == ["T1003.002", "T1003.003"]
    assert {r.type for r in RULES.values()} == {"single", "sequence", "threshold", "periodicity"}


def test_hc001_office_spawns_powershell():
    assert len(fired("HC-001", [proc(0, "powershell.exe", parent="winword.exe")])) == 1
    assert fired("HC-001", [proc(0, "powershell.exe", parent="explorer.exe"), proc(1, "cmd.exe", parent="winword.exe")]) == []


def test_hc002_encoded_powershell_and_exclusion():
    assert len(fired("HC-002", [proc(0, "powershell.exe", cmdline=ENC)])) == 1
    assert len(fired("HC-002", [proc(0, "powershell.exe", cmdline="powershell.exe -EncodedCommand SQBFAFgAIAAoAA==")])) == 1
    assert len(fired("HC-002", [proc(0, "powershell.exe", cmdline="powershell.exe -e SQBFAFgAIAAoAA==")])) == 1
    negatives = [
        proc(0, "powershell.exe", cmdline="powershell.exe -NoProfile -File x.ps1"),
        proc(1, "powershell.exe", cmdline="powershell.exe -e short"),
        proc(2, "python.exe", cmdline="python.exe build.py --data SGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ="),
        proc(3, "powershell.exe", cmdline=ENC, host="WS-08", user="adm_it"),
    ]
    assert fired("HC-002", negatives) == []


def test_hc003_encoded_powershell_then_outbound_within_120s():
    assert len(fired("HC-003", [proc(0, "powershell.exe", cmdline=ENC), net(100, "203.0.113.50")])) == 1
    late = [proc(0, "powershell.exe", cmdline=ENC), net(130, "203.0.113.50")]
    assert fired("HC-003", late) == []
    internal = [proc(0, "powershell.exe", cmdline=ENC), net(10, "10.10.2.21", direction="internal")]
    assert fired("HC-003", internal) == []
    excluded = [proc(0, "powershell.exe", cmdline=ENC, host="WS-08", user="adm_it"), net(10, "198.51.100.5", host="WS-08")]
    assert fired("HC-003", excluded) == []


def test_hc004_remote_exec_tools_and_exclusion():
    positives = [
        proc(0, "psexec.exe", cmdline=r"psexec.exe \\10.10.2.31 -accepteula cmd.exe"),
        proc(1, "wmic.exe", cmdline="wmic.exe /node:10.10.2.21 process call create cmd.exe"),
        proc(2, "winrs.exe", cmdline="winrs.exe -r:10.10.2.21 cmd"),
    ]
    assert len(fired("HC-004", positives)) == 3
    negatives = [
        proc(0, "psexec.exe", cmdline="psexec.exe -h", host="WS-03"),
        proc(1, "wmic.exe", cmdline="wmic.exe os get caption"),
        proc(2, "psexec.exe", cmdline=r"psexec.exe \\10.10.2.31 cmd", host="WS-08", user="adm_it"),
    ]
    assert fired("HC-004", negatives) == []


def test_hc005_fanout_and_svc_backup_exclusion():
    ips = [f"10.10.2.{i}" for i in range(21, 27)]
    positive = [net(i * 30, ip, port=445, direction="internal", user="adm_it") for i, ip in enumerate(ips[:4])]
    assert len(fired("HC-005", positive)) == 1
    three = [net(i * 30, ip, port=445, direction="internal") for i, ip in enumerate(ips[:3])]
    assert fired("HC-005", three) == []
    nightly = [net(i * 10, ip, port=445, direction="internal", host="FILE-01", user="svc_backup") for i, ip in enumerate(ips)]
    assert fired("HC-005", nightly) == []
    other_port = [net(i * 30, ip, port=443, direction="internal") for i, ip in enumerate(ips[:4])]
    assert fired("HC-005", other_port) == []


def test_hc006_psexesvc():
    assert len(fired("HC-006", [proc(0, "psexesvc.exe", parent="services.exe", host="DB-01")])) == 1
    assert fired("HC-006", [proc(0, "psexec.exe"), proc(1, "services.exe")]) == []


def test_hc007_lsass_dump():
    positives = [
        proc(0, "procdump.exe", cmdline=r"procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp", host="DB-01"),
        proc(1, "rundll32.exe", cmdline=r"C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 612 C:\Windows\Temp\d.dmp full"),
    ]
    assert len(fired("HC-007", positives)) == 2
    negatives = [proc(0, "procdump.exe", cmdline="procdump.exe -ma chrome.exe c.dmp"),
                 proc(1, "rundll32.exe", cmdline="rundll32.exe shell32.dll,Control_RunDLL")]
    assert fired("HC-007", negatives) == []


def test_hc008_credential_store_extraction():
    positives = [
        proc(0, "reg.exe", cmdline=r"reg.exe save HKLM\SAM C:\Windows\Temp\sam.save", host="DB-01"),
        proc(1, "reg.exe", cmdline=r"reg save HKLM\SYSTEM C:\Windows\Temp\system.save"),
        proc(2, "ntdsutil.exe", cmdline=r"ntdsutil.exe ifm create full C:\Windows\Temp\ntds", host="DC-01"),
    ]
    assert len(fired("HC-008", positives)) == 3
    negatives = [proc(0, "reg.exe", cmdline=r"reg.exe query HKLM\SOFTWARE\Microsoft"),
                 proc(1, "reg.exe", cmdline=r"reg.exe save HKLM\SOFTWARE C:\x.hiv")]
    assert fired("HC-008", negatives) == []


def test_hc009_beaconing_and_update_server_exclusion():
    beacon = [net(i * 60 + (i % 5), "203.0.113.50", host="DB-01") for i in range(16)]
    assert len(fired("HC-009", beacon)) == 1
    updater = [net(i * 300, "198.51.100.77") for i in range(20)]
    assert fired("HC-009", updater) == []
    jittery = [net(t, "198.51.100.9") for t in (0, 3, 40, 700, 705, 1500, 1503, 2300, 2400, 3300, 3305, 3900, 4100, 5000, 5004, 6100)]
    assert fired("HC-009", jittery) == []
    few = [net(i * 60, "203.0.113.50") for i in range(10)]
    assert fired("HC-009", few) == []


def test_hc010_executable_in_appdata_roaming():
    assert len(fired("HC-010", [file_ev(0, r"C:\Users\carol\AppData\Roaming\update.exe"),
                                file_ev(1, r"C:\Users\carol\AppData\Roaming\x\helper.dll")])) == 2
    negatives = [file_ev(0, r"C:\Users\carol\AppData\Roaming\notes.txt"),
                 file_ev(1, r"C:\Users\carol\Downloads\setup.exe"),
                 file_ev(2, r"C:\Users\carol\AppData\Local\Temp\a.exe")]
    assert fired("HC-010", negatives) == []


def test_fixture_expected_alerts():
    expected = json.loads((fixtures_dir() / "expected_alerts.json").read_text(encoding="utf-8"))
    alerts = evaluate_rules(RULES.values(), load_sample())
    pairs = {(a.rule_id, a.host) for a in alerts}
    for item in expected["must_fire"]:
        assert (item["rule_id"], item["host"]) in pairs, item
    for item in expected["must_not_fire"]:
        if "host" in item:
            assert (item["rule_id"], item["host"]) not in pairs, item
        else:
            assert all(a.rule_id != item["rule_id"] for a in alerts), item


def test_fixture_alerts_are_idempotent_and_valid():
    events = load_sample()
    first = evaluate_rules(RULES.values(), events)
    assert first == evaluate_rules(RULES.values(), events)
    assert len({a.alert_id for a in first}) == len(first)


def test_hard_negatives_do_not_alert():
    b64 = "SGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyBmb3IgZGV2ZWxvcGVycw=="
    events = []
    # 1 adm_it encoded PowerShell on WS-08 with outbound traffic right after
    events += [proc(0, "powershell.exe", cmdline=ENC, host="WS-08", user="adm_it"), net(20, "198.51.100.8", host="WS-08", user="heidi")]
    # 2 adm_it psexec from WS-08 to one server
    events += [proc(100, "psexec.exe", cmdline=r"psexec.exe \\10.10.2.31 ipconfig", host="WS-08", user="adm_it")]
    # 3 svc_backup fan-out on 445 at night
    events += [net(200 + i, f"10.10.2.{20 + i}", port=445, direction="internal", host="FILE-01", user="svc_backup") for i in range(7)]
    # 4 updater beacon every 300 s
    events += [net(300 + i * 300, "198.51.100.77", host=f"WS-0{h}") for h in (1, 2) for i in range(20)]
    # 5 developer command lines with base64 text but no encoded-command flag
    events += [proc(10 + i, "python.exe", cmdline=f"python.exe tool.py --payload {b64}", host="WS-02", user="bob") for i in range(5)]
    assert evaluate_rules(RULES.values(), events) == []


def test_engine_handles_50000_events_within_30_seconds():
    events = []
    for i in range(50000):
        host = f"WS-0{1 + i % 8}"
        if i % 5 == 0:
            ev = net(i * 1.5, f"198.51.100.{i % 200}", host=host, user="alice")
        elif i % 5 == 1:
            ev = proc(i * 1.5, "chrome.exe", cmdline="chrome.exe --type=renderer", parent="explorer.exe", host=host)
        elif i % 5 == 2:
            ev = dns(i * 1.5, f"site{i % 40}.corp.test", host=host)
        elif i % 5 == 3:
            ev = net(i * 1.5, "10.10.2.21", port=445, direction="internal", host=host)
        else:
            ev = file_ev(i * 1.5, rf"C:\Users\u\Documents\f{i}.xlsx", host=host)
        events.append(ev)
    events.append(auth(10, host="DB-01"))
    started = time.perf_counter()
    evaluate_rules(RULES.values(), events)
    assert time.perf_counter() - started < 30


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_every_rule_has_tactics_and_techniques(rule_id):
    rule = RULES[rule_id]
    assert rule.mitre.tactics and rule.mitre.techniques and rule.description
