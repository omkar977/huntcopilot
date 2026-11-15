"""Generator acceptance tests (spec 7.5): validity, determinism, volume, hard negatives, scenarios."""
import base64
import ipaddress
import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime

import pytest

from generator.core import GenConfig, build_events, to_line
from hc_common.schemas import Event


@pytest.fixture(scope="module")
def eval_data():
    return build_events(GenConfig(profile="eval", scenarios=["apt_chain"], seed=2002))


@pytest.fixture(scope="module")
def train_data():
    return build_events(GenConfig(profile="benign_train"))


def ts(e):
    return datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))


def test_every_event_is_schema_valid(eval_data):
    events, _ = eval_data
    for e in events:
        Event.model_validate(e)
        assert e["gt"] is not None and isinstance(e["gt"]["is_malicious"], bool)
        assert e["ts"].endswith("Z") and "." not in e["ts"]


def test_volume_in_range_and_malicious_share(eval_data):
    events, labels = eval_data
    assert 40_000 <= len(events) <= 60_000
    assert labels["malicious_count"] / len(events) >= 0.005
    assert sum(1 for e in events if e["gt"]["is_malicious"]) == labels["malicious_count"]


def test_sorted_and_unique_ids(eval_data):
    events, _ = eval_data
    assert [e["ts"] for e in events] == sorted(e["ts"] for e in events)
    assert len({e["event_id"] for e in events}) == len(events)
    assert all(re.fullmatch(r"[0-9a-f]{32}", e["event_id"]) for e in events)


def test_deterministic_byte_identical(eval_data):
    events, labels = eval_data
    again, labels2 = build_events(GenConfig(profile="eval", scenarios=["apt_chain"], seed=2002))
    assert "\n".join(map(to_line, events)) == "\n".join(map(to_line, again))
    assert labels == labels2


def test_different_seed_differs(eval_data):
    events, _ = eval_data
    other, _ = build_events(GenConfig(profile="eval", scenarios=["apt_chain"], seed=7))
    assert [e["event_id"] for e in other][:50] != [e["event_id"] for e in events][:50]
    assert to_line(other[100]) != to_line(events[100])


def test_train_profile_has_no_attacks_and_is_tagged(train_data):
    events, labels = train_data
    assert 40_000 <= len(events) <= 60_000
    assert not any(e["gt"]["is_malicious"] for e in events)
    assert all(e["tags"] == ["train"] for e in events)
    assert labels["malicious_count"] == 0 and labels["scenarios"] == {}
    assert len(labels["hard_negatives"]) == 5


def test_eval_not_tagged_train(eval_data):
    assert not any("train" in e["tags"] for e in eval_data[0])


def test_default_seeds_and_days_differ_between_profiles(eval_data, train_data):
    assert eval_data[1]["seed"] == 2002 and train_data[1]["seed"] == 1001
    assert eval_data[0][0]["ts"][:10] != train_data[0][0]["ts"][:10]


def test_benign_train_rejects_scenarios():
    with pytest.raises(ValueError):
        GenConfig(profile="benign_train", scenarios=["c2"]).validate()
    with pytest.raises(ValueError):
        GenConfig(profile="eval", scenarios=["nope"]).validate()
    with pytest.raises(ValueError):
        GenConfig(duration_hours=0).validate()
    with pytest.raises(ValueError):
        GenConfig(start="2026-11-12T00:30:00Z").validate()


def test_diurnal_curve(eval_data):
    events, _ = eval_data
    by_hour = Counter(int(e["ts"][11:13]) for e in events if not e["gt"]["is_malicious"])
    busy = statistics.mean(by_hour[h] for h in range(8, 18))
    quiet = statistics.mean(by_hour[h] for h in (0, 1, 2, 3, 22, 23))
    assert busy > 2.5 * quiet


def test_events_per_host_hour_scales_volume():
    small, _ = build_events(GenConfig(profile="benign_train", events_per_host_hour=100, duration_hours=6))
    big, _ = build_events(GenConfig(profile="benign_train", events_per_host_hour=300, duration_hours=6))
    assert len(big) > 2 * len(small)


def test_duration_limits_window():
    events, _ = build_events(GenConfig(profile="benign_train", duration_hours=3))
    assert max(e["ts"] for e in events) < "2026-11-11T03:00:00Z"


def test_safe_content_only(eval_data):
    events, _ = eval_data
    external = ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")
    internal = ipaddress.ip_network("10.10.0.0/16")
    for e in events:
        for ip in filter(None, [e["host_ip"], (e["net"] or {}).get("src_ip"), (e["net"] or {}).get("dst_ip")]):
            addr = ipaddress.ip_address(ip)
            assert addr in internal or any(addr in n for n in external), ip
        if e["dns"]:
            assert e["dns"]["query"].endswith(".test")
    c2 = [e for e in events if e["event_type"] == "dns_query" and "badhost" in e["dns"]["query"]]
    assert c2 and all(e["dns"]["query"] == "cdn-sync.badhost.test" for e in c2)


def test_hosts_users_and_assets(eval_data):
    events, _ = eval_data
    hosts = {e["host"] for e in events}
    assert hosts == {f"WS-0{i}" for i in range(1, 9)} | {"FILE-01", "DB-01", "DC-01", "WEB-01"}
    assert {"adm_it", "svc_backup", "svc_web"} <= {e["user"] for e in events}


# ----------------------------------------------------------------- hard negatives (spec 7.3)
def _by_hn(eval_data, name):
    events, labels = eval_data
    ids = set(labels["hard_negatives"][name]["event_ids"])
    return [e for e in events if e["event_id"] in ids]


def test_all_five_hard_negatives_present(eval_data):
    assert set(eval_data[1]["hard_negatives"]) == {
        "adm_powershell", "adm_psexec", "backup_fanout", "update_beacon", "dev_base64"}
    assert all(not e["gt"]["is_malicious"] for n in eval_data[1]["hard_negatives"] for e in _by_hn(eval_data, n))


def test_hn1_admin_encoded_powershell(eval_data):
    evs = _by_hn(eval_data, "adm_powershell")
    assert len(evs) == 3
    for e in evs:
        assert e["host"] == "WS-08" and e["user"] == "adm_it" and e["process"]["name"] == "powershell.exe"
        blob = e["process"]["cmdline"].split("-enc ")[1]
        assert base64.b64decode(blob).decode().isascii()


def test_hn2_admin_psexec(eval_data):
    evs = [e for e in _by_hn(eval_data, "adm_psexec") if e["event_type"] == "process_create"]
    assert len(evs) == 1 and evs[0]["host"] == "WS-08" and evs[0]["process"]["name"] == "psexec.exe"
    assert "\\\\10.10." in evs[0]["process"]["cmdline"]


def test_hn3_backup_fanout(eval_data):
    evs = [e for e in _by_hn(eval_data, "backup_fanout") if e["event_type"] == "network_conn"]
    assert len({e["net"]["dst_ip"] for e in evs}) >= 6
    assert all(e["net"]["dst_port"] == 445 and e["user"] == "svc_backup" for e in evs)
    assert all(e["ts"][11:13] in ("02", "01", "03") for e in evs)


def test_hn4_update_beacon(eval_data):
    evs = _by_hn(eval_data, "update_beacon")
    per_host = defaultdict(list)
    for e in evs:
        assert e["net"]["dst_ip"] == "198.51.100.77" and e["net"]["dst_port"] == 443
        per_host[e["host"]].append(ts(e))
    assert len(per_host) == 8
    for times in per_host.values():
        gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        assert 290 <= statistics.mean(gaps) <= 310
        assert max(gaps) <= 300 * 1.03 + 1 and min(gaps) >= 300 * 0.97 - 1


def test_hn5_dev_base64_without_encoded_flag(eval_data):
    evs = _by_hn(eval_data, "dev_base64")
    assert evs and all(e["host"] == "WS-02" for e in evs)
    for e in evs:
        cmd = e["process"]["cmdline"]
        assert len(cmd) > 60 and re.search(r"[A-Za-z0-9+/]{24,}={0,2}", cmd)
        assert not re.search(r"(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{8,}", cmd)


# ----------------------------------------------------------------- independent sanity check of the rules
ENC = re.compile(r"(?i)-(enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}")


def test_encoded_powershell_only_phishing_and_admin(eval_data):
    events, _ = eval_data
    hits = [e for e in events if e["event_type"] == "process_create" and e["process"]["name"] == "powershell.exe"
            and ENC.search(e["process"]["cmdline"])]
    assert {(e["host"], e["user"]) for e in hits if e["gt"]["is_malicious"]} == {("WS-03", "carol")}
    assert {(e["host"], e["user"]) for e in hits if not e["gt"]["is_malicious"]} == {("WS-08", "adm_it")}


def test_lateral_fanout_threshold_only_backup_and_attack(eval_data):
    events, _ = eval_data
    cand = defaultdict(list)
    for e in events:
        n = e["net"]
        if e["event_type"] == "network_conn" and n["direction"] == "internal" and n["dst_port"] in (445, 135, 5985):
            cand[e["host"]].append(e)
    flagged = defaultdict(set)
    for host, evs in cand.items():
        for i, first in enumerate(evs):
            window = [x for x in evs[i:] if (ts(x) - ts(first)).total_seconds() <= 600]
            if len({x["net"]["dst_ip"] for x in window}) >= 4:
                flagged[host].update(x["user"] for x in window)
    assert set(flagged) == {"FILE-01", "WS-03"}
    assert flagged["FILE-01"] == {"svc_backup"}  # the rule excludes this user
    assert "adm_it" in flagged["WS-03"]


def test_periodicity_only_update_server_and_c2(eval_data):
    events, _ = eval_data
    groups = defaultdict(list)
    for e in events:
        if e["event_type"] == "network_conn" and e["net"]["direction"] == "outbound":
            groups[(e["host"], e["net"]["dst_ip"])].append(ts(e))
    periodic = set()
    for key, times in groups.items():
        for i in range(len(times)):
            window = [t for t in times[i:] if (t - times[i]).total_seconds() <= 7200]
            if len(window) >= 15:
                gaps = [(b - a).total_seconds() for a, b in zip(window, window[1:])]
                if statistics.pstdev(gaps) / statistics.mean(gaps) <= 0.25:
                    periodic.add(key[1])
    assert periodic == {"198.51.100.77", "203.0.113.50"}


# ----------------------------------------------------------------- scenarios (spec 7.4)
def _scn(eval_data, comp):
    events, labels = eval_data
    ids = set(labels["scenarios"]["apt_chain"]["components"][comp]["event_ids"])
    return [e for e in events if e["event_id"] in ids]


def test_labels_structure(eval_data):
    events, labels = eval_data
    apt = labels["scenarios"]["apt_chain"]
    assert set(apt["components"]) == {"phishing", "c2_ws03", "lateral_movement", "credential_dumping", "c2_db01"}
    assert set(apt["hosts"]) >= {"WS-03", "DB-01", "DC-01", "FILE-01", "WS-05", "WS-06"}
    assert apt["event_count"] == labels["malicious_count"] == sum(c["event_count"] for c in apt["components"].values())
    assert "10:00:00Z" <= apt["t0"][11:] <= "15:00:00Z"
    assert {e["gt"]["scenario"] for e in events if e["gt"]["is_malicious"]} == {"apt_chain"}
    json.dumps(labels)


def test_phishing_chain(eval_data):
    evs = _scn(eval_data, "phishing")
    t0 = ts(evs[0])
    assert [int((ts(e) - t0).total_seconds()) for e in evs] == [0, 2, 8, 10, 12, 20]
    f1, word, ps, dns_e, conn, drop = evs
    assert f1["file"]["path"].endswith("invoice_4471.docm") and f1["gt"]["stage"] == "initial_access"
    assert word["process"]["name"] == "winword.exe" and word["process"]["parent_name"] == "outlook.exe"
    assert "invoice_4471.docm" in word["process"]["cmdline"]
    assert ps["process"]["parent_name"] == "winword.exe" and ps["process"]["parent_pid"] == word["process"]["pid"]
    assert ps["process"]["cmdline"].startswith("powershell.exe -nop -w hidden -enc ")
    assert base64.b64decode(ps["process"]["cmdline"].split("-enc ")[1]).decode() == "hunt-demo"
    assert ps["gt"]["stage"] == "execution"
    assert dns_e["dns"]["query"] == "cdn-sync.badhost.test"
    assert conn["net"]["dst_ip"] == "203.0.113.50" and conn["net"]["dst_port"] == 443
    assert 4000 <= conn["net"]["bytes_out"] <= 4400
    assert drop["file"]["path"].endswith("AppData\\Roaming\\update.exe")
    assert {e["host"] for e in evs} == {"WS-03"} and {e["user"] for e in evs} == {"carol"}


def test_lateral_movement(eval_data):
    evs = _scn(eval_data, "lateral_movement")
    fails = [e for e in evs if e["event_type"] == "auth" and e["auth"]["result"] == "failure"]
    assert len(fails) == 3 and {e["host"] for e in fails} == {"FILE-01"}
    assert all(e["auth"]["logon_type"] == 3 for e in fails)
    conns = [e for e in evs if e["event_type"] == "network_conn"]
    assert {e["net"]["dst_host"] for e in conns} == {"FILE-01", "DB-01", "WS-05", "WS-06"}
    assert {e["net"]["dst_port"] for e in conns} == {445, 135, 5985}
    assert all(e["host"] == "WS-03" and e["net"]["direction"] == "internal" for e in conns)
    ok = [e for e in evs if e["event_type"] == "auth" and e["auth"]["result"] == "success"]
    assert {e["host"] for e in ok} == {"FILE-01", "DB-01", "WS-05", "WS-06"}
    assert all(e["auth"]["src_host"] == "WS-03" and e["auth"]["target_user"] == "adm_it" for e in ok)
    svc = [e for e in evs if e["event_type"] == "process_create" and e["process"]["name"] == "psexesvc.exe"]
    assert {e["host"] for e in svc} == {"FILE-01", "DB-01", "WS-05", "WS-06"}
    assert all(e["process"]["parent_name"] == "services.exe" for e in svc)
    ws03 = {e["process"]["name"]: e for e in evs if e["event_type"] == "process_create" and e["host"] == "WS-03"}
    assert "\\\\10.10.2.31" in ws03["psexec.exe"]["process"]["cmdline"]
    assert "/node:10.10.2.21" in ws03["wmic.exe"]["process"]["cmdline"]
    assert ws03["wmic.exe"]["process"]["parent_name"] == "powershell.exe"
    span = max(ts(e) for e in conns) - min(ts(e) for e in conns)
    assert span.total_seconds() <= 600
    assert all(e["gt"]["stage"] == "lateral_movement" for e in evs)


def test_credential_dumping(eval_data):
    evs = _scn(eval_data, "credential_dumping")
    procs = {e["process"]["name"]: e for e in evs if e["event_type"] == "process_create"}
    assert "-ma lsass.exe C:\\Windows\\Temp\\lsass.dmp" in procs["procdump.exe"]["process"]["cmdline"]
    assert procs["procdump.exe"]["process"]["parent_name"] == "cmd.exe"
    assert "comsvcs.dll, MiniDump 612 C:\\Windows\\Temp\\d.dmp full" in procs["rundll32.exe"]["process"]["cmdline"]
    assert "save HKLM\\SAM C:\\Windows\\Temp\\sam.save" in procs["reg.exe"]["process"]["cmdline"]
    assert procs["ntdsutil.exe"]["host"] == "DC-01"
    assert "ifm" in procs["ntdsutil.exe"]["process"]["cmdline"] and "create full" in procs["ntdsutil.exe"]["process"]["cmdline"]
    assert any(e["event_type"] == "file_create" and e["file"]["path"].endswith("lsass.dmp") for e in evs)
    assert {e["host"] for e in evs} == {"DB-01", "DC-01"}
    assert all(e["gt"]["stage"] == "credential_access" for e in evs)


@pytest.mark.parametrize("comp,host", [("c2_ws03", "WS-03"), ("c2_db01", "DB-01")])
def test_c2_beacon(eval_data, comp, host):
    evs = _scn(eval_data, comp)
    conns = [e for e in evs if e["event_type"] == "network_conn"]
    dns_e = [e for e in evs if e["event_type"] == "dns_query"]
    assert len(conns) == len(dns_e) >= 100 and {e["host"] for e in evs} == {host}
    assert all(e["net"]["dst_ip"] == "203.0.113.50" and 300 <= e["net"]["bytes_out"] <= 420 for e in conns)
    times = [ts(e) for e in conns]
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    assert 54 <= min(gaps) and max(gaps) <= 66.5 and statistics.pstdev(gaps) / statistics.mean(gaps) < 0.1
    assert (times[-1] - times[0]).total_seconds() >= 7000
    assert any(e["event_type"] == "process_create" and e["process"]["name"] == "rundll32.exe" for e in evs)
    assert all(e["gt"]["stage"] == "c2" for e in evs)


def test_apt_chain_timeline(eval_data):
    t0 = ts(_scn(eval_data, "phishing")[0])
    first = lambda c: int((ts(_scn(eval_data, c)[0]) - t0).total_seconds())  # noqa: E731
    assert first("c2_ws03") == 300
    assert first("lateral_movement") == 900
    assert first("credential_dumping") == 1800
    assert first("c2_db01") == 2100


def test_master_acceptance_data_shape(eval_data):
    """Top finding needs the PowerShell host plus at least 2 lateral hosts."""
    events, _ = eval_data
    ps_hosts = {e["host"] for e in events if e["gt"]["is_malicious"] and e["event_type"] == "process_create"
                and e["process"]["name"] == "powershell.exe"}
    lateral = {e["net"]["dst_host"] for e in events if e["gt"]["stage"] == "lateral_movement"
               and e["event_type"] == "network_conn"}
    assert ps_hosts == {"WS-03"} and len(lateral) >= 2


@pytest.mark.parametrize("name", ["phishing", "lateral_movement", "credential_dumping", "c2"])
def test_each_standalone_scenario(name):
    events, labels = build_events(GenConfig(profile="eval", scenarios=[name], duration_hours=24))
    assert set(labels["scenarios"]) == {name}
    assert labels["scenarios"][name]["event_count"] > 0
    assert {e["gt"]["scenario"] for e in events if e["gt"]["is_malicious"]} == {name}


def test_performance_50k_in_60s():
    import time
    t = time.monotonic()
    events, _ = build_events(GenConfig(profile="eval", events_per_host_hour=380))
    lines = [to_line(e) for e in events]
    assert time.monotonic() - t <= 60 and len(lines) >= 50_000
