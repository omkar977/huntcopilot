"""Event frame, 15-minute host windows and the exact feature set of spec Section 9.1.

Ground-truth labels are never read here: events are reduced to an explicit list of columns.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Iterable, Optional

import numpy as np
import pandas as pd

from . import WINDOW_MINUTES

FEATURE_NAMES = [
    "n_events", "n_process", "n_net", "n_auth", "n_file", "n_dns",
    "distinct_dst_ips", "distinct_dst_ports", "distinct_internal_dst_hosts", "n_smb_winrm",
    "n_ps_encoded", "n_office_child_ps", "n_remote_exec_tools", "n_cred_tools",
    "rare_process_score", "rare_parent_child_score", "bytes_out_sum", "beacon_cv",
    "new_domain_count", "auth_fail_rate", "hour_sin", "hour_cos",
]
# Features that carry no behavioural meaning when explained to an analyst.
NON_EXPLAINABLE = {"hour_sin", "hour_cos"}

KEY = ["host", "win"]
_PS_ENC = re.compile(r"(?:^|\s)[-/](?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
_CRED = re.compile(r"lsass|ntds|\bsam\b", re.IGNORECASE)
_OFFICE = {"winword.exe", "excel.exe", "outlook.exe"}
_REMOTE = {"psexec.exe", "psexesvc.exe", "wmic.exe", "winrs.exe"}
_LATERAL_PORTS = {445, 135, 5985}
_FRAME_COLUMNS = [
    "event_id", "ts", "host", "etype", "pname", "pparent", "cmdline", "dst_ip", "dst_port",
    "direction", "dst_host", "bytes_out", "auth_result", "logon_type", "dns_query", "tok", "is_train",
]


def iso_z(dt) -> str:
    """UTC ISO 8601 with Z suffix and no microseconds."""
    ts = pd.Timestamp(dt)
    if ts.tzinfo is None:
        ts = ts.tz_localize("UTC")
    return ts.tz_convert("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")


def window_id_for(host: str, start) -> str:
    """sha1 hex of host and window start (same rule as hc_common.ids.sha1_hex)."""
    return hashlib.sha1(f"{host}|{iso_z(start)}".encode("utf-8")).hexdigest()


def _file_ext(path: str) -> str:
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else "none"


def _token(etype: str, d: dict) -> str:
    if etype == "process_create":
        return "p:" + str((d.get("process") or {}).get("name", "")).lower()
    if etype == "network_conn":
        return "n:" + str((d.get("net") or {}).get("dst_port", 0))
    if etype == "auth":
        a = d.get("auth") or {}
        return f"a:{a.get('logon_type', 0)}:{a.get('result', '')}"
    if etype == "file_create":
        return "f:" + _file_ext(str((d.get("file") or {}).get("path", "")))
    return "d"


def events_to_frame(events: Iterable[dict]) -> pd.DataFrame:
    """Flatten event dicts into a frame with only the columns the models may use."""
    rows = []
    for d in events:
        et = str(d.get("event_type", ""))
        p = d.get("process") or {}
        n = d.get("net") or {}
        a = d.get("auth") or {}
        q = d.get("dns") or {}
        rows.append((
            d.get("event_id", ""), d.get("ts"), d.get("host", ""), et,
            str(p.get("name", "")).lower(), str(p.get("parent_name", "")).lower(), str(p.get("cmdline", "")),
            str(n.get("dst_ip", "")), int(n.get("dst_port", 0) or 0), str(n.get("direction", "")),
            str(n.get("dst_host", "")), int(n.get("bytes_out", 0) or 0),
            str(a.get("result", "")), int(a.get("logon_type", 0) or 0), str(q.get("query", "")).lower(),
            _token(et, d), "train" in (d.get("tags") or []),
        ))
    df = pd.DataFrame(rows, columns=_FRAME_COLUMNS)
    if len(df):
        df["ts"] = pd.to_datetime(df["ts"], utc=True, format="ISO8601")
        df = df.sort_values(["host", "ts"], kind="mergesort").reset_index(drop=True)
        df["win"] = df["ts"].dt.floor(f"{WINDOW_MINUTES}min")
    else:
        df["win"] = pd.Series(dtype="datetime64[ns, UTC]")
    return df


def build_stats(df: pd.DataFrame, per_host_rare: bool = False, beacon_min_net: int = 0) -> dict:
    """Training statistics needed by rare_* and new_domain_count (computed on training events only).

    per_host_rare adds per-host frequency tables so rare_* compare a host with its own history.
    beacon_min_net makes beacon_cv report 1.0 (no beacon) for windows with fewer network events.
    """
    proc = df[df["etype"] == "process_create"]
    pc = Counter(proc["pname"])
    pairs = Counter(zip(proc["pparent"], proc["pname"]))
    domains = sorted(set(df.loc[df["etype"] == "dns_query", "dns_query"]))
    host_tables: dict = {}
    if per_host_rare:
        for h, g in proc.groupby("host"):
            host_tables[h] = {"proc": dict(Counter(g["pname"])),
                              "pair": {f"{a}>{b}": c for (a, b), c in Counter(zip(g["pparent"], g["pname"])).items()},
                              "n": int(len(g))}
    return {"per_host_rare": per_host_rare, "beacon_min_net": beacon_min_net, "host_tables": host_tables,
        "proc_freq": dict(pc),
        "pair_freq": {f"{a}>{b}": c for (a, b), c in pairs.items()},
        "n_proc": int(len(proc)),
        "domains": domains,
    }


def _neglog_map(counts: dict, total: int) -> tuple[dict, float]:
    v = len(counts)
    denom = total + v + 1
    table = {k: -math.log((c + 1) / denom) for k, c in counts.items()}
    return table, -math.log(1 / denom)


def _group_cv(net: pd.DataFrame) -> pd.Series:
    """Smallest coefficient of variation of gaps for any destination with at least 5 events."""
    if net.empty:
        return pd.Series(dtype=float)
    n = net.sort_values(["host", "win", "dst_ip", "ts"], kind="mergesort").copy()
    n["gap"] = n.groupby(KEY + ["dst_ip"])["ts"].diff().dt.total_seconds()
    g = n.groupby(KEY + ["dst_ip"])["gap"].agg(["count", "mean", "std"])
    g = g[(g["count"] >= 4) & (g["mean"] > 0)]  # 4 gaps means 5 events
    std = n.groupby(KEY + ["dst_ip"])["gap"].std(ddof=0).reindex(g.index)
    cv = std / g["mean"]
    return cv.groupby(level=[0, 1]).min()


def compute_features(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    """Return one row per (host, window) with the 22 features of FEATURE_NAMES (floats)."""
    idx = df.groupby(KEY).size().index
    out = pd.DataFrame(0.0, index=idx, columns=FEATURE_NAMES)
    if len(df) == 0:
        return out
    out["n_events"] = df.groupby(KEY).size().astype(float)
    for col, et in (("n_process", "process_create"), ("n_net", "network_conn"), ("n_auth", "auth"),
                    ("n_file", "file_create"), ("n_dns", "dns_query")):
        out[col] = df[df["etype"] == et].groupby(KEY).size().reindex(idx).fillna(0.0)
    net = df[df["etype"] == "network_conn"]
    out["distinct_dst_ips"] = net.groupby(KEY)["dst_ip"].nunique().reindex(idx).fillna(0.0)
    out["distinct_dst_ports"] = net.groupby(KEY)["dst_port"].nunique().reindex(idx).fillna(0.0)
    internal = net[net["direction"] == "internal"].copy()
    internal["target"] = np.where(internal["dst_host"] != "", internal["dst_host"], internal["dst_ip"])
    out["distinct_internal_dst_hosts"] = internal.groupby(KEY)["target"].nunique().reindex(idx).fillna(0.0)
    smb = internal[internal["dst_port"].isin(_LATERAL_PORTS)]
    out["n_smb_winrm"] = smb.groupby(KEY).size().reindex(idx).fillna(0.0)
    out["bytes_out_sum"] = net.groupby(KEY)["bytes_out"].sum().reindex(idx).fillna(0.0).astype(float)
    out["beacon_cv"] = _group_cv(net).reindex(idx).fillna(1.0)
    min_net = int(stats.get("beacon_min_net", 0))
    if min_net > 0:
        out.loc[out["n_net"] < min_net, "beacon_cv"] = 1.0
    _process_features(df, stats, idx, out)
    dns = df[df["etype"] == "dns_query"]
    known = set(stats.get("domains", []))
    new = dns[~dns["dns_query"].isin(known)]
    out["new_domain_count"] = new.groupby(KEY)["dns_query"].nunique().reindex(idx).fillna(0.0)
    auth = df[df["etype"] == "auth"]
    fails = (auth["auth_result"] == "failure").groupby([auth["host"], auth["win"]]).sum()
    n_auth = out["n_auth"].replace(0, np.nan)
    out["auth_fail_rate"] = (fails.reindex(idx).fillna(0.0) / n_auth).fillna(0.0)
    starts = idx.get_level_values("win")
    hour = np.asarray(starts.hour, dtype=float) + np.asarray(starts.minute, dtype=float) / 60.0
    out["hour_sin"] = np.sin(2 * np.pi * hour / 24.0)
    out["hour_cos"] = np.cos(2 * np.pi * hour / 24.0)
    return out[FEATURE_NAMES]


def _process_features(df: pd.DataFrame, stats: dict, idx: pd.MultiIndex, out: pd.DataFrame) -> None:
    proc = df[df["etype"] == "process_create"].copy()
    if proc.empty:
        return
    ps_cmd = proc["pname"].eq("powershell.exe")
    proc["ps_enc"] = ps_cmd & proc["cmdline"].map(lambda c: bool(_PS_ENC.search(c)))
    proc["office_ps"] = ps_cmd & proc["pparent"].isin(_OFFICE)
    proc["remote"] = proc["pname"].isin(_REMOTE)
    proc["cred"] = proc["cmdline"].map(lambda c: bool(_CRED.search(c)))
    for col, src in (("n_ps_encoded", "ps_enc"), ("n_office_child_ps", "office_ps"),
                     ("n_remote_exec_tools", "remote"), ("n_cred_tools", "cred")):
        out[col] = proc.groupby(KEY)[src].sum().reindex(idx).fillna(0.0).astype(float)
    ptab, punseen = _neglog_map(stats["proc_freq"], stats["n_proc"])
    pair_counts = stats["pair_freq"]
    qtab, qunseen = _neglog_map(pair_counts, stats["n_proc"])
    proc["rare_p"] = proc["pname"].map(ptab).fillna(punseen)
    pair = proc["pparent"] + ">" + proc["pname"]
    proc["rare_pc"] = pair.map(qtab).fillna(qunseen)
    if stats.get("per_host_rare") and stats.get("host_tables"):
        _per_host_rare(proc, pair, stats["host_tables"])
    out["rare_process_score"] = proc.groupby(KEY)["rare_p"].mean().reindex(idx).fillna(0.0)
    out["rare_parent_child_score"] = proc.groupby(KEY)["rare_pc"].mean().reindex(idx).fillna(0.0)


def _per_host_rare(proc: pd.DataFrame, pair: pd.Series, tables: dict) -> None:
    """Overwrite rare_p and rare_pc with per-host scores for hosts that have a training table."""
    lookups = {}
    for h, t in tables.items():
        pt, pu = _neglog_map(t["proc"], t["n"])
        qt, qu = _neglog_map(t["pair"], t["n"])
        lookups[h] = (pt, pu, qt, qu)
    rp, rq = [], []
    for h, name, pr in zip(proc["host"], proc["pname"], pair):
        if h in lookups:
            pt, pu, qt, qu = lookups[h]
            rp.append(pt.get(name, pu))
            rq.append(qt.get(pr, qu))
        else:
            rp.append(np.nan)
            rq.append(np.nan)
    proc["rare_p"] = pd.Series(rp, index=proc.index).fillna(proc["rare_p"])
    proc["rare_pc"] = pd.Series(rq, index=proc.index).fillna(proc["rare_pc"])


def window_table(df: pd.DataFrame, idx: pd.MultiIndex) -> pd.DataFrame:
    """Per-window ts_first, ts_last and event_ids aligned to idx."""
    if len(df) == 0:
        return pd.DataFrame(columns=["ts_first", "ts_last", "event_ids"], index=idx)
    g = df.groupby(KEY)
    tab = pd.DataFrame({"ts_first": g["ts"].min(), "ts_last": g["ts"].max(), "event_ids": g["event_id"].apply(list)})
    return tab.reindex(idx)


def feature_stats(feats: pd.DataFrame) -> tuple[dict, dict]:
    """Per-feature mean and population std over training windows."""
    mean = {c: float(feats[c].mean()) for c in FEATURE_NAMES}
    std = {c: float(feats[c].std(ddof=0)) for c in FEATURE_NAMES}
    return mean, std


def filter_hosts(events: Iterable[dict], hosts: Optional[list[str]]) -> list[dict]:
    """Keep events of the given hosts (all events when hosts is empty or None)."""
    evs = list(events)
    if not hosts:
        return evs
    wanted = set(hosts)
    return [e for e in evs if e.get("host") in wanted]
