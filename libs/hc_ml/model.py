"""Train, score, save and load the anomaly model (spec Section 9.2 and 9.4)."""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from hc_common.constants import ASSETS

from . import THRESHOLD
from .cluster import cluster_windows
from .features import (FEATURE_NAMES, KEY, NON_EXPLAINABLE, build_stats, compute_features, events_to_frame,
                       feature_stats, filter_hosts, iso_z, window_id_for, window_table)
from .sequence import MarkovModel

N_MODELS = 5
N_ESTIMATORS = 200
MIN_TRAIN_WINDOWS = 5
STD_FLOOR = 0.1
Z_CAP = 99.0
W_IF, W_SEQ = 0.6, 0.4


ROLE = {a["host"]: a["role"] for a in ASSETS}
GROUPS = ("workstation", "server")


class NoTrainingData(ValueError):
    """Raised when there are no usable training events or windows."""


def group_of(host: str) -> str:
    """Baseline group of a host: workstation, or server for every other asset role."""
    role = ROLE.get(host, "workstation")
    return "workstation" if role == "workstation" else "server"


def _swap_in(root: Path, writer) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    tmp = root / f"current.tmp-{uuid.uuid4().hex[:8]}"
    tmp.mkdir()
    writer(tmp)
    cur = root / "current"
    if cur.exists():
        shutil.rmtree(cur)
    os.replace(tmp, cur)
    return cur


def _norm(values: np.ndarray, p50: float, p99: float) -> np.ndarray:
    return np.clip((values - p50) / max(p99 - p50, 1e-6), 0.0, 1.0)


class PartModel:
    """Scaler, five Isolation Forests, Markov chain and the training statistics they need."""

    def __init__(self, scaler, forests, markov, meta: dict) -> None:
        self.scaler = scaler
        self.forests = forests
        self.markov = markov
        self.meta = meta

    # ----- training -----
    @classmethod
    def train(cls, events: list[dict], seed: int = 1001, require_train_tag: bool = True,
              per_host_rare: bool = False, beacon_min_net: int = 0) -> "PartModel":
        """Fit on events tagged train. Ground truth is never read."""
        df = events_to_frame(events)
        if require_train_tag:
            df = df[df["is_train"]].reset_index(drop=True)
        if len(df) == 0:
            raise NoTrainingData("no events tagged train")
        stats = build_stats(df, per_host_rare, beacon_min_net)
        feats = compute_features(df, stats)
        if len(feats) < MIN_TRAIN_WINDOWS:
            raise NoTrainingData(f"need at least {MIN_TRAIN_WINDOWS} training windows, got {len(feats)}")
        scaler = StandardScaler().fit(feats.to_numpy())
        x = scaler.transform(feats.to_numpy())
        forests = [IsolationForest(n_estimators=N_ESTIMATORS, contamination="auto", random_state=seed + i).fit(x)
                   for i in range(N_MODELS)]
        s_mean = np.mean([-f.decision_function(x) for f in forests], axis=0)
        if_p50, if_p99 = (float(v) for v in np.percentile(s_mean, [50, 99]))
        markov = MarkovModel.fit(df)
        seq = markov.score_windows(df, feats.index).to_numpy()
        seq_p50, seq_p99 = (float(v) for v in np.percentile(seq, [50, 99]))
        mean, std = feature_stats(feats)
        meta = {
            "model_id": uuid.uuid4().hex,
            "trained_at": iso_z(datetime.now(timezone.utc)),
            "seed": seed,
            "feature_names": list(FEATURE_NAMES),
            "train_event_count": int(len(df)),
            "train_window_count": int(len(feats)),
            "if_p50": if_p50, "if_p99": if_p99, "seq_p50": seq_p50, "seq_p99": seq_p99,
            "feature_mean": mean, "feature_std": std, "stats": stats,
        }
        model = cls(scaler, forests, markov, meta)
        meta["train_metrics"] = model.train_metrics(feats, df)
        return model

    def train_metrics(self, feats: pd.DataFrame, df: pd.DataFrame) -> dict:
        """In-sample sanity metrics: share of training windows at or above the threshold."""
        scored = self._score_features(feats, self._seq_raw(df, feats))
        return {
            "n_events": int(len(df)), "n_windows": int(len(feats)), "n_models": N_MODELS,
            "train_windows_over_threshold": float(np.mean(scored["anomaly"] >= THRESHOLD)),
            "mean_anomaly": float(np.mean(scored["anomaly"])),
        }

    # ----- scoring -----
    def _seq_raw(self, df: pd.DataFrame, feats: pd.DataFrame) -> np.ndarray:
        return self.markov.score_windows(df, feats.index).to_numpy()

    def _score_features(self, feats: pd.DataFrame, seq_raw: np.ndarray) -> dict:
        x = self.scaler.transform(feats.to_numpy())
        raw = np.array([-f.decision_function(x) for f in self.forests])
        m = self.meta
        per_model = _norm(raw, m["if_p50"], m["if_p99"])
        a_if = _norm(raw.mean(axis=0), m["if_p50"], m["if_p99"])
        a_seq = _norm(seq_raw, m["seq_p50"], m["seq_p99"])
        anomaly = W_IF * a_if + W_SEQ * a_seq
        unc = np.clip(2 * per_model.std(axis=0) + 0.5 * np.abs(a_if - a_seq), 0.0, 1.0)
        return {"anomaly_if": a_if, "anomaly_seq": a_seq, "anomaly": anomaly, "uncertainty": unc, "x": x}

    def score_events(self, events: list[dict], hosts: Optional[list[str]] = None,
                     threshold: float = THRESHOLD) -> list[dict]:
        """Score every host window. Returns ScoredWindow-shaped dicts sorted by (host, ts_first)."""
        df = events_to_frame(filter_hosts(events, hosts))
        if len(df) == 0:
            return []
        feats = compute_features(df, self.meta["stats"])
        sc = self._score_features(feats, self._seq_raw(df, feats))
        table = window_table(df, feats.index)
        clusters = self._clusters(sc["x"], sc["anomaly"], threshold)
        zs = self._z_matrix(feats)
        out = []
        for i, (host, win) in enumerate(feats.index):
            out.append({
                "window_id": window_id_for(host, win), "host": host,
                "ts_first": table["ts_first"].iloc[i].to_pydatetime(),
                "ts_last": table["ts_last"].iloc[i].to_pydatetime(),
                "event_ids": list(table["event_ids"].iloc[i]),
                "anomaly_if": round(float(sc["anomaly_if"][i]), 4),
                "anomaly_seq": round(float(sc["anomaly_seq"][i]), 4),
                "anomaly": round(float(sc["anomaly"][i]), 4),
                "uncertainty": round(float(sc["uncertainty"][i]), 4),
                "top_features": self._top_features(feats.iloc[i], zs[i]),
                "cluster_id": clusters.get(i),
            })
        return out

    @staticmethod
    def _clusters(x: np.ndarray, anomaly: np.ndarray, threshold: float) -> dict:
        rows = np.where(anomaly >= threshold)[0]
        if len(rows) == 0:
            return {}
        labels = cluster_windows(x[rows])
        return {int(r): int(c) for r, c in zip(rows, labels)}

    def _z_matrix(self, feats: pd.DataFrame) -> np.ndarray:
        mean = np.array([self.meta["feature_mean"][c] for c in FEATURE_NAMES])
        std = np.maximum(np.array([self.meta["feature_std"][c] for c in FEATURE_NAMES]), STD_FLOOR)
        return np.clip((feats.to_numpy() - mean) / std, -Z_CAP, Z_CAP)

    @staticmethod
    def _top_features(row: pd.Series, z: np.ndarray, n: int = 3) -> list[dict]:
        cand = [(FEATURE_NAMES[j], float(row.iloc[j]), float(z[j])) for j in range(len(FEATURE_NAMES))
                if z[j] > 0 and FEATURE_NAMES[j] not in NON_EXPLAINABLE]
        cand.sort(key=lambda t: (-t[2], t[0]))
        return [{"name": a, "value": round(b, 4), "z": round(c, 2)} for a, b, c in cand[:n]]

    # ----- persistence -----
    def write_files(self, target: Path) -> None:
        """Write isoforest_0..4.joblib, scaler.joblib, markov.json and meta.json into target."""
        target.mkdir(parents=True, exist_ok=True)
        for i, f in enumerate(self.forests):
            joblib.dump(f, target / f"isoforest_{i}.joblib")
        joblib.dump(self.scaler, target / "scaler.joblib")
        (target / "markov.json").write_text(json.dumps(self.markov.to_dict()), encoding="utf-8")
        (target / "meta.json").write_text(json.dumps(self.meta, sort_keys=True), encoding="utf-8")

    @classmethod
    def read_files(cls, cur: Path) -> "PartModel":
        """Load from a directory written by write_files. Raises FileNotFoundError when missing."""
        meta_path = cur / "meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"no model in {cur}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        forests = [joblib.load(cur / f"isoforest_{i}.joblib") for i in range(N_MODELS)]
        scaler = joblib.load(cur / "scaler.joblib")
        markov = MarkovModel.from_dict(json.loads((cur / "markov.json").read_text(encoding="utf-8")))
        return cls(scaler, forests, markov, meta)

    def public_meta(self) -> dict:
        """Meta returned by GET /v1/models/current (no bulky statistics)."""
        keys = ["model_id", "trained_at", "feature_names", "train_event_count", "train_window_count", "seed"]
        out = {k: self.meta[k] for k in keys}
        out["train_metrics"] = self.meta.get("train_metrics", {})
        return out

    def feature_baseline(self) -> list[dict]:
        """Training mean and std per feature (for the dashboard z-score view)."""
        return [{"name": n, "mean": self.meta["feature_mean"][n], "std": self.meta["feature_std"][n]}
                for n in FEATURE_NAMES]


class AnomalyModel:
    """Global model plus one baseline per host group (workstation, server).

    Each group has its own scaler, forests, Markov chain, p50/p99 and z-score baseline, so servers are
    not judged against workstation behaviour. A group with too little training data uses the global part.
    """

    def __init__(self, global_part: PartModel, groups: dict[str, PartModel]) -> None:
        self.global_part = global_part
        self.groups = groups

    @property
    def meta(self) -> dict:
        return self.global_part.meta

    @classmethod
    def train(cls, events: list[dict], seed: int = 1001, require_train_tag: bool = True,
              per_group: bool = True, per_host_rare: bool = True, beacon_min_net: int = 0) -> "AnomalyModel":
        """Train the global part and, by default, one part per group (workstation, server).

        Per-group is the default: on M1 data it doubled PR-AUC and lifted recall (Lead run, round 3).
        per_host_rare and beacon_min_net are opt-in false-positive reducers. Ground truth is never read.
        """
        events = list(events)
        glob = PartModel.train(events, seed, require_train_tag, per_host_rare, beacon_min_net)
        groups: dict[str, PartModel] = {}
        for g in GROUPS if per_group else ():
            sub = [e for e in events if group_of(e.get("host", "")) == g]
            try:
                part = PartModel.train(sub, seed, require_train_tag, per_host_rare, beacon_min_net)
            except NoTrainingData:
                continue
            part.meta["model_id"] = glob.meta["model_id"]
            part.meta["trained_at"] = glob.meta["trained_at"]
            groups[g] = part
        glob.meta["groups"] = {g: {"train_event_count": p.meta["train_event_count"],
                                   "train_window_count": p.meta["train_window_count"]} for g, p in groups.items()}
        return cls(glob, groups)

    def score_events(self, events: list[dict], hosts: Optional[list[str]] = None,
                     threshold: float = THRESHOLD) -> list[dict]:
        """Score every host window with its group baseline; cluster ids are unique across groups."""
        evs = filter_hosts(events, hosts)
        buckets: dict[str, list[dict]] = {}
        for e in evs:
            g = group_of(e.get("host", ""))
            buckets.setdefault(g if g in self.groups else "_global", []).append(e)
        out: list[dict] = []
        offset = 0
        for key in sorted(buckets):
            part = self.global_part if key == "_global" else self.groups[key]
            scored = part.score_events(buckets[key], None, threshold)
            ids = [w["cluster_id"] for w in scored if w["cluster_id"] is not None]
            for w in scored:
                if w["cluster_id"] is not None:
                    w["cluster_id"] += offset
            offset += (max(ids) + 1) if ids else 0
            out.extend(scored)
        out.sort(key=lambda w: (w["host"], w["ts_first"]))
        return out

    def save(self, model_dir: str) -> Path:
        """Global files in model_dir/current (spec layout); group parts in current/groups/<name>/."""
        def write(tmp: Path) -> None:
            self.global_part.write_files(tmp)
            for g, p in self.groups.items():
                p.write_files(tmp / "groups" / g)
        return _swap_in(Path(model_dir), write)

    @classmethod
    def load(cls, model_dir: str) -> "AnomalyModel":
        cur = Path(model_dir) / "current"
        glob = PartModel.read_files(cur)
        groups = {g: PartModel.read_files(cur / "groups" / g) for g in GROUPS if (cur / "groups" / g).exists()}
        return cls(glob, groups)

    def public_meta(self) -> dict:
        out = self.global_part.public_meta()
        out["groups"] = self.meta.get("groups", {})
        return out

    def feature_baseline(self) -> list[dict]:
        return self.global_part.feature_baseline()


__all__ = ["AnomalyModel", "PartModel", "NoTrainingData", "KEY", "group_of"]
