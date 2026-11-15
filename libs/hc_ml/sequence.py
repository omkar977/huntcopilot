"""First-order Markov chain over event tokens with Laplace smoothing (alpha = 1)."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import KEY

UNK = "unk"


class MarkovModel:
    """Token transition model. Window score is the mean negative log probability per transition."""

    def __init__(self, vocab: list[str], counts: np.ndarray, alpha: float = 1.0) -> None:
        self.vocab = list(vocab)
        self.index = {t: i for i, t in enumerate(self.vocab)}
        self.counts = counts.astype(float)
        self.alpha = alpha
        v = len(self.vocab)
        row = self.counts.sum(axis=1, keepdims=True)
        self.nll = -np.log((self.counts + alpha) / (row + alpha * v))

    @classmethod
    def fit(cls, df: pd.DataFrame) -> "MarkovModel":
        """Fit on a training frame (columns host, win, tok in time order)."""
        vocab = sorted(set(df["tok"])) + [UNK]
        index = {t: i for i, t in enumerate(vocab)}
        counts = np.zeros((len(vocab), len(vocab)))
        a, b = _transitions(df, index)[:2]
        np.add.at(counts, (a, b), 1.0)
        return cls(vocab, counts)

    def score_windows(self, df: pd.DataFrame, idx: pd.MultiIndex) -> pd.Series:
        """Mean negative log probability per transition for each (host, win) in idx (0 if no transition)."""
        out = pd.Series(0.0, index=idx)
        if len(df) == 0:
            return out
        a, b, gid_keys = _transitions(df, self.index)
        if len(a) == 0:
            return out
        nll = self.nll[a, b]
        mean = pd.Series(nll, index=gid_keys).groupby(level=[0, 1]).mean()
        return mean.reindex(idx).fillna(0.0)

    def to_dict(self) -> dict:
        nz = np.argwhere(self.counts > 0)
        trans = [[int(i), int(j), int(self.counts[i, j])] for i, j in nz]
        return {"alpha": self.alpha, "vocab": self.vocab, "transitions": trans}

    @classmethod
    def from_dict(cls, data: dict) -> "MarkovModel":
        v = len(data["vocab"])
        counts = np.zeros((v, v))
        for i, j, c in data["transitions"]:
            counts[i, j] = c
        return cls(data["vocab"], counts, float(data.get("alpha", 1.0)))


def _transitions(df: pd.DataFrame, index: dict):
    """Return (prev ids, next ids, window MultiIndex) for consecutive tokens inside one host window."""
    d = df.sort_values(["host", "win", "ts"], kind="mergesort")
    ids = d["tok"].map(index).fillna(index[UNK]).astype(int).to_numpy()
    gid = d.groupby(KEY, sort=False).ngroup().to_numpy()
    same = gid[1:] == gid[:-1]
    hosts = d["host"].iloc[1:][same]
    wins = d["win"].iloc[1:][same]
    keys = pd.MultiIndex.from_arrays([hosts.to_numpy(), pd.DatetimeIndex(wins)], names=KEY)
    return ids[:-1][same], ids[1:][same], keys
