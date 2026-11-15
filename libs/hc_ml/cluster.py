"""KMeans clustering of high-anomaly windows with k chosen by silhouette."""
from __future__ import annotations

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

MIN_WINDOWS = 4
MAX_K = 8
RANDOM_STATE = 0


def cluster_windows(x: np.ndarray) -> np.ndarray:
    """Return a cluster id per row of the scaled feature matrix x.

    Fewer than 4 rows give cluster 0 for all. Otherwise k runs from 2 to min(8, n - 1) and the
    best silhouette wins (ties go to the smaller k). Fixed random_state, so results are repeatable.
    """
    n = len(x)
    if n < MIN_WINDOWS:
        return np.zeros(n, dtype=int)
    best_labels = np.zeros(n, dtype=int)
    best_score = -2.0
    for k in range(2, min(MAX_K, n - 1) + 1):
        labels = KMeans(n_clusters=k, n_init=10, random_state=RANDOM_STATE).fit_predict(x)
        if len(set(labels)) < 2:
            continue
        score = float(silhouette_score(x, labels))
        if score > best_score + 1e-12:
            best_score, best_labels = score, labels
    return best_labels.astype(int)
