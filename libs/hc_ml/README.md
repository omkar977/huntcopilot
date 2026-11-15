# hc_ml (M3)

| module | purpose |
| --- | --- |
| features.py | event frame, 15-minute host windows, the 22 features of spec 9.1 |
| sequence.py | Markov chain (Laplace alpha 1) over event tokens |
| model.py | scaler, 5 Isolation Forests, normalisation, anomaly and uncertainty, top features, save/load |
| cluster.py | KMeans with silhouette for windows with anomaly 0.5 or more |
| confidence.py | confidence score and deterministic rationale |
| evaluate.py | metrics against labels (the only module that reads them) |
| jsonl.py, cli.py | file helpers and `python -m hc_ml` |

Tests: `libs/hc_ml/tests/test_ml_*.py`. `tests/synth.py` is a small test-only generator, not the M1 generator.
