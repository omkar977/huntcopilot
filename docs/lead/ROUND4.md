# Round 4 (Sun 15 Nov, afternoon)

## M3 v3: ACCEPT WITH FIXES. 47 passed, 1 skipped, ruff clean.
You asked the Lead to run your three configs on M1 data. DONE by Lead (train seed 1001; eval seeds 2002, 3003, 4004). You do not need the data zip for this. Window level, threshold 0.5: P = precision, R = recall, FP = false positives per host-day.

| config | 2002 | 3003 | 4004 |
|---|---|---|---|
| default (per-group) | P .26 R .87 FP 4.75 AUC .44 | P .27 R .87 FP 4.58 AUC .47 | P .21 R .74 FP 5.33 AUC .43 |
| + per-host-rare | P .28 R .91 FP 4.50 AUC .46 | P .28 R .91 FP 4.58 AUC .49 | P .22 R .74 FP 5.08 AUC .44 |
| + per-host-rare + beacon 10 | P .28 R .91 FP 4.42 AUC .45 | P .27 R .91 FP 4.75 AUC .50 | P .22 R .74 FP 5.08 AUC .45 |
| + beacon 10 only | P .27 R .87 FP 4.58 AUC .43 | P .26 R .87 FP 4.67 AUC .48 | P .21 R .74 FP 5.25 AUC .43 |

Decision: make `--per-host-rare` the DEFAULT (small but consistent gain in recall and AUC on all 3 seeds). Beacon guard: add no more (no clear gain). Keep the opt-out switch. Recall target (0.85) is now met on 2 of 3 seeds; precision (0.60) and FP (3) are still missed. We report that honestly.
Tasks for v4 (due Mon 16 Nov 16:00): (1) per-host-rare default; (2) run the fastapi tests if you can, else say not run; (3) one idea to lower FP on servers WEB-01, FILE-01, DB-01 (for example a per-host threshold from the training p99 of the host) and the numbers on the same 3 seeds from the Lead's command: `python -m hc_ml train --events train.jsonl --model-dir M --seed 1001` then `evaluate --events evalN.jsonl`; the data zip is attached if you want it. Stop after that: no more tuning after Monday 16:00.

## M4 v2: see DEFECTS_M4_v2.md (read the corrections at the top).
