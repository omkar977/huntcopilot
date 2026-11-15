# Round 3 (Sun 15 Nov, midday)

## M2 v3: ACCEPT. 181 passed. Option A (time bound) done. Thanks.
## M3 v2: ACCEPT WITH FIXES
44 passed, 1 skipped. M3 did NOT receive the train/eval data (human did not forward it). The data zip is now attached: unzip, then train/evaluate.
Lead ran `--per-group` on M1 data (train 1001; eval seeds 2002, 3003, 4004):
| mode | seed | precision | recall | FP/host-day | PR-AUC |
|---|---|---|---|---|---|
| global | 2002 | 0.24 | 0.61 | 3.75 | 0.22 |
| per-group | 2002 | 0.26 | 0.87 | 4.75 | 0.44 |
| per-group | 3003 | 0.27 | 0.87 | 4.58 | 0.47 |
| per-group | 4004 | 0.21 | 0.74 | 5.33 | 0.43 |
Per-group doubles PR-AUC and lifts recall: make it the DEFAULT. Precision and FP are still far off target (0.60 / 3). At threshold 0.7 per-group gives precision about 0.5 and 1 FP/host-day but recall about 0.5. Targets cannot both be met yet.
M3 tasks (due v3 Mon 16:00): (1) make per-group default; (2) lower false positives on servers (FILE-01, WEB-01, DB-01, DC-01 dominate the FPs): per-host rare_* tables, beacon_cv guarded by n_net; (3) report the table above before/after on 3 seeds; (4) run the fastapi tests and paste the output; (5) if targets stay missed, say so in MANIFEST: we will report it honestly.
## M1 v2: still waiting for the Docker run output (verify_stack.sh). Not M1's fault: needs a Docker host.
