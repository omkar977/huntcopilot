# Round 2 notes (Sat 14 Nov 23:50)

## M1 v2: ACCEPT (v2 is the verify script; real checks still open)
Lead merged it: 117 passed, 2 skipped, ruff clean, checker PASS, `verify_stack.sh` has valid bash syntax.
Still OPEN (needs a machine with Docker, nobody here can run it): items 1, 4, 5 of DEFECTS_M1. Lead/human runs `bash deploy/verify_stack.sh 2>&1 | tee verify_report.txt` on a Docker host and pastes the output. M1 must not claim these done until the output exists.
Lead changed Dockerfile.ml to `ml_main:app`. api start command stays a guess until M4 delivers.
v3 (final) due Mon 16 Nov 16:00.

## M2 v2: ACCEPT
178 passed (one new test file), ruff clean, checker PASS.
Decisions:
- Item 4: accepted. Do not exclude admin pairs in the executor. M4 must rank by stages, alerts and anomaly and split chain components so WS-08 stays out of the WS-03 finding.
- Item 5: A + C. M2 implements A in `run_plan` (a step that depends on an earlier step queries from the earliest event of that step to the end of the plan range). M4 sets template step size to 500 (C). Add a test on the generated-style demo data. Due v3, Mon 16 Nov 16:00.
- Item 6 still open (Streamlit render and screenshot). Needs a machine with Streamlit.
