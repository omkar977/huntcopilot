# M1: verdict ACCEPT WITH FIXES (zip v1). Due: v2 Sun 15 Nov 18:00

Lead already fixed on merge: checker now allows page 7; `7_Simulation.py` moved to services/dashboard/pages/; spec updated (Dockerfiles in deploy/docker/). Lead ran your tests here: 110 passed, 2 skipped, ruff clean. Generator is deterministic (same seed twice = same sha256), 49,217 / 49,832 events as expected.

1. [M1] Verify OpenSearch tag: `docker manifest inspect opensearchproject/opensearch:2.17.1` (must have arm64) or set OPENSEARCH_IMAGE. Report result in MANIFEST.
2. [M1] Container start commands: ml and api are guesses (`python -m uvicorn main:app`). Keep until M3/M4 deliver; detector `python -m main` works with PYTHONPATH (main.py). No action unless M3/M4 differ.
3. [M1] Lead added services/dashboard/requirements.txt (streamlit, httpx, pydantic, pydantic-settings, pyyaml). Check that Dockerfile.dashboard builds with it.
4. [M1] Run on a machine with Docker: `docker compose config`, `docker compose up -d --build` for redis+opensearch+generator+ingestor, run an eval to redis, report ingest rate (target 800 events/s) and DLQ count.
5. [M1] `kubectl apply --dry-run=client -f deploy/k8s/` and report output (the 2 skipped tests).
6. [Lead, done] train and eval data for M3 shared by link, not in zips.
