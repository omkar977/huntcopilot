# services/api (M4)

Run: `HC_API_KEY=... uvicorn main:app --host 0.0.0.0 --port 8000` from `services/api` with `common` and `libs` on PYTHONPATH.
Mocks: `HC_MOCK_ML=1` (canned ml), `HC_MOCK_HUNT=1` (fixture events, fixture alerts, in-memory run_plan). Unset to remove.
Layout: `hc_api/` (app, store, audit, approvals, hunts, assembly, export, mocks, backends), `agent/` (templates, llm, pipeline).
