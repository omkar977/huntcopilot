# HuntCopilot skeleton (Build 0, v1.0)

Shared starting point for all members. Read the full specification document first. Contracts are law.

## What is inside
- `common/hc_common/` shared package: `schemas.py` (all data contracts), `config.py`, `logging.py`, `clients.py`, `ids.py`, `constants.py`. Owner: Lead. Do not edit.
- `tests/fixtures/` about 290 synthetic events (`events_sample.jsonl`), `assets.json`, `expected_alerts.json`. Regenerate with `python tools/make_fixtures.py --check`.
- `tools/verify_submission.py` checks your zip before you send it. `tools/make_fixtures.py` builds the fixtures.
- Empty module folders with a `MODULE.md` each: `services/*`, `libs`, `deploy`.
- `MANIFEST_TEMPLATE.md`, `CHANGE_REQUEST_TEMPLATE.md`, `.env.example`, `ruff.toml`, `pytest.ini`, `requirements-dev.txt`.

## Setup (Python 3.10 or 3.11)
Linux or macOS:
```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```
Windows PowerShell:
```
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest -q
```
`pytest -q` at the repo root must pass (fixture tests and schema tests) before you start.

## Work on your module
1. Create your files only under the paths you own (see `MODULE.md` and Section 2 of the specification).
2. Add a `requirements.txt` in your service folder with version ranges.
3. Put tests next to your code (for example `services/generator/tests/`). Run them with the module on the path:
   - Linux: `PYTHONPATH=common:libs:services/<module> pytest -q services/<module>`
   - Windows: `$env:PYTHONPATH='common;libs;services\<module>'; pytest -q services\<module>`
4. Tests that need Redis or OpenSearch use `@pytest.mark.integration` and run only with `HC_INTEGRATION=1`.
5. Use `tests/fixtures/events_sample.jsonl` as input. Never read `gt` in features, filters or prompts.

## Submit
1. Save the outputs: `pytest -q > pytest_output.txt` and `ruff check --config ruff.toml . > ruff_output.txt`.
2. Copy `MANIFEST_TEMPLATE.md` to `MANIFEST.md` and fill it in.
3. Zip your owned folders plus the root files `MANIFEST.md`, `pytest_output.txt`, `ruff_output.txt` (and `CHANGE_REQUEST.md` if needed). Name: `HC_<M1..M4>_<module>_v<N>_<YYYYMMDD-HHMM>.zip`. The repo-relative paths must be preserved inside the zip.
4. Run `python tools/verify_submission.py <your zip>`. It must print `FINAL RESULT: PASS`.
5. Send the zip to the Lead before the deadline of the day.

## Rules
No secrets in files. No `.env`, `.venv`, `__pycache__`, `.git`, or files over 5 MB. Synthetic data only. Do not change hc_common.
