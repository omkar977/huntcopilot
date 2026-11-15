# HuntCopilot: run guide (extract, configure, run, demo)

Time needed: about 40 minutes the first time (most of it is Docker downloading images).
Everything is synthetic data. Nothing here touches real systems.

## 0. What you need on your laptop
- **Docker Desktop** (Windows or Mac) or Docker Engine + compose plugin (Linux). Give it at least **6 GB RAM** (Docker Desktop > Settings > Resources). The stack needs about 4.6 GB.
- **Python 3.11 or newer** (only for the test script and the optional unit tests).
- A **Gemini API key** from Google AI Studio (optional; without it the system uses the built-in fallback plans and the demo still works).

## 1. Extract
1. Unzip `huntcopilot_final_YYYYMMDD.zip`. You get a folder `repo/` (the project root). Open a terminal **inside that folder**.
2. Check: `ls` (Windows: `dir`) shows `common  deploy  libs  services  tests  tools  RUN_GUIDE.md`.

## 2. Configure the .env file (keys live only here)
```
cd deploy/compose
cp .env.example .env            # Windows PowerShell: copy .env.example .env
```
Open `.env` in a text editor and set:
```
HC_API_KEY=<a long random string, at least 24 characters, letters and digits only>
LLM_PROVIDER=gemini
LLM_API_KEY=<your Gemini key from aistudio.google.com/apikey>
LLM_MODEL=<a current Flash model name shown in AI Studio, for example gemini-2.5-flash>
LLM_BASE_URL=
```
Leave `LLM_BASE_URL` empty: the Gemini address is built in (Google's OpenAI-compatible endpoint).
No Gemini key? Set `LLM_PROVIDER=none` and leave the other three empty.
**Never paste the key in chat, in a zip, or in a screenshot.** The file `.env` must not be shared.

## 3. Start the stack
Still in `deploy/compose`:
```
docker compose config -q        # prints nothing if the file is fine
docker compose up -d --build    # first time: 10 to 20 minutes
docker compose ps               # wait until every service says healthy (about 2 minutes)
```
Services: redis, opensearch, generator, ingestor, detector, ml, api, dashboard, mlflow.
If OpenSearch keeps restarting on Linux: `sudo sysctl -w vm.max_map_count=262144` and `docker compose up -d` again.
If a build fails, copy the last 20 lines of the error: `docker compose logs --tail 20 <service>`.

## 4. Run the full test (spec section 14), one command
Go back to the project root and run the script with the same key as in `.env`.
Mac / Linux:
```
cd ../..
HC_API_KEY=<your HC_API_KEY> python tests/e2e/run_e2e.py
```
Windows PowerShell:
```
cd ..\..
$env:HC_API_KEY='<your HC_API_KEY>'
python tests\e2e\run_e2e.py
```
It generates the training data (seed 1001), trains the model, generates the attack data (seed 2002), runs the rules, creates and runs the hunt, approves one proposal, checks the audit chain, exports the case and evaluates the model. It takes 5 to 15 minutes. Expected end: `11 of 11 checks passed`.
Copy the console output into a text file for the report: step 11 gives the model metrics.
If a step FAILS: send me that line and `docker compose logs --tail 30 <service>` of the service named in it. Do not send the .env file.
Data already loaded? Add `--skip-generate` to repeat only the hunt part.

## 5. The demo (about 3 minutes)
Open **http://localhost:8501**.
1. Sidebar: all service badges are OK.
2. **Hunt Builder**: type `Find lateral movement after suspicious PowerShell`, press Generate plan (shows hypothesis, steps, source badge: `llm` with Gemini, `fallback` without), then Run hunt.
3. **Alert Queue**: the top finding (confidence about 100) with its rationale and score components.
4. **Attack Chain**: the graph WS-03 to FILE-01, DB-01 and others.
5. **Response Approvals**: type your name as approver, tick confirm, Approve one proposal. The audit badge stays green. Nothing real happens: actions are simulated.
6. **Case Export**: download the JSON and Markdown.
7. **Model and Data**: model details and the Evaluate button.
Take screenshots of each page for the report.

## 6. Stop and clean
```
cd deploy/compose
docker compose down             # keep data
docker compose down -v          # delete all data (start from scratch)
```

## 7. Optional: unit tests without Docker
```
python -m venv .venv
.venv\Scripts\activate          # Mac/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt -r services/generator/requirements.txt -r services/ingestor/requirements.txt -r services/detector/requirements.txt -r services/ml/requirements.txt -r services/api/requirements.txt -r services/dashboard/requirements.txt
```
Then run each line with PYTHONPATH set (Mac/Linux `export PYTHONPATH=...`; Windows `$env:PYTHONPATH='...'`, semicolons instead of colons):
```
pytest -q                                                              # PYTHONPATH=common:libs
pytest -q services/generator services/ingestor deploy services/dashboard   # PYTHONPATH=common:libs:services/generator:services/ingestor:services/dashboard
pytest -q libs/hc_detect libs/hc_hunt services/detector                # PYTHONPATH=common:libs:services/detector
pytest -q libs/hc_ml services/ml                                       # PYTHONPATH=common:libs:services/ml
pytest -q services/api                                                 # PYTHONPATH=common:libs:services/api
ruff check --config ruff.toml .
```
Expected: 15, 118, 181, 47, 144 passed (a few skip). With real fastapi installed a few more tests run, and any failure there is new information: send it to me.
Never run all service folders in one pytest command (several have a `main.py`).

## 8. Known limits (state them in the report)
- ML window-level targets: recall about 0.9 is met on 2 of 3 test seeds; precision (0.22 to 0.28) and false positives per host-day (4.5 to 5.1) miss the targets of 0.60 and 3. Rules plus hunt give a clean finding (5 of 6 compromised hosts; 0 false positives from the rules).
- The hunt plan template misses DC-01 (1 malicious event).
- WS-08 (benign admin script) appears as its own lower-confidence finding without proposals: a deliberate hard negative.
- Data and rules were written by the same team from the same spec, so rule results are optimistic. ML uses different seeds.
- Real-stack checks (docker compose, FastAPI http tests, Streamlit pages, MLflow, kubectl) were NOT run by the Lead; step 4 above is the first real run.
