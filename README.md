# SentinelLine (COMP4990 Capstone)

SentinelLine is a lightweight malware triage layer on top of Assemblyline.
It accepts uploaded files, runs an FSM pipeline, records audit events, and returns a final recommendation.

## What Is In This Repository

- agent/: FastAPI service and FSM pipeline
- dashboard/: Streamlit audit dashboard
- data/samples/: test files
- data/logs/: JSONL audit logs
- agent/triage_rules.yar: YARA rules used during triage

## End-to-End Pipeline Stages

Every file goes through these states in order:

1. received
- Generates file_id, hash, size, timestamps

2. triage
- Computes quick file signals
- Runs YARA rules from triage_rules.yar
- Produces initial risk profile

3. route
- Chooses routing decision based on triage output
- Typical routes: FAST, DEEP, HUMAN_REVIEW

4. submit
- Authenticates to Assemblyline
- Submits file to POST /api/v4/submit/

5. wait
- Polls Assemblyline submission status
- Retrieves final submission result payload

6. score
- Normalizes report signals to final risk score and confidence

7. respond
- Returns final API response to caller
- Writes dashboard-ready summary data

## Requirements

- Docker + Docker Compose
- Assemblyline reachable from the agent container
- Valid Assemblyline credentials

## Setup And Run (Docker, Recommended)

Run these commands from project root:

```bash
docker compose up -d --build
```

Check service health:

```bash
curl http://localhost:18000/health
```

Open dashboard:

```text
http://localhost:8501
```

Stop services:

```bash
docker compose down
```

## Assemblyline Configuration

Set these in docker-compose.yml under agent.environment:

```yaml
LOG_DIR: /logs
ASSEMBLYLINE_API_URL: https://host.docker.internal
ASSEMBLYLINE_USERNAME: admin
ASSEMBLYLINE_PASSWORD: admin
ASSEMBLYLINE_API_KEY: 'key_name:key_secret'
```

Notes:

- If your API key contains special characters like $, keep it quoted.
- If Assemblyline is not on your host machine, replace host.docker.internal with the correct hostname.

## Terminal Commands For Testing

Submit benign sample:

```bash
curl -F "file=@data/samples/benign.txt" http://localhost:18000/submit
```

Submit YARA-triggering sample:

```bash
curl -F "file=@agent/test_payload.txt" http://localhost:18000/submit
```

Watch logs live:

```bash
docker compose logs -f agent
```

## What A Good Response Looks Like

You should see:

- status: complete
- recommendation: value returned from scoring
- final_report.analysis_summary.routing_decision
- final_report.analysis_summary.initial_risk_profile.yara_hits
- final_report.audit_trail.states_visited including all FSM states

Expected behavior:

- benign.txt usually has yara_hits as [] and routes FAST
- test_payload.txt should include Definitive_Malware_Signature and route HUMAN_REVIEW

## Local Run (Without Docker)

Agent:

```bash
cd agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LOG_DIR="$(pwd)/../data/logs"
export ASSEMBLYLINE_API_URL=https://localhost
export ASSEMBLYLINE_USERNAME=admin
export ASSEMBLYLINE_PASSWORD=admin
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Dashboard:

```bash
cd dashboard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.port=8501 --server.address=0.0.0.0
```

If running local agent on port 8000, test with:

```bash
curl -F "file=@data/samples/benign.txt" http://localhost:8000/submit
```

## Troubleshooting

1. 401 Unauthorized
- Credentials or API key format is incorrect.

2. 403 Invalid XSRF token
- Session login is required before protected API calls.

3. 400 Bad Request on submit
- Assemblyline expects upload field name bin for /api/v4/submit/.

4. Dashboard is empty
- Confirm data/logs has JSONL files and volume mount is active.

5. Compose warning about version
- version key is ignored by Compose v2; warning is harmless.

## License

See LICENSE.
1