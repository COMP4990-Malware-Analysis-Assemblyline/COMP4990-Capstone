# SentinelLine (COMP4990 Capstone)

SentinelLine is a lightweight malware triage layer on top of Assemblyline.
It accepts uploaded files, runs an FSM pipeline, records audit events, and returns a final recommendation.
It now uses an explicit route-to-policy map (FAST, DEEP, HUMAN_REVIEW), submits that policy to Assemblyline,
and marks escalated cases as pending_human_review for analyst follow-up.

## What Is In This Repository

- agent/: FastAPI service and FSM pipeline
- dashboard/: Streamlit audit dashboard
- data/samples/: test files
- data/logs/: JSONL audit logs
- data/docs/testing-playbook.md: step-by-step test commands and output/file explanations
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
- Resolves route to explicit policy fields (policy_id, timeout, deep_scan, services)

4. submit
- Authenticates to Assemblyline
- Submits file to POST /api/v4/submit/
- Sends policy-driven payload fields:
	- timeout
	- deep_scan
	- extra_services
	- analysis_type
	- services.selected (optional services.excluded)
	- metadata with SentinelLine route/policy IDs

5. wait
- Polls Assemblyline submission status
- Retrieves final submission result payload

6. score
- Normalizes report signals to final risk score and confidence

7. respond
- Returns final API response to caller
- Writes dashboard-ready summary data
- Marks escalated cases as pending_human_review

## Route To Policy Mapping

SentinelLine makes route behavior explicit through a single policy map:

- FAST
	- policy_id: STATIC_OFFLINE
	- timeout: 60
	- deep_scan: false
	- extra_services: []
	- selected_services: []

- DEEP
	- policy_id: DYNAMIC_OFFLINE
	- timeout: 600
	- deep_scan: true
	- extra_services: ["yara", "pe_recommendations"]
	- selected_services: ["Antivirus", "Extraction", "Static Analysis"]

- HUMAN_REVIEW
	- policy_id: ESCALATED
	- timeout: 1800
	- deep_scan: true
	- extra_services: ["yara", "pe_recommendations", "code_analysis"]
	- selected_services: ["Antivirus", "Extraction", "Static Analysis"]

This means route labels are now tied to concrete submission behavior and audit metadata.

## Requirements

- Docker + Docker Compose
- Assemblyline reachable from the agent container
- Valid Assemblyline credentials

## Setup And Run (Docker, Recommended)

Run these commands from project root:

```bash
cd /home/arifh/COMP4990-Capstone
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

Submit DEEP-route sample:

```bash
curl -F "file=@data/samples/deep_test.txt" http://localhost:18000/submit
```

Watch logs live:

```bash
docker compose logs -f agent
```

## Stress Test Queue (Multiple Files)

Run a queue-based stress test that submits many files in parallel and reports pass/fail + latency stats:

```bash
cd /home/arifh/COMP4990-Capstone
bash scripts/stress_queue.sh --concurrency 8 --repeat 5 --extra-file agent/test_payload.txt
```

What this does:

- Builds a job queue from files in data/samples plus optional extra files
- Submits jobs concurrently to POST /submit
- Stores raw JSON responses in test_results/stress_<timestamp>/raw
- Generates a tab-delimited per-job summary and final report with:
	- total jobs
	- pass/fail counts
	- pass includes both complete and pending_human_review statuses
	- pass rate
	- latency p50 and p95
	- route distribution
	- error breakdown

Useful variants:

```bash
# Smaller, quick check
bash scripts/stress_queue.sh --concurrency 2 --repeat 2

# Heavier run against local default endpoint
bash scripts/stress_queue.sh --concurrency 12 --repeat 10 --extra-file agent/test_payload.txt

# Custom endpoint (if agent runs on different host/port)
bash scripts/stress_queue.sh --url http://localhost:8000/submit --concurrency 6 --repeat 3
```

## What A Good Response Looks Like

You should see:

- status: complete OR pending_human_review
- recommendation: value returned from scoring
- final_report.analysis_summary.routing_decision
- final_report.analysis_summary.analysis_policy.policy_id
- final_report.analysis_summary.initial_risk_profile.yara_hits
- final_report.audit_trail.states_visited including all FSM states

For escalated paths, logs include ESCALATED events and the dashboard lists those samples under Needs Analyst Review.

Expected behavior:

- benign.txt usually has yara_hits as [] and routes FAST
- deep_test.txt usually routes DEEP (1-3 YARA hits, no definitive signature)
- test_payload.txt should include Definitive_Malware_Signature and route HUMAN_REVIEW

## Local Run (Without Docker)

Agent:

```bash
cd /home/arifh/COMP4990-Capstone/agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export LOG_DIR=/home/arifh/COMP4990-Capstone/data/logs
export ASSEMBLYLINE_API_URL=https://localhost
export ASSEMBLYLINE_USERNAME=admin
export ASSEMBLYLINE_PASSWORD=admin
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Dashboard:

```bash
cd /home/arifh/COMP4990-Capstone/dashboard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py --server.port=8501 --server.address=0.0.0.0
```

If running local agent on port 8000, test with:

```bash
curl -F "file=@/home/arifh/COMP4990-Capstone/data/samples/benign.txt" http://localhost:8000/submit
```


