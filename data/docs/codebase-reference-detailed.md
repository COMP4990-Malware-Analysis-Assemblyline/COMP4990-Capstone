# SentinelLine Codebase Reference (Detailed)

Date: 2026-03-24

This document explains:
1. What each folder and file in your codebase does.
2. How files correlate to each other.
3. How data moves through the system.
4. Why each component exists.

## 1) High-level architecture

You have one custom application layer and one external analysis platform:

- SentinelLine app (this repository):
  - FastAPI agent
  - FSM states
  - routing policy logic
  - audit logging
  - Streamlit dashboard
  - test/stress scripts

- Assemblyline platform (external dependency):
  - receives submissions
  - runs analysis services
  - provides status/report APIs

Core runtime path:

Client -> FastAPI /submit -> FSM states -> Assemblyline -> scoring/respond -> JSON response
                                               -> JSONL logs -> dashboard + test reports

## 2) Top-level folders and files

### .gitignore
Purpose:
- excludes cache, venv, generated outputs, secrets (depends on content).

### LICENSE
Purpose:
- project license terms.

### README.md
Purpose:
- primary operator guide: run instructions, routing intent, test commands.
Correlates to:
- docker-compose.yml
- scripts/stress_queue.sh
- data/docs/testing-playbook.md

### docker-compose.yml
Purpose:
- starts two containers:
  - agent on port 18000
  - dashboard on port 8501
- mounts ./data/logs into both containers at /logs.
Why:
- shared logs are the integration point between backend and dashboard.

### .vscode/
Purpose:
- editor settings for workspace only.
Not part of runtime logic.

### .venv/
Purpose:
- local python environment (generated artifact).
Not part of application source logic.

## 3) agent/ folder (core backend)

### agent/Dockerfile
Purpose:
- build image for FastAPI backend.
- installs dependencies from agent/requirements.txt.
- copies app/ and triage_rules.yar into container.
- launches uvicorn app.main:app.

Correlation:
- used by docker-compose.yml service agent.

### agent/requirements.txt
Purpose:
- backend dependencies:
  - fastapi, uvicorn, pydantic
  - requests (Assemblyline API calls)
  - python-magic + yara-python (triage features)

### agent/test_payload.txt
Purpose:
- deterministic test file to trigger definitive YARA signature path.
Used by:
- manual curl tests
- stress script extra file runs

### agent/triage_rules.yar
Purpose:
- YARA rules used by triage state to generate early indicators.
Contains:
- many behavior rules
- one definitive rule: Definitive_Malware_Signature

### agent/yaraProj.py
Purpose:
- standalone experimental script for old/simple YARA bucket routing.
Status:
- not used by FastAPI FSM runtime.
Reason to keep:
- useful as a prototype/reference script.

### agent/.venv_tmp/
Purpose:
- temporary local environment/cache.
Not runtime code.

### agent/rules/
Purpose:
- additional/alternate YARA rule files.
Not all are necessarily used by runtime.
Important detail:
- triage.py resolves rule path from multiple candidate locations, including both root and rules/.

## 4) agent/app/ (backend application package)

This is the most important folder.

### agent/app/main.py
Purpose:
- FastAPI entrypoint.
Endpoints:
- GET /health
- POST /submit
Correlation:
- POST /submit calls run_fsm() in fsm.py.

### agent/app/models.py
Purpose:
- shared data models and enums.
Defines:
- RoutingDecision
- Recommendation
- ConfidenceLevel
- RiskProfile
- StateContext
Why it matters:
- StateContext is the object passed through all FSM states.

### agent/app/policy.py
Purpose:
- central route-to-policy map.
Defines policy configs for:
- FAST
- DEEP
- HUMAN_REVIEW
Fields include:
- policy_id, display_name
- analysis_type, timeout, deep_scan
- extra_services, selected_services
Why it matters:
- makes route behavior explicit and consistent.

### agent/app/explain.py
Purpose:
- human-readable route explanation text.
Uses:
- get_policy_for_route() to include policy context in text.

### agent/app/auditlog.py
Purpose:
- writes runtime events to JSONL files in LOG_DIR.
Functions:
- log_event(): per-trace events -> <trace_id>.jsonl
- log_escalation(): queue-style escalations -> escalations.jsonl
Correlation:
- called by fsm.py after each state.
- consumed by dashboard/app.py.

### agent/app/fsm.py
Purpose:
- orchestrates the full 7-state pipeline:
  1. received
  2. triage
  3. route
  4. submit
  5. wait
  6. score
  7. respond

Also does:
- in-memory state transition history
- JSONL audit events
- ESCALATED event emission

Correlation:
- imports all state handlers from app/states/
- consumes explain.py + auditlog.py

## 5) agent/app/states/ (state handlers)

Each file encapsulates one FSM stage.

### received.py
Purpose:
- create file_id, SHA256 hash
- initialize StateContext
- set status to triage

### triage.py
Purpose:
- calculate entropy
- detect file type
- run YARA rules
- compute initial risk score
- attach RiskProfile
- set status to route

Notes:
- includes YARA compilation cache for performance.
- external threat intel query function exists but currently stubbed.

### route.py
Purpose:
- deterministic decision FAST/DEEP/HUMAN_REVIEW based on triage profile.
- build routing rationale.
- attach analysis_config from policy.py.
- set status to submit.

Important:
- decision logic uses if/elif execution block.
- ROUTING_RULES dict is descriptive but not the active decision engine.

### submit.py
Purpose:
- authenticate to Assemblyline
- submit file to /api/v4/submit/
- send policy-driven settings payload
- collect submission_id
- set status to wait

Payload includes:
- timeout, deep_scan, extra_services
- analysis_type
- services.selected (and optional excluded)
- metadata with SentinelLine route/policy fields

### wait.py
Purpose:
- poll Assemblyline submission status
- fetch full analysis report when completed
- store report in context
- set status to score

### score.py
Purpose:
- parse report metrics
- compute confidence score
- normalize final risk score (0-100)
- set status to respond

### respond.py
Purpose:
- generate final recommendation
- build final_report and dashboard_update payloads
- apply escalation rule
- return final API response status:
  - complete
  - or pending_human_review

Escalation logic:
- route HUMAN_REVIEW always escalates
- uncertain + medium/high score can escalate

### __init__.py
Purpose:
- package marker for states module.

## 6) agent/api_demo/ (separate integration demo utilities)

Important distinction:
- this folder is not the main FastAPI FSM path.
- it is an auxiliary toolkit to test Assemblyline client usage directly.

### .env.example
Purpose:
- template for local AL_HOST/AL_USER/AL_APIKEY.

### .env
Purpose:
- local credentials/settings (private).

### requirements.txt
Purpose:
- dependencies for this demo toolkit.

### config.py
Purpose:
- load settings from environment/.env.

### client.py
Purpose:
- build authenticated Assemblyline Python client.

### submit_demo.py
Purpose:
- direct submit via client.

### fetch_submission.py
Purpose:
- fetch full result by submission id (sid).

### ingest_sender.py
Purpose:
- async ingest with notification queue.

### ingest_receiver.py
Purpose:
- listen for queue notifications and fetch results.

### README.md / structure.txt
Purpose:
- usage notes and folder explanation.

## 7) dashboard/ folder

### dashboard/Dockerfile
Purpose:
- build Streamlit container.

### dashboard/requirements.txt
Purpose:
- dashboard dependency list (streamlit).

### dashboard/app.py
Purpose:
- read JSONL logs from /logs
- summarize trace-level fields
- render tables/views:
  - Trace Overview
  - Needs Analyst Review
  - Trace Details
  - Escalation Queue Log

Correlation:
- consumes logs written by agent/app/auditlog.py.

## 8) data/ folder

### data/docs/
Purpose:
- project documentation set.
Includes:
- architecture notes
- walkthrough/review docs
- demo/testing playbooks

### data/logs/
Purpose:
- runtime audit artifacts (JSONL).
Contains:
- per-trace files: <trace_id>.jsonl
- queue file: escalations.jsonl (when escalations occur)

Correlation:
- written by backend
- read by dashboard
- used for post-run debugging

### data/samples/
Purpose:
- reusable test input files.
Used by:
- manual curl tests
- stress_queue.sh default input glob

## 9) scripts/ folder

### scripts/stress_queue.sh
Purpose:
- stress/load test harness.
Workflow:
1. build jobs list
2. run parallel submissions
3. write raw API outputs
4. write summary.tsv
5. write report.txt aggregate

Output structure:
- test_results/stress_<timestamp>/jobs.txt
- summary.tsv
- report.txt
- raw/job_<n>.json

Correlation:
- drives POST /submit
- parses final_report routing info from each response

## 10) test_results/ folder

Purpose:
- historical results from stress runs.
Each run folder holds reproducible evidence for:
- pass rate
- latency
- route distribution
- per-job raw outputs

Not source code, but operational evidence.

## 11) How everything works together (correlation map)

### A) Runtime request path
1. User sends file to POST /submit (main.py).
2. main.py calls fsm.run_fsm().
3. fsm.py runs each state handler in order.
4. route.py attaches policy map from policy.py.
5. submit.py sends file + policy payload to Assemblyline.
6. wait.py polls/fetches Assemblyline report.
7. score.py computes normalized score/confidence.
8. respond.py returns final JSON response.
9. fsm.py logs each step via auditlog.py.
10. dashboard/app.py renders those logs.

### B) Data artifact correlations
- API response trace id:
  - final_report.file_analysis.file_id
  - this equals JSONL filename in data/logs/<trace_id>.jsonl

- Stress output to raw response:
  - summary.tsv column job_id -> raw/job_<job_id>.json

- raw response to logs:
  - raw/job_N.json final_report.file_analysis.file_id -> data/logs/<trace_id>.jsonl

- escalations:
  - ESCALATED state events appear in trace log
  - queue entries append to data/logs/escalations.jsonl

### C) Configuration correlations
- docker-compose.yml env vars -> submit.py/wait.py auth + endpoint behavior
- LOG_DIR -> where agent writes logs and dashboard reads logs
- ASSEMBLYLINE_* vars -> external API integration reliability

## 12) Why this structure is useful

Design reasons behind your architecture:

1. Separation of concerns
- each state has one responsibility
- easier to debug and present

2. Explicit policy layer
- policy.py centralizes routing behavior
- makes claims auditable and testable

3. Full traceability
- every run gets a trace id
- logs, API response, dashboard, and stress artifacts can be cross-linked

4. Demo friendliness
- dashboard provides readable operational status
- scripts produce reproducible evidence files

5. Extensibility
- human review escalation already has status + queue log pattern
- can be expanded to full analyst approval workflow later

## 13) Quick "where to look first" checklist

If something fails, start here:
1. agent/app/main.py (API entry)
2. agent/app/fsm.py (state orchestration)
3. agent/app/states/submit.py (external submit)
4. agent/app/states/wait.py (polling/report retrieval)
5. agent/app/states/respond.py (final output + escalation)
6. data/logs/<trace_id>.jsonl (truth of what happened)
7. dashboard/app.py (how logs are shown)
8. scripts/stress_queue.sh (batch behavior)

## 14) Known boundaries (current state)

1. SentinelLine does not launch full Assemblyline stack itself.
2. Escalation exists as status/log/queue, not full analyst action UI yet.
3. External threat-intel in triage is still mostly stubbed.

These are roadmap opportunities, not blockers for your current capstone demo.
