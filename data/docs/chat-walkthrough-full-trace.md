# SentinelLine Full Walkthrough Trace

## 1) High-level setup

### 1.1 Assemblyline deployment

Reference deployment file:
- [deployments/assemblyline/docker-compose.yaml](../../deployments/assemblyline/docker-compose.yaml)

Key points:
- Assemblyline infrastructure and core services are started by the Assemblyline compose stack.
- SentinelLine does not boot the full Assemblyline platform itself.
- SentinelLine expects a reachable Assemblyline API endpoint via environment configuration.

### 1.2 SentinelLine compose stack

SentinelLine runtime file:
- [docker-compose.yml](../../docker-compose.yml)

What this stack starts:
- `agent` (FastAPI service) on host port `18000`
- `dashboard` (Streamlit) on host port `8501`

Shared integration point:
- Both services mount `./data/logs` to `/logs`.

---

## 2) API demo toolkit flow (separate from FSM runtime)

Toolkit folder:
- [agent/api_demo](../../agent/api_demo)

Purpose:
- Demonstrate direct Assemblyline API usage (submit/fetch/ingest queue).
- This is auxiliary tooling and is not the same as the FastAPI FSM path.

Main scripts:
- [agent/api_demo/submit_demo.py](../../agent/api_demo/submit_demo.py)
- [agent/api_demo/fetch_submission.py](../../agent/api_demo/fetch_submission.py)
- [agent/api_demo/ingest_sender.py](../../agent/api_demo/ingest_sender.py)
- [agent/api_demo/ingest_receiver.py](../../agent/api_demo/ingest_receiver.py)

---

## 3) Main runtime path (what `/submit` does)

Core files:
- [agent/app/main.py](../../agent/app/main.py)
- [agent/app/fsm.py](../../agent/app/fsm.py)
- [agent/app/models.py](../../agent/app/models.py)
- [agent/app/policy.py](../../agent/app/policy.py)
- [agent/app/explain.py](../../agent/app/explain.py)
- [agent/app/auditlog.py](../../agent/app/auditlog.py)

Request lifecycle:
1. Client sends file to `POST /submit`.
2. FastAPI reads bytes and calls `run_fsm(filename, content)`.
3. FSM executes states in order:
   - `received`
   - `triage`
   - `route`
   - `submit`
   - `wait`
   - `score`
   - `respond`
4. FSM logs state events to JSONL after each stage.
5. Final JSON response is returned with recommendation, report, and dashboard payload.

---

## 4) State-by-state truth

### 4.1 received

File:
- [agent/app/states/received.py](../../agent/app/states/received.py)

What it does:
- Generates `file_id`.
- Calculates file hash.
- Initializes `StateContext`.
- Moves status to `triage`.

### 4.2 triage

File:
- [agent/app/states/triage.py](../../agent/app/states/triage.py)

What it does:
- Calculates entropy.
- Detects file type.
- Runs YARA rules.
- Computes initial risk score.
- Stores `RiskProfile` in context.
- Moves status to `route`.

### 4.3 route

File:
- [agent/app/states/route.py](../../agent/app/states/route.py)

What it does:
- Applies deterministic rule logic over triage features.
- Chooses `FAST`, `DEEP`, or `HUMAN_REVIEW`.
- Builds routing rationale.
- Resolves route to policy via [agent/app/policy.py](../../agent/app/policy.py).
- Stores `analysis_config` and moves status to `submit`.

### 4.4 submit

File:
- [agent/app/states/submit.py](../../agent/app/states/submit.py)

What it does:
- Authenticates to Assemblyline.
- Submits file to `/api/v4/submit/`.
- Sends policy-derived JSON payload including:
  - `timeout`
  - `deep_scan`
  - `extra_services`
  - `analysis_type`
  - `services.selected` (and optional `services.excluded`)
  - metadata (`sentinelline_route`, `sentinelline_policy_id`, `sentinelline_policy_name`)
- Stores `submission_id` and moves status to `wait`.

### 4.5 wait

File:
- [agent/app/states/wait.py](../../agent/app/states/wait.py)

What it does:
- Polls submission status endpoint until complete or timeout.
- Fetches analysis report using submission endpoints.
- Stores `analysis_report` and moves status to `score`.

### 4.6 score

File:
- [agent/app/states/score.py](../../agent/app/states/score.py)

What it does:
- Parses report metrics.
- Computes confidence and normalized final risk score.
- Stores scoring details and moves status to `respond`.

### 4.7 respond

File:
- [agent/app/states/respond.py](../../agent/app/states/respond.py)

What it does:
- Determines recommendation.
- Builds `final_report` and `dashboard_update`.
- Applies escalation logic.
- Sets final status to:
  - `complete`, or
  - `pending_human_review`.

Current escalation behavior:
- Route `HUMAN_REVIEW` always escalates.
- Uncertain outcomes with medium/high score can escalate.

---

## 5) Logging and dashboard behavior

### 5.1 Logging truth

Files:
- [agent/app/auditlog.py](../../agent/app/auditlog.py)
- [agent/app/fsm.py](../../agent/app/fsm.py)

What is logged:
- Per-trace events to `/logs/<trace_id>.jsonl`.
- Escalation queue events to `/logs/escalations.jsonl`.

Common states seen in trace files:
- `RECEIVED`, `TRIAGE`, `ROUTE`, `SUBMIT`, `WAIT`, `SCORE`, `RESPOND`
- `ESCALATED` when escalation criteria are met

### 5.2 Dashboard truth

File:
- [dashboard/app.py](../../dashboard/app.py)

What it renders:
- **Trace Overview** table
- **Needs Analyst Review** table
- **Trace Details** expandable entries
- **Escalation Queue Log** from `escalations.jsonl`

Data source:
- Reads JSONL files from `LOG_DIR` (default `/logs`).

---

## 6) End-to-end correlation map

1. API response includes `final_report.file_analysis.file_id`.
2. That value maps to trace log `data/logs/<file_id>.jsonl`.
3. Stress test output `raw/job_N.json` contains the same `file_id` field.
4. Escalated traces appear both:
   - in per-trace logs (`ESCALATED` state)
   - and queue file `data/logs/escalations.jsonl`.

---

## 7) Known boundaries (current)

1. SentinelLine runtime does not switch Assemblyline compose profiles.
2. Human-review escalation is implemented as status + logging, not a full analyst approval API.
3. External threat-intel enrichment in triage remains mostly stubbed.

This is accurate for the current repository state and current runtime behavior.
