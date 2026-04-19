# SentinelLine + Assemblyline: Full Code Truth Review

---

## A) Beginner-friendly explanation

SentinelLine is a custom orchestration layer in front of Assemblyline.

What happens for one file:
1. File enters FastAPI endpoint POST /submit.
2. FSM runs 7 states in order: received -> triage -> route -> submit -> wait -> score -> respond.
3. Route is resolved to an explicit policy map (FAST, DEEP, HUMAN_REVIEW).
4. Submit sends file and policy-derived settings to Assemblyline /api/v4/submit/.
5. Wait polls until analysis completes and fetches report payload.
6. Score computes final risk and confidence.
7. Respond returns recommendation and marks case as complete or pending_human_review.
8. Audit events are written to JSONL logs, including ESCALATED events when applicable.
9. Dashboard shows structured trace overview and analyst-review queue views.

---

## B) Runtime stacks

There are two stacks:

1. SentinelLine app stack
- File: COMP4990-Capstone/docker-compose.yml
- Starts only agent and dashboard.
- Expects Assemblyline to be reachable via configured URL.

2. Assemblyline platform stack
- File: deployments/assemblyline/docker-compose.yaml
- Starts full Assemblyline ecosystem (storage, dispatch, workers, UI, APIs).

SentinelLine does not start the Assemblyline platform itself.

---

## C) Core entry points

- Agent API entry: COMP4990-Capstone/agent/app/main.py (submit endpoint)
- FSM orchestrator: COMP4990-Capstone/agent/app/fsm.py
- Route policy source: COMP4990-Capstone/agent/app/policy.py
- Assemblyline submit logic: COMP4990-Capstone/agent/app/states/submit.py
- Final recommendation and escalation status: COMP4990-Capstone/agent/app/states/respond.py
- Audit logging and escalation queue file: COMP4990-Capstone/agent/app/auditlog.py
- Dashboard rendering: COMP4990-Capstone/dashboard/app.py

---

## D) Route logic and policy mapping

Routing decision is made in route state using deterministic conditions over:
- YARA hit count
- Definitive signature flag
- Initial risk score
- Entropy
- File type

Route-to-policy is explicit and centralized in policy.py.

FAST policy:
- policy_id: STATIC_OFFLINE
- timeout: 60
- deep_scan: false
- extra_services: []
- selected_services: []
- analysis_type: quick

DEEP policy:
- policy_id: DYNAMIC_OFFLINE
- timeout: 600
- deep_scan: true
- extra_services: ["yara", "pe_recommendations"]
- selected_services: ["Antivirus", "Extraction", "Static Analysis"]
- analysis_type: standard

HUMAN_REVIEW policy:
- policy_id: ESCALATED
- timeout: 1800
- deep_scan: true
- extra_services: ["yara", "pe_recommendations", "code_analysis"]
- selected_services: ["Antivirus", "Extraction", "Static Analysis"]
- analysis_type: comprehensive

Important truth:
- Route meaning is now explicit in app policy and audit data.
- This still does not switch Assemblyline docker compose profiles (minimal/full). That is infrastructure-level, not controlled by current SentinelLine runtime code.

---

## E) Submit payload truth (FSM path)

Submit state sends:
- file field: bin
- json payload containing:
  - timeout
  - deep_scan
  - extra_services
  - analysis_type
  - services.selected (and optional services.excluded)
  - metadata:
    - sentinelline_route
    - sentinelline_policy_id
    - sentinelline_policy_name

This means analysis_type and selected services are now used in the main FSM path.

---

## F) Human review behavior (current implementation)

Current behavior now includes a lightweight escalation workflow:

1. Route-level escalation signal
- If routing decision is HUMAN_REVIEW, FSM emits ESCALATED event immediately.
- Event includes route rationale and policy snapshot.

2. Response-level escalation signal
- Respond stage sets status:
  - complete, or
  - pending_human_review
- Escalation is true when:
  - route is HUMAN_REVIEW, or
  - confidence is Uncertain and final risk >= 50

3. Queue logging
- Escalated cases are appended to logs/escalations.jsonl.

4. Dashboard visibility
- "Needs Analyst Review" section shows escalated traces.
- "Escalation Queue Log" shows normalized queue rows.

Important boundary:
- There is no analyst approval UI/action endpoint yet.
- Escalation is implemented as status + audit events + queue log for follow-up.

---

## G) Explainability and auditability

Explain route messaging now has explicit wording for:
- FAST
- DEEP
- HUMAN_REVIEW

Audit output includes:
- Per-trace JSONL state events
- Analysis policy details in ROUTE/SUBMIT/RESPOND logs
- ESCALATED events
- Separate escalations.jsonl queue

Final report includes:
- routing_decision
- routing_rationale
- analysis_policy
- scoring details
- complete state history

---

## H) Dashboard behavior now

Dashboard is no longer just raw line-by-line rendering.

It now provides:
1. Trace Overview table
- trace_id, route, policy_id, submission_id, score, confidence, status, escalation flag

2. Needs Analyst Review table
- filtered escalated traces

3. Trace Details
- per-trace summary and raw event expansion

4. Escalation Queue Log
- entries from escalations.jsonl


---

## J) Remaining gaps (still true)

1. No direct control of Assemblyline compose profile selection from runtime route decisions.
2. No built-in analyst action workflow yet (approve/dismiss endpoint and persistent state transitions).
3. External threat-intel enrichment in triage remains mostly stubbed.

These are the next upgrades if you want a fuller HITL loop.
