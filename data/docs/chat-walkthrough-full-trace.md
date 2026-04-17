# SentinelLine Full Walkthrough Trace (From This Chat)

This document captures everything explained in this chat about how your system is set up and how execution flows step by step, with exact file and line jump points.

## 1) High-level setup explained first

### 1.1 Assemblyline deployment compose overview

File reviewed:
- [deployments/assemblyline/docker-compose.yaml](../../deployments/assemblyline/docker-compose.yaml)

Main points explained:
- YAML anchors define reusable dependency bundles and core templates.
- Two profiles are used: minimal and full.
- Infrastructure services (Elasticsearch, Redis, Minio, Kibana/APM in full mode) come up before core services.
- Core services inherit shared config from common files using extends and anchor merges.

Key anchor blocks in order:
- elasticsearch minimal depends anchor
- elasticsearch full depends anchor
- elasticsearch + redis minimal depends anchor
- elasticsearch + redis full depends anchor
- core minimal template (extends common/core.yaml + minimal ES dependency)
- core full template (extends common/core.yaml + full ES dependency)

Infrastructure sequencing explained:
- Elasticsearch must be healthy before many services start.
- kb_setup waits for elasticsearch_full and sets Kibana user password.
- kibana depends on elasticsearch_full health and kb_setup completion.
- apm_server, filebeat, metricbeat are full-profile monitoring stack.

Core sequencing explained:
- Services like alerter, workflow, scaler, updater, dispatcher, ingester, ui, socketio inherit dependency wiring via anchors.
- Profiles decide what starts (minimal, full, archive).

## 2) API demo ingest flow explained next

Files reviewed:
- [COMP4990-Capstone/agent/api_demo/config.py](../../agent/api_demo/config.py)
- [COMP4990-Capstone/agent/api_demo/client.py](../../agent/api_demo/client.py)
- [COMP4990-Capstone/agent/api_demo/ingest_sender.py](../../agent/api_demo/ingest_sender.py)
- [COMP4990-Capstone/agent/api_demo/ingest_receiver.py](../../agent/api_demo/ingest_receiver.py)
- [COMP4990-Capstone/agent/api_demo/fetch_submission.py](../../agent/api_demo/fetch_submission.py)
- [COMP4990-Capstone/agent/api_demo/submit_demo.py](../../agent/api_demo/submit_demo.py)

### 2.1 Config and auth creation

- Env config is loaded in [config.py](../../agent/api_demo/config.py#L9).
- Host/user/apikey/verify/nq are defined in [config.py](../../agent/api_demo/config.py#L14), [config.py](../../agent/api_demo/config.py#L17), [config.py](../../agent/api_demo/config.py#L20), [config.py](../../agent/api_demo/config.py#L23), [config.py](../../agent/api_demo/config.py#L26).
- Shared settings object is created in [config.py](../../agent/api_demo/config.py#L28).
- API client wrapper starts in [client.py](../../agent/api_demo/client.py#L7).
- get_client(...) call is in [client.py](../../agent/api_demo/client.py#L12).

### 2.2 Sender path (submit for async ingest)

- Sender entry is [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L31).
- Input path resolution starts in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L10).
- File argument is read in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L36).
- AL client is created in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L47).
- Params dict is built in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L50).
- Metadata dict is built in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L56).
- Async ingest call happens in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L61).
- Queue name output is in [ingest_sender.py](../../agent/api_demo/ingest_sender.py#L65).

What was explained about this line:
- Ingest is fire-and-forget.
- Queue name nq is attached.
- Assemblyline writes completion message to that queue when done.

### 2.3 Receiver path (poll queue + fetch full report)

- Receiver entry is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L8).
- Client creation is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L10).
- Queue poll loop starts in [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L15).
- Queue read is in [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L18).
- Sleep/continue on empty queue is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L21).
- Raw message print is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L26).
- SID extraction logic is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L31).
- Full submission fetch is [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L43).
- Verdict and score output are [ingest_receiver.py](../../agent/api_demo/ingest_receiver.py#L47).

### 2.4 Manual fetch helper

- fetch script entry is [fetch_submission.py](../../agent/api_demo/fetch_submission.py#L7).
- SID argument read is [fetch_submission.py](../../agent/api_demo/fetch_submission.py#L13).
- submission full call is [fetch_submission.py](../../agent/api_demo/fetch_submission.py#L17).
- Per-result listing loop is [fetch_submission.py](../../agent/api_demo/fetch_submission.py#L36).

### 2.5 Direct submit helper (non-queue demo)

- submit entry is [submit_demo.py](../../agent/api_demo/submit_demo.py#L7).
- Path read is [submit_demo.py](../../agent/api_demo/submit_demo.py#L15).
- Client creation is [submit_demo.py](../../agent/api_demo/submit_demo.py#L18).
- Services and params are set in [submit_demo.py](../../agent/api_demo/submit_demo.py#L21).
- Metadata set in [submit_demo.py](../../agent/api_demo/submit_demo.py#L31).
- Submit call is [submit_demo.py](../../agent/api_demo/submit_demo.py#L40).

## 3) Project-level compose and app/dashboard flow explained after that

Files reviewed:
- [COMP4990-Capstone/docker-compose.yml](../../docker-compose.yml)
- [COMP4990-Capstone/agent/app/main.py](../../agent/app/main.py)
- [COMP4990-Capstone/agent/app/fsm.py](../../agent/app/fsm.py)
- [COMP4990-Capstone/agent/app/models.py](../../agent/app/models.py)
- [COMP4990-Capstone/agent/app/explain.py](../../agent/app/explain.py)
- [COMP4990-Capstone/agent/app/auditlog.py](../../agent/app/auditlog.py)
- [COMP4990-Capstone/dashboard/app.py](../../dashboard/app.py)

### 3.1 Docker wiring for this capstone app

- Agent service starts in [docker-compose.yml](../../docker-compose.yml#L4).
- Agent build context is [docker-compose.yml](../../docker-compose.yml#L5).
- Agent port map 18000:8000 is [docker-compose.yml](../../docker-compose.yml#L6).
- Shared logs volume mount is [docker-compose.yml](../../docker-compose.yml#L8).
- Agent env vars begin in [docker-compose.yml](../../docker-compose.yml#L10).
- Dashboard service starts in [docker-compose.yml](../../docker-compose.yml#L17).
- Dashboard logs mount is [docker-compose.yml](../../docker-compose.yml#L21).

Note explained in chat:
- An API key appears directly in compose env; better to move to secret/env handling.

### 3.2 API entrypoint and FSM handoff

- FastAPI app object in [main.py](../../agent/app/main.py#L5).
- Health endpoint in [main.py](../../agent/app/main.py#L7).
- Submit endpoint in [main.py](../../agent/app/main.py#L11).
- File bytes read in [main.py](../../agent/app/main.py#L20).
- Full pipeline started by run_fsm(...) in [main.py](../../agent/app/main.py#L21).

### 3.3 FSM ordered state chain

- FSM function starts in [fsm.py](../../agent/app/fsm.py#L32).

State order and callsites:
1. received in [fsm.py](../../agent/app/fsm.py#L47)
2. triage in [fsm.py](../../agent/app/fsm.py#L53)
3. route in [fsm.py](../../agent/app/fsm.py#L66)
4. submit in [fsm.py](../../agent/app/fsm.py#L80)
5. wait in [fsm.py](../../agent/app/fsm.py#L91)
6. score in [fsm.py](../../agent/app/fsm.py#L102)
7. respond in [fsm.py](../../agent/app/fsm.py#L115)
8. return final response in [fsm.py](../../agent/app/fsm.py#L124)

Audit log events emitted after each state:
- [fsm.py](../../agent/app/fsm.py#L49)
- [fsm.py](../../agent/app/fsm.py#L59)
- [fsm.py](../../agent/app/fsm.py#L72)
- [fsm.py](../../agent/app/fsm.py#L84)
- [fsm.py](../../agent/app/fsm.py#L95)
- [fsm.py](../../agent/app/fsm.py#L107)
- [fsm.py](../../agent/app/fsm.py#L119)

Error logging path:
- Exception logging in [fsm.py](../../agent/app/fsm.py#L126).

### 3.4 State internals one by one

#### received state

- Handler starts in [received.py](../../agent/app/states/received.py#L25).
- file_id generated in [received.py](../../agent/app/states/received.py#L41).
- SHA256 hash generated in [received.py](../../agent/app/states/received.py#L44).
- StateContext initialized in [received.py](../../agent/app/states/received.py#L47).
- Status set to triage in [received.py](../../agent/app/states/received.py#L52).

#### triage state

- Entropy function in [triage.py](../../agent/app/states/triage.py#L35).
- File type detection in [triage.py](../../agent/app/states/triage.py#L59).
- YARA check in [triage.py](../../agent/app/states/triage.py#L90).
- YARA path resolution in [triage.py](../../agent/app/states/triage.py#L129).
- YARA compile/cache in [triage.py](../../agent/app/states/triage.py#L153).
- External metadata placeholder in [triage.py](../../agent/app/states/triage.py#L176).
- Main triage handler in [triage.py](../../agent/app/states/triage.py#L196).
- Risk score computation starts in [triage.py](../../agent/app/states/triage.py#L224).
- Context updated for next state in [triage.py](../../agent/app/states/triage.py#L267).
- Status set to route in [triage.py](../../agent/app/states/triage.py#L269).

#### route state

- Route handler starts in [route.py](../../agent/app/states/route.py#L40).
- Inputs unpacked in [route.py](../../agent/app/states/route.py#L56).
- HUMAN_REVIEW branch starts in [route.py](../../agent/app/states/route.py#L68).
- DEEP branch starts in [route.py](../../agent/app/states/route.py#L86).
- FAST branch starts in [route.py](../../agent/app/states/route.py#L98).
- Rationale string created in [route.py](../../agent/app/states/route.py#L106).
- Analysis config selection in [route.py](../../agent/app/states/route.py#L109).
- Config mapping function in [route.py](../../agent/app/states/route.py#L120).
- Status set to submit in [route.py](../../agent/app/states/route.py#L115).

#### submit state

- Env-based AL config in [submit.py](../../agent/app/states/submit.py#L29).
- API key candidate handling in [submit.py](../../agent/app/states/submit.py#L36).
- Auth session builder in [submit.py](../../agent/app/states/submit.py#L59).
- Submit helper starts in [submit.py](../../agent/app/states/submit.py#L98).
- Submit URL built in [submit.py](../../agent/app/states/submit.py#L125).
- Multipart file payload in [submit.py](../../agent/app/states/submit.py#L131).
- Analysis json payload in [submit.py](../../agent/app/states/submit.py#L136).
- HTTP POST request in [submit.py](../../agent/app/states/submit.py#L145).
- submission_id extraction in [submit.py](../../agent/app/states/submit.py#L156).
- State handler starts in [submit.py](../../agent/app/states/submit.py#L172).
- status set to wait in [submit.py](../../agent/app/states/submit.py#L200).

#### wait state

- Poll settings in [wait.py](../../agent/app/states/wait.py#L98).
- Status endpoint helper in [wait.py](../../agent/app/states/wait.py#L103).
- Report fetch helper in [wait.py](../../agent/app/states/wait.py#L129).
- Main wait loop starts in [wait.py](../../agent/app/states/wait.py#L163).
- Status check each cycle in [wait.py](../../agent/app/states/wait.py#L184).
- On completed, report fetch in [wait.py](../../agent/app/states/wait.py#L189).
- status set to score in [wait.py](../../agent/app/states/wait.py#L193).
- Failure case in [wait.py](../../agent/app/states/wait.py#L196).
- Timeout raise in [wait.py](../../agent/app/states/wait.py#L209).

#### score state

- Metric parsing starts in [score.py](../../agent/app/states/score.py#L25).
- Detection count loop in [score.py](../../agent/app/states/score.py#L50).
- Severity tag extraction in [score.py](../../agent/app/states/score.py#L61).
- Confidence algorithm starts in [score.py](../../agent/app/states/score.py#L68).
- Risk normalization starts in [score.py](../../agent/app/states/score.py#L118).
- Main scoring handler starts in [score.py](../../agent/app/states/score.py#L144).
- confidence_level threshold set in [score.py](../../agent/app/states/score.py#L167).
- Final scoring details dict in [score.py](../../agent/app/states/score.py#L180).
- status set to respond in [score.py](../../agent/app/states/score.py#L197).

#### respond state

- Recommendation policy starts in [respond.py](../../agent/app/states/respond.py#L24).
- Final report builder starts in [respond.py](../../agent/app/states/respond.py#L48).
- Dashboard payload builder starts in [respond.py](../../agent/app/states/respond.py#L94).
- Main respond handler starts in [respond.py](../../agent/app/states/respond.py#L122).
- Recommendation assignment in [respond.py](../../agent/app/states/respond.py#L140).
- status set complete in [respond.py](../../agent/app/states/respond.py#L147).
- Final response object return in [respond.py](../../agent/app/states/respond.py#L153).

### 3.5 Model structures involved in flow

- RoutingDecision enum in [models.py](../../agent/app/models.py#L7).
- Recommendation enum in [models.py](../../agent/app/models.py#L13).
- ConfidenceLevel enum in [models.py](../../agent/app/models.py#L20).
- RiskProfile model in [models.py](../../agent/app/models.py#L25).
- StateContext model in [models.py](../../agent/app/models.py#L35).
- Audit trail field in [models.py](../../agent/app/models.py#L71).

### 3.6 Logging and dashboard rendering

- log_event function starts in [auditlog.py](../../agent/app/auditlog.py#L5).
- Log directory setup in [auditlog.py](../../agent/app/auditlog.py#L16).
- JSONL append write in [auditlog.py](../../agent/app/auditlog.py#L17).

Dashboard side:
- Streamlit title in [dashboard/app.py](../../dashboard/app.py#L5).
- Log file glob in [dashboard/app.py](../../dashboard/app.py#L7).
- Per-file section in [dashboard/app.py](../../dashboard/app.py#L10).
- Per-line JSON render in [dashboard/app.py](../../dashboard/app.py#L13).

## 4) End-to-end path summary that was explained

1. Docker starts agent and dashboard, both mount logs.
2. Client posts file to agent /submit.
3. main.py reads file and calls run_fsm.
4. FSM executes: received -> triage -> route -> submit -> wait -> score -> respond.
5. Every stage logs events to jsonl via auditlog.
6. Dashboard reads /logs jsonl files and displays entries.

## 5) Additional architecture notes provided in chat

- There are two related but separate execution modes:
  - app FSM runtime path under agent/app (FastAPI production-style flow)
  - api_demo script path under agent/api_demo (manual testing and API exploration)
- The api_demo queue-based ingest uses notification queue settings.nq.
- The app FSM path does direct submit + polling in states submit/wait.

## 6) Suggested next trace (offered in chat)

Offered follow-up was to create a strict clickable jump sequence for debugging one single sample request, following one request across files in exact open-next order.
