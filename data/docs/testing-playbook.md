# SentinelLine Testing Playbook

This guide explains:
- what commands to run
- why each test exists
- what output to expect
- what each result file means

Use this when you want to demo confidently or debug confusing output.

## 1) Why We Are Doing These Tests

SentinelLine is an orchestration layer. We test to prove:
1. API is reachable.
2. FSM runs all states.
3. Routing works (FAST, DEEP, HUMAN_REVIEW).
4. Response fields are correct.
5. Logs and dashboard match API output.
6. Stress summary matches expected outcomes.

## 2) Start Fresh (important)

If your output looks outdated, rebuild containers first.

```bash
cd /home/arifh/COMP4990-Capstone
docker compose down
docker compose up -d --build --force-recreate agent dashboard
```

Check health:

```bash
curl http://localhost:18000/health
```

Expected:
- `{\"status\":\"ok\"}`

## 3) Single-File Functional Tests

### Test A: Benign sample (expected FAST)

Command:

```bash
curl -s -F "file=@data/samples/benign.txt" http://localhost:18000/submit > /tmp/fast.json
python3 -m json.tool /tmp/fast.json
```

Why:
- validates low-risk path.

Expected key fields:
- `status`: usually `complete`
- `final_report.analysis_summary.routing_decision`: `FAST`
- `final_report.analysis_summary.initial_risk_profile.yara_hits`: usually `[]`
- `recommendation`: usually `IGNORE` when FAST has no YARA hits, no detections, and no severity indicators

### Test B: Definitive signature sample (expected HUMAN_REVIEW)

Command:

```bash
curl -s -F "file=@agent/test_payload.txt" http://localhost:18000/submit > /tmp/human.json
python3 -m json.tool /tmp/human.json
```

Why:
- validates high-risk route and escalation behavior.

Expected key fields:
- `final_report.analysis_summary.routing_decision`: `HUMAN_REVIEW`
- `final_report.analysis_summary.initial_risk_profile.yara_hits` includes `Definitive_Malware_Signature`
- `status`: `complete` or `pending_human_review` depending on currently running build

### Test C: Controlled suspicious sample (expected DEEP)

Command:

```bash
curl -s -F "file=@data/samples/deep_test.txt" http://localhost:18000/submit > /tmp/deep.json
python3 -m json.tool /tmp/deep.json
```

Why:
- validates the 1-3 YARA hit path that should route to DEEP.

Expected key fields:
- `final_report.analysis_summary.routing_decision`: `DEEP`
- `final_report.analysis_summary.initial_risk_profile.yara_hits`: usually one hit (`Triage_Networking_Capability`)
- `recommendation`: often `QUARANTINE` (depends on scoring output)

### Quick field-only view (easier to read)

```bash
python3 - <<'PY'
import json
for path in ['/tmp/fast.json', '/tmp/deep.json', '/tmp/human.json']:
    with open(path) as f:
        d = json.load(f)
    a = d.get('final_report', {}).get('analysis_summary', {})
    print('\nFILE:', path)
    print('status=', d.get('status'))
    print('recommendation=', d.get('recommendation'))
    print('route=', a.get('routing_decision'))
    print('yara_hits=', a.get('initial_risk_profile', {}).get('yara_hits', []))
    print('file_id=', d.get('final_report', {}).get('file_analysis', {}).get('file_id'))
PY
```

## 4) Stress Test (many files)

Command:

```bash
cd /home/arifh/COMP4990-Capstone
bash scripts/stress_queue.sh --concurrency 4 --repeat 2 --extra-file agent/test_payload.txt
```

Why:
- validates stability under parallel requests.
- gives pass/fail, latency, route distribution.

## 5) What Is In Stress Output Files

A stress run creates:

- `test_results/stress_<timestamp>/jobs.txt`
- `test_results/stress_<timestamp>/summary.tsv`
- `test_results/stress_<timestamp>/report.txt`
- `test_results/stress_<timestamp>/raw/job_<n>.json`

### jobs.txt
Queue plan before execution.

Columns:
1. `job_id`
2. `input_file`

Example:
- `1 data/samples/benign.txt`
- `2 agent/test_payload.txt`

### summary.tsv
One result line per job.

Columns:
1. `job_id`
2. `input_file`
3. `http_code`
4. `curl_rc`
5. `elapsed_ms`
6. `passed`
7. `status`
8. `recommendation`
9. `route`
10. `yara_count`
11. `error`

Interpretation:
- `http_code=200` and `curl_rc=0` means request succeeded.
- `passed=yes` means status is accepted by test rules.
- `error` non-empty explains failure reason.

### report.txt
Aggregated summary across all jobs.

Includes:
- total jobs
- passed/failed
- pass rate
- latency p50 and p95
- route distribution
- error counts

### raw/job_N.json
Raw API output for one job. This is the full truth for that request.

Important fields:
- `status`
- `recommendation`
- `final_report.file_analysis.file_id`
- `final_report.analysis_summary.routing_decision`
- `final_report.analysis_summary.initial_risk_profile.yara_hits`
- `dashboard_update`

## 6) Mapping raw job JSON to per-trace logs

1. Open `raw/job_N.json`.
2. Copy `final_report.file_analysis.file_id`.
3. Open `data/logs/<file_id>.jsonl`.

That log file contains state-by-state events:
- RECEIVED
- TRIAGE
- ROUTE
- SUBMIT
- WAIT
- SCORE
- RESPOND
- sometimes ESCALATED

## 7) Dashboard checks

Open:
- `http://localhost:8501`

What to verify:
1. Trace Overview shows recent traces.
2. Needs Analyst Review shows escalated traces (if any).
3. Escalation Queue Log shows queue events (if any).

## 8) Common Confusions (and fixes)

### "Route says HUMAN_REVIEW but status is complete"
Possible cause:
- older container/image still running.

Fix:

```bash
cd /home/arifh/COMP4990-Capstone
docker compose down
docker compose up -d --build --force-recreate agent dashboard
```

### "Raw JSON and dashboard do not match"
Possible cause:
- looking at old stress folder while dashboard shows newest logs.

Fix:
- compare trace by `file_id` and open matching `data/logs/<file_id>.jsonl`.

### "summary.tsv has yes/no but I do not know why"
Use columns 3,4,7,11:
- if `http_code != 200`: HTTP failure.
- if `curl_rc != 0`: network/timeout.
- if `status` unexpected: application-level behavior.
- `error` tells exact reason string.

## 9) Fast Demo Script (copy-paste)

```bash
cd /home/arifh/COMP4990-Capstone

echo "=== Health ==="
curl -s http://localhost:18000/health

echo "\n=== FAST sample ==="
curl -s -F "file=@data/samples/benign.txt" http://localhost:18000/submit > /tmp/fast.json
python3 - <<'PY'
import json
with open('/tmp/fast.json') as f:
    d=json.load(f)
a=d.get('final_report',{}).get('analysis_summary',{})
print('status=',d.get('status'),'route=',a.get('routing_decision'),'rec=',d.get('recommendation'))
PY

echo "\n=== HUMAN_REVIEW sample ==="
curl -s -F "file=@agent/test_payload.txt" http://localhost:18000/submit > /tmp/human.json
python3 - <<'PY'
import json
with open('/tmp/human.json') as f:
    d=json.load(f)
a=d.get('final_report',{}).get('analysis_summary',{})
print('status=',d.get('status'),'route=',a.get('routing_decision'),'rec=',d.get('recommendation'))
print('yara_hits=',a.get('initial_risk_profile',{}).get('yara_hits',[]))
print('trace_id=',d.get('final_report',{}).get('file_analysis',{}).get('file_id'))
PY

echo "\n=== DEEP sample ==="
curl -s -F "file=@data/samples/deep_test.txt" http://localhost:18000/submit > /tmp/deep.json
python3 - <<'PY'
import json
with open('/tmp/deep.json') as f:
    d=json.load(f)
a=d.get('final_report',{}).get('analysis_summary',{})
print('status=',d.get('status'),'route=',a.get('routing_decision'),'rec=',d.get('recommendation'))
print('yara_hits=',a.get('initial_risk_profile',{}).get('yara_hits',[]))
print('trace_id=',d.get('final_report',{}).get('file_analysis',{}).get('file_id'))
PY

echo "\n=== Stress run ==="
bash scripts/stress_queue.sh --concurrency 4 --repeat 2 --extra-file agent/test_payload.txt
```

This gives a complete proof run from API health to route checks to batch stress results.
