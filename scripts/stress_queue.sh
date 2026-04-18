#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_URL="http://localhost:18000/submit"
INPUT_GLOB="data/samples/*"
EXTRA_FILE=""
CONCURRENCY=4
REPEAT=1
TIMEOUT=180
OUT_DIR="${ROOT_DIR}/test_results"

usage() {
  cat <<'EOF'
Queue-based stress test for SentinelLine submit endpoint.

Usage:
  scripts/stress_queue.sh [options]

Options:
  --url URL              Submit endpoint URL (default: http://localhost:18000/submit)
  --input-glob GLOB      File glob relative to repo root (default: data/samples/*)
  --extra-file PATH      Extra file relative to repo root (example: agent/test_payload.txt)
  --concurrency N        Number of parallel in-flight requests (default: 4)
  --repeat N             Repeat each file N times (default: 1)
  --timeout SECONDS      Curl max time per request (default: 180)
  --out-dir PATH         Output directory for raw responses (default: ./test_results)
  -h, --help             Show this help

Examples:
  scripts/stress_queue.sh --concurrency 8 --repeat 10
  scripts/stress_queue.sh --extra-file agent/test_payload.txt --repeat 5
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      TARGET_URL="$2"
      shift 2
      ;;
    --input-glob)
      INPUT_GLOB="$2"
      shift 2
      ;;
    --extra-file)
      EXTRA_FILE="$2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    --repeat)
      REPEAT="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required but not installed." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required but not installed." >&2
  exit 1
fi

if ! [[ "$CONCURRENCY" =~ ^[0-9]+$ ]] || [[ "$CONCURRENCY" -lt 1 ]]; then
  echo "--concurrency must be an integer >= 1" >&2
  exit 1
fi

if ! [[ "$REPEAT" =~ ^[0-9]+$ ]] || [[ "$REPEAT" -lt 1 ]]; then
  echo "--repeat must be an integer >= 1" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUT_DIR}/stress_${RUN_ID}"
mkdir -p "$RUN_DIR/raw"

mapfile -t FILES < <(cd "$ROOT_DIR" && compgen -G "$INPUT_GLOB" || true)
if [[ -n "$EXTRA_FILE" ]]; then
  FILES+=("$EXTRA_FILE")
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No files matched input pattern: ${INPUT_GLOB}" >&2
  exit 1
fi

JOB_FILE="$RUN_DIR/jobs.txt"
SUMMARY_TSV="$RUN_DIR/summary.tsv"
: > "$JOB_FILE"
: > "$SUMMARY_TSV"
printf 'job_id\tinput_file\thttp_code\tcurl_rc\telapsed_ms\tpassed\tstatus\trecommendation\troute\tyara_count\terror\n' >> "$SUMMARY_TSV"

job_count=0
for rel_file in "${FILES[@]}"; do
  abs_file="${ROOT_DIR}/${rel_file}"
  if [[ ! -f "$abs_file" ]]; then
    echo "Skipping missing file: $rel_file" >&2
    continue
  fi
  for ((i=1; i<=REPEAT; i++)); do
    job_count=$((job_count + 1))
    printf '%s\t%s\n' "$job_count" "$rel_file" >> "$JOB_FILE"
  done
done

if [[ "$job_count" -eq 0 ]]; then
  echo "No valid input files found." >&2
  exit 1
fi

echo "Starting stress test"
echo "  URL: ${TARGET_URL}"
echo "  Files: ${#FILES[@]}"
echo "  Repeat each: ${REPEAT}"
echo "  Total jobs: ${job_count}"
echo "  Concurrency: ${CONCURRENCY}"
echo "  Output: ${RUN_DIR}"

run_one() {
  local id="$1"
  local rel_file="$2"
  local abs_file="${ROOT_DIR}/${rel_file}"
  local raw_out="${RUN_DIR}/raw/job_${id}.json"
  local started ended elapsed_ms
  local http_code="000"
  local curl_rc=0

  started="$(date +%s%3N 2>/dev/null || true)"
  if [[ -z "$started" ]]; then
    started="$(( $(date +%s) * 1000 ))"
  fi

  http_code="$(curl -sS -m "$TIMEOUT" -o "$raw_out" -w '%{http_code}' \
    -F "file=@${abs_file}" "$TARGET_URL")" || curl_rc=$?

  ended="$(date +%s%3N 2>/dev/null || true)"
  if [[ -z "$ended" ]]; then
    ended="$(( $(date +%s) * 1000 ))"
  fi
  elapsed_ms="$((ended - started))"

  python3 - "$id" "$rel_file" "$http_code" "$curl_rc" "$elapsed_ms" "$raw_out" >> "$SUMMARY_TSV" <<'PY'
import json
import pathlib
import sys

job_id, rel_file, http_code, curl_rc, elapsed_ms, raw_path = sys.argv[1:]

status = ""
recommendation = ""
route = ""
yara_count = ""
error = ""
passed = "no"

if curl_rc != "0":
    error = f"curl_exit_{curl_rc}"
elif http_code != "200":
    error = f"http_{http_code}"
else:
    try:
        payload = json.loads(pathlib.Path(raw_path).read_text(encoding="utf-8"))
        status = str(payload.get("status", ""))
        recommendation = str(payload.get("recommendation", ""))
        route = str((payload.get("final_report", {})
                     .get("analysis_summary", {})
                     .get("routing_decision", "")))
        yara_hits = ((payload.get("final_report", {})
                      .get("analysis_summary", {})
                      .get("initial_risk_profile", {})
                      .get("yara_hits", [])))
        yara_count = str(len(yara_hits))
        passed = "yes" if status in {"complete", "pending_human_review"} else "no"
        if passed == "no":
            error = f"status_{status or 'missing'}"
    except Exception as exc:
        error = f"json_parse_error:{type(exc).__name__}"

print("\t".join([
    job_id,
    rel_file,
    http_code,
    curl_rc,
    elapsed_ms,
    passed,
    status,
    recommendation,
    route,
    yara_count,
    error,
]))
PY
}

in_flight=0
while IFS=$'\t' read -r id rel_file; do
  run_one "$id" "$rel_file" &
  in_flight=$((in_flight + 1))

  if (( in_flight >= CONCURRENCY )); then
    wait -n
    in_flight=$((in_flight - 1))
  fi
done < "$JOB_FILE"

wait

REPORT_FILE="$RUN_DIR/report.txt"
python3 - "$SUMMARY_TSV" > "$REPORT_FILE" <<'PY'
import statistics
import sys

summary_path = sys.argv[1]
rows = []
with open(summary_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        cols = line.split("\t")
        if not cols:
            continue
        # Skip header row and malformed lines.
        if cols[0] == "job_id" or len(cols) < 11:
            continue
        rows.append(cols)

total = len(rows)
passes = sum(1 for r in rows if r[5] == "yes")
fails = total - passes

latencies = [int(r[4]) for r in rows if r[4].isdigit()]
p50 = int(statistics.median(latencies)) if latencies else 0
lat_sorted = sorted(latencies)
p95 = lat_sorted[max(0, int(len(lat_sorted) * 0.95) - 1)] if lat_sorted else 0

route_counts = {}
error_counts = {}
for r in rows:
    route = r[8] or "(none)"
    route_counts[route] = route_counts.get(route, 0) + 1
    if r[10]:
      error_counts[r[10]] = error_counts.get(r[10], 0) + 1

print("Stress test summary")
print(f"Total jobs: {total}")
print(f"Passed: {passes}")
print(f"Failed: {fails}")
print(f"Pass rate: {(passes/total*100 if total else 0):.1f}%")
print(f"Latency p50 (ms): {p50}")
print(f"Latency p95 (ms): {p95}")
print("")
print("Route distribution:")
for k in sorted(route_counts):
    print(f"- {k}: {route_counts[k]}")

if error_counts:
    print("")
    print("Errors:")
    for k in sorted(error_counts):
        print(f"- {k}: {error_counts[k]}")
PY

cat "$REPORT_FILE"
echo
echo "Detailed results: ${SUMMARY_TSV}"
echo "Raw responses: ${RUN_DIR}/raw"
