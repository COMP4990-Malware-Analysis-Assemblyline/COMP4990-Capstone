import streamlit as st
import json
import glob
import os
from datetime import datetime

st.title("SentinelLine Audit Dashboard")

LOG_DIR = os.getenv("LOG_DIR", "/logs")


def read_jsonl(path):
    events = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return events


def ts_to_iso(ts):
    if ts is None:
        return None
    try:
        return datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
    except (TypeError, ValueError):
        return None


def summarize_trace(events):
    summary = {
        "trace_id": None,
        "filename": None,
        "route": None,
        "policy_id": None,
        "submission_id": None,
        "final_score": None,
        "confidence": None,
        "recommendation": None,
        "status": None,
        "escalated": False,
        "updated_at": None,
    }

    for event in events:
        state = event.get("state")
        data = event.get("data", {})

        summary["trace_id"] = summary["trace_id"] or event.get("trace_id")
        summary["updated_at"] = ts_to_iso(event.get("timestamp")) or summary["updated_at"]
        summary["filename"] = data.get("filename") or summary["filename"]

        if state == "ROUTE":
            summary["route"] = data.get("route")
            policy = data.get("analysis_policy", {})
            summary["policy_id"] = policy.get("policy_id") if isinstance(policy, dict) else summary["policy_id"]

        elif state == "SUBMIT":
            summary["submission_id"] = data.get("submission_id")
            policy = data.get("analysis_policy", {})
            if isinstance(policy, dict) and not summary["policy_id"]:
                summary["policy_id"] = policy.get("policy_id")

        elif state == "RESPOND":
            summary["submission_id"] = data.get("submission_id") or summary["submission_id"]
            summary["route"] = data.get("route") or summary["route"]
            summary["recommendation"] = data.get("recommendation")
            summary["status"] = data.get("status")
            summary["final_score"] = data.get("final_score")
            summary["confidence"] = data.get("confidence")
            summary["escalated"] = bool(data.get("escalated", summary["escalated"]))
            policy = data.get("policy", {})
            if isinstance(policy, dict) and not summary["policy_id"]:
                summary["policy_id"] = policy.get("policy_id")

        elif state == "ESCALATED":
            summary["escalated"] = True
            summary["status"] = data.get("status", "pending_human_review")
            summary["route"] = data.get("route") or summary["route"]
            summary["submission_id"] = data.get("submission_id") or summary["submission_id"]
            policy = data.get("policy", {})
            if isinstance(policy, dict) and not summary["policy_id"]:
                summary["policy_id"] = policy.get("policy_id")

    if summary["escalated"] and not summary["status"]:
        summary["status"] = "pending_human_review"

    return summary


trace_files = sorted(glob.glob(f"{LOG_DIR}/*.jsonl"))
trace_files = [path for path in trace_files if not path.endswith("escalations.jsonl")]

summaries = []
for path in trace_files:
    events = read_jsonl(path)
    if not events:
        continue
    summary = summarize_trace(events)
    summary["log_file"] = os.path.basename(path)
    summaries.append(summary)

st.subheader("Trace Overview")
if not summaries:
    st.info(f"No trace logs found in {LOG_DIR}.")
else:
    summaries = sorted(
        summaries,
        key=lambda item: item.get("updated_at") or "",
        reverse=True,
    )
    st.dataframe(summaries, use_container_width=True)

    escalated = [item for item in summaries if item.get("escalated")]
    st.subheader("Needs Analyst Review")
    if escalated:
        st.dataframe(escalated, use_container_width=True)
    else:
        st.success("No escalated samples at the moment.")

    st.subheader("Trace Details")
    for item in summaries:
        label = f"{item.get('trace_id', 'unknown')} | {item.get('filename') or 'unknown file'}"
        with st.expander(label):
            st.json(item)

            detail_path = f"{LOG_DIR}/{item['log_file']}"
            for event in read_jsonl(detail_path):
                st.json(event)

queue_path = f"{LOG_DIR}/escalations.jsonl"
queue_events = read_jsonl(queue_path)
st.subheader("Escalation Queue Log")
if queue_events:
    queue_rows = []
    for event in queue_events:
        data = event.get("data", {})
        queue_rows.append(
            {
                "trace_id": event.get("trace_id"),
                "filename": data.get("filename"),
                "route": data.get("route"),
                "policy_id": (data.get("policy") or {}).get("policy_id") if isinstance(data.get("policy"), dict) else None,
                "submission_id": data.get("submission_id"),
                "status": data.get("status"),
                "final_score": data.get("final_score"),
                "confidence": data.get("confidence"),
                "timestamp": ts_to_iso(event.get("timestamp")),
            }
        )

    queue_rows = sorted(
        queue_rows,
        key=lambda item: item.get("timestamp") or "",
        reverse=True,
    )
    st.dataframe(queue_rows, use_container_width=True)
else:
    st.caption("No entries in escalations.jsonl yet.")
