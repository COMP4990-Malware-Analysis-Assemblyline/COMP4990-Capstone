import json, uuid, time, os

LOG_DIR = os.getenv("LOG_DIR", "./logs")

def log_event(state, data, trace_id=None):
    if not trace_id:
        trace_id = str(uuid.uuid4())

    entry = {
        "trace_id": trace_id,
        "state": state,
        "data": data,
        "timestamp": time.time()
    }

    os.makedirs(LOG_DIR, exist_ok=True)
    with open(f"{LOG_DIR}/{trace_id}.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")

    return trace_id
