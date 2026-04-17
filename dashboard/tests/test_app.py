import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


def _load_dashboard_app(app_path: Path, module_name: str) -> None:
    spec = importlib.util.spec_from_file_location(module_name, app_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)


class _Expander:
    def __init__(self, labels):
        self._labels = labels

    def __call__(self, label):
        self._labels.append(label)
        return self

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_dashboard_renders_log_file_entries(tmp_path, monkeypatch) -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    log_file = tmp_path / "audit.jsonl"
    queue_file = tmp_path / "escalations.jsonl"

    log_file.write_text(
        json.dumps(
            {
                "trace_id": "trace-1",
                "state": "ROUTE",
                "timestamp": 1710000000,
                "data": {
                    "filename": "sample.bin",
                    "route": "DEEP",
                    "analysis_policy": {"policy_id": "POL-001"},
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "trace_id": "trace-1",
                "state": "RESPOND",
                "timestamp": 1710000010,
                "data": {
                    "submission_id": "sub-1",
                    "route": "DEEP",
                    "recommendation": "ALERT",
                    "status": "complete",
                    "final_score": 62,
                    "confidence": "Confident",
                    "escalated": True,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    queue_file.write_text(
        json.dumps(
            {
                "trace_id": "trace-1",
                "timestamp": 1710000011,
                "data": {
                    "filename": "sample.bin",
                    "route": "DEEP",
                    "policy": {"policy_id": "POL-001"},
                    "submission_id": "sub-1",
                    "status": "pending_human_review",
                    "final_score": 62,
                    "confidence": "Confident",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    titles = []
    subheaders = []
    infos = []
    captions = []
    successes = []
    dataframes = []
    json_entries = []
    expanders = []

    fake_streamlit = SimpleNamespace(
        title=lambda text: titles.append(text),
        subheader=lambda text: subheaders.append(text),
        info=lambda text: infos.append(text),
        caption=lambda text: captions.append(text),
        success=lambda text: successes.append(text),
        dataframe=lambda rows, use_container_width=True: dataframes.append(rows),
        json=lambda payload: json_entries.append(payload),
        expander=_Expander(expanders),
    )

    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)

    _load_dashboard_app(app_path, "dashboard_app_test_render")

    assert titles == ["SentinelLine Audit Dashboard"]
    assert "Trace Overview" in subheaders
    assert "Needs Analyst Review" in subheaders
    assert "Trace Details" in subheaders
    assert "Escalation Queue Log" in subheaders
    assert len(dataframes) == 3
    assert infos == []
    assert captions == []
    assert successes == []
    assert any(entry.get("trace_id") == "trace-1" for entry in json_entries)
    assert expanders == ["trace-1 | sample.bin"]


def test_dashboard_handles_no_logs(monkeypatch) -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"

    titles = []
    subheaders = []
    infos = []
    captions = []
    dataframes = []
    json_entries = []
    expanders = []

    fake_streamlit = SimpleNamespace(
        title=lambda text: titles.append(text),
        subheader=lambda text: subheaders.append(text),
        info=lambda text: infos.append(text),
        caption=lambda text: captions.append(text),
        success=lambda _text: None,
        dataframe=lambda rows, use_container_width=True: dataframes.append(rows),
        json=lambda payload: json_entries.append(payload),
        expander=_Expander(expanders),
    )

    monkeypatch.setenv("LOG_DIR", "/tmp/does-not-exist")
    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)

    _load_dashboard_app(app_path, "dashboard_app_test_empty")

    assert titles == ["SentinelLine Audit Dashboard"]
    assert "Trace Overview" in subheaders
    assert "Escalation Queue Log" in subheaders
    assert len(infos) == 1
    assert len(captions) == 1
    assert dataframes == []
    assert json_entries == []
    assert expanders == []
