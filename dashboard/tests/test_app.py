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


def test_dashboard_renders_log_file_entries(tmp_path, monkeypatch) -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    log_file = tmp_path / "audit.jsonl"
    log_file.write_text(
        json.dumps({"event": "RECEIVED", "file_id": "abc"}) + "\n"
        + json.dumps({"event": "TRIAGE", "file_id": "abc"})
        + "\n",
        encoding="utf-8",
    )

    titles = []
    subheaders = []
    json_entries = []

    fake_streamlit = SimpleNamespace(
        title=lambda text: titles.append(text),
        subheader=lambda text: subheaders.append(text),
        json=lambda payload: json_entries.append(payload),
    )

    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    monkeypatch.setattr("glob.glob", lambda _pattern: [str(log_file)])

    _load_dashboard_app(app_path, "dashboard_app_test_render")

    assert titles == ["SentinelLine Audit Dashboard"]
    assert subheaders == [str(log_file)]
    assert json_entries == [
        {"event": "RECEIVED", "file_id": "abc"},
        {"event": "TRIAGE", "file_id": "abc"},
    ]


def test_dashboard_handles_no_logs(monkeypatch) -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"

    titles = []
    subheaders = []
    json_entries = []

    fake_streamlit = SimpleNamespace(
        title=lambda text: titles.append(text),
        subheader=lambda text: subheaders.append(text),
        json=lambda payload: json_entries.append(payload),
    )

    monkeypatch.setitem(sys.modules, "streamlit", fake_streamlit)
    monkeypatch.setattr("glob.glob", lambda _pattern: [])

    _load_dashboard_app(app_path, "dashboard_app_test_empty")

    assert titles == ["SentinelLine Audit Dashboard"]
    assert subheaders == []
    assert json_entries == []
