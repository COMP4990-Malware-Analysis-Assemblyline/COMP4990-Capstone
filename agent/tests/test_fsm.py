from datetime import datetime, timezone

import pytest

from app.models import ConfidenceLevel, RiskProfile, RoutingDecision, StateContext
from app import fsm


def _base_context() -> StateContext:
    return StateContext(
        file_id="file-123",
        filename="sample.bin",
        file_content=b"payload",
        file_hash="hash-123",
        status="triage",
        created_at=datetime.now(timezone.utc),
    )


def test_run_fsm_happy_path(monkeypatch) -> None:
    calls = []

    def fake_received(filename, content):
        calls.append("received")
        return _base_context()

    def fake_triage(context):
        calls.append("triage")
        context.risk_profile = RiskProfile(
            entropy=2.0,
            file_type="text/plain",
            file_size=len(context.file_content or b""),
            yara_hits=[],
            initial_risk_score=10.0,
            metadata_summary={"has_definitive_signature": False},
        )
        context.status = "route"
        return context

    def fake_route(context):
        calls.append("route")
        context.routing_decision = RoutingDecision.FAST
        context.routing_rationale = "Low risk"
        context.analysis_config = {"timeout": 60, "analysis_type": "quick", "deep_scan": False}
        context.status = "submit"
        return context

    def fake_submit(context):
        calls.append("submit")
        context.submission_id = "sub-1"
        context.submitted_at = datetime.now(timezone.utc)
        context.status = "wait"
        return context

    def fake_wait(context):
        calls.append("wait")
        context.analysis_report = {"derived": {"score": -800}, "results": {}, "result": {"tags": []}}
        context.completed_at = datetime.now(timezone.utc)
        context.status = "score"
        return context

    def fake_score(context):
        calls.append("score")
        context.final_risk_score = 8.0
        context.confidence_level = ConfidenceLevel.CONFIDENT
        context.confidence_score = 0.9
        context.scoring_details = {"assemblyline_score": -800}
        context.status = "respond"
        return context

    def fake_respond(context):
        calls.append("respond")
        return {
            "recommendation": "IGNORE",
            "final_report": {"audit_trail": {"states_visited": []}},
            "dashboard_update": {"status": "complete"},
            "status": "complete",
        }

    monkeypatch.setattr(fsm, "handle_received", fake_received)
    monkeypatch.setattr(fsm, "handle_triage", fake_triage)
    monkeypatch.setattr(fsm, "handle_route", fake_route)
    monkeypatch.setattr(fsm, "handle_submit", fake_submit)
    monkeypatch.setattr(fsm, "handle_wait", fake_wait)
    monkeypatch.setattr(fsm, "handle_score", fake_score)
    monkeypatch.setattr(fsm, "handle_respond", fake_respond)
    monkeypatch.setattr(fsm, "explain_route", lambda *_: "explanation")
    monkeypatch.setattr(fsm, "log_event", lambda *_: None)

    result = fsm.run_fsm("sample.bin", b"payload")

    assert result["status"] == "complete"
    assert result["recommendation"] == "IGNORE"
    assert calls == ["received", "triage", "route", "submit", "wait", "score", "respond"]


def test_run_fsm_logs_error_with_file_id(monkeypatch) -> None:
    events = []

    monkeypatch.setattr(fsm, "handle_received", lambda *_: _base_context())

    def failing_triage(_context):
        raise RuntimeError("triage failed")

    monkeypatch.setattr(fsm, "handle_triage", failing_triage)

    def capture_event(event_type, payload, file_id):
        events.append((event_type, payload, file_id))

    monkeypatch.setattr(fsm, "log_event", capture_event)

    with pytest.raises(RuntimeError, match="triage failed"):
        fsm.run_fsm("sample.bin", b"payload")

    assert events[-1][0] == "ERROR"
    assert events[-1][2] == "file-123"
    assert events[-1][1]["error_type"] == "RuntimeError"
