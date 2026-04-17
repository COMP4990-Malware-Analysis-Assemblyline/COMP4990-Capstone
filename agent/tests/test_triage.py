from datetime import datetime, timezone

from app.models import StateContext
from app.states import triage


def _context() -> StateContext:
    return StateContext(
        file_id="file-1",
        filename="sample.bin",
        file_content=b"abc123",
        file_hash="hash-1",
        status="triage",
        created_at=datetime.now(timezone.utc),
    )


def test_calculate_entropy_empty_bytes_is_zero() -> None:
    assert triage.calculate_entropy(b"") == 0.0


def test_calculate_entropy_uniform_distribution_is_high() -> None:
    data = bytes(range(256)) * 2
    assert triage.calculate_entropy(data) > 7.5


def test_resolve_yara_rules_path_prefers_env_file(tmp_path, monkeypatch) -> None:
    rules = tmp_path / "custom_rules.yar"
    rules.write_text("rule Example { condition: true }", encoding="utf-8")

    monkeypatch.setenv("TRIAGE_YARA_RULES_PATH", str(rules))
    resolved = triage.resolve_yara_rules_path()

    assert resolved == rules


def test_handle_triage_scores_definitive_match(monkeypatch) -> None:
    context = _context()

    monkeypatch.setattr(triage, "calculate_entropy", lambda _: 5.0)
    monkeypatch.setattr(triage, "detect_file_type", lambda *_: "text/plain")
    monkeypatch.setattr(
        triage,
        "check_yara_rules",
        lambda *_: {
            "hits": [triage.DEFINITIVE_RULE_NAME],
            "hit_count": 1,
            "has_definitive": True,
        },
    )
    monkeypatch.setattr(
        triage,
        "query_external_apis",
        lambda *_: {"virustotal_detections": 0, "first_seen": None, "known_good": False},
    )

    updated = triage.handle_triage(context)

    assert updated.status == "route"
    assert updated.risk_profile is not None
    assert updated.risk_profile.initial_risk_score == 80.0
    assert triage.DEFINITIVE_RULE_NAME in updated.risk_profile.yara_hits


def test_handle_triage_caps_score_at_100(monkeypatch) -> None:
    context = _context()

    monkeypatch.setattr(triage, "calculate_entropy", lambda _: 8.0)
    monkeypatch.setattr(triage, "detect_file_type", lambda *_: "application/octet-stream")
    monkeypatch.setattr(
        triage,
        "check_yara_rules",
        lambda *_: {
            "hits": ["A", "B", "C", "D"],
            "hit_count": 4,
            "has_definitive": False,
        },
    )
    monkeypatch.setattr(
        triage,
        "query_external_apis",
        lambda *_: {"virustotal_detections": 3, "first_seen": None, "known_good": False},
    )

    updated = triage.handle_triage(context)

    assert updated.risk_profile is not None
    assert updated.risk_profile.initial_risk_score == 100


def test_query_external_apis_without_api_key_returns_defaults(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    metadata = triage.query_external_apis("deadbeef")

    assert metadata == {
        "virustotal_detections": 0,
        "first_seen": None,
        "known_good": False,
    }


def test_query_external_apis_virustotal_success(monkeypatch) -> None:
    class FakeResponse:
        status_code = 200
        content = b"ok"

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "attributes": {
                        "first_submission_date": 1710000000,
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                        },
                    }
                }
            }

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(triage.requests, "get", lambda *args, **kwargs: FakeResponse())

    metadata = triage.query_external_apis("deadbeef")

    assert metadata["virustotal_detections"] == 3
    assert metadata["first_seen"] == 1710000000
    assert metadata["known_good"] is False


def test_query_external_apis_fails_open(monkeypatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-key")

    def _raise(*_args, **_kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(triage.requests, "get", _raise)

    metadata = triage.query_external_apis("deadbeef")

    assert metadata == {
        "virustotal_detections": 0,
        "first_seen": None,
        "known_good": False,
    }
