from datetime import datetime, timezone

from app.models import RiskProfile, RoutingDecision, StateContext
from app.states.route import handle_route


def _context(profile: RiskProfile) -> StateContext:
    return StateContext(
        file_id="file-1",
        filename="sample.bin",
        file_content=b"abc",
        file_hash="hash-1",
        status="route",
        created_at=datetime.now(timezone.utc),
        risk_profile=profile,
    )


def test_handle_route_human_review_for_definitive_signature() -> None:
    profile = RiskProfile(
        entropy=5.0,
        file_type="text/plain",
        file_size=12,
        yara_hits=["Definitive_Malware_Signature"],
        initial_risk_score=40.0,
        metadata_summary={"has_definitive_signature": True},
    )

    updated = handle_route(_context(profile))

    assert updated.routing_decision == RoutingDecision.HUMAN_REVIEW
    assert updated.status == "submit"
    assert updated.analysis_config["analysis_type"] == "comprehensive"


def test_handle_route_deep_for_medium_score() -> None:
    profile = RiskProfile(
        entropy=6.5,
        file_type="application/pdf",
        file_size=24,
        yara_hits=[],
        initial_risk_score=50.0,
        metadata_summary={"has_definitive_signature": False},
    )

    updated = handle_route(_context(profile))

    assert updated.routing_decision == RoutingDecision.DEEP
    assert updated.status == "submit"
    assert updated.analysis_config["analysis_type"] == "standard"


def test_handle_route_fast_for_low_risk() -> None:
    profile = RiskProfile(
        entropy=2.0,
        file_type="text/plain",
        file_size=8,
        yara_hits=[],
        initial_risk_score=5.0,
        metadata_summary={"has_definitive_signature": False},
    )

    updated = handle_route(_context(profile))

    assert updated.routing_decision == RoutingDecision.FAST
    assert updated.status == "submit"
    assert updated.analysis_config["analysis_type"] == "quick"
