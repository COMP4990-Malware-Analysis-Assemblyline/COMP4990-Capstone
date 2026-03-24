"""
Respond State Handler

Generates final report and recommendations.

Input:
    - Final risk score
    - Confidence level
    - All state transition logs

Output:
    - Final JSON report
    - Dashboard update

Description:
    Final state in the analysis pipeline. Generates a final recommendation
    (Block, Quarantine, Ignore, etc.) and comprehensive report for analysis.
    Fulfills explainability requirements by providing complete audit trail.
"""

from ..models import StateContext, Recommendation


def determine_recommendation(final_risk_score: float, confidence_level: str) -> Recommendation:
    """
    Determine action recommendation based on risk score and confidence.
    
    Args:
        final_risk_score: Final normalized risk score (0-100)
        confidence_level: 'Confident' or 'Uncertain'
        
    Returns:
        Recommendation enum value
    """
    if final_risk_score >= 75:
        return Recommendation.BLOCK
    elif final_risk_score >= 50:
        # Moderate risk: quarantine if confident, alert if uncertain
        return Recommendation.QUARANTINE if confidence_level == "Confident" else Recommendation.ALERT
    elif final_risk_score >= 25:
        # Low-moderate risk: quarantine if confident, ignore if uncertain
        return Recommendation.QUARANTINE if confidence_level == "Confident" else Recommendation.IGNORE
    else:
        # Very low risk
        return Recommendation.IGNORE


def _parse_detection_rate_percent(raw_detection_rate) -> float:
    """Parse detection rate from score details, accepting numeric or percent text."""
    if raw_detection_rate is None:
        return 0.0

    if isinstance(raw_detection_rate, (int, float)):
        return float(raw_detection_rate)

    if isinstance(raw_detection_rate, str):
        text = raw_detection_rate.strip()
        if text.endswith("%"):
            text = text[:-1].strip()
            try:
                return float(text)
            except ValueError:
                return 0.0

        try:
            return float(text)
        except ValueError:
            return 0.0

    return 0.0


def should_force_ignore_low_signal_fast(context: StateContext) -> bool:
    """Guardrail: no-signal FAST samples should not be quarantined by midpoint normalization."""
    if not context.routing_decision or context.routing_decision.value != "FAST":
        return False

    yara_hits = context.risk_profile.yara_hits if context.risk_profile else []
    if yara_hits:
        return False

    details = context.scoring_details or {}
    detection_rate_percent = _parse_detection_rate_percent(details.get("detection_rate"))
    severity_indicators = details.get("severity_indicators") or []
    assemblyline_score = details.get("assemblyline_score")

    no_detections = detection_rate_percent == 0.0
    no_severity = len(severity_indicators) == 0
    neutral_or_benign_score = assemblyline_score in (0, None) or (isinstance(assemblyline_score, (int, float)) and assemblyline_score < 0)

    return no_detections and no_severity and neutral_or_benign_score


def should_escalate_to_human(context: StateContext) -> bool:
    """Escalate high-risk route or uncertain medium/high outcomes for analyst review."""
    if context.routing_decision and context.routing_decision.value == "HUMAN_REVIEW":
        return True

    confidence = context.confidence_level.value if context.confidence_level else "Uncertain"
    if confidence == "Uncertain" and (context.final_risk_score or 0) >= 50:
        return True

    return False


def build_final_report(context: StateContext) -> dict:
    """
    Build comprehensive final report with full audit trail.
    
    Args:
        context: Complete StateContext with all analysis data
        
    Returns:
        Final report dictionary
    """
    return {
        "file_analysis": {
            "file_id": context.file_id,
            "filename": context.filename,
            "file_hash": context.file_hash,
            "file_size": context.risk_profile.file_size if context.risk_profile else None
        },
        "risk_assessment": {
            "final_risk_score": context.final_risk_score,
            "confidence_level": context.confidence_level.value if context.confidence_level else None,
            "confidence_score": context.confidence_score,
            "recommendation": context.recommendation.value if context.recommendation else None
        },
        "analysis_summary": {
            "initial_risk_profile": {
                "entropy": context.risk_profile.entropy if context.risk_profile else None,
                "file_type": context.risk_profile.file_type if context.risk_profile else None,
                "yara_hits": context.risk_profile.yara_hits if context.risk_profile else [],
                "initial_risk_score": context.risk_profile.initial_risk_score if context.risk_profile else None
            },
            "routing_decision": context.routing_decision.value if context.routing_decision else None,
            "routing_rationale": context.routing_rationale,
            "analysis_policy": context.analysis_config,
        },
        "scoring_details": context.scoring_details,
        "timestamps": {
            "created_at": context.created_at.isoformat() if context.created_at else None,
            "submitted_at": context.submitted_at.isoformat() if context.submitted_at else None,
            "completed_at": context.completed_at.isoformat() if context.completed_at else None
        },
        "audit_trail": {
            "states_visited": [entry.get("state") for entry in context.audit_trail],
            "full_history": context.audit_trail
        }
    }


def build_dashboard_update(context: StateContext) -> dict:
    """
    Build data for dashboard visualization.
    
    Args:
        context: Complete StateContext
        
    Returns:
        Dashboard update dictionary
    """
    return {
        "file_id": context.file_id,
        "filename": context.filename,
        "status": "complete",
        "risk_level": (
            "CRITICAL" if context.final_risk_score >= 75
            else "HIGH" if context.final_risk_score >= 50
            else "MEDIUM" if context.final_risk_score >= 25
            else "LOW"
        ),
        "final_score": context.final_risk_score,
        "recommendation": context.recommendation.value if context.recommendation else None,
        "confidence": context.confidence_level.value if context.confidence_level else None,
        "timestamp": context.completed_at.isoformat() if context.completed_at else None,
        "routing_path": context.routing_decision.value if context.routing_decision else None,
        "policy_id": context.analysis_config.get("policy_id") if context.analysis_config else None,
        "escalated": should_escalate_to_human(context),
    }


def handle_respond(context: StateContext) -> dict:
    """
    Generate final report and recommendations.

    Args:
        context: Complete StateContext with all analysis data and logs

    Returns:
        Final response containing:
            - recommendation: One of ('BLOCK', 'QUARANTINE', 'IGNORE', 'ALERT')
            - final_report: Comprehensive JSON report
            - dashboard_update: Data for dashboard visualization
            - status: 'complete'
    """
    if context.final_risk_score is None:
        raise ValueError("final_risk_score required for response")
    
    # Determine recommendation.
    # Guardrail prevents benign/no-signal FAST samples from being quarantined.
    if should_force_ignore_low_signal_fast(context):
        recommendation = Recommendation.IGNORE
    else:
        recommendation = determine_recommendation(
            context.final_risk_score,
            context.confidence_level.value if context.confidence_level else "Uncertain"
        )
    
    escalated = should_escalate_to_human(context)

    # Update context
    context.recommendation = recommendation
    context.status = "pending_human_review" if escalated else "complete"
    
    # Build reports
    final_report = build_final_report(context)
    dashboard_update = build_dashboard_update(context)
    
    return {
        "recommendation": recommendation.value,
        "final_report": final_report,
        "dashboard_update": dashboard_update,
        "status": context.status,
        "escalated": escalated,
    }
