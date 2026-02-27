"""
Finite State Machine for malware analysis pipeline.

Orchestrates the flow through analysis states:
  Received -> Triage -> Route -> Submit -> Wait -> Score -> Respond
"""

from .auditlog import log_event
from .explain import explain_route
from .models import StateContext
from .states.received import handle_received
from .states.triage import handle_triage
from .states.route import handle_route
from .states.submit import handle_submit
from .states.wait import handle_wait
from .states.score import handle_score
from .states.respond import handle_respond


def log_state_transition(context: StateContext, new_state: str, details: dict = None):
    """Log state transition to audit trail."""
    entry = {
        "state": new_state,
        "file_id": context.file_id,
        "timestamp": context.completed_at.isoformat() if context.completed_at else None
    }
    if details:
        entry.update(details)
    context.audit_trail.append(entry)


def run_fsm(filename: str, content: bytes):
    """
    Execute the complete malware analysis FSM.

    Args:
        filename: Name of file to analyze
        content: Raw file bytes

    Returns:
        Final analysis response with recommendation and report
    """
    
    try:
        # STATE 1: RECEIVED
        # ================
        context = handle_received(filename, content)
        log_state_transition(context, "received", {"file_hash": context.file_hash})
        log_event("RECEIVED", {"file_id": context.file_id, "filename": filename}, context.file_id)
        
        # STATE 2: TRIAGE
        # ===============
        context = handle_triage(context)
        log_state_transition(context, "triage", {
            "entropy": context.risk_profile.entropy,
            "file_type": context.risk_profile.file_type,
            "initial_risk_score": context.risk_profile.initial_risk_score
        })
        log_event("TRIAGE", {
            "file_id": context.file_id,
            "risk_profile": context.risk_profile.dict()
        }, context.file_id)
        
        # STATE 3: ROUTE
        # ==============
        context = handle_route(context)
        log_state_transition(context, "route", {
            "routing_decision": context.routing_decision.value,
            "rationale": context.routing_rationale
        })
        explanation = explain_route(context.routing_decision.value, filename)
        log_event("ROUTE", {
            "file_id": context.file_id,
            "route": context.routing_decision.value,
            "explanation": explanation
        }, context.file_id)
        
        # STATE 4: SUBMIT
        # ===============
        context = handle_submit(context)
        log_state_transition(context, "submit", {
            "submission_id": context.submission_id
        })
        log_event("SUBMIT", {
            "file_id": context.file_id,
            "submission_id": context.submission_id
        }, context.file_id)
        
        # STATE 5: WAIT
        # =============
        context = handle_wait(context)
        log_state_transition(context, "wait", {
            "report_received": True
        })
        log_event("WAIT", {
            "file_id": context.file_id,
            "analysis_complete": True
        }, context.file_id)
        
        # STATE 6: SCORE
        # ==============
        context = handle_score(context)
        log_state_transition(context, "score", {
            "final_risk_score": context.final_risk_score,
            "confidence_level": context.confidence_level.value if context.confidence_level else None
        })
        log_event("SCORE", {
            "file_id": context.file_id,
            "final_risk_score": context.final_risk_score,
            "scoring_details": context.scoring_details
        }, context.file_id)
        
        # STATE 7: RESPOND
        # ================
        response = handle_respond(context)
        log_state_transition(context, "respond", {
            "recommendation": response["recommendation"]
        })
        log_event("RESPOND", {
            "file_id": context.file_id,
            "recommendation": response["recommendation"]
        }, context.file_id)
        
        return response
        
    except Exception as e:
        # Log error and fail gracefully
        log_event("ERROR", {
            "error": str(e),
            "error_type": type(e).__name__
        }, context.file_id if 'context' in locals() else "unknown")
        
        raise
