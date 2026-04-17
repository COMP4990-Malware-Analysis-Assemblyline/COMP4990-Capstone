from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum


class RoutingDecision(str, Enum):
    FAST = "FAST"
    DEEP = "DEEP"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class Recommendation(str, Enum):
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    IGNORE = "IGNORE"
    ALERT = "ALERT"


class ConfidenceLevel(str, Enum):
    CONFIDENT = "Confident"
    UNCERTAIN = "Uncertain"


class RiskProfile(BaseModel):
    """Risk profile containing initial file characteristics."""
    entropy: Optional[float] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    yara_hits: List[str] = []
    initial_risk_score: Optional[float] = None
    metadata_summary: Optional[Dict[str, Any]] = None


class StateContext(BaseModel):
    """Complete context carrying through the FSM."""
    file_id: str
    filename: str
    file_content: Optional[bytes] = None
    file_hash: Optional[str] = None
    status: str  # Current state: received, triage, route, submit, wait, score, respond
    created_at: datetime
    
    # Triage results
    risk_profile: Optional[RiskProfile] = None
    
    # Routing results
    routing_decision: Optional[RoutingDecision] = None
    routing_rationale: Optional[str] = None
    
    # Submission results
    submission_id: Optional[str] = None
    submitted_at: Optional[datetime] = None
    analysis_config: Optional[Dict[str, Any]] = None
    
    # Analysis results
    completed_at: Optional[datetime] = None
    analysis_report: Optional[Dict[str, Any]] = None
    
    # Scoring results
    final_risk_score: Optional[float] = None
    confidence_level: Optional[ConfidenceLevel] = None
    confidence_score: Optional[float] = None
    scoring_details: Optional[Dict[str, Any]] = None
    
    # Final response
    recommendation: Optional[Recommendation] = None
    final_report: Optional[Dict[str, Any]] = None
    
    # Audit trail
    audit_trail: List[Dict[str, Any]] = []
    
    model_config = ConfigDict(arbitrary_types_allowed=True)


class Decision(BaseModel):
    trace_id: str
    route: str
    explanation: str
