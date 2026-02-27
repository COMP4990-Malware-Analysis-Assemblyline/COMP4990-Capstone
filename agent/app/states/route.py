"""
Route State Handler

Determines the analysis depth based on risk profile.

Input:
    - Populated RiskProfile

Output:
    - Routing decision: one of ('FAST', 'DEEP', 'HUMAN_REVIEW')

Description:
    Logic gate that applies explicit deterministic rules to data gathered during Triage.
    Automates routing decisions to prioritize next steps based on initial risk assessment.
"""

from ..models import StateContext, RoutingDecision


ROUTING_RULES = {
    # FAST: Low risk, known benign patterns
    "FAST": {
        "max_risk_score": 25,
        "conditions": ["entropy < 6.0", "file_type in known_safe"]
    },
    # DEEP: Medium risk, needs comprehensive analysis
    "DEEP": {
        "min_risk_score": 25,
        "max_risk_score": 75,
        "conditions": ["requires_comprehensive_analysis"]
    },
    # HUMAN_REVIEW: High risk or suspicious patterns
    "HUMAN_REVIEW": {
        "min_risk_score": 75,
        "conditions": ["yara_hits > 0 OR high_entropy OR unknown_type"]
    }
}


def handle_route(context: StateContext) -> StateContext:
    """
    Route file to appropriate analysis path based on risk profile.

    Args:
        context: StateContext with populated RiskProfile

    Returns:
        Updated StateContext with:
            - routing_decision: One of ('FAST', 'DEEP', 'HUMAN_REVIEW')
            - routing_rationale: Explanation of routing decision
            - status: 'submit'
    """
    if not context.risk_profile:
        raise ValueError("RiskProfile required for routing")
    
    risk_score = context.risk_profile.initial_risk_score or 0
    entropy = context.risk_profile.entropy or 0
    file_type = context.risk_profile.file_type or ""
    yara_hits = context.risk_profile.yara_hits or []
    
    # Apply routing rules
    routing_decision = None
    rationale = ""
    reasons = []
    
    # Check for HUMAN_REVIEW conditions
    if risk_score >= 75:
        routing_decision = RoutingDecision.HUMAN_REVIEW
        reasons.append(f"High risk score: {risk_score:.1f}")
    elif yara_hits:
        routing_decision = RoutingDecision.HUMAN_REVIEW
        reasons.append(f"YARA matches detected: {', '.join(yara_hits)}")
    elif entropy > 7.5:
        routing_decision = RoutingDecision.HUMAN_REVIEW
        reasons.append(f"Very high entropy: {entropy:.2f} (possibly encrypted/compressed)")
    elif "unknown" in file_type.lower():
        routing_decision = RoutingDecision.HUMAN_REVIEW
        reasons.append("Unknown file type detected")
    
    # Check for DEEP analysis conditions
    elif 25 <= risk_score < 75:
        routing_decision = RoutingDecision.DEEP
        reasons.append(f"Medium risk score: {risk_score:.1f} requires comprehensive analysis")
    elif 6.0 <= entropy <= 7.5:
        routing_decision = RoutingDecision.DEEP
        reasons.append(f"Moderate entropy: {entropy:.2f} (potentially suspicious)")
    
    # Otherwise, FAST analysis
    else:
        routing_decision = RoutingDecision.FAST
        reasons.append(f"Low risk score: {risk_score:.1f}")
        if entropy < 4.0:
            reasons.append(f"Low entropy: {entropy:.2f}")
    
    rationale = " | ".join(reasons)
    
    # Determine analysis configuration based on routing
    analysis_config = determine_analysis_config(routing_decision)
    
    # Update StateContext
    context.routing_decision = routing_decision
    context.routing_rationale = rationale
    context.analysis_config = analysis_config
    context.status = "submit"
    
    return context


def determine_analysis_config(routing_decision: RoutingDecision) -> dict:
    """
    Determine Assemblyline submission configuration based on routing.
    
    Args:
        routing_decision: The routing decision
        
    Returns:
        Configuration dict for Assemblyline submission
    """
    configs = {
        RoutingDecision.FAST: {
            "timeout": 60,
            "analysis_type": "quick",
            "deep_scan": False,
            "extra_services": []
        },
        RoutingDecision.DEEP: {
            "timeout": 600,
            "analysis_type": "standard",
            "deep_scan": True,
            "extra_services": ["yara", "pe_recommendations"]
        },
        RoutingDecision.HUMAN_REVIEW: {
            "timeout": 1800,
            "analysis_type": "comprehensive",
            "deep_scan": True,
            "extra_services": ["yara", "pe_recommendations", "code_analysis"]
        }
    }
    
    return configs.get(routing_decision, configs[RoutingDecision.DEEP])
