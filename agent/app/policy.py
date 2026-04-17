"""Centralized SentinelLine route-to-policy mapping."""

from copy import deepcopy
from .models import RoutingDecision


ROUTE_TO_POLICY = {
    RoutingDecision.FAST.value: {
        "policy_id": "STATIC_OFFLINE",
        "display_name": "Static Analysis [OFFLINE]",
        "analysis_type": "quick",
        "timeout": 60,
        "deep_scan": False,
        "extra_services": [],
        "selected_services": [],
    },
    RoutingDecision.DEEP.value: {
        "policy_id": "DYNAMIC_OFFLINE",
        "display_name": "Static + Dynamic Analysis [OFFLINE]",
        "analysis_type": "standard",
        "timeout": 600,
        "deep_scan": True,
        "extra_services": ["yara", "pe_recommendations"],
        "selected_services": ["Antivirus", "Extraction", "Static Analysis"],
    },
    RoutingDecision.HUMAN_REVIEW.value: {
        "policy_id": "ESCALATED",
        "display_name": "Escalate for Analyst Review",
        "analysis_type": "comprehensive",
        "timeout": 1800,
        "deep_scan": True,
        "extra_services": ["yara", "pe_recommendations", "code_analysis"],
        "selected_services": ["Antivirus", "Extraction", "Static Analysis"],
    },
}


def get_policy_for_route(route: RoutingDecision | str) -> dict:
    """Return a copy of policy config for a route, defaulting to DEEP."""
    route_key = route.value if isinstance(route, RoutingDecision) else str(route)
    policy = ROUTE_TO_POLICY.get(route_key, ROUTE_TO_POLICY[RoutingDecision.DEEP.value])
    return deepcopy(policy)
