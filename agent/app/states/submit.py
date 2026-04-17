"""
Submit State Handler

Executes file analysis via REST API.

Input:
    - Routing decision
    - File ID

Output:
    - submission_id: Unique identifier for the analysis job

Description:
    Submits the file to Assemblyline API for analysis based on the routing decision.
    Initiates the actual analysis process.
"""

import os
import json
import requests
import urllib3
from datetime import datetime
from ..models import StateContext

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Assemblyline configuration (from environment variables)
ASSEMBLYLINE_API_URL = os.getenv("ASSEMBLYLINE_API_URL", "http://localhost:5000")
ASSEMBLYLINE_API_KEY = os.getenv("ASSEMBLYLINE_API_KEY", "")
ASSEMBLYLINE_USERNAME = os.getenv("ASSEMBLYLINE_USERNAME", "")
ASSEMBLYLINE_PASSWORD = os.getenv("ASSEMBLYLINE_PASSWORD", "")


def _api_key_candidates() -> list[str]:
    """Return likely API key header formats for Assemblyline."""
    if not ASSEMBLYLINE_API_KEY:
        return []

    raw = ASSEMBLYLINE_API_KEY.strip()
    candidates = [raw]

    if ":" in raw:
        # Some UIs copy API key as "name:key" while APIs expect only "key".
        candidates.append(raw.split(":", 1)[1])
    elif ASSEMBLYLINE_USERNAME:
        # Some deployments expect "username:key" in X-APIKEY.
        candidates.append(f"{ASSEMBLYLINE_USERNAME}:{raw}")

    unique_candidates = []
    for value in candidates:
        if value and value not in unique_candidates:
            unique_candidates.append(value)

    return unique_candidates


def _create_authenticated_session() -> requests.Session:
    """Create an authenticated Assemblyline session."""
    # Prefer session-based auth because some deployments require a login session.
    if ASSEMBLYLINE_USERNAME and ASSEMBLYLINE_PASSWORD:
        session = requests.Session()
        session.verify = False
        login_url = f"{ASSEMBLYLINE_API_URL}/api/v4/auth/login/"
        login_response = session.post(
            login_url,
            json={"user": ASSEMBLYLINE_USERNAME, "password": ASSEMBLYLINE_PASSWORD},
            timeout=30
        )
        if login_response.status_code == 200:
            xsrf = (
                session.cookies.get("XSRF-TOKEN")
                or session.cookies.get("csrftoken")
                or session.cookies.get("_xsrf")
            )
            if xsrf:
                session.headers.update({
                    "X-XSRF-TOKEN": xsrf,
                    "X-CSRFToken": xsrf,
                })
            return session

    # Fallback to API key header formats.
    if ASSEMBLYLINE_API_KEY:
        probe_url = f"{ASSEMBLYLINE_API_URL}/api/v4/submit/"
        for key_candidate in _api_key_candidates():
            session = requests.Session()
            session.verify = False
            session.headers.update({"X-APIKEY": key_candidate})
            probe_response = session.get(probe_url, timeout=30)
            if probe_response.status_code != 401:
                return session

    raise ValueError("Assemblyline authentication failed")


def submit_to_assemblyline(
    filename: str,
    file_content: bytes,
    analysis_config: dict
) -> str:
    """
    Submit file to Assemblyline API.
    
    Args:
        filename: Name of file
        file_content: Raw file bytes
        analysis_config: Configuration dict from route state
        
    Returns:
        submission_id from Assemblyline
        
    Raises:
        ValueError: If submission fails
    """
    
    if not ASSEMBLYLINE_API_KEY and not (ASSEMBLYLINE_USERNAME and ASSEMBLYLINE_PASSWORD):
        raise ValueError(
            "Assemblyline credentials not configured. "
            "Set ASSEMBLYLINE_API_KEY or ASSEMBLYLINE_USERNAME/PASSWORD environment variables"
        )
    
    # Prepare submission endpoint
    submit_url = f"{ASSEMBLYLINE_API_URL}/api/v4/submit/"
    
    # Build authenticated session
    session = _create_authenticated_session()
    
    # Prepare files
    files = {
        "bin": (filename, file_content)
    }
    
    # Prepare JSON data with explicit policy controls.
    policy_payload = {
        "timeout": analysis_config.get("timeout", 600),
        "deep_scan": analysis_config.get("deep_scan", False),
        "extra_services": analysis_config.get("extra_services", []),
        "analysis_type": analysis_config.get("analysis_type", "standard"),
        "services": {
            "selected": analysis_config.get("selected_services", [])
        },
        "metadata": {
            "sentinelline_route": analysis_config.get("route"),
            "sentinelline_policy_id": analysis_config.get("policy_id"),
            "sentinelline_policy_name": analysis_config.get("display_name"),
        },
    }

    excluded_services = analysis_config.get("excluded_services", [])
    if excluded_services:
        policy_payload["services"]["excluded"] = excluded_services

    data = {
        "json": json.dumps(policy_payload)
    }
    
    try:
        response = session.post(
            submit_url,
            files=files,
            data=data,
            timeout=30
        )

        response.raise_for_status()

        result = response.json()
        api_response = result.get("api_response", {}) if isinstance(result, dict) else {}
        submission_id = (
            result.get("submission_id")
            or result.get("sid")
            or api_response.get("submission_id")
            or api_response.get("sid")
        )

        if not submission_id:
            raise ValueError("No submission_id in response")

        return submission_id

    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to submit to Assemblyline: {str(e)}")


def handle_submit(context: StateContext) -> StateContext:
    """
    Submit file to Assemblyline for analysis.

    Args:
        context: StateContext with routing_decision and file_id

    Returns:
        Updated StateContext with:
            - submission_id: ID returned by Assemblyline API
            - submitted_at: Timestamp of submission
            - status: 'wait'
    """
    if not context.file_content:
        raise ValueError("File content required for submission")
    if not context.analysis_config:
        raise ValueError("Analysis config required for submission")
    
    # Submit file to Assemblyline
    submission_id = submit_to_assemblyline(
        context.filename,
        context.file_content,
        context.analysis_config
    )
    
    # Update StateContext
    context.submission_id = submission_id
    context.submitted_at = datetime.utcnow()
    context.status = "wait"
    
    return context
