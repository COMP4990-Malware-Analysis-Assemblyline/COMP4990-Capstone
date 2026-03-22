"""
Wait State Handler

Monitors analysis progress.

Input:
    - submission_id

Output:
    - JSON analysis report (from Assemblyline)

Description:
    Polling/monitoring state that waits for confirmation that analysis is complete.
    Retrieves and stores the comprehensive analysis results from Assemblyline.
"""

import os
import time
import requests
import urllib3
from datetime import datetime
from ..models import StateContext

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Assemblyline configuration
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
        candidates.append(raw.split(":", 1)[1])
    elif ASSEMBLYLINE_USERNAME:
        candidates.append(f"{ASSEMBLYLINE_USERNAME}:{raw}")

    unique_candidates = []
    for value in candidates:
        if value and value not in unique_candidates:
            unique_candidates.append(value)

    return unique_candidates


def _create_authenticated_session() -> requests.Session:
    """Create an authenticated Assemblyline session."""
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


def _get_with_auth(url: str) -> requests.Response:
    """Call GET endpoint with a pre-authenticated session."""
    session = _create_authenticated_session()
    return session.get(url, timeout=30)

# Polling configuration
POLL_INTERVAL = 5  # seconds
MAX_WAIT_TIME = 3600  # seconds (1 hour)


def get_submission_status(submission_id: str) -> dict:
    """
    Check submission status with Assemblyline API.
    
    Args:
        submission_id: Submission ID from previous state
        
    Returns:
        Status dict with 'status', 'report_id', etc.
    """
    if not ASSEMBLYLINE_API_KEY and not (ASSEMBLYLINE_USERNAME and ASSEMBLYLINE_PASSWORD):
        raise ValueError("Assemblyline credentials not configured")
    
    status_url = f"{ASSEMBLYLINE_API_URL}/api/v4/submission/{submission_id}/"
    
    try:
        response = _get_with_auth(status_url)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and isinstance(payload.get("api_response"), dict):
            return payload["api_response"]
        return payload
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to get submission status: {str(e)}")


def get_analysis_report(submission_id: str) -> dict:
    """
    Retrieve complete analysis report from Assemblyline.
    
    Args:
        submission_id: Submission ID
        
    Returns:
        Complete analysis report JSON
    """
    if not ASSEMBLYLINE_API_KEY and not (ASSEMBLYLINE_USERNAME and ASSEMBLYLINE_PASSWORD):
        raise ValueError("Assemblyline credentials not configured")

    # Assemblyline v4 exposes submission-level result endpoints.
    report_urls = [
        f"{ASSEMBLYLINE_API_URL}/api/v4/submission/full/{submission_id}/",
        f"{ASSEMBLYLINE_API_URL}/api/v4/submission/{submission_id}/",
    ]

    last_error = None
    for report_url in report_urls:
        try:
            response = _get_with_auth(report_url)
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict) and isinstance(payload.get("api_response"), dict):
                return payload["api_response"]
            return payload
        except requests.exceptions.RequestException as e:
            last_error = e

    raise ValueError(f"Failed to get analysis report: {str(last_error)}")


def handle_wait(context: StateContext, timeout: int = MAX_WAIT_TIME) -> StateContext:
    """
    Wait for and retrieve analysis results from Assemblyline.

    Args:
        context: StateContext with submission_id
        timeout: Maximum seconds to wait (default 1 hour)

    Returns:
        Updated StateContext with:
            - analysis_report: Complete JSON report from Assemblyline
            - completed_at: Timestamp of completion
            - status: 'score'
    """
    if not context.submission_id:
        raise ValueError("submission_id required for wait state")
    
    elapsed = 0
    while elapsed < timeout:
        try:
            # Check status
            status = get_submission_status(context.submission_id)
            
            state = status.get("state")
            if state == "completed":
                # Analysis complete, retrieve report
                report = get_analysis_report(context.submission_id)
                
                context.analysis_report = report
                context.completed_at = datetime.utcnow()
                context.status = "score"
                return context
            
            elif state == "failed":
                raise ValueError(f"Analysis failed: {status.get('error', 'Unknown error')}")
            
            # Still processing, wait and retry
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            
        except requests.exceptions.RequestException as e:
            # Network error, retry
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
    
    # Timeout reached
    raise TimeoutError(f"Analysis did not complete within {timeout} seconds")
