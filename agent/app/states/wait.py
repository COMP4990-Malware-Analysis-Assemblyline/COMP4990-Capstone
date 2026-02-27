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
from datetime import datetime
from ..models import StateContext


# Assemblyline configuration
ASSEMBLYLINE_API_URL = os.getenv("ASSEMBLYLINE_API_URL", "http://localhost:5000")
ASSEMBLYLINE_API_KEY = os.getenv("ASSEMBLYLINE_API_KEY", "")
ASSEMBLYLINE_USERNAME = os.getenv("ASSEMBLYLINE_USERNAME", "")
ASSEMBLYLINE_PASSWORD = os.getenv("ASSEMBLYLINE_PASSWORD", "")

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
    
    auth = None
    headers = {}
    if ASSEMBLYLINE_API_KEY:
        headers["X-APIKEY"] = ASSEMBLYLINE_API_KEY
    else:
        auth = (ASSEMBLYLINE_USERNAME, ASSEMBLYLINE_PASSWORD)
    
    try:
        response = requests.get(
            status_url,
            headers=headers,
            auth=auth,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
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
    # Get status to find report_id
    status = get_submission_status(submission_id)
    
    if not status.get("report_id"):
        raise ValueError("No report_id in submission status")
    
    report_id = status["report_id"]
    
    if not ASSEMBLYLINE_API_KEY and not (ASSEMBLYLINE_USERNAME and ASSEMBLYLINE_PASSWORD):
        raise ValueError("Assemblyline credentials not configured")
    
    report_url = f"{ASSEMBLYLINE_API_URL}/api/v4/report/{report_id}/"
    
    auth = None
    headers = {}
    if ASSEMBLYLINE_API_KEY:
        headers["X-APIKEY"] = ASSEMBLYLINE_API_KEY
    else:
        auth = (ASSEMBLYLINE_USERNAME, ASSEMBLYLINE_PASSWORD)
    
    try:
        response = requests.get(
            report_url,
            headers=headers,
            auth=auth,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Failed to get analysis report: {str(e)}")


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
            
            if status.get("state") == "completed":
                # Analysis complete, retrieve report
                report = get_analysis_report(context.submission_id)
                
                context.analysis_report = report
                context.completed_at = datetime.utcnow()
                context.status = "score"
                return context
            
            elif status.get("state") == "failed":
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
