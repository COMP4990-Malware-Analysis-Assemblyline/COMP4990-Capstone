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
import requests
from datetime import datetime
from ..models import StateContext


# Assemblyline configuration (from environment variables)
ASSEMBLYLINE_API_URL = os.getenv("ASSEMBLYLINE_API_URL", "http://localhost:5000")
ASSEMBLYLINE_API_KEY = os.getenv("ASSEMBLYLINE_API_KEY", "")
ASSEMBLYLINE_USERNAME = os.getenv("ASSEMBLYLINE_USERNAME", "")
ASSEMBLYLINE_PASSWORD = os.getenv("ASSEMBLYLINE_PASSWORD", "")


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
    
    # Prepare auth
    auth = None
    headers = {}
    if ASSEMBLYLINE_API_KEY:
        headers["X-APIKEY"] = ASSEMBLYLINE_API_KEY
    else:
        auth = (ASSEMBLYLINE_USERNAME, ASSEMBLYLINE_PASSWORD)
    
    # Prepare files
    files = {
        "file": (filename, file_content)
    }
    
    # Prepare JSON data with analysis configuration
    data = {
        "json": {
            "timeout": analysis_config.get("timeout", 600),
            "deep_scan": analysis_config.get("deep_scan", False),
            "extra_services": analysis_config.get("extra_services", [])
        }
    }
    
    try:
        response = requests.post(
            submit_url,
            files=files,
            data=data,
            headers=headers,
            auth=auth,
            timeout=30
        )
        response.raise_for_status()
        
        result = response.json()
        submission_id = result.get("submission_id")
        
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
