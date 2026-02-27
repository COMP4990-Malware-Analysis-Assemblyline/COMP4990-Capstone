"""
Received State Handler

Entry-point state for the malware analysis pipeline.

Input:
    - Raw file or file metadata

Output:
    - Initialized StateContext object with:
      - Unique file_id
      - Status set to 'triage'

Description:
    Ingests the file metadata and initializes a unique session for analysis.
    Creates the initial StateContext that carries context through the FSM.
"""

import hashlib
import uuid
from datetime import datetime
from ..models import StateContext


def handle_received(filename: str, file_content: bytes) -> StateContext:
    """
    Process incoming file and initialize analysis context.

    Args:
        filename: Name of the file
        file_content: Raw file bytes

    Returns:
        StateContext: Initialized context object with:
            - file_id: Generated unique identifier
            - status: 'triage'
            - file_hash: SHA256 of file content
            - created_at: Timestamp
    """
    # Generate unique file_id
    file_id = str(uuid.uuid4())
    
    # Calculate file hash
    file_hash = hashlib.sha256(file_content).hexdigest()
    
    # Initialize StateContext
    context = StateContext(
        file_id=file_id,
        filename=filename,
        file_content=file_content,
        file_hash=file_hash,
        status="triage",
        created_at=datetime.utcnow()
    )
    
    return context
