"""
Triage State Handler

Gathers initial file characteristics and metadata.

Input:
    - StateContext object

Output:
    - Updated RiskProfile containing:
      - Entropy value
      - File type
      - File size
      - YARA rule hits (if applicable)
      - Initial risk indicators

Description:
    Populates RiskProfile using lightweight API calls to avoid resource-heavy analysis.
    Gathers preliminary information to make intelligent routing decisions in the next step.
"""

import math
from collections import Counter
from ..models import StateContext, RiskProfile


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of file data.
    
    Args:
        data: File bytes
        
    Returns:
        Entropy value (0-8 for bytes)
    """
    if not data:
        return 0.0
    
    byte_counts = Counter(data)
    entropy = 0.0
    data_len = len(data)
    
    for count in byte_counts.values():
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    return entropy


def detect_file_type(filename: str, content: bytes) -> str:
    """
    Detect file type from extension and magic bytes.
    
    Args:
        filename: File name
        content: File bytes
        
    Returns:
        File type string
    """
    # Try to use python-magic if available, otherwise use basic extension detection
    try:
        import magic
        mime = magic.from_buffer(content, mime=True)
        return mime
    except (ImportError, Exception):
        # Fallback to extension-based detection
        ext = filename.split('.')[-1].lower() if '.' in filename else "unknown"
        mime_map = {
            'exe': 'application/x-msdownload',
            'dll': 'application/x-msdownload',
            'bin': 'application/octet-stream',
            'zip': 'application/zip',
            'pdf': 'application/pdf',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        }
        return mime_map.get(ext, f"application/{ext}")


def check_yara_rules(content: bytes, filename: str) -> dict:
    """
    Check against YARA rules (architecture ready for integration).
    
    Args:
        content: File bytes
        filename: File name
        
    Returns:
        Dictionary with:
            - hits: List of matching YARA rule names
            - hit_count: Total number of rules triggered
            - has_definitive: Boolean if definitive malware signature found
    """
    # TODO: Integrate YARA rule scanning when rules are available
    # from ..rules import CORE_RULES, SUPPLEMENTARY_RULES
    # Then load and compile rules here
    
    return {
        "hits": [],
        "hit_count": 0,
        "has_definitive": False
    }


def query_external_apis(file_hash: str) -> dict:
    """
    Query external metadata APIs (VirusTotal, etc.).
    
    Args:
        file_hash: SHA256 hash of file
        
    Returns:
        Dictionary with metadata from external APIs
    """
    # TODO: Integrate VirusTotal API, URLhaus, etc.
    # Requires API keys in environment variables
    # For now, return empty metadata
    return {
        "virustotal_detections": 0,
        "first_seen": None,
        "known_good": False
    }


def handle_triage(context: StateContext) -> StateContext:
    """
    Perform initial triage analysis on file.

    Args:
        context: Current StateContext object with file_id and metadata

    Returns:
        Updated StateContext with populated RiskProfile
    """
    if not context.file_content:
        raise ValueError("File content required for triage")
    
    # Calculate entropy
    entropy = calculate_entropy(context.file_content)
    
    # Detect file type
    file_type = detect_file_type(context.filename, context.file_content)
    
    # Check YARA rules
    yara_results = check_yara_rules(context.file_content, context.filename)
    yara_hits = yara_results["hits"]
    yara_hit_count = yara_results["hit_count"]
    has_definitive = yara_results["has_definitive"]
    
    # Query external APIs
    metadata = query_external_apis(context.file_hash)
    
    # Calculate initial risk score (0-100
    initial_risk_score = 0.0
    
    # YARA-based risk scoring
    if has_definitive:
        # Definitive malware signature found
        initial_risk_score = 80.0
    elif yara_hit_count >= 4:
        # 4+ rules triggered = highly suspicious
        initial_risk_score = 70.0
    elif yara_hit_count >= 1:
        # 1-3 rules triggered = moderately suspicious
        initial_risk_score = 40.0
    
    # Entropy-based scoring (supplementary)
    if entropy > 7.5:  # High compression/encryption
        initial_risk_score += 20
    
    # File type scoring
    if "octet-stream" in file_type or "unknown" in file_type:
        initial_risk_score += 10
    
    # External metadata scoring
    if metadata.get("virustotal_detections", 0) > 0:
        initial_risk_score += 10
    
    # Cap at 100
    initial_risk_score = min(initial_risk_score, 100)
    
    # Create RiskProfile
    risk_profile = RiskProfile(
        entropy=entropy,
        file_type=file_type,
        file_size=len(context.file_content),
        yara_hits=yara_hits,
        initial_risk_score=initial_risk_score,
        metadata_summary={
            **metadata,
            "yara_hit_count": yara_hit_count,
            "has_definitive_signature": has_definitive
        }
    )
    
    # Update StateContext
    context.risk_profile = risk_profile
    context.status = "route"
    
    return context
