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
import os
from collections import Counter
from pathlib import Path
import requests
from ..models import StateContext, RiskProfile


DEFINITIVE_RULE_NAME = "Definitive_Malware_Signature"
DEFAULT_YARA_RULE_FILENAME = "triage_rules.yar"
_COMPILED_YARA_RULES = None
_COMPILED_YARA_RULES_PATH = None
VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"


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
    rules = get_compiled_yara_rules()
    if rules is None:
        return {
            "hits": [],
            "hit_count": 0,
            "has_definitive": False
        }

    try:
        matches = rules.match(data=content)
    except Exception:
        return {
            "hits": [],
            "hit_count": 0,
            "has_definitive": False
        }

    match_names = sorted({match.rule for match in matches})
    return {
        "hits": match_names,
        "hit_count": len(match_names),
        "has_definitive": DEFINITIVE_RULE_NAME in match_names
    }


def resolve_yara_rules_path() -> Path | None:
    """Resolve YARA rule file path for both local and container runs."""
    env_path = os.getenv("TRIAGE_YARA_RULES_PATH")
    states_file = Path(__file__).resolve()
    agent_root = states_file.parents[2]

    candidates = []
    if env_path:
        candidates.append(Path(env_path).expanduser())

    candidates.extend([
        agent_root / DEFAULT_YARA_RULE_FILENAME,
        agent_root / "rules" / DEFAULT_YARA_RULE_FILENAME,
        Path("/app") / DEFAULT_YARA_RULE_FILENAME,
        Path("/app") / "rules" / DEFAULT_YARA_RULE_FILENAME,
    ])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate

    return None


def get_compiled_yara_rules():
    """Compile and cache YARA rules for reuse across triage requests."""
    global _COMPILED_YARA_RULES
    global _COMPILED_YARA_RULES_PATH

    rules_path = resolve_yara_rules_path()
    if rules_path is None:
        return None

    if _COMPILED_YARA_RULES is not None and _COMPILED_YARA_RULES_PATH == str(rules_path):
        return _COMPILED_YARA_RULES

    try:
        import yara
        compiled = yara.compile(filepath=str(rules_path))
    except Exception:
        return None

    _COMPILED_YARA_RULES = compiled
    _COMPILED_YARA_RULES_PATH = str(rules_path)
    return _COMPILED_YARA_RULES


def query_external_apis(file_hash: str) -> dict:
    """
    Query external metadata APIs (VirusTotal, etc.).
    
    Args:
        file_hash: SHA256 hash of file
        
    Returns:
        Dictionary with metadata from external APIs
    """
    metadata = {
        "virustotal_detections": 0,
        "first_seen": None,
        "known_good": False
    }

    if not file_hash:
        return metadata

    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not virustotal_api_key:
        return metadata

    base_url = os.getenv("VIRUSTOTAL_API_URL", VIRUSTOTAL_API_BASE).rstrip("/")
    timeout = float(os.getenv("VIRUSTOTAL_TIMEOUT_SECONDS", "4"))

    try:
        response = requests.get(
            f"{base_url}/files/{file_hash}",
            headers={"x-apikey": virustotal_api_key},
            timeout=timeout,
        )

        if response.status_code == 404:
            return metadata

        response.raise_for_status()
        payload = response.json() if response.content else {}
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        detections = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        metadata["virustotal_detections"] = detections
        metadata["first_seen"] = attributes.get("first_submission_date")
        metadata["known_good"] = detections == 0
    except Exception:
        return metadata

    return metadata


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
