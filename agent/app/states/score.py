"""
Score State Handler

Processes analysis results and calculates confidence.

Input:
    - JSON analysis report (from Assemblyline)

Output:
    - Final risk score
    - Confidence flag ('Confident' or 'Uncertain')

Description:
    Processes the full analysis report and uses lightweight ML or rule-based policies
    to calculate a final confidence score and uncertainty estimate.

    Note: Assemblyline reports provide a heuristic score from -1000 to +1000.
          This state implements an algorithm to break it down and assess
          confidence in the evaluation.
"""

from ..models import StateContext, ConfidenceLevel


def parse_assemblyline_score(report: dict) -> dict:
    """
    Extract key metrics from Assemblyline report.
    
    Args:
        report: Complete analysis report from Assemblyline
        
    Returns:
        Dict with parsed metrics:
            - al_score: Assemblyline derived score (-1000 to +1000)
            - engine_detections: Number of AV engines with detections
            - total_engines: Total engines used
            - detection_rate: Percentage of engines with detections
            - severity_indicators: List of high-severity findings
    """
    metrics = {
        "al_score": report.get("derived", {}).get("score", 0),
        "engine_detections": 0,
        "total_engines": 0,
        "detection_rate": 0.0,
        "severity_indicators": [],
        "tags": report.get("result", {}).get("tags", [])
    }
    
    # Count engine detections
    scans = report.get("results", {})
    for engine, result in scans.items():
        if result:  # Engine has results
            metrics["total_engines"] += 1
            if result.get("detections"):  # Engine has detections
                metrics["engine_detections"] += 1
    
    if metrics["total_engines"] > 0:
        metrics["detection_rate"] = metrics["engine_detections"] / metrics["total_engines"]
    
    # Extract severity indicators
    for tag in metrics["tags"]:
        if tag in ["malware", "trojan", "ransomware", "backdoor", "rootkit"]:
            metrics["severity_indicators"].append(tag)
    
    return metrics


def calculate_confidence_score(metrics: dict) -> float:
    """
    Calculate confidence in the analysis result (0-1).
    
    Factors considered:
    - Agreement between engines (agreement = confidence)
    - Detection rate consistency
    - Clear positive or negative result
    - Presence of high-confidence signals
    
    Args:
        metrics: Parsed metrics from Assemblyline report
        
    Returns:
        Confidence score (0-1)
    """
    confidence = 0.5  # Start at neutral
    
    # Factor 1: Engine agreement
    detection_rate = metrics["detection_rate"]
    
    if detection_rate > 0.7:  # Strong agreement on malicious
        confidence = 0.90
    elif detection_rate > 0.5:  # Moderate agreement on malicious
        confidence = 0.75
    elif detection_rate > 0.3:  # Weak agreement
        confidence = 0.60
    elif detection_rate > 0:  # Very few detections
        confidence = 0.55
    else:  # No detections (clean)
        confidence = 0.85
    
    # Factor 2: Severity indicators
    severity = len(metrics["severity_indicators"])
    if severity > 0:
        confidence = min(confidence + 0.1 * severity, 1.0)
    
    # Factor 3: Assemblyline score clarity
    al_score = metrics["al_score"]
    
    if al_score > 500:  # Very strong malicious signal
        confidence = min(confidence + 0.05, 1.0)
    elif al_score < -500:  # Very strong benign signal
        confidence = min(confidence + 0.05, 1.0)
    elif -200 < al_score < 200:  # Weak signal
        confidence = max(confidence - 0.1, 0.0)
    
    return confidence


def normalize_risk_score(al_score: int, detection_rate: float, severity_count: int) -> float:
    """
    Normalize Assemblyline score (-1000 to +1000) to 0-100 risk scale.
    
    Args:
        al_score: Assemblyline score
        detection_rate: Fraction of engines with detections
        severity_count: Number of high-severity indicators
        
    Returns:
        Normalized risk score (0-100)
    """
    # Start with normalized AL score
    al_normalized = ((al_score + 1000) / 2000) * 100  # Convert to 0-100
    
    # Boost score if engines agree
    detection_boost = detection_rate * 20  # 0-20 point boost
    
    # Boost score if severity indicators present
    severity_boost = min(severity_count * 10, 20)  # 0-20 point boost
    
    final_score = al_normalized + detection_boost + severity_boost
    
    return min(final_score, 100)


def handle_score(context: StateContext) -> StateContext:
    """
    Process analysis report and calculate final confidence score.

    Args:
        context: StateContext with analysis_report

    Returns:
        Updated StateContext with:
            - final_risk_score: Normalized risk score (0-100)
            - confidence_level: 'Confident' or 'Uncertain'
            - confidence_score: Numeric confidence (0-1)
            - scoring_details: Breakdown of scoring calculation
            - status: 'respond'
    """
    if not context.analysis_report:
        raise ValueError("analysis_report required for scoring")
    
    # Parse report metrics
    metrics = parse_assemblyline_score(context.analysis_report)
    
    # Calculate confidence
    confidence_score = calculate_confidence_score(metrics)
    confidence_level = (
        ConfidenceLevel.CONFIDENT if confidence_score >= 0.65 
        else ConfidenceLevel.UNCERTAIN
    )
    
    # Normalize risk score to 0-100 scale
    final_risk_score = normalize_risk_score(
        metrics["al_score"],
        metrics["detection_rate"],
        len(metrics["severity_indicators"])
    )
    
    # Prepare detailed scoring breakdown
    scoring_details = {
        "assemblyline_score": metrics["al_score"],
        "engine_agreement": f"{metrics['engine_detections']}/{metrics['total_engines']}",
        "detection_rate": f"{metrics['detection_rate']:.1%}",
        "severity_indicators": metrics["severity_indicators"],
        "confidence_justification": (
            f"High engine agreement ({metrics['detection_rate']:.0%})" 
            if confidence_score >= 0.65 
            else "Low or mixed signals from analysis engines"
        )
    }
    
    # Update StateContext
    context.final_risk_score = final_risk_score
    context.confidence_level = confidence_level
    context.confidence_score = confidence_score
    context.scoring_details = scoring_details
    context.status = "respond"
    
    return context
