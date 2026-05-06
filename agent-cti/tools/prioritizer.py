"""
==========================================
 TOOL 5 — Prioritizer & Summary Engine
==========================================
Ranks actions based on risk and generates a 
concise summary for human stakeholders.
"""

def prioritize_actions(aggregated_report: dict) -> list[dict]:
    """
    Ranks techniques by severity score and assigns urgency levels.
    """
    techniques = aggregated_report.get("techniques", [])
    # Sort by severity score descending
    sorted_techs = sorted(techniques, key=lambda x: x.get("severity", 0), reverse=True)
    
    prioritized = []
    for tech in sorted_techs:
        score = tech.get("severity", 0)
        # Assign Urgency
        if score >= 4.0:
            urgency = "IMMEDIATE"
        elif score >= 3.0:
            urgency = "SHORT_TERM"
        else:
            urgency = "LONG_TERM"
            
        prioritized.append({
            "technique_id": tech.get("id"),
            "technique_name": tech.get("name"),
            "priority_score": score,
            "urgency": urgency,
            "recommended_actions": tech.get("mitigation", [])
        })
    return prioritized

def generate_executive_summary(aggregated_report: dict) -> dict:
    """
    Generates a high-level summary string and top 3 actions.
    """
    threats = ", ".join(aggregated_report.get("threats_identified", ["Unknown"]))
    severity = aggregated_report.get("global_severity", "Low")
    count = aggregated_report.get("statistics", {}).get("total_techniques", 0)
    
    summary_text = (
        f"The analysis identified activity associated with {threats}. "
        f"The overall threat landscape is currently rated as {severity} risk, "
        f"with {count} distinct MITRE ATT&CK techniques detected across the environment."
    )
    
    # Extract top 3 actions from the report for the "Quick Fix" section
    all_actions = []
    for tech in aggregated_report.get("techniques", []):
        all_actions.extend(tech.get("mitigation", []))
    
    # Deduplicate and take top 3
    top_3 = list(dict.fromkeys(all_actions))[:3]
    if not top_3:
        top_3 = ["Enable multi-factor authentication", "Review system logs", "Isolate affected hosts"]

    return {
        "executive_summary": summary_text,
        "risk_trend": "Increasing" if severity in ["High", "Critical"] else "Stable",
        "top_3_actions": top_3
    }