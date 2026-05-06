"""
TOOL 3 (MITRE Layer) — Mitigation Engine
==========================================
Generates defense recommendations for each ATT&CK technique.

Two sources are combined per technique:
  Source 1 (STIX) : Official MITRE CourseOfAction objects from the STIX database
  Source 2 (LLM)  : Contextual CIS Controls + NIST 800-53 recommendations

FIX vs original:
  - In _llm_mitigations(), the f-string used t.get('severity_score', '?').
    When severity_score is None (unscored techniques), dict.get() returns None
    (the actually stored value), NOT the '?' fallback — the fallback only triggers
    when the KEY is absent, not when its value is None.
    Fixed using `t.get('severity_score') or '?'` which correctly falls back to
    '?' when the value is None (falsy) as well as when the key is absent.
"""

from langchain_core.tools import tool
from core.llm_helper import llm_analyze
from mitre.mitre_mapper import _get_mitre_data


# =============================================================================
# SOURCE 1 — OFFICIAL STIX MITIGATIONS
# =============================================================================

def _get_stix_mitigations(technique_id: str) -> list[str]:
    """
    Retrieve official MITRE ATT&CK mitigations for a technique from the STIX database.

    Steps:
    1. Resolve the ATT&CK external ID (e.g. "T1003") to a STIX object ID.
    2. Fetch all CourseOfAction objects related to that technique.
    3. Return formatted strings like "M1042: Disable or Remove Feature or Capability".

    Returns an empty list if the technique is not found or an error occurs.
    """
    mitre      = _get_mitre_data()
    mitigations = []

    try:
        # Step 1: Find the STIX internal ID for this ATT&CK technique
        tech_stix_id = None
        for t in mitre.get_techniques():
            for ref in t.get("external_references", []):
                if ref.get("external_id") == technique_id:
                    tech_stix_id = t.get("id")
                    break
            if tech_stix_id:
                break

        if not tech_stix_id:
            print(f"[STIX] No STIX ID found for {technique_id}")
            return []

        # Step 2: Fetch all CourseOfAction objects linked to this technique
        for item in mitre.get_mitigations_mitigating_technique(tech_stix_id):
            coa    = item.get("object")
            name   = coa.get("name", "")
            ext_id = next(
                (
                    ref.get("external_id", "")
                    for ref in coa.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if name:
                # Format: "M1042: Disable or Remove Feature" or just the name
                label = f"{ext_id}: {name}" if ext_id else name
                mitigations.append(label)

        print(f"[STIX] {technique_id} → {len(mitigations)} mitigation(s): {mitigations}")

    except Exception as e:
        print(f"[STIX ERROR] {technique_id} → {e}")

    return mitigations


# =============================================================================
# SOURCE 2 — LLM ENRICHMENT (CIS Controls + NIST 800-53)
# =============================================================================

_LLM_MITIGATION_PROMPT = """You are a Defense Expert specialized in MITRE ATT&CK mitigations.

For each technique provided, produce 2–3 actionable mitigation steps.
Each step MUST reference at least one of: MITRE M-code, CIS Control, or NIST 800-53 control.
Tailor recommendations to the specific technique — do NOT give generic tactic-level advice.

Priority values: "immediate" | "short_term" | "long_term"

Return ONLY valid JSON — no markdown, no explanation:
{
  "mitigations": [
    {
      "technique_id": "T1003.001",
      "recommendations": [
        "M1043: Enable Credential Guard to protect LSASS memory (Hardening)",
        "CIS 6.3: Restrict admin tool access via Just-In-Time PAM (Preventative)",
        "NIST AC-6: Apply least-privilege to accounts with SeDebugPrivilege (Policy)"
      ],
      "priority": "immediate"
    }
  ],
  "global_recommendations": [
    "Deploy EDR with memory protection on all endpoints (CIS 10.1)",
    "Enforce MFA across all privileged accounts (NIST IA-5)"
  ]
}"""


def _llm_mitigations(techniques: list[dict]) -> dict:
    """
    Generate CIS/NIST-referenced mitigation recommendations via LLM.

    A single batched call covers all techniques to minimize LLM round-trips.

    FIX: severity_score can be None for unscored techniques.
    Using `t.get('severity_score') or '?'` correctly handles:
      - Key absent      → returns None → 'or '?'' activates → shows '?'
      - Key present, value is None → 'or '?'' activates    → shows '?'
      - Key present, value is 0.0  → 'or '?'' activates    → shows '?' (0 is falsy)
    Note: a score of 0.0 is theoretically impossible given our 1.0–5.0 range,
    so treating it as missing is safe here.

    Returns the parsed LLM result, or an empty fallback on failure.
    """
    content = "\n".join(
        # FIX: use `or '?'` instead of get(..., '?') to handle None values
        f"- {t['id']} | {t.get('name', '')} | tactic: {t.get('tactic', 'unknown')}"
        f" | severity: {t.get('severity_score') or '?'} ({t.get('severity_level', '?')})"
        for t in techniques
    )

    result = llm_analyze(_LLM_MITIGATION_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return {"mitigations": [], "global_recommendations": []}

    return result


# =============================================================================
# LANGCHAIN TOOL ENTRY POINT
# =============================================================================

@tool
def recommend_mitigations(scored_techniques: list[dict]) -> dict:
    """
    Generate mitigations for each scored ATT&CK technique.

    Combines:
    - Official MITRE STIX mitigations (CourseOfAction objects, per technique)
    - LLM contextual recommendations with CIS Controls + NIST 800-53 references

    Results are sorted by descending severity. Techniques marked Critical or High
    have their top-2 mitigations promoted to a priority_actions list for executive reports.

    Args:
        scored_techniques: Output from calculate_severity (must include
                           id, name, tactic, severity_score, severity_level)

    Returns:
        {technique_mitigations, global_recommendations, priority_actions}
    """
    if not scored_techniques:
        return {"error": "No techniques provided"}

    # --- SOURCE 2: LLM (single batched call for all techniques) ---
    llm_result = _llm_mitigations(scored_techniques)
    llm_map    = {
        m["technique_id"]: m
        for m in llm_result.get("mitigations", [])
        if m.get("technique_id")
    }

    # --- SOURCE 1 + 2: MERGE PER TECHNIQUE ---
    technique_mitigations = []

    for tech in scored_techniques:
        tech_id  = tech.get("id", "")

        # Fetch official STIX mitigations for this technique
        stix_mits = _get_stix_mitigations(tech_id)

        # Fetch LLM recommendations for this technique
        llm_entry = llm_map.get(tech_id, {})
        llm_mits  = llm_entry.get("recommendations", [])
        priority  = llm_entry.get("priority", "short_term")

        # Merge and deduplicate across both sources (case-insensitive)
        seen     = set()
        all_mits = []
        for mit in stix_mits + llm_mits:
            key = mit.lower()
            if key not in seen:
                seen.add(key)
                all_mits.append(mit)

        technique_mitigations.append({
            "id":             tech_id,
            "name":           tech.get("name", ""),
            "tactic":         tech.get("tactic", ""),
            "severity_score": tech.get("severity_score"),
            "severity_level": tech.get("severity_level", ""),
            "mitigations":    all_mits,
            "priority":       priority,
            "sources": {
                "stix_count": len(stix_mits),
                "llm_count":  len(llm_mits),
            },
        })

    # Sort by descending severity (techniques with None scores go last)
    technique_mitigations.sort(
        key=lambda t: t["severity_score"] if t["severity_score"] is not None else -1,
        reverse=True,
    )

    # Build priority actions: top-2 mitigations from Critical/High techniques only
    priority_actions = [
        f"[{tm['id']}] {mit}"
        for tm in technique_mitigations
        if tm["severity_level"] in ("Critical", "High")
        for mit in tm["mitigations"][:2]
    ]

    return {
        "technique_mitigations":  technique_mitigations,
        "global_recommendations": llm_result.get("global_recommendations", []),
        "priority_actions":       priority_actions[:10],  # cap at 10 for executive readability
    }