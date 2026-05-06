"""
MITRE ATT&CK AGENT
===================
Receives the threat_brief from the CTI Agent and orchestrates:
  1. map_to_mitre          → MITRE ATT&CK technique mapping
  2. calculate_severity    → context-calibrated risk scores
  3. recommend_mitigations → CIS/NIST/STIX defense recommendations

Input contract (from build_threat_brief → mitre_input):
  behaviors           : Fusion-enriched behaviors with attack_technique_hint T-codes
  actor_context       : Validated actor, maturity, double_extortion, disruption_risk
  kill_chain_stages   : Ordered list of observed ATT&CK stages
  urgency             : CRITICAL | HIGH | MEDIUM | LOW
  intelligence_gaps   : What NOT to hallucinate
  behavioral_iocs     : Malware/tool/CVE names for STIX keyword search
  resolved_confidence : Overall analysis confidence score
"""

from langsmith import traceable

from mitre.mitre_mapper import map_to_mitre
from mitre.severity_engine import calculate_severity
from mitre.mitigation_engine import recommend_mitigations


def _build_env_context(threat_brief: dict, mitre_input: dict) -> dict:
    """
    Build the enriched environment context injected into severity scoring.

    Merges the fusion LLM's environment_context with actor intelligence from
    mitre_input so the severity engine can calibrate scores on two axes:
      - Infrastructure: target_os, sector, criticality
      - Actor:          maturity, disruption_risk

    Priority: mitre_input actor fields > threat_brief environment fields.
    """
    base = dict(threat_brief.get("environment_context", {}))

    actor_ctx = mitre_input.get("actor_context", {})
    base["actor_maturity"]    = actor_ctx.get("actor_maturity",  base.get("actor_maturity",  "unknown"))
    base["disruption_risk"]   = actor_ctx.get("disruption_risk", "unknown")
    base["urgency"]           = mitre_input.get("urgency",        "unknown")
    base["resolved_confidence"] = mitre_input.get("resolved_confidence", 0.5)

    return base


def _enrich_behaviors_with_hints(behaviors: list[dict]) -> list[dict]:
    """
    Forward attack_technique_hint T-codes from fusion output to map_to_mitre.

    The fusion LLM already assigned T-code hints (e.g. "T1003.001 — LSASS Memory")
    to each behavior. Forwarding these as additional matched_indicators gives the
    STIX keyword scanner strong seeds, dramatically reducing missed mappings.

    The original matched_indicators are preserved — hints are appended only.
    """
    enriched = []
    for b in behaviors:
        hint = b.get("attack_technique_hint", "")
        b_copy = dict(b)

        if hint:
            # Append the T-code + name as an extra indicator for STIX scanning
            existing = list(b_copy.get("matched_indicators", []))
            if hint not in existing:
                existing.append(hint)
            b_copy["matched_indicators"] = existing

        enriched.append(b_copy)
    return enriched

def extract_behaviors_from_cti(cti_result: dict) -> list:
    """
    Robustly extract behavior objects from different possible CTI result schemas.
    """

    if not isinstance(cti_result, dict):
        return []

    candidates = []

    # Common locations
    candidates.append(cti_result.get("behaviors"))

    candidates.append(
        cti_result.get("malicious_behaviors", {}).get("behaviors")
        if isinstance(cti_result.get("malicious_behaviors"), dict)
        else None
    )

    candidates.append(
        cti_result.get("behavior_analysis", {}).get("behaviors")
        if isinstance(cti_result.get("behavior_analysis"), dict)
        else None
    )

    candidates.append(
        cti_result.get("behavior_detection", {}).get("behaviors")
        if isinstance(cti_result.get("behavior_detection"), dict)
        else None
    )

    candidates.append(
        cti_result.get("mitre_input", {}).get("behaviors")
        if isinstance(cti_result.get("mitre_input"), dict)
        else None
    )

    candidates.append(
        cti_result.get("fusion_analysis", {}).get("mitre_relevant_behaviors")
        if isinstance(cti_result.get("fusion_analysis"), dict)
        else None
    )

    candidates.append(
        cti_result.get("llm_fusion_analysis", {}).get("mitre_relevant_behaviors")
        if isinstance(cti_result.get("llm_fusion_analysis"), dict)
        else None
    )

    # Pick first non-empty list
    for candidate in candidates:
        if isinstance(candidate, list) and len(candidate) > 0:
            return candidate

    # Deep fallback search
    def recursive_find_behaviors(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in {"behaviors", "mitre_relevant_behaviors"} and isinstance(value, list) and value:
                    return value
                found = recursive_find_behaviors(value)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = recursive_find_behaviors(item)
                if found:
                    return found
        return []

    return recursive_find_behaviors(cti_result)
    
@traceable(name="MITRE Agent — run_mitre_analysis")
def run_mitre_analysis(cti_result: dict) -> dict:
    """
    Orchestrate the full MITRE ATT&CK pipeline from the CTI analysis result.

    Args:
        cti_result: Output of analyze_message() — must contain "threat_brief"
                    with a populated "mitre_input" sub-dict.

    Returns:
        Full MITRE analysis: techniques, severity, mitigations, executive summary.
    """
    threat_brief = cti_result.get("threat_brief", {})
    mitre_input  = threat_brief.get("mitre_input", {})

    # ------------------------------------------------------------------
    # INPUT VALIDATION & FALLBACK
    # ------------------------------------------------------------------
    behaviors = mitre_input.get("behaviors", [])
    
    # Check if behaviors have technique hints (proper fusion output)
    has_hints = any(b.get("attack_technique_hint") for b in behaviors)
    
    if not behaviors or not has_hints:
        raw_behaviors = cti_result.get("behaviors", [])
        if raw_behaviors:
            # Convert raw behaviors to mitre_input format
            behaviors = [
                {
                    "category": b.get("category", ""),
                    "description": b.get("description", ""),
                    "attack_technique_hint": "",
                    "confidence": b.get("confidence", 0.7),
                    "evidence": [b.get("detection_source", "")],
                    "key_indicators": b.get("indicators", b.get("matched_indicators", []))[:3],
                    "matched_indicators": b.get("indicators", b.get("matched_indicators", [])),
                    "detection_source": b.get("detection_source", "llm_only"),
                    "severity": b.get("severity", "medium"),
                }
                for b in raw_behaviors
            ]
            print(f"[MITRE Agent] Reconstructed {len(behaviors)} behaviors from raw output")
    if not behaviors:
        print("[MITRE Agent] ❌ Aucun behavior trouvé nulle part — pipeline CTI incomplet")
        return {
            "status": "no_behaviors",
            "message": "Le CTI agent n'a produit aucun behavior détectable.",
            "techniques_mapped": {"techniques": [], "total_techniques": 0},
            "severity_analysis": {"global_severity_level": "Unknown", "global_severity_score": 0.0},
            "mitigations": {},
            "executive_summary": {}
        }
    # Build enriched environment context (infra + actor intelligence)
    env_context = _build_env_context(threat_brief, mitre_input)

    # ------------------------------------------------------------------
    # STEP 1: ATT&CK MAPPING
    # Forward fusion T-code hints as STIX keyword seeds.
    # ------------------------------------------------------------------
    enriched_behaviors = _enrich_behaviors_with_hints(behaviors)

    print(f"[MITRE 1/3] Mapping {len(enriched_behaviors)} behavior(s) to ATT&CK techniques...")
    mapping_result = map_to_mitre.invoke({"behaviors": enriched_behaviors})
    techniques     = mapping_result.get("techniques", [])

    if not techniques:
        print("[MITRE 1/3] ⚠️  No techniques mapped.")
        return {
            "status":         "no_techniques",
            "message":        "No ATT&CK techniques identified.",
            "mapping_result": mapping_result,
            "severity":       {},
            "mitigations":    {},
        }

    print(
        f"[MITRE 1/3] ✅ {mapping_result.get('total_techniques', 0)} technique(s) mapped "
        f"across {len(mapping_result.get('tactics_covered', []))} tactic(s)."
    )

    # ------------------------------------------------------------------
    # STEP 2: SEVERITY SCORING
    # Inject enriched env_context (OS + sector + criticality + actor maturity
    # + urgency) so the LLM calibrates scores to the specific threat context.
    # ------------------------------------------------------------------
    print(f"[MITRE 2/3] Calculating severity for {len(techniques)} technique(s)...")

    techniques_with_context = [{**t, "environment_context": env_context} for t in techniques]
    severity_result         = calculate_severity.invoke({"techniques": techniques_with_context})
    scored_techniques       = severity_result.get("scored_techniques", [])

    print(
        f"[MITRE 2/3] ✅ Global severity: "
        f"{severity_result.get('global_severity_level', '?')} "
        f"({severity_result.get('global_severity_score', 0)}/5.0) "
        f"| Chain bonus: {severity_result.get('chain_bonus_applied', 0.0)}"
    )

    # ------------------------------------------------------------------
    # STEP 3: MITIGATIONS
    # env_context injected so recommendations are OS/sector-specific.
    # ------------------------------------------------------------------
    print("[MITRE 3/3] Generating mitigations...")

    scored_with_context = [{**t, "environment_context": env_context} for t in scored_techniques]
    mitigation_result   = recommend_mitigations.invoke({"scored_techniques": scored_with_context})

    print(
        f"[MITRE 3/3] ✅ {len(mitigation_result.get('priority_actions', []))} "
        f"priority action(s) generated."
    )

    # ------------------------------------------------------------------
    # FINAL RESULT
    # ------------------------------------------------------------------
    actor_ctx = mitre_input.get("actor_context", {})

    return {
        "status": "success",

        # ── Intelligence context ────────────────────────────────────────
        "attack_narrative":   threat_brief.get("attack_narrative", ""),
        "kill_chain_stages":  mitre_input.get("kill_chain_stages",  threat_brief.get("kill_chain_stages", [])),
        "actor_profile":      threat_brief.get("actor_profile",     {}),
        "actor_context":      actor_ctx,
        "environment_context": env_context,
        "attack_maturity":    mitre_input.get("attack_maturity",    "unknown"),
        "urgency":            mitre_input.get("urgency",            "unknown"),
        # Surface intelligence gaps so consumers know what is uncertain
        "intelligence_gaps":  mitre_input.get("intelligence_gaps",  []),
        "attribution_gaps":   mitre_input.get("attribution_gaps",   []),

        # ── ATT&CK results ─────────────────────────────────────────────
        "techniques_mapped":  mapping_result,
        "severity_analysis":  severity_result,
        "mitigations":        mitigation_result,

        # ── Executive summary ───────────────────────────────────────────
        "executive_summary": {
            "total_techniques":    mapping_result.get("total_techniques",     0),
            "tactics_covered":     mapping_result.get("tactics_covered",      []),
            "global_severity":     severity_result.get("global_severity_level", "Unknown"),
            "global_score":        severity_result.get("global_severity_score",  0.0),
            "chain_bonus":         severity_result.get("chain_bonus_applied",    0.0),
            "priority_actions":    mitigation_result.get("priority_actions",     []),
            "unscored_techniques": severity_result.get("unscored_techniques",    []),
            # Actor summary for executive reports
            "actor":               actor_ctx.get("validated_actor", threat_brief.get("actor_profile", {}).get("likely_actor", "unknown")),
            "double_extortion":    actor_ctx.get("double_extortion", False),
            "disruption_risk":     actor_ctx.get("disruption_risk",  "unknown"),
            "rag_confirmed":       actor_ctx.get("rag_confirmed",     False),
        },
    }