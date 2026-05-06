"""
==========================================
 AGGREGATOR — Final Report Orchestrator
==========================================
Report sections:
  1. Summary & Context        (narrative + classification)
  2. Key Takeaways            (actor, vector, kill chain, environment)
  3. Severity                 (score, level, chain bonus)
  4. TTPs                     (techniques linked to behaviors)
  5. IOCs & Artifacts         (clean, filtered)
  6. Mitigation & Remediation (priority actions + global recs)
"""

from datetime import datetime, timezone
from collections import Counter
from langsmith import traceable
import re


# ---------------------------------------------------------------------------
#  CONSTANTS
# ---------------------------------------------------------------------------

_LLM_CATEGORY_MAP = {
    "process manipulation":   "process_creation",
    "persistence mechanisms": "registry_modification",
    "network activity":       "network_communication",
    "file system operations": "file_system_activity",
    "defense evasion":        "defense_evasion",
    "discovery":              "discovery",
    "lateral movement":       "lateral_movement",
    "impact":                 "file_system_activity",
    "credential theft":       "credential_access",
    "credential access":      "credential_access",
}

LLM_CATEGORY_MAP = _LLM_CATEGORY_MAP  # kept for external imports

_TERMINAL_STAGES = {"impact", "exfiltration", "command_and_control"}
_SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

_OBJECTIVE_TO_VECTOR = {
    "ransomware_extortion":        "Ransomware delivery (see TTPs for entry vector)",
    "data_exfiltration_espionage": "Targeted intrusion / spear-phishing (see TTPs)",
    "financial_theft":             "Financial fraud / credential theft (see TTPs)",
}
_OBJECTIVE_TO_IMPACT = {
    "ransomware_extortion":        "Ransomware / Data Encryption",
    "data_exfiltration_espionage": "Data Exfiltration / Espionage",
    "financial_theft":             "Financial Theft / Fraud",
}

_KILL_CHAIN_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]

def _kc_sort_key(tactic: str) -> int:
    norm = tactic.lower().replace(" ", "_").replace("-", "_").replace("&", "and")
    return _KILL_CHAIN_ORDER.index(norm) if norm in _KILL_CHAIN_ORDER else 99


def _format_priority_actions(raw_actions: list) -> list:
    """
    Convert flat priority action strings into {text, refs} dicts.
    Extracts standard control references so PDF is pure display.
    """
    result = []
    for action in raw_actions:
        refs = re.findall(r"(?:M\d{4}|CIS\s[\d.]+|NIST\s[\w-]+)", str(action))
        result.append({
            "text": action,
            "refs": ", ".join(refs) if refs else "Best Practice",
        })
    return result


def _format_ioc_tables(iocs: dict) -> list:
    """
    Convert the nested IOC dict into a flat list of {title, rows} dicts
    ready for direct table rendering — no logic needed in pdf_report.
    """
    tables = []

    network_rows = [
        (k.upper(), v)
        for k, vals in iocs.get("network", {}).items()
        for v in vals
        if isinstance(v, str) and v.strip()
    ]
    if network_rows:
        tables.append({"title": "Network Indicators", "rows": network_rows})

    file_rows = [
        (k.upper(), v)
        for k, vals in iocs.get("files", {}).items()
        for v in vals
        if isinstance(v, str) and v.strip()
    ]
    if file_rows:
        tables.append({"title": "Host Indicators (Hashes)", "rows": file_rows})

    crypto_rows = [
        (k.upper(), v)
        for k, vals in iocs.get("crypto", {}).items()
        for v in vals
        if isinstance(v, str) and v.strip()
    ]
    if crypto_rows:
        tables.append({"title": "Cryptocurrency Wallets", "rows": crypto_rows})

    return tables
# ---------------------------------------------------------------------------
#  UTILITIES
# ---------------------------------------------------------------------------

def _normalize_category(category: str) -> str:
    lower = category.lower().strip()
    return _LLM_CATEGORY_MAP.get(lower, lower.replace(" ", "_"))


def _deduplicate_ordered(items: list) -> list:
    seen, out = set(), []
    for item in items:
        key = str(item).lower().strip()
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _classify_score(score: float) -> str:
    if score >= 4.0: return "Critical"
    if score >= 3.0: return "High"
    if score >= 2.0: return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
#  IOC CLEANING
# ---------------------------------------------------------------------------

def _clean_iocs(entities: dict) -> dict:
    def _clean(lst):
        return _deduplicate_ordered([x for x in lst if isinstance(x, str) and x.strip()])

    wallets = entities.get("crypto_wallets", {})
    hashes  = entities.get("hashes", {})
    return {
        "network": {k: _clean(entities.get(k, [])) for k in ("ips", "urls", "domains")},
        "files":   {k: _clean(hashes.get(k, [])) for k in ("md5", "sha1", "sha256")},
        "crypto":  {k: _clean(wallets.get(k, [])) for k in ("btc", "eth", "xmr")},
        "threat_intelligence": {
            k: _clean(entities.get(k, []))
            for k in ("malware_names", "ransomware_groups", "apt_groups",
                      "tools_abused", "cves", "campaign_names")
        },
    }


# ---------------------------------------------------------------------------
#  SECTION 2 — KEY TAKEAWAYS
# ---------------------------------------------------------------------------

def _build_key_takeaways(cti_result: dict, global_severity: str) -> dict:
    threat_brief  = cti_result.get("threat_brief", {})
    patterns      = cti_result.get("patterns", {})
    actor_profile = threat_brief.get("actor_profile", {})
    env_context   = threat_brief.get("environment_context", {})
    kill_chain    = threat_brief.get("kill_chain_stages", [])
    objective     = (threat_brief.get("fusion", {})
                                 .get("hypotheses", {})
                                 .get("h1_objective", {})
                                 .get("assessment", "unknown"))

    if "initial_access" in kill_chain:
        vector = "Initial Access detected (see TTPs)"
    elif patterns.get("threat_classification", "").upper() in ("PHISHING", "SPEAR_PHISHING"):
        vector = "Phishing / Social Engineering"
    else:
        vector = _OBJECTIVE_TO_VECTOR.get(objective, "Unknown (see TTPs)")

    impact = next(
        (s.replace("_", " ").title() for s in reversed(kill_chain) if s in _TERMINAL_STAGES),
        _OBJECTIVE_TO_IMPACT.get(objective)
        or ("Critical impact — see severity" if global_severity == "Critical" else "Unknown"),
    )

    return {
        "threat_actor": {
            "name":       actor_profile.get("likely_actor", "Unknown"),
            "confidence": actor_profile.get("confidence", 0.0),
        },
        "initial_access_vector": vector,
        "impact":                impact,
        "target_environment": {
            "os":          env_context.get("target_os", "unknown"),
            "sector":      env_context.get("target_sector", []),
            "criticality": env_context.get("infrastructure_criticality", "unknown"),
        },
        "kill_chain_stages":    kill_chain,
        "attack_maturity":      threat_brief.get("mitre_input", {}).get("attack_maturity", "unknown"),
        "predicted_next_steps": patterns.get("predicted_next_steps", []),
    }


# ---------------------------------------------------------------------------
#  SECTION 4 — TTP LINKER
# ---------------------------------------------------------------------------

def _build_behavior_index(behaviors: list[dict]) -> dict[str, dict]:
    return {_normalize_category(b.get("category", "")): b for b in behaviors}


def _find_linked_behavior(tech, behavior_by_cat, brief_by_cat, behaviors):
    src = _normalize_category(tech.get("source_behavior", ""))
    if src and src in behavior_by_cat:
        return behavior_by_cat[src], "source_behavior"

    tactic_norm = _normalize_category(tech.get("tactic", ""))
    if tactic_norm in behavior_by_cat:
        return behavior_by_cat[tactic_norm], "tactic_category"

    tech_text = (tech.get("name", "") + " " + tech.get("tactic", "")).lower()
    for cat_key, brief_b in brief_by_cat.items():
        if cat_key in tech_text:
            return brief_b, "threat_brief_keyword"

    if behaviors:
        sev = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        pool = [b for b in behaviors if b.get("detection_source") in ("static_regex", "static+llm")] or behaviors
        return max(pool, key=lambda b: sev.get(b.get("severity", "low"), 0)), "fallback"

    return None, "none"


def _link_techniques_to_behaviors(scored_techniques, behaviors, mitre_relevant_behaviors):
    behavior_by_cat = _build_behavior_index(behaviors)
    brief_by_cat    = _build_behavior_index(mitre_relevant_behaviors)

    ttps = []
    for tech in scored_techniques:
        linked, link_method = _find_linked_behavior(tech, behavior_by_cat, brief_by_cat, behaviors)
        ttps.append({
            "technique_id":   tech.get("id", ""),
            "technique_name": tech.get("name", ""),
            "tactic":         tech.get("tactic", ""),
            "mapping_source": tech.get("mapping_source", ""),
            "severity_score": tech.get("severity_score"),
            "severity_level": tech.get("severity_level", "Unknown"),
            "llm_reasoning":  tech.get("llm_reasoning", ""),
            "observed_behavior": {
                "category":    linked.get("category", "")         if linked else "",
                "description": linked.get("description", "")      if linked else "",
                "source":      linked.get("detection_source", "") if linked else "",
                "confidence":  linked.get("confidence", 0)        if linked else 0,
                "indicators":  linked.get("matched_indicators", [])[:3] if linked else [],
            },
            "link_method": link_method,
        })

    ttps.sort(
        key=lambda t: (_SEV_ORDER.get(t["severity_level"], 0), t["severity_score"] or 0),
        reverse=True,
    )
    return ttps


# ---------------------------------------------------------------------------
#  MAIN ORCHESTRATOR
# ---------------------------------------------------------------------------

@traceable(name="Aggregator — build_report_metadata")
def build_report_metadata(
    original_message: str,
    cti_result: dict,
    mitre_result: dict,
) -> dict:
    """
    3 params instead of 7. All sub-fields extracted internally.
    """
    if not cti_result or not mitre_result:
        return {"error": "CTI result or MITRE result missing"}

    # ── Single unpack point ──────────────────────────────────────────────────
    threat_brief      = cti_result.get("threat_brief", {})
    entities          = cti_result.get("entities", {})
    behaviors         = cti_result.get("behaviors", [])
    patterns          = cti_result.get("patterns", {})
    severity_result   = mitre_result.get("severity_analysis", {})
    mapping_result    = mitre_result.get("techniques_mapped", {})
    mitigation_result = mitre_result.get("mitigations", {})

    scored_techniques        = severity_result.get("scored_techniques", [])
    mitre_relevant_behaviors = threat_brief.get("mitre_input", {}).get("behaviors", [])
    env_context              = threat_brief.get("environment_context", {})
    global_severity          = severity_result.get("global_severity_level", "Unknown")

    # ── Sections ─────────────────────────────────────────────────────────────
    s1 = {
        "raw_message":           original_message,
        "attack_narrative":      threat_brief.get("attack_narrative", ""),
        "kill_chain_narrative":  threat_brief.get("kill_chain_narrative", ""),
        "threat_classification": patterns.get("threat_classification", ""),
        "is_malicious":          patterns.get("is_malicious", False),
        "semantic_summary":      patterns.get("semantic_summary", ""),
        "rag_context_used":      cti_result.get("rag_context", {}).get("num_results", 0),
    }

    s2 = _build_key_takeaways(cti_result, global_severity)

    s3 = {
        "global_score":        severity_result.get("global_severity_score", 0.0),
        "global_level":        global_severity,
        "chain_bonus_applied": severity_result.get("chain_bonus_applied", 0.0),
        "overall_reasoning":   severity_result.get("overall_reasoning", ""),
        "distribution":        dict(Counter(
            t.get("severity_level", "Unknown") for t in scored_techniques
        )),
        "environment_context": env_context,
    }

    s4 = _link_techniques_to_behaviors(scored_techniques, behaviors, mitre_relevant_behaviors)
    s4.sort(key=lambda t: _kc_sort_key(t.get("tactic", "")))
    # Add procedure_text to each TTP so pdf_report doesn't assemble strings
    for ttp in s4:
        obs = ttp.get("observed_behavior", {})
        ttp["procedure_text"] = (
            f"{obs.get('description', '')} {ttp.get('llm_reasoning', '')}".strip()
            or "Behavior observed."
        )
    s5 = _clean_iocs(entities)
    s5["_stats"] = {
        "total_network_iocs": sum(len(s5["network"][k]) for k in ("ips", "urls", "domains")),
        "total_file_iocs":    sum(len(s5["files"][k])   for k in ("md5", "sha1", "sha256")),
        "total_cves":         len(s5["threat_intelligence"]["cves"]),
        "noise_filtered_for_mitre": threat_brief.get("noise_filtered", []),
    }
    s5["ioc_tables"] = _format_ioc_tables(s5)
    s6 = {
        "environment_grounding": {
            "target_os":     env_context.get("target_os", "unknown"),
            "target_sector": env_context.get("target_sector", []),
            "criticality":   env_context.get("infrastructure_criticality", "unknown"),
        },
        "priority_actions": _deduplicate_ordered(
            mitigation_result.get("priority_actions", [])
        )[:10],
        "global_recommendations": _deduplicate_ordered(
            mitigation_result.get("global_recommendations", [])
        ),
        "by_technique": [
            {
                "technique_id":   tm.get("id", ""),
                "technique_name": tm.get("name", ""),
                "severity_level": tm.get("severity_level", ""),
                "priority":       tm.get("priority", "short_term"),
                "mitigations":    tm.get("mitigations", []),
            }
            for tm in mitigation_result.get("technique_mitigations", [])
        ],
    }
    # Pre-format priority actions with extracted control refs
    s6["priority_actions"] = _format_priority_actions(s6.get("priority_actions", []))

    return {
        "report_metadata": {
            "type":            "threat_intelligence_report",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "pipeline_status": mitre_result.get("status", "unknown"),
        },
        "raw_input":                 original_message,        # pdf_report.py compat
        "section_1_summary_context": s1,
        "section_2_key_takeaways":   s2,
        "section_3_severity":        s3,
        "section_4_ttps":            s4,
        "section_5_iocs_artifacts":  s5,
        "section_6_mitigations":     s6,
        "executive_summary": {
            "threat_classification":  patterns.get("threat_classification", ""),
            "global_severity":        global_severity,
            "global_score":           severity_result.get("global_severity_score", 0.0),
            "total_techniques":       mapping_result.get("total_techniques", 0),
            "tactics_covered":        mapping_result.get("tactics_covered", []),
            "total_iocs":             entities.get("ioc_count", 0),
            "threat_actor":           threat_brief.get("actor_profile", {}).get("likely_actor", "Unknown"),
            "priority_actions_count": len(mitigation_result.get("priority_actions", [])),
            "kill_chain_stages":      threat_brief.get("kill_chain_stages", []),
        },
    }


# ---------------------------------------------------------------------------
#  MULTI-REPORT AGGREGATION
# ---------------------------------------------------------------------------

@traceable(name="Aggregator — aggregate_reports")
def aggregate_reports(report_metadatas: list[dict]) -> dict:
    """Merges N reports into one consolidated campaign report."""
    if not report_metadatas:
        return {"error": "No reports to aggregate"}

    all_techniques, all_scores, all_actors, all_actions, all_malware = [], [], [], [], []
    all_iocs: dict[str, list] = {"ips": [], "urls": [], "domains": [], "cves": []}

    for meta in report_metadatas:
        all_techniques.extend(meta.get("section_4_ttps", []))

        if score := meta.get("section_3_severity", {}).get("global_score", 0):
            all_scores.append(score)

        actor = meta.get("section_2_key_takeaways", {}).get("threat_actor", {}).get("name", "")
        if actor and actor.lower() not in ("unknown", ""):
            all_actors.append(actor)

        network = meta.get("section_5_iocs_artifacts", {}).get("network", {})
        for key in ("ips", "urls", "domains"):
            all_iocs[key].extend(network.get(key, []))
        all_iocs["cves"].extend(
            meta.get("section_5_iocs_artifacts", {})
                .get("threat_intelligence", {})
                .get("cves", [])
        )

        all_actions.extend(meta.get("section_6_mitigations", {}).get("priority_actions", []))

        ti = meta.get("section_5_iocs_artifacts", {}).get("threat_intelligence", {})
        all_malware.extend(ti.get("malware_names", []) + ti.get("ransomware_groups", []))

    for key in all_iocs:
        all_iocs[key] = _deduplicate_ordered(all_iocs[key])

    global_score = max(all_scores) if all_scores else 0.0
    return {
        "report_metadata": {
            "type":               "consolidated_threat_report",
            "generated_at":       datetime.now(timezone.utc).isoformat(),
            "reports_aggregated": len(report_metadatas),
        },
        "global_severity":       _classify_score(global_score),
        "global_severity_score": global_score,
        "threats_identified":    _deduplicate_ordered(all_malware),
        "threat_actors":         _deduplicate_ordered(all_actors),
        "statistics": {
            "total_techniques":      len(all_techniques),
            "unique_techniques":     len({t.get("technique_id", "") for t in all_techniques}),
            "tactics_distribution":  dict(Counter(t.get("tactic", "")         for t in all_techniques)),
            "severity_distribution": dict(Counter(t.get("severity_level", "") for t in all_techniques)),
            "total_iocs":            sum(len(v) for v in all_iocs.values()),
        },
        "all_iocs":        all_iocs,
        "priority_actions": _deduplicate_ordered(all_actions)[:15],
    }
