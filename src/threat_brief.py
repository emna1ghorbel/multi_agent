"""
CTI FUSION ENGINE — Threat Brief Builder (v3)
===============================================
Redesigned from a passive summarizer (v1) and made fully dynamic (v3).

v2 → v3 changes: eliminated all hardcoded static content lists:
  ✗ Hardcoded malware/country regex in RAG normalization
  ✗ Keyword-based kill chain detection (_KILL_CHAIN_MAP with word lists)
  ✗ Static actor TTP database (_ACTOR_FINGERPRINTS)

Replaced with dynamic approaches:
  ✓ RAG entity search uses entities already extracted by extract_entities (Tool 1)
  ✓ Kill chain derived from behavior .category fields (ATT&CK ontology aliasing)
  ✓ Actor profiling delegated to LLM — enriched with RAG intelligence

Architecture (6 stages):
  Stage 0: Signal Normalization  — parse RAG using already-known entities
  Stage 1: Cross-Signal Correlation — entity×behavior, entity×RAG, CVE×RAG
  Stage 2: Contradiction Resolution  — RAG > regex > llm_only > patterns
  Stage 3: Hypothesis Building       — objective, kill chain, LLM actor profile
  Stage 4: LLM Fusion Analysis       — validate hypotheses, write narrative, T-codes
  Stage 5: Output Assembly           — structured for MITRE Agent + report

Source confidence hierarchy:
  RAG (0.90) > static_regex (0.85) > static+llm (0.87) > llm_only (0.70) > patterns (0.60)
"""

import json
import re
from typing import Any

from llm_helper import llm_analyze


# =============================================================================
# CONSTANTS — weights and ontology mappings only (no content lists)
# =============================================================================

SOURCE_CONFIDENCE = {
    "rag":          0.90,
    "static_regex": 0.85,
    "static+llm":   0.87,
    "llm_only":     0.70,
    "patterns":     0.60,
}

RAG_SCORE_THRESHOLD = 150.0

# Minimum confidence for a correlation link to enter the evidence graph
CORRELATION_MIN_CONFIDENCE = 0.50

_ATTACKCAT_TO_STAGE = {
    # detect_behaviors canonical regex categories
    "process_creation":       "execution",
    "registry_modification":  "persistence",
    "network_communication":  "command_and_control",
    "file_system_activity":   "impact",
    "credential_access":      "credential_access",
    "defense_evasion":        "defense_evasion",
    # LLM-detected categories (from detect_behaviors LLM_CATEGORY_MAP)
    "process_manipulation":   "execution",
    "persistence_mechanisms": "persistence",
    "network_activity":       "command_and_control",
    "file_system_operations": "impact",
    "discovery":              "discovery",
    "lateral_movement":       "lateral_movement",
    "collection":             "collection",
    "exfiltration":           "exfiltration",
    "initial_access":         "initial_access",
    "privilege_escalation":   "privilege_escalation",
    "impact":                 "impact",
}

# Canonical kill chain order (ordering only — no keywords)
_KILL_CHAIN_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]

# Stage → urgency rating (no keyword matching — stage names are categorical)
_STAGE_URGENCY = {
    "impact":               ("CRITICAL", "Attack in final impact stage — immediate response required"),
    "exfiltration":         ("HIGH",     "Data exfiltration in progress — contain now"),
    "command_and_control":  ("HIGH",     "Active C2 — attacker has established foothold"),
    "collection":           ("HIGH",     "Data being staged for exfiltration"),
    "lateral_movement":     ("MEDIUM",   "Attacker moving laterally — expanding access"),
    "credential_access":    ("MEDIUM",   "Credentials being harvested — escalation likely"),
    "privilege_escalation": ("MEDIUM",   "Privilege escalation observed"),
    "persistence":          ("MEDIUM",   "Persistence established — attacker intends long-term access"),
    "defense_evasion":      ("LOW",      "Evasion active — detection may be impaired"),
    "execution":            ("LOW",      "Payload executing — initial compromise confirmed"),
    "initial_access":       ("LOW",      "Initial access phase — early stage, contain before escalation"),
    "discovery":            ("LOW",      "Reconnaissance in progress"),
}

# Confirmed-event keywords — indicate LE action, patch releases, or attribution
_CONFIRMED_EVENT_KEYWORDS = {
    "arrested", "disrupted", "seized", "taken down", "indicted",
    "confirmed", "attributed", "decryptor", "patch released",
    "infrastructure dismantled", "convicted", "charged", "sanctions",
}

# LE disruption keywords — subset of confirmed-event, reduces threat urgency
_LE_DISRUPTION_KEYWORDS = {
    "arrested", "seized", "disrupted", "taken down", "indicted",
    "infrastructure dismantled", "convicted", "charged",
}


# =============================================================================
# STAGE 0 — SIGNAL NORMALIZATION
# =============================================================================

def _normalize_rag_results(rag_context: dict, entities: dict) -> list[dict]:
    """
    Parse RAG results into structured intelligence objects.

    Dynamic entity matching:
      The search vocabulary is built entirely from entities already extracted
      by extract_entities (Tool 1). No hardcoded actor/country/tool lists.
      This means RAG normalization automatically adapts to whatever is relevant
      in the current message — new actors, unknown malware, emerging threats.

    CVE extraction uses a format-based regex (CVE-YEAR-ID universal standard),
    which is the one legitimate exception: it matches a format, not a content list.

    Args:
        rag_context : Raw rag_search tool output
        entities    : extract_entities tool output — provides dynamic vocabulary

    Returns:
        Score-filtered list of structured RAG intelligence objects
    """
    # Build dynamic search vocabulary from what extract_entities already found
    known_actors: set[str] = set()
    for field in ("malware_names", "ransomware_groups", "apt_groups", "threat_actors"):
        for item in entities.get(field, []):
            if isinstance(item, str) and item.strip():
                known_actors.add(item.strip().lower())

    known_countries: set[str] = {
        c.strip().lower()
        for c in entities.get("targeted_countries", [])
        if isinstance(c, str) and c.strip()
    }

    known_tools: set[str] = {
        t.strip().lower()
        for t in entities.get("tools_abused", [])
        if isinstance(t, str) and t.strip()
    }

    normalized = []
    for r in rag_context.get("results", []):
        score   = r.get("score", 999.0)
        content = r.get("content", "")

        if score > RAG_SCORE_THRESHOLD:
            continue  # too dissimilar to the query — discard

        content_lower = content.lower()

        # CVE: format-based (matches universal CVE-YEAR-ID specification)
        cves_found = [c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", content, re.IGNORECASE)]

        # All other entity checks are dynamic — driven by what extract_entities found
        actors_found    = [a for a in known_actors    if a in content_lower]
        countries_found = [c for c in known_countries if c in content_lower]
        tools_found     = [t for t in known_tools     if t in content_lower]

        # Classify this RAG item: confirmed event vs unverified report
        is_confirmed_event = any(kw in content_lower for kw in _CONFIRMED_EVENT_KEYWORDS)
        has_le_action      = any(kw in content_lower for kw in _LE_DISRUPTION_KEYWORDS)

        normalized.append({
            "similarity_score":   round(score, 4),
            "confidence":         SOURCE_CONFIDENCE["rag"],
            "content":            content,
            "channel":            r.get("channel", "unknown"),
            "date":               r.get("date", ""),
            # Dynamically matched entities
            "actors_found":       actors_found,
            "countries_found":    countries_found,
            "tools_found":        tools_found,
            "cves_found":         cves_found,
            # Event classification flags
            "is_confirmed_event": is_confirmed_event,
            "has_le_action":      has_le_action,
        })

    # Most similar first (ascending L2 distance = ascending score)
    return sorted(normalized, key=lambda r: r["similarity_score"])


def _extract_behavioral_iocs(entities: dict) -> list[str]:
    """
    Extract IOCs relevant for MITRE ATT&CK technique mapping.
    Excludes raw network IOCs (IPs, hashes, emails) — no ATT&CK signal.
    """
    relevant = []
    for key in (
        "malware_names", "ransomware_groups", "apt_groups",
        "tools_abused", "cves", "campaign_names", "threat_actors",
    ):
        for item in entities.get(key, []):
            if isinstance(item, str) and item.strip():
                relevant.append(item.strip())

    urls = entities.get("urls", [])
    if len(urls) <= 5:
        relevant.extend(urls)

    return list(dict.fromkeys(relevant))


# =============================================================================
# STAGE 1 — CROSS-SIGNAL CORRELATION ENGINE
# =============================================================================

def _correlate_signals(
    entities:       dict,
    behaviors:      list[dict],
    patterns:       dict,
    rag_normalized: list[dict],
) -> dict:
    """
    Build an evidence graph by correlating signals across all four tools.

    Correlation pairs:
      entity × behavior : Actor type (ransomware/APT/malware) matched against
                          behavior category and severity — no name lookup tables
      entity × RAG      : Dynamic search: which of our extracted actors appear
                          in RAG content? Boosts confidence; flags LE actions
      behavior × pattern: Coherence check between behavior severity and pattern
                          classification; detects BENIGN vs MALICIOUS contradictions
      RAG × pattern     : Independent theme corroboration via pattern CTI term overlap
      CVE × RAG         : Same CVE in current message AND historical RAG = strong signal
    """
    links              = []
    rag_confirmations  = []
    rag_contradictions = []
    entity_scores      = {}

    all_actors = list(dict.fromkeys(
        entities.get("malware_names",     []) +
        entities.get("ransomware_groups", []) +
        entities.get("apt_groups",        []) +
        entities.get("threat_actors",     [])
    ))

    behavior_categories = {b.get("category", "") for b in behaviors}
    behavior_severities  = {b.get("severity",  "") for b in behaviors}

    # ── Entity × Behavior Correlation ────────────────────────────────────────
    # Coherence is determined by ACTOR TYPE (from entity dict labels),
    # not by a hardcoded name→behavior lookup table.
    ransomware_behaviors = {"file_system_activity", "network_communication", "credential_access"}
    apt_behaviors        = {"lateral_movement", "credential_access", "defense_evasion",
                            "network_communication", "discovery"}
    generic_behaviors    = {"process_creation", "network_communication"}

    for actor in all_actors:
        if actor in entities.get("ransomware_groups", []):
            actor_type = "ransomware"
            expected   = ransomware_behaviors
        elif actor in entities.get("apt_groups", []):
            actor_type = "apt"
            expected   = apt_behaviors
        else:
            actor_type = "malware"
            expected   = generic_behaviors

        confirmed = expected & behavior_categories
        base_conf = SOURCE_CONFIDENCE["llm_only"]
        conf      = min(0.95, base_conf + 0.08 * len(confirmed)) if confirmed else base_conf

        entity_scores[actor] = conf
        if confirmed:
            links.append({
                "type":               "entity_x_behavior",
                "entity":             actor,
                "actor_type":         actor_type,
                "confirmed_behaviors": list(confirmed),
                "confidence":         conf,
                "interpretation": (
                    f"'{actor}' ({actor_type}) corroborated by "
                    f"{len(confirmed)} matching behavior(s): {', '.join(confirmed)}"
                ),
            })

    # ── Entity × RAG Correlation ──────────────────────────────────────────────
    for rag_item in rag_normalized:
        for actor in all_actors:
            if actor.lower() in rag_item["actors_found"]:
                boost    = 0.15 if rag_item["is_confirmed_event"] else 0.08
                new_conf = min(0.98, entity_scores.get(actor, 0.70) + boost)

                rag_confirmations.append({
                    "type":               "rag_confirms_entity",
                    "entity":             actor,
                    "rag_channel":        rag_item["channel"],
                    "rag_date":           rag_item["date"],
                    "is_confirmed_event": rag_item["is_confirmed_event"],
                    "confidence_before":  entity_scores.get(actor, 0.70),
                    "confidence_after":   new_conf,
                    "interpretation": (
                        f"RAG independently references '{actor}' "
                        f"({'confirmed event' if rag_item['is_confirmed_event'] else 'related report'}) "
                        f"— confidence {entity_scores.get(actor, 0.70):.2f} → {new_conf:.2f}"
                    ),
                })
                entity_scores[actor] = new_conf

                if rag_item["has_le_action"]:
                    rag_contradictions.append({
                        "type":        "rag_le_action",
                        "entity":      actor,
                        "rag_channel": rag_item["channel"],
                        "note": (
                            f"RAG intelligence indicates law enforcement action against '{actor}' "
                            f"— verify whether this actor's infrastructure is still active"
                        ),
                    })

    # ── Behavior × Pattern Coherence ─────────────────────────────────────────
    classification  = patterns.get("threat_classification", "").upper()
    cti_terms_found = patterns.get("known_cti_terms", [])
    has_critical    = "critical" in behavior_severities
    has_high        = "high"     in behavior_severities

    if has_critical and any(kw in classification for kw in ("RANSOMWARE", "APT", "MALICIOUS")):
        coherence_score = 0.88
        coherence_note  = "Critical behaviors and pattern classification are coherent."
    elif has_high and classification not in ("BENIGN", "ADMINISTRATIVE"):
        coherence_score = 0.75
        coherence_note  = "High-severity behaviors partially corroborate pattern classification."
    elif classification in ("BENIGN", "ADMINISTRATIVE") and (has_critical or has_high):
        coherence_score = 0.35
        coherence_note  = (
            "⚠ CONTRADICTION: Pattern engine says BENIGN/ADMINISTRATIVE but "
            "critical/high-severity behaviors detected. "
            "Behaviors (static_regex, conf=0.85) override patterns (conf=0.60)."
        )
    else:
        coherence_score = SOURCE_CONFIDENCE["patterns"]
        coherence_note  = "Pattern classification has limited behavioral corroboration."

    links.append({
        "type":             "behavior_x_pattern",
        "classification":   classification,
        "behavior_severity": "critical" if has_critical else ("high" if has_high else "medium"),
        "coherence_score":  coherence_score,
        "interpretation":   coherence_note,
    })

    # ── RAG × Pattern Correlation ─────────────────────────────────────────────
    all_rag_text     = " ".join(r["content"].lower() for r in rag_normalized)
    rag_term_overlap = [t for t in cti_terms_found if t in all_rag_text]
    if rag_term_overlap:
        links.append({
            "type":         "rag_x_pattern",
            "shared_terms": rag_term_overlap,
            "confidence":   SOURCE_CONFIDENCE["rag"],
            "interpretation": (
                f"RAG and pattern engine independently identify "
                f"{len(rag_term_overlap)} shared CTI term(s): "
                f"{', '.join(rag_term_overlap[:5])} — independent theme confirmation"
            ),
        })

    # ── CVE × RAG ─────────────────────────────────────────────────────────────
    entity_cves = set(entities.get("cves", []))
    rag_cves    = set(cve for r in rag_normalized for cve in r["cves_found"])
    cve_overlap = entity_cves & rag_cves
    if cve_overlap:
        links.append({
            "type":        "cve_x_rag",
            "shared_cves": list(cve_overlap),
            "confidence":  SOURCE_CONFIDENCE["rag"],
            "interpretation": (
                f"CVE(s) {', '.join(cve_overlap)} appear in BOTH the current message "
                f"AND historical RAG intelligence — active exploitation confirmed"
            ),
        })

    return {
        "links":              links,
        "rag_confirmations":  rag_confirmations,
        "contradictions":     rag_contradictions,
        "entity_scores":      entity_scores,
        "cve_overlap":        list(cve_overlap),
        "rag_term_overlap":   rag_term_overlap,
        "total_correlations": len(links) + len(rag_confirmations),
    }


# =============================================================================
# STAGE 2 — CONTRADICTION RESOLUTION
# =============================================================================

def _resolve_contradictions(
    correlation_graph: dict,
    entities:          dict,
    patterns:          dict,
    rag_normalized:    list[dict],
) -> dict:
    """
    Apply source confidence priority chain to resolve conflicting signals.
    Priority: RAG (0.90) > static_regex (0.85) > llm_only (0.70) > patterns (0.60)
    """
    notes = []

    # A — Behavior vs Pattern contradiction
    bp_link = next(
        (l for l in correlation_graph["links"] if l["type"] == "behavior_x_pattern"), None
    )
    if bp_link and bp_link["coherence_score"] < 0.50:
        final_classification = "MALICIOUS (Behavior-Confirmed, Pattern Overridden)"
        final_confidence     = SOURCE_CONFIDENCE["static_regex"]
        notes.append(
            f"Pattern overridden: static_regex (conf={SOURCE_CONFIDENCE['static_regex']}) "
            f"> patterns (conf={SOURCE_CONFIDENCE['patterns']})"
        )
    else:
        raw_class        = patterns.get("threat_classification", "UNKNOWN")
        raw_conf         = patterns.get("classification_confidence", 0.50)
        rag_boost        = 0.10 if correlation_graph.get("rag_term_overlap") else 0.0
        final_classification = raw_class
        final_confidence     = min(0.95, raw_conf + rag_boost)

    # B — Entity confidence flags
    entity_scores = correlation_graph.get("entity_scores", {})
    entity_flags  = {}
    for entity, score in entity_scores.items():
        if score < CORRELATION_MIN_CONFIDENCE:
            entity_flags[entity] = f"unconfirmed (conf={score:.2f})"
        elif score >= SOURCE_CONFIDENCE["rag"]:
            entity_flags[entity] = f"high-confidence (conf={score:.2f}) — RAG+behavior corroborated"
        else:
            entity_flags[entity] = f"moderate-confidence (conf={score:.2f})"

    # C — LE disruption flags
    le_flags = [c for c in correlation_graph.get("contradictions", []) if c["type"] == "rag_le_action"]
    if le_flags:
        notes.append(
            f"RAG references possible LE action against: "
            f"{', '.join(f['entity'] for f in le_flags)}. "
            f"Assess whether threat actor infrastructure remains active."
        )

    return {
        "final_classification": final_classification,
        "final_confidence":     round(final_confidence, 2),
        "resolution_notes":     notes,
        "entity_flags":         entity_flags,
        "high_conf_actors":     [e for e, f in entity_flags.items() if "high-confidence" in f],
        "unconfirmed_actors":   [e for e, f in entity_flags.items() if "unconfirmed"     in f],
        "le_action_flags":      le_flags,
    }


# =============================================================================
# STAGE 3 — HYPOTHESIS BUILDING
# =============================================================================

def _derive_kill_chain(behaviors: list[dict]) -> tuple[list[str], str, str]:
    """
    Derive kill chain stages from behavior .category fields via ATT&CK ontology.

    No keyword scanning. detect_behaviors already maps raw text → ATT&CK categories.
    We alias those category names to Unified Kill Chain stage names via
    _ATTACKCAT_TO_STAGE (a principled ontology mapping, not a word list).

    Returns:
        (ordered_stages, current_stage, urgency_level)
    """
    detected: set[str] = set()
    for b in behaviors:
        cat    = b.get("category", "").lower()
        mapped = _ATTACKCAT_TO_STAGE.get(cat)
        if mapped:
            detected.add(mapped)
        # If category IS already a canonical stage name, include directly
        if cat in _STAGE_URGENCY:
            detected.add(cat)

    ordered       = [s for s in _KILL_CHAIN_ORDER if s in detected]
    current_stage = ordered[-1] if ordered else "unknown"
    urgency, _    = _STAGE_URGENCY.get(current_stage, ("UNKNOWN", ""))

    return ordered, current_stage, urgency


# ── LLM Actor Profiling ───────────────────────────────────────────────────────

_ACTOR_PROFILE_PROMPT = """You are a Cyber Threat Intelligence actor attribution analyst.

You receive:
- Observed tools, behaviors, and entities from a current CTI message
- RAG intelligence (highest confidence source — historical, vetted data)
- Pre-computed kill chain stages and entity confidence scores

YOUR TASK: Profile the most likely threat actor from what is actually observed.
Use your knowledge of known APT groups, ransomware operators, and cybercrime actors.
Do NOT invent actors. If evidence is insufficient, output "unknown".

SOURCE HIERARCHY: RAG (0.90) > behaviors (0.85) > entities (0.70)

STRICT RULES:
- Unconfirmed actors (no RAG / no behavior corroboration) → confidence < 0.50
- If RAG shows law enforcement action against an actor, flag disruption_risk
- typical_next_moves must reflect this actor's KNOWN playbook, not generic steps
- All fields required; null for unknown
- IMPORTANT: Distinguish between MALWARE FAMILY (the tool) and THREAT ACTOR (the operator).
  "LockBit 3.0" is a malware family; the operator may be an affiliate group such as ALPHV/BlackCat.
  If both are present, report the OPERATOR as likely_actor and the malware as evidence.
- If multiple actor names appear, report the one with strongest behavioral corroboration,
  not necessarily the one mentioned most often.

Return ONLY valid JSON:
{
  "likely_actor": "actor name | 'unknown opportunistic' | 'unknown targeted APT'",
  "confidence": 0.0,
  "actor_maturity": "script_kiddie | opportunistic | targeted | apt_level",
  "actor_type": "ransomware | apt | stealer | ddos | broker | unknown",
  "double_extortion": false,
  "typical_next_moves": ["concrete next steps from this actor's known playbook"],
  "known_campaigns": ["campaigns matching this profile from your knowledge base"],
  "target_sectors": ["sectors this actor is known to target"],
  "target_geographies": ["countries/regions typically targeted"],
  "infrastructure_notes": "What is known about this actor's C2 / hosting infrastructure",
  "disruption_risk": "active | possibly_disrupted | disrupted | unknown",
  "evidence_summary": ["specific evidence items driving this attribution"],
  "attribution_gaps": ["what information is missing to raise confidence further"]
}"""


def _llm_actor_profile(
    entities:          dict,
    behaviors:         list[dict],
    rag_normalized:    list[dict],
    kill_chain_stages: list[str],
    resolution:        dict,
) -> dict:
    """
    Dynamically profile the threat actor via LLM + RAG intelligence.

    Replaces the static _ACTOR_FINGERPRINTS dictionary entirely.
    The LLM has actor TTP knowledge from training; RAG provides mission-specific
    historical intelligence. Together they replace any hardcoded lookup table
    while covering far more actors and staying current via RAG.
    """
    context = {
        "high_confidence_actors": resolution.get("high_conf_actors", []),
        "unconfirmed_actors":     resolution.get("unconfirmed_actors", []),
        "le_disruption_flags":    [f["entity"] for f in resolution.get("le_action_flags", [])],
        "observed_tools":         entities.get("tools_abused",      []),
        "observed_malware":       entities.get("malware_names",     []),
        "ransomware_groups":      entities.get("ransomware_groups", []),
        "apt_groups":             entities.get("apt_groups",        []),
        "detected_behaviors": [
            {
                "category":  b.get("category"),
                "severity":  b.get("severity"),
                "source":    b.get("detection_source"),
                "indicators": b.get("matched_indicators", [])[:3],
            }
            for b in behaviors
        ],
        "kill_chain_stages_observed": kill_chain_stages,
        "targeted_sectors":           entities.get("targeted_sectors",   []),
        "targeted_countries":         entities.get("targeted_countries", []),
        # RAG as ground truth — full structured intelligence
        "rag_intelligence": [
            {
                "content":     r["content"][:350],
                "channel":     r["channel"],
                "date":        r["date"],
                "actors_found": r["actors_found"],
                "is_confirmed_event": r["is_confirmed_event"],
                "has_le_action":      r["has_le_action"],
            }
            for r in rag_normalized
        ],
    }

    result = llm_analyze(_ACTOR_PROFILE_PROMPT, json.dumps(context, default=str))

    if result.get("llm_failed") or result.get("parse_error"):
        candidates = (
            resolution.get("high_conf_actors") or
            entities.get("ransomware_groups") or
            entities.get("apt_groups") or
            entities.get("threat_actors") or
            ["unknown"]
        )
        actor = candidates[0] if candidates else "unknown"
        return {
            "likely_actor":       actor,
            "confidence":         0.50 if actor != "unknown" else 0.10,
            "actor_maturity":     "unknown",
            "actor_type":         "unknown",
            "double_extortion":   False,
            "typical_next_moves": [],
            "known_campaigns":    [],
            "target_sectors":     entities.get("targeted_sectors", []),
            "target_geographies": entities.get("targeted_countries", []),
            "infrastructure_notes": "",
            "disruption_risk":    "unknown",
            "evidence_summary":   resolution.get("high_conf_actors", []),
            "attribution_gaps":   ["LLM actor profiling unavailable — fallback used"],
        }

    return result


def _build_hypotheses(
    entities:          dict,
    behaviors:         list[dict],
    patterns:          dict,
    rag_normalized:    list[dict],
    correlation_graph: dict,
    resolution:        dict,
) -> dict:
    """
    Build pre-computed intelligence hypotheses before the main LLM fusion call.

    H1 — Attack Objective : from entity type labels + behavior categories (no hardcoded names)
    H2 — Operational Stage: from behavior categories via ATT&CK ontology alias
    H3 — Actor Profile    : fully dynamic LLM call enriched with RAG intelligence
    """
    # H1 — Objective: inferred from entity TYPE (dict key) + behavior CATEGORY
    is_ransomware = (
        bool(entities.get("ransomware_groups")) or
        any(b.get("category") == "file_system_activity" and
            b.get("severity") in ("high", "critical") for b in behaviors)
    )
    is_espionage = (
        bool(entities.get("apt_groups")) or
        any(b.get("category") in ("exfiltration", "collection", "discovery") for b in behaviors)
    )
    is_financial = bool(any(entities.get("crypto_wallets", {}).values()))

    if is_ransomware:
        objective    = "ransomware_extortion"
        obj_conf     = min(0.95, 0.65 + 0.08 * len(entities.get("ransomware_groups", [])))
        obj_evidence = entities.get("ransomware_groups", []) + (
            ["file encryption behavior confirmed"] if any(
                b.get("category") == "file_system_activity" for b in behaviors
            ) else []
        )
    elif is_espionage:
        objective    = "data_exfiltration_espionage"
        obj_conf     = min(0.90, 0.60 + 0.08 * len(entities.get("apt_groups", [])))
        obj_evidence = entities.get("apt_groups", []) + ["exfiltration/collection behaviors"]
    elif is_financial:
        objective    = "financial_theft"
        obj_conf     = 0.70
        obj_evidence = ["crypto wallet indicators present"]
    else:
        objective    = "unknown"
        obj_conf     = 0.30
        obj_evidence = []

    h1 = {
        "hypothesis": "H1 — Attack Objective",
        "assessment": objective,
        "confidence": round(obj_conf, 2),
        "evidence":   obj_evidence,
    }

    # H2 — Kill Chain / Operational Stage: from behavior categories (ontology)
    ordered_stages, current_stage, urgency_level = _derive_kill_chain(behaviors)
    urgency_note = _STAGE_URGENCY.get(current_stage, ("UNKNOWN", ""))[1]

    h2 = {
        "hypothesis":       "H2 — Operational Stage",
        "all_stages":       ordered_stages,
        "current_stage":    current_stage,
        "urgency":          urgency_level,
        "urgency_note":     urgency_note,
        "stages_completed": len(ordered_stages),
    }

    # H3 — Actor Profile: fully dynamic LLM call
    actor_profile = _llm_actor_profile(
        entities          = entities,
        behaviors         = behaviors,
        rag_normalized    = rag_normalized,
        kill_chain_stages = ordered_stages,
        resolution        = resolution,
    )

    h3 = {
        "hypothesis":    "H3 — Actor Profile (LLM-Dynamic)",
        "actor_profile": actor_profile,
        "best_match":    actor_profile.get("likely_actor", "unknown"),
        "best_score":    actor_profile.get("confidence",   0.0),
        "note": (
            f"LLM attribution: '{actor_profile.get('likely_actor', 'unknown')}' "
            f"(conf={actor_profile.get('confidence', 0.0):.2f})"
        ),
    }

    return {
        "h1_objective":         h1,
        "h2_operational_stage": h2,
        "h3_actor_profile":     h3,
        "kill_chain_stages":    ordered_stages,
        "urgency":              urgency_level,
    }


# =============================================================================
# STAGE 4 — LLM FUSION ANALYST
# =============================================================================

_FUSION_PROMPT = """You are a Cyber Threat Intelligence (CTI) Fusion Analyst.

### YOUR ROLE
You do NOT summarize tool outputs independently.
You receive pre-computed correlation results and static hypotheses.
Your job: VALIDATE, ENRICH, and CONNECT them into one unified intelligence picture.

### WHAT IS ALREADY DONE
1. Cross-signal correlation graph (entity×behavior, entity×RAG, CVE×RAG)
2. Contradiction resolution using source confidence hierarchy
3. Attack objective, kill chain, and actor profile hypothesized

### YOUR TASKS
1. Validate the pre-built hypotheses — confirm or adjust with reasoning
2. Write the unified attack NARRATIVE (one connected paragraph, not a list)
3. Identify signal relationships the static engine missed
4. Assign ATT&CK T-codes to each behavior for the MITRE Agent
5. List intelligence gaps — tell the MITRE Agent what NOT to hallucinate

### SOURCE PRIORITY (use when signals conflict)
  RAG (0.90) > static_regex (0.85) > llm_entity (0.70) > patterns (0.60)

### STRICT RULES
- Do NOT assert unconfirmed_actors with confidence ≥ 0.50
- Do NOT invent CVEs, tools, or actor names not present in the input
- Do NOT copy RAG content verbatim — interpret and cite it
- attack_narrative must be one connected paragraph, not bullet points
- Every mitre_relevant_behavior MUST include an attack_technique_hint.
Use a real MITRE ATT&CK T-code ONLY if you are certain it matches the observed behavior.
If uncertain, write 'T-code: unknown — [describe the technique in plain English]'.
NEVER invent a T-code. An honest 'unknown' is required over a hallucinated T-code.
- If RAG shows LE disruption, reduce threat urgency and note it explicitly

Return ONLY valid JSON — no markdown, no preamble:
{
  "attack_narrative": "Single connected paragraph describing the full correlated attack chain",
  "actor_assessment": {
    "validated_actor": "actor name or unknown",
    "confidence_adjustment": "raised | unchanged | lowered",
    "adjustment_reason": "why confidence was adjusted from the H3 hypothesis",
    "validated_maturity": "opportunistic | targeted | apt_level",
    "rag_confirmed": true
  },
  "environment_context": {
    "target_os": "Windows | Linux | macOS | unknown",
    "target_sector": ["list"],
    "infrastructure_criticality": "high | medium | low | unknown",
    "victim_profile": "brief description of likely victim org type"
  },
  "attack_maturity": "opportunistic | targeted | apt_level",
  "operational_stage": "current kill chain stage name + urgency context",
  "kill_chain_narrative": "Causal paragraph connecting each observed stage to the next",
  "intelligence_gaps": ["Specific unknowns that matter for MITRE technique mapping"],
  "mitre_relevant_behaviors": [
    {
      "category": "credential_access",
      "description": "LSASS dumped via Mimikatz following UAC bypass",
      "attack_technique_hint": "T1003.001 — OS Credential Dumping: LSASS Memory",
      "confidence": 0.92,
      "evidence": ["mimikatz entity (RAG-confirmed)", "credential_access behavior (static_regex)"],
      "key_indicators": ["mimikatz", "lsass", "hashdump"]
    }
  ],
  "campaign_assessment": {
    "is_known_campaign": true,
    "campaign_name_or_type": "string",
    "double_extortion": true,
    "threat_still_active": true,
    "disruption_note": null
  },
  "noise_filtered": [
    {"item": "192.168.1.1", "reason": "raw network IOC — no ATT&CK technique mapping"}
  ]
}"""


def _llm_fusion_analyst(
    correlation_graph: dict,
    resolution:        dict,
    hypotheses:        dict,
    entities:          dict,
    behaviors:         list[dict],
    patterns:          dict,
    rag_normalized:    list[dict],
    behavioral_iocs:   list[str],
) -> dict:
    """
    Main LLM fusion call — reasons over pre-computed correlations, not raw dumps.

    v1 sent 6 raw JSON blobs → LLM treated tools independently → no correlation.
    v3 sends correlation graph + resolved contradictions + static hypotheses
    → LLM validates and enriches relationships → true fusion analysis.
    """
    context = {
        "correlation_graph": {
            "confirmed_links":    correlation_graph["links"],
            "rag_confirmations":  correlation_graph["rag_confirmations"],
            "contradictions":     correlation_graph["contradictions"],
            "total_correlations": correlation_graph["total_correlations"],
        },
        "resolution": {
            "final_classification":   resolution["final_classification"],
            "final_confidence":       resolution["final_confidence"],
            "high_confidence_actors": resolution["high_conf_actors"],
            "unconfirmed_actors":     resolution["unconfirmed_actors"],
            "resolution_notes":       resolution["resolution_notes"],
            "le_action_flags":        resolution["le_action_flags"],
        },
        "hypotheses": {
            "attack_objective":  hypotheses["h1_objective"],
            "operational_stage": hypotheses["h2_operational_stage"],
            "actor_profile":     hypotheses["h3_actor_profile"],
        },
        # RAG — highest confidence source, full content
        "rag_intelligence": [
            {
                "content":      r["content"][:400],
                "channel":      r["channel"],
                "date":         r["date"],
                "confidence":   r["confidence"],
                "actors_found": r["actors_found"],
                "cves_found":   r["cves_found"],
                "is_confirmed_event": r["is_confirmed_event"],
                "has_le_action":      r["has_le_action"],
            }
            for r in rag_normalized
        ],
        "behaviors": [
            {
                "category":   b.get("category"),
                "description": b.get("description"),
                "severity":   b.get("severity"),
                "confidence": b.get("confidence"),
                "source":     b.get("detection_source"),
                "indicators": b.get("matched_indicators", [])[:5],
            }
            for b in behaviors
        ],
        "entities": {
            "malware":       entities.get("malware_names",     []),
            "ransomware":    entities.get("ransomware_groups", []),
            "apt_groups":    entities.get("apt_groups",        []),
            "tools":         entities.get("tools_abused",      []),
            "cves":          entities.get("cves",              []),
            "threat_actors": entities.get("threat_actors",     []),
            "campaigns":     entities.get("campaign_names",    []),
            "sectors":       entities.get("targeted_sectors",  []),
            "countries":     entities.get("targeted_countries",[]),
        },
        "pattern_signals": {
            "classification":  patterns.get("threat_classification", ""),
            "semantic_summary": patterns.get("semantic_summary", ""),
            "known_cti_terms": patterns.get("known_cti_terms", []),
            "predicted_steps": patterns.get("predicted_next_steps", []),
            "emerging_terms":  patterns.get("emerging_terms", []),
        },
        "behavioral_iocs_for_mitre": behavioral_iocs,
    }

    result = llm_analyze(_FUSION_PROMPT, json.dumps(context, default=str))

    if result.get("llm_failed") or result.get("parse_error"):
        return _static_fallback(entities, behaviors, hypotheses, resolution)

    return result


def _static_fallback(
    entities:   dict,
    behaviors:  list[dict],
    hypotheses: dict,
    resolution: dict,
) -> dict:
    """Minimal static fallback when the LLM call fails."""
    h1 = hypotheses["h1_objective"]
    h2 = hypotheses["h2_operational_stage"]
    h3 = hypotheses["h3_actor_profile"]

    return {
        "attack_narrative": (
            f"[STATIC FALLBACK] Objective: {h1['assessment']} (conf={h1['confidence']}). "
            f"Stage: {h2['current_stage']} — urgency: {h2['urgency']}. "
            f"Actor: {h3['best_match']} (conf={h3['best_score']:.2f}). "
            f"Classification: {resolution['final_classification']}."
        ),
        "actor_assessment": {
            "validated_actor":      h3["best_match"],
            "confidence_adjustment": "unchanged",
            "adjustment_reason":    "LLM unavailable — hypothesis used directly",
            "validated_maturity":   h3["actor_profile"].get("actor_maturity", "unknown"),
            "rag_confirmed":        bool(resolution["high_conf_actors"]),
        },
        "environment_context": {
            "target_os":                 "unknown",
            "target_sector":             entities.get("targeted_sectors", []),
            "infrastructure_criticality": "unknown",
            "victim_profile":            "unknown",
        },
        "attack_maturity":    "unknown",
        "operational_stage":  h2["current_stage"],
        "kill_chain_narrative": f"Stages detected: {', '.join(h2['all_stages'])}",
        "intelligence_gaps":  ["LLM fusion unavailable — static fallback active"],
        "mitre_relevant_behaviors": [
            {
                "category":             b.get("category", ""),
                "description":          b.get("description", ""),
                "attack_technique_hint": "",
                "confidence":           b.get("confidence", 0.70),
                "evidence":             [b.get("detection_source", "")],
                "key_indicators":       b.get("matched_indicators", [])[:3],
            }
            for b in behaviors
        ],
        "campaign_assessment": {
            "is_known_campaign":    h3["best_score"] > 0.60,
            "campaign_name_or_type": h3["note"],
            "double_extortion":     h3["actor_profile"].get("double_extortion", False),
            "threat_still_active":  not bool(resolution["le_action_flags"]),
            "disruption_note":      None,
        },
        "noise_filtered": [],
    }


# =============================================================================
# STAGE 5 — OUTPUT ASSEMBLY
# =============================================================================

def _assemble_mitre_input(
    fusion_result:   dict,
    hypotheses:      dict,
    resolution:      dict,
    behavioral_iocs: list[str],
) -> dict:
    """Assemble enriched MITRE Agent input from fusion results."""
    actor_assess = fusion_result.get("actor_assessment", {})
    h3           = hypotheses["h3_actor_profile"]

    return {
        # Correlated behaviors with T-code hints
        "behaviors":      fusion_result.get("mitre_relevant_behaviors", []),
        # Fully resolved actor context
        "actor_context": {
            "validated_actor":    actor_assess.get("validated_actor",    h3["best_match"]),
            "confidence":         h3["actor_profile"].get("confidence",  0.0),
            "actor_type":         h3["actor_profile"].get("actor_type",  "unknown"),
            "actor_maturity":     actor_assess.get("validated_maturity", "unknown"),
            "double_extortion":   h3["actor_profile"].get("double_extortion", False),
            "typical_next_moves": h3["actor_profile"].get("typical_next_moves", []),
            "rag_confirmed":      actor_assess.get("rag_confirmed",      False),
            "disruption_risk":    h3["actor_profile"].get("disruption_risk", "unknown"),
            "campaign_assessment": fusion_result.get("campaign_assessment", {}),
        },
        "kill_chain_stages":       hypotheses["kill_chain_stages"],
        "attack_maturity":         fusion_result.get("attack_maturity",    "unknown"),
        "operational_stage":       fusion_result.get("operational_stage",  "unknown"),
        "urgency":                 hypotheses["urgency"],
        "intelligence_gaps":       fusion_result.get("intelligence_gaps",  []),
        "behavioral_iocs":         behavioral_iocs,
        "resolved_classification": resolution["final_classification"],
        "resolved_confidence":     resolution["final_confidence"],
        "attribution_gaps":        h3["actor_profile"].get("attribution_gaps", []),
    }


# =============================================================================
# PUBLIC ENTRY POINT
# =============================================================================

def build_threat_brief(
    entities:    dict,
    behaviors:   list[dict],
    patterns:    dict,
    rag_context: dict,
) -> dict:
    """
    CTI Fusion Engine — fully dynamic, 6-stage pipeline.

    No hardcoded actor lists, no keyword-based kill chain detection,
    no static TTP fingerprint databases. All intelligence is derived
    dynamically from tool outputs + LLM knowledge + RAG.

    Args:
        entities    : Output from extract_entities tool
        behaviors   : behaviors_detected list from detect_behaviors tool
        patterns    : Output from detect_patterns tool
        rag_context : Parsed output from rag_search tool
    """
    print("  [Fusion 0/5] Normalizing signals (dynamic entity matching)...")
    rag_normalized  = _normalize_rag_results(rag_context, entities)
    behavioral_iocs = _extract_behavioral_iocs(entities)

    print("  [Fusion 1/5] Building cross-signal correlation graph...")
    correlation_graph = _correlate_signals(entities, behaviors, patterns, rag_normalized)

    print("  [Fusion 2/5] Resolving contradictions (priority chain)...")
    resolution = _resolve_contradictions(
        correlation_graph, entities, patterns, rag_normalized
    )

    print("  [Fusion 3/5] Building hypotheses (kill chain + LLM actor profile)...")
    hypotheses = _build_hypotheses(
        entities, behaviors, patterns,
        rag_normalized, correlation_graph, resolution,
    )

    print("  [Fusion 4/5] Running LLM fusion analysis...")
    fusion_result = _llm_fusion_analyst(
        correlation_graph = correlation_graph,
        resolution        = resolution,
        hypotheses        = hypotheses,
        entities          = entities,
        behaviors         = behaviors,
        patterns          = patterns,
        rag_normalized    = rag_normalized,
        behavioral_iocs   = behavioral_iocs,
    )

    print("  [Fusion 5/5] Assembling output for MITRE Agent...")
    mitre_input = _assemble_mitre_input(
        fusion_result   = fusion_result,
        hypotheses      = hypotheses,
        resolution      = resolution,
        behavioral_iocs = behavioral_iocs,
    )

    return {
        # For MITRE Agent
        "mitre_input": mitre_input,

        # Full fusion intelligence
        "fusion": {
            "correlation_graph": {
                "links":             correlation_graph["links"],
                "rag_confirmations": correlation_graph["rag_confirmations"],
                "contradictions":    correlation_graph["contradictions"],
                "entity_scores":     correlation_graph["entity_scores"],
                "total_correlations": correlation_graph["total_correlations"],
            },
            "resolution":  resolution,
            "hypotheses":  hypotheses,
            "rag_results_used": len(rag_normalized),
        },

        # For final report
        "attack_intelligence": {
            "narrative":           fusion_result.get("attack_narrative", ""),
            "actor_profile":       hypotheses["h3_actor_profile"]["actor_profile"],
            "actor_assessment":    fusion_result.get("actor_assessment", {}),
            "campaign_assessment": fusion_result.get("campaign_assessment", {}),
            "environment_context": fusion_result.get("environment_context", {}),
        },

        # Legacy compatibility
        "attack_narrative":     fusion_result.get("attack_narrative", ""),
        "kill_chain_narrative": fusion_result.get("kill_chain_narrative", ""),
        "kill_chain_stages":    hypotheses["kill_chain_stages"],
        "actor_profile":        hypotheses["h3_actor_profile"]["actor_profile"],
        "environment_context":  fusion_result.get("environment_context", {}),

        # Transparency
        "behavioral_iocs_used":      behavioral_iocs,
        "noise_filtered":            fusion_result.get("noise_filtered", []),
        "ioc_count_network_raw":    entities.get("ioc_count_network", 0),   # pure network IOCs
        "ioc_count_entities_raw":   entities.get("ioc_count", 0),           # all entities
        "ioc_count_for_mitre":      len(behavioral_iocs),                   # behaviorally relevant subset
        "entity_confidence_scores":  correlation_graph["entity_scores"],
        "high_confidence_entities":  resolution["high_conf_actors"],
        "unconfirmed_entities":      resolution["unconfirmed_actors"],
        "intelligence_gaps":         fusion_result.get("intelligence_gaps", []),
        "attribution_gaps":          hypotheses["h3_actor_profile"]["actor_profile"].get(
                                         "attribution_gaps", []
                                     ),
    }
