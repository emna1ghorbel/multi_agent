"""
TOOL 1 (MITRE Layer) — MITRE ATT&CK Mapper
============================================
Maps detected malicious behaviors to official MITRE ATT&CK techniques.

Two-phase architecture:
  Phase 1 (STIX)  : Keyword search in the official MITRE ATT&CK STIX database,
                    followed by LLM batch-validation to remove false positives.
  Phase 2 (LLM)   : Contextual mapping for behaviors not covered by STIX.

FIXES vs original:
  1. DOUBLE STIX SCAN: The `uncovered` behaviors filter re-ran _search_mitre_stix()
     for every indicator of every behavior, duplicating all work already done by
     _collect_stix_candidates(). Fixed by building a behavior→technique coverage
     index during the first pass and reusing it.

  2. MISSING source_behavior FIELD: _collect_stix_candidates() never set
     source_behavior on candidates, so _llm_batch_verify() always logged "unknown"
     for the source, making the LLM validation context useless. Fixed by recording
     the originating behavior category when each candidate is created.
"""

import os
import json
from mitreattack.stix20 import MitreAttackData
from langchain_core.tools import tool
from core.llm_helper import llm_analyze
from core import config


# =============================================================================
# STIX DATABASE LOADER
# =============================================================================

_mitre_data: MitreAttackData | None = None


def _get_mitre_data() -> MitreAttackData:
    """
    Lazily load the MITRE ATT&CK STIX database from disk.
    Subsequent calls return the cached instance (expensive to reload).
    """
    global _mitre_data
    if _mitre_data is None:
        path = config.MITRE_STIX_PATH
        if os.path.exists(path):
            print(f"[MITRE] Loading STIX database from: {path}")
            _mitre_data = MitreAttackData(path)
            print("[MITRE] STIX database loaded successfully.")
        else:
            raise FileNotFoundError(
                f"Critical Error: enterprise-attack.json not found at {path}"
            )
    return _mitre_data


# =============================================================================
# PHASE 1a — STIX KEYWORD SEARCH
# =============================================================================

def _search_mitre_stix(keyword: str, limit: int = 3) -> list[dict]:
    """
    Search the STIX database for ATT&CK techniques matching a keyword.

    Scans both technique name and description fields.
    Returns up to `limit` techniques with their ATT&CK ID, name, and tactic.
    """
    mitre        = _get_mitre_data()
    results      = []
    keyword_lower = keyword.lower()

    for tech in mitre.get_techniques():
        name        = tech.get("name", "").lower()
        description = tech.get("description", "").lower()

        if keyword_lower not in name and keyword_lower not in description:
            continue

        # Extract the external ATT&CK ID 
        external_id = next(
            (
                ref.get("external_id", "")
                for ref in tech.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            "",
        )

        # Extract the primary tactic name
        tactic = next(
            (
                phase.get("phase_name", "").replace("-", " ").title()
                for phase in tech.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ),
            "",
        )

        if external_id:
            results.append({
                "id":             external_id,
                "name":           tech.get("name", ""),
                "tactic":         tactic,
                "mapping_source": "mitre_stix",
            })

        if len(results) >= limit:
            break

    return results


def _collect_stix_candidates(behaviors: list[dict]) -> tuple[list[dict], dict[str, set[str]]]:
    """
    Run STIX keyword searches for all matched indicators across all behaviors.

    FIX: Now also builds and returns a behavior_coverage index mapping each
    behavior's category to the set of ATT&CK technique IDs it produced.
    This index is reused later to identify uncovered behaviors without
    re-scanning the full STIX database a second time.

    Returns:
        candidates        : Flat list of candidate technique dicts
        behavior_coverage : {behavior_category: set(technique_ids)} index
    """
    candidates        = []
    behavior_coverage = {} 

    for behavior in behaviors:
        category       = behavior.get("category", "unknown")
        found_tech_ids = set()

        for indicator in behavior.get("matched_indicators", [])[:2]:
            stix_results = _search_mitre_stix(indicator, limit=2)
            for result in stix_results:
                # FIX: record which behavior generated this candidate
                result["source_behavior"] = category
                candidates.append(result)
                found_tech_ids.add(result["id"])

        behavior_coverage[category] = found_tech_ids

    return candidates, behavior_coverage


# =============================================================================
# PHASE 1b — LLM BATCH VALIDATION
# =============================================================================

_VALIDATION_PROMPT = """You are a MITRE ATT&CK Validator.

Review the observed behaviors and the candidate technique mappings.

REJECTION RULES:
- Reject mappings for administrative or benign activity (routine login, backup, system check).
- Reject mappings where the technique does not match the described behavior.

Return ONLY valid JSON — no markdown, no explanation:
{"validated_ids": ["T1234", "T1059.001"]}"""


def _llm_batch_verify(candidates: list[dict], behaviors: list[dict]) -> list[dict]:
    """
    Ask the LLM to validate STIX candidates and reject false positives.

    Provides the LLM with both the observed behaviors AND the candidate mappings
    so it can make an informed accept/reject decision for each technique.

    Falls back to the first 3 candidates if the LLM call fails or returns nothing,
    rather than returning empty results and losing all coverage.
    """
    if not candidates:
        return []

    context = {
        "observed_behaviors": [
            {"desc": b.get("description"), "cat": b.get("category")}
            for b in behaviors
        ],
        "potential_mappings": [
            {
                "id":              c["id"],
                "name":            c["name"],
                "source_behavior": c.get("source_behavior", "unknown"), 
            }
            for c in candidates
        ],
    }

    result        = llm_analyze(_VALIDATION_PROMPT, json.dumps(context))
    validated_ids = result.get("validated_ids", [])

    if not validated_ids:
        return candidates[:3]

    return [c for c in candidates if c["id"] in validated_ids]


# =============================================================================
# PHASE 2 — LLM CONTEXTUAL MAPPING (for uncovered behaviors)
# =============================================================================

_MAPPING_PROMPT = """You are a MITRE ATT&CK mapping expert.

Given a list of malicious behaviors that were NOT matched by the STIX database,
map each to the most relevant MITRE ATT&CK technique(s).

STRICT RULES:
- Only use REAL technique IDs from the MITRE ATT&CK framework.
- "Dumping memory"  → T1003 (OS Credential Dumping), NOT T1059 (PowerShell)
- "Keylogger"       → T1056.001 (Keylogging),         NOT T1059
- If you are less than 85% confident, omit the mapping entirely.
- Never guess.

Return ONLY valid JSON — no markdown, no explanation:
{
    "mappings": [
        {
            "behavior": "original behavior description",
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": "Credential Access",
            "confidence": 0.9
        }
    ]
}"""


def _llm_mapping(behaviors: list[dict]) -> list[dict]:
    """
    Ask the LLM to map behaviors that produced no STIX hits.

    Only called for behaviors where _collect_stix_candidates() found no
    technique candidates (or none survived LLM validation).

    Returns a list of technique dicts tagged with mapping_source="llm".
    """
    if not behaviors:
        return []

    descriptions = [
        f"- {b.get('category', 'unknown')}: {b.get('description', '')}"
        for b in behaviors
    ]
    content = "Behaviors to map:\n" + "\n".join(descriptions)
    result  = llm_analyze(_MAPPING_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return []

    return [
        {
            "id":              m.get("technique_id", ""),
            "name":            m.get("technique_name", ""),
            "tactic":          m.get("tactic", ""),
            "source_behavior": m.get("behavior", ""),
            "mapping_source":  "llm",
            "confidence":      m.get("confidence", 0.7),
        }
        for m in result.get("mappings", [])
        if m.get("technique_id")
    ]


# =============================================================================
# MERGE & DEDUPLICATION
# =============================================================================

def _merge_mappings(stix: list[dict], llm: list[dict]) -> list[dict]:
    """
    Merge STIX-validated and LLM-derived technique mappings.

    Deduplicates on technique ID. STIX results take priority — if both
    sources map to the same technique, the STIX entry is kept and its
    mapping_source field is updated to reflect both sources.
    """
    seen: dict[str, dict] = {}

    for mapping in stix + llm:
        tech_id = mapping.get("id", "")
        if not tech_id:
            continue

        if tech_id not in seen:
            seen[tech_id] = mapping
        else:
            # Both sources agree — record that for confidence downstream
            seen[tech_id]["mapping_source"] += f"+{mapping['mapping_source']}"

    return list(seen.values())


# =============================================================================
# LANGCHAIN TOOL ENTRY POINT
# =============================================================================

@tool
def map_to_mitre(behaviors: list[dict]) -> dict:
    """
    Map detected malicious behaviors to MITRE ATT&CK techniques.

    Phase 1: STIX keyword search → LLM validation (removes false positives).
    Phase 2: LLM contextual mapping for behaviors with no STIX coverage.
    Phase 3: Merge + deduplicate results from both phases.

    FIX: The uncovered-behavior detection now reuses the coverage index built
    during Phase 1 instead of re-running the full STIX scan a second time.

    Args:
        behaviors: List of behavior dicts from detect_behaviors tool

    Returns:
        {techniques, total_techniques, tactics_covered, coverage_summary}
    """
    if not behaviors:
        return {
            "techniques":       [],
            "total_techniques": 0,
            "error":            "No behaviors provided",
        }

    # --- PHASE 1: STIX CANDIDATE COLLECTION ---
    # FIX: _collect_stix_candidates now returns both the candidates AND the
    # behavior_coverage index, eliminating the need for a second STIX scan.
    stix_candidates, behavior_coverage = _collect_stix_candidates(behaviors)

    # --- PHASE 1b: LLM VALIDATION ---
    validated_stix  = _llm_batch_verify(stix_candidates, behaviors)
    covered_ids     = {c["id"] for c in validated_stix}

    # --- PHASE 2: LLM MAPPING FOR UNCOVERED BEHAVIORS ---
    # A behavior is "uncovered" if none of its STIX candidates survived validation.
    uncovered = [
        b for b in behaviors
        if not behavior_coverage.get(b.get("category", ""), set()).intersection(covered_ids)
    ]
    llm_results = _llm_mapping(uncovered)

    # --- PHASE 3: MERGE & REPORT ---
    techniques = _merge_mappings(validated_stix, llm_results)
    tactics    = sorted({t.get("tactic", "") for t in techniques if t.get("tactic")})

    return {
        "techniques":       techniques,
        "total_techniques": len(techniques),
        "tactics_covered":  tactics,
        "coverage_summary": (
            f"{len(techniques)} validated technique(s) across {len(tactics)} tactic(s)."
        ),
    }