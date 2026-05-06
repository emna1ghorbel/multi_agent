"""
TOOL 4 — Dynamic Behavior Detection (HYBRID)
=============================================
Detects malicious behaviors in raw CTI text using three layers:
  Layer 1 (Static)  : Regex signatures for known MITRE ATT&CK techniques
  Layer 2 (LLM)     : Contextual detection of novel or implied techniques
  Layer 3 (Scoring) : Weighted merge with confidence thresholding

FIXES vs original:
  1. SEVERITY_SCORES was defined twice (module level + inside detect_behaviors()).
     The duplicate inside the function has been removed.
  2. LLM_CATEGORY_MAP was rebuilt on every _merge_behaviors() call.
     Moved to module level as a constant.
  3. filtered_merged intermediate variable simplified — merged directly.
"""

import re
from langchain_core.tools import tool
from llm_helper import llm_analyze
from config import WEIGHTS


# =============================================================================
# LAYER 1 — STATIC BEHAVIOR SIGNATURES (Regex)
# =============================================================================

BEHAVIOR_SIGNATURES = {
    "process_creation": {
        "description": "Suspicious process creation or injection",
        "patterns": [
            r"(?i)process\s*(creation|injection|hollowing)",
            r"(?i)(spawn|execute|launch|run)\s*(cmd|powershell|wscript|mshta|rundll)",
            r"(?i)(CreateProcess|NtCreateThread|WriteProcessMemory)",
            r"(?i)shellcode\s*(inject|execution|load)",
            r"(?i)(?:cmd|powershell|bash)\.exe",
            r"(?i)invoke[- ]expression",
        ],
        "severity": "high",
    },
    "registry_modification": {
        "description": "Windows registry modification for persistence",
        "patterns": [
            r"(?i)reg(istry)?\s*(key|value|modif|add|set|delete|write)",
            r"(?i)(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)",
            r"(?i)\\CurrentVersion\\Run",
            r"(?i)(autorun|startup|persistence)\s*(registry|reg)",
        ],
        "severity": "high",
    },
    "network_communication": {
        "description": "Suspicious network communications (C2, data exfiltration)",
        "patterns": [
            r"(?i)(c2|c&c|command\s*and\s*control)\s*(server|communication|beacon)",
            r"(?i)(beacon|callback|phone\s*home|heartbeat)",
            r"(?i)(exfiltrat|data\s*theft|upload\s*stolen)",
            r"(?i)(reverse\s*shell|bind\s*shell|netcat)",
            r"(?i)tor\s*(network|proxy|hidden|onion)",
        ],
        "severity": "critical",
    },
    "file_system_activity": {
        "description": "Suspicious file activity (encryption, deletion)",
        "patterns": [
            r"(?i)(encrypt|decrypt|cipher)\s*(file|document|data)",
            r"(?i)(ransom\s*note|\.locked|\.encrypted|\.crypt)",
            r"(?i)(drop|write|create)\s*(file|payload|executable|dll)",
            r"(?i)(delete|wipe|shred)\s*(log|shadow|backup)",
            r"(?i)vssadmin\s*delete\s*shadows",
        ],
        "severity": "high",
    },
    "credential_access": {
        "description": "Theft or access of credentials",
        "patterns": [
            r"(?i)(steal|dump|harvest|extract)\s*(credential|password|token|cookie)",
            r"(?i)(mimikatz|lsass\s*dump|hashdump|sam\s*dump)",
            r"(?i)(keylog|keystroke|clipboard)",
            r"(?i)(brute\s*force|password\s*spray|credential\s*stuff)",
        ],
        "severity": "critical",
    },
    "defense_evasion": {
        "description": "Evasion and anti-analysis techniques",
        "patterns": [
            r"(?i)(obfuscat|pack|crypt|encod)\s*(code|payload|script|binary)",
            r"(?i)(anti[- ]?(debug|vm|sandbox|analysis))",
            r"(?i)(disable|bypass|tamper)\s*(antivirus|defender|edr|amsi)",
            r"(?i)(fileless|living\s*off\s*the\s*land|lolbin)",
        ],
        "severity": "medium",
    },
}


# =============================================================================
# MODULE-LEVEL CONSTANTS (FIX: moved out of functions to avoid re-creation)
# =============================================================================


SEVERITY_SCORES = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "none":     0,
}

LLM_CATEGORY_MAP = {
    "process manipulation":   "process_creation",
    "persistence mechanisms": "registry_modification",
    "network activity":       "network_communication",
    "file system operations": "file_system_activity",
    "defense evasion":        "defense_evasion",
    "discovery":              "discovery",
    "lateral movement":       "lateral_movement",
    "impact":                 "file_system_activity",
}

ALERT_THRESHOLD = 0.5


# =============================================================================
# LAYER 1 — STATIC REGEX DETECTION
# =============================================================================

def _static_behavior_detection(text: str) -> list[dict]:
    """
    Scan the text with all BEHAVIOR_SIGNATURES regex patterns.

    For each matching category, records up to 10 matched indicator strings.
    Static matches are assigned a high base confidence (0.95) because regex
    patterns require an exact or near-exact textual match.

    Returns:
        List of detected behavior dicts, each with category, severity,
        matched indicators, and detection metadata.
    """
    behaviors = []

    for category, config in BEHAVIOR_SIGNATURES.items():
        matched = []
        for pattern in config["patterns"]:
            matches = re.findall(pattern, text)
            if matches:
                for m in matches:
                    indicator = m if isinstance(m, str) else m[0]
                    if indicator and indicator not in matched:
                        matched.append(indicator)

        if matched:
            behaviors.append({
                "category":          category,
                "description":       config["description"],
                "severity":          config["severity"],
                "matched_indicators": matched[:10],  # cap at 10 to avoid overload
                "match_count":       len(matched),
                "detection_source":  "static_regex",
                "confidence":        0.95,           # high confidence for exact regex match
            })

    return behaviors


# =============================================================================
# LAYER 2 — LLM BEHAVIOR DETECTION
# =============================================================================

LLM_BEHAVIOR_PROMPT = """You are a literal-minded Malware Behavior Analyst.

### CRITICAL NEUTRALITY MANDATE:
- Do NOT search for hidden malicious intent in routine IT tasks.
- Routine reboots, patching, or HR links are NOT "Persistence" or "Phishing".
- If the text describes legitimate activity, return an EMPTY behaviors list.

### TASK:
Analyze the message and identify explicit malicious behaviors from categories such as:
1. Process manipulation (injection, hollowing)
2. Persistence (registry, scheduled tasks)
3. Network activity (C2, tunneling)
4. File system operations (encryption, dropper)
5. Credential theft (dumping, keylogging)
6. Defense evasion (obfuscation, AV bypass)
7. Discovery (recon, enumeration)
8. Lateral movement (pass-the-hash, RDP abuse)

Return ONLY valid JSON:
{
    "behaviors": [
        {
            "category": "category_name",
            "description": "Literal description of what was observed",
            "severity": "critical|high|medium|low",
            "confidence": 0.0,
            "indicators": ["excerpt from text"],
            "is_novel": false,
            "notes": "Additional context"
        }
    ],
    "attack_chain_summary": "Brief narrative connecting the behaviors",
    "novel_techniques": ["Description of any never-seen-before techniques"]
}"""


def _llm_behavior_detection(text: str) -> dict:
    """
    Ask the LLM to identify malicious behaviors that regex patterns may miss.

    Returns the parsed LLM result, or a safe empty fallback on failure.
    """
    result = llm_analyze(LLM_BEHAVIOR_PROMPT, text)

    if result.get("llm_failed") or result.get("parse_error"):
        return {
            "behaviors":             [],
            "attack_chain_summary":  "",
            "novel_techniques":      [],
        }

    return result


# =============================================================================
# LAYER 3 — MERGE AND SCORE
# =============================================================================

def _merge_behaviors(
    static_behaviors: list[dict],
    llm_result:       dict,
) -> list[dict]:
    """
    Merge behaviors detected by static regex and LLM into a unified list.

    Merge strategy:
    - Both layers agree on a category  → boost confidence (+0.05), mark "static+llm"
    - Only static detected it          → keep as-is at 0.95 confidence
    - Only LLM detected it             → include if weighted confidence >= ALERT_THRESHOLD
    - Novel LLM behaviors              → flagged with is_novel=True for reporting

    LLM category names are normalized via LLM_CATEGORY_MAP before comparison.
    """
    merged = []
    static_categories = {b["category"] for b in static_behaviors}
    llm_behaviors     = llm_result.get("behaviors", [])

    # --- Process static behaviors first ---
    for sb in static_behaviors:
        cat = sb["category"]

        # Check if the LLM also detected this same category
        llm_match = next(
            (lb for lb in llm_behaviors if lb.get("category") == cat),
            None,
        )

        if llm_match:
            # Both layers agree → boost confidence and enrich indicators
            sb["confidence"]       = min(0.99, sb["confidence"] + 0.05)
            sb["detection_source"] = "static+llm"
            sb["llm_notes"]        = llm_match.get("notes", "")

            # Merge LLM indicators without duplicating existing ones
            llm_indicators        = llm_match.get("indicators", [])
            combined_indicators   = sb["matched_indicators"] + [
                i for i in llm_indicators if i not in sb["matched_indicators"]
            ]
            sb["matched_indicators"] = combined_indicators[:15]

        merged.append(sb)

    # --- Process LLM-only behaviors ---
    for lb in llm_behaviors:
        raw_cat   = lb.get("category", "unknown").lower()
        # Normalize to a canonical category key using the module-level map
        cat       = LLM_CATEGORY_MAP.get(raw_cat, raw_cat)
        lb["category"] = cat

        # Only add if this category was NOT already found by static regex
        if cat not in static_categories:
            merged.append({
                "category":          cat,
                "description":       lb.get("description", ""),
                "severity":          lb.get("severity", "medium"),
                "confidence":        lb.get("confidence", 0.7) * WEIGHTS["llm"],
                "matched_indicators": lb.get("indicators", []),
                "match_count":       len(lb.get("indicators", [])),
                "detection_source":  "llm_only",
                "is_novel":          lb.get("is_novel", False),
                "llm_notes":         lb.get("notes", ""),
            })

    # Sort by severity then confidence (highest first)
    merged.sort(
        key=lambda b: (
            SEVERITY_SCORES.get(b["severity"], 0),
            b.get("confidence", 0),
        ),
        reverse=True,
    )

    return merged


# =============================================================================
# LANGCHAIN TOOL ENTRY POINT
# =============================================================================

@tool
def detect_behaviors(message: str) -> dict:
    """
    Hybrid detection of malicious behaviors in a single CTI message.

    Layer 1 (Static)  : Regex signatures for known ATT&CK techniques
    Layer 2 (LLM)     : Contextual analysis for novel or implied techniques
    Layer 3 (Scoring) : Confidence-weighted merge with safety gate

    Safety Gate Logic:
    - Static regex detections are always included (high confidence).
    - LLM-only detections are included only if their weighted confidence
      is >= ALERT_THRESHOLD (0.5) to suppress hallucinations.

    Args:
        message: Raw text describing a threat or malware behavior

    Returns:
        Complete behavioral analysis with source attribution and severity
    """
    static_behaviors = _static_behavior_detection(message)
    llm_result       = _llm_behavior_detection(message)
    merged           = _merge_behaviors(static_behaviors, llm_result)

    # -------------------------------------------------------------------------
    # SAFETY GATE — filter out low-confidence LLM-only detections
    # A behavior passes if:
    #   A) Static regex found it (high certainty, no threshold needed)
    #   B) Both static AND LLM confirmed it (verified by two sources)
    #   C) LLM found it alone but weighted confidence >= ALERT_THRESHOLD
    # -------------------------------------------------------------------------
    merged = [
        b for b in merged
        if b.get("detection_source") in ("static_regex", "static+llm")
        or b.get("confidence", 0) >= ALERT_THRESHOLD
    ]

    # Determine the most severe behavior detected
    max_severity = "none"
    if merged:
        max_severity = max(
            merged,
            key=lambda b: SEVERITY_SCORES.get(b["severity"], 0),
        )["severity"]

    # Count detections per source type for the summary
    source_counts = {
        "static_regex":   sum(1 for b in merged if b["detection_source"] == "static_regex"),
        "static_plus_llm": sum(1 for b in merged if b["detection_source"] == "static+llm"),
        "llm_only":       sum(1 for b in merged if b["detection_source"] == "llm_only"),
    }

    # Collect novel techniques for the report
    novel = [b for b in merged if b.get("is_novel")]

    # Build a human-readable behavior summary
    summary_parts = [f"{len(merged)} behavior(s) detected."]
    if source_counts["llm_only"] > 0:
        summary_parts.append(
            f"{source_counts['llm_only']} detected ONLY by LLM "
            f"(not covered by static signatures)."
        )
    if novel:
        summary_parts.append(
            f"{len(novel)} potentially novel technique(s) identified."
        )
    summary_parts.append(f"Max severity: {max_severity}.")

    return {
        "behaviors_detected": merged,
        "total_behaviors":    len(merged),
        "max_severity":       max_severity,
        "detection_sources":  source_counts,
        "novel_techniques":   llm_result.get("novel_techniques", []),
        "attack_chain":       llm_result.get("attack_chain_summary", ""),
        "behavior_summary":   " ".join(summary_parts),
    }
