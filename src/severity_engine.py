"""
TOOL 2 (MITRE Layer) — Severity Engine
========================================
Calculates risk severity scores for MITRE ATT&CK techniques.

Two-phase architecture:
  Phase 1 (LLM): Score each technique individually on four axes.
  Phase 2 (LLM): Evaluate the full set for attack-chain coherence and award
                 a bonus (0.0–0.5) when a multi-stage kill-chain is confirmed.

Scoring axes (each 1.0–5.0):
  Impact         (35%) : Damage potential if the technique succeeds
  Exploitability (25%) : Ease of use in the wild (tooling, skill required)
  Prevalence     (20%) : How frequently observed in real threat actor activity
  Stealth        (20%) : Difficulty for defenders to detect
"""

from langchain_core.tools import tool
from llm_helper import llm_analyze


# =============================================================================
# SCORING WEIGHTS — must sum to 1.0
# =============================================================================

W_IMPACT     = 0.35
W_EXPLOIT    = 0.25
W_PREVALENCE = 0.20
W_STEALTH    = 0.20


def _compute_score(impact: float, exploit: float, prevalence: float, stealth: float) -> float:
    """
    Weighted severity score clamped to [0.0, 5.0].

    With valid 1.0–5.0 inputs and weights summing to 1.0, the natural output
    is [1.0, 5.0]. The clamp guards against malformed LLM responses (e.g. 0 or 6).
    """
    raw = W_IMPACT * impact + W_EXPLOIT * exploit + W_PREVALENCE * prevalence + W_STEALTH * stealth
    return round(min(5.0, max(0.0, raw)), 2)


def _classify(score: float) -> str:
    """Map a numeric severity score to a human-readable severity level."""
    if score >= 4.0:
        return "Critical"
    if score >= 3.0:
        return "High"
    if score >= 2.0:
        return "Medium"
    return "Low"


# =============================================================================
# PHASE 1 — LLM PER-TECHNIQUE SCORING
# =============================================================================

_SCORING_PROMPT = """You are an autonomous Cyber Risk Scoring Engine.

For each MITRE ATT&CK technique provided, assign scores on four axes
based on real-world threat intelligence — NOT generic defaults.

You will also receive environment context (target OS, sector, infrastructure
criticality, actor maturity). Use it to calibrate scores:
- Same technique scores HIGHER on critical infrastructure than on an isolated workstation.
- APT-level actor → boost stealth and exploitability.
- Opportunistic actor → reduce stealth, reduce prevalence for advanced techniques.

Axes (all 1.0 – 5.0, one decimal):
  imp : Impact         — damage potential if the technique succeeds
  exp : Exploitability — ease of execution / tooling availability in the wild
  pre : Prevalence     — frequency of observed use by threat actors
  ste : Stealth        — difficulty of detection by defenders

RULES:
- Score every technique individually. Do NOT group by tactic.
- Base scores on the specific sub-technique, not the parent tactic.
- If you are unsure, use 2.5 as a neutral mid-point rather than guessing high.
- Return ONLY valid JSON — no markdown, no explanation.

{
  "scores": [
    {
      "id":    "T1003.001",
      "imp":   4.5,
      "exp":   3.5,
      "pre":   4.0,
      "ste":   3.0,
      "reason": "LSASS dumping is trivial with Mimikatz and yields high-value credentials"
    }
  ]
}"""


def _llm_score_techniques(techniques: list[dict], env_context: dict) -> dict[str, dict]:
    """
    Ask the LLM to score every technique individually, calibrated to env_context.

    env_context keys used: target_os, target_sector, infrastructure_criticality,
    actor_maturity (injected by mitre_agent before calling calculate_severity).

    Returns a dict keyed by technique ID for O(1) lookup.
    Returns an empty dict if the LLM call fails.
    """
    env_lines = [
        f"  target_os:                 {env_context.get('target_os', 'unknown')}",
        f"  target_sector:             {', '.join(env_context.get('target_sector', [])) or 'unknown'}",
        f"  infrastructure_criticality:{env_context.get('infrastructure_criticality', 'unknown')}",
        f"  actor_maturity:            {env_context.get('actor_maturity', 'unknown')}",
    ]

    tech_lines = "\n".join(
        f"- {t.get('id')} | {t.get('name')} | tactic: {t.get('tactic', 'unknown')}"
        for t in techniques
    )

    content = (
        "Environment context:\n" + "\n".join(env_lines)
        + "\n\nTechniques to score:\n" + tech_lines
    )

    result = llm_analyze(_SCORING_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return {}

    return {
        entry["id"]: entry
        for entry in result.get("scores", [])
        if entry.get("id")
    }


# =============================================================================
# PHASE 2 — LLM ATTACK CHAIN BONUS
# =============================================================================

_CHAIN_PROMPT = """You are a MITRE ATT&CK attack-chain analyst.

Given a set of techniques observed together, assess whether they form
a coherent, multi-stage attack chain that amplifies overall risk.

RULES:
- Only award a bonus when the techniques form a logical, multi-stage sequence.
- bonus = 0.0 for isolated or unrelated techniques.
- bonus range: 0.0 (none) – 0.5 (full kill-chain confirmed).
- Return ONLY valid JSON — no markdown, no explanation.

{"bonus": 0.3, "reason": "Credential dumping followed by lateral movement and ransomware deployment."}"""


def _llm_chain_bonus(techniques: list[dict]) -> tuple[float, str]:
    """
    Evaluate whether the observed techniques form a cohesive attack chain.

    A chain bonus (0.0–0.5) is added to each LLM-scored technique's final score
    when the techniques collectively demonstrate multi-stage attacker behavior.

    Returns:
        (bonus, reasoning) — bonus is 0.0 if chain analysis fails
    """
    content = "Observed techniques:\n" + "\n".join(
        f"- {t.get('id')} {t.get('name')} ({t.get('tactic', '')})"
        for t in techniques
    )

    result = llm_analyze(_CHAIN_PROMPT, content)

    if result.get("llm_failed") or result.get("parse_error"):
        return 0.0, "Chain analysis unavailable."

    bonus  = min(0.5, float(result.get("bonus", 0.0)))
    reason = result.get("reason", "")
    return bonus, reason


# =============================================================================
# LANGCHAIN TOOL ENTRY POINT
# =============================================================================

@tool
def calculate_severity(techniques: list[dict]) -> dict:
    """
    Calculate risk severity for a list of MITRE ATT&CK techniques.

    Phase 1: LLM scores each technique on four axes (impact, exploitability,
             prevalence, stealth), calibrated to the environment context injected
             by mitre_agent (target_os, sector, infrastructure_criticality,
             actor_maturity). Produces a weighted score in [0.0, 5.0].
    Phase 2: LLM evaluates the full set for attack-chain coherence and applies
             a bonus (0.0–0.5) when a multi-stage kill-chain is confirmed.

    Args:
        techniques: List of technique dicts (id, name, tactic) — each may carry
                    an `environment_context` dict injected by mitre_agent.py.

    Returns:
        {scored_techniques, global_severity_score, global_severity_level,
         chain_bonus_applied, overall_reasoning, unscored_techniques}
    """
    if not techniques:
        return {"error": "No techniques provided"}

    # Pull shared env_context from the first technique (all share the same context)
    env_context = techniques[0].get("environment_context", {}) if techniques else {}

    # --- PHASE 1: PER-TECHNIQUE SCORING (env-calibrated) ---
    score_map    = _llm_score_techniques(techniques, env_context)
    scored       = []
    unscored_ids = []

    for tech in techniques:
        tech_id = tech.get("id", "")
        entry   = score_map.get(tech_id)

        if entry:
            imp   = entry.get("imp", 2.5)
            exp   = entry.get("exp", 2.5)
            pre   = entry.get("pre", 2.5)
            ste   = entry.get("ste", 2.5)
            score = _compute_score(imp, exp, pre, ste)

            scored.append({
                **tech,
                "severity_details": {
                    "impact":         imp,
                    "exploitability": exp,
                    "prevalence":     pre,
                    "stealth":        ste,
                },
                "severity_score": score,
                "severity_level": _classify(score),
                "llm_reasoning":  entry.get("reason", ""),
                "scoring_source": "llm",
            })
        else:
            # LLM did not return a score for this technique — flag explicitly
            unscored_ids.append(tech_id)
            scored.append({
                **tech,
                "severity_score": None,
                "severity_level": "Unknown",
                "llm_reasoning":  "No LLM score returned for this technique.",
                "scoring_source": "none",
            })

    # --- PHASE 2: ATTACK CHAIN BONUS ---
    # Apply bonus only to techniques that were actually LLM-scored.
    chain_bonus, chain_reason = _llm_chain_bonus(techniques)

    if chain_bonus > 0:
        for item in scored:
            if item["scoring_source"] == "llm":
                item["severity_score"] = round(min(5.0, item["severity_score"] + chain_bonus), 2)
                item["severity_level"] = _classify(item["severity_score"])

    # --- GLOBAL SCORE: maximum individual score ---
    valid_scores = [s["severity_score"] for s in scored if s["severity_score"] is not None]
    global_score = round(max(valid_scores), 2) if valid_scores else 0.0

    return {
        "scored_techniques":     scored,
        "global_severity_score": global_score,
        "global_severity_level": _classify(global_score),
        "chain_bonus_applied":   chain_bonus,
        "overall_reasoning":     chain_reason,
        "unscored_techniques":   unscored_ids,
    }
