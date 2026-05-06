"""
CTI ANALYSIS AGENT — Entry Point
==================================
Orchestrates the four CTI tools in sequence, then synthesizes their outputs
into a structured threat_brief that the MITRE Agent can consume directly.

Pipeline:
  raw message
    → [extract_entities]  → IOCs and named threat entities
    → [detect_behaviors]  → malicious behavior signatures
    → [detect_patterns]   → statistical + semantic classification
    → [rag_search]        → similar historical CTI messages
    → [build_threat_brief] → narrative synthesis + noise filtering
    → threat_brief         → ready for MITRE Agent

No bugs were found in the original — this version adds English comments only.
"""

import json
from langsmith import traceable

from extract_entities import extract_entities
from detect_behaviors import detect_behaviors
from detect_patterns  import detect_patterns
from rag_search       import rag_search
from threat_brief     import build_threat_brief


@traceable(name="CTI Analysis — analyze_message")
def analyze_message(message: str) -> dict:
    """
    Analyze a raw CTI message and return a structured, contextualized threat brief.

    The threat_brief["mitre_input"] is the only field the MITRE Agent needs:
      - Contextualized behaviors (not raw IOCs)
      - Target environment (OS, sector, infrastructure criticality)
      - Actor profile (APT, opportunistic, or unknown)
      - Inferred kill chain stages

    Args:
        message: Raw text from a CTI source (Telegram, web scrape, report, etc.)

    Returns:
        dict with "threat_brief" (for MITRE Agent) + raw tool outputs (for debug/audit)
    """

    # ------------------------------------------------------------------
    # STEPS 1–4: Run the four CTI tools sequentially.
    # Each tool's output can inform downstream tools — behaviors feed the
    # pattern engine, patterns feed the synthesizer, etc.
    # ------------------------------------------------------------------

    print("[Step 1/5] Extracting entities (IOCs, malware, actors)...")
    entities = extract_entities.invoke({"message": message})

    print("[Step 2/5] Detecting malicious behaviors...")
    behaviors_result = detect_behaviors.invoke({"message": message})
    behaviors        = behaviors_result.get("behaviors_detected", [])

    print("[Step 3/5] Detecting patterns and classifying threat...")
    patterns_result = detect_patterns.invoke({"messages": [message]})

    print("[Step 4/5] Searching RAG database for similar threats...")
    rag_raw    = rag_search.invoke({"query": message[:300]})  # truncate long messages for vector search
    rag_result = json.loads(rag_raw) if isinstance(rag_raw, str) else rag_raw

    # ------------------------------------------------------------------
    # STEP 5: Synthesize — build the narrative and filter noise before
    # passing anything to the MITRE Agent.
    # ------------------------------------------------------------------

    print("[Step 5/5] Building threat brief (synthesizer)...")
    brief = build_threat_brief(
        entities    = entities,
        behaviors   = behaviors,
        patterns    = patterns_result,
        rag_context = rag_result,
    )

    print(
        f"[✓] CTI Analysis complete. "
        f"Network IOCs: {brief['ioc_count_network_raw']} | "
        f"Named entities: {brief['ioc_count_entities_raw']} | "
        f"MITRE-relevant: {brief['ioc_count_for_mitre']}"
    )

    # ------------------------------------------------------------------
    # ASSEMBLE FINAL RESULT
    # ------------------------------------------------------------------
    result = {
        "status": "success",

        # ── For the MITRE Agent ─────────────────────────────────────
        # Pass threat_brief["mitre_input"] — not raw entities
        "threat_brief": brief,

        # ── Backward compatibility (other components may read these) ─
        "entities":    entities,
        "behaviors":   behaviors,
        "rag_context": {
            "num_results": len(rag_result.get("results", [])),
            "results":     rag_result.get("results", []),
        },
        "patterns": {
            "threat_classification": patterns_result.get("threat_classification", ""),
            "emerging_terms":        patterns_result.get("emerging_terms", []),
            "semantic_summary":      patterns_result.get("semantic_summary", ""),
            "predicted_next_steps":  patterns_result.get("predicted_next_steps", []),
            "is_malicious":          patterns_result.get("is_malicious", False),
        },

        # ── Full tool outputs for debugging and auditing ─────────────
        "behaviors_full": behaviors_result,
        "patterns_full":  patterns_result,
    }

    # ------------------------------------------------------------------
    # RAGAS EVALUATION (fire-and-forget — runs after result is prepared
    # so it never blocks the main pipeline even if it fails)
    # ------------------------------------------------------------------
    try:
        from ragas_worker import submit_for_evaluation
        # thread_id injecté par graph.py → seul le thread cible est évalué
        _thread_id = result.get("_thread_id", "")
        submit_for_evaluation(
            job_id     = f"cti-{abs(hash(message)) % 100000}",
            cti_result = result,
            message    = message,
            thread_id  = _thread_id,
        )
    except Exception as e:
        print(f"[RAGAS] Evaluation submission skipped: {e}")

    return result
