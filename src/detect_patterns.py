"""
TOOL 3 — Pattern Detection (HYBRID)
=====================================
Analyzes a batch of CTI messages to identify dominant themes, statistical
anomalies, and semantic threat classifications.

Three layers:
  Layer 1 (Static)      : Frequency counting of known CTI vocabulary
  Layer 2 (Statistical) : Z-score anomaly detection + Shannon entropy
  Layer 3 (LLM)         : Semantic threat classification and emerging terms

No bugs were found in the original — this version adds English comments only.
"""

import re
import math
from collections import Counter
from langchain_core.tools import tool
from llm_helper import llm_analyze


CTI_SHORT_TOKENS = {
    "c2", "c&c", "ip", "vm", "av", "os", "id", "db", "xss", "sql",
    "rce", "lfi", "rfi", "poc", "apt", "rat", "bot", "dns", "tcp",
    "udp", "ssh", "rdp", "smb", "ftp", "vpn", "tor", "ioc", "ttps",
    "edr", "ids", "ips", "waf", "dll", "exe", "cmd", "ps1", "bat",
}


def _tokenize_smart(text: str) -> list[str]:
    """
    Tokenize text into meaningful terms for frequency analysis.

    Keeps compound tokens (e.g. 'cobalt.strike', 'c&c') and CTI short tokens.
    Discards short pure-digit sequences (port numbers, random IDs) that add noise.
    """
    raw_tokens = re.findall(r"[a-zA-Z0-9&][\w&.-]*", text.lower())

    filtered = []
    for token in raw_tokens:
        if token in CTI_SHORT_TOKENS:
            # Always keep known CTI abbreviations regardless of length
            filtered.append(token)
        elif token.isdigit() and len(token) < 4:
            # Skip short numeric strings (e.g. port "80", year "22")
            continue
        else:
            filtered.append(token)

    return filtered


# =============================================================================
# LAYER 1 — STATIC FREQUENCY ANALYSIS
# =============================================================================

CTI_TERMS_SEEDS = {
    "ransomware", "phishing", "exploit", "vulnerability", "cve",
    "botnet", "c2", "payload", "dropper", "loader", "stealer",
    "keylogger", "backdoor", "rootkit", "zero-day", "0day",
    "breach", "leak", "dump", "credentials", "brute", "ddos",
    "injection", "xss", "sqli", "rce", "privilege", "escalation",
    "lateral", "exfiltration", "encryption", "ransom", "bitcoin",
    "monero", "tor", "onion", "obfuscation", "persistence",
    "evasion", "sandbox", "rat", "apt", "campaign", "malware",
    "trojan", "worm", "spyware", "adware", "cryptominer",
}


def _static_frequency_analysis(tokens: list[str]) -> dict:
    """
    Count token frequencies and identify known CTI terms.

    Returns:
        word_counts    : Full Counter of all tokens
        top_keywords   : Top-30 tokens with CTI-term flag
        known_cti_terms: Sorted list of recognized CTI vocabulary hits
    """
    word_counts = Counter(tokens)
    top_30      = word_counts.most_common(30)

    top_keywords = [
        {
            "word":              word,
            "count":             count,
            "is_known_cti_term": word in CTI_TERMS_SEEDS,
        }
        for word, count in top_30
    ]

    # Sort known CTI terms by frequency (most frequent first)
    known_cti_found = sorted(
        [w for w in word_counts if w in CTI_TERMS_SEEDS],
        key=lambda w: word_counts[w],
        reverse=True,
    )

    return {
        "word_counts":     word_counts,
        "top_keywords":    top_keywords,
        "known_cti_terms": known_cti_found,
    }


# =============================================================================
# LAYER 2 — STATISTICAL ANOMALY DETECTION
# =============================================================================

def _statistical_anomaly_detection(word_counts: Counter) -> dict:
    """
    Detect statistically unusual tokens and measure vocabulary diversity.

    Methods:
      Z-score          : Flags tokens whose frequency is > 2 standard deviations
                         above the mean — strong signal of a dominant theme.
      Shannon entropy  : Low entropy → very repetitive (campaign/botnet).
                         High entropy → diverse vocabulary (mixed traffic/noise).
      Concentration    : % of total word mass in the top-10 tokens.
                         High concentration → dominant single theme.

    Returns:
        anomalies          : Up to 10 high-Z-score tokens with interpretation
        entropy            : Normalized Shannon entropy value
        diversity_ratio    : entropy / max_possible_entropy (0.0–1.0)
        concentration_ratio: Share of vocabulary in top-10 tokens
        stats              : Raw statistical parameters
        interpretation     : Human-readable summary
    """
    if not word_counts:
        return {"anomalies": [], "entropy": 0, "concentration_ratio": 0}

    counts = list(word_counts.values())
    total  = sum(counts)
    n      = len(counts)

    # Compute mean and standard deviation for Z-score
    mean     = total / n
    variance = sum((c - mean) ** 2 for c in counts) / n
    std_dev  = math.sqrt(variance) if variance > 0 else 1  # avoid division by zero

    # Flag tokens with Z-score > 2 (statistically unusual frequency)
    anomalies = []
    for word, count in word_counts.items():
        z_score = (count - mean) / std_dev
        if z_score > 2.0:
            anomalies.append({
                "word":           word,
                "count":          count,
                "z_score":        round(z_score, 2),
                "interpretation": (
                    f"'{word}' appears {count}x "
                    f"(mean={mean:.1f}, z={z_score:.1f}) "
                    f"— abnormally high frequency"
                ),
            })
    anomalies.sort(key=lambda a: a["z_score"], reverse=True)

    # Shannon entropy: H = -∑ p(x) log2(p(x))
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    max_entropy     = math.log2(n) if n > 1 else 0
    diversity_ratio = entropy / max_entropy if max_entropy > 0 else 0

    # Concentration: what fraction of total tokens are the top-10?
    top_10_sum  = sum(count for _, count in word_counts.most_common(10))
    concentration = top_10_sum / total if total > 0 else 0

    return {
        "anomalies":          anomalies[:10],
        "entropy":            round(entropy, 3),
        "max_entropy":        round(max_entropy, 3),
        "diversity_ratio":    round(diversity_ratio, 3),
        "concentration_ratio": round(concentration, 3),
        "stats": {
            "mean_frequency": round(mean, 2),
            "std_deviation":  round(std_dev, 2),
            "unique_tokens":  n,
            "total_tokens":   total,
        },
        "interpretation": _interpret_stats(diversity_ratio, concentration),
    }


def _interpret_stats(diversity: float, concentration: float) -> str:
    """Generate a human-readable interpretation of the statistical metrics."""
    parts = []

    if diversity < 0.3:
        parts.append(
            "Very concentrated vocabulary → likely targeted campaign "
            "or highly similar messages (spam/botnet pattern)"
        )
    elif diversity < 0.6:
        parts.append(
            "Moderately diverse vocabulary → possible themed messages "
            "related to the same actor or technique"
        )
    else:
        parts.append(
            "Very diverse vocabulary → varied messages, "
            "no obvious dominant campaign or theme"
        )

    if concentration > 0.5:
        parts.append(
            f"The top-10 most frequent words represent "
            f"{concentration:.0%} of total tokens → strong dominant theme"
        )

    return " | ".join(parts)


# =============================================================================
# LAYER 3 — LLM SEMANTIC CLASSIFICATION
# =============================================================================

LLM_PATTERN_PROMPT = """You are a literal-minded Cyber Threat Intelligence (CTI) Auditor.

### CRITICAL NEUTRALITY MANDATE:
You must distinguish between routine IT work and actual cyber attacks.
- Do NOT search for 'hidden' malicious meanings in standard corporate English.
- Words like 'view', 'scheduled', 'new', 'update', or 'internal' are NOT suspicious alone.
- If the text describes a scheduled reboot, a patch, or an HR portal, it is NOT an attack.

### CLASSIFICATION CATEGORIES (Choose EXACTLY ONE):
1. BENIGN: Internal company news, holiday calendars, general greetings, or HR links.
2. ADMINISTRATIVE: Scheduled reboots, system patching, IT maintenance, or routine tickets.
3. MALICIOUS: ONLY if there is explicit evidence of C2, Exploit payloads, Ransomware,
   or Unauthorized Data Leaks.

### YOUR TASKS:
1. CLASSIFY the primary theme using the categories above.
2. If BENIGN or ADMINISTRATIVE: Set 'is_malicious' to false, 'confidence' to 1.0,
   and 'predicted_next_steps' to ['None' or 'Routine Maintenance'].
3. If MALICIOUS: Identify specific patterns and predict the attacker's next steps.

STRICT JSON SCHEMA — use exact keys 'keywords' and 'attack_pattern'
inside 'correlated_patterns'. Do not use 'pattern' or 'description'.

Return ONLY valid JSON:
{
    "threat_classification": "BENIGN | ADMINISTRATIVE | RANSOMWARE | PHISHING | APT | etc.",
    "is_malicious": false,
    "confidence": 1.0,
    "emerging_terms": [],
    "correlated_patterns": [],
    "predicted_next_steps": ["Step 1", "Step 2"],
    "flagged_jargon": [],
    "semantic_summary": "Literal explanation. If safe, state why."
}"""


def _llm_pattern_analysis(
    top_keywords:    list[dict],
    anomalies:       list[dict],
    sample_messages: list[str],
) -> dict:
    """
    Ask the LLM to semantically classify the dominant threat pattern.

    Provides the LLM with:
      - Top-20 keywords by frequency
      - Statistical anomalies
      - First 3 sample messages (up to 300 chars each)

    Returns the parsed LLM response, or a safe fallback on failure.
    """
    context_parts = [
        "## Top Keywords (by frequency):",
        *[f"  - {kw['word']}: {kw['count']}x" for kw in top_keywords[:20]],
        "",
        "## Statistical Anomalies:",
        *[f"  - {a['interpretation']}" for a in anomalies[:5]],
        "",
        "## Sample Messages (first 3):",
        *[f"  ---\n  {msg[:300]}" for msg in sample_messages[:3]],
    ]
    context = "\n".join(context_parts)
    result  = llm_analyze(LLM_PATTERN_PROMPT, context)

    # Return a neutral fallback if the LLM call or JSON parsing failed
    if "llm_failed" in result or "parse_error" in result:
        return {
            "threat_classification": "unknown",
            "confidence":            0.0,
            "emerging_terms":        [],
            "correlated_patterns":   [],
            "predicted_next_steps":  [],
            "semantic_summary":      "LLM analysis unavailable",
        }

    return result


# =============================================================================
# LANGCHAIN TOOL ENTRY POINT
# =============================================================================

@tool
def detect_patterns(messages: list[str]) -> dict:
    """
    Hybrid pattern analysis across a batch of CTI messages.

    Layer 1 (Static)      : Known CTI term frequencies
    Layer 2 (Statistical) : Z-score anomaly detection + entropy measurement
    Layer 3 (LLM)         : Semantic threat classification and emerging term detection

    Args:
        messages: List of raw CTI message strings to analyze together

    Returns:
        Combined analysis with token statistics, anomalies, and LLM classification
    """
    if not messages:
        return {"error": "No messages provided for analysis."}

    # Step 1: Tokenize all messages together into one corpus
    all_tokens = []
    for msg in messages:
        all_tokens.extend(_tokenize_smart(msg))

    # Step 2: Layer 1 — static frequency analysis
    static = _static_frequency_analysis(all_tokens)

    # Step 3: Layer 2 — statistical anomaly detection
    stats = _statistical_anomaly_detection(static["word_counts"])

    # Step 4: Layer 3 — LLM semantic classification
    llm_analysis = _llm_pattern_analysis(
        top_keywords    = static["top_keywords"],
        anomalies       = stats["anomalies"],
        sample_messages = messages,
    )

    # -------------------------------------------------------------------------
    # SAFETY GATE
    # The LLM can over-classify benign content as MALICIOUS.
    # We only trust a MALICIOUS verdict if there is hard evidence
    # (known CTI terms found) OR at least a statistical anomaly.
    # -------------------------------------------------------------------------
    has_hard_evidence       = len(static["known_cti_terms"]) > 0
    has_statistical_anomaly = len(stats["anomalies"]) > 0
    has_evidence            = has_hard_evidence or has_statistical_anomaly

    classification = llm_analysis.get("threat_classification", "UNKNOWN")
    confidence     = llm_analysis.get("confidence", 0.0)
    is_malicious   = llm_analysis.get("is_malicious", False)

    if not has_hard_evidence and classification == "MALICIOUS":
        if has_statistical_anomaly:
            # Downgrade: statistical signal but no confirmed CTI terms
            classification = "POTENTIALLY SUSPICIOUS (Unconfirmed)"
            confidence    *= 0.7
        else:
            # No evidence at all — override the LLM verdict
            classification = "BENIGN / INFORMATIONAL (No Evidence)"
            confidence    *= 0.5
            is_malicious   = False

    # Only mark as malicious if we have at least some corroborating evidence
    final_is_malicious = is_malicious if has_evidence else False

    return {
        "total_messages": len(messages),
        "is_malicious":   final_is_malicious,
        "unique_tokens":  stats["stats"]["unique_tokens"],

        # Layer 1 results
        "top_keywords":    static["top_keywords"],
        "known_cti_terms": static["known_cti_terms"],

        # Layer 2 results
        "statistical_anomalies": stats["anomalies"],
        "entropy":               stats["entropy"],
        "diversity_ratio":       stats["diversity_ratio"],
        "concentration_ratio":   stats["concentration_ratio"],
        "stats_interpretation":  stats["interpretation"],

        # Layer 3 results
        "threat_classification":     classification,
        "classification_confidence": round(confidence, 2),
        "emerging_terms":            llm_analysis.get("emerging_terms", []),
        "correlated_patterns":       llm_analysis.get("correlated_patterns", []),
        "predicted_next_steps":      llm_analysis.get("predicted_next_steps", []),
        "flagged_jargon":            llm_analysis.get("flagged_jargon", []),
        "semantic_summary":          llm_analysis.get("semantic_summary", ""),
    }
