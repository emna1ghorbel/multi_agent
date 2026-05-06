"""
TOOL 1 — Entity Extraction (HYBRID)
====================================
Static + LLM IOC extraction pipeline (Kaggle-safe version)
"""

import re
from typing import Any
from langchain_core.tools import tool
from core.llm_helper import llm_analyze


# =============================================================================
# REGEX PATTERNS
# =============================================================================

IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\.\d)\b")
# The (?<![\.,;:!]) ensures the match doesn't end with a period, comma, colon, etc.
URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)]+(?<![\.,;:!])")

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|io|xyz|top|cc|"
    r"tk|ml|ga|cf|info|biz|onion|gov|edu|co|me)\b"
)

BTC_PATTERN = re.compile(r"\b(?:1|3)[A-HJ-NP-Za-km-z1-9]{25,39}\b|bc1[a-zA-HJ-NP-Z0-9]{25,87}\b")
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN   = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN    = re.compile(r"\b[a-fA-F0-9]{32}\b")

EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
CVE_PATTERN   = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# =============================================================================
# THREAT SEEDS
# =============================================================================

THREAT_INTEL_SEEDS = {
    "malware_families": {"emotet", "trickbot", "qakbot", "redline", "lumma stealer"},
    "ransomware_groups": {"lockbit", "conti", "play", "clop"},
    "apt_groups": {"apt28", "apt29", "lazarus", "apt41"},
    "abused_tools": {"mimikatz", "cobalt strike", "metasploit", "rclone"},
}

TOOL_BLACKLIST = {"powershell", "cmd", "mshta", "rundll32", "vssadmin"}


# =============================================================================
# HELPERS
# =============================================================================

def _deduplicate(items: list) -> list:
    seen = set()
    out = []
    for i in items:
        if not i:
            continue
        k = i.strip().lower()
        if k not in seen:
            seen.add(k)
            out.append(i.strip())
    return out


def _find_seeds(seeds: set, text: str) -> list:
    return [s for s in seeds if re.search(rf"\b{re.escape(s)}\b", text)]


def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


# =============================================================================
# STATIC EXTRACTION
# =============================================================================

def _static_extraction(text: str) -> dict:
    sha256 = _deduplicate(SHA256_PATTERN.findall(text))
    sha1   = _deduplicate([h for h in SHA1_PATTERN.findall(text) if h not in sha256])
    md5    = _deduplicate([h for h in MD5_PATTERN.findall(text) if h not in sha256 + sha1])

    urls    = _deduplicate(URL_PATTERN.findall(text))
    domains = _deduplicate(DOMAIN_PATTERN.findall(text))
    domains = [d for d in domains if not any(d in u for u in urls)]

    low = text.lower()

    return {
        "ips": _deduplicate(IP_PATTERN.findall(text)),
        "urls": urls,
        "domains": domains,

        "crypto_wallets": {
            "btc": _deduplicate(BTC_PATTERN.findall(text)),
            "eth": _deduplicate(ETH_PATTERN.findall(text)),
            "xmr": _deduplicate(XMR_PATTERN.findall(text)),
        },

        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },

        "malware_names": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["malware_families"], low)),
        "ransomware_groups": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["ransomware_groups"], low)),
        "apt_groups": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["apt_groups"], low)),
        "tools_abused_static": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["abused_tools"], low)),

        "emails": _deduplicate(EMAIL_PATTERN.findall(text)),
        "cves": _deduplicate(CVE_PATTERN.findall(text)),
    }


# =============================================================================
# LLM EXTRACTION
# =============================================================================

LLM_PROMPT = """You are a Cyber Threat Intelligence (CTI) entity extractor.
Analyze the text and extract the following entities. Return ONLY valid JSON with
exactly these keys (use empty lists/string when nothing is found):

{
  "new_malware":        ["malware family names NOT already well-known (novel strains)"],
  "threat_actors":      ["APT group names, ransomware operator aliases, threat actor handles"],
  "defanged_iocs":      ["defanged IPs like 1.2.3[.]4, defanged URLs like hxxps://evil[.]com"],
  "campaign_names":     ["named operation or campaign identifiers, e.g. Operation ShadowHammer"],
  "targeted_sectors":   ["industry verticals targeted, e.g. healthcare, finance, energy"],
  "targeted_countries": ["country or region names explicitly mentioned as targets"],
  "tools_abused":       ["legitimate tools abused by attackers, e.g. PsExec, AnyDesk, ngrok"],
  "additional_cves":    ["any CVE IDs not already captured by regex, e.g. CVE-2024-1234"],
  "context_notes":      "one sentence summarising the most important context not captured above"
}

Return ONLY the JSON object. No markdown, no explanation, no preamble."""


def _llm_extraction(text: str) -> dict:
    res = llm_analyze(LLM_PROMPT, text)

    if res.get("llm_failed") or res.get("parse_error"):
        return {
            "new_malware": [],
            "threat_actors": [],
            "defanged_iocs": [],
            "campaign_names": [],
            "targeted_sectors": [],
            "targeted_countries": [],
            "tools_abused": [],
            "additional_cves": [],
            "context_notes": "",
        }

    return res


# =============================================================================
# MERGE ENGINE
# =============================================================================

def _merge_results(static: dict, llm: dict) -> dict:

    malware = _deduplicate(static.get("malware_names", []) + llm.get("new_malware", []))
    ransomware = static.get("ransomware_groups", [])
    apt = static.get("apt_groups", [])

    tools = _deduplicate(
        static.get("tools_abused_static", []) + llm.get("tools_abused", [])
    )
    tools = [t for t in tools if t.lower() not in TOOL_BLACKLIST]

    extra_ips, extra_urls, extra_domains = [], [], []

    for ioc in llm.get("defanged_iocs", []):

        if isinstance(ioc, dict):
            items = [str(v) for v in ioc.values()]
        elif isinstance(ioc, str):
            items = [ioc]
        else:
            continue

        for item in items:
            clean = (
                item.replace("[.]", ".")
                    .replace("hxxp://", "http://")
                    .replace("hxxps://", "https://")
            )

            ip = IP_PATTERN.search(clean)
            if ip and _is_valid_ipv4(ip.group()):
                extra_ips.append(ip.group())

            elif clean.startswith("http"):
                extra_urls.append(clean)

            elif DOMAIN_PATTERN.search(clean):
                extra_domains.append(clean)

    cves = _deduplicate(static.get("cves", []) + llm.get("additional_cves", []))

    merged = {
        "ips": _deduplicate(static.get("ips", []) + extra_ips),
        "urls": _deduplicate(static.get("urls", []) + extra_urls),
        "domains": _deduplicate(static.get("domains", []) + extra_domains),

        "crypto_wallets": static.get("crypto_wallets", {}),
        "hashes": static.get("hashes", {}),

        "malware_names": malware,
        "ransomware_groups": ransomware,
        "apt_groups": apt,
        "tools_abused": tools,

        "emails": static.get("emails", []),
        "cves": cves,

        "threat_actors": _deduplicate(llm.get("threat_actors", [])),
        "campaign_names": _deduplicate(llm.get("campaign_names", [])),
        "targeted_sectors": llm.get("targeted_sectors", []),
        "targeted_countries": llm.get("targeted_countries", []),
        "context_notes": llm.get("context_notes", ""),
    }

    # ========================
    # IOC COUNTERS
    # ========================

    merged["ioc_count_network"] = (
        len(merged["ips"]) + len(merged["urls"]) + len(merged["domains"]) +
        len(merged["emails"]) + len(merged["cves"]) +
        sum(len(v) for v in merged["crypto_wallets"].values()) +
        sum(len(v) for v in merged["hashes"].values())
    )

    merged["ioc_count"] = merged["ioc_count_network"] + (
        len(merged["malware_names"]) +
        len(merged["ransomware_groups"]) +
        len(merged["apt_groups"]) +
        len(merged["tools_abused"])
    )

    return merged


# =============================================================================
# TOOL ENTRY
# =============================================================================

@tool
def extract_entities(message: str) -> dict[str, Any]:
    """Extract IOCs, malware names, threat actors, CVEs, and all CTI entities
    from a raw threat intelligence message using hybrid static + LLM analysis."""
    static = _static_extraction(message)
    llm = _llm_extraction(message)
    return _merge_results(static, llm)