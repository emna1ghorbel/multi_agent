"""
==========================================
 WEB SEARCH AGENT (LangGraph compatible)
==========================================
Collects CTI threats from multiple open sources,
filters by embedding similarity (no keywords),
and returns raw textual messages for downstream
CTI analysis agents.
"""

import requests
import feedparser
import time
import random
import numpy as np
from difflib import SequenceMatcher
from sentence_transformers import SentenceTransformer, util
from langsmith import traceable

# ─────────────────────────────────────
# CONFIG
# ─────────────────────────────────────
from kaggle_secrets import UserSecretsClient
OTX_API_KEY = UserSecretsClient().get_secret("OTX_API_KEY")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/119.0.0.0",
]

# ─────────────────────────────────────
# EMBEDDING THREAT FILTER
# ─────────────────────────────────────

# Modèle léger, multilingue, rapide
EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")

# Phrase de référence CTI — décrit ce qu'est une menace
CTI_REFERENCE = (
    "A cybersecurity threat, attack, vulnerability, malware, exploit, "
    "data breach, or malicious actor targeting systems or organizations."
)

# Embedding de référence (calculé une seule fois)
CTI_REFERENCE_EMB = EMBED_MODEL.encode(CTI_REFERENCE, convert_to_tensor=True)

# Seuil de similarité cosinus (0.0 → 1.0)
# 0.35 = bon équilibre précision/rappel pour du texte CTI court
THREAT_THRESHOLD = 0.35


def is_threat(item: dict) -> tuple[bool, float]:
    """
    Retourne (is_threat: bool, score: float).
    Compare title + summary à la phrase de référence CTI
    via similarité cosinus sur embeddings.
    """
    text = (item.get("title", "") + ". " + item.get("summary", "")).strip()
    if not text:
        return False, 0.0

    emb = EMBED_MODEL.encode(text, convert_to_tensor=True)
    score = float(util.cos_sim(emb, CTI_REFERENCE_EMB))
    return score >= THREAT_THRESHOLD, round(score, 4)


# ─────────────────────────────────────
# HELPERS
# ─────────────────────────────────────
def headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

def wait():
    time.sleep(random.uniform(2, 4))


# ─────────────────────────────────────
# COLLECTORS
# ─────────────────────────────────────
def collect_rss():
    sources = {
        "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
    }
    data = []
    for src, url in sources.items():
        feed = feedparser.parse(url)
        for e in feed.entries[:5]:
            data.append({
                "source": src,
                "title": e.title,
                "summary": e.summary,
                "link": e.link
            })
        wait()
    return data


def collect_reddit():
    url = "https://www.reddit.com/r/netsec/hot.json?limit=5"
    try:
        r = requests.get(url, headers=headers(), timeout=30)
        if r.status_code != 200:
            return []
        posts = r.json()["data"]["children"]
        return [{
            "source": "Reddit r/netsec",
            "title": p["data"]["title"],
            "summary": p["data"]["selftext"][:300],
            "link": p["data"]["url"]
        } for p in posts]
    except Exception:
        return []


def collect_stackoverflow():
    url = "https://api.stackexchange.com/2.3/questions"
    params = {
        "order": "desc",
        "sort": "creation",
        "tagged": "security",
        "site": "stackoverflow",
        "pagesize": 5
    }
    r = requests.get(url, params=params, headers=headers())
    data = r.json().get("items", [])
    wait()
    return [{
        "source": "StackOverflow",
        "title": q["title"],
        "summary": str(q["tags"]),
        "link": q["link"]
    } for q in data]


def collect_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers_otx = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(url, headers=headers_otx, timeout=30)
        pulses = r.json().get("results", [])[:5]
        return [{
            "source": "AlienVault OTX",
            "title": p["name"],
            "summary": p.get("description", "")[:300],
            "link": f"https://otx.alienvault.com/pulse/{p['id']}"
        } for p in pulses]
    except Exception:
        return []


# ─────────────────────────────────────
# UTILS
# ─────────────────────────────────────
def deduplicate(items):
    unique = []
    for item in items:
        title = item["title"].lower()
        if any(SequenceMatcher(None, title, u["title"].lower()).ratio() >= 0.7 for u in unique):
            continue
        unique.append(item)
    return unique


# ─────────────────────────────────────
# MAIN ENTRY (LangGraph)
# ─────────────────────────────────────
@traceable(name="SearchAgent — web_search_agent")
def main() -> list[str]:
    """
    LangGraph entry point.
    Returns list[str] of raw CTI messages (threats only).
    """

    print("🌐 Web Search Agent running...")

    collected = (
        collect_rss()
        + collect_reddit()
        + collect_stackoverflow()
        + collect_otx()
    )
    total_count = len(collected)


    # 1️⃣  Filtre par similarité d'embedding
    threats, non_threats = [], []
    for item in collected:
        threat, score = is_threat(item)
        item["threat_score"] = score
        if threat:
            threats.append(item)
        else:
            non_threats.append(item)

    print(f"🔍 Embedding filter : {len(threats)} threat(s) (score ≥ {THREAT_THRESHOLD}) "
          f"/ {len(non_threats)} non-threat(s) ignoré(s)")

    # 2️⃣  Déduplication
    unique = deduplicate(threats)
    threat_count = len(threats)
    non_threat_count = len(non_threats)
    # 3️⃣  Formatage — score inclus pour traçabilité
    messages = []
    for a in unique:
        messages.append(
            f"Source: {a['source']}\n"
            f"Title: {a['title']}\n"
            f"URL: {a['link']}\n"
            f"Threat Score: {a['threat_score']}\n"
            f"Summary: {a.get('summary','')}"
        )
    print("📊 ===== STATISTICS =====")
    print(f"🌐 Total collected items: {total_count}")
    print(f"🚨 Threats detected: {threat_count}")
    print(f"🧹 Non-threats filtered out: {non_threat_count}")
    print("=========================")

    print(f"✅ Web Search Agent returned {len(messages)} messages")
    return messages
