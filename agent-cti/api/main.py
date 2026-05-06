"""
CTI Multi-Agent System — FastAPI Backend (Production v3)
=========================================================
Pipeline exact du notebook (graph.py) :
  NODE 0  web_search_agent  → collecte RSS / Reddit / OTX
  NODE 1  cti_analysis_agent → extract_entities + detect_behaviors
                               + detect_patterns + rag_search + build_threat_brief
  NODE 2  mitre_agent        → map_to_mitre + calculate_severity + recommend_mitigations
  NODE 3  aggregator         → aggregate_reports + build_report_metadata
  NODE 4  prioritizer        → prioritize_actions + generate_executive_summary
  NODE 5  pdf_report         → generate_pdf_report

NGROK : tunnel automatique pour accès depuis un frontend local
"""

import asyncio
import io
import json
import logging
import os
import sys
import uuid
import threading
import time
from datetime import datetime
from typing import Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from api.schemas import AnalyzeRequest, RagSearchRequest
from api.api_auth import verify_api_key
from core import config

# ══════════════════════════════════════════════════════════════════════════════
#  NGROK — TUNNEL PUBLIC VERS KAGGLE
# ══════════════════════════════════════════════════════════════════════════════

def start_ngrok(port: int = 8000) -> str:
    """
    Lance un tunnel ngrok et retourne l'URL publique.
    Appelle cette fonction UNE SEULE FOIS au démarrage.

    Prérequis (dans Kaggle) :
      !pip install pyngrok -q
      Ajouter NGROK_TOKEN dans Kaggle Secrets (Add-ons → Secrets)
    """
    try:
        from pyngrok import ngrok, conf

        # ── 1. Récupère le token ────────────────────────────────────────────
        # Priorité : variable d'environnement → Kaggle Secrets
        token = os.environ.get("NGROK_TOKEN", "")

        if not token:
            try:
                from kaggle_secrets import UserSecretsClient
                token = UserSecretsClient().get_secret("NGROK_TOKEN")
            except Exception:
                pass

        if not token:
            print("⚠️  NGROK_TOKEN introuvable — ngrok désactivé")
            print("   → Ajoutez NGROK_TOKEN dans Kaggle Add-ons → Secrets")
            return ""

        # ── 2. Configure et ouvre le tunnel ────────────────────────────────
        ngrok.set_auth_token(token)
        tunnel = ngrok.connect(port, "http")
        public_url = tunnel.public_url

        print("\n" + "=" * 60)
        print("✅  NGROK TUNNEL ACTIF")
        print(f"🌐  URL publique : {public_url}")
        print(f"🔌  Port local   : {port}")
        print("=" * 60)
        print("📋  Copiez cette URL dans dashboard.py :")
        print(f"    API_BASE_URL = \"{public_url}\"")
        print("=" * 60 + "\n")

        return public_url

    except ImportError:
        print("❌  pyngrok non installé → !pip install pyngrok -q")
        return ""
    except Exception as e:
        print(f"❌  Erreur ngrok : {e}")
        return ""


# ── Logger ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cti_api")

sys.path.insert(0, os.path.dirname(__file__))

# verify_api_key is now in api_auth.py

jobs: dict[str, dict] = {}
JOBS_FILE = config.JOBS_STORE_PATH

def save_jobs():
    try:
        with open(JOBS_FILE, "w") as f:
            json.dump(jobs, f, default=str)
    except Exception as e:
        logger.warning(f"save_jobs failed: {e}")

def load_jobs():
    global jobs
    try:
        if os.path.exists(JOBS_FILE):
            with open(JOBS_FILE) as f:
                jobs = json.load(f)
            logger.info(f"✅ {len(jobs)} jobs restaurés depuis {JOBS_FILE}")
    except Exception as e:
        logger.warning(f"load_jobs failed: {e}")

# Charger au démarrage
load_jobs()
app = FastAPI(
    title="CTI Multi-Agent Backend",
    version="3.0.0",
    description="RAG-Enhanced Cyber Threat Intelligence Pipeline — LangGraph",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# @app.post("/inject_test")
# async def inject_test(api_key: str = Depends(verify_api_key)):
#     """Injecte un faux job complet pour tester le dashboard sans pipeline."""
    
#     test_id = "cti-test-debug-001"
    
#     jobs[test_id] = {
#         "job_id": test_id,
#         "status": "complete",
#         "created_at": datetime.now().isoformat(),
#         "completed_at": datetime.now().isoformat(),
#         "global_severity": "high",
#         "risk_trend": "Escalating",
#         "executive_summary": "LockBit 3.0 detected targeting finance via CVE-2024-21413.",
#         "threats_identified": ["LockBit 3.0", "APT28"],
#         "top_3_actions": [
#             "Block IP 185.220.101.45",
#             "Patch CVE-2024-21413",
#             "Enable MFA on privileged accounts",
#         ],
#         "kill_chain_stages": ["initial_access", "execution", "persistence", "exfiltration"],
#         "actor_profile": {
#             "likely_actor": "LockBit",
#             "confidence": 0.87,
#             "actor_type": "ransomware",
        #     "actor_maturity": "highly_capable",
        #     "typical_next_moves": ["double extortion", "data leak", "C2 beacon"],
        # },
        # "rag_results": [
        #     {"channel": "TheHackerNews", "date": "2024-12-01",
        #      "content": "LockBit 3.0 targets finance sector.", "score": 42.5},
        # ],
        # "statistics": {"total_iocs": 12, "techniques_count": 5, "behaviors_count": 6},
        # "techniques": [
        #     {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment",
        #      "tactic": "initial_access", "severity_level": "high", "severity_score": 4.2,
        #      "confidence": 0.91, "description": "Malicious .docx via CVE-2024-21413",
        #      "mitigations": ["Disable macros", "User training"], "priority": "immediate",
        #      "mapping_source": "static", "llm_reasoning": "Confirmed by RAG"},
        #     {"technique_id": "T1003.001", "technique_name": "LSASS Memory",
        #      "tactic": "credential_access", "severity_level": "critical", "severity_score": 5.0,
        #      "confidence": 0.78, "description": "Mimikatz LSASS dump",
        #      "mitigations": ["Credential Guard", "Monitor lsass"], "priority": "immediate",
        #      "mapping_source": "static", "llm_reasoning": ""},
        #     {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact",
        #      "tactic": "impact", "severity_level": "critical", "severity_score": 5.0,
        #      "confidence": 0.95, "description": "LockBit 3.0 encryptor",
        #      "mitigations": ["Offline backups", "Immutable storage"], "priority": "immediate",
        #      "mapping_source": "static", "llm_reasoning": ""},
        # ],
        # "all_iocs": {
        #     "ips": ["185.220.101.45"], "urls": ["https://185.220.101.45/payload.bin"],
        #     "domains": ["evil-lockbit.onion"], "emails": ["ransom@lockbit3.onion"],
        #     "cves": ["CVE-2024-21413"], "malware_names": ["lockbit"],
        #     "ransomware_groups": ["lockbit"], "apt_groups": ["apt28"],
        #     "tools_abused": ["mimikatz", "cobalt strike"],
        #     "hashes": {"md5": ["d41d8cd98f00b204e9800998ecf8427e"], "sha1": [], "sha256": []},
        # },
        # "web_search_stats": {
        #     "total": 42,
        #     "sources": ["TheHackerNews", "BleepingComputer", "CISA KEV", "AlienVault OTX"],
        #     "counts": [15, 12, 8, 7],
        # },
        # "cti_agent_stats": {
        #     "total_messages_analyzed": 42,
        #     "behaviors_detected": 3,
        #     "entities_found": 12,
        #     "behaviors": [
            #     {"category": "credential_access", "description": "Mimikatz LSASS dump on DC01",
            #      "severity": "critical", "confidence": 0.93,
            #      "matched_indicators": ["mimikatz.exe", "lsass"],
            #      "source": "static", "attack_technique_hint": "T1003.001"},
            #     {"category": "network_communication", "description": "HTTPS C2 to 185.220.101.45",
            #      "severity": "high", "confidence": 0.81,
            #      "matched_indicators": ["185.220.101.45"],
            #      "source": "llm", "attack_technique_hint": "T1071.001"},
            # ],
            # "entities": {
            #     "ips": ["185.220.101.45"], "urls": [], "domains": ["evil-lockbit.onion"],
            #     "emails": ["ransom@lockbit3.onion"], "cves": ["CVE-2024-21413"],
            #     "malware_names": ["lockbit"], "ransomware_groups": ["lockbit"],
            #     "apt_groups": ["apt28"], "tools_abused": ["mimikatz"],
            #     "hashes": {"md5": [], "sha1": [], "sha256": []}, "ioc_count": 12,
            # },
            # "patterns": {
            #     "threat_classification": "ransomware",
            #     "classification_confidence": 0.92,
            #     "entropy": 3.847, "diversity_ratio": 0.621,
            #     "known_cti_terms": ["lockbit", "mimikatz", "CVE-2024-21413"],
            #     "semantic_summary": "LockBit 3.0 ransomware targeting finance sector.",
            # },
            # "rag_results": [
                # {"channel": "TheHackerNews", "date": "2024-12-01",
    #              "content": "LockBit 3.0 targets financial sector.", "score": 42.5}
    #         ],
    #     },
    #     "mitre_agent_stats": {
    #         "techniques_mapped": 3,
    #         "tactics_covered": ["initial_access", "credential_access", "impact"],
    #         "global_severity_score": 4.6,
    #         "chain_bonus_applied": 0.3,
    #         "overall_reasoning": "Multi-stage attack with credential theft and ransomware.",
    #         "environment_context": {"os": "windows", "sector": "finance"},
    #         "severity_distribution": {"critical": 2, "high": 1},
    #         "priority_actions": ["Block 185.220.101.45", "Patch CVE-2024-21413"],
    #         "mitigations": [
    #             {"technique_id": "T1003.001", "technique_name": "LSASS Memory",
    #              "priority": "immediate", "recommendations": ["Enable Credential Guard"]},
    #         ],
    #     },
    # }
    
    # save_jobs()
    # return {"job_id": test_id, "message": "Test job injected — check dashboard"}

# Request classes moved to api/schemas.py


# ══════════════════════════════════════════════════════════════════════════════
#  IMPORT DES MODULES DU NOTEBOOK
# ══════════════════════════════════════════════════════════════════════════════
try:
    from pipeline.graph import run_pipeline as _run_pipeline
    from tools.rag_search import rag_search as _rag_search_tool
    PIPELINE_AVAILABLE = True
    logger.info("✅ LangGraph pipeline chargé (graph.py + modules notebook)")
except ImportError as e:
    PIPELINE_AVAILABLE = False
    logger.warning(f"⚠️  Pipeline LangGraph non disponible : {e}")
    logger.warning("    → Placez les fichiers .py du notebook dans ce répertoire.")


# ══════════════════════════════════════════════════════════════════════════════
#  ONTOLOGIE : catégorie behavior → kill chain stage
# ══════════════════════════════════════════════════════════════════════════════
_BEHAVIOR_TO_KC = {
    "process_creation":       "execution",
    "registry_modification":  "persistence",
    "network_communication":  "command_and_control",
    "file_system_activity":   "impact",
    "credential_access":      "credential_access",
    "defense_evasion":        "defense_evasion",
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

_KC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact",
]


def _behaviors_to_kill_chain(behaviors: list) -> list:
    stages = set()
    for b in behaviors:
        cat = b.get("category", b.get("type", "")).lower()
        stage = _BEHAVIOR_TO_KC.get(cat)
        if stage:
            stages.add(stage)
    return [s for s in _KC_ORDER if s in stages]


# ══════════════════════════════════════════════════════════════════════════════
#  ADAPTATEUR : état LangGraph → format API dashboard
# ══════════════════════════════════════════════════════════════════════════════

def _state_to_api(state: dict, job_id: str) -> dict:

    agg           = state.get("aggregated_report", {})
    ex_sum        = state.get("executive_summary", {})
    mitre_reports = state.get("mitre_reports", [])
    cti_results   = state.get("cti_results", [])
    messages      = state.get("messages", [])
    menaces       = state.get("menaces_brutes", [])

    first_report = next(
        (r for r in mitre_reports if "error" not in r and r.get("report_metadata")),
        {}
    )
    first_cti = next(
        (c for c in cti_results if "error" not in c),
        {}
    )

    s1 = first_report.get("section_1_summary_context", {})
    s2 = first_report.get("section_2_key_takeaways", {})
    s3 = first_report.get("section_3_severity", {})
    s4 = first_report.get("section_4_ttps", [])
    s5 = first_report.get("section_5_iocs_artifacts", {})
    s6 = first_report.get("section_6_mitigations", {})
    exec_obj = first_report.get("executive_summary", {})

    global_severity = (
        agg.get("global_severity")
        or s3.get("global_level")
        or "Unknown"
    )
    global_score = float(
        agg.get("global_severity_score")
        or s3.get("global_score", 0.0)
        or 0.0
    )

    risk_trend = ex_sum.get("risk_trend") or (
        "Escalating" if global_score >= 4.5 else
        "Increasing" if global_score >= 3.5 else
        "Elevated"   if global_score >= 2.5 else
        "Stable"
    )

    threats_identified = (
        agg.get("threats_identified")
        or exec_obj.get("threats_identified")
        or [s2.get("threat_actor", {}).get("name", "")]
    )
    threats_identified = [t for t in threats_identified if t and t.lower() not in ("unknown", "")]

    exec_text = (
        s1.get("attack_narrative")
        or ex_sum.get("executive_summary")
        or first_cti.get("threat_brief", {}).get("attack_narrative", "")
        or ""
    )

    actor_raw = (
        first_cti.get("threat_brief", {}).get("actor_profile")
        or first_cti.get("threat_brief", {}).get("mitre_input", {}).get("actor_context")
        or s2.get("threat_actor")
        or {}
    )
    if isinstance(actor_raw, dict):
        actor_profile = {
            "likely_actor":       actor_raw.get("name") or actor_raw.get("likely_actor") or actor_raw.get("validated_actor", "unknown"),
            "confidence":         float(actor_raw.get("confidence", 0.0)),
            "actor_type":         actor_raw.get("actor_type", "unknown"),
            "actor_maturity":     actor_raw.get("actor_maturity") or actor_raw.get("maturity", "unknown"),
            "typical_next_moves": actor_raw.get("typical_next_moves", []),
            "double_extortion":   actor_raw.get("double_extortion", False),
            "disruption_risk":    actor_raw.get("disruption_risk", "unknown"),
        }
    else:
        actor_profile = {"likely_actor": str(actor_raw) if actor_raw else "unknown", "confidence": 0.0}

    kill_chain_stages = (
        first_cti.get("threat_brief", {}).get("kill_chain_stages")
        or first_cti.get("threat_brief", {}).get("mitre_input", {}).get("kill_chain_stages")
        or s2.get("kill_chain_stages")
        or _behaviors_to_kill_chain(first_cti.get("behaviors", []))
        or []
    )

    rag_raw = first_cti.get("rag_context", {}).get("results", [])
    if not rag_raw:
        rag_raw = first_cti.get("threat_brief", {}).get("rag_signals", [])
    rag_results = [
        {
            "channel": r.get("channel", "?"),
            "date":    r.get("date", ""),
            "content": r.get("content", ""),
            "score":   float(r.get("score", 999)),
        }
        for r in rag_raw
    ]

    mits_by_tid = {}
    for tm in s6.get("by_technique", []):
        mits_by_tid[tm.get("technique_id", "")] = {
            "priority":       tm.get("priority", "short_term"),
            "mitigations":    tm.get("mitigations", []),
            "technique_name": tm.get("technique_name", ""),
        }

    techniques = []
    for ttp in s4:
        tid     = ttp.get("technique_id", "")
        obs     = ttp.get("observed_behavior", {})
        mit_obj = mits_by_tid.get(tid, {})
        techniques.append({
            "technique_id":   tid,
            "technique_name": ttp.get("technique_name", ""),
            "tactic":         ttp.get("tactic", ""),
            "severity_level": (ttp.get("severity_level") or "medium").lower(),
            "severity_score": float(ttp.get("severity_score") or 0.0),
            "confidence":     float(obs.get("confidence") or ttp.get("confidence", 0.7)),
            "description":    ttp.get("procedure_text") or obs.get("description", ""),
            "mitigations":    mit_obj.get("mitigations", []),
            "priority":       mit_obj.get("priority", "short_term"),
            "mapping_source": ttp.get("mapping_source", ""),
            "llm_reasoning":  ttp.get("llm_reasoning", ""),
        })

    net      = s5.get("network", {})
    fls      = s5.get("files", {})
    ti       = s5.get("threat_intelligence", {})
    cryp     = s5.get("crypto", {})
    s5_stats = s5.get("_stats", {})
    ent      = first_cti.get("entities", {})

    all_iocs = {
        "ips":               net.get("ips", []) or ent.get("ips", []),
        "urls":              net.get("urls", []) or ent.get("urls", []),
        "domains":           net.get("domains", []) or ent.get("domains", []),
        "emails":            ent.get("emails", []),
        "cves":              ti.get("cves", []) or ent.get("cves", []),
        "malware_names":     ti.get("malware_names", []) or ent.get("malware_names", []),
        "ransomware_groups": ti.get("ransomware_groups", []) or ent.get("ransomware_groups", []),
        "apt_groups":        ti.get("apt_groups", []) or ent.get("apt_groups", []),
        "tools_abused":      ti.get("tools_abused", []) or ent.get("tools_abused", []),
        "hashes": {
            "md5":    fls.get("md5", []) or ent.get("hashes", {}).get("md5", []),
            "sha1":   fls.get("sha1", []) or ent.get("hashes", {}).get("sha1", []),
            "sha256": fls.get("sha256", []) or ent.get("hashes", {}).get("sha256", []),
        },
        "crypto_wallets": cryp,
    }
    total_iocs = (
        s5_stats.get("total_network_iocs", 0)
        + len(ti.get("cves", []))
        + len(ti.get("malware_names", []))
        or ent.get("ioc_count", 0)
    )

    top_3_actions = ex_sum.get("top_3_actions", [])
    if not top_3_actions:
        prio_raw = s6.get("priority_actions", [])
        top_3_actions = [(p["text"] if isinstance(p, dict) else p) for p in prio_raw[:3]]

    behaviors_list = first_cti.get("behaviors", [])
    patterns_full  = first_cti.get("patterns", {})

    sources_count: dict[str, int] = {}
    for m in menaces:
        src = m.get("source", "Unknown") if isinstance(m, dict) else "Unknown"
        sources_count[src] = sources_count.get(src, 0) + 1

    web_search_stats = {
        "total": len(menaces) if menaces else len(messages),
        "sources":            list(sources_count.keys()) or ["TheHackerNews", "BleepingComputer", "CISA KEV", "AlienVault OTX"],
        "counts":             list(sources_count.values()) or [0, 0, 0, 0],
        "messages_collected": menaces[:5],
    }

    cti_agent_stats = {
        "total_messages_analyzed": len(messages),
        "behaviors_detected":      len(behaviors_list),
        "entities_found":          ent.get("ioc_count", total_iocs),
        "behaviors": [
            {
                "category":              b.get("category", b.get("type", "")),
                "description":           b.get("description", ""),
                "severity":              b.get("severity", "medium"),
                "confidence":            float(b.get("confidence", 0.7)),
                "matched_indicators":    b.get("matched_indicators", []),
                "source":                b.get("source", "static"),
                "attack_technique_hint": b.get("attack_technique_hint", ""),
            }
            for b in behaviors_list
        ],
        "entities": {
            "ips":               ent.get("ips", []),
            "urls":              ent.get("urls", []),
            "domains":           ent.get("domains", []),
            "emails":            ent.get("emails", []),
            "cves":              ent.get("cves", []),
            "malware_names":     ent.get("malware_names", []),
            "ransomware_groups": ent.get("ransomware_groups", []),
            "apt_groups":        ent.get("apt_groups", []),
            "tools_abused":      ent.get("tools_abused", []),
            "hashes":            ent.get("hashes", {}),
            "ioc_count":         ent.get("ioc_count", 0),
        },
        "patterns": {
            "threat_classification":     patterns_full.get("threat_classification", s1.get("threat_classification", "")),
            "classification_confidence": float(patterns_full.get("classification_confidence", 0.0)),
            "entropy":                   float(patterns_full.get("entropy", 0.0)),
            "diversity_ratio":           float(patterns_full.get("diversity_ratio", 0.0)),
            "known_cti_terms":           patterns_full.get("known_cti_terms", []),
            "semantic_summary":          patterns_full.get("semantic_summary") or s1.get("semantic_summary", ""),
            "top_keywords":              patterns_full.get("top_keywords", []),
        },
        "rag_results": rag_results,
    }

    severity_dist_raw = s3.get("distribution", {})
    severity_dist = {k.lower(): v for k, v in severity_dist_raw.items()}

    mitre_agent_stats = {
        "techniques_mapped":     len(techniques),
        "tactics_covered":       list(set(t["tactic"] for t in techniques if t.get("tactic"))),
        "global_severity_score": global_score,
        "global_severity_level": global_severity,
        "chain_bonus_applied":   float(s3.get("chain_bonus_applied", 0.0)),
        "overall_reasoning":     s3.get("overall_reasoning", ""),
        "environment_context":   s3.get("environment_context", {}),
        "severity_distribution": severity_dist,
        "techniques":            techniques,
        "priority_actions": [
            (p["text"] if isinstance(p, dict) else p)
            for p in s6.get("priority_actions", [])
        ],
        "mitigations": [
            {
                "technique_id":    tm.get("technique_id", ""),
                "technique_name":  tm.get("technique_name", ""),
                "priority":        tm.get("priority", "short_term"),
                "recommendations": tm.get("mitigations", []),
            }
            for tm in s6.get("by_technique", [])
        ],
    }

    return {
        "status":      "complete",
        "job_id":       job_id,
        "completed_at": datetime.now().isoformat(),

        "global_severity":    global_severity,
        "risk_trend":         risk_trend,
        "executive_summary":  exec_text,
        "threats_identified": threats_identified,
        "top_3_actions":      top_3_actions,
        "kill_chain_stages":  kill_chain_stages,
        "actor_profile":      actor_profile,
        "rag_results":        rag_results,

        "statistics": {
            "total_iocs":       total_iocs,
            "techniques_count": len(techniques),
            "behaviors_count":  len(behaviors_list),
        },

        "techniques":        techniques,
        "all_iocs":          all_iocs,
        "web_search_stats":  web_search_stats,
        "cti_agent_stats":   cti_agent_stats,
        "mitre_agent_stats": mitre_agent_stats,

        "_raw_executive_summary": ex_sum,
        "_raw_agg_report":        {k: v for k, v in agg.items() if k != "section_4_ttps"},
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MODE DÉGRADÉ
# ══════════════════════════════════════════════════════════════════════════════
def _fallback_result(job_id: str, query: str) -> dict:
    return {
        "status":         "complete",
        "job_id":          job_id,
        "completed_at":    datetime.now().isoformat(),
        "global_severity": "unknown",
        "risk_trend":      "Unknown",
        "executive_summary": (
            "⚠️  Pipeline LangGraph non chargé. "
            "Copiez graph.py, cti_analysis_agent.py, mitre_agent.py, "
            "aggregator.py, prioritizer.py, pdf_report.py, rag_search.py "
            "et les autres modules du notebook dans ce répertoire, "
            "puis redémarrez le serveur."
        ),
        "threats_identified": [],
        "top_3_actions": [
            "Copier graph.py dans le répertoire backend",
            "Copier tous les modules du notebook (.py)",
            "Configurer les variables d'environnement (GROQ_API_KEY, etc.)",
        ],
        "kill_chain_stages": [],
        "actor_profile":     {"likely_actor": "unknown", "confidence": 0.0},
        "rag_results":       [],
        "statistics":        {"total_iocs": 0, "techniques_count": 0, "behaviors_count": 0},
        "techniques":        [],
        "all_iocs": {
            "ips": [], "urls": [], "domains": [], "emails": [], "cves": [],
            "malware_names": [], "ransomware_groups": [], "apt_groups": [],
            "tools_abused": [], "hashes": {"md5": [], "sha1": [], "sha256": []},
        },
        "web_search_stats":  {"total": 0, "sources": [], "counts": []},
        "cti_agent_stats": {
            "total_messages_analyzed": 0, "behaviors_detected": 0,
            "entities_found": 0, "behaviors": [], "entities": {},
            "patterns": {}, "rag_results": [],
        },
        "mitre_agent_stats": {
            "techniques_mapped": 0, "tactics_covered": [],
            "global_severity_score": 0.0, "chain_bonus_applied": 0.0,
            "severity_distribution": {}, "priority_actions": [],
            "mitigations": [], "techniques": [],
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
#  RUNNER ASYNCHRONE
# ══════════════════════════════════════════════════════════════════════════════
async def _run_job(job_id: str, query: str, web_search: bool, notify: bool):
    try:
        jobs[job_id]["status"]     = "running"
        jobs[job_id]["started_at"] = datetime.now().isoformat()
        logger.info(f"[{job_id}] Pipeline started — query: {query[:80]!r}")

        if not PIPELINE_AVAILABLE:
            jobs[job_id].update(_fallback_result(job_id, query))
            save_jobs()   # ← persist
            return

        input_messages = [] if web_search else [query]

        final_state = await asyncio.to_thread(
            _run_pipeline,
            messages=input_messages,
            thread_id=job_id,
        )

        # Fix #3 — vérifier que le pipeline a bien retourné quelque chose
        if not final_state:
            raise ValueError("run_pipeline() returned empty state")

        logger.info(f"[{job_id}] Pipeline terminé — conversion...")
        api_result = _state_to_api(final_state, job_id)
        api_result["status"] = "complete"   # ← forcer explicitement
        jobs[job_id].update(api_result)
        save_jobs()   # ← persist

        logger.info(
            f"[{job_id}] ✅ sévérité={api_result.get('global_severity')} "
            f"techniques={api_result.get('statistics', {}).get('techniques_count')} "
            f"IOCs={api_result.get('statistics', {}).get('total_iocs')}"
        )

    except Exception as exc:
        logger.exception(f"[{job_id}] ❌ Erreur pipeline : {exc}")
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"]  = str(exc)
        save_jobs()   # ← persist même en cas d'erreur


# ══════════════════════════════════════════════════════════════════════════════
#  PDF BUILDER
# ══════════════════════════════════════════════════════════════════════════════
def _build_pdf(job: dict) -> bytes | None:
    try:
        from reporting.pdf_report import generate_pdf_report
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name
        generate_pdf_report(report_data=job, output_filepath=tmp_path)
        with open(tmp_path, "rb") as f:
            data = f.read()
        os.unlink(tmp_path)
        return data
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"pdf_report.py failed: {e} — fallback ReportLab")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable,
        )

        buf    = io.BytesIO()
        doc    = SimpleDocTemplate(buf, pagesize=A4,
                                   rightMargin=2*cm, leftMargin=2*cm,
                                   topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        NAVY   = colors.HexColor("#0F172A")
        BLUE   = colors.HexColor("#0EA5E9")
        PURPLE = colors.HexColor("#7C3AED")
        RED    = colors.HexColor("#DC2626")
        ORANGE = colors.HexColor("#EA580C")
        YELLOW = colors.HexColor("#EAB308")
        GREEN  = colors.HexColor("#16A34A")

        SEV_COLORS = {"critical": RED, "high": ORANGE, "medium": YELLOW, "low": GREEN}

        H1    = ParagraphStyle("H1",   parent=styles["Heading1"], textColor=NAVY, fontSize=13, spaceAfter=6)
        H2    = ParagraphStyle("H2",   parent=styles["Heading2"], textColor=BLUE, fontSize=11, spaceBefore=8, spaceAfter=4)
        BODY  = ParagraphStyle("BODY", parent=styles["Normal"],   textColor=colors.HexColor("#334155"), fontSize=9, leading=14)
        MUTED = ParagraphStyle("MUTED",parent=styles["Normal"],   textColor=colors.HexColor("#64748B"), fontSize=8)

        story = []

        story.append(Paragraph("🛡️  CTI Multi-Agent Intelligence Report", H1))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Job: {job.get('job_id','?')}",
            MUTED
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
        story.append(Spacer(1, 0.4*cm))

        sev   = job.get("global_severity", "unknown").upper()
        story.append(Paragraph(f"1. Executive Summary — Severity: {sev}", H2))
        story.append(Paragraph(f"<b>Risk Trend:</b> {job.get('risk_trend','?')}", BODY))
        story.append(Paragraph(job.get("executive_summary","") or "No summary available.", BODY))
        story.append(Spacer(1, 0.3*cm))

        threats = job.get("threats_identified", [])
        if threats:
            story.append(Paragraph("2. Threats Identified", H2))
            for t in threats:
                story.append(Paragraph(f"• {t}", BODY))
            story.append(Spacer(1, 0.2*cm))

        actor = job.get("actor_profile", {})
        if actor and actor.get("likely_actor") and actor["likely_actor"] != "unknown":
            story.append(Paragraph("3. Threat Actor Profile", H2))
            rows_a = [
                ["Likely Actor",     actor.get("likely_actor", "?")],
                ["Confidence",       f"{actor.get('confidence', 0)*100:.0f}%"],
                ["Actor Type",       actor.get("actor_type", "?").title()],
                ["Maturity",         str(actor.get("actor_maturity", "?")).replace("_"," ").title()],
                ["Double Extortion", str(actor.get("double_extortion", False))],
                ["Disruption Risk",  str(actor.get("disruption_risk", "?")).title()],
            ]
            tbl_a = Table(rows_a, colWidths=[5*cm, 12*cm])
            tbl_a.setStyle(TableStyle([
                ("FONTSIZE",     (0,0), (-1,-1), 8),
                ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
                ("TEXTCOLOR",    (0,0), (0,-1), colors.HexColor("#64748B")),
                ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS",(0,0),(-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]))
            story.append(tbl_a)
            story.append(Spacer(1, 0.2*cm))

        cti_stats = job.get("cti_agent_stats", {})
        story.append(Paragraph("4. CTI Analysis Agent Results", H2))
        pats = cti_stats.get("patterns", {})
        story.append(Paragraph(
            f"Messages Analyzed: {cti_stats.get('total_messages_analyzed',0)} | "
            f"Behaviors Detected: {cti_stats.get('behaviors_detected',0)} | "
            f"Entities Found: {cti_stats.get('entities_found',0)} | "
            f"Classification: {pats.get('threat_classification','?')} "
            f"({pats.get('classification_confidence',0)*100:.0f}%)",
            BODY
        ))
        sem = pats.get("semantic_summary","")
        if sem:
            story.append(Paragraph(f"<i>Semantic Summary:</i> {sem}", BODY))

        behaviors = cti_stats.get("behaviors", [])
        if behaviors:
            story.append(Paragraph("Detected Behaviors:", MUTED))
            rows_b = [["Category", "Severity", "Confidence", "Hint", "Description"]]
            for b in behaviors[:10]:
                rows_b.append([
                    b.get("category","?"),
                    b.get("severity","?").upper(),
                    f"{b.get('confidence',0)*100:.0f}%",
                    b.get("attack_technique_hint","")[:20],
                    b.get("description","")[:60],
                ])
            tbl_b = Table(rows_b, colWidths=[3*cm, 2*cm, 2*cm, 3*cm, 7*cm])
            tbl_b.setStyle(TableStyle([
                ("BACKGROUND",   (0,0),(-1,0), NAVY),
                ("TEXTCOLOR",    (0,0),(-1,0), colors.white),
                ("FONTSIZE",     (0,0),(-1,-1), 7),
                ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F0F9FF")]),
            ]))
            story.append(tbl_b)
        story.append(Spacer(1, 0.3*cm))

        iocs = job.get("all_iocs", {})
        story.append(Paragraph("5. Indicators of Compromise (IOCs)", H2))
        rows_i = [["Type", "Values"]]
        ioc_map = [
            ("IP Addresses",      iocs.get("ips", [])),
            ("URLs",              iocs.get("urls", [])),
            ("Domains",           iocs.get("domains", [])),
            ("Emails",            iocs.get("emails", [])),
            ("CVEs",              iocs.get("cves", [])),
            ("Malware",           iocs.get("malware_names", [])),
            ("Ransomware Groups", iocs.get("ransomware_groups", [])),
            ("APT Groups",        iocs.get("apt_groups", [])),
            ("Tools Abused",      iocs.get("tools_abused", [])),
        ]
        for label, vals in ioc_map:
            if vals:
                rows_i.append([label, ", ".join(str(v) for v in vals[:10])])
        if iocs.get("hashes", {}).get("sha256"):
            rows_i.append(["SHA256 Hashes", ", ".join(iocs["hashes"]["sha256"][:3])])
        if len(rows_i) > 1:
            tbl_i = Table(rows_i, colWidths=[4*cm, 13*cm])
            tbl_i.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), BLUE),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("FONTSIZE",      (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#F0F9FF")]),
            ]))
            story.append(tbl_i)
        story.append(Spacer(1, 0.3*cm))

        mm    = job.get("mitre_agent_stats", {})
        techs = job.get("techniques", [])
        story.append(Paragraph("6. MITRE ATT&CK Techniques", H2))
        story.append(Paragraph(
            f"Techniques Mapped: {mm.get('techniques_mapped', len(techs))} | "
            f"Tactics Covered: {len(mm.get('tactics_covered', []))} | "
            f"Global Score: {mm.get('global_severity_score', 0):.1f}/5 | "
            f"Chain Bonus: +{mm.get('chain_bonus_applied', 0):.2f}",
            BODY
        ))
        if mm.get("overall_reasoning"):
            story.append(Paragraph(f"<i>{mm['overall_reasoning']}</i>", MUTED))

        if techs:
            rows_t = [["ID", "Technique", "Tactic", "Severity", "Score", "Conf."]]
            for t in techs[:15]:
                rows_t.append([
                    t.get("technique_id","?"),
                    t.get("technique_name","?")[:38],
                    t.get("tactic","?"),
                    t.get("severity_level","medium").capitalize(),
                    f"{t.get('severity_score',0):.1f}",
                    f"{t.get('confidence',0)*100:.0f}%",
                ])
            tbl_t = Table(rows_t, colWidths=[2*cm, 6.5*cm, 3.5*cm, 2*cm, 1.5*cm, 1.5*cm])
            tbl_t.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0), PURPLE),
                ("TEXTCOLOR",     (0,0),(-1,0), colors.white),
                ("FONTSIZE",      (0,0),(-1,-1), 7.5),
                ("GRID",          (0,0),(-1,-1), 0.5, colors.HexColor("#E2E8F0")),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor("#FAF5FF")]),
            ]))
            story.append(tbl_t)
        story.append(Spacer(1, 0.3*cm))

        mits = mm.get("mitigations", [])
        if mits:
            story.append(Paragraph("7. Mitigations & Remediation", H2))
            for mit in mits[:8]:
                prio = mit.get("priority", "short_term").replace("_"," ").title()
                story.append(Paragraph(
                    f"<b>{mit.get('technique_id','?')} — {mit.get('technique_name','?')}</b> [{prio}]",
                    BODY
                ))
                for rec in mit.get("recommendations", [])[:3]:
                    story.append(Paragraph(f"    • {rec}", BODY))
            story.append(Spacer(1, 0.2*cm))

        actions = job.get("top_3_actions", []) or mm.get("priority_actions", [])
        if actions:
            story.append(Paragraph("8. Priority Actions", H2))
            for i, action in enumerate(actions[:5], 1):
                story.append(Paragraph(f"[{i:02d}] {action}", BODY))

        rag_hits = job.get("rag_results", [])
        if rag_hits:
            story.append(Paragraph("9. RAG Historical Intelligence", H2))
            for r in rag_hits[:3]:
                sim_pct = max(0, 100 - int(r.get("score", 999) / 2))
                story.append(Paragraph(
                    f"<b>{r.get('channel','?')}</b> ({r.get('date','')}) — {sim_pct}% match",
                    MUTED
                ))
                story.append(Paragraph(r.get("content","")[:300], BODY))
            story.append(Spacer(1, 0.2*cm))

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))
        story.append(Paragraph(
            "Generated by CTI Multi-Agent System v3.0 — ENIS PFA 2025-2026",
            ParagraphStyle("F", parent=MUTED, fontSize=7),
        ))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        txt = (
            f"CTI REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Job: {job.get('job_id','?')}\n"
            f"Severity: {job.get('global_severity','?').upper()}\n\n"
            f"{job.get('executive_summary','')}\n"
        )
        return txt.encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  RAG SEARCH DIRECT
# ══════════════════════════════════════════════════════════════════════════════
async def _rag_search_api(query: str, k: int) -> list[dict]:
    if not PIPELINE_AVAILABLE:
        return []
    try:
        raw    = await asyncio.to_thread(_rag_search_tool.invoke, {"query": query[:300], "k": k})
        parsed = json.loads(raw) if isinstance(raw, str) else raw
        return parsed.get("results", [])
    except Exception as e:
        logger.warning(f"RAG search error: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    active = sum(1 for j in jobs.values() if j.get("status") == "running")
    return {
        "status":         "ok",
        "version":        "3.0.0",
        "pipeline":       "langgraph" if PIPELINE_AVAILABLE else "unavailable",
        "modules_loaded": PIPELINE_AVAILABLE,
        "active_jobs":    active,
        "total_jobs":     len(jobs),
        "timestamp":      datetime.now().isoformat(),
        # Expose l'URL ngrok si disponible
        "public_url":     os.environ.get("NGROK_PUBLIC_URL", ""),
    }


@app.post("/analyze")
async def analyze(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key),
):
    query = " ".join(req.messages).strip()
    if not query:
        raise HTTPException(status_code=400, detail="Empty query")

    job_id = f"cti-{uuid.uuid4().hex[:12]}"
    jobs[job_id] = {
        "job_id":     job_id,
        "status":     "pending",
        "query":      query,
        "created_at": datetime.now().isoformat(),
        "progress":   0,
        "rag_mode":   req.rag_mode,
        "web_search": req.web_search,
    }

    background_tasks.add_task(_run_job, job_id, query, req.web_search, req.notify)
    return {"job_id": job_id, "status": "pending", "message": "Pipeline LangGraph démarré"}


@app.get("/report/{job_id}")
async def get_report(job_id: str, api_key: str = Depends(verify_api_key)):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/report/{job_id}/pdf")
async def get_pdf(job_id: str, api_key: str = Depends(verify_api_key)):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = jobs[job_id]
    if job.get("status") != "complete":
        raise HTTPException(status_code=400, detail="Report not ready yet")

    pdf_bytes = _build_pdf(job)
    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="PDF generation failed")

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cti_report_{job_id}.pdf"'},
    )


@app.post("/rag/search")
async def rag_search_endpoint(
    req: RagSearchRequest,
    api_key: str = Depends(verify_api_key),
):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Empty query")
    results = await _rag_search_api(req.query, req.k)
    return {"query": req.query, "k": req.k, "count": len(results), "results": results}


@app.get("/history")
async def history(api_key: str = Depends(verify_api_key)):
    feed = []
    for job in sorted(jobs.values(), key=lambda x: x.get("created_at", ""), reverse=True)[:50]:
        threats = job.get("threats_identified", [])
        title   = threats[0] if threats else job.get("query", "Unknown")[:60]
        feed.append({
            "job_id":    job["job_id"],
            "title":     title,
            "severity":  job.get("global_severity", ""),
            "status":    job.get("status", ""),
            "timestamp": job.get("created_at", ""),
        })
    return feed


@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str, api_key: str = Depends(verify_api_key)):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    del jobs[job_id]
    return {"deleted": job_id}


@app.get("/")
async def root():
    return {
        "name":       "CTI Multi-Agent Backend",
        "version":    "3.0.0",
        "pipeline":   "langgraph" if PIPELINE_AVAILABLE else "unavailable",
        "public_url": os.environ.get("NGROK_PUBLIC_URL", ""),
        "docs":       "/docs",
        "modules_needed": [] if PIPELINE_AVAILABLE else [
            "graph.py", "cti_analysis_agent.py", "mitre_agent.py",
            "mitre_mapper.py", "severity_engine.py", "mitigation_engine.py",
            "aggregator.py", "prioritizer.py", "web_search_agent.py",
            "rag_search.py", "extract_entities.py", "detect_behaviors.py",
            "detect_patterns.py", "threat_brief.py", "llm_helper.py",
            "config.py", "pdf_report.py",
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE KAGGLE
#  Colle ce bloc dans une cellule Kaggle APRÈS avoir écrit ce fichier
# ══════════════════════════════════════════════════════════════════════════════
#
#  %%writefile main.py
#  ... (ce fichier entier) ...
#
#  Puis dans la cellule suivante :
#
#  import nest_asyncio, uvicorn, threading, time
#  from api.main import app, start_ngrok
#
#  nest_asyncio.apply()
#
#  # Lance le serveur FastAPI en arrière-plan
#  def run():
#      uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
#
#  t = threading.Thread(target=run, daemon=True)
#  t.start()
#  time.sleep(3)  # attend que le serveur démarre
#
#  # Ouvre le tunnel ngrok
#  public_url = start_ngrok(port=8000)
#
#  # Sauvegarde l'URL pour référence
#  import os
#  os.environ["NGROK_PUBLIC_URL"] = public_url
#
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Lancement direct (hors Kaggle) : python main.py
    import uvicorn
    import nest_asyncio
    nest_asyncio.apply()

    PORT = int(os.environ.get("PORT", 8000))

    # Lance ngrok si TOKEN présent
    ngrok_url = start_ngrok(PORT)
    if ngrok_url:
        os.environ["NGROK_PUBLIC_URL"] = ngrok_url

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")