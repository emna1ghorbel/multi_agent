"""
CTI PIPELINE — graph.py  PRODUCTION VERSION v2
================================================
Corrections vs v1 :
  FIX D-1 — dashboard_node : merge agrégat + premier rapport individuel
             Avant : dashboard recevait uniquement aggregated_report →
             generate_dashboard() ne trouvait pas section_4_ttps,
             behaviors, IOCs → "0 behaviors / 0 techniques / 0 IOCs"

  FIX D-2 — pdf_node : section_3_severity écrasée par les stats agrégées
             Avant : severity MEDIUM (1er rapport) au lieu de Critical (global)

CORRECTIONS héritées de v1 :
  FIX 1 — _source_message stocké dans cti_result (désynchronisation index)
  FIX 2 — pdf_node utilise l'agrégat
  FIX 3 — notify_node : bare except → except Exception
  FIX 4 — Checkpoint SQLite
  FIX 5 — thread_id configurable
  FIX 6 — sanitize_unicode sur executive_summary
  FIX 7 — aggregation_node : filtre global_score > 0 supprimé
"""

import re
import os
from typing import TypedDict, List, Optional
from datetime import datetime

from langgraph.graph import StateGraph, START, END

# ==============================
# LangSmith CONFIG
# ==============================
try:
    from kaggle_secrets import UserSecretsClient
    secrets = UserSecretsClient()
    os.environ["LANGSMITH_TRACING"]  = "true"
    os.environ["LANGSMITH_ENDPOINT"] = "https://api.smith.langchain.com"
    os.environ["LANGSMITH_API_KEY"]  = secrets.get_secret("LANGCHAIN_API_KEY")
    os.environ["LANGSMITH_PROJECT"]  = "cti_rag"
    os.environ["HF_HOME"]            = "/kaggle/working/hf_cache"
    print("✅ LangSmith enabled")
except Exception as e:
    print(f"⚠️ LangSmith disabled: {e}")

# ==============================
# IMPORTS
# ==============================
from core import config
from agents.cti_analysis_agent import analyze_message
from agents.mitre_agent        import run_mitre_analysis
from pipeline.aggregator        import aggregate_reports, build_report_metadata
from tools.prioritizer        import prioritize_actions, generate_executive_summary
from reporting.dashboard          import generate_dashboard
from reporting.pdf_report         import generate_pdf_report
from agents.web_search_agent   import main as main_websearch
from reporting.notify_agent       import main as main_notify
from tools.ragas_worker       import start_worker, submit_for_evaluation

BASE = config.BASE_WORKING_DIR


# ==============================
# STATE
# ==============================
class PipelineState(TypedDict):
    messages:            List[str]
    cti_results:         List[dict]
    mitre_reports:       List[dict]
    aggregated_report:   dict
    prioritized_actions: List[dict]
    executive_summary:   dict
    dashboard_path:      str
    pdf_path:            str
    menaces_brutes:      List[dict]
    rapport_final:       dict
    alertes_envoyees:    int
    agent_logs:          List[dict]
    _thread_id:          Optional[str]


# ==============================
# UTILS
# ==============================
def sanitize_unicode(obj):
    """Remplace les tirets unicode (–, —, −) par des tirets ASCII pour FPDF."""
    if isinstance(obj, str):
        return re.sub(r"[\u2013\u2014\u2212]", "-", obj)
    if isinstance(obj, dict):
        return {k: sanitize_unicode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_unicode(i) for i in obj]
    return obj


# ==============================
# NODE 0 — WEB SEARCH
# ==============================
def web_search_node(state: PipelineState) -> dict:
    print("\n🌐 [NODE 0] Web Search")
    try:
        fetched = main_websearch()          # ← retourne list[str]
        if not isinstance(fetched, list):
            fetched = [str(fetched)]
    except Exception as e:
        print(f"⚠️ Web search error: {e}")
        fetched = []

    # ── NOUVEAU : reconstruire les dicts depuis les strings ──────────────
    import re
    menaces_dicts = []
    for msg in fetched:
        src   = re.search(r"^Source:\s*(.+)$",  msg, re.M)
        title = re.search(r"^Title:\s*(.+)$",   msg, re.M)
        url   = re.search(r"^URL:\s*(.+)$",     msg, re.M)
        score = re.search(r"^Threat Score:\s*(.+)$", msg, re.M)
        menaces_dicts.append({
            "source":       src.group(1).strip()   if src   else "Unknown",
            "title":        title.group(1).strip() if title else "",
            "link":         url.group(1).strip()   if url   else "",
            "threat_score": float(score.group(1))  if score else 0.0,
            "content":      msg,
        })

    return {
        "messages":       state.get("messages", []) + fetched,
        "menaces_brutes": menaces_dicts,   # ← list[dict] maintenant
    }


# ==============================
# NODE 1 — CTI ANALYSIS
# FIX 1 : stocker _source_message dans chaque résultat
# ==============================
def cti_analysis_node(state: PipelineState) -> dict:
    print("\n🧠 [NODE 1] CTI Analysis")

    messages  = state.get("messages", [])
    thread_id = state.get("_thread_id", "cti-run-001")
    results, logs = [], []

    for idx, msg in enumerate(messages):
        try:
            result = analyze_message(msg)

            # FIX 1 — conserver le message source dans le résultat
            result["_source_message"] = msg

            semantic = result.get("patterns", {}).get(
                "semantic_summary",
                str(result.get("threat_brief", ""))[:200]
            )

            logs.append({
                "agent":     "cti",
                "timestamp": datetime.now().isoformat(),
                "input":     msg,
                "output":    semantic,
                "tool_calls": [{"name": "analyze_message", "arguments": {"message": msg}}],
                "status":    "done",
            })

            results.append(result)

            # Soumettre pour évaluation RAGAS si thread ciblé
            submit_for_evaluation(
                job_id    = f"{thread_id}-msg-{idx}",
                cti_result = result,
                message   = msg,
                thread_id = thread_id,
            )

        except Exception as e:
            results.append({"error": str(e), "_source_message": msg})
            logs.append({
                "agent":     "cti",
                "timestamp": datetime.now().isoformat(),
                "input":     msg,
                "output":    str(e),
                "status":    "error",
            })

    return {
        "cti_results": results,
        "agent_logs":  state.get("agent_logs", []) + logs,
    }


# ==============================
# NODE 2 — MITRE
# FIX 1 : lire _source_message depuis le résultat, pas depuis messages[i]
# ==============================
def mitre_mapping_node(state: PipelineState) -> dict:
    print("\n🗺️ [NODE 2] MITRE Mapping")

    reports, logs = [], []
    valid = [r for r in state.get("cti_results", []) if "error" not in r]
    print(f"[MITRE NODE] {len(valid)} résultat(s) CTI valide(s)")

    for cti in valid:
        try:
            # FIX 1 — message source fiable, sans risque de désynchronisation
            msg_text = cti.get("_source_message", "")

            behaviors_raw = cti.get("behaviors", [])
            mitre_input   = cti.get("threat_brief", {}).get("mitre_input", {})
            print(f"[MITRE NODE] behaviors bruts  : {len(behaviors_raw)}")
            print(f"[MITRE NODE] behaviors fusion : {len(mitre_input.get('behaviors', []))}")
            
            # APRÈS (sécurisé + timeout)
            import threading
            
            result_holder = [None]
            error_holder  = [None]
            
            def _run_with_timeout():
                try:
                    result_holder[0] = run_mitre_analysis(cti)
                except Exception as e:
                    error_holder[0] = e
            
            t = threading.Thread(target=_run_with_timeout)
            t.start()
            t.join(timeout=300)  # 5 minutes max
            
            if t.is_alive():
                print("[MITRE NODE] ⚠️ Timeout — résultat minimal")
                reports.append({
                    "report_metadata": {"source": "timeout_fallback"},
                    "section_1_summary_context": {},
                    "section_2_key_takeaways": {},
                    "section_3_severity": {"global_level": "unknown", "global_score": 0.0},
                    "section_4_ttps": [],
                    "section_5_iocs_artifacts": {},
                    "section_6_mitigations": {},
                })
                continue
            
            if error_holder[0]:
                raise error_holder[0]
            
            mitre_res = result_holder[0]
            print(f"[MITRE NODE] status : {mitre_res.get('status')}")

            # Fix du crash AttributeError
            n_techs = mitre_res.get('techniques_mapped', 0)
            if isinstance(n_techs, dict):
                n_techs = n_techs.get('total_techniques', 0)
            print(f"[MITRE NODE] techniques : {n_techs}")

            rich = build_report_metadata(msg_text, cti, mitre_res)
            reports.append(rich)

            logs.append({
                "agent":     "mitre",
                "timestamp": datetime.now().isoformat(),
                "input":     str(cti)[:300],
                "output":    str(mitre_res.get("techniques_mapped", [])),
                "tool_calls": [{"name": "run_mitre_analysis", "arguments": {"cti": cti}}],
                "status":    "done",
            })

        except Exception as e:
            import traceback
            print(f"[MITRE NODE] ❌ {e}")
            print(traceback.format_exc())
            reports.append({"error": str(e)})

    return {
        "mitre_reports": reports,
        "agent_logs":    state.get("agent_logs", []) + logs,
    }


# ==============================
# NODE 3 — AGGREGATION
# FIX 7 : suppression du critère global_score > 0
# ==============================
def aggregation_node(state: PipelineState) -> dict:
    print("\n📊 [NODE 3] Aggregation")

    all_reports = state.get("mitre_reports", [])

    # FIX 7 — ne plus exclure les rapports avec global_score == 0
    valid = [
        r for r in all_reports
        if "error" not in r and r.get("report_metadata") is not None
    ]

    print(f"[AGG] {len(all_reports)} rapports reçus, {len(valid)} valides")

    if not valid:
        print("[AGG] ⚠️ Aucun rapport valide — vérifier MITRE mapping")
        return {
            "aggregated_report":   {"global_severity": "Unknown", "global_severity_score": 0.0},
            "prioritized_actions": [],
            "executive_summary":   {},
        }

    agg     = aggregate_reports(valid)
    actions = prioritize_actions(agg)
    summary = generate_executive_summary(agg)

    return {
        "aggregated_report":   agg,
        "prioritized_actions": actions,
        "executive_summary":   summary,
    }


# ==============================
# NODE 4 — DASHBOARD
# FIX D-1 : merger agrégat + premier rapport individuel
# ==============================
def dashboard_node(state: PipelineState) -> dict:
    print("\n📈 [NODE 4] Dashboard")

    agg     = state.get("aggregated_report", {})
    reports = state.get("mitre_reports", [])

    # FIX D-1 — le premier rapport individuel contient section_4_ttps,
    # behaviors, IOCs que generate_dashboard() cherche.
    # L'agrégat écrase les stats globales (severity, actor, etc.)
    first_valid = next((r for r in reports if "error" not in r), {})
    dashboard_data = {**first_valid, **agg}   # ← clé du fix

    result = generate_dashboard(
        dashboard_data,
        output=config.DASHBOARD_OUTPUT_PATH,
    )
    path = result.get("path", "") if isinstance(result, dict) else str(result)
    return {"dashboard_path": path}


# ==============================
# NODE 5 — PDF
# FIX 2 + FIX D-2 : rapport agrégé + section_3_severity corrigée
# ==============================
def pdf_node(state: PipelineState) -> dict:
    print("\n📄 [NODE 5] PDF")

    dash = state.get("dashboard_path", "")
    dash_path = dash.get("path", "") if isinstance(dash, dict) else dash

    agg     = state.get("aggregated_report", {})
    reports = state.get("mitre_reports", [])
    base    = next((r for r in reports if "error" not in r), {})

    # FIX D-2 — reconstruire section_3_severity depuis les stats globales
    # pour que le PDF affiche la severity agrégée (Critical) et non
    # la severity du 1er rapport individuel (Medium)
    agg_severity = {
        "global_score":        agg.get("global_severity_score", 0.0),
        "global_level":        agg.get("global_severity", "Unknown"),
        "chain_bonus_applied": 0.0,
        "overall_reasoning":   f"Aggregated from {len(reports)} report(s)",
        "distribution":        agg.get("statistics", {}).get("severity_distribution", {}),
        "environment_context": base.get("section_3_severity", {}).get(
                                   "environment_context", {}
                               ),
    }

    data = {
        **base,
        **{k: v for k, v in agg.items() if k not in ("report_metadata",)},
        "section_3_severity":  agg_severity,
        "dashboard_path":      dash_path,
        "executive_summary":   sanitize_unicode(state.get("executive_summary", {})),
    }

    output_path = config.PDF_REPORT_OUTPUT_PATH
    generate_pdf_report(report_data=data, output_filepath=output_path)

    return {"pdf_path": output_path}


# ==============================
# NODE 6 — NOTIFY
# FIX 3 : bare except → except Exception
# ==============================
def notify_node(state: PipelineState) -> dict:
    print("\n📢 [NODE 6] Notify")

    try:
        rapport, alertes = main_notify(
            state.get("pdf_path", ""),
            state.get("executive_summary", {}),
        )
    except Exception as e:   # FIX 3 — ne plus capturer KeyboardInterrupt
        print(f"[NOTIFY] ❌ Erreur d'envoi : {e}")
        rapport, alertes = {"error": str(e)}, 0

    return {
        "rapport_final":    rapport,
        "alertes_envoyees": alertes,
    }


# ==============================
# GRAPH
# FIX 4 : checkpoint SQLite
# ==============================
def build_pipeline():
    g = StateGraph(PipelineState)

    g.add_node("web",    web_search_node)
    g.add_node("cti",    cti_analysis_node)
    g.add_node("mitre",  mitre_mapping_node)
    g.add_node("agg",    aggregation_node)
    g.add_node("dash",   dashboard_node)
    g.add_node("pdf",    pdf_node)
    g.add_node("notify", notify_node)

    g.add_edge(START,    "web")
    g.add_edge("web",    "cti")
    g.add_edge("cti",    "mitre")
    g.add_edge("mitre",  "agg")
    g.add_edge("agg",    "dash")
    g.add_edge("dash",   "pdf")
    g.add_edge("pdf",    "notify")
    g.add_edge("notify", END)

    # FIX 4 — checkpoint SQLite pour reprise automatique
    # SqliteSaver(conn) — API correcte pour LangGraph >= 0.2
    # from_conn_string() est dépréciée et ne crée pas les tables
    try:
        import sqlite3
        from langgraph.checkpoint.sqlite import SqliteSaver
        db_path      = config.CHECKPOINT_DB_PATH
        conn         = sqlite3.connect(db_path, check_same_thread=False)
        checkpointer = SqliteSaver(conn)
        print(f"✅ Checkpoint SQLite actif : {db_path}")
        return g.compile(checkpointer=checkpointer)
    except ImportError:
        print("⚠️ langgraph-checkpoint-sqlite manquant — sans checkpoint")
        print("   → pip install langgraph-checkpoint-sqlite")
        return g.compile()
    except Exception as e:
        print(f"⚠️ Checkpoint désactivé : {e}")
        return g.compile()


# ==============================
# RUN
# FIX 5 : thread_id configurable
# ==============================
def run_pipeline(messages=None, thread_id: str = "cti-run-001"):
    """
    Lance ou reprend le pipeline CTI.

    Args:
        messages  : liste de messages CTI. Si None, web_search_node
                    les récupère automatiquement.
        thread_id : identifiant pour le checkpointer SQLite ET pour
                    le filtrage RAGAS (doit correspondre à
                    RAGAS_TARGET_THREAD_ID dans ragas_worker.py).
    """
    pipeline = build_pipeline()
    start_worker()

    initial_state: PipelineState = {
        "messages":            messages or [],
        "cti_results":         [],
        "mitre_reports":       [],
        "aggregated_report":   {},
        "prioritized_actions": [],
        "executive_summary":   {},
        "dashboard_path":      "",
        "pdf_path":            "",
        "menaces_brutes":      [],
        "rapport_final":       {},
        "alertes_envoyees":    0,
        "agent_logs":          [],
        "_thread_id":          thread_id,
    }

    # FIX 5 — thread_id transmis au checkpointer
    config = {"configurable": {"thread_id": thread_id}}

    return pipeline.invoke(initial_state, config=config)