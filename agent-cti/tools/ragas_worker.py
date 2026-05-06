# # %%writefile /kaggle/working/ragas_worker.py

# # import threading
# # import queue
# # import json

# # from langchain_huggingface import HuggingFacePipeline
# # from langchain_community.embeddings import HuggingFaceEmbeddings

# # from llm_helper import get_llm
# # import threading

# # _eval_counter = 0
# # _eval_lock = threading.Lock()
# # try:
# #     from ragas_evaluator import build_sample, run_rag_evaluation, save_scores
# #     _ragas_available = True
# # except ImportError as e:
# #     print(f"[RAGAS] ⚠️ ragas_evaluator unavailable: {e}")
# #     _ragas_available = False
# # EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

# # _eval_queue = queue.Queue()
# # _worker_started = False


# # # ================================================================
# # # Utilities
# # # ================================================================

# # def sanitize_json_payload(payload):
# #     """
# #     Nettoie toute sortie avant envoi à RAGAS :
# #     - supprime ```json ``` et ```
# #     - supprime le texte hors { ... }
# #     - safe : ne lève jamais
# #     """
# #     if not isinstance(payload, str):
# #         return payload

# #     text = payload.strip()

# #     # Supprimer markdown ```json
# #     if text.startswith("```"):
# #         parts = text.split("```")
# #         if len(parts) >= 2:
# #             text = parts[1].strip()

# #     # Extraire contenu JSON
# #     try:
# #         start = text.find("{")
# #         end = text.rfind("}") + 1
# #         if start != -1 and end != -1:
# #             return text[start:end]
# #     except Exception:
# #         pass

# #     return text


# # def extract_tool_calls(cti_result):
# #     """
# #     Extrait les tool_calls s'ils existent dans le résultat CTI.
# #     Compatible avec les logs LangGraph.
# #     """
# #     tool_calls = []

# #     # Cas direct
# #     if isinstance(cti_result, dict) and "tool_calls" in cti_result:
# #         return cti_result["tool_calls"]

# #     # Cas imbriqué (agent_logs)
# #     if isinstance(cti_result, dict):
# #         logs = cti_result.get("agent_logs", [])
# #         for log in logs:
# #             if "tool_calls" in log:
# #                 tool_calls.extend(log["tool_calls"])

# #     return tool_calls


# # # ================================================================
# # # Worker loop
# # # ================================================================

# # def _worker_loop():
# #     if not _ragas_available:
# #         print("[RAGAS] ⚠️ Worker stopped — ragas_evaluator not available")
# #         return

# #     pipe, _ = get_llm()
# #     llm = HuggingFacePipeline(pipeline=pipe)
# #     embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)

# #     while True:
# #         job = _eval_queue.get()
# #         if job is None:
# #             break

# #         try:
# #             # ✅ Nettoyage strict
# #             clean_message = sanitize_json_payload(job["message"])
# #             raw_result = job["cti_result"]

# #             # ✅ Forcer JSON → dict Python
# #             if isinstance(raw_result, str):
# #                 cleaned = sanitize_json_payload(raw_result)
# #                 clean_result = json.loads(cleaned)
# #             elif isinstance(raw_result, dict):
# #                 clean_result = raw_result
# #             else:
# #                 raise TypeError("cti_result must be dict or JSON string")

# #             # ✅ Extraction tool calls
# #             tool_calls = extract_tool_calls(clean_result)

# #             # ✅ Build RAGAS sample enrichi
# #             sample = build_sample(
# #                 answer=clean_result,
# #                 question=clean_message,
# #                 tool_calls=tool_calls,   # 🔑 clé manquante avant
# #             )

# #             scores = run_rag_evaluation([sample], llm, embeddings)
# #             scores["job_id"] = job["job_id"]

# #             save_scores(scores)

# #             print(f"\n[RAGAS] ✅ Job {job['job_id']}")
# #             print(f"  Tool accuracy : {scores.get('tool_call_accuracy')}")
# #             print(f"  Faithfulness  : {scores.get('faithfulness')}")
# #             print(f"  Relevancy     : {scores.get('answer_relevancy')}")
# #             print(f"  Ctx Precision : {scores.get('context_precision')}")
# #             print(f"  Ctx Recall    : {scores.get('context_recall')}")

# #         except Exception as e:
# #             print(f"[RAGAS] ❌ Job {job['job_id']} failed: {e}")

# #         finally:
# #             _eval_queue.task_done()


# # # ================================================================
# # # API
# # # ================================================================

# # def start_worker():
# #     global _worker_started
# #     if not _worker_started:
# #         t = threading.Thread(target=_worker_loop, daemon=True)
# #         t.start()
# #         _worker_started = True
# #         print("[RAGAS] ✅ Worker started")


# # def submit_for_evaluation(job_id: str, cti_result: dict, message: str):
# #     global _eval_counter

# #     is_critical = cti_result.get("is_malicious", False)

# #     with _eval_lock:
# #         _eval_counter += 1
# #         # Évaluer si : malveillant, OU 1er message, OU tous les 3
# #         should_eval = is_critical or _eval_counter == 1 or (_eval_counter % 3 == 0)

# #     if not should_eval:
# #         return

# #     _eval_queue.put({
# #         "job_id":     job_id,
# #         "cti_result": cti_result,
# #         "message":    message,
# #     })


# import queue
# import json

# from langchain_community.embeddings import HuggingFaceEmbeddings
# from llm_helper import get_llm

# try:
#     from ragas_evaluator import (
#         AsyncSafePipeline,
#         build_sample,
#         run_rag_evaluation,
#         save_scores,
#     )
#     _ragas_available = True
# except ImportError as e:
#     print(f"[RAGAS] ragas_evaluator unavailable: {e}")
#     _ragas_available = False

# EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

# # ← Changer ici pour cibler un autre thread
# RAGAS_TARGET_THREAD_ID = "cti-run-001"

# # Queue de taille 1 : 1 seul job à la fois, les autres ignorés
# _eval_queue = queue.Queue(maxsize=1)

# _llm_singleton        = None
# _embeddings_singleton = None


# def _sanitize_payload(payload):
#     if not isinstance(payload, str):
#         return payload
#     text = payload.strip()
#     if text.startswith("```"):
#         parts = text.split("```")
#         if len(parts) >= 2:
#             text = parts[1].strip()
#     try:
#         start = text.find("{")
#         end   = text.rfind("}")
#         if start != -1 and end != -1:
#             return text[start:end + 1]
#     except Exception:
#         pass
#     return text


# def _extract_tool_calls(cti_result):
#     tool_calls = []
#     if isinstance(cti_result, dict) and "tool_calls" in cti_result:
#         return cti_result["tool_calls"]
#     if isinstance(cti_result, dict):
#         for log in cti_result.get("agent_logs", []):
#             if "tool_calls" in log:
#                 tool_calls.extend(log["tool_calls"])
#     return tool_calls


# def _get_models():
#     global _llm_singleton, _embeddings_singleton
#     if _llm_singleton is None:
#         pipe, _ = get_llm()
#         _llm_singleton        = AsyncSafePipeline(pipeline=pipe)
#         _embeddings_singleton = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
#         print("[RAGAS] Models loaded.")
#     return _llm_singleton, _embeddings_singleton


# def submit_for_evaluation(job_id: str, cti_result: dict, message: str,
#                           thread_id: str = ""):
#     """
#     Dépose dans la queue UNIQUEMENT si thread_id == RAGAS_TARGET_THREAD_ID.
#     Non bloquant — les autres threads CTI/MITRE ne sont jamais bloqués.
#     """
#     if not _ragas_available:
#         return
#     if thread_id != RAGAS_TARGET_THREAD_ID:
#         return  # thread non ciblé → ignoré silencieusement
#     try:
#         _eval_queue.put_nowait({
#             "job_id":     job_id,
#             "cti_result": cti_result,
#             "message":    message,
#             "thread_id":  thread_id,
#         })
#         print(f"[RAGAS] Job {job_id} queued for thread '{thread_id}'")
#     except queue.Full:
#         print(f"[RAGAS] Queue full — job {job_id} skipped")


# def evaluate_one_now() -> dict:
#     """
#     Consomme 1 seul job et l'évalue directement dans le thread notebook.
#     Appelé manuellement APRÈS run_pipeline() → pas de conflit asyncio.
#     """
#     if not _ragas_available:
#         return {"error": "ragas_not_available"}

#     print(f"[RAGAS] Waiting for job (target: '{RAGAS_TARGET_THREAD_ID}')...")
#     job = _eval_queue.get()  # bloquant jusqu'au job disponible

#     try:
#         raw = job["cti_result"]
#         cti_result = json.loads(_sanitize_payload(raw)) if isinstance(raw, str) else raw
#         message    = _sanitize_payload(job["message"])
#         tool_calls = _extract_tool_calls(cti_result)

#         print(f"[RAGAS] Evaluating job '{job['job_id']}' thread '{job.get('thread_id')}'...")

#         sample = build_sample(answer=cti_result, question=message, tool_calls=tool_calls)
#         llm, embeddings = _get_models()

#         scores = run_rag_evaluation([sample], llm, embeddings)
#         scores["job_id"]    = job["job_id"]
#         scores["thread_id"] = job.get("thread_id", "")
#         save_scores(scores)

#         print(f"[RAGAS] ✅ Done — job '{job['job_id']}'")
#         return scores

#     except Exception as e:
#         print(f"[RAGAS] ❌ Failed: {e}")
#         return {"error": str(e), "job_id": job.get("job_id", "?")}
#     finally:
#         _eval_queue.task_done()
"""
ragas_worker.py — PRODUCTION VERSION
======================================
CORRECTIONS vs version commentée :
  FIX W-1 : Import AsyncSafePipeline depuis ragas_evaluator (était manquant
             → ImportError → _ragas_available = False → "ragas_not_available")

  FIX W-2 : evaluate_one_now() est appelé SYNCHRONEMENT dans le thread
             notebook, après run_pipeline(). Pas de thread daemon asyncio —
             élimine IndexError: pop from an empty deque.

  FIX W-3 : submit_for_evaluation() filtre par thread_id == RAGAS_TARGET_THREAD_ID.
             Avec 1 seul message, _eval_counter==1, 1%3!=0 → le job était
             silencieusement ignoré. Désormais tout job du thread cible passe.

  FIX W-4 : Queue maxsize=1 — si le pipeline produit plusieurs CTI results,
             seul le dernier est conservé pour évaluation.
"""

import queue
import json

from langchain_community.embeddings import HuggingFaceEmbeddings
from llm_helper import get_llm

try:
    from ragas_evaluator import (
        AsyncSafePipeline,   # FIX W-1 — était manquant → ImportError
        build_sample,
        run_rag_evaluation,
        save_scores,
    )
    _ragas_available = True
    print("[RAGAS] ✅ ragas_evaluator imported successfully")
except ImportError as e:
    print(f"[RAGAS] ⚠️ ragas_evaluator unavailable: {e}")
    _ragas_available = False

EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"

# Thread cible : seuls les jobs de ce thread sont évalués
RAGAS_TARGET_THREAD_ID = "cti-run-001"

# FIX W-4 — Queue de taille 1 : 1 seul job à la fois
_eval_queue = queue.Queue(maxsize=1)

# Singletons LLM/embeddings — chargés une seule fois au premier evaluate_one_now()
_llm_singleton        = None
_embeddings_singleton = None


# =============================================================================
# UTILITIES
# =============================================================================

def _sanitize_payload(payload):
    """Nettoie les backticks markdown que Qwen ajoute parfois en sortie."""
    if not isinstance(payload, str):
        return payload
    text = payload.strip()
    if text.startswith("```"):
        parts = text.split("```")
        if len(parts) >= 2:
            text = parts[1].strip()
            # Enlever le label de langage (```json → "json\n{...")
            if "\n" in text:
                first_line = text.split("\n")[0].strip()
                if first_line in ("json", "python", ""):
                    text = text[len(first_line):].strip()
    try:
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end != -1:
            return text[start:end + 1]
    except Exception:
        pass
    return text


def _extract_tool_calls(cti_result: dict) -> list:
    """Extrait les tool_calls depuis un résultat CTI ou ses agent_logs."""
    tool_calls = []
    if isinstance(cti_result, dict) and "tool_calls" in cti_result:
        return cti_result["tool_calls"]
    if isinstance(cti_result, dict):
        for log in cti_result.get("agent_logs", []):
            if "tool_calls" in log:
                tool_calls.extend(log["tool_calls"])
    return tool_calls

# def _get_models():
#     global _llm_singleton, _embeddings_singleton
#     if _llm_singleton is None:
#         print("[RAGAS] Loading models (first call)...")

#         from kaggle_secrets import UserSecretsClient
#         from langchain_groq import ChatGroq
    #     from langchain_google_genai import GoogleGenerativeAIEmbeddings
    #     from ragas.llms import LangchainLLMWrapper
    #     from ragas.embeddings import LangchainEmbeddingsWrapper

    #     secrets = UserSecretsClient()
    #     GROQ_API_KEY   = secrets.get_secret("GROQ_API_KEY")
    #     GOOGLE_API_KEY = secrets.get_secret("GOOGLE_API_KEY")

    #     # LLM juge — Groq supporte multiple candidates
    #     _llm_singleton = LangchainLLMWrapper(ChatGroq(
    #         model="llama-3.3-70b-versatile",
    #         api_key=GROQ_API_KEY,
    #         temperature=0
    #     ))

    #     # Embeddings — Gemini (ta clé fonctionne pour les embeddings)
    #     _embeddings_singleton = LangchainEmbeddingsWrapper(
    #         GoogleGenerativeAIEmbeddings(
    #             model="models/gemini-embedding-001",
    #             google_api_key=GOOGLE_API_KEY
    #         )
    #     )

    #     print("[RAGAS] ✅ Models loaded.")
    # return _llm_singleton, _embeddings_singleton

def _get_models():
    global _llm_singleton, _embeddings_singleton
    if _llm_singleton is None:
        print("[RAGAS] Loading models (first call)...")
        # LLM et embeddings gérés directement dans run_rag_evaluation()
        _llm_singleton        = "gemini+groq"  # placeholder
        _embeddings_singleton = "gemini"        # placeholder
        print("[RAGAS] ✅ Models loaded.")
    return _llm_singleton, _embeddings_singleton
# =============================================================================
# FIX W-3 — submit_for_evaluation : filtre par thread_id, pas par compteur
# =============================================================================

def submit_for_evaluation(
    job_id:     str,
    cti_result: dict,
    message:    str,
    thread_id:  str = "",
) -> None:
    """
    Dépose un job dans la queue UNIQUEMENT si :
      - RAGAS est disponible
      - thread_id == RAGAS_TARGET_THREAD_ID

    Non bloquant — put_nowait() ignore si la queue est pleine.
    """
    if not _ragas_available:
        return

    if thread_id != RAGAS_TARGET_THREAD_ID:
        # Thread non ciblé — ignorer silencieusement
        return

    try:
        _eval_queue.put_nowait({
            "job_id":     job_id,
            "cti_result": cti_result,
            "message":    message,
            "thread_id":  thread_id,
        })
        print(f"[RAGAS] Job '{job_id}' queued (thread: '{thread_id}')")
    except queue.Full:
        # Remplacer l'ancien job par le nouveau
        try:
            _eval_queue.get_nowait()
        except queue.Empty:
            pass
        try:
            _eval_queue.put_nowait({
                "job_id":     job_id,
                "cti_result": cti_result,
                "message":    message,
                "thread_id":  thread_id,
            })
            print(f"[RAGAS] Job '{job_id}' replaced previous job in queue")
        except queue.Full:
            print(f"[RAGAS] ⚠️ Queue still full — job '{job_id}' skipped")


# =============================================================================
# FIX W-2 — evaluate_one_now : synchrone, appelé dans le thread notebook
# Pas de thread daemon → pas de conflit asyncio → pas de IndexError deque
# =============================================================================

def evaluate_one_now(timeout: float = 300.0) -> dict:
    """
    Consomme et évalue 1 job directement dans le thread courant.

    USAGE dans le notebook :
        state  = run_pipeline([...], thread_id="cti-run-001")
        scores = evaluate_one_now()   # appelé APRÈS run_pipeline()

    Args:
        timeout: secondes à attendre qu'un job soit disponible (défaut 5min)

    Returns:
        dict avec faithfulness, answer_relevancy, context_precision,
        context_recall, reliability_score, flags, job_id, thread_id
    """
    if not _ragas_available:
        return {"error": "ragas_not_available"}

    print(f"[RAGAS] Waiting for job (target thread: '{RAGAS_TARGET_THREAD_ID}')...")

    try:
        # Attente bloquante avec timeout
        job = _eval_queue.get(timeout=timeout)
    except queue.Empty:
        return {
            "error":    "timeout",
            "message":  f"No job received within {timeout}s. "
                        f"Check that submit_for_evaluation() was called with "
                        f"thread_id='{RAGAS_TARGET_THREAD_ID}'.",
        }

    try:
        # Nettoyage et désérialisation du résultat CTI
        raw = job["cti_result"]
        if isinstance(raw, str):
            cti_result = json.loads(_sanitize_payload(raw))
        elif isinstance(raw, dict):
            cti_result = raw
        else:
            raise TypeError(f"cti_result must be dict or JSON string, got {type(raw)}")

        message    = _sanitize_payload(str(job["message"]))
        tool_calls = _extract_tool_calls(cti_result)

        print(f"[RAGAS] Evaluating job '{job['job_id']}' (thread: '{job.get('thread_id')}')...")

        sample = build_sample(
            answer     = cti_result,
            question   = message,
            tool_calls = tool_calls,
        )

        llm, embeddings = _get_models()
        scores = run_rag_evaluation([sample], llm, embeddings)

        scores["job_id"]    = job["job_id"]
        scores["thread_id"] = job.get("thread_id", "")

        save_scores(scores)

        print(f"[RAGAS] ✅ Evaluation done — job '{job['job_id']}'")
        print(f"  Reliability   : {scores.get('reliability_score', 0):.3f}")
        print(f"  Faithfulness  : {scores.get('faithfulness', 0):.3f}")
        print(f"  Relevancy     : {scores.get('answer_relevancy', 0):.3f}")
        print(f"  Ctx Precision : {scores.get('context_precision', 0):.3f}")
        print(f"  Ctx Recall    : {scores.get('context_recall', 0):.3f}")
        if scores.get("flags"):
            print(f"  ⚠️  Flags      : {', '.join(scores['flags'])}")

        return scores

    except Exception as e:
        import traceback
        print(f"[RAGAS] ❌ Evaluation failed: {e}")
        print(traceback.format_exc())
        return {"error": str(e), "job_id": job.get("job_id", "?")}

    finally:
        _eval_queue.task_done()


# =============================================================================
# start_worker — stub pour compatibilité avec graph.py
# (le worker thread est désactivé — evaluate_one_now() remplace)
# =============================================================================

def start_worker() -> None:
    """
    Stub de compatibilité — ne démarre plus de thread daemon.
    L'évaluation RAGAS est maintenant synchrone via evaluate_one_now().
    Gardé pour éviter ImportError dans graph.py si appelé.
    """
    if not _ragas_available:
        print("[RAGAS] ⚠️ RAGAS not available — worker disabled")
        return
    print("[RAGAS] ✅ Worker ready (synchronous mode — call evaluate_one_now() after pipeline)")