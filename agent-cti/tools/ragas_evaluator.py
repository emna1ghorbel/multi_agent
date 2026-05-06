import json
import math
import asyncio
from pathlib import Path
from typing import Any, List, Optional

from ragas import evaluate
from ragas.run_config import RunConfig
from ragas.metrics import (
    faithfulness,
    answer_relevancy,
    context_precision,
    context_recall,
)
from ragas.dataset_schema import SingleTurnSample, EvaluationDataset
from langchain_core.language_models import BaseLLM
from langchain_core.outputs import LLMResult, Generation
# AJOUTER ces imports
from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from ragas.llms import LangchainLLMWrapper
from ragas.embeddings import LangchainEmbeddingsWrapper
from kaggle_secrets import UserSecretsClient
SCORES_FILE = Path("/kaggle/working/ragas_scores.jsonl")


class AsyncSafePipeline(BaseLLM):
    pipeline: Any
    model_name: str = "qwen-cti"

    class Config:
        arbitrary_types_allowed = True

    @property
    def _llm_type(self) -> str:
        return "async_safe_hf_pipeline"

    def _generate(self, prompts, stop=None, **kwargs):
        generations = []
        for prompt in prompts:
            try:
                output = self.pipeline(prompt, max_new_tokens=512, do_sample=False)
                if isinstance(output, list) and output:
                    text = output[0].get("generated_text", "")
                    if text.startswith(prompt):
                        text = text[len(prompt):].strip()
                else:
                    text = str(output)
            except Exception as e:
                text = f'{{"error": "{str(e)}"}}'
            generations.append([Generation(text=text)])
        return LLMResult(generations=generations)

    async def _agenerate(self, prompts, stop=None, **kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: self._generate(prompts, stop, **kwargs)
        )

    def _call(self, prompt, stop=None, **kwargs):
        return self._generate([prompt], stop, **kwargs).generations[0][0].text


def build_sample(answer: dict, question: str, tool_calls=None) -> SingleTurnSample:
    if not isinstance(answer, dict):
        raise ValueError(f"build_sample expects dict, got {type(answer)}")

    response_text = (
        answer.get("patterns", {}).get("semantic_summary")
        or answer.get("threat_brief", {}).get("attack_narrative")
        or answer.get("attack_narrative", "")
        or str(answer)[:500]
    )

    rag_results = answer.get("rag_context", [])
    if isinstance(rag_results, dict):
        rag_results = rag_results.get("results", [])
    retrieved_contexts = [str(r) for r in rag_results if r] if rag_results else []
    if not retrieved_contexts:
        retrieved_contexts = ["No RAG context available"]

    brief    = answer.get("threat_brief", {})
    patterns = answer.get("patterns", {})
    entities = answer.get("entities", {})

    threat_class  = patterns.get("threat_classification", "UNKNOWN")
    is_malicious  = patterns.get("is_malicious", False)
    kill_chain    = brief.get("kill_chain_stages", [])
    malware       = entities.get("malware_names",     [])
    ransomware    = entities.get("ransomware_groups", [])
    apt           = entities.get("apt_groups",        [])
    likely_actor  = brief.get("actor_profile", {}).get("likely_actor", "unknown")
    sectors       = brief.get("environment_context", {}).get("target_sector", [])

    ref_parts = [f"Threat classification: {threat_class}.", f"Malicious: {is_malicious}."]
    if malware:                   ref_parts.append(f"Malware: {', '.join(malware)}.")
    if ransomware:                ref_parts.append(f"Ransomware: {', '.join(ransomware)}.")
    if apt:                       ref_parts.append(f"APT: {', '.join(apt)}.")
    if likely_actor != "unknown": ref_parts.append(f"Actor: {likely_actor}.")
    if sectors:                   ref_parts.append(f"Sectors: {', '.join(sectors)}.")
    if kill_chain:                ref_parts.append(f"Kill chain: {', '.join(kill_chain)}.")

    return SingleTurnSample(
        user_input         = question,
        response           = response_text,
        retrieved_contexts = retrieved_contexts,
        reference          = " ".join(ref_parts),
    )


_METRICS = [faithfulness, answer_relevancy, context_precision, context_recall]
_WEIGHTS = {"faithfulness": 0.35, "answer_relevancy": 0.30,
            "context_precision": 0.20, "context_recall": 0.15}


def _to_float(val) -> float:
    if isinstance(val, list):
        valid = []
        for v in val:
            try:
                f = float(v)
                if not math.isnan(f): valid.append(f)
            except (TypeError, ValueError): pass
        return round(sum(valid) / len(valid), 3) if valid else 0.0
    if val is None: return 0.0
    try:
        f = float(val)
        return round(f, 3) if not math.isnan(f) else 0.0
    except (TypeError, ValueError): return 0.0


def run_rag_evaluation(samples, llm, embeddings) -> dict:
    dataset = EvaluationDataset(samples=samples)

    # ── Charger les clés ──────────────────────────────────────────
    from kaggle_secrets import UserSecretsClient
    from langchain_groq import ChatGroq
    from langchain_google_genai import GoogleGenerativeAIEmbeddings
    from ragas.llms import LangchainLLMWrapper
    from ragas.embeddings import LangchainEmbeddingsWrapper
    secrets        = UserSecretsClient()
    GOOGLE_API_KEY_2 = secrets.get_secret("GOOGLE_API_KEY_2")
    GROQ_API_KEY     = secrets.get_secret("GROQ_API_KEY")
    
    # Gemini pour Faithfulness
    gemini_llm = LangchainLLMWrapper(ChatGoogleGenerativeAI(
        model="gemini-flash-latest",
        google_api_key=GOOGLE_API_KEY_2,
        temperature=0
    ))
    
    # Groq pour les autres
    groq_llm = LangchainLLMWrapper(ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=GROQ_API_KEY,
        temperature=0
    ))
    # ── Groq LLM ─────────────────────────────────────────────────
    groq_llm = LangchainLLMWrapper(ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=GROQ_API_KEY,
        temperature=0
    ))
    
    # ── Embeddings Gemini ─────────────────────────────────────────  ← MANQUANT
    gemini_embeddings = LangchainEmbeddingsWrapper(GoogleGenerativeAIEmbeddings(
        model="models/gemini-embedding-001",
        google_api_key=GOOGLE_API_KEY_2
    ))
    
    faithfulness.llm            = gemini_llm   # ← Gemini
    faithfulness.strictness     = 1
    answer_relevancy.llm        = groq_llm     # ← Groq
    answer_relevancy.strictness = 1
    context_precision.llm       = groq_llm
    context_recall.llm          = groq_llm
    
    

    # ── Assigner embeddings à chaque métrique ────────────────────
    faithfulness.embeddings      = gemini_embeddings
    answer_relevancy.embeddings  = gemini_embeddings
    context_precision.embeddings = gemini_embeddings
    context_recall.embeddings    = gemini_embeddings

    run_config = RunConfig(max_retries=2, max_wait=60, timeout=120, max_workers=1)
    try:
        result = evaluate(dataset=dataset, metrics=_METRICS, run_config=run_config)
    except Exception as e:
        print(f"[RAGAS] ❌ evaluate() failed: {e}")
        return {"faithfulness": 0.0, "answer_relevancy": 0.0,
                "context_precision": 0.0, "context_recall": 0.0,
                "reliability_score": 0.0, "flags": ["EVALUATION_FAILED"], "error": str(e)}

    row = result.scores[0] if result.scores else {}
    f  = _to_float(row.get("faithfulness"))
    ar = _to_float(row.get("answer_relevancy"))
    cp = _to_float(row.get("context_precision"))
    cr = _to_float(row.get("context_recall"))

    reliability = (_WEIGHTS["faithfulness"] * f + _WEIGHTS["answer_relevancy"] * ar +
                   _WEIGHTS["context_precision"] * cp + _WEIGHTS["context_recall"] * cr)

    flags = []
    if f  < 0.50: flags.append("HIGH_HALLUCINATION_RISK")
    if ar < 0.50: flags.append("LOW_RELEVANCY")
    if cp < 0.50: flags.append("NOISY_RETRIEVAL")
    if cr < 0.50: flags.append("MISSING_CONTEXT")
    if reliability < 0.50: flags.append("UNRELIABLE_PIPELINE")

    return {"faithfulness": f, "answer_relevancy": ar, "context_precision": cp,
            "context_recall": cr, "reliability_score": round(reliability, 3), "flags": flags}

def save_scores(scores: dict) -> None:
    from datetime import datetime
    scores["timestamp"] = datetime.now().isoformat()
    with open(SCORES_FILE, "a") as f:
        f.write(json.dumps(scores) + "\n")


def load_scores() -> list:
    if not SCORES_FILE.exists():
        return []
    scores = []
    with open(SCORES_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                try:    scores.append(json.loads(line))
                except json.JSONDecodeError: pass
    return scores