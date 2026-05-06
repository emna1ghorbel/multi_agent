"""
TOOL 2 — RAG Search
====================
Searches a pre-built FAISS vector index of historical Telegram CTI messages
to find past threats similar to the current message being analyzed.

"""

import json
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.tools import tool
import config

INDEX_PATH = config.FAISS_INDEX_PATH
MODEL_NAME = config.EMBEDDING_MODEL

# Module-level cache so the vectorstore is only loaded once per process
_vectorstore = None


def _get_vectorstore() -> FAISS:
    """
    Lazily load the FAISS vectorstore from disk.
    Subsequent calls return the cached instance without reloading.
    The model runs on CPU to preserve GPU memory for LLM inference.
    """
    global _vectorstore
    if _vectorstore is None:
        embeddings = HuggingFaceEmbeddings(
            model_name=MODEL_NAME,
            model_kwargs={"device": "cpu"},
        )
        _vectorstore = FAISS.load_local(
            INDEX_PATH,
            embeddings,
            allow_dangerous_deserialization=True,
        )
    return _vectorstore


@tool
def rag_search(query: str, k: int = 3) -> str:
    """
    Search the Telegram CTI database for messages similar to the given query.

    Uses L2 (Euclidean) distance — a LOWER score means a CLOSER (more similar) match.

    Args:
        query: Natural-language description or raw IOC text to search for
        k    : Number of top results to return (default: 3)

    Returns:
        JSON string with the query and a list of matched documents,
        each including its similarity score, content snippet, channel, and date.
    """
    vs = _get_vectorstore()

    # similarity_search_with_score returns (Document, float) pairs
    # For FAISS with L2 distance: lower score = more similar
    results_with_scores = vs.similarity_search_with_score(query, k=k)

    formatted_results = []
    for doc, score in results_with_scores:
        formatted_results.append({
            "score":   round(float(score), 4),
            "content": doc.page_content[:500],           # truncate to avoid token overload
            "channel": doc.metadata.get("channel_name", "unknown"),
            "date":    doc.metadata.get("date", ""),
        })

    return json.dumps({"query": query, "results": formatted_results})
