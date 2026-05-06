import os

# ── Paths to data ───────────────────────────────────
FAISS_INDEX_PATH = "/kaggle/input/datasets/chaymadallel/cti-faiss-index"
JSONL_DATA_PATH  = "/kaggle/input/datasets/chaymadallel/dataa-1/darkgram_cti_final.jsonl"

# ── LLM & Embedding ──────────────────────────────────
EMBEDDING_MODEL = "sentence-transformers/all-mpnet-base-v2"
LLM_MODEL = "Qwen/Qwen2.5-7B-Instruct"
TEMPERATURE = 0.1

# RAG & Hybrid Logic
RAG_TOP_K = 3
WEIGHTS = {
    "static":      0.5,   
    "llm":         0.35,   
    "statistical": 0.15,   
}
