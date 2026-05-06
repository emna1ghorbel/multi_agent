# verify_after_pipeline.py
from transformers import AutoTokenizer
from load_documents import load_and_prepare

tokenizer = AutoTokenizer.from_pretrained(
    "sentence-transformers/all-mpnet-base-v2"
)

docs = load_and_prepare()

over = 0
max_tok = 0

for doc in docs:
    tok = len(tokenizer.encode(doc.page_content))
    if tok > 384:
        over += 1
    max_tok = max(max_tok, tok)

print(f"\nAPRÈS PIPELINE COMPLET :")
print(f"  Total documents  : {len(docs)}")
print(f"  > 384 tokens     : {over}")
print(f"  Max tokens       : {max_tok}")
# Objectif : over = 0, max_tok < 384