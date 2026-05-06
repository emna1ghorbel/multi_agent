# verify_split.py
from transformers import AutoTokenizer
import json
import re

tokenizer = AutoTokenizer.from_pretrained(
    "sentence-transformers/all-mpnet-base-v2"
)

def extract_content(text):
    match = re.search(r'CONTENT:\s*(.+)$', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()

# Trouve les 5 plus longs pour voir ce qu'ils contiennent
long_docs = []

with open('darkgram_cti_final.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        obj = json.loads(line)
        content = extract_content(obj['text'])
        tok = len(tokenizer.encode(content))
        if tok > 384:
            long_docs.append({
                'tokens': tok,
                'type': obj['metadata'].get('doc_type', ''),
                'channel': obj['metadata'].get('channel_name', ''),
                'category': obj['metadata'].get('category', ''),
                'preview': content[:150] + '...',
            })

# Trier par tokens décroissant
long_docs.sort(key=lambda x: x['tokens'], reverse=True)

print(f"Total docs > 384 tokens : {len(long_docs)}")
print(f"\nTOP 10 les plus longs :")
print(f"{'─'*70}")

for i, doc in enumerate(long_docs[:10]):
    print(f"\n  #{i+1} | {doc['tokens']} tokens")
    print(f"  Type     : {doc['type']}")
    print(f"  Channel  : {doc['channel']}")
    print(f"  Category : {doc['category']}")
    print(f"  Preview  : {doc['preview']}")

# Répartition par catégorie
print(f"\n{'─'*70}")
print(f"Répartition des docs longs par catégorie :")
from collections import Counter
cats = Counter(d['category'] for d in long_docs)
for cat, count in cats.most_common():
    print(f"  {cat.ljust(30)} : {count}")

types = Counter(d['type'] for d in long_docs)
print(f"\nRépartition par type :")
for t, count in types.most_common():
    print(f"  {t.ljust(20)} : {count}")