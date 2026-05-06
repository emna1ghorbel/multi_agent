# test_scores.py
"""
Diagnostique les scores réels de FAISS
pour calibrer le seuil de pertinence.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from create_index import load_index

vectorstore = load_index()

# Questions de test CTI
questions = [
    "cracking tools",
    "stolen credentials",
    "cloud logs",
    "pirated software",
    "hacking tutorial",
    "combo list mail pass",
    "carding credit card",
    "malware android",
]

print("═" * 60)
print("  DIAGNOSTIC DES SCORES FAISS")
print("═" * 60)

for q in questions:
    results = vectorstore.similarity_search_with_score(
        query=q,
        k=5,
    )
    
    print(f"\n🔍 Query: '{q}'")
    print(f"{'─' * 55}")
    
    for doc, score in results:
        content = doc.page_content[:80]
        doc_type = doc.metadata.get("doc_type", "?")
        print(
            f"  Score: {score:.4f} | "
            f"Type: {doc_type:15s} | "
            f"{content}..."
        )

print(f"\n{'═' * 60}")
print("  RÉSUMÉ")
print("═" * 60)

# Collecte tous les scores pour analyse
all_scores = []
for q in questions:
    results = vectorstore.similarity_search_with_score(
        query=q, k=10,
    )
    for _, score in results:
        all_scores.append(score)

all_scores.sort()

print(f"  Score min     : {min(all_scores):.4f}")
print(f"  Score max     : {max(all_scores):.4f}")
print(f"  Score médian  : {all_scores[len(all_scores)//2]:.4f}")
print(f"  Score moyen   : {sum(all_scores)/len(all_scores):.4f}")

print(f"\n  Distribution :")
for threshold in [0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0]:
    count = sum(1 for s in all_scores if s <= threshold)
    pct = 100 * count / len(all_scores)
    bar = "█" * int(pct / 2)
    print(f"  ≤ {threshold:.2f} : {pct:5.1f}% {bar}")

print(f"\n💡 Recommandation seuil : utilise la valeur")
print(f"   où ~80% des résultats pertinents passent")