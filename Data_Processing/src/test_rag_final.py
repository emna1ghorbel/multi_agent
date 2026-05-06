# test_rag.py
"""
Test de performance et détection d'hallucinations.
Évalue la qualité du pipeline RAG CTI.
"""
import sys
import re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from create_index import load_index
from rag_chain import CTIAgent

vectorstore = load_index()
agent = CTIAgent(vectorstore)


# ══════════════════════════════════════════════
# TEST 1 : Questions hors-sujet (doit REJETER)
# ══════════════════════════════════════════════

off_topic = [
    "hello how are you?",
    "what is the weather today?",
    "merci beaucoup",
    "hi",
    "who are you?",
    "tell me a joke",
]

print("═" * 60)
print("  TEST 1 : Questions hors-sujet (doit rejeter)")
print("═" * 60)

pass_count = 0
for q in off_topic:
    result = agent.analyze(q, verbose=False)
    has_sources = len(result["sources"]) > 0
    if has_sources:
        status = "❌ FAIL (a retourné des sources)"
    else:
        status = "✅ PASS"
        pass_count += 1
    print(f"  {status} | '{q}'")

print(f"\n  Résultat : {pass_count}/{len(off_topic)} rejetées")


# ══════════════════════════════════════════════
# TEST 2 : Questions CTI (doit RÉPONDRE)
# ══════════════════════════════════════════════

on_topic = [
    {
        "question": "What cracking tools are shared?",
        "expected_post": "573",
        "expected_channel": "hackingandcrackingtools",
    },
    {
        "question": "What are dark method cloud logs?",
        "expected_post": "381",
        "expected_channel": "hackingandcrackingtools",
    },
    {
        "question": "What cloud logs are available?",
        "expected_post": None,
        "expected_channel": None,
    },
    {
        "question": "What stolen credentials are sold?",
        "expected_post": None,
        "expected_channel": None,
    },
    {
        "question": "What pirated software is shared?",
        "expected_post": None,
        "expected_channel": None,
    },
    {
        "question": "combo list mail pass",
        "expected_post": None,
        "expected_channel": None,
    },
    {
        "question": "carding credit card stolen",
        "expected_post": None,
        "expected_channel": None,
    },
    {
        "question": "android malware telegram",
        "expected_post": None,
        "expected_channel": None,
    },
]

print(f"\n{'═' * 60}")
print("  TEST 2 : Questions CTI (doit répondre)")
print("═" * 60)

pass_count = 0
for test in on_topic:
    q = test["question"]
    result = agent.analyze(q, verbose=False)
    has_sources = len(result["sources"]) > 0

    if not has_sources:
        print(f"  ❌ FAIL (aucune source) | '{q}'")
        continue

    top_score = result["sources"][0]["score"]
    top_post = result["sources"][0]["post_id"]
    top_channel = result["sources"][0]["channel"]

    # Vérifie si le post attendu est trouvé
    found_expected = True
    if test["expected_post"]:
        source_ids = [s["post_id"] for s in result["sources"]]
        if test["expected_post"] not in source_ids:
            found_expected = False

    if found_expected:
        status = "✅ PASS"
        pass_count += 1
    else:
        status = "⚠️  MISS"

    print(
        f"  {status} | '{q}'\n"
        f"         Top: POST {top_post} | "
        f"{top_channel} | Score: {top_score:.3f} | "
        f"Sources: {len(result['sources'])} | "
        f"Replies: {sum(s['replies'] for s in result['sources'])}"
    )

    if test["expected_post"] and not found_expected:
        print(
            f"         ⚠️  POST {test['expected_post']} attendu "
            f"mais non trouvé dans les sources"
        )

print(f"\n  Résultat : {pass_count}/{len(on_topic)} réussis")


# ══════════════════════════════════════════════
# TEST 3 : Anti-hallucination
# ══════════════════════════════════════════════

print(f"\n{'═' * 60}")
print("  TEST 3 : Anti-hallucination (doit avouer ignorance)")
print("═" * 60)

trick_questions = [
    "What ransomware attacks target hospitals in Japan?",
    "Which APT groups use zero-day exploits on Linux?",
    "Tell me about North Korean hackers on Telegram",
    "What are the latest CVE vulnerabilities in Apache?",
]

pass_count = 0
for q in trick_questions:
    result = agent.analyze(q, verbose=False)
    analysis = result["analysis"].lower()

    # Mots-clés d'honnêteté
    honesty_keywords = [
        "insufficient", "no relevant", "not enough",
        "no data", "cannot", "not found",
        "no specific", "not explicitly",
        "does not contain", "no direct",
        "limited", "no evidence",
        "not mentioned", "no mention",
        "beyond the scope", "not available",
    ]

    is_honest = any(kw in analysis for kw in honesty_keywords)
    no_sources = len(result["sources"]) == 0

    if no_sources:
        status = "✅ PASS (aucune source)"
        pass_count += 1
    elif is_honest:
        status = "✅ PASS (avoue manque de données)"
        pass_count += 1
    else:
        status = "⚠️  CHECK (possible hallucination)"

    print(f"  {status} | '{q}'")
    if not no_sources and not is_honest:
        print(f"         Sources: {len(result['sources'])}")
        print(f"         Début réponse: {analysis[:120]}...")

print(f"\n  Résultat : {pass_count}/{len(trick_questions)} honnêtes")


# ══════════════════════════════════════════════
# TEST 4 : Cohérence sources vs réponse
# ══════════════════════════════════════════════

print(f"\n{'═' * 60}")
print("  TEST 4 : Cohérence sources citées vs retournées")
print("═" * 60)

test_questions = [
    "What cracking tools are shared?",
    "What are dark method cloud logs?",
]

pass_count = 0
total_checks = 0

for q in test_questions:
    result = agent.analyze(q, verbose=False)

    if not result["sources"]:
        print(f"  ⏭️  SKIP | '{q}' (aucune source)")
        continue

    # POST_IDs retournés par le retriever
    source_ids = set(
        s["post_id"] for s in result["sources"]
        if s["post_id"]
    )

    # POST_IDs cités dans l'analyse du LLM
    cited_ids = set(
        re.findall(r'POST_ID:\s*(\d+)', result["analysis"])
    )

    print(f"\n  Question : '{q}'")
    print(f"  Sources retournées : {source_ids}")
    print(f"  Sources citées LLM : {cited_ids}")

    # Vérifie que chaque ID cité existe dans les sources
    for cid in cited_ids:
        total_checks += 1
        if cid in source_ids:
            print(f"    ✅ POST {cid} cité et présent")
            pass_count += 1
        else:
            print(f"    ❌ POST {cid} cité mais ABSENT des sources")

    if not cited_ids:
        print(f"    ⚠️  Aucun POST_ID cité dans l'analyse")

if total_checks > 0:
    print(
        f"\n  Résultat : {pass_count}/{total_checks} "
        f"citations cohérentes"
    )
else:
    print(f"\n  Résultat : Aucune citation à vérifier")


# ══════════════════════════════════════════════
# TEST 5 : Replies récupérées
# ══════════════════════════════════════════════

print(f"\n{'═' * 60}")
print("  TEST 5 : Récupération des replies (engagement)")
print("═" * 60)

result = agent.analyze(
    "What are dark method cloud logs?",
    verbose=False
)

for s in result["sources"]:
    reply_info = (
        f"Replies: {s['replies']}"
        if s['replies'] > 0
        else "No replies"
    )
    print(
        f"  POST {s['post_id']} | "
        f"{s['channel']} | "
        f"{reply_info}"
    )

total_replies = sum(s["replies"] for s in result["sources"])
print(f"\n  Total replies récupérées : {total_replies}")
print(f"  Note : Les replies indiquent l'ENGAGEMENT")
print(f"         communautaire, pas la qualité du post")


# ══════════════════════════════════════════════
# RÉSUMÉ GLOBAL
# ══════════════════════════════════════════════

print(f"\n{'═' * 60}")
print("  📊 RÉSUMÉ GLOBAL")
print("═" * 60)
print(f"  Test 1 (Hors-sujet)     : Voir résultats ci-dessus")
print(f"  Test 2 (CTI pertinent)  : Voir résultats ci-dessus")
print(f"  Test 3 (Hallucination)  : Voir résultats ci-dessus")
print(f"  Test 4 (Cohérence)      : Voir résultats ci-dessus")
print(f"  Test 5 (Replies)        : {total_replies} replies")
print(f"{'═' * 60}")