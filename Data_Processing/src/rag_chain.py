# 3_rag_chain.py
"""
Agent CTI avec retrieval intelligent et Phi-3.5
"""

import re
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser


def get_llm():
    """Phi-3.5 via Ollama."""
    return OllamaLLM(
        model="phi3.5",
        temperature=0.1,
        num_ctx=4096,
        num_predict=700,    # Limite la réponse à 700 tokens max
    )


# ══════════════════════════════════════════════
# VALIDATION
# ══════════════════════════════════════════════

def is_relevant_question(question):
    """Rejette les questions hors-sujet CTI."""
    question_lower = question.lower().strip()

    irrelevant_patterns = [
        r'^(hi|hello|hey|bonjour|salut|coucou)',
        r'^how are you',
        r'^(merci|thanks|thank you)',
        r'^(bye|goodbye|au revoir)',
        r'^(oui|non|yes|no|ok|okay)$',
        r'^(test|testing)$',
        r'^what is the weather',
        r'^who are you',
        r'^what can you do',
        r'^tell me a joke',
        r'^(joke|funny|laugh)',
    ]

    for pattern in irrelevant_patterns:
        if re.match(pattern, question_lower):
            return False

    if len(question_lower.split()) < 3:
        return False

    return True


# ══════════════════════════════════════════════
# RETRIEVER INTELLIGENT
# ══════════════════════════════════════════════

# Seuil de pertinence : au-dessus = non pertinent
RELEVANCE_THRESHOLD = 1.0
def retrieve_with_context(vectorstore, query,
                          original_query=None, k=10):
    """
    Double recherche + récupération replies via docstore.
    """
    # Recherche 1 : query combinée
    posts1 = vectorstore.similarity_search_with_score(
        query=query,
        k=k * 2,
        filter={"doc_type": "original_post"},
    )

    # Recherche 2 : query originale
    posts2 = []
    if original_query and original_query != query:
        posts2 = vectorstore.similarity_search_with_score(
            query=original_query,
            k=k * 2,
            filter={"doc_type": "original_post"},
        )

    # Fusionner et dédupliquer
    best_scores = {}
    best_docs = {}

    for doc, score in posts1 + posts2:
        if score > RELEVANCE_THRESHOLD:
            continue
        post_id = doc.metadata.get("post_id", "")
        if not post_id:
            continue
        if post_id not in best_scores or score < best_scores[post_id]:
            best_scores[post_id] = score
            best_docs[post_id] = doc

    sorted_ids = sorted(best_scores, key=best_scores.get)

    results = []
    for post_id in sorted_ids[:k]:
        doc = best_docs[post_id]
        score = best_scores[post_id]

        # Replies via docstore (PAS via similarity_search)
        replies = get_replies_for_post(
            vectorstore, post_id, max_replies=5
        )

        results.append({
            "post": doc,
            "score": score,
            "post_id": post_id,
            "replies": replies,
        })

    return results
def get_replies_for_post(vectorstore, post_id, max_replies=5):
    """
    Récupère les replies directement depuis le docstore.
    Pas de similarity search, juste un filtre exact.
    """
    replies = []
    for doc_id, doc in vectorstore.docstore._dict.items():
        if doc.metadata.get("parent_post_id") == str(post_id):
            replies.append(doc)
            if len(replies) >= max_replies:
                break
    return replies



def format_context(results, max_results=4):
    """
    Formate pour le prompt du LLM.
    Qualifie les replies comme des RÉACTIONS communautaires.
    """
    if not results:
        return "NO RELEVANT RESULT FOUND."

    blocks = []

    for i, r in enumerate(results[:max_results]):
        meta = r["post"].metadata
        content = r["post"].page_content
        post_id = meta.get("post_id", "?")
        channel = meta.get("channel_name", "?")

        block = f"══ SOURCE {i+1} "
        block += f"(score: {r['score']:.3f}) ══\n"
        block += (
            f"[POST_ID: {post_id}] | "
            f"CHANNEL: {channel} | "
            f"CONTENT: {content}\n"
        )

        views = meta.get("views", "")
        forwards = meta.get("forwards", "")
        if views:
            block += (
                f"  [Views: {views} | "
                f"Forwards: {forwards}]\n"
            )

        # Replies = réactions communautaires
        if r["replies"]:
            block += (
                f"  ── Community reactions "
                f"({len(r['replies'])} replies) ──\n"
            )
            for reply in r["replies"]:
                r_meta = reply.metadata
                r_id = r_meta.get("reply_id", "?")
                block += (
                    f"  → [REPLY {r_id}] "
                    f"{reply.page_content}\n"
                )
        else:
            block += "  [No community replies]\n"

        blocks.append(block)

    return "\n\n".join(blocks)


# ══════════════════════════════════════════════
# PROMPTS CTI
# ══════════════════════════════════════════════

REWRITE_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "You are a CTI search query optimizer. "
     "Rewrite the user question as a short search query "
     "for a database of cybercriminal Telegram posts. "
     "Rules:\n"
     "- Maximum 15 words\n"
     "- English only\n"
     "- No explanation, no notes, no parentheses\n"
     "- Only output the search query, nothing else"),
    ("human", "{question}")
])

ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior CTI analyst specialized in 
monitoring cybercriminal Telegram channels (DarkGram dataset).

RETRIEVED DATA:
{context}

STRICT RULES:
1. Base your analysis ONLY on the data above
2. NEVER invent information not in the context
3. Cite exact POST_ID and CHANNEL in your sources
4. If context says "NO RELEVANT RESULT", say so clearly
5. Assess reliability using these criteria:
   - High views + high forwards = widely shared threat
   - High views + zero forwards = possibly clickbait
   - Many interrogative replies like "how to use?" or 
     "what is this?" = audience does NOT understand the 
     content, likely spam or scam
   - Few or no replies does NOT mean low quality
   - Replies are community REACTIONS, not answers
6. Do NOT analyze if data is insufficient
7. Keep your response concise and factual

FORMAT:
## Threat Analysis
[Your factual analysis based on the data]

## Indicators of Compromise (IOC)
- [ONLY those present in the context]

## Sources
- POST_ID: X | Channel: Y | Score: Z

## Community Engagement
- [What replies reveal about post credibility]

## Overall Reliability
[High/Medium/Low] - [justification]"""),
    ("human", "{question}")
])


# ══════════════════════════════════════════════
# AGENT CTI
# ══════════════════════════════════════════════

class CTIAgent:
    def __init__(self, vectorstore):
        self.vectorstore = vectorstore
        self.llm = get_llm()
        self.parser = StrOutputParser()
        self.rewrite_chain = (
            REWRITE_PROMPT | self.llm | self.parser
        )
        self.analysis_chain = (
            ANALYSIS_PROMPT | self.llm | self.parser
        )

    def analyze(self, question, k=10, verbose=True):
        """Pipeline RAG complet avec validation."""

        # Vérification pertinence question
        if not is_relevant_question(question):
            msg = (
                "⚠️ This question does not seem related "
                "to Cyber Threat Intelligence.\n\n"
                "Examples of valid questions:\n"
                "- What cracking tools are shared?\n"
                "- Which channels sell stolen credentials?\n"
                "- What cloud logs are available?\n"
                "- Are there pirated software shared?"
            )
            if verbose:
                print(f"\n⚠️ Off-topic question detected")
            return {
                "question": question,
                "rewritten": None,
                "analysis": msg,
                "sources": [],
            }

        # 1. Reformulation
        if verbose:
            print(f"\n🔍 Question : {question}")
        raw_rewrite = self.rewrite_chain.invoke(
            {"question": question}
        )
        rewritten = raw_rewrite.split("\n")[0].strip()
        rewritten = re.sub(r'\(.*?\)', '', rewritten).strip()
        rewritten = rewritten.strip('"').strip("'").strip()

        # Combiner : question originale DEUX FOIS + reformulation
        combined_query = f"{question} {question} {rewritten}"

        if verbose:
            print(f"🔄 Reformulée : {rewritten}")

        # 2. Retrieval avec la requête combinée
        results = retrieve_with_context(
            self.vectorstore, 
            query=combined_query,
            original_query=question,
            k=k,
        )
        if verbose:
            print(f"📦 {len(results)} résultats pertinents")

        # Aucun résultat pertinent
        if not results:
            if verbose:
                print("❌ No results under threshold")
            return {
                "question": question,
                "rewritten": rewritten,
                "analysis": (
                    "❌ No relevant results found "
                    "in the DarkGram database.\n"
                    "Retrieved documents had similarity scores "
                    "too low "
                    f"(threshold: {RELEVANCE_THRESHOLD})."
                ),
                "sources": [],
            }

        # 3. Formatage
        context = format_context(results, max_results=3)
        if verbose:
            print(f"📋 Contexte : {len(context)} car.")

        # 4. Analyse
        if verbose:
            print(f"🤖 Analyse en cours...")

        analysis = self.analysis_chain.invoke({
            "context": context,
            "question": question,
        })

        return {
            "question": question,
            "rewritten": rewritten,
            "analysis": analysis,
            "sources": [
                {
                    "post_id": r["post_id"],
                    "score": r["score"],
                    "replies": len(r["replies"]),
                    "channel": r["post"].metadata.get(
                        "channel_name", ""
                    ),
                }
                for r in results[:5]
            ],
        }