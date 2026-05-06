# 1_load_documents.py
import json
import re
from pathlib import Path
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

JSONL_PATH = Path('darkgram_cti_final.jsonl')


def extract_content(text):
    """Extract ONLY the content after 'CONTENT:'"""
    match = re.search(r'CONTENT:\s*(.+)$', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def load_documents():
    """Load the JSONL → LangChain Documents."""
    print("📄 Load the JSONL...")

    documents = []
    stats = {'loaded': 0, 'empty': 0, 'url': 0}

    with open(JSONL_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            obj = json.loads(line.strip())
            raw_text = obj.get('text', '')
            metadata = obj.get('metadata', {})

            content = extract_content(raw_text)

            if not content:
                stats['empty'] += 1
                continue

            if re.match(r'^https?://\S+$', content.strip()):
                stats['url'] += 1
                continue

            clean_meta = {}
            for k, v in metadata.items():
                if v is None:
                    clean_meta[k] = ""
                elif isinstance(v, (str, int, float, bool)):
                    clean_meta[k] = v
                else:
                    clean_meta[k] = str(v)

            # clean_meta["full_structured_text"] = raw_text # ❌ SUPPRIMER
            # Extraire post_id et reply_id depuis le texte structuré
            match_post = re.search(r'\[POST_ID:\s*(\d+)\]', raw_text)
            match_parent = re.search(r'\[PARENT_POST_ID:\s*(\d+)\]', raw_text)
            match_reply = re.search(r'\[REPLY_ID:\s*(\d+)\]', raw_text)

            clean_meta["post_id"] = match_post.group(1) if match_post else ""
            if match_parent:
                  clean_meta["post_id"] = match_parent.group(1)
            clean_meta["reply_id"] = match_reply.group(1) if match_reply else ""

            documents.append(
                Document(
                    page_content=content,
                    metadata=clean_meta,
                )
            )
            stats['loaded'] += 1

    print(f"  ✅ Chargés  : {stats['loaded']}")
    print(f"  ⏭️  Vides   : {stats['empty']}")
    print(f"  🔗 URL-only : {stats['url']}")

    return documents


def filter_spam_content(documents):
    """Remove spam (repeated URLs)."""
    filtered = []
    removed = 0

    for doc in documents:
        content = doc.page_content
        urls = re.findall(r'https?://\S+', content)

        if urls:
            unique_urls = set(urls)
            if len(urls) >= 3 and len(unique_urls) == 1:
                removed += 1
                continue

            text_no_urls = re.sub(
                r'https?://\S+', '', content
            ).strip()
            if (
                len(urls) >= 5
                and len(text_no_urls) < len(content) * 0.2
            ):
                removed += 1
                continue

        filtered.append(doc)

    print(f"  🗑️  Spam supprimé : {removed}")
    print(f"  📄 Restants      : {len(filtered)}")

    return filtered


def smart_split(documents, max_tokens=300):
    """
    Split based on REAL token count, not character approximation.
    """
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        "sentence-transformers/all-mpnet-base-v2"
    )

    # Taille en CARACTÈRES ajustée pour le contenu CTI
    # Ratio réel : ~2.5 car/token pour URLs/IPs
    MAX_CHARS = max_tokens * 2  # 600 car au lieu de 1200

    short_docs = []
    long_docs = []

    for doc in documents:
        tok_count = len(tokenizer.encode(doc.page_content))
        if tok_count > max_tokens:
            long_docs.append(doc)
        else:
            short_docs.append(doc)

    print(f"\n📏 Longueurs (comptage RÉEL tokens) :")
    print(f"  Seuil  : {max_tokens} tokens")
    print(f"  Courts : {len(short_docs)}")
    print(f"  Longs  : {len(long_docs)}")

    if not long_docs:
        for doc in short_docs:
            doc.metadata["was_split"] = False
        return short_docs

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=MAX_CHARS,           # 600 car ≈ 300 tokens CTI
        chunk_overlap=int(MAX_CHARS * 0.15),  # 90 car overlap
        separators=["\n\n", "\n", " | ", "  ", " "],
        keep_separator=True,
        strip_whitespace=True,
    )

    split_docs = splitter.split_documents(long_docs)

    # VÉRIFICATION : re-check les splits
    still_long = []
    ok_docs = []

    for doc in split_docs:
        tok = len(tokenizer.encode(doc.page_content))
        if tok > 384:
            still_long.append(doc)
        else:
            ok_docs.append(doc)

    # Les irréductibles : forcer un split plus agressif
    if still_long:
        print(f"  ⚠️  {len(still_long)} chunks encore trop longs")
        aggressive_splitter = RecursiveCharacterTextSplitter(
            chunk_size=350,       # ~175 tokens, très conservateur
            chunk_overlap=50,
            separators=["\n", " ", ""],  # Coupe partout si nécessaire
            keep_separator=False,
            strip_whitespace=True,
        )
        forced_splits = aggressive_splitter.split_documents(
            still_long
        )
        ok_docs.extend(forced_splits)
        print(f"  🔄 Re-split → {len(forced_splits)} chunks")

    for doc in ok_docs:
        doc.metadata["was_split"] = True
    for doc in short_docs:
        doc.metadata["was_split"] = False

    total = short_docs + ok_docs
    print(f"  📦 Total final : {len(total)}")

    return total


def load_and_prepare():
    """Pipeline complet."""
    docs = load_documents()
    docs = filter_spam_content(docs)
    docs = smart_split(docs, max_tokens=300)
    return docs


if __name__ == "__main__":
    docs = load_and_prepare()
    print("\n── Aperçu ──")
    for doc in docs[:3]:
        print(f"  Type  : {doc.metadata.get('doc_type')}")
        print(f"  Split : {doc.metadata.get('was_split')}")
        print(f"  Len   : {len(doc.page_content)} car.")
        print(f"  Text  : {doc.page_content[:80]}...")
        print()