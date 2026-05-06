# main.py
from pathlib import Path
from load_documents import load_and_prepare
from create_index import create_index, load_index, FAISS_INDEX_PATH
from rag_chain import CTIAgent


def main():
    # ── Index ──
    if FAISS_INDEX_PATH.exists():
        vectorstore = load_index()
    else:
        print("🔨 Première exécution : création de l'index")
        docs = load_and_prepare()
        vectorstore = create_index(docs)

    # ── Agent ──
    agent = CTIAgent(vectorstore)

    # ── Interface ──
    print("\n" + "═" * 50)
    print("  🛡️  CTI INTELLIGENCE AGENT (DarkGram)")
    print("  Modèle : Phi-3.5 | Embeddings : MiniLM-L6-v2")
    print("  'quit' pour quitter")
    print("═" * 50)

    while True:
        question = input("\n💬 Question : ").strip()
        if question.lower() in ('quit', 'exit', 'q'):
            break
        if not question:
            continue

        result = agent.analyze(question, k=10, verbose=True)

        print("\n" + "─" * 50)
        print(result["analysis"])
        print("─" * 50)
        print("\n📌 Sources :")
        for s in result["sources"]:
            print(
                f"  POST {s['post_id']} | "
                f"{s['channel']} | "
                f"Score: {s['score']:.3f} | "
                f"Replies: {s['replies']}"
            )


if __name__ == "__main__":
    main()