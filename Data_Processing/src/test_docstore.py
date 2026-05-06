# test_docstore.py
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from create_index import load_index

vectorstore = load_index()

# Parcourir TOUT le docstore pour trouver les replies du POST 381
count = 0
for doc_id, doc in vectorstore.docstore._dict.items():
    if doc.metadata.get("parent_post_id") == "381":
        count += 1
        print(
            f"  doc_id: {doc_id} | "
            f"reply_id: {doc.metadata.get('reply_id')} | "
            f"content: {doc.page_content}"
        )

print(f"\nTotal replies pour POST 381 : {count}")