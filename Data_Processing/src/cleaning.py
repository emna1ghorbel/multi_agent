import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
from collections import Counter
from pathlib import Path
import logging

# Config
DATA_JSONL = Path('JSONL') / 'darkgram_cti_final.jsonl'
OUTPUT_IMG = 'cti_dashboard_final.png'

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Chargement
data = []
errors = 0
logging.info("🔍 Chargement du fichier JSONL...")
try:
    with open(DATA_JSONL, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            try:
                data.append(json.loads(line))
            except Exception as e:
                errors += 1
    logging.info(f"✅ Chargement terminé. {errors} lignes corrompues ignorées.")
except FileNotFoundError:
    logging.error(f"Fichier introuvable: {DATA_JSONL}")
    raise

# Extraction vers DataFrame
rows = []
dynamic_stop_words = set()

for d in data:
    meta = d.get('metadata', {})
    doc_type = meta.get('doc_type')
    if not doc_type:
        doc_type = 'original_post' if meta.get('recovered') else ('reply' if 'parent_post_id' in meta else 'original_post')
    ch_info = meta.get('channel_id') or meta.get('channel id') or meta.get('channel_name') or "Unknown"

    if meta.get('category'): dynamic_stop_words.add(meta['category'].lower())
    if str(ch_info) != "Unknown": dynamic_stop_words.add(str(ch_info).lower())

    rows.append({
        'category': meta.get('category', 'Unknown'),
        'doc_type': doc_type,
        'channel': str(ch_info),
        'text_len': len(d.get('text', '')),
        'is_recovered': meta.get('recovered', False)
    })

df = pd.DataFrame(rows)

text_blob = " ".join([d.get('text', '').lower() for d in data])

extended_stop_words = {
    # (tu gardes tel quel)
    'type', 'content', 'channel', 'main_post', 'post_id', 'source', 'statut', 
    'accessible', 'restreint', 'avertissement', 'original', 'reply', 'parent_post_id',
    'recovered', 'message', 'text', 'none', 'false', 'true', 'unknown',
    'https', 'http', 'com', 'net', 'org', 'www', 'link', 'download', 'file', 
    'click', 'join', 'group', 'channel', 'telegram', 'video', 'photo', 'media',
    'info', 'more', 'details', 'about', 'here', 'there', 'would', 'should',
    'les', 'des', 'une', 'pour', 'dans', 'sur', 'est', 'aux', 'pas', 'que',
    'with', 'from', 'your', 'this', 'that', 'they', 'will', 'been', 'were'
}
final_stop_words = extended_stop_words.union(dynamic_stop_words)

words = re.findall(r'\b[a-z]{4,}\b', text_blob)
filtered_words = [w for w in words if w not in final_stop_words]
kw_counts = Counter(filtered_words)

# Dashboard
sns.set_theme(style="whitegrid")
fig, axes = plt.subplots(2, 2, figsize=(18, 12))
plt.subplots_adjust(hspace=0.4, wspace=0.3)

# Catégories
df['category'].value_counts().plot.pie(autopct='%1.1f%%', ax=axes[0,0])
axes[0,0].set_ylabel('')
axes[0,0].set_title("📦 Répartition des Catégories")

# Canaux actifs
top_channels = df['channel'].value_counts().nlargest(10)
sns.barplot(x=top_channels.values, y=top_channels.index, ax=axes[0,1], palette="magma", legend=False)
axes[0,1].set_title("📢 Canaux les plus actifs (ID)")

# Types de documents
sns.countplot(x='doc_type', data=df, ax=axes[1,0], palette="coolwarm", hue='doc_type', legend=False)
axes[1,0].set_title("📊 Types de Documents")

# Mots-clés
top_kw = dict(kw_counts.most_common(10))
sns.barplot(x=list(top_kw.values()), y=list(top_kw.keys()), ax=axes[1,1], color="teal")
axes[1,1].set_title("🔑 Top 10 Mots-clés Découverts")

plt.savefig(OUTPUT_IMG, dpi=300)
logging.info(f"Dashboard sauvegardé: {OUTPUT_IMG}")

# Résumé
print("\n" + "="*35)
print("     📊 RAPPORT ANALYTIQUE CTI")
print("="*35)
print(f"🔹 Total Documents  : {len(df)}")
print(f"🔹 Posts (Original) : {len(df[df['doc_type'] == 'original_post'])}")
print(f"🔹 Réponses (Reply) : {len(df[df['doc_type'] == 'reply'])}")
print(f"🔹 Auto-Recovered   : {df['is_recovered'].sum()}")
print(f"🔹 Taille Moyenne   : {df['text_len'].mean():.0f} car.")
print("\n🚀 TOP MOTS-CLÉS DÉCOUVERTS :")
for kw, count in kw_counts.most_common(15):
    print(f"  - {kw.ljust(15)} : {count}")
print("\n✅ Analyse terminée. Dashboard : '{}'".format(OUTPUT_IMG))
