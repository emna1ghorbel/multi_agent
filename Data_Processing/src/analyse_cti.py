import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
from collections import Counter
from pathlib import Path

# ══════════════════════════════════════════════
# PHASE 1 : CHARGEMENT ROBUSTE
# ══════════════════════════════════════════════

filepath = Path('JSONL\darkgram_cti_final.jsonl')  
data = []
errors = 0

print("🔍 Chargement du fichier JSONL...")
try:
    with open(filepath, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            try:
                obj = json.loads(line.strip())
                if 'text' in obj:  # Validation minimale
                    data.append(obj)
                else:
                    errors += 1
            except json.JSONDecodeError:
                errors += 1
    print(f"✅ {len(data)} documents chargés. {errors} lignes ignorées.")
except FileNotFoundError:
    print(f"❌ Fichier introuvable : {filepath}")
    exit()

# ══════════════════════════════════════════════
# PHASE 2 : PARSING INTELLIGENT DU FORMAT
# ══════════════════════════════════════════════

def parse_doc_type(text, metadata):
    """Parse le type DEPUIS le texte structuré (source de vérité)"""
    # Le type est encodé dans le texte : "TYPE: MAIN_POST" ou "TYPE: REPLY"
    match = re.search(r'TYPE:\s*(\w+)', text)
    if match:
        raw = match.group(1).upper()
        if raw in ('REPLY',):
            return 'reply'
        elif raw in ('MAIN_POST',):
            return 'original_post'

    # Fallback sur la structure des métadonnées
    if 'parent_post_id' in metadata:
        return 'reply'
    return 'original_post'


def extract_content(text):
    """Extrait le CONTENU réel en supprimant les métadonnées structurelles"""
    # Supprime les tags structurels : [POST_ID: X] | TYPE: Y | CHANNEL: Z |
    content_match = re.search(r'CONTENT:\s*(.+?)(?:\s*\|\s*Statut:|$)', text, re.DOTALL)
    if content_match:
        return content_match.group(1).strip()
    # Si pas de tag CONTENT, retourne le texte brut nettoyé
    cleaned = re.sub(
        r'\[(?:POST_ID|PARENT_POST_ID|REPLY_ID):[^\]]*\]|\|?\s*TYPE:\s*\w+\s*\|?'
        r'|\|?\s*CHANNEL:\s*\w+\s*\|?|\|?\s*Source\s*:[^|]*\|?',
        '', text
    )
    return cleaned.strip(' |')


def compute_rag_metrics(content):
    """Métriques spécifiques à la qualité RAG d'un chunk"""
    if not content:
        return {
            'content_length': 0,
            'word_count': 0,
            'has_url_only': False,
            'is_question': False,
            'info_density': 0.0
        }

    words = content.split()
    word_count = len(words)

    # Un chunk qui n'est QU'une URL = inutile pour le RAG sémantique
    url_pattern = r'^https?://\S+$'
    has_url_only = bool(re.match(url_pattern, content.strip()))

    # Les questions courtes (replies) ont peu de valeur informationnelle
    is_question = content.strip().endswith('?') and word_count < 15

    # Densité informationnelle = ratio de mots "uniques" vs total
    unique_ratio = len(set(words)) / max(word_count, 1)

    # Score composite de qualité pour le RAG (0 à 1)
    density = 0.0
    if has_url_only:
        density = 0.1
    elif is_question and word_count < 8:
        density = 0.15
    else:
        length_score = min(word_count / 50, 1.0)  # Optimal ~50+ mots
        density = round(unique_ratio * 0.6 + length_score * 0.4, 3)

    return {
        'content_length': len(content),
        'word_count': word_count,
        'has_url_only': has_url_only,
        'is_question': is_question,
        'info_density': density
    }


# ══════════════════════════════════════════════
# PHASE 3 : CONSTRUCTION DU DATAFRAME ENRICHI
# ══════════════════════════════════════════════

rows = []
contents_for_analysis = []  # Textes nettoyés pour l'analyse sémantique

for d in data:
    meta = d.get('metadata', {})
    text = d.get('text', '')

    doc_type = parse_doc_type(text, meta)
    content = extract_content(text)
    rag_metrics = compute_rag_metrics(content)

    channel = str(
        meta.get('channel id')
        or meta.get('channel_id')
        or meta.get('channel_name')
        or 'Unknown'
    )

    # Date parsing robuste
    date_raw = meta.get('date', '')
    try:
        date_parsed = pd.to_datetime(date_raw)
    except Exception:
        date_parsed = pd.NaT

    rows.append({
        'category':      meta.get('category', 'Unknown'),
        'doc_type':      doc_type,
        'channel':       channel,
        'date':          date_parsed,
        'views':         meta.get('views'),
        'forwards':      meta.get('forwards', 0),
        'is_recovered':  meta.get('recovered', False),
        'raw_text_len':  len(text),
        'content':       content,
        **rag_metrics  # content_length, word_count, has_url_only, etc.
    })

    if content and not rag_metrics['has_url_only']:
        contents_for_analysis.append(content.lower())

df = pd.DataFrame(rows)

# ══════════════════════════════════════════════
# PHASE 4 : ANALYSE DE QUALITÉ RAG
# ══════════════════════════════════════════════

print("\n" + "=" * 50)
print("     📊 RAPPORT DE QUALITÉ RAG")
print("=" * 50)

total = len(df)
print(f"\n🔹 Total Documents       : {total}")
print(f"🔹 Posts Originaux       : {len(df[df['doc_type'] == 'original_post'])}")
print(f"🔹 Réponses (Replies)    : {len(df[df['doc_type'] == 'reply'])}")
print(f"🔹 Recovered             : {df['is_recovered'].sum()}")

# --- Métriques critiques pour le RAG ---
url_only = df['has_url_only'].sum()
questions_low = df['is_question'].sum()
empty = df[df['content_length'] == 0].shape[0]
low_density = df[df['info_density'] < 0.2].shape[0]
good_chunks = df[df['info_density'] >= 0.5].shape[0]

print(f"\n{'─'*40}")
print(f"  🎯 MÉTRIQUES RAG")
print(f"{'─'*40}")
print(f"  ✅ Chunks exploitables (densité≥0.5) : {good_chunks} ({100*good_chunks/total:.1f}%)")
print(f"  ⚠️  URL seule (inutile sémantique)   : {url_only} ({100*url_only/total:.1f}%)")
print(f"  ⚠️  Questions courtes (<15 mots)      : {questions_low}")
print(f"  ❌ Contenu vide                       : {empty}")
print(f"  ❌ Densité faible (<0.2)              : {low_density} ({100*low_density/total:.1f}%)")
print(f"  📏 Longueur moyenne du contenu        : {df['content_length'].mean():.0f} car.")
print(f"  📏 Mots moyens par chunk              : {df['word_count'].mean():.1f}")

# Distribution de la densité par catégorie
print(f"\n{'─'*40}")
print(f"  📦 DENSITÉ MOYENNE PAR CATÉGORIE")
print(f"{'─'*40}")
density_by_cat = (
    df.groupby('category')['info_density']
    .agg(['mean', 'count'])
    .sort_values('mean', ascending=False)
)
for cat, row in density_by_cat.iterrows():
    bar = "█" * int(row['mean'] * 20)
    print(f"  {cat[:30].ljust(30)} : {row['mean']:.3f} {bar} (n={int(row['count'])})")

# ══════════════════════════════════════════════
# PHASE 5 : ANALYSE LEXICALE NETTOYÉE
# ══════════════════════════════════════════════

text_blob = " ".join(contents_for_analysis)

stop_words = {
    # English
    'the', 'and', 'for', 'this', 'that', 'with', 'from', 'your', 'all',
    'have', 'was', 'not', 'are', 'been', 'were', 'their', 'which', 'what',
    'when', 'where', 'who', 'will', 'would', 'should', 'can', 'could',
    'about', 'than', 'then', 'them', 'just', 'also', 'more', 'some',
    'into', 'only', 'very', 'here', 'there', 'every', 'each', 'much',
    # French
    'les', 'des', 'une', 'pour', 'dans', 'sur', 'est', 'aux', 'pas',
    'que', 'qui', 'avec', 'plus', 'vous', 'nous', 'sont', 'tout',
    'person',
    # Structural / RAG noise
    'type', 'content', 'channel', 'main_post', 'post', 'reply', 'source',
    'message', 'original', 'statut', 'accessible', 'restreint', 'none',
    'false', 'true', 'unknown', 'null', 'date_time', 'avertissement',
    # Web
    'https', 'http', 'link', 'download', 'file', 'files', 'click',
    'join', 'group', 'telegram', 'photo', 'media', 'video',
}

# Ajout dynamique des noms de canaux
stop_words.update(df['channel'].str.lower().unique())
stop_words.update(df['category'].str.lower().unique())

words = re.findall(r'\b[a-z]{4,}\b', text_blob)
filtered = [w for w in words if w not in stop_words]
kw_counts = Counter(filtered)

print(f"\n{'─'*40}")
print(f"  🔑 TOP 20 MOTS-CLÉS CTI")
print(f"{'─'*40}")
for kw, count in kw_counts.most_common(20):
    bar = "█" * min(int(count / max(kw_counts.most_common(1)[0][1], 1) * 30), 30)
    print(f"  {kw.ljust(18)} : {str(count).rjust(5)} {bar}")

# ══════════════════════════════════════════════
# PHASE 6 : DASHBOARD VISUEL
# ══════════════════════════════════════════════

sns.set_theme(style="whitegrid")
fig, axes = plt.subplots(2, 3, figsize=(24, 14))
plt.subplots_adjust(hspace=0.4, wspace=0.35)
fig.suptitle("🛡️ CTI RAG Quality Dashboard", fontsize=18, fontweight='bold', y=0.98)

# 1. Répartition des catégories
axes[0, 0].set_title("📦 Répartition des Menaces", fontsize=13, fontweight='bold')
cat_counts = df['category'].value_counts()
cat_counts.plot.pie(autopct='%1.1f%%', ax=axes[0, 0], colors=sns.color_palette("viridis", len(cat_counts)))
axes[0, 0].set_ylabel('')

# 2. Top canaux
axes[0, 1].set_title("📢 Top 10 Canaux Actifs", fontsize=13, fontweight='bold')
top_ch = df['channel'].value_counts().nlargest(10)
sns.barplot(x=top_ch.values, y=top_ch.index, ax=axes[0, 1], palette="magma")

# 3. ⭐ NOUVEAU : Distribution de la densité RAG
axes[0, 2].set_title("🎯 Distribution Densité RAG", fontsize=13, fontweight='bold')
df['info_density'].hist(bins=30, ax=axes[0, 2], color='teal', edgecolor='white', alpha=0.85)
axes[0, 2].axvline(x=0.5, color='red', linestyle='--', label='Seuil qualité (0.5)')
axes[0, 2].axvline(x=0.2, color='orange', linestyle='--', label='Seuil faible (0.2)')
axes[0, 2].legend()
axes[0, 2].set_xlabel('Info Density Score')

# 4. Types de documents
axes[1, 0].set_title("📊 Types de Documents", fontsize=13, fontweight='bold')
type_counts = df['doc_type'].value_counts()
sns.barplot(x=type_counts.index, y=type_counts.values, ax=axes[1, 0], palette="coolwarm")

# 5. ⭐ NOUVEAU : Qualité par catégorie (boxplot)
axes[1, 1].set_title("📦 Densité RAG par Catégorie", fontsize=13, fontweight='bold')
top_cats = df['category'].value_counts().nlargest(8).index
df_filtered = df[df['category'].isin(top_cats)]
sns.boxplot(data=df_filtered, y='category', x='info_density', ax=axes[1, 1], palette="Set2")
axes[1, 1].axvline(x=0.5, color='red', linestyle='--', alpha=0.5)

# 6. Top mots-clés
axes[1, 2].set_title("🔑 Top 10 Mots-clés CTI", fontsize=13, fontweight='bold')
top_kw = dict(kw_counts.most_common(10))
sns.barplot(x=list(top_kw.values()), y=list(top_kw.keys()), ax=axes[1, 2], color="teal")

plt.savefig('cti_rag_dashboard.png', dpi=300, bbox_inches='tight')
print("\n✅ Dashboard sauvegardé : 'cti_rag_dashboard.png'")

# ══════════════════════════════════════════════
# PHASE 7 : RECOMMANDATIONS AUTOMATIQUES
# ══════════════════════════════════════════════

print(f"\n{'═'*50}")
print(f"  💡 RECOMMANDATIONS POUR TON PIPELINE RAG")
print(f"{'═'*50}")

if url_only / total > 0.1:
    print(f"  ⚠️  {url_only} docs sont des URL seules → Enrichis-les")
    print(f"     (scrape le contenu) ou exclus-les de l'index")

if low_density / total > 0.3:
    print(f"  ⚠️  {100*low_density/total:.0f}% de chunks ont une densité")
    print(f"     faible → Fusionne les replies avec leur parent post")

if df['word_count'].median() < 20:
    print(f"  ⚠️  Médiane de {df['word_count'].median():.0f} mots/chunk")
    print(f"     → Chunks trop courts, combine parent + replies")

if good_chunks / total < 0.5:
    print(f"  🔴 Seulement {100*good_chunks/total:.0f}% de chunks de qualité")
    print(f"     → Stratégie de chunking à revoir")
else:
    print(f"  ✅ {100*good_chunks/total:.0f}% de chunks exploitables")
    print(f"     → Base correcte pour le RAG")

print(f"\n{'═'*50}\n")