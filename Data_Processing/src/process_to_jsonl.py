import pandas as pd
import json
import os
import re

# --- CONFIGURATION ---
DATA_ROOT = 'cleaned_data' 
OUTPUT_FILE = 'darkgram_cti_final_test.jsonl'

def clean_val(val):
    """Convertit les types NumPy/Pandas en types Python natifs pour le JSON."""
    if pd.isna(val): 
        return None
    # .item() convertit int64/float64 en int/float Python natif
    if hasattr(val, 'item'): 
        return val.item()
    return val

def id_to_str(val):
    """Force la conversion de l'ID en string propre (sans .0)."""
    if pd.isna(val): return ""
    try:
        # Gère les cas où l'ID est lu comme un float
        return str(int(float(val)))
    except:
        return str(val).strip()

def process_to_jsonl():
    total_posts = 0
    total_replies = 0
    total_recovered = 0
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f_out:
        if not os.path.exists(DATA_ROOT):
            print(f"Erreur : Le dossier {DATA_ROOT} n'existe pas.")
            return

        for category in os.listdir(DATA_ROOT):
            cat_path = os.path.join(DATA_ROOT, category)
            if not os.path.isdir(cat_path): continue

            for channel_name in os.listdir(cat_path):
                channel_path = os.path.join(cat_path, channel_name)
                posts_csv = os.path.join(channel_path, f"{channel_name}.csv")
                replies_folder = os.path.join(channel_path, f"{channel_name}_replies")
                
                processed_ids = set() 

                # --- PHASE 1 : POSTS ---
                if os.path.exists(posts_csv):
                    try:
                        df_posts = pd.read_csv(posts_csv, low_memory=False)
                        df_posts.rename(columns=lambda x: x.strip().lower(), inplace=True)

                        for _, post in df_posts.iterrows():
                            p_id = id_to_str(post.get('post id'))
                            if not p_id: continue
                            # --- LOGIQUE D'ENRICHISSEMENT DU TEXTE (VECTOR INDEX) ---
                            msg_content = post.get('message', '')
                            fwd_from = clean_val(post.get('fwd_from'))
                            restr_reason = clean_val(post.get('restriction_reason'))

                            # Gestion de la source (Fwd_From)
                            source_text = f"Source : Transféré depuis {fwd_from}." if fwd_from else "Source : Message original"

                            # Gestion des restrictions
                            if not restr_reason or restr_reason == "[]":
                                restriction_text = "Statut: Accessible/Non restreint."
                            else:
                                restriction_text = f"Avertissement: Ce contenu est restreint pour {restr_reason}."
                            # Construction du bloc texte optimisé pour la vectorisation
                            text_formatted = (
                                f"[POST_ID: {p_id}] | "
                                f"TYPE: MAIN_POST | "
                                f"CHANNEL: {channel_name} | "
                                f"{source_text} | "
                                f"CONTENT: {msg_content} | "
                                f"{restriction_text}"
                            )

                            # --- LOGIQUE DES MÉTADONNÉES (FILTERS) ---
                            metadata = {
                                "category": category,
                                "channel id": clean_val(post.get('channel id')),
                                "url": clean_val(post.get('url')),
                                "date": clean_val(post.get('date')),
                                "views": clean_val(post.get('views')),
                                "forwards": clean_val(post.get('forwards')),
                                "replies": clean_val(post.get('replies')),
                                "out": clean_val(post.get('out')),
                                "mentioned": clean_val(post.get('mentioned')),
                                "media_unread": clean_val(post.get('media_unread')),
                                "silent": clean_val(post.get('silent')),
                                "post": clean_val(post.get('post')),
                                "from_scheduled": clean_val(post.get('from_scheduled')),
                                "legacy": clean_val(post.get('legacy')),
                                "edit_hide": clean_val(post.get('edit_hide')),
                                "pinned": clean_val(post.get('pinned')),
                                "noforwards" : clean_val(post.get('noforwards')),
                                "peer_channel": clean_val(post.get('peer_channel')),
                                "from_id_user": clean_val(post.get('from_id_user')),
                                "via_bot_id": clean_val(post.get('via_bot_id')),
                                "reply_to_msg_id": clean_val(post.get('reply_to_msg_id')),
                                "reply_to_scheduled": clean_val(post.get('reply_to_scheduled')),
                                "forum_topic": clean_val(post.get('forum_topic')),
                                "media_photo_id": clean_val(post.get('media_photo_id')),
                                "reply_markup": clean_val(post.get('reply_markup')),
                                "edit_date": clean_val(post.get('edit_date')),
                                "post_author": clean_val(post.get('post_author')),
                                "grouped_id": clean_val(post.get('grouped_id')),
                                "ttl_period": clean_val(post.get('ttl_period')),
                            }
                            f_out.write(json.dumps({"text": text_formatted, "metadata": metadata}, ensure_ascii=False) + '\n')
                            processed_ids.add(p_id)
                            total_posts += 1
                    except Exception as e:
                        print(f"⚠️ Erreur CSV Posts {channel_name}: {e}")

                # --- PHASE 2 : REPLIES & RECOVERY ---
                if os.path.exists(replies_folder):
                    for f_rep in os.listdir(replies_folder):
                        if not f_rep.endswith("_replies.csv"): continue
                        
                        # Extraction robuste de l'ID (ex: 'timestamp_ID_replies.csv' -> on prend l'ID)
                        parts = f_rep.replace("_replies.csv", "").split("_")
                        p_id_from_file = parts[-1] if parts else None

                        if not p_id_from_file: continue

                        try:
                            df_rep = pd.read_csv(os.path.join(replies_folder, f_rep), low_memory=False)
                            df_rep.rename(columns=lambda x: x.strip().lower(), inplace=True)
                            if df_rep.empty: continue

                            # AUTO-RECOVERY DU POST SI ABSENT DU CSV PRINCIPAL
                            if p_id_from_file not in processed_ids:
                                row_zero = df_rep.iloc[0]
                                
                                text_rec = (
                                    f"[POST_ID: {p_id_from_file}] | "
                                    f"TYPE: MAIN_POST | "
                                    f"CHANNEL: {channel_name} | "
                                    f"CONTENT: {row_zero.get('message', '')}"
                                )
                                # Métadonnées sans le message
                                exclude_fields = {'message'}
                                meta_rec = {
                                    col: clean_val(row_zero.get(col)) 
                                    for col in df_rep.columns 
                                    if col.lower() not in exclude_fields
                                }
                                meta_rec.update({"category": category, "recovered": True})
                                
                                f_out.write(json.dumps({"text": text_rec, "metadata": meta_rec}, ensure_ascii=False) + '\n')
                                processed_ids.add(p_id_from_file)
                                total_recovered += 1
                                total_posts += 1

                            # TRAITEMENT DES RÉPONSES
                            for _, rep in df_rep.iloc[1:].iterrows():
                                r_id = id_to_str(rep.get('id'))
                              
                                text_reply = (
                                    f"[PARENT_POST_ID: {p_id_from_file}] | [REPLY_ID: {r_id}] | "
                                    f"TYPE: REPLY | "
                                    f"CHANNEL: {channel_name} | "
                                    f"CONTENT: {rep.get('message', '')}"
                                )

                                  # --- LOGIQUE DES MÉTADONNÉES (FILTERS) ---
                                  # Sélection stricte des variables demandées pour les réponses
                                metadata_reply = {
                                    "category": category,
                                    "parent_post_id": p_id_from_file,
                                    "channel id": clean_val(rep.get('channel id')),
                                    "url": clean_val(rep.get('url')),
                                    "date": clean_val(rep.get('date')),
                                    "views": clean_val(rep.get('views')),
                                    "forwards": clean_val(rep.get('forwards')),
                                    "reactions": clean_val(rep.get('reactions')), 
                                }

                                  # Écriture dans le fichier
                                f_out.write(json.dumps({"text": text_reply, "metadata": metadata_reply}, ensure_ascii=False) + '\n')
                                total_replies += 1
                        except Exception as e:
                            print(f"⚠️ Erreur fichier {f_rep}: {e}")

    print(f"\n✅ Terminé !")
    print(f"   - Posts (Total): {total_posts} (dont {total_recovered} récupérés)")
    print(f"   - Réponses: {total_replies}")

if __name__ == "__main__":
    process_to_jsonl()