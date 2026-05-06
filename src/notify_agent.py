"""
==========================================
 SINGLE NOTIFY AGENT (Kaggle + Brevo)
==========================================
"""
import os
import logging
import requests
import base64
from kaggle_secrets import UserSecretsClient
from langsmith import traceable

logging.basicConfig(level=logging.INFO)
from kaggle_secrets import UserSecretsClient
@traceable(name="NotifyAgent — notify_agent")
def main(pdf_path: str, executive_summary: dict):
    logging.info("📢 Notify Agent started")

    # 🔒 Lire les secrets ICI (jamais au niveau global)
    secrets = UserSecretsClient()
    try:
        BREVO_API_KEY = secrets.get_secret("BREVO_API_KEY")
        EMAIL_SENDER  = secrets.get_secret("EMAIL_SENDER")
    except Exception as e:
        logging.error(f"❌ Cannot read Kaggle secrets: {e}")
        return {"error": "secrets_not_found"}, 0

    logging.info(f"🔑 BREVO_API_KEY loaded: {bool(BREVO_API_KEY)}")
    logging.info(f"📧 EMAIL_SENDER loaded: {EMAIL_SENDER}")

    if not BREVO_API_KEY or not EMAIL_SENDER:
        logging.error("❌ Missing BREVO_API_KEY or EMAIL_SENDER")
        print("❌ Missing BREVO_API_KEY or EMAIL_SENDER")
        return {"error": "missing_secrets"}, 0

    # ───────────────────────────────────
    # Email content
    # ───────────────────────────────────
    subject = "Notification de sécurité – Rapport CTI automatique"
    html_content = f"""
    <p>Bonjour,</p>
    <p>Un rapport de cybersécurité a été analysé automatiquement.</p>
    <pre>{executive_summary}</pre>
    <p>Cordialement,<br><b>Notify Agent</b></p>
    """

    # ───────────────────────────────────
    # PDF attachment
    # ───────────────────────────────────
    attachments = []
    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            attachments.append({
                "content": base64.b64encode(f.read()).decode(),
                "name": os.path.basename(pdf_path),
            })

    # ───────────────────────────────────
    # Send via Brevo
    # ───────────────────────────────────
    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json"
        },
        json={
            "sender": {"name": "Notify Agent", "email": EMAIL_SENDER},
            "to": [{"email": "emnaghorbel56@gmail.com"}],
            "subject": subject,
            "htmlContent": html_content,
            "attachment": attachments
        }
    )

    logging.info(f"✅ Brevo status: {response.status_code}")
    return {
        "subject": subject,
        "recipient": "emnaghorbel56@gmail.com",
        "pdf_path": pdf_path,
        "status_code": response.status_code
    }, 1 if response.status_code == 201 else 0
