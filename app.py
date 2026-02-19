from flask import Flask, render_template, request, jsonify
import pickle
import json
import re
import torch
import requests
import os
import imaplib
import email as email_lib
from email.header import decode_header
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import threading
import uuid
from dotenv import load_dotenv
from transformers import BertTokenizer, BertForSequenceClassification

load_dotenv()

app = Flask(__name__)

# ===============================
# Load URL Detection Models
# ===============================
vector = pickle.load(open("vectorizer.pkl", 'rb'))
url_model = pickle.load(open("phishing.pkl", 'rb'))

# ===============================
# Load Email Phishing BERT Model
# ===============================
MODEL_PATH = "email_phishing"

email_tokenizer = BertTokenizer.from_pretrained(MODEL_PATH)
email_model = BertForSequenceClassification.from_pretrained(MODEL_PATH)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
email_model.to(device)
email_model.eval()

# ===============================
# Groq API Configuration
# ===============================
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_URL = os.getenv("GROQ_URL")
GROQ_MODEL = os.getenv("GROQ_MODEL")


# ===============================
# Runtime Email Scanner State
# ===============================
runtime_lock = threading.Lock()
runtime_emails = []
runtime_connection = {
    "connected": False,
    "email": None,
    "imap": None,
}


# ===============================
# HTML-to-Text Utility
# ===============================
class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            self.result.append(data)

    def get_text(self):
        return ' '.join(''.join(self.result).split())


def html_to_text(html_str):
    extractor = HTMLTextExtractor()
    try:
        extractor.feed(html_str)
        return extractor.get_text()
    except Exception:
        return html_str


# ===============================
# Email Parsing Helpers
# ===============================
def decode_mime_header(header_value):
    if not header_value:
        return ""
    decoded_parts = decode_header(header_value)
    result = []
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            result.append(part)
    return ' '.join(result)


def parse_email_message(raw_bytes):
    msg = email_lib.message_from_bytes(raw_bytes)
    sender = decode_mime_header(msg.get("From", ""))
    subject = decode_mime_header(msg.get("Subject", "(No Subject)"))
    date_str = msg.get("Date", "")

    try:
        date_obj = parsedate_to_datetime(date_str)
        date_iso = date_obj.isoformat()
    except Exception:
        date_iso = date_str

    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in content_disposition:
                continue
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or 'utf-8'
                decoded = payload.decode(charset, errors='replace')
                if content_type == "text/plain":
                    body_text = decoded
                elif content_type == "text/html":
                    body_html = decoded
            except Exception:
                continue
    else:
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            decoded = payload.decode(charset, errors='replace')
            if msg.get_content_type() == "text/html":
                body_html = decoded
            else:
                body_text = decoded
        except Exception:
            body_text = ""

    if not body_text.strip() and body_html:
        body_text = html_to_text(body_html)

    body_preview = body_text[:500] + "..." if len(body_text) > 500 else body_text

    return {
        "from": sender,
        "subject": subject,
        "date": date_iso,
        "body_preview": body_preview,
        "body_full": body_text
    }


# ===============================
# Reusable Email Scan Function
# ===============================
def scan_email_text(text):
    try:
        inputs = email_tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )
        inputs = {key: val.to(device) for key, val in inputs.items()}

        with torch.no_grad():
            outputs = email_model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            predicted_class = torch.argmax(probabilities, dim=1).item()
            confidence = probabilities[0][predicted_class].item() * 100

        preview = text[:200] + "..." if len(text) > 200 else text

        if predicted_class == 1:
            return {
                "status": "danger",
                "label": "Phishing Email Detected",
                "message": "This email is likely a phishing attempt.",
                "confidence": round(confidence, 1),
                "preview": preview
            }
        else:
            return {
                "status": "safe",
                "label": "Legitimate Email",
                "message": "This email appears to be legitimate.",
                "confidence": round(confidence, 1),
                "preview": preview
            }
    except Exception:
        return {
            "status": "error",
            "label": "Analysis Error",
            "message": "Could not analyze the email. Please try again.",
            "confidence": None,
            "preview": text[:200] if text else ""
        }


# ===============================
# Groq-based Email Phishing Scanner
# ===============================
def _extract_sender_domain(sender):
    """Extract the domain from a sender string like 'Name <user@domain.com>'."""
    match = re.search(r'[\w.+-]+@([\w.-]+)', sender)
    return match.group(1).lower() if match else ""


def _extract_sender_email(sender):
    """Extract the email address from a sender string."""
    match = re.search(r'[\w.+-]+@[\w.-]+', sender)
    return match.group(0).lower() if match else sender


TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googlemail.com",
    "accounts.google.com", "microsoft.com", "outlook.com", "live.com",
    "hotmail.com", "amazon.com", "amazon.in", "apple.com", "icloud.com",
    "github.com", "linkedin.com", "facebook.com", "meta.com",
    "twitter.com", "x.com", "instagram.com", "netflix.com",
    "paypal.com", "stripe.com", "razorpay.com",
    "yahoo.com", "yahoo.co.in", "rediffmail.com",
    "flipkart.com", "swiggy.in", "zomato.com", "paytm.com",
    "phonepe.com", "gpay.com", "uber.com", "ola.com",
    "slack.com", "zoom.us", "notion.so", "figma.com",
    "spotify.com", "discord.com", "whatsapp.com",
    "stackoverflow.com", "npmjs.com", "vercel.com", "netlify.com",
    "edu", "gov", "gov.in", "ac.in", "nic.in",
}


def _is_trusted_domain(domain):
    """Check if a domain or its parent domain is in the trusted list."""
    if not domain:
        return False
    domain = domain.lower()
    if domain in TRUSTED_DOMAINS:
        return True
    # Check parent domain (e.g. mail.google.com -> google.com)
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in TRUSTED_DOMAINS:
            return True
    return False


def scan_email_with_groq(sender, subject, body):
    """
    Use Groq API to intelligently analyze an email for phishing.
    First checks sender domain, then sends full content to LLM for analysis.
    """
    sender_email = _extract_sender_email(sender)
    sender_domain = _extract_sender_domain(sender)
    is_trusted = _is_trusted_domain(sender_domain)
    email_content = body[:2000] if body else "(empty body)"
    preview = body[:200] + "..." if len(body) > 200 else body

    prompt = f"""Analyze this email and decide: is it PHISHING or SAFE?

SENDER EMAIL: {sender_email}
SENDER DOMAIN: {sender_domain}
DOMAIN TRUSTED: {"YES - this is a known legitimate domain" if is_trusted else "UNKNOWN - verify carefully"}
SUBJECT: {subject}

FULL EMAIL BODY:
---
{email_content}
---

CLASSIFICATION RULES:
- If the sender domain is a well-known trusted company/service (Google, Amazon, Microsoft, GitHub, LinkedIn, banks, universities, government, etc.) AND the email content is normal (notifications, receipts, OTPs, newsletters, promotions, updates, alerts), then verdict MUST be "safe".
- Normal emails include: order confirmations, shipping updates, login alerts, password resets, OTP codes, newsletters, marketing/promotions, meeting invites, system notifications, social media notifications, billing receipts, subscription updates.
- An email is ONLY phishing if it has MULTIPLE of these red flags:
  (a) Sender domain is fake/misspelled/suspicious (like "g00gle.com", "amaz0n-support.xyz", "secure-paypal.tk")
  (b) Asks you to click a suspicious link to "verify your account" or "confirm your identity" urgently
  (c) Directly asks for passwords, credit card numbers, bank details, or SSN
  (d) Claims you won a lottery, inheritance, or prize you never entered
  (e) Threatens account suspension/legal action unless you act immediately
- If the sender is from a trusted domain, the email is SAFE even if it contains promotional language, urgency about deals, or marketing content.
- When in doubt, default to "safe".

Respond with ONLY this JSON (no other text):
{{"verdict": "safe", "confidence": 95, "reason": "explanation"}}
or
{{"verdict": "phishing", "confidence": 90, "reason": "explanation"}}"""

    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an email security classifier. You MUST respond with ONLY valid JSON. No markdown, no explanation, no code blocks. Just the JSON object. You are conservative - you default to 'safe' unless there are clear phishing indicators. Normal emails from real companies are ALWAYS safe."
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.0,
                "max_tokens": 150
            },
            timeout=30
        )

        if resp.status_code != 200:
            # API failed — if domain is trusted, mark safe; otherwise mark safe with low confidence
            if is_trusted:
                return {
                    "status": "safe",
                    "label": "Legitimate Email",
                    "message": f"Email from trusted domain ({sender_domain}).",
                    "confidence": 85.0,
                    "preview": preview
                }
            return {
                "status": "safe",
                "label": "Email Received",
                "message": "Could not verify — defaulting to safe. Review manually.",
                "confidence": 50.0,
                "preview": preview
            }

        content = resp.json()["choices"][0]["message"]["content"].strip()

        # Strip markdown code block wrappers if present
        if content.startswith("```"):
            lines = content.split("\n")
            content = "\n".join(lines[1:])
            if content.endswith("```"):
                content = content[:-3].strip()

        result = json.loads(content)

        verdict = result.get("verdict", "safe").lower().strip()
        confidence = float(result.get("confidence", 50))
        reason = result.get("reason", "")

        # Safety override: if domain is trusted and LLM still says phishing,
        # require very high confidence — otherwise override to safe
        if verdict == "phishing" and is_trusted and confidence < 95:
            return {
                "status": "safe",
                "label": "Legitimate Email",
                "message": f"Email from trusted domain ({sender_domain}). {reason}",
                "confidence": round(100 - confidence, 1),
                "preview": preview
            }

        if verdict == "phishing":
            return {
                "status": "danger",
                "label": "Phishing Email Detected",
                "message": reason or "This email is likely a phishing attempt.",
                "confidence": round(confidence, 1),
                "preview": preview
            }
        else:
            return {
                "status": "safe",
                "label": "Legitimate Email",
                "message": reason or "This email appears to be legitimate.",
                "confidence": round(confidence, 1),
                "preview": preview
            }

    except Exception:
        # On any error, default to safe instead of falling back to BERT
        if is_trusted:
            return {
                "status": "safe",
                "label": "Legitimate Email",
                "message": f"Email from trusted domain ({sender_domain}).",
                "confidence": 85.0,
                "preview": preview
            }
        return {
            "status": "safe",
            "label": "Email Received",
            "message": "Could not verify — defaulting to safe. Review manually.",
            "confidence": 50.0,
            "preview": preview
        }


# ===============================
# Runtime Email Fetch Helper
# ===============================
def _fetch_emails(limit=50, unseen_only=False):
    imap = runtime_connection.get("imap")
    if not imap:
        return []

    try:
        imap.select("INBOX")
    except Exception:
        raise Exception("IMAP connection lost. Please reconnect.")

    search_criteria = "UNSEEN" if unseen_only else "ALL"
    status, message_ids = imap.search(None, search_criteria)
    if status != "OK":
        return []

    id_list = message_ids[0].split()
    if not id_list:
        return []

    id_list = id_list[-limit:]

    new_emails = []
    for msg_id in id_list:
        try:
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue
            raw_email = msg_data[0][1]
            parsed = parse_email_message(raw_email)

            with runtime_lock:
                is_dup = any(
                    e["from"] == parsed["from"] and
                    e["subject"] == parsed["subject"] and
                    e["date"] == parsed["date"]
                    for e in runtime_emails
                )
            if is_dup:
                continue

            # Use Groq API for intelligent phishing detection
            scan_result = scan_email_with_groq(
                parsed["from"], parsed["subject"], parsed["body_full"]
            )

            record = {
                "id": str(uuid.uuid4())[:8],
                "from": parsed["from"],
                "subject": parsed["subject"],
                "date": parsed["date"],
                "body_preview": parsed["body_preview"],
                "body_full": parsed["body_full"],
                "status": scan_result["status"],
                "label": scan_result["label"],
                "confidence": scan_result["confidence"],
                "message": scan_result["message"],
                "report": None
            }

            with runtime_lock:
                runtime_emails.insert(0, record)

            safe_record = {k: v for k, v in record.items() if k != "body_full"}
            new_emails.append(safe_record)

        except Exception:
            continue

    return new_emails


def call_groq(messages):
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": GROQ_MODEL,
                "messages": messages,
                "temperature": 0.3,
                "max_tokens": 1500
            },
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return None
    except Exception:
        return None


@app.route("/")
def index():
    return render_template("index.html")


# ===============================
# API: Scan URL
# ===============================
@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "label": "Error",
            "message": "Please enter a URL to check."
        })

    cleaned_url = re.sub(r'^https?://(www\.)?', '', url)
    prediction = url_model.predict(vector.transform([cleaned_url]))[0]

    if prediction == "bad":
        return jsonify({
            "status": "danger",
            "label": "Phishing Detected",
            "message": "This website is likely a phishing site. Do not enter any personal information.",
            "url": url
        })
    else:
        return jsonify({
            "status": "safe",
            "label": "Safe Website",
            "message": "This website appears to be legitimate and safe to visit.",
            "url": url
        })


# ===============================
# API: Scan Email
# ===============================
@app.route("/api/scan-email", methods=["POST"])
def api_scan_email():
    data = request.get_json()
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({
            "status": "error",
            "label": "Error",
            "message": "Please paste an email to analyze."
        })

    result = scan_email_text(email_text)
    return jsonify(result)


# ===============================
# API: Generate AI Report
# ===============================
@app.route("/api/report", methods=["POST"])
def generate_report():
    data = request.get_json()
    scan_type = data.get("type")
    input_data = data.get("input", "")
    verdict = data.get("verdict", "")
    confidence = data.get("confidence")

    if scan_type == "url":
        prompt = f"""You are a senior cybersecurity analyst at PhishGuard. A website URL was scanned by our ML phishing detection model (Logistic Regression trained on 549K+ URLs).

URL Scanned: {input_data}
ML Model Verdict: {verdict}

Write a professional security analysis report with these exact sections:

## Threat Assessment
State the risk level (Critical / High / Medium / Low / Safe) and give a 2-3 sentence summary explaining why.

## URL Pattern Analysis
Analyze the URL structure — domain name, TLD, path, query parameters, use of IP addresses, hyphens, suspicious keywords, URL length, etc. List each finding as a bullet point.

## Similar Known Sites
List 2-3 examples of known phishing sites with similar patterns (if phishing) OR confirm similarity to well-known legitimate sites (if safe).

## Risk Indicators
List specific red flags or trust signals found in this URL as bullet points.

## Recommendations
Provide 4-5 actionable steps the user should take right now.

Be factual, professional, and concise. Use bullet points where appropriate."""

    else:
        prompt = f"""You are a senior cybersecurity analyst at PhishGuard. An email was analyzed by our BERT deep learning phishing detection model (110M parameters).

Email Content:
---
{input_data[:1500]}
---

ML Model Verdict: {verdict}
Model Confidence: {confidence}%

Write a professional security analysis report with these exact sections:

## Threat Assessment
State the risk level (Critical / High / Medium / Low / Safe) and give a 2-3 sentence summary.

## Phishing Indicator Analysis
Identify the specific words, phrases, and patterns that indicate phishing or legitimacy. For each indicator, estimate its contribution to the overall phishing score as a percentage. Format as bullet points like: "- **word/phrase** (XX%) — explanation"

## Social Engineering Tactics
Identify any manipulation techniques used — urgency, authority impersonation, fear, reward/greed, curiosity, etc. Explain how each tactic works.

## Language Analysis
Analyze writing style, grammar quality, tone, and any suspicious linguistic patterns.

## Recommendations
Provide 4-5 actionable measures the user should take right now.

Be factual, professional, and concise. Use bullet points where appropriate."""

    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity expert at PhishGuard generating professional security analysis reports. Be concise, factual, and actionable. Always use the exact section headers provided. Use markdown formatting."
        },
        {"role": "user", "content": prompt}
    ]

    report = call_groq(messages)

    if report:
        return jsonify({"status": "success", "report": report})
    else:
        return jsonify({
            "status": "error",
            "report": "Unable to generate AI report at this time. The AI service may be temporarily unavailable. Please try again."
        })


# ===============================
# API: Runtime Email Scanner
# ===============================
@app.route("/api/runtime/connect", methods=["POST"])
def runtime_connect():
    data = request.get_json()
    email_addr = data.get("email", "").strip()
    app_password = data.get("app_password", "").strip()

    if not email_addr or not app_password:
        return jsonify({"status": "error", "message": "Email and App Password are required."})

    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        imap.login(email_addr, app_password)
    except imaplib.IMAP4.error:
        return jsonify({"status": "error", "message": "Authentication failed. Check your email and App Password."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"})

    with runtime_lock:
        if runtime_connection.get("imap"):
            try:
                runtime_connection["imap"].logout()
            except Exception:
                pass
        runtime_connection["connected"] = True
        runtime_connection["email"] = email_addr
        runtime_connection["imap"] = imap
        runtime_emails.clear()

    try:
        fetched = _fetch_emails(limit=15)
        return jsonify({
            "status": "success",
            "message": f"Connected to {email_addr}",
            "email": email_addr,
            "fetched": len(fetched),
            "emails": fetched
        })
    except Exception as e:
        return jsonify({
            "status": "success",
            "message": f"Connected to {email_addr}, but initial fetch failed: {str(e)}",
            "email": email_addr,
            "fetched": 0,
            "emails": []
        })


@app.route("/api/runtime/fetch", methods=["POST"])
def runtime_fetch():
    if not runtime_connection.get("connected"):
        return jsonify({"status": "error", "message": "Not connected. Please connect first."})

    try:
        fetched = _fetch_emails(limit=20, unseen_only=True)
        return jsonify({
            "status": "success",
            "fetched": len(fetched),
            "emails": fetched
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/runtime/emails", methods=["GET"])
def runtime_get_emails():
    with runtime_lock:
        emails = [
            {k: v for k, v in e.items() if k != "body_full"}
            for e in runtime_emails
        ]
    return jsonify({"status": "success", "emails": emails})


@app.route("/api/runtime/email/<email_id>", methods=["GET"])
def runtime_get_email(email_id):
    with runtime_lock:
        email_record = next((e for e in runtime_emails if e["id"] == email_id), None)
    if not email_record:
        return jsonify({"status": "error", "message": "Email not found."}), 404
    return jsonify({"status": "success", "email": email_record})


@app.route("/api/runtime/report/<email_id>", methods=["POST"])
def runtime_generate_report(email_id):
    with runtime_lock:
        email_record = next((e for e in runtime_emails if e["id"] == email_id), None)

    if not email_record:
        return jsonify({"status": "error", "message": "Email not found."}), 404

    if email_record.get("report"):
        return jsonify({"status": "success", "report": email_record["report"]})

    prompt = f"""You are a senior cybersecurity analyst at PhishGuard. An email was analyzed by our BERT deep learning phishing detection model (110M parameters).

Email Content:
---
{email_record['body_full'][:1500]}
---

Sender: {email_record['from']}
Subject: {email_record['subject']}

ML Model Verdict: {email_record['label']}
Model Confidence: {email_record['confidence']}%

Write a professional security analysis report with these exact sections:

## Threat Assessment
State the risk level (Critical / High / Medium / Low / Safe) and give a 2-3 sentence summary.

## Phishing Indicator Analysis
Identify the specific words, phrases, and patterns that indicate phishing or legitimacy. For each indicator, estimate its contribution to the overall phishing score as a percentage. Format as bullet points.

## Social Engineering Tactics
Identify any manipulation techniques used — urgency, authority impersonation, fear, reward/greed, curiosity, etc.

## Sender & Header Analysis
Analyze the sender address, display name patterns, and any suspicious indicators.

## Recommendations
Provide 4-5 actionable measures the user should take right now.

Be factual, professional, and concise. Use bullet points where appropriate."""

    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity expert at PhishGuard generating professional security analysis reports. Be concise, factual, and actionable. Always use the exact section headers provided. Use markdown formatting."
        },
        {"role": "user", "content": prompt}
    ]

    report = call_groq(messages)
    if report:
        with runtime_lock:
            email_record["report"] = report
        return jsonify({"status": "success", "report": report})
    else:
        return jsonify({
            "status": "error",
            "report": "Unable to generate AI report at this time."
        })


@app.route("/api/runtime/email/<email_id>", methods=["DELETE"])
def runtime_delete_email(email_id):
    with runtime_lock:
        before = len(runtime_emails)
        runtime_emails[:] = [e for e in runtime_emails if e["id"] != email_id]
        deleted = before - len(runtime_emails)
    if deleted:
        return jsonify({"status": "success", "message": "Email removed."})
    else:
        return jsonify({"status": "error", "message": "Email not found."}), 404


@app.route("/api/runtime/emails", methods=["DELETE"])
def runtime_delete_all():
    with runtime_lock:
        count = len(runtime_emails)
        runtime_emails.clear()
    return jsonify({"status": "success", "message": f"Cleared {count} emails."})


@app.route("/api/runtime/stats", methods=["GET"])
def runtime_stats():
    with runtime_lock:
        total = len(runtime_emails)
        phishing = sum(1 for e in runtime_emails if e["status"] == "danger")
        safe = sum(1 for e in runtime_emails if e["status"] == "safe")
        threat_rate = round((phishing / total) * 100, 1) if total > 0 else 0

        hourly = {}
        for e in runtime_emails:
            try:
                dt = e["date"][:13]
                hourly[dt] = hourly.get(dt, 0) + 1
            except Exception:
                pass

        phishing_list = [
            {k: v for k, v in e.items() if k not in ("body_full", "report")}
            for e in runtime_emails if e["status"] == "danger"
        ][:5]

    return jsonify({
        "status": "success",
        "total": total,
        "phishing": phishing,
        "safe": safe,
        "threat_rate": threat_rate,
        "hourly": hourly,
        "recent_phishing": phishing_list
    })


@app.route("/api/runtime/disconnect", methods=["POST"])
def runtime_disconnect():
    with runtime_lock:
        if runtime_connection.get("imap"):
            try:
                runtime_connection["imap"].logout()
            except Exception:
                pass
        runtime_connection["connected"] = False
        runtime_connection["email"] = None
        runtime_connection["imap"] = None
        runtime_emails.clear()
    return jsonify({"status": "success", "message": "Disconnected."})


if __name__ == "__main__":
    app.run(debug=True)
