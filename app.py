from flask import Flask, render_template, request, jsonify
import pickle
import re
import torch
import requests
import os
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

    try:
        inputs = email_tokenizer(
            email_text,
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

        preview = email_text[:200] + "..." if len(email_text) > 200 else email_text

        if predicted_class == 1:
            return jsonify({
                "status": "danger",
                "label": "Phishing Email Detected",
                "message": "This email is likely a phishing attempt.",
                "confidence": round(confidence, 1),
                "preview": preview
            })
        else:
            return jsonify({
                "status": "safe",
                "label": "Legitimate Email",
                "message": "This email appears to be legitimate.",
                "confidence": round(confidence, 1),
                "preview": preview
            })

    except Exception:
        return jsonify({
            "status": "error",
            "label": "Analysis Error",
            "message": "Could not analyze the email. Please try again."
        })


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


if __name__ == "__main__":
    app.run(debug=True)
