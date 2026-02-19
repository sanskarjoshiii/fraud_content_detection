# PhishGuard — Cybersecurity Fraud Detection Platform

PhishGuard is a full-stack cybersecurity web application that detects phishing threats in **websites (URLs)** and **emails** using machine learning and large language models. It provides an interactive dashboard, live Gmail inbox scanning, AI-generated security reports, and downloadable PDF analysis — all from a single browser interface.

---

## Features

| Feature | Details |
|---|---|
| **Website Scanner** | Detects phishing URLs using TF-IDF + Logistic Regression trained on 549K+ URLs |
| **Email Scanner** | Analyzes pasted email content using a fine-tuned BERT model (110M parameters) |
| **Runtime Email Scanner** | Connects to a Gmail inbox via IMAP and scans incoming emails automatically |
| **AI Security Reports** | Generates detailed analyst-grade reports via Groq LLM (Llama 3.3 70B) |
| **PDF Export** | Download any AI report as a formatted PDF using jsPDF |
| **Analytics Dashboard** | Charts for email/URL analysis ratios, 7-day activity, and threat rate |
| **Scan History** | Persistent history of all URL and email scans within the session |
| **Runtime Dashboard** | Live stats for connected inbox — total scans, phishing count, threat rate |
| **Trusted Domain Whitelist** | 50+ known legitimate domains (Google, Amazon, Microsoft, etc.) bypass false-positives |
| **Confidence Scoring** | Every verdict comes with a percentage confidence score |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              PRESENTATION LAYER (Browser)                │
│  Dashboard · URL Scanner · Email Scanner · Runtime Monitor│
│  Chart.js · jsPDF · Marked.js                           │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP / REST API (JSON)
┌───────────────────────▼─────────────────────────────────┐
│           APPLICATION LAYER (Flask — app.py)             │
│  POST /api/scan-url     POST /api/scan-email             │
│  POST /api/report       GET|POST|DELETE /api/runtime/*   │
└────┬──────────┬─────────────┬──────────────┬────────────┘
     │          │             │              │
┌────▼───┐ ┌───▼────┐  ┌─────▼─────┐  ┌────▼──────────┐
│  URL   │ │  BERT  │  │ Groq LLM  │  │Security Logic │
│TF-IDF +│ │110M    │  │Llama 3.3  │  │Trusted Domains│
│Log.Reg.│ │params  │  │70B        │  │Safety Override│
└────┬───┘ └───┬────┘  └─────┬─────┘  └────┬──────────┘
     │         │             │              │
┌────▼─────────▼─────────────▼──────────────▼────────────┐
│                   EXTERNAL SERVICES                      │
│  Groq Cloud API · Gmail IMAP (SSL:993) · AI Reports     │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│                    DATA & MODELS                         │
│  vectorizer.pkl · phishing.pkl · email_phishing/ · .env  │
└─────────────────────────────────────────────────────────┘
```

See [`PhishGuard_Architecture.jpg`](PhishGuard_Architecture.jpg) for the full detailed diagram.

---

## Project Structure

```
Fraud-Detection/
├── app.py                          # Flask backend — all routes & ML logic
├── templates/
│   └── index.html                  # Single-page dashboard (HTML/CSS/JS)
├── vectorizer.pkl                  # TF-IDF vectorizer for URL feature extraction
├── phishing.pkl                    # Logistic Regression URL classification model
├── email_phishing/                 # Fine-tuned BERT model (not tracked in git)
│   ├── config.json
│   ├── model.safetensors
│   ├── tokenizer.json
│   └── tokenizer_config.json
├── requirements.txt                # Python dependencies
├── .env                            # API keys (not tracked in git)
├── .gitignore
├── PhishGuard_Architecture.jpg     # System architecture diagram
└── CONTENTS/
    └── SNAPSHOTS/                  # UI screenshots
```

---

## Tech Stack

**Backend**
- [Flask](https://flask.palletsprojects.com/) — Python web framework
- [scikit-learn](https://scikit-learn.org/) — TF-IDF vectorizer + Logistic Regression (URL model)
- [PyTorch](https://pytorch.org/) + [Transformers](https://huggingface.co/docs/transformers) — BERT email classification model
- [Groq API](https://console.groq.com/) — Llama 3.3 70B for LLM-based email analysis & report generation
- `imaplib` — Gmail IMAP integration for live inbox scanning
- `threading` — Thread-safe in-memory email state management

**Frontend**
- Vanilla JavaScript + HTML5 + CSS3
- [Chart.js](https://www.chartjs.org/) — Donut and bar charts for analytics
- [jsPDF](https://github.com/parallax/jsPDF) — Client-side PDF report export
- [Marked.js](https://marked.js.org/) — Markdown rendering for AI reports

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Fraud-Detection.git
cd Fraud-Detection
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> Python 3.9+ is recommended. For GPU acceleration, install the CUDA-compatible version of PyTorch.

### 3. Add environment variables

Create a `.env` file in the root directory:

```env
GROQ_API_KEY=your_groq_api_key_here
GROQ_URL=https://api.groq.com/openai/v1/chat/completions
GROQ_MODEL=llama-3.3-70b-versatile
```

Get a free API key at [console.groq.com](https://console.groq.com/).

### 4. Add the BERT model

Place the fine-tuned BERT model files inside the `email_phishing/` folder:

```
email_phishing/
├── config.json
├── model.safetensors
├── tokenizer.json
└── tokenizer_config.json
```

> The model is excluded from version control via `.gitignore` due to its size. Obtain it from the project maintainer or fine-tune `bert-base-uncased` on a phishing email dataset.

### 5. Run the application

```bash
python app.py
```

Open your browser at `http://127.0.0.1:5000`.

---

## Usage

### Website Scanner
1. Click **Website Scanner** in the sidebar.
2. Enter a full URL (e.g., `https://example-site.com`).
3. Click **Scan** — the ML model returns a verdict instantly.
4. Click **Generate AI Report** for a detailed analyst breakdown.

### Email Scanner
1. Click **Email Scanner** in the sidebar.
2. Paste the full email body into the text area.
3. Click **Analyze** — the BERT model classifies it as phishing or legitimate.
4. Click **Generate AI Report** for phishing indicator analysis and recommendations.

### Runtime Email Scanner
1. Click **Runtime Scanner** in the sidebar.
2. Enter your Gmail address and an [App Password](https://myaccount.google.com/apppasswords).
3. Click **Connect** — the app fetches your last 15 emails and scans each one.
4. Click **Fetch New** to poll for unseen emails.
5. Click any email row to view the full content and generate a detailed report.
6. Visit **Runtime Dashboard** for live statistics and charts.

> **Note:** Standard Gmail passwords do not work. You must use a Google App Password with 2-Step Verification enabled.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan-url` | Scan a URL for phishing |
| `POST` | `/api/scan-email` | Analyze email text with BERT |
| `POST` | `/api/report` | Generate AI report (URL or email) |
| `POST` | `/api/runtime/connect` | Connect Gmail IMAP + fetch initial emails |
| `POST` | `/api/runtime/fetch` | Fetch new unseen emails |
| `GET` | `/api/runtime/emails` | List all scanned emails |
| `GET` | `/api/runtime/email/<id>` | Get a single email with full body |
| `POST` | `/api/runtime/report/<id>` | Generate AI report for a runtime email |
| `DELETE` | `/api/runtime/email/<id>` | Remove a single email |
| `DELETE` | `/api/runtime/emails` | Clear all emails |
| `GET` | `/api/runtime/stats` | Get inbox statistics |
| `POST` | `/api/runtime/disconnect` | Disconnect IMAP session |

### Example: Scan a URL

```bash
curl -X POST http://127.0.0.1:5000/api/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.xyz/login"}'
```

**Response:**
```json
{
  "status": "danger",
  "label": "Phishing Detected",
  "message": "This website is likely a phishing site. Do not enter any personal information.",
  "url": "https://suspicious-site.xyz/login"
}
```

---

## Screenshots

| Dashboard | Website Scanner |
|---|---|
| ![Dashboard](CONTENTS/SNAPSHOTS/OVERALL%20DASHBOARD.png) | ![Website Scanning](CONTENTS/SNAPSHOTS/WEBSITE%20SCANNING.png) |

| Email Scanner | AI Report |
|---|---|
| ![Email Scanning](CONTENTS/SNAPSHOTS/EMAIL%20SCANNING.png) | ![Report Generated](CONTENTS/SNAPSHOTS/REPORT%20GENERATED.png) |

| Runtime Scanner | Runtime Dashboard |
|---|---|
| ![Runtime Scanning](CONTENTS/SNAPSHOTS/RUNTIME%20SCANNING.png) | ![Runtime Dashboard](CONTENTS/SNAPSHOTS/DASHBOARD%20FOR%20RUNTIME.png) |

---

## Models

### URL Phishing Detection
- **Algorithm:** Logistic Regression
- **Features:** TF-IDF character/word n-grams on the URL string
- **Preprocessing:** Strips `http(s)://` and `www.` prefix before vectorization
- **Training data:** 549,000+ labeled URLs (phishing / legitimate)
- **Artifacts:** `vectorizer.pkl`, `phishing.pkl`

### Email Phishing Detection
- **Architecture:** `bert-base-uncased` fine-tuned for binary sequence classification
- **Parameters:** 110M
- **Framework:** PyTorch + Hugging Face Transformers
- **Input:** Raw email body text, tokenized to max 512 tokens
- **Output:** Softmax probability over [legitimate, phishing]
- **Device:** Automatically uses CUDA if available, otherwise CPU

### LLM-Based Runtime Analysis
- **Model:** Llama 3.3 70B Versatile via Groq API
- **Used for:** Runtime email classification and AI report generation
- **Prompt strategy:** Zero-shot classification with explicit phishing rules; JSON-structured output
- **Safety logic:** Trusted domain whitelist overrides LLM verdict below 95% confidence

---

## Security Notes

- The `.env` file is excluded from version control — never commit API keys.
- Model files (`*.pkl`, `email_phishing/`) are excluded from git due to size and sensitivity.
- Gmail App Passwords are used only in-memory and never stored to disk.
- All email scan state is held in-memory per server session; it clears on restart.

---

## Requirements

```
flask
scikit-learn
torch
transformers
requests
python-dotenv
```

Install with:
```bash
pip install -r requirements.txt
```

---

## Demo

A recorded demo is available at [`CONTENTS/FRAUD_DETECTION_VIDEO.mp4`](CONTENTS/FRAUD_DETECTION_VIDEO.mp4).

---

## License

This project is for educational and research purposes.
