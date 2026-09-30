# Aegis — AI-Powered Phishing & Scam Message Detector
> **Know if a message is trying to scam you — before you click anything.**

Aegis is an AI-powered phishing and scam detection system that analyzes **emails, SMS messages, social-media messages, DMs, and embedded URLs**. It combines machine learning, text analysis, URL analysis, and security heuristics to provide a real-time **0–100 risk score** along with a clear, human-readable explanation of the suspicious patterns it detects.

### 🔍 Two Ways to Analyze

Aegis supports both **Single Message Analysis** and **Conversation Thread Analysis**.

- **Single Message:** Analyze an individual email, SMS, DM, or suspicious message and receive its risk score, detected red flags, and explanation.
- **Conversation Thread:** Analyze an entire conversation message-by-message to identify **risk escalation, manipulation patterns, increasing financial pressure, and scam progression** that may not be obvious from a single message.

### 🚨 Already Been Scammed?

Aegis is also designed to help **after a scam has already happened**. If you have clicked a suspicious link, shared sensitive information, or lost money, the application provides an **"Already Been Scammed?"** section with immediate safety guidance and a direct link to India's official **National Cyber Crime Reporting Portal**.

👉 **Report Cyber Crime:** https://www.cybercrime.gov.in/

📞 **Cyber Crime Helpline:** **1930**

Users are encouraged to report financial fraud and other cybercrime **as soon as possible**, while preserving screenshots, transaction details, sender information, and other evidence.

> **Aegis doesn't just help you detect a scam — it helps you understand the risk, recognize how the scam is developing, and know what to do next.**

Built for the **NLP — AI-Powered Phishing & Scam Message Detector** challenge.

---

## Why this approach

Most simple phishing detectors are one of two things: a keyword blocklist (brittle, easy to evade, no scoring) or a black-box ML model (accurate-ish, but tells the user nothing). Aegis combines both, deliberately, so it gets the strengths of each:

| Layer | What it catches | Why it's explainable |
|---|---|---|
| **URL heuristics** (`app/url_analysis.py`) | Link shorteners, IP-literal links, lookalike/typosquatted brand domains, suspicious TLDs, `@`-obfuscation, excessive subdomains/hyphens, missing HTTPS, credential-harvesting keywords in the URL path | Every check is an independent, named rule — the output *is* the explanation |
| **Text heuristics** (`app/features.py`) | Urgency/pressure language, threats, prize/reward bait, direct requests for passwords/OTP/SSN/card data, generic greetings, brand impersonation, ALL-CAPS/exclamation spam | Same — each rule fires with its own plain-English message |
| **ML model** (`app/model.py`, `train_model.py`) | Statistical language patterns a fixed rule list can't anticipate — the "unknown unknowns" | Logistic Regression's coefficients map 1:1 to vocabulary terms, so we surface the *actual words* that most pushed the model's decision (see "top_ml_terms" in the API) |

`app/risk_engine.py` blends all three into one score (50% ML / 30% text rules / 20% URL rules), then returns every triggered flag, tagged by severity and source, so the verdict is always traceable back to specific evidence — never just a mystery number.

This means Aegis can still flag a dangerous message even on wording the model has never seen (the rules catch it), and can still catch subtle scams that don't match any hand-written rule (the model catches it). That combination is the core pitch of the project.

---

## Conversation-thread mode: catching long-con scams

Single-message scoring misses a whole category of scam: romance scams and fake investment "recruiters" deliberately spread their manipulation across many messages, so no single one looks dangerous alone. A message asking for money on message 1 gets deleted; the same message after 10 messages of manufactured trust often works.

Switching the scanner to **Conversation thread** mode (paste one message per line, oldest first) runs `app/conversation_engine.py`, which adds two things on top of the normal per-message scoring:

- **Tactic tagging** (`app/tactics.py`): every message is classified into a manipulation stage — rapport building, trust/sympathy building, isolation ("don't tell anyone"), opportunity pitch, urgency, direct financial ask, or escalation.
- **Context-aware scoring**: if a message asks for money or escalates the ask *after* earlier messages showed rapport/trust/isolation tactics, its score is boosted and flagged — because that build-up-then-ask sequence is itself the red flag, not just the ask in isolation.

The API also returns a per-message score array and an `escalation_detected` flag (true when risk climbs meaningfully from the first third of the conversation to the last third), which the frontend plots as a line chart so the escalation pattern is visible at a glance.

## Architecture

```
                     ┌─────────────────────────┐
   message text ───▶ │      risk_engine.py      │
                     │  (weighted signal fusion) │
                     └───────────┬─────────────┘
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
        features.py        url_analysis.py       model.py
      (text heuristics)   (URL heuristics)   (TF-IDF + LogReg)
                 │                │                │
                 └────────────────┴────────────────┘
                                  ▼
                  { risk_score, risk_level, flags[],
                    urls[], top_ml_terms[] }
                                  ▼
                    Flask API  (app/main.py)
                                  ▼
                  frontend/index.html (analyst console UI)
```

---

## Tech stack

- **Backend:** Python, Flask, gunicorn
- **ML:** scikit-learn (TF-IDF vectorizer + Logistic Regression), joblib for persistence
- **Frontend:** single self-contained HTML/CSS/vanilla JS file (no build step, no framework needed)
- **Dataset:** programmatically generated from curated phishing-email / smishing / social-scam / legitimate-message templates (`generate_dataset.py`) — fully reproducible, no external downloads required

---

## Project structure

```
aegis-phishing-detector/
├── app/
│   ├── main.py                # Flask app: API + serves the frontend
│   ├── risk_engine.py         # combines ML + heuristics into final score
│   ├── conversation_engine.py # multi-message thread analysis + escalation detection
│   ├── tactics.py             # manipulation-tactic tagging per message
│   ├── features.py            # text/language heuristics
│   ├── url_analysis.py        # URL structure heuristics
│   └── model.py               # loads/trains the TF-IDF + LogReg model
├── frontend/
│   └── index.html        # the web UI
├── data/
│   └── dataset.csv        # generated training data
├── models/                 # trained model artifacts (generated, gitignored)
├── tests/
│   └── test_examples.py   # smoke tests
├── generate_dataset.py     # builds data/dataset.csv
├── train_model.py          # trains + saves the classifier
├── requirements.txt
├── Dockerfile
├── render.yaml              # one-click Render deploy config
├── Procfile                  # Heroku/Railway-style start command
└── README.md
```

---

## Running locally

```bash
git clone <your-repo-url>
cd aegis-phishing-detector
pip install -r requirements.txt

# optional — the app trains automatically on first request if you skip this:
python generate_dataset.py
python train_model.py

python -m app.main
# open http://localhost:5000
```

Or with Docker:

```bash
docker build -t aegis .
docker run -p 8000:8000 aegis
# open http://localhost:8000
```

### API

```
POST /api/analyze
Content-Type: application/json

{ "text": "Dear Customer, your account has been suspended. Verify at bit.ly/xyz..." }
```

```jsonc
{
  "risk_score": 78,
  "risk_level": "Dangerous",
  "ml_probability": 0.91,
  "heuristic_text_score": 63,
  "heuristic_url_score": 45,
  "flags": [
    {"severity": "high", "source": "url", "message": "[bit.ly/xyz] Uses the link shortener 'bit.ly', which hides the real destination"},
    {"severity": "medium", "source": "text", "message": "Uses urgency/pressure language to rush the reader into acting without thinking"}
  ],
  "urls": [{"url": "bit.ly/xyz", "score": 45, "flags": ["..."]}],
  "top_ml_terms": [{"term": "suspended", "weight": 0.42}]
}
```

Run the smoke tests: `pytest tests/` (or `python tests/test_examples.py`).

---

## Deploying 

**Render (recommended, free tier, `render.yaml` included):**
1. Push this repo to GitHub (public).
2. Go to [render.com](https://render.com) → New → Blueprint → select your repo. Render will read `render.yaml` and configure the build/start commands automatically.
3. Once deployed, copy the live `.onrender.com` URL into this README and your submission.

**Railway / Heroku:** uses the included `Procfile` the same way — connect the repo and deploy.

**Any Docker host (Fly.io, Cloud Run, etc.):** `docker build -t aegis . && docker run -p 8000:8000 aegis`.

---

## Improving the model further

The bundled dataset is a template-generated corpus built for full reproducibility without any internet access. It's enough to demonstrate the architecture end-to-end (held-out accuracy prints when you run `train_model.py`), but for production-grade generalization to real-world phrasing, swap in a real corpus, for example:
- UCI SMS Spam Collection
- Nazario Phishing Email Corpus
- Kaggle's "Phishing Email Detection" datasets

Just drop a CSV with `text,label` columns into `data/dataset.csv` (or merge it with the generated one) and rerun `python train_model.py`. Nothing else needs to change — `app/model.py` picks up the new artifacts automatically.

## Limitations & responsible use

- This is a decision-support tool, not a guarantee: a low score does not mean a message is safe, and it should never be the only line of defense.
- No URLs are ever fetched or visited — analysis is purely structural/textual, so it's fast and safe to run on unknown links, but it can't detect a malicious page hosted on an otherwise clean-looking domain.
- The frontend explicitly reminds users to verify suspicious messages through an official channel rather than any link inside the message itself.

## License

MIT — see `LICENSE`.
