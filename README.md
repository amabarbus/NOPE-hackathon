# NOPE! (Network Operations Protection Edge) 🛡️

**"The Intelligent Perimeter for the Modern Web."**

NOPE! is a centralized **Security-as-a-Service (SECaaS)** platform that provides professional-grade Web Application Firewall (WAF) protection and AI-driven security auditing to any website in under 60 seconds.

---

## 🚀 The Core Innovation

Most security tools are hard to configure and isolated. **NOPE!** changes the game by centralizing protection:
- **Centralized Hub:** One "Brain" that protects an entire ecosystem of partner sites.
- **AI-Active Defense:** Uses **Google Gemini 2.5** to not just analyze logs, but to **generate real-time WAF rules** to block zero-day threats.
- **Instant Compliance:** Transforms raw attack logs into professional **ISO 27001 Security Audit Reports** (PDF) using AI.

---

## ✨ Key Features

### 🛡️ Next-Gen WAF
- **Heuristic Engine:** Real-time blocking of SQL Injection, XSS, and Path Traversal.
- **Smart Rate Limiting:** Behavioral analysis to stop DDoS and brute-force attempts.
- **Global Blocklist:** Instantly ban malicious IPs across all protected sites with one click.

### 🤖 Gemini AI Security Analyst
- **Risk Scoring:** Every attack is assigned a 1-10 Risk Score with a plain-English explanation.
- **One-Click Rule Gen:** See a new attack? Click "AI Generate Rule" to create a custom Regex block instantly.
- **Audit Engine:** Automated ISO 27001 compliance mapping and PDF report generation.

### 🔌 Security-as-a-Service (SDK)
- **Universal API:** Protect any site (Node, Go, PHP, Python) via the `/api/v1/inspect` endpoint.
- **60-Second Integration:** Drop-in Flask middleware included for instant protection.

---

## 🛠️ Tech Stack
- **Backend:** Python / Flask
- **AI:** Google Gemini 2.5 Flash
- **Frontend:** Tailwind CSS / Lucide Icons / html2pdf
- **Alerts:** ntfy.sh (Push & Email)

---

## 📦 Project Structure

```bash
├── src/                # Central Security Hub (The "Brain")
├── sdk/                # Drop-in Middleware for Partner Sites
├── demo/               
│   ├── partner_site/   # Example of an external site protected by NOPE!
│   ├── traffic_gen/    # Automated "Live Attack" simulator for demos
│   └── demo_scenario/  # Guided walkthrough script
├── tests/              # Full security integration test suite
├── launcher.sh         # One-script startup for the entire ecosystem
└── run.py              # Hub entry point
```

---

## 🚦 Quick Start (For Demo)

### 1. Prerequisites
- Python 3.10+
- A Google Gemini API Key

### 2. Setup
```bash
# Clone and install
git clone https://github.com/your-username/nope-hackathon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Launch the Ecosystem
```bash
# This starts the Hub, a Partner Site, and a Traffic Generator
bash launcher.sh
```

### 4. View the Magic
- **Dashboard:** [http://localhost:8080/dashboard](http://localhost:8080/dashboard)
- **Partner Site:** [http://localhost:9000](http://localhost:9000)

---

## 🔌 Integrating the SDK (60-Second Setup)

To protect your own Flask app, copy `sdk/nope_sdk.py` to your project and add:

```python
from sdk.nope_sdk import nope_middleware

@app.before_request
def security_gate():
    return nope_middleware() # Every request is now scanned by the NOPE! Hub
```

---

## 🏆 Hackathon Credits
Developed for the **NOPE! Hackathon 2026**. Built to demonstrate the power of centralized, AI-enhanced network security.
