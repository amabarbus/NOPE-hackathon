# NOPE! (Network Operations Protection Edge) 🛡️

A professional-grade Cloud Firewall and AI Security Analyst for modern web applications.

## 🚀 Features
- **WAF (Web Application Firewall):** Real-time protection against SQL Injection, XSS, and Path Traversal.
- **Smart Rate Limiting:** Automatically blocks spam and brute-force attempts.
- **AI Security Analyst:** Uses Google Gemini to explain attacks and provide mitigation strategies.
- **Multi-Channel Alerts:** Instant Push notifications (via ntfy.sh) and Email alerts.
- **Interactive Dashboard:** Modern dark-themed UI for monitoring threats in real-time.

## 🛠️ Setup & Running

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment:**
   ```bash
   export GEMINI_API_KEY="your_api_key"
   export SENDER_EMAIL="your_email@gmail.com"
   export SENDER_PASSWORD="your_app_password"
   ```

3. **Start the App:**
   ```bash
   ./start.sh
   ```

## 🧪 Testing
Run the security test suite to verify protection:
```bash
cd testproto && ../venv/bin/python test.py
```

Check your notifications:
- **Push:** [https://ntfy.sh/nope-hackathon](https://ntfy.sh/nope-hackathon)
- **Email:** Sent to the configured `ADMIN_EMAIL`.
