from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import google.generativeai as genai
import os
import re
import html
import csv
from datetime import datetime

app = Flask(__name__)

# 🔑 IMPORTANT: Replace with your actual Gemini API Key!
genai.configure(api_key="YOUR_ACTUAL_API_KEY")

# ==========================================
# 📊 KAGGLE DATASET LOADER
# ==========================================
log_database = {}

def load_kaggle_data():
    try:
        with open('attacks.csv', mode='r', encoding='utf-8-sig') as file:
            csv_reader = csv.DictReader(file, quoting=csv.QUOTE_NONE)
            for row in csv_reader:
                timestamp = row.get('Timestamp', '')
                if not timestamp: continue
                parts = timestamp.split(' ')
                date = parts[0]
                time_val = parts[1] if len(parts) > 1 else "00:00:00"
                sev = str(row.get('Severity Level', 'Low')).upper()
                badge = "[CRITICAL]" if "HIGH" in sev or "CRITICAL" in sev else "[WARNING]" if "MEDIUM" in sev else "[INFO]"
                ip = row.get('Source IP Address', 'Unknown')
                attack = row.get('Attack Type', 'Threat Detected')
                payload = str(row.get('Payload Data', '')).replace('"', '')[:45]
                entry = f"{time_val} {badge} - Blocked {attack} from {ip}. Payload: '{payload}...'"
                if date not in log_database: log_database[date] = []
                log_database[date].append(entry)
        print("✅ Kaggle Data Loaded.")
    except Exception as e: 
        print(f"⚠️ CSV Error: {e}")

load_kaggle_data()

TODAY = datetime.now().strftime("%Y-%m-%d")
if TODAY not in log_database:
    log_database[TODAY] = [f"{datetime.now().strftime('%I:%M %p')} [INFO] - CyberShield Edge Firewall initialized and active."]

# ==========================================
# 🛡️ CYBERSHIELD LIVE FIREWALL (WAF)
# ==========================================
THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or 1=1|--)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|javascript:|onerror=|<img src=)", re.IGNORECASE)
}

@app.before_request
def live_firewall():
    # EXEMPT ROUTES: These paths bypass WAF so your users can log in, subscribe, and use the dashboard.
    if request.path in ['/dashboard', '/manage', '/get-logs', '/ask-ai', '/static', '/subscribe']: 
        return
        
    data = list(request.args.values()) + list(request.form.values())
    for payload in data:
        for threat, pattern in THREAT_PATTERNS.items():
            if pattern.search(payload):
                log = f"{datetime.now().strftime('%I:%M %p')} [CRITICAL] - LIVE BLOCK: {threat} from {request.remote_addr}."
                if TODAY not in log_database: log_database[TODAY] = []
                log_database[TODAY].insert(0, log)
                abort(403, description=f"🛑 CYBERSHIELD EDGE BLOCK: Suspected {threat} attack detected.")

# ==========================================
# 🌐 NORMAL ROUTES
# ==========================================
@app.route('/')
def home(): 
    return render_template('index.html')

# This is the route that fixes your "URL does not exist" error!
@app.route('/subscribe', methods=['POST'])
def subscribe(): 
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard(): 
    return render_template('dashboard.html')

@app.route('/manage')
def manage(): 
    return render_template('subscription.html')

# ==========================================
# 🤖 API ROUTES (Logs & AI)
# ==========================================
@app.route('/get-logs', methods=['POST'])
def get_logs():
    date = request.json.get('date')
    return jsonify({"logs": log_database.get(date, ["✅ Perimeter Secure. No threats detected."])})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"Analyze log: {request.json.get('log_context')}. Question: {request.json.get('message')}"
        response = model.generate_content(prompt)
        return jsonify({"response": response.text})
    except Exception as e: 
        return jsonify({"response": f"AI Error: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)