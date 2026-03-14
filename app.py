from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import google.generativeai as genai
import os
import re
import html
import csv
from datetime import datetime

app = Flask(__name__)

# IMPORTANT: Paste your actual Gemini API key here!
genai.configure(api_key="AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q")

# ==========================================
# 📊 KAGGLE DATASET LOADER (HISTORICAL DATA)
# ==========================================
log_database = {}

def load_kaggle_data():
    try:
        # csv.QUOTE_NONE forces Python to ignore mismatched quotes in Kaggle data!
        with open('cybersecurity_attacks.csv', mode='r', encoding='utf-8-sig') as file:
            csv_reader = csv.DictReader(file, quoting=csv.QUOTE_NONE)
            
            loaded_count = 0
            for row in csv_reader:
                timestamp = row.get('Timestamp', '')
                if not timestamp: 
                    continue
                
                # Split '2023-05-30 06:33:58' into Date and Time
                parts = timestamp.split(' ')
                date = parts[0]
                time_val = parts[1] if len(parts) > 1 else "Unknown Time"
                
                # Convert the CSV's Severity Level to our UI Badges
                sev_raw = str(row.get('Severity Level', 'Low')).upper()
                if "HIGH" in sev_raw or "CRITICAL" in sev_raw:
                    badge = "[CRITICAL]"
                elif "MEDIUM" in sev_raw:
                    badge = "[WARNING]"
                else:
                    badge = "[INFO]"
                
                ip = row.get('Source IP Address', 'Unknown')
                attack_type = row.get('Attack Type', 'Cyber Threat')
                
                # Trim payload to 45 chars so it doesn't break the UI, and strip stray quotes
                payload = str(row.get('Payload Data', '')).replace('"', '')[:45] 
                
                log_entry = f"{time_val} {badge} - Blocked {attack_type} from {ip}. Payload: '{payload}...'"
                
                if date not in log_database:
                    log_database[date] = []
                log_database[date].append(log_entry)
                loaded_count += 1
                
        print(f"✅ Kaggle Dataset Loaded! Found {loaded_count} attacks.")
        print(f"📅 Dates available in database: {list(log_database.keys())}")
        
    except Exception as e:
        print(f"⚠️ Could not load CSV: {e}")

# Load historical data
load_kaggle_data()

# Make sure today's date exists in the database for the live WAF
TODAY = datetime.now().strftime("%Y-%m-%d")
if TODAY not in log_database:
    log_database[TODAY] = [f"{datetime.now().strftime('%I:%M %p')} [INFO] - CyberShield Edge Firewall initialized and active."]

# ==========================================
# 🛡️ CYBERSHIELD LIVE FIREWALL (WAF)
# ==========================================
THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or 1=1|--)", re.IGNORECASE),
    "XSS (Cross-Site Scripting)": re.compile(r"(<script>|javascript:|onerror=|<img src=)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd)", re.IGNORECASE)
}

@app.before_request
def live_firewall():
    if request.path in ['/dashboard', '/get-logs', '/ask-ai']:
        return

    incoming_data = list(request.args.values()) + list(request.form.values())
    
    for payload in incoming_data:
        for threat_type, pattern in THREAT_PATTERNS.items():
            if pattern.search(payload):
                time_now = datetime.now().strftime("%I:%M %p")
                ip = request.remote_addr or "Unknown IP"
                
                short_payload = (payload[:30] + '...') if len(payload) > 30 else payload
                safe_payload = html.escape(short_payload) 
                
                live_log = f"{time_now} [CRITICAL] - LIVE BLOCK {threat_type} from {ip}. Payload: '{safe_payload}'"

                if TODAY not in log_database:
                    log_database[TODAY] = []
                log_database[TODAY].insert(0, live_log) 
                
                abort(403, description=f"🛑 CYBERSHIELD EDGE BLOCK: Suspected {threat_type} attack detected.")

# ==========================================
# NORMAL ROUTES
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    client_domain = request.form.get('domain', 'yourbusiness.com')
    print(f"🚀 Provisioning Cloud Armor routing for: {client_domain}")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/manage')
def manage():
    # This looks for the subscription.html file you created
    return render_template('subscription.html')

@app.route('/get-logs', methods=['POST'])
def get_logs():
    selected_date = request.json.get('date')
    logs = log_database.get(selected_date, ["✅ No attacks recorded on this date. Cloud perimeter secure."])
    return jsonify({"logs": logs})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    user_question = request.json.get('message')
    log_context = request.json.get('log_context')
    
    system_prompt = f"""
    You are CyberShield AI. Analyze this specific Cloud Firewall log: "{log_context}"
    User Question: "{user_question}"
    Explain what the hackers were trying to do to the client's site, how the firewall stopped them, and why the user is safe in simple terms.
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(system_prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        return jsonify({"response": f"SYSTEM ERROR: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)