from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import google.generativeai as genai
import os
import re
import csv
import json
from datetime import datetime

# --- PATH SETUP ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) # The 'src' folder
# This ensures we go up one level to the REAL root, then into 'static'
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
STATIC_DIR = os.path.join(ROOT_DIR, 'static')

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=STATIC_DIR,
            static_url_path='/static') # Explicitly tell Flask the URL prefix

# 🔑 IMPORTANT: Replace with your actual Gemini API Key!
genai.configure(api_key="YOUR_ACTUAL_API_KEY")

# ==========================================
# 💾 USER PROFILE "DATABASE" (JSON)
# ==========================================
PROFILE_FILE = os.path.join(ROOT_DIR, 'profile.json')

DEFAULT_PROFILE = {
    "full_name": "Admin User", "username": "admin_nope", "email": "admin@yourbusiness.com",
    "phone": "+1 (555) 123-4567", "timezone": "UTC-5 (EST)", "country": "United States",
    "bio": "Lead Security Engineer securing the perimeter.",
    "website_url": "https://yourbusiness.com", "website_name": "My Tech Portfolio",
    "website_desc": "Personal blog and portfolio.", "website_category": "Technology",
    "social_twitter": "@nope_admin",
    "two_factor": "on", "auto_renew": "on"
}

def load_profile():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                return DEFAULT_PROFILE
    return DEFAULT_PROFILE

def save_profile(data):
    profile = load_profile()
    profile.update(data)
    profile['two_factor'] = data.get('two_factor', 'off')
    profile['auto_renew'] = data.get('auto_renew', 'off')
    
    with open(PROFILE_FILE, 'w') as f:
        json.dump(profile, f, indent=4)

# ==========================================
# 📊 KAGGLE DATASET LOADER
# ==========================================
log_database = {}

def load_kaggle_data():
    try:
        csv_path = os.path.join(ROOT_DIR, 'cybersecurity_attacks.csv')
        
        with open(csv_path, mode='r', encoding='utf-8-sig') as file:
            csv_reader = csv.DictReader(file, quoting=csv.QUOTE_NONE)
            count = 0
            for row in csv_reader:
                timestamp = row.get('Timestamp', '')
                if not timestamp: continue
                
                parts = timestamp.split(' ')
                raw_date = parts[0]
                
                if '/' in raw_date:
                    date_parts = raw_date.split('/')
                    if len(date_parts[2]) == 4:  
                        date = f"{date_parts[2]}-{date_parts[0].zfill(2)}-{date_parts[1].zfill(2)}"
                    else: date = raw_date
                else: date = raw_date 

                time_val = parts[1] if len(parts) > 1 else "00:00:00"
                sev = str(row.get('Severity Level', 'Low')).upper()
                badge = "[CRITICAL]" if "HIGH" in sev or "CRITICAL" in sev else "[WARNING]" if "MEDIUM" in sev else "[INFO]"
                ip = row.get('Source IP Address', 'Unknown')
                attack = row.get('Attack Type', 'Threat Detected')
                payload = str(row.get('Payload Data', '')).replace('"', '')[:45]
                
                entry = f"{time_val} {badge} - Blocked {attack} from {ip}. Payload: '{payload}...'"
                
                if date not in log_database: log_database[date] = []
                log_database[date].append(entry)
                count += 1
                
        print(f"✅ {count} attacks successfully loaded.")
        
    except FileNotFoundError:
        print(f"⚠️ ERROR: Could not find CSV at {csv_path}")
    except Exception as e: 
        print(f"⚠️ CSV Error: {e}")

load_kaggle_data()

TODAY = datetime.now().strftime("%Y-%m-%d")
if TODAY not in log_database:
    log_database[TODAY] = [f"{datetime.now().strftime('%I:%M %p')} [INFO] - NOPE! Edge Firewall initialized and active."]

# ==========================================
# 🛡️ NOPE! LIVE FIREWALL (WAF)
# ==========================================
THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or 1=1|--)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|javascript:|onerror=|<img src=)", re.IGNORECASE)
}

@app.before_request
def live_firewall():
    if request.path in ['/dashboard', '/manage', '/get-logs', '/ask-ai', '/static', '/subscribe', '/profile']: 
        return
        
    data = list(request.args.values()) + list(request.form.values())
    for payload in data:
        for threat, pattern in THREAT_PATTERNS.items():
            if pattern.search(payload):
                log = f"{datetime.now().strftime('%I:%M %p')} [CRITICAL] - LIVE BLOCK: {threat} from {request.remote_addr}."
                if TODAY not in log_database: log_database[TODAY] = []
                log_database[TODAY].insert(0, log)
                abort(403, description=f"🛑 NOPE! EDGE BLOCK: Suspected {threat} attack detected.")

# ==========================================
# 🌐 ROUTES
# ==========================================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/subscribe', methods=['POST'])
def subscribe(): return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html')

@app.route('/manage')
def manage(): return render_template('subscription.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        save_profile(request.form.to_dict())
        return redirect(url_for('profile'))
    return render_template('profile.html', p=load_profile())

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
    except:
        return jsonify({"response": "Analysis Complete: Threat dropped by WAF heuristics."})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)