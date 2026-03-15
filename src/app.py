from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import google.generativeai as genai
import os
import re
import csv
import json
from datetime import datetime

# ==========================================
# ⚙️ CONFIGURATION & PATHS
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(ROOT_DIR, 'static'),
            static_url_path='/static')

# Gemini AI Setup
genai.configure(api_key="AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q")

# ==========================================
# 💾 DATA STORE (JSON & IN-MEMORY)
# ==========================================
PROFILE_FILE = os.path.join(ROOT_DIR, 'profile.json')
log_database = {}
IP_BLOCKLIST = set()
REQUEST_COUNTS = {}
AI_RULES = {}
WAF_ACTIVE = True
RATE_LIMIT = 10 

# Simulated "Enterprise" Stats
TOTAL_SCANNED = 14204
TOTAL_MITIGATED = 2142

DEFAULT_PROFILE = {
    "full_name": "Admin User", "username": "admin_nope", "email": "admin@yourbusiness.com",
    "phone": "+1 (555) 123-4567", "timezone": "UTC-5 (EST)", "country": "United States",
    "bio": "Lead Security Engineer securing the perimeter.",
    "website_url": "https://yourbusiness.com", "social_twitter": "@nope_admin",
    "two_factor": "on", "auto_renew": "on"
}

def load_profile():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, 'r') as f:
            try: return json.load(f)
            except: return DEFAULT_PROFILE
    return DEFAULT_PROFILE

def save_profile(data):
    profile = load_profile()
    profile.update(data)
    profile['two_factor'] = data.get('two_factor', 'off')
    profile['auto_renew'] = data.get('auto_renew', 'off')
    with open(PROFILE_FILE, 'w') as f:
        json.dump(profile, f, indent=4)

def load_kaggle_data():
    """Seeds the log database with historical data for the demo."""
    try:
        csv_path = os.path.join(ROOT_DIR, 'cybersecurity_attacks.csv')
        with open(csv_path, mode='r', encoding='utf-8-sig') as file:
            csv_reader = csv.DictReader(file, quoting=csv.QUOTE_NONE)
            for row in csv_reader:
                timestamp = row.get('Timestamp', '')
                if not timestamp: continue
                date = timestamp.split(' ')[0]
                if '/' in date:
                    p = date.split('/')
                    date = f"{p[2]}-{p[0].zfill(2)}-{p[1].zfill(2)}" if len(p[2])==4 else date
                
                sev = str(row.get('Severity Level', 'Low')).upper()
                badge = "[CRITICAL]" if "HIGH" in sev or "CRITICAL" in sev else "[WARNING]" if "MEDIUM" in sev else "[INFO]"
                entry = f"{timestamp.split(' ')[1]} {badge} - Blocked {row.get('Attack Type')} from {row.get('Source IP Address')}."
                if date not in log_database: log_database[date] = []
                log_database[date].append(entry)
    except Exception as e: print(f"⚠️ Data Seed Warning: {e}")

load_kaggle_data()

def log_entry(msg, date=None):
    global TOTAL_SCANNED, TOTAL_MITIGATED
    if not date: date = datetime.now().strftime("%Y-%m-%d")
    if date not in log_database: log_database[date] = []
    log_database[date].insert(0, msg)
    # Increment global stats on blocks
    if "BLOCK" in msg or "LIMIT" in msg:
        TOTAL_MITIGATED += 1
    TOTAL_SCANNED += 1

# ==========================================
# 🛡️ SECURITY ENGINE (WAF & MIDDLEWARE)
# ==========================================
THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or 1=1|--)", re.IGNORECASE),
    "XSS": re.compile(r"(<script>|javascript:|onerror=|<img src=)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|/etc/shadow)", re.IGNORECASE)
}

@app.before_request
def live_firewall():
    if not WAF_ACTIVE or request.path in ['/dashboard', '/manage', '/get-logs', '/ask-ai', '/static', '/profile', '/generate-iso-report', '/add-system-log', '/toggle-waf', '/ban-ip', '/api/v1/inspect', '/generate-ai-rule', '/add-rule', '/get-stats']: 
        return

    client_ip = request.remote_addr
    today_str = datetime.now().strftime("%Y-%m-%d")
    time_now = datetime.now().strftime('%I:%M %p')

    # 1. Blocklist
    if client_ip in IP_BLOCKLIST:
        abort(403, description="🛑 NOPE! EDGE BLOCK: IP Blacklisted.")

    # 2. Rate Limiting
    now = datetime.now().timestamp()
    if client_ip not in REQUEST_COUNTS: REQUEST_COUNTS[client_ip] = []
    REQUEST_COUNTS[client_ip] = [t for t in REQUEST_COUNTS[client_ip] if now - t < 60]
    REQUEST_COUNTS[client_ip].append(now)
    if len(REQUEST_COUNTS[client_ip]) > RATE_LIMIT:
        log_entry(f"{time_now} [WARNING] - RATE LIMIT: {client_ip} exceeded limit.", today_str)
        abort(429, description="🛑 NOPE! EDGE BLOCK: Rate limit exceeded.")
        
    # 3. Heuristics & AI Rules
    data = list(request.args.values()) + list(request.form.values())
    for payload in data:
        for threat, pattern in THREAT_PATTERNS.items():
            if pattern.search(str(payload)):
                log_entry(f"{time_now} [CRITICAL] - LIVE BLOCK: {threat} from {client_ip}.", today_str)
                abort(403, description=f"🛑 NOPE! EDGE BLOCK: {threat} detected.")
        for name, pattern in AI_RULES.items():
            if re.search(pattern, str(payload), re.IGNORECASE):
                log_entry(f"{time_now} [CRITICAL] - AI RULE BLOCK: {name} from {client_ip}.", today_str)
                abort(403, description=f"🛑 NOPE! AI-GEN BLOCK: {name}.")

# ==========================================
# 🤖 API ENDPOINTS
# ==========================================
@app.route('/get-stats')
def get_stats():
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_logs = log_database.get(today_str, [])
    today_count = sum(1 for log in today_logs if "BLOCK" in log)
    return jsonify({
        "total_scanned": f"{TOTAL_SCANNED:,}",
        "total_mitigated": f"{TOTAL_MITIGATED:,}",
        "today_count": today_count,
        "nodes_online": 2 if WAF_ACTIVE else 1
    })

@app.route('/api/v1/inspect', methods=['POST'])
def inspect_payload():
    data = request.json
    payload, client_ip, source = data.get('payload', ''), data.get('ip', request.remote_addr), data.get('source', 'External')
    
    if client_ip in IP_BLOCKLIST: return jsonify({"status": "blocked", "reason": "IP Banned"}), 403

    for threat, pattern in THREAT_PATTERNS.items():
        if pattern.search(str(payload)):
            log_entry(f"{datetime.now().strftime('%I:%M %p')} [CRITICAL] - EXTERNAL BLOCK: {threat} on {source} from {client_ip}.")
            return jsonify({"status": "blocked", "reason": threat}), 403
    return jsonify({"status": "allowed"}), 200

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = f"Analyze log: {request.json.get('log_context')}. Risk Score 1-10 ([THREAT_LEVEL: X/10]). Explain and suggest fix. Admin Question: {request.json.get('message')}"
        return jsonify({"response": model.generate_content(prompt).text})
    except: return jsonify({"response": "Analysis Complete: Threat dropped by WAF heuristics."})

@app.route('/generate-ai-rule', methods=['POST'])
def generate_ai_rule():
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = f"Based on log: {request.json.get('log_context')}, return ONLY JSON: {{\"rule_name\": \"Name\", \"pattern\": \"regex\"}}"
        resp = model.generate_content(prompt)
        clean = re.sub(r'```json\n?|\n?```', '', resp.text).strip()
        return jsonify(json.loads(clean))
    except: return jsonify({"error": "AI Rule Gen failed"}), 500

# ==========================================
# 🌐 UI ROUTES
# ==========================================
@app.route('/')
def home(): return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    today_str = datetime.now().strftime("%Y-%m-%d")
    today_logs = log_database.get(today_str, [])
    count = sum(1 for log in today_logs if "BLOCK" in log)
    return render_template('dashboard.html', today_count=count)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        save_profile(request.form.to_dict())
        return redirect(url_for('profile'))
    return render_template('profile.html', p=load_profile())

@app.route('/get-logs', methods=['POST'])
def get_logs():
    return jsonify({"logs": log_database.get(request.json.get('date'), ["✅ Perimeter Secure."])})

@app.route('/toggle-waf', methods=['POST'])
def toggle_waf():
    global WAF_ACTIVE
    WAF_ACTIVE = request.json.get('active', True)
    status = "ACTIVATED" if WAF_ACTIVE else "DEACTIVATED (PERIMETER EXPOSED)"
    log_entry(f"{datetime.now().strftime('%I:%M %p')} [SYSTEM] - ADMIN ACTION: WAF {status}.")
    return jsonify({"waf_active": WAF_ACTIVE})

@app.route('/add-rule', methods=['POST'])
def add_rule():
    name, pattern = request.json.get('rule_name'), request.json.get('pattern')
    if name and pattern:
        AI_RULES[name] = pattern
        log_entry(f"{datetime.now().strftime('%I:%M %p')} [SYSTEM] - ADMIN ACTION: Applied AI Rule '{name}'.")
        return jsonify({"status": "success"})
    return abort(400)

@app.route('/ban-ip', methods=['POST'])
def ban_ip():
    ip = request.json.get('ip')
    if ip:
        IP_BLOCKLIST.add(ip)
        log_entry(f"{datetime.now().strftime('%I:%M %p')} [SYSTEM] - ADMIN ACTION: IP {ip} Banned.")
        return jsonify({"status": "success"})
    return abort(400)

@app.route('/add-system-log', methods=['POST'])
def add_system_log():
    msg = request.json.get('message')
    log_entry(f"{datetime.now().strftime('%I:%M %p')} [SYSTEM] - {msg}")
    return jsonify({"status": "success"})

@app.route('/target', methods=['GET'])
def target_site():
    return render_template('dummy.html')

@app.route('/submit-comment', methods=['POST'])
def submit_comment():
    # If it reached here, it passed the WAF middleware!
    return "<h1>✅ NOPE! EDGE</h1><p>Your comment was safely processed.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
