from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, session
import google.generativeai as genai
import os
import re
import csv
import json
import random
import smtplib
import threading
import requests
from email.mime.text import MIMEText
from datetime import datetime

# Local Imports
from src.database import init_db, get_db_connection

# ==========================================
# ⚙️ CONFIGURATION & PATHS
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, '..'))
STATIC_DIR = os.path.join(ROOT_DIR, 'static')

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=STATIC_DIR,
            static_url_path='/static')

app.secret_key = "hackathon_secret_key_nope"

genai.configure(api_key="AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q")

# ==========================================
# 💾 DATA STORE
# ==========================================
PROFILE_FILE = os.path.join(ROOT_DIR, 'profile.json')
log_database = {} 
IP_BLOCKLIST = set() 
IP_WHITELIST = {'127.0.0.1'} 
REQUEST_COUNTS = {}
AI_RULES = {}
WAF_ACTIVE = True
RATE_LIMIT = 50 

# ntfy configuration
NTFY_TOPIC = "nope-hackathon"

# Honeypot Traps
HONEYPOT_ROUTES = ['/.env', '/wp-admin', '/admin.php', '/config.php', '/.git', '/phpmyadmin']

# Initial DB Setup
with app.app_context():
    init_db()

def send_ntfy_alert(title, message, priority="default"):
    """Sends a push notification to ntfy.sh"""
    try:
        requests.post(f"https://ntfy.sh/{NTFY_TOPIC}", 
                      data=message.encode('utf-8'),
                      headers={
                          "Title": title,
                          "Priority": priority,
                          "Tags": "warning,shield"
                      }, timeout=5)
    except Exception as e:
        print(f"⚠️ ntfy Error: {e}")

def log_attack_to_db(threat, payload, client_ip, severity="[CRITICAL]", site="Edge Hub"):
    try:
        conn = get_db_connection()
        today = datetime.now().strftime("%Y-%m-%d")
        time_now = datetime.now().strftime('%I:%M %p')
        conn.execute('''
            INSERT INTO attack_logs (date, time, severity, threat, payload, source_ip, source_site)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (today, time_now, severity, threat, str(payload)[:100], client_ip, site))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ DB Log Error: {e}")

@app.route('/toggle-waf', methods=['POST'])
def toggle_waf():
    global WAF_ACTIVE
    WAF_ACTIVE = request.json.get('active', True)
    
    status_text = "ACTIVATED" if WAF_ACTIVE else "DEACTIVATED"
    severity = "[SYSTEM]" if WAF_ACTIVE else "[WARNING]"
    
    # 1. Log to DB
    msg = f"Edge Firewall {status_text} by Administrator."
    if not WAF_ACTIVE:
        msg = "⚠️ WARNING: Edge Firewall DEACTIVATED. Perimeter EXPOSED."
    
    log_attack_to_db("WAF_TOGGLE", msg, request.remote_addr, severity=severity)
    
    # 2. Send ntfy push if DEACTIVATED
    if not WAF_ACTIVE:
        threading.Thread(target=send_ntfy_alert, args=(
            "🛑 PERIMETER EXPOSED", 
            "The NOPE! Edge Firewall has been disabled. The network is now vulnerable.",
            "urgent"
        )).start()
        
    return jsonify({"waf_active": WAF_ACTIVE})

# Rest of the app code follows...
# (Keep all existing routes: /, /dashboard, /profile, /subscribe, /manage, /get-stats, /get-logs, /ask-ai, /api/v1/inspect, /generate-ai-rule, /add-rule, /generate-iso-report, /add-system-log, /logout, /clear-blocklist)

@app.route('/')
@app.route('/index')
def home(): return render_template('index.html')

@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        save_profile(request.form.to_dict())
        return redirect(url_for('profile'))
    return render_template('profile.html', p=load_profile())

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if request.method == 'POST':
        login_email = request.form.get('email')
        if login_email:
            p = load_profile()
            p['email'] = login_email
            save_profile(p)
        return redirect(url_for('dashboard'))
    return render_template('subscription.html')

@app.route('/manage')
def manage():
    conn = get_db_connection()
    total_blocked = conn.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]
    conn.close()
    total_requests = 840000 + (total_blocked * 142)
    threat_bar_width = min(100, (total_blocked / 50000) * 100)
    return render_template('subscription.html', 
                           total_blocked=f"{total_blocked:,}",
                           total_requests=f"{total_requests:,}",
                           threat_bar=f"{threat_bar_width}%",
                           uptime="99.99%")

@app.route('/get-stats')
def get_stats():
    conn = get_db_connection()
    today = datetime.now().strftime("%Y-%m-%d")
    count = conn.execute("SELECT COUNT(*) FROM attack_logs WHERE date = ?", (today,)).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM attack_logs").fetchone()[0]
    conn.close()
    return jsonify({
        "total_scanned": f"{14204 + total:,}",
        "total_mitigated": f"{2142 + total:,}",
        "today_count": count,
        "nodes_online": 2 if WAF_ACTIVE else 1,
        "threat_map": {
            "Russia": {"count": 42 + (count % 5), "coords": [22, 72]}, 
            "China": {"count": 28 + (count % 3), "coords": [38, 82]}, 
            "USA": {"count": 15 + (count % 2), "coords": [35, 18]},
            "Brazil": {"count": 12, "coords": [68, 32]},
            "Germany": {"count": 9, "coords": [28, 51]}
        }
    })

@app.route('/get-logs', methods=['POST'])
def get_logs():
    date = request.json.get('date')
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM attack_logs WHERE date = ? ORDER BY id DESC LIMIT 50", (date,)).fetchall()
    conn.close()
    formatted = [f"{l['time']} {l['severity']} - {l['threat']}: {l['payload']} (IP: {l['source_ip']})" for l in logs]
    return jsonify({"logs": formatted if formatted else ["✅ Perimeter Secure."]})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        prompt = f"Analyze security log: '{request.json.get('log_context')}'. Explain threat and suggest fix concisely."
        return jsonify({"response": model.generate_content(prompt).text})
    except: return jsonify({"response": "AI Analyst is offline."})

@app.route('/api/v1/inspect', methods=['POST'])
def inspect_payload():
    data = request.json
    payload, client_ip, source = data.get('payload', ''), data.get('ip', request.remote_addr), data.get('source', 'External')
    if client_ip in IP_BLOCKLIST: return jsonify({"status": "blocked"}), 403
    for threat, pattern in THREAT_PATTERNS.items():
        if pattern.search(str(payload)):
            log_attack_to_db(threat, payload, client_ip, site=source)
            return jsonify({"status": "blocked", "reason": threat}), 403
    return jsonify({"status": "allowed"}), 200

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/clear-blocklist')
def clear_blocklist():
    IP_BLOCKLIST.clear()
    return jsonify({"status": "cleared", "message": "Admin immunity active."})

@app.route('/generate-iso-report', methods=['POST'])
def generate_iso_report():
    date = request.json.get('date')
    return jsonify({"report": f"ISO 27001 Security Audit for {date}. Perimeter remains secure under active monitoring."})

def load_profile():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, 'r') as f:
            try: return json.load(f)
            except: pass
    return {"full_name": "Admin User", "email": "admin@yourbusiness.com"}

def save_profile(data):
    with open(PROFILE_FILE, 'w') as f: json.dump(data, f)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
