from flask import Flask, render_template, request, redirect, url_for, jsonify, abort
import google.generativeai as genai
import os
import re
import html  # <--- ADD THIS LINE
from datetime import datetime

app = Flask(__name__)

# IMPORTANT: Paste your new Gemini API key here!
genai.configure(api_key="AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q")

# Make the database dynamic so it logs today's real attacks!
TODAY = datetime.now().strftime("%Y-%m-%d")
log_database = {
    TODAY: [
        f"{datetime.now().strftime('%I:%M %p')} [INFO] - CyberShield Live Firewall initialized and active."
    ]
}

# ==========================================
# 🛡️ CYBERSHIELD LIVE FIREWALL (WAF)
# ==========================================
# These are the actual signatures used to detect hackers
THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or 1=1|--)", re.IGNORECASE),
    "XSS (Cross-Site Scripting)": re.compile(r"(<script>|javascript:|onerror=|<img src=)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd)", re.IGNORECASE)
}

@app.before_request
def live_firewall():
    # Ignore the dashboard and API routes so we don't block ourselves!
    if request.path in ['/dashboard', '/get-logs', '/ask-ai']:
        return

    # Check everything the user types in the URL or submits in a form
    incoming_data = list(request.args.values()) + list(request.form.values())
    
    for payload in incoming_data:
        for threat_type, pattern in THREAT_PATTERNS.items():
            if pattern.search(payload):
                # 1. CATCH THE HACKER: Generate a live log
                time_now = datetime.now().strftime("%I:%M %p")
                ip = request.remote_addr or "Unknown IP"
                
                # Make the payload shorter and ESCAPE it so it doesn't break our HTML!
                short_payload = (payload[:30] + '...') if len(payload) > 30 else payload
                safe_payload = html.escape(short_payload) # <--- THIS FIXES THE BUG
                
                live_log = f"{time_now} [CRITICAL] - Blocked {threat_type} from {ip}. Payload: '{safe_payload}'"

                # 2. SAVE IT TO THE DASHBOARD
                if TODAY not in log_database:
                    log_database[TODAY] = []
                log_database[TODAY].insert(0, live_log) # Put it at the top of the list!
                
                # 3. BLOCK THE ATTACK
                abort(403, description=f"🛑 CYBERSHIELD BLOCKED THIS REQUEST: Suspected {threat_type} attack detected.")

# ==========================================
# NORMAL ROUTES
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/get-logs', methods=['POST'])
def get_logs():
    selected_date = request.json.get('date')
    logs = log_database.get(selected_date, ["✅ No attacks recorded on this date. Your site was completely safe!"])
    return jsonify({"logs": logs})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    user_question = request.json.get('message')
    log_context = request.json.get('log_context')
    
    system_prompt = f"""
    You are CyberShield AI. Analyze this specific server log: "{log_context}"
    User Question: "{user_question}"
    Explain what the hackers were trying to do, how the firewall stopped them, and why the user is safe in simple terms.
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