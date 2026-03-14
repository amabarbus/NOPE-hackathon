from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
from datetime import datetime

# Local Module Imports
from src.database import init_db, get_db_connection
from src.data_loader import load_kaggle_to_db
from src.firewall import run_firewall_check
from src.ai_analyst import analyze_threat

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

GEMINI_API_KEY = "AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q"
TODAY = datetime.now().strftime("%Y-%m-%d")

# ==========================================
# 📊 DATABASE INITIALIZATION
# ==========================================
with app.app_context():
    init_db()
    load_kaggle_to_db()
    
    # Add a system initialization log for today
    from src.firewall import log_attack_to_db
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE date = ?", (TODAY,))
    if cursor.fetchone()[0] == 0:
        log_attack_to_db("System Shield", "CyberShield Edge Firewall active", source_ip="127.0.0.1", severity="[INFO]")
    conn.close()

# ==========================================
# 🛡️ WAF MIDDLEWARE
# ==========================================
@app.before_request
def live_firewall():
    return run_firewall_check(TODAY)

# ==========================================
# 🛣️ ROUTES
# ==========================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/manage')
def manage():
    return render_template('subscription.html')

@app.route('/get-logs', methods=['POST'])
def get_logs():
    data = request.json
    selected_date = data.get('date')
    search_query = data.get('search', '').lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Base query for logs on selected date
    query = "SELECT severity, time, attack_type, source_ip, payload FROM attack_logs WHERE date = ?"
    params = [selected_date]
    
    if search_query:
        query += " AND (LOWER(source_ip) LIKE ? OR LOWER(payload) LIKE ? OR LOWER(attack_type) LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    
    query += " ORDER BY id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    logs = []
    for row in rows:
        logs.append(f"{row['time']} {row['severity']} - Blocked {row['attack_type']} from {row['source_ip']}. Payload: '{row['payload']}'")
    
    if not logs:
        logs = ["✅ No attacks recorded on this date. Cloud perimeter secure."]

    # Dynamic Stats
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE severity IN ('[CRITICAL]', '[WARNING]')")
    total_threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE date = ? AND severity IN ('[CRITICAL]', '[WARNING]')", (TODAY,))
    today_threats = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        "logs": logs,
        "total_threats": total_threats,
        "today_threats": today_threats
    })

@app.route('/get-firewall-settings', methods=['GET'])
def get_firewall_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT name, pattern FROM custom_rules")
    rules = [{"name": r["name"], "pattern": r["pattern"]} for r in cursor.fetchall()]
    
    cursor.execute("SELECT ip_address FROM ip_blocklist")
    ips = [r["ip_address"] for r in cursor.fetchall()]
    
    conn.close()
    return jsonify({"custom_rules": rules, "ip_blocklist": ips})

@app.route('/update-firewall-settings', methods=['POST'])
def update_firewall_settings():
    data = request.json
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if 'custom_rules' in data:
        cursor.execute("DELETE FROM custom_rules")
        for rule in data['custom_rules']:
            cursor.execute("INSERT INTO custom_rules (name, pattern) VALUES (?, ?)", (rule['name'], rule['pattern']))
            
    if 'ip_blocklist' in data:
        cursor.execute("DELETE FROM ip_blocklist")
        for ip in data['ip_blocklist']:
            cursor.execute("INSERT INTO ip_blocklist (ip_address, reason) VALUES (?, ?)", (ip, "Manual Block"))
            
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Database settings updated."})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    user_question = request.json.get('message')
    log_context = request.json.get('log_context')
    return analyze_threat(user_question, log_context, GEMINI_API_KEY)

# ==========================================
# 🔌 EXTERNAL PROTECTION API (For Clients)
# ==========================================
@app.route('/api/v1/inspect', methods=['POST'])
def inspect_external_request():
    """
    Endpoint for external clients to verify request safety.
    Expects: { "payload": "...", "ip": "...", "source": "..." }
    """
    data = request.json
    if not data or 'payload' not in data:
        return jsonify({"status": "error", "message": "Missing payload"}), 400
    
    from src.firewall import is_malicious, log_attack_to_db, get_current_settings
    
    payload = data.get('payload')
    client_ip = data.get('ip', 'Unknown External')
    source = data.get('source', 'External API')
    
    current_rules, _ = get_current_settings()
    threat = is_malicious(payload, current_rules)
    
    if threat:
        log_attack_to_db(f"External: {threat}", payload, source_ip=client_ip, severity="[CRITICAL]")
        return jsonify({
            "status": "blocked", 
            "threat": threat,
            "message": f"CyberShield Edge: {threat} detected."
        }), 403
        
    return jsonify({"status": "allowed", "message": "Clear for transmission."}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
