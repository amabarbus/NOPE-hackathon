import re
import time
from flask import request, abort
from src.database import get_db_connection

# Rate limiting settings
RATE_LIMIT = 5
RATE_LIMIT_PERIOD = 60
request_counts = {}

def is_malicious(payload, rules):
    if not payload:
        return None
    for rule_name, pattern in rules.items():
        if re.search(pattern, payload, re.IGNORECASE):
            return rule_name
    return None

def log_attack_to_db(threat, payload, source_ip, severity="[CRITICAL]", source_site="Edge Hub"):
    try:
        conn = get_db_connection()
        today = time.strftime("%Y-%m-%d")
        time_now = time.strftime('%I:%M %p')
        conn.execute('''
            INSERT INTO attack_logs (date, time, severity, threat, payload, source_ip, source_site)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (today, time_now, severity, threat, str(payload)[:100], source_ip, source_site))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging attack: {e}")

def run_firewall_check(date_str):
    client_ip = request.remote_addr
    
    # 1. Rate Limiting
    now = time.time()
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    request_counts[client_ip] = [t for t in request_counts[client_ip] if now - t < RATE_LIMIT_PERIOD]
    request_counts[client_ip].append(now)
    
    if len(request_counts[client_ip]) > RATE_LIMIT:
        log_attack_to_db("Rate Limit", "Excessive requests", client_ip, "[WARNING]")
        abort(429, description="🛑 Rate limit exceeded.")

    # 2. Payload Inspection
    custom_rules = {
        "SQL Injection": r"(union|select|insert|update|delete|drop|or 1=1|--)",
        "XSS": r"(<script>|javascript:|onerror=|<img src=)"
    }
    
    payloads = list(request.args.values()) + list(request.form.values())
    for val in payloads:
        threat = is_malicious(str(val), custom_rules)
        if threat:
            log_attack_to_db(threat, val, client_ip)
            abort(403, description=f"🛑 {threat} detected.")
