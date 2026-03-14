import re
import time
from flask import request, abort
from src.database import get_db_connection
from src.notifications import dispatch_security_alert

# Global cache to avoid excessive DB reads per request
_rules_cache = None
_blocklist_cache = None
_last_cache_update = 0

def get_current_settings():
    global _rules_cache, _blocklist_cache, _last_cache_update
    now = time.time()
    
    # Update cache every 10 seconds
    if _rules_cache is None or (now - _last_cache_update > 10):
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name, pattern FROM custom_rules")
        _rules_cache = [{"name": r["name"], "pattern": r["pattern"]} for r in cursor.fetchall()]
        
        cursor.execute("SELECT ip_address FROM ip_blocklist")
        _blocklist_cache = [r["ip_address"] for r in cursor.fetchall()]
        
        _last_cache_update = now
        conn.close()
    
    return _rules_cache, _blocklist_cache

# RATE LIMITING STORE
request_counts = {} # { ip: [timestamp1, timestamp2, ...] }
RATE_LIMIT_THRESHOLD = 4
RATE_LIMIT_WINDOW = 60 # Seconds

# BOT / VM DETECTION PATTERNS
SUSPICIOUS_AGENTS = [
    "python-requests", "curl", "wget", "go-http-client", 
    "postman", "headless", "selenium", "phantomjs"
]

THREAT_PATTERNS = {
    "SQL Injection": re.compile(r"(union|select|insert|update|delete|drop|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|--|#|/\*)", re.IGNORECASE),
    "XSS (Cross-Site Scripting)": re.compile(r"(<script.*?>|javascript:|onerror\s*=|onload\s*=|alert\(|<img.*?src=)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini|/etc/shadow)", re.IGNORECASE)
}

def is_malicious(payload, custom_rules):
    if not isinstance(payload, str): return None
    
    for threat_type, pattern in THREAT_PATTERNS.items():
        if pattern.search(payload): return threat_type
            
    for rule in custom_rules:
        try:
            if re.search(rule['pattern'], payload, re.IGNORECASE):
                return f"Custom Rule: {rule['name']}"
        except Exception: continue
    return None

def log_attack_to_db(threat_type, payload, source_ip=None, location="Unknown", severity="[CRITICAL]"):
    from datetime import datetime
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now()
    cursor.execute('''
        INSERT INTO attack_logs (date, time, severity, attack_type, source_ip, payload, source_location, is_live)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        now.strftime("%Y-%m-%d"),
        now.strftime("%I:%M %p"),
        severity,
        threat_type,
        source_ip or request.remote_addr,
        payload[:100],
        location,
        1 # is_live = True
    ))
    conn.commit()
    conn.close()

    # 🚨 DISPATCH NOTIFICATIONS
    dispatch_security_alert(threat_type, payload, source_ip or request.remote_addr, severity)

def get_client_ip():
    """Gets the real client IP, even through proxies."""
    if request.headers.get('X-Forwarded-For'):
        # The first IP in the list is the original client
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def check_rate_limit(client_ip):
    global request_counts
    now = time.time()
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    request_counts[client_ip].append(now)
    request_counts[client_ip] = [ts for ts in request_counts[client_ip] if now - ts < RATE_LIMIT_WINDOW]

    if len(request_counts[client_ip]) > RATE_LIMIT_THRESHOLD:
        _, ip_blocklist = get_current_settings()
        if client_ip not in ip_blocklist:
            conn = get_db_connection()
            conn.execute("INSERT OR IGNORE INTO ip_blocklist (ip_address, reason) VALUES (?, ?)", (client_ip, "Rate limit exceeded"))
            conn.commit()
            conn.close()
            log_attack_to_db("Rate Limit Exceeded", f"{len(request_counts[client_ip])} req/min", client_ip)
        return True
    return False

def run_firewall_check(TODAY):
    if request.path in ['/dashboard', '/get-logs', '/ask-ai', '/static', '/get-firewall-settings', '/update-firewall-settings', '/api/v1/inspect']:
        return

    custom_rules, ip_blocklist = get_current_settings()
    client_ip = get_client_ip()

    # 0. RATE LIMITING
    if check_rate_limit(client_ip):
        abort(429, description="🛑 Rate limit exceeded.")

    # 1. IP BLOCKLIST
    if client_ip in ip_blocklist:
        abort(403, description="🛑 IP Manually Blocked.")

    # 2. BOT / VM DETECTION (User-Agent Check)
    user_agent = request.headers.get('User-Agent', '').lower()
    for agent in SUSPICIOUS_AGENTS:
        if agent in user_agent:
            log_attack_to_db(f"Automated Bot/VM ({agent})", "User-Agent blocked", client_ip, severity="[WARNING]")
            abort(403, description=f"🛑 ACCESS DENIED: Automated tools ({agent}) are restricted on this endpoint.")

    # 3. PAYLOAD SCANNING
    data_sources = [("URL Query", request.args.values()), ("Form Data", request.form.values())]
    if request.is_json:
        json_data = request.get_json(silent=True)
        if json_data and isinstance(json_data, dict): data_sources.append(("JSON Body", json_data.values()))

    for source_name, values in data_sources:
        for val in values:
            threat = is_malicious(val, custom_rules)
            if threat:
                log_attack_to_db(threat, val, client_ip)
                abort(403, description=f"🛑 {threat} detected.")
