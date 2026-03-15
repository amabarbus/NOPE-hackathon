import requests
import time

BASE_URL = "http://localhost:8080"

def log(msg):
    print(f"\n🧪 [TEST] {msg}")

def test_ban():
    log("Testing IP Banning...")
    ip_to_ban = "1.2.3.4"
    requests.post(f"{BASE_URL}/ban-ip", json={"ip": ip_to_ban})
    logs = requests.post(f"{BASE_URL}/get-logs", json={"date": time.strftime("%Y-%m-%d")}).json()
    if any(f"IP {ip_to_ban} Banned" in l for l in logs['logs']):
        print(f"    ✅ IP {ip_to_ban} successfully blacklisted.")

def test_rate_limit():
    log("Testing Rate Limiting (10 req/min)...")
    for i in range(12):
        resp = requests.get(f"{BASE_URL}/")
        if resp.status_code == 429:
            print(f"    ✅ Request {i+1} blocked (Status 429).")
            return
        time.sleep(0.1)

def test_ai_scoring():
    log("Testing AI Threat Scoring...")
    log_entry = "09:39 AM [CRITICAL] - LIVE BLOCK: SQL Injection from 127.0.0.1."
    resp = requests.post(f"{BASE_URL}/ask-ai", json={
        "log_context": log_entry,
        "message": "Explain this."
    }).json()
    
    if "[THREAT_LEVEL:" in resp.get('response', ''):
        print("    ✅ AI correctly included a Threat Level score.")

if __name__ == "__main__":
    try:
        test_ban()
        test_rate_limit()
        test_ai_scoring()
    except Exception as e:
        print(f"❌ Test Failed: {e}")
