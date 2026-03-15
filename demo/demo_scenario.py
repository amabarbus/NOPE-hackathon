import requests
import time

HUB_URL = "http://localhost:8080"
PARTNER_URL = "http://localhost:9000"

def log(msg):
    print(f"\n🚀 [DEMO] {msg}")

def test_attack(url, name, payload, expected_status):
    print(f"  - Testing {name} on {url}...")
    response = requests.post(f"{url}/submit-comment", data={"comment": payload})
    if response.status_code == expected_status:
        print(f"    ✅ Blocked: {response.status_code}")
    else:
        print(f"    ❌ Failed: {response.status_code}")

def run_demo():
    log("Scenario: Multi-Site AI Protection")
    
    # 1. Attack Hub
    test_attack(HUB_URL, "SQL Injection", "OR 1=1 --", 403)
    
    # 2. Attack Partner Site
    test_attack(PARTNER_URL, "XSS", "<script>alert(1)</script>", 403)

    # 3. AI Report
    log("Generating ISO 27001 Report...")
    today = time.strftime("%Y-%m-%d")
    resp = requests.post(f"{HUB_URL}/generate-iso-report", json={"date": today})
    print("\n--- REPORT PREVIEW ---")
    print(resp.json().get('report', '')[:300] + "...")

if __name__ == "__main__":
    run_demo()
