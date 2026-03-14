import requests
import time
import os

API_KEY = "1a45d596-bce5-4bc5-b0ee-3614cf476751"
NAMESPACE = "ybe6o"

def check_testmail():
    print(f"🔍 Querying testmail.app for namespace: {NAMESPACE}...")
    url = f"https://api.testmail.app/api/json?apikey={API_KEY}&namespace={NAMESPACE}"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        if data['result'] == 'success' and data['count'] > 0:
            latest = data['emails'][0]
            print("\n✅ NEW SECURITY ALERT RECEIVED!")
            print(f"📬 To: {latest['to']}")
            print(f"📝 Subject: {latest['subject']}")
            print(f"🛡️ Content: {latest['text'][:100]}...")
            return True
        else:
            print("📭 Mailbox is currently empty (Waiting for ntfy.sh relay...).")
            return False
    except Exception as e:
        print(f"❌ API Error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Running Live Security Verification...")
    # Trigger the attack
    from src.notifications import dispatch_security_alert
    dispatch_security_alert("LIVE_DEMO_ATTACK", "9.9.9.9", "SQLI Attempt", "[CRITICAL]")
    
    print("⏳ Waiting 15 seconds for ntfy.sh to relay the email...")
    time.sleep(15)
    
    # Check 3 times
    for _ in range(3):
        if check_testmail(): break
        print("Retrying in 10 seconds...")
        time.sleep(10)
