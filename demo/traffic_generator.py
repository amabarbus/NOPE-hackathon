import requests
import time
import random

HUB_URL = "http://localhost:8080"
PARTNER_URL = "http://localhost:9000"

SAFE_MESSAGES = [
    "Great blog post!", "How do I sign up?", "Is this service available in the UK?",
    "Love the UI design.", "Check out my portfolio at site.com", "Thanks for the help!"
]

ATTACKS = [
    ("SQL Injection", "admin' OR 1=1 --"),
    ("XSS", "<script>alert('pwned')</script>"),
    ("Path Traversal", "../../../etc/passwd"),
    ("SQL Injection", "UNION SELECT username, password FROM users"),
    ("XSS", "<img src=x onerror=alert(1)>")
]

HONEYPOTS = ['/.env', '/wp-admin', '/.git', '/phpmyadmin']

def run_generator():
    print("🚀 NOPE! Live Traffic Generator Active...")
    print("Simulating real-world traffic to Hub and Partner Site...")
    
    while True:
        try:
            # 60% safe, 30% attack, 10% honeypot
            rand = random.random()
            target = random.choice([HUB_URL, PARTNER_URL])
            
            if rand < 0.6:
                msg = random.choice(SAFE_MESSAGES)
                requests.post(f"{target}/submit-comment", data={"comment": msg}, timeout=2)
                print(f"✅ [SAFE] Sent message to {target}")
            elif rand < 0.9:
                threat_name, payload = random.choice(ATTACKS)
                requests.post(f"{target}/submit-comment", data={"comment": payload}, timeout=2)
                print(f"🔥 [ATTACK] Sent {threat_name} to {target}")
            else:
                trap = random.choice(HONEYPOTS)
                requests.get(f"{target}{trap}", timeout=2)
                print(f"🪤 [HONEYPOT] Triggered trap {trap} on {target}")
                
        except Exception as e:
            print(f"⚠️ Generator error (Server offline?): {e}")
            
        # Wait between 2 to 6 seconds
        time.sleep(random.uniform(2, 6))

if __name__ == "__main__":
    run_generator()
