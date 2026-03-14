from src.notifications import dispatch_security_alert
import time

print("🚀 Starting Standalone Notification Test...")
print("Checking ntfy.sh/nope-hackathon...")

dispatch_security_alert(
    threat="TEST_ATTACK_SQLI", 
    ip="99.99.99.99", 
    payload="SELECT * FROM users; --", 
    severity="[CRITICAL]"
)

print("✅ Dispatcher called. Waiting 5 seconds for background threads to finish...")
time.sleep(5)
print("🏁 Test Finished. Check https://ntfy.sh/nope-hackathon")
