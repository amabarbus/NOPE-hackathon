import requests
import os
import threading

# --- CONFIGURATION ---
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "nope-hackathon")
# We will send the email TO your Gmail address using ntfy's relay
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "maiorpaul@gmail.com")

def send_push_and_email_async(title, message, priority="high"):
    """Sends a push notification AND an email via ntfy.sh (Free & No Password Needed)"""
    def _send():
        try:
            url = f"https://ntfy.sh/{NTFY_TOPIC}"
            
            # This header tells ntfy.sh to ALSO send an email to this address
            headers = {
                "Title": title.encode('ascii', 'ignore').decode('ascii'),
                "Priority": priority,
                "Tags": "shield,warning,fire",
                "Email": ADMIN_EMAIL 
            }
            
            response = requests.post(url,
                data=message.encode('utf-8'),
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                print(f"✅ Alert Dispatched to Push & Email ({ADMIN_EMAIL})")
            else:
                print(f"❌ Dispatch Failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Notification Error: {e}")

    threading.Thread(target=_send).start()

def dispatch_security_alert(threat, ip, payload, severity="[CRITICAL]"):
    """Main entry point for notifications."""
    title = f"NOPE! {severity} Alert"
    body = f"An attack was blocked on your site!\n\n" \
           f"Type: {threat}\n" \
           f"Source IP: {ip}\n" \
           f"Payload: {payload}\n\n" \
           f"Check your dashboard: http://localhost:8080/dashboard"

    # Send both at once
    send_push_and_email_async(title, body)
    print(f"📢 Notification Dispatched: {threat} from {ip}")
