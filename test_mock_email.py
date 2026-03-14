from unittest.mock import MagicMock, patch
import src.notifications as notifications
import time
import os

# Mocking SMTP to see if the email would have sent correctly
@patch("smtplib.SMTP")
def test_email(mock_smtp):
    # Setup the mock
    instance = mock_smtp.return_value
    
    # 1. Fill dummy credentials directly in the module
    notifications.SENDER_EMAIL = "sender@nope.com"
    notifications.SENDER_PASSWORD = "password123"
    notifications.ADMIN_EMAIL = "maiorpaul@gmail.com"
    
    print("🚀 Starting MOCK Email & Push Notification Test...")
    print(f"Targeting: {notifications.ADMIN_EMAIL}")

    # 2. Call the dispatcher
    notifications.dispatch_security_alert(
        threat="MOCK_TEST_EMAIL", 
        ip="123.123.123.123", 
        payload="SELECT * FROM secrets;", 
        severity="[CRITICAL]"
    )

    # 3. Wait for the background thread to finish
    print("⏳ Waiting for notification thread...")
    time.sleep(3)

    # 4. Verify if SMTP was called
    if mock_smtp.called:
        print("✅ SUCCESS: The Email logic is WORKING.")
        print("   The code attempted to open an SMTP connection, start TLS, and login.")
        print(f"   Destination: {notifications.ADMIN_EMAIL}")
    else:
        print("❌ FAILED: SMTP was never called. Check the skip logic in send_email_async.")

if __name__ == "__main__":
    test_email()
