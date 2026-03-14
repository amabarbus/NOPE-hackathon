import requests
import time

# Pointing to your local development server on port 9000
BASE_URL = "http://localhost:9000"

def test_input_sanitization():
    """Test that the endpoint safely handles unexpected or malicious input."""
    # TODO: Change '/login' to an actual route on your local site that takes input
    url = f"{BASE_URL}/login"
    
    # A basic SQLi payload to see how your site reacts
    malicious_payload = {"username": "admin' OR '1'='1", "password": "password"}
    
    try:
        response = requests.post(url, data=malicious_payload)
        
        # We want the server to catch the bad input and return an error (400-level), 
        # NOT process it (200 OK) or crash (500 Internal Server Error).
        if response.status_code in [400, 401, 403, 422]:
            print("✅ Input Sanitization Test Passed: Payload safely rejected.")
        elif response.status_code == 500:
            print("❌ Input Sanitization Test Failed: Server crashed (500 Internal Server Error). Check your error handling.")
        else:
            print(f"⚠️ Warning: Unexpected status code {response.status_code}. Verify if the input was processed.")
            
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection Error: Is your server running on {BASE_URL}?")

def test_rate_limiting():
    """Test that the server blocks requests after a limit is exceeded."""
    # TODO: Change '/api/data' to a route you want to protect against spam
    url = f"{BASE_URL}/api/data"
    
    print("\nTesting rate limiting (sending 5 rapid requests)...")
    try:
        for i in range(5):
            response = requests.get(url)
            
            # Assuming you configure a limit of 3 requests per second
            if i >= 3:
                if response.status_code == 429: # 429 Too Many Requests
                    print(f"✅ Request {i+1}: Blocked as expected (429).")
                else:
                    print(f"❌ Request {i+1}: Failed to block! Status code: {response.status_code}")
            else:
                 print(f"Request {i+1}: Allowed (Status {response.status_code})")
            
            time.sleep(0.1) # Wait 100ms between requests
            
    except requests.exceptions.ConnectionError:
         print(f"❌ Connection Error: Is your server running on {BASE_URL}?")

if __name__ == "__main__":
    print(f"Starting Security Integration Tests against {BASE_URL}...\n")
    test_input_sanitization()
    print("-" * 40)
    test_rate_limiting()
