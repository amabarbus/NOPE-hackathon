from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

# CONFIGURATION: Point this to your running CyberShield Server
CYBERSHIELD_API_URL = "http://localhost:8080/api/v1/inspect"

@app.route('/')
def index():
    # A simple "Business Site" with a comment form
    return render_template('index.html')

@app.route('/submit-comment', methods=['POST'])
def submit_comment():
    comment = request.form.get('comment', '')
    user_ip = request.remote_addr
    
    # 🛡️ THE CYBERSHIELD INTEGRATION
    # Before we save the comment, we ask our WAF if it's safe
    try:
        response = requests.post(CYBERSHIELD_API_URL, json={
            "payload": comment,
            "ip": user_ip,
            "source": "TestProto Business Site"
        }, timeout=2) # Fast timeout for good UX
        
        security_result = response.json()
        
        if response.status_code == 403:
            # CyberShield blocked it!
            return render_template('index.html', 
                                 error=f"SECURITY ALERT: {security_result.get('message')}",
                                 comment=comment)
        
        # If allowed, we proceed normally
        return render_template('index.html', 
                             success="Thank you! Your comment was safely processed and verified by CyberShield Edge.")
                             
    except requests.exceptions.RequestException as e:
        # Fallback if WAF is offline
        return render_template('index.html', 
                             warning="Note: Security inspection is currently unavailable, but your comment was queued.")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    user_ip = request.remote_addr
    
    # Check both username and password for security
    for field in [username, password]:
        try:
            response = requests.post(CYBERSHIELD_API_URL, json={
                "payload": field,
                "ip": user_ip,
                "source": "TestProto Login"
            }, timeout=2)
            if response.status_code == 403:
                return jsonify({"status": "blocked", "message": "Malicious input detected"}), 403
        except:
            pass
            
    return jsonify({"status": "success", "message": "Login attempt processed"}), 200

@app.route('/api/data', methods=['GET'])
def get_data():
    user_ip = request.remote_addr
    # For rate limiting test, we still want to hit the firewall
    try:
        response = requests.post(CYBERSHIELD_API_URL, json={
            "payload": "GET DATA",
            "ip": user_ip,
            "source": "TestProto API"
        }, timeout=2)
        if response.status_code == 429:
            return jsonify({"status": "blocked", "message": "Rate limit exceeded"}), 429
        if response.status_code == 403:
             return jsonify({"status": "blocked", "message": "Access Denied"}), 403
    except:
        pass
        
    return jsonify({"status": "success", "data": "Confidential Business Data"}), 200

if __name__ == '__main__':
    # Run on a different port so we can run both at once
    app.run(host='0.0.0.0', port=9000, debug=True)
