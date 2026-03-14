from flask import Flask, render_template, request, redirect, url_for, jsonify
import google.generativeai as genai
import os

app = Flask(__name__)

# IMPORTANT: Paste your actual Gemini API key here inside the quotes!
genai.configure(api_key="AIzaSyCnVEwTcJUuShYYUyPcp79k70YBJDtSn9Q")

# Fake Database: Logs organized by date (YYYY-MM-DD)
mock_log_database = {
    "2026-03-14": [
        "10:15 AM [CRITICAL] - Blocked SQL Injection attempt from IP 192.168.1.50 at /login. Payload: ' OR 1=1 --",
        "11:30 AM [WARNING] - Mitigated Layer 7 DDoS attack targeting index.html. 5000 req/sec dropped.",
        "01:45 PM [CRITICAL] - Unauthorized root access attempt via SSH from unknown IP."
    ],
    "2026-03-13": [
        "09:00 AM [INFO] - Routine malware scan completed. 0 threats found.",
        "02:14 PM [WARNING] - Blocked Cross-Site Scripting (XSS) payload in contact form submission."
    ]
}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/subscribe', methods=['POST'])
def subscribe():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/get-logs', methods=['POST'])
def get_logs():
    selected_date = request.json.get('date')
    logs = mock_log_database.get(selected_date, ["No attacks recorded on this date. Your site was completely safe!"])
    return jsonify({"logs": logs})

@app.route('/ask-ai', methods=['POST'])
def ask_ai():
    user_question = request.json.get('message')
    log_context = request.json.get('log_context')
    
    system_prompt = f"""
    You are CyberShield AI, a friendly cybersecurity assistant. 
    Analyze this specific server log: "{log_context}"
    User Question: "{user_question}"
    Explain what the hackers were trying to do and why the user is safe in very simple, non-technical terms.
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(system_prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        # This will spit the ACTUAL error directly into your chat box
        print(f"CRITICAL ERROR: {str(e)}")
        return jsonify({"response": f"SYSTEM ERROR: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)