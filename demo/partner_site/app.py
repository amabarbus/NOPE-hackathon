from flask import Flask, render_template, request, jsonify, abort
import requests
import os

# Pointing to the template folder inside demo/partner_site/
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=template_dir)

# CONFIGURATION: Point this to your centralized NOPE! Hub
NOPE_HUB_URL = "http://localhost:8080/api/v1/inspect"

@app.before_request
def security_check():
    """Global Security Middleware for Partner Sites."""
    if request.path.startswith('/static'): return

    payloads = []
    if request.args: payloads += list(request.args.values())
    if request.form: payloads += list(request.form.values())
    if request.is_json:
        json_data = request.get_json(silent=True)
        if json_data and isinstance(json_data, dict): 
            payloads += list(json_data.values())

    for val in payloads:
        try:
            resp = requests.post(NOPE_HUB_URL, json={
                "payload": str(val),
                "ip": request.remote_addr,
                "source": "Partner Business Site" 
            }, timeout=2)

            if resp.status_code == 403:
                msg = resp.json().get("message", "🛑 NOPE! EDGE BLOCK: Security threat detected.")
                return f"<h1>403 Forbidden</h1><p>{msg}</p>", 403
        except Exception as e:
            # Fallback (Fail-open)
            pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-comment', methods=['POST'])
def submit_comment():
    return render_template('index.html', 
                         success="Thank you! Your comment was safely processed and verified by NOPE! Edge.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=False)
