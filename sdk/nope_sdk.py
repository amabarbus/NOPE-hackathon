import requests
from flask import request, abort

# URL of your running NOPE! Security Hub
NOPE_HUB_URL = "http://localhost:8080/api/v1/inspect"

def nope_middleware():
    """Drop-in security middleware for other sites."""
    
    # 1. Gather all incoming data from the request
    payloads = list(request.args.values()) + list(request.form.values())
    if request.is_json:
        json_data = request.get_json(silent=True)
        if json_data: payloads += list(json_data.values())

    # 2. If no payloads (e.g., simple GET), we're good
    if not payloads: return

    # 3. Check each payload against the NOPE! Hub
    for val in payloads:
        try:
            resp = requests.post(NOPE_HUB_URL, json={
                "payload": str(val),
                "ip": request.remote_addr,
                "source": "Partner Site A" # Identifying the site
            }, timeout=1)

            if resp.status_code == 403:
                # 🛑 Blocked by NOPE! Hub
                abort(403, description=resp.json().get("message", "Security Blocked by NOPE!"))
        except:
            # Fallback (Fail-open): If the hub is offline, let it pass to avoid downtime
            pass
