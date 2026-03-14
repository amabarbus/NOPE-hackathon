import google.generativeai as genai
from flask import jsonify

def analyze_threat(user_question, log_context, api_key):
    genai.configure(api_key=api_key)
    
    system_prompt = f"""
    You are NOPE! AI. Analyze this specific Cloud Firewall log: "{log_context}"
    User Question: "{user_question}"
    Explain what the hackers were trying to do to the client's site, how the firewall stopped them, and why the user is safe in simple terms.
    """
    
    try:
        model = genai.GenerativeModel('gemini-flash-latest')
        response = model.generate_content(system_prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        error_msg = str(e)
        print(f"AI ERROR: {error_msg}")
        if "429" in error_msg or "ResourceExhausted" in error_msg:
             return jsonify({"response": "🛑 NOPE! AI: We've reached the free-tier rate limit (15 requests/min). Please wait 60 seconds or use a different API key."})
        return jsonify({"response": f"AI Analyser temporarily unavailable: {error_msg}"})
