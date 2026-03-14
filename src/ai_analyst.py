import google.generativeai as genai
from flask import jsonify

def analyze_threat(user_question, log_context, api_key):
    genai.configure(api_key=api_key)
    
    system_prompt = f"""
    You are CyberShield AI. Analyze this specific Cloud Firewall log: "{log_context}"
    User Question: "{user_question}"
    Explain what the hackers were trying to do to the client's site, how the firewall stopped them, and why the user is safe in simple terms.
    """
    
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(system_prompt)
        return jsonify({"response": response.text})
    except Exception as e:
        print(f"CRITICAL ERROR: {str(e)}")
        return jsonify({"response": f"SYSTEM ERROR: {str(e)}"})
