import os
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# CRITICAL: Allow CORS so the Extension & Dashboard can talk to this server
CORS(app, resources={r"/*": {"origins": "*"}})

# --- GLOBAL STATS ---
# In-memory storage for the demo
SCAN_LOGS = []
STATS = {
    "total_scans": 0,
    "pii_blocked": 0,
    "verified_safe": 0
}

@app.route('/scan', methods=['POST'])
def scan_text():
    """
    Endpoint called by the Chrome Extension.
    Receives text and a 'local_pii_detected' flag.
    """
    global STATS # Ensure we modify the global variable
    
    data = request.get_json()
    text = data.get('text', '')
    url = data.get('source_url', 'Unknown')
    # Check if the extension already flagged it (e.g. for phone numbers)
    local_pii = data.get('local_pii_detected', False)
    
    # DEBUG PRINT: What did we receive?
    print(f"\n--- INCOMING SCAN ---")
    print(f"Received: '{text[:50]}...' | Extension Flagged: {local_pii}")
    
    STATS["total_scans"] += 1
    
    # LOGIC: Check for Email (@ and .) OR Phone (10 digits) OR Local Flag
    # 1. Backend simple check for Email
    has_email = "@" in text and "." in text
    
    # 2. Backend simple check for Phone (count digits)
    digit_count = sum(c.isdigit() for c in text)
    has_phone = digit_count >= 10
    
    pii_detected = False
    status = "Safe"
    risk = "None"

    # If ANY check fails (Backend Email, Backend Phone, or Frontend Flag), mark as Risk
    if has_email or has_phone or local_pii: 
        pii_detected = True
        STATS["pii_blocked"] += 1  # INCREMENT BLOCK COUNT
        status = "Risk"
        risk = "PII Detected"
        print(f"!!! PII DETECTED !!! New PII Count: {STATS['pii_blocked']}")
    else:
        STATS["verified_safe"] += 1
        print("Text marked as Safe.")

    # Create Log Entry
    log_entry = {
        "id": len(SCAN_LOGS) + 1,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source": "ChatGPT" if "chatgpt" in url else "Gemini",
        "snippet": text[:50] + "...",
        "status": status,
        "risk": risk
    }
    
    # Add to beginning of list
    SCAN_LOGS.insert(0, log_entry)
    # Keep logs manageable for demo
    if len(SCAN_LOGS) > 50:
        SCAN_LOGS.pop()
    
    return jsonify({
        "pii_detected": pii_detected,
        "message": "Scan Complete"
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """
    Endpoint called by the React Dashboard.
    """
    response = jsonify({
        "stats": STATS,
        "logs": SCAN_LOGS
    })
    
    # CRITICAL: Prevent Browser Caching so Dashboard updates instantly
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response

if __name__ == '__main__':
    print("--- Backend Running on Port 5000 ---")
    # Turn off debug mode to prevent double-reloading in some environments
    app.run(host='127.0.0.1', port=5000, debug=False)