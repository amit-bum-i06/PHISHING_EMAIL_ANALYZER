import flask
from flask_cors import CORS
import re
import os
import sqlite3
from datetime import datetime

app = flask.Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enable Cross-Origin Resource Sharing

# 1. Initialize SQLite Database Table for Support Tickets
def init_db():
    conn = sqlite3.connect('security_hub.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Run database setup on startup
init_db()

def analyze_payload(content, vector_type):
    score = 0
    details = []
    
    if vector_type == "email":
        # 1. Email Header & Spoofing Inspection
        if re.search(r'from:.*@.*(spoof|fake|test|admin-secure)', content, re.IGNORECASE):
            score += 30
            details.append("Header Mismatch: Potential sender spoofing or deceptive display name detected.")
        else:
            details.append("Header Check: Envelope sender and header domains align cleanly.")
            
        # 2. Email Social Engineering Keywords
        urgency_words = ['urgent', 'immediate action', 'verify your account', 'suspended', 'click below', 'password reset']
        found_urgency = [w for w in urgency_words if w in content.lower()]
        if found_urgency:
            score += 35
            details.append(f"Social Engineering: High-pressure manipulation keywords identified ({', '.join(found_urgency)}).")
        else:
            details.append("Social Engineering Check: Standard linguistic tone observed.")
            
        # 3. Email URL Threat Scanning
        if re.search(r'http://\d+\.\d+\.\d+\.\d+', content) or 'bit.ly' in content or 'tinyurl' in content:
            score += 35
            details.append("URL Inspection: High-risk indicators found (raw IP links or unmasked URL shorteners).")
        else:
            details.append("URL Inspection: No blacklisted shorteners or raw IP links detected.")

    elif vector_type == "sms":
        # 1. SMS Sender/Prefix Check
        if re.search(r'(won|lottery|prize|claim|cash|free)', content, re.IGNORECASE):
            score += 40
            details.append("SMS Content Heuristic: High-risk financial incentive or lottery bait terminology identified.")
        else:
            details.append("SMS Content Check: No financial bait keywords detected.")
            
        # 2. SMS Urgency & Threat Check
        sms_urgency = ['alert', 'blocked', 'debit', 'kyc', 'expire', 'update', 'verify']
        found_sms_urgency = [w for w in sms_urgency if w in content.lower()]
        if found_sms_urgency:
            score += 30
            details.append(f"Urgency Patterns: Account restriction pressure tactics found ({', '.join(found_sms_urgency)}).")
        else:
            details.append("Urgency Check: Normal linguistic patterns observed.")
            
        # 3. SMS Link Analysis (Smishing URL Shorteners)
        if re.search(r'http[s]?://', content) or 'bit.ly' in content or 'goo.gl' in content or 't.me' in content:
            score += 30
            details.append("Smishing Indicator: Embedded hyperlink or shortener found within text body.")
        else:
            details.append("Link Scan: No external hyperlinks detected in SMS string.")

    # Cap score at 100
    score = min(score, 100)
    
    # Determine Risk Tier
    if score == 0:
        tier = "Safe"
    elif score <= 40:
        tier = "Low Risk"
    elif score <= 75:
        tier = "Medium Risk"
    else:
        tier = "Critical"
        
    return score, tier, details

@app.route('/')
def home():
    return flask.render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = flask.request.get_json(silent=True) or {}
    content = data.get('content', '')
    vector_type = data.get('vector_type', 'email')
    human_Override = data.get('human_Override', False)
    analystNotes = data.get('analystNotes', '')
    
    score, tier, details = analyze_payload(content, vector_type)
    
    if human_Override:
        details.insert(0, f"⚠️ HUMAN REVIEW OVERRIDE: Analyst added manual note - '{analystNotes}'")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details.append(f"Reviewed by Tier-1 SOC Analyst at {timestamp}")

    return flask.jsonify({
        'score': score, 
        'tier': tier, 
        'details': details,
        'timestamp': datetime.now().strftime("%H:%M:%S")
    })

@app.route('/support-ticket', methods=['POST'])
def support_ticket():
    try:
        data = flask.request.get_json()
        email = data.get('email')
        category = data.get('issue_type') or data.get('category')
        description = data.get('message') or data.get('description')
        
        # Simple Validation
        if not email or not description:
            return flask.jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
            
        # Save to SQLite Database
        conn = sqlite3.connect('security_hub.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO support_tickets (email, category, description) 
            VALUES (?, ?, ?)
        ''', (email, category, description))
        
        conn.commit()
        conn.close()
        
        return flask.jsonify({'status': 'success', 'message': 'Support ticket successfully transmitted and logged in database.'})
        
    except Exception as e:
        return flask.jsonify({'status': 'error', 'message': f'Server Error: {str(e)}'}), 500
    
@app.route('/admin/tickets')
def admin_tickets():
    try:
        conn = sqlite3.connect('security_hub.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, email, category, description, timestamp FROM support_tickets ORDER BY timestamp DESC')
        tickets = cursor.fetchall()
        conn.close()
        return flask.render_template('admin.html', tickets=tickets)
    except Exception as e:
        return f"Database Error: {str(e)}"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)


# cd "c:\Users\rji60\OneDrive\Documents\VS CODE\.vscode\PROJECT\EMAIL_ANALYZER"
# pip install flask flask-cors
# python app.py
#http://127.0.0.1:5000/admin/tickets# /n
#http://127.0.0.1:5000#
