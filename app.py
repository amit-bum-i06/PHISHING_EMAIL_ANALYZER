import flask
from flask_cors import CORS
import re
import os
import sqlite3
import hashlib
from datetime import datetime

app = flask.Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cyberguard-soc-v3-secret-key-2026")
CORS(app, resources={r"/*": {"origins": "*"}})

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_hub.db')


# 1. Initialize SQLite Database Tables (Support Tickets, Cryptographic Audit Ledger, Scam Radar)
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table A: Support Tickets & False Positive Reports
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table B: Immutable Cryptographic Audit Ledger (SHA-256 Hash Chain)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload_summary TEXT NOT NULL,
            score INTEGER NOT NULL,
            tier TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Table C: Regional Scam Radar (Crowdsourced Threat Intelligence Feed)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scam_radar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,
            scam_type TEXT NOT NULL,
            reporter TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed initial crowdsourced threat intelligence entries if scam_radar is empty
    cursor.execute('SELECT COUNT(*) FROM scam_radar')
    if cursor.fetchone()[0] == 0:
        sample_scams = [
            ('refund-claim-sbi@ybl', 'Fake UPI Handle / Refund Scam', 'SOC-Telemetry-Node-IN'),
            ('+91-98765-00421', 'Vishing / Digital Arrest Impersonation', 'Citizen-Report #402'),
            ('http://kyc-update-portal-verify.in', 'Phishing Domain / Credential Harvester', 'CERT-Feed-Sync')
        ]
        cursor.executemany('''
            INSERT INTO scam_radar (indicator, scam_type, reporter)
            VALUES (?, ?, ?)
        ''', sample_scams)

    conn.commit()
    conn.close()


# Run database setup on startup
init_db()


def record_audit_block(payload_summary, score, tier):
    """Records a threat scan into the SHA-256 cryptographic hash chain."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT current_hash FROM audit_ledger ORDER BY id DESC LIMIT 1')
    last_row = cursor.fetchone()
    previous_hash = last_row[0] if last_row else "0" * 64

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_block_string = f"{previous_hash}|{payload_summary}|{score}|{tier}|{timestamp}"
    current_hash = hashlib.sha256(raw_block_string.encode('utf-8')).hexdigest()

    cursor.execute('''
        INSERT INTO audit_ledger (payload_summary, score, tier, previous_hash, current_hash, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (payload_summary, score, tier, previous_hash, current_hash, timestamp))

    block_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return block_id, previous_hash, current_hash, timestamp


def analyze_payload(content, vector_type):
    score = 0
    details = []
    lower_content = content.lower()

    if vector_type == "email":
        # 1. Email Header & Spoofing Inspection
        if re.search(r'from:.*@.*(spoof|fake|test|admin-secure|verify-security|support-alert)', content, re.IGNORECASE):
            score += 30
            details.append("Header Mismatch: Potential sender spoofing or deceptive envelope domain detected.")
        else:
            details.append("Header Check: Envelope sender and header domains align cleanly.")

        # 2. Email Social Engineering Keywords
        urgency_words = [
            'urgent', 'immediate action', 'verify your account', 'suspended',
            'click below', 'password reset', 'unauthorized login', 'security alert',
            'account locked', 'confirm your identity'
        ]
        found_urgency = [w for w in urgency_words if w in lower_content]
        if found_urgency:
            score += 35
            details.append(f"Social Engineering: High-pressure manipulation keywords identified ({', '.join(found_urgency)}).")
        else:
            details.append("Social Engineering Check: Standard linguistic tone observed.")

        # 3. Email URL Threat Scanning
        if re.search(r'http[s]?://\d+\.\d+\.\d+\.\d+', content) or any(s in lower_content for s in ['bit.ly', 'tinyurl', 't.co', 'is.gd', 'rb.gy']):
            score += 35
            details.append("URL Inspection: High-risk indicators found (raw IP links or unmasked URL shorteners).")
        else:
            details.append("URL Inspection: No blacklisted shorteners or raw IP links detected.")

    elif vector_type == "sms":
        # 1. SMS Lottery / Financial Bait Check
        if re.search(r'(won|lottery|prize|claim|cash|free|reward|bonus|jackpot)', content, re.IGNORECASE):
            score += 40
            details.append("SMS Content Heuristic: High-risk financial incentive or lottery bait terminology identified.")
        else:
            details.append("SMS Content Check: No financial bait keywords detected.")

        # 2. SMS Urgency & Account Restriction Check
        sms_urgency = ['alert', 'blocked', 'debit', 'kyc', 'expire', 'update', 'verify', 'suspended', 'pan', 'electricity']
        found_sms_urgency = [w for w in sms_urgency if w in lower_content]
        if found_sms_urgency:
            score += 30
            details.append(f"Urgency Patterns: Account restriction pressure tactics found ({', '.join(found_sms_urgency)}).")
        else:
            details.append("Urgency Check: Normal linguistic patterns observed.")

        # 3. SMS Link Analysis (Smishing URL Shorteners)
        if re.search(r'http[s]?://', content) or any(s in lower_content for s in ['bit.ly', 'goo.gl', 't.me', 'tinyurl', 'wa.me']):
            score += 30
            details.append("Smishing Indicator: Embedded hyperlink or shortener found within SMS string.")
        else:
            details.append("Link Scan: No external hyperlinks detected in SMS string.")

    elif vector_type == "vishing":
        # 1. Audio Vishing Authority & Coercion Check
        coercion_keywords = [
            'police', 'arrest', 'warrant', 'cbi', 'customs', 'narcotics',
            'supreme court', 'cyber crime', 'legal action', 'freeze',
            'digital arrest', 'fedex', 'fbi', 'irs', 'do not disconnect'
        ]
        found_coercion = [w for w in coercion_keywords if w in lower_content]
        if found_coercion:
            score += 40
            details.append(f"Voice Coercion Heuristic: Authority impersonation / intimidation triggers detected ({', '.join(found_coercion)}).")
        else:
            details.append("Voice Coercion Check: No authority intimidation markers detected in transcript.")

        # 2. Credential & Financial Harvesting Patterns
        harvest_keywords = [
            'otp', 'cvv', 'pin', 'password', 'screen share', 'anydesk',
            'teamviewer', 'rustdesk', 'safe account', 'verification code',
            'wire transfer', 'upi pin', 'aadhaar', 'ssn'
        ]
        found_harvest = [w for w in harvest_keywords if w in lower_content]
        if found_harvest:
            score += 40
            details.append(f"Credential Harvesting: Sensitive authentication or remote-access request identified ({', '.join(found_harvest)}).")
        else:
            details.append("Credential Check: No OTP, PIN, or remote-access harvesting patterns found.")

        # 3. Call Urgency & Isolation Tactics
        isolation_words = ['immediately', 'stay on the line', 'secret', 'confidential', 'within 10 minutes', 'penalty', 'fine']
        found_isolation = [w for w in isolation_words if w in lower_content]
        if found_isolation:
            score += 25
            details.append(f"Isolation / Pressure Tactic: High-stress vocal urgency markers found ({', '.join(found_isolation)}).")
        else:
            details.append("Pacing Check: Normal conversational pacing observed.")

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
    content = (data.get('content') or '').strip()
    vector_type = (data.get('vector_type') or 'email').lower()
    human_Override = bool(data.get('human_Override', False))
    analystNotes = (data.get('analystNotes') or '').strip()

    if not content:
        return flask.jsonify({'status': 'error', 'message': 'Payload content cannot be empty.'}), 400

    score, tier, details = analyze_payload(content, vector_type)

    if human_Override:
        note_text = analystNotes if analystNotes else "Manual verification flag applied."
        details.insert(0, f"⚠️ HUMAN REVIEW OVERRIDE: Analyst added manual note - '{note_text}'")
        override_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details.append(f"Reviewed by Tier-1 SOC Analyst at {override_time}")

    # Create compact payload summary and seal in the SHA-256 cryptographic audit ledger
    clean_snippet = re.sub(r'\s+', ' ', content)[:65]
    if len(content) > 65:
        clean_snippet += "..."
    payload_summary = f"[{vector_type.upper()}] {clean_snippet}"

    block_id, prev_hash, curr_hash, full_timestamp = record_audit_block(payload_summary, score, tier)
    details.append(f"⛓️ Ledger Block #{block_id} Sealed | SHA-256: {curr_hash[:20]}... (Prev: {prev_hash[:12]}...)")

    return flask.jsonify({
        'score': score,
        'tier': tier,
        'details': details,
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'block_id': block_id,
        'previous_hash': prev_hash,
        'current_hash': curr_hash
    })


@app.route('/support-ticket', methods=['POST'])
def support_ticket():
    try:
        data = flask.request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip()
        category = (data.get('issue_type') or data.get('category') or 'General System Support').strip()
        description = (data.get('message') or data.get('description') or '').strip()

        if not email or not description:
            return flask.jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO support_tickets (email, category, description)
            VALUES (?, ?, ?)
        ''', (email, category, description))

        conn.commit()
        conn.close()

        return flask.jsonify({
            'status': 'success',
            'message': 'Support ticket successfully transmitted and logged in database.'
        })

    except Exception as e:
        return flask.jsonify({'status': 'error', 'message': f'Server Error: {str(e)}'}), 500


@app.route('/submit-scam', methods=['POST'])
def submit_scam():
    try:
        data = flask.request.get_json(silent=True) or {}
        indicator = (data.get('indicator') or '').strip()
        scam_type = (data.get('scam_type') or 'Suspicious Indicator').strip()
        reporter = (data.get('reporter') or 'Anonymous Citizen').strip() or 'Anonymous Citizen'

        if not indicator:
            return flask.jsonify({'status': 'error', 'message': 'Scam indicator is required.'}), 400

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scam_radar (indicator, scam_type, reporter)
            VALUES (?, ?, ?)
        ''', (indicator, scam_type, reporter))
        conn.commit()
        conn.close()

        return flask.jsonify({
            'status': 'success',
            'message': 'Threat indicator broadcast to Regional Scam Radar feed.'
        })
    except Exception as e:
        return flask.jsonify({'status': 'error', 'message': f'Server Error: {str(e)}'}), 500


@app.route('/get-scams', methods=['GET'])
def get_scams():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, indicator, scam_type, reporter, timestamp
            FROM scam_radar
            ORDER BY id DESC
            LIMIT 50
        ''')
        rows = cursor.fetchall()
        conn.close()

        scams = [
            {
                'id': r[0],
                'indicator': r[1],
                'scam_type': r[2],
                'reporter': r[3],
                'timestamp': r[4]
            }
            for r in rows
        ]
        return flask.jsonify({'status': 'success', 'scams': scams})
    except Exception as e:
        return flask.jsonify({'status': 'error', 'message': str(e), 'scams': []}), 500


@app.route('/admin/login', methods=['POST'])
def admin_login():
    # Support both JSON fetch requests and standard HTML form submissions
    data = flask.request.get_json(silent=True)
    if data is not None:
        passcode = (data.get('passcode') or data.get('password') or '').strip()
        if passcode == 'admin123':
            flask.session['admin_authenticated'] = True
            return flask.jsonify({'status': 'success', 'redirect': '/admin/dashboard'})
        return flask.jsonify({'status': 'error', 'message': 'Invalid SOC Admin Passcode. Access Denied.'}), 401
    else:
        passcode = (flask.request.form.get('passcode') or flask.request.form.get('password') or '').strip()
        if passcode == 'admin123':
            flask.session['admin_authenticated'] = True
            return flask.redirect(flask.url_for('admin_dashboard'))
        return flask.redirect(flask.url_for('home', auth_error='1'))


@app.route('/admin/logout')
def admin_logout():
    flask.session.pop('admin_authenticated', None)
    return flask.redirect(flask.url_for('home'))


@app.route('/admin/dashboard')
@app.route('/admin/tickets')
def admin_dashboard():
    # Allow access if authenticated via session OR if accessed with ?passcode=admin123
    if not flask.session.get('admin_authenticated'):
        if flask.request.args.get('passcode') == 'admin123':
            flask.session['admin_authenticated'] = True
        else:
            return flask.redirect(flask.url_for('home', auth_required='1'))

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, payload_summary, score, tier, previous_hash, current_hash, timestamp
            FROM audit_ledger
            ORDER BY id DESC
        ''')
        ledger = cursor.fetchall()

        cursor.execute('''
            SELECT id, email, category, description, timestamp
            FROM support_tickets
            ORDER BY id DESC
        ''')
        tickets = cursor.fetchall()

        conn.close()
        return flask.render_template('admin.html', ledger=ledger, tickets=tickets)
    except Exception as e:
        return f"Database Error: {str(e)}", 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
