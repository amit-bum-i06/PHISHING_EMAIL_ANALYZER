import flask
from flask_cors import CORS
import re
import os
import sqlite3
import hashlib
import hmac
from urllib.parse import urlparse
from datetime import datetime

app = flask.Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cyberguard-soc-v3-secret-key-2026")
CORS(app, resources={r"/*": {"origins": "*"}})

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'security_hub.db')
ADMIN_PASSCODE = os.environ.get("ADMIN_PASSCODE", "admin123")
MAX_PAYLOAD_LENGTH = 15000


@app.after_request
def apply_security_headers(response):
    """Apply enterprise security headers to all HTTP responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# 1. Initialize SQLite Database Tables (Support Tickets, Cryptographic Audit Ledger, Scam Radar)
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
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
                ('http://secure-login-paypal-verify.xyz/auth', 'Phishing URL / Credential Harvester', 'SOC-Telemetry-Node-IN'),
                ('refund-claim-sbi@ybl', 'Fake UPI Handle / Refund Scam', 'Citizen-Report #402'),
                ('http://192.168.88.41/kyc-update-portal', 'Raw IP Phishing Link', 'CERT-Feed-Sync')
            ]
            cursor.executemany('''
                INSERT INTO scam_radar (indicator, scam_type, reporter)
                VALUES (?, ?, ?)
            ''', sample_scams)

        conn.commit()


# Run database setup on startup
init_db()


def record_audit_block(payload_summary, score, tier):
    """Records a threat scan into the immutable SHA-256 cryptographic hash chain."""
    with sqlite3.connect(DB_PATH) as conn:
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

    return block_id, previous_hash, current_hash, timestamp


def analyze_url_phishing(content):
    """Deep heuristic and structural inspection for URL Phishing Detection."""
    score = 0
    details = []

    raw_target = content.strip().split()[0]
    normalized_url = raw_target if re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', raw_target) else f'http://{raw_target}'

    try:
        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or '').lower()
        path_and_query = ((parsed.path or '') + '?' + (parsed.query or '')).lower()
    except Exception:
        hostname = raw_target.lower()
        path_and_query = raw_target.lower()

    lower_content = content.lower()

    # 1. Raw IP Host, @ Redirect Obfuscation, or Non-Standard Port Check
    has_raw_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)) or bool(re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}', lower_content))
    has_at_symbol = '@' in raw_target
    if has_raw_ip or has_at_symbol:
        score += 35
        details.append("Host Obfuscation Alert: URL uses a raw IPv4 address or '@' credential-redirect trick to bypass domain filters.")
    else:
        details.append("Host Resolution Check: Standard domain hostname structure observed.")

    # 2. Brand Impersonation, Typosquatting & IDN Homograph Check
    spoof_patterns = [
        'paypa1', 'paypal-', '-paypal', 'g00gle', 'google-verify', 'micros0ft', 'microsoft-login',
        'amaz0n', 'amazon-security', 'apple-support', 'netf1ix', 'faceb00k', 'sbi-kyc', 'hdfc-verify',
        'icici-alert', 'admin-secure', 'secure-login', 'account-verify', 'xn--'
    ]
    matched_spoofs = [p for p in spoof_patterns if p in lower_content]
    if matched_spoofs:
        score += 35
        details.append(f"Typosquatting / Brand Spoofing: Deceptive lookalike or Punycode tokens detected ({', '.join(matched_spoofs[:4])}).")
    else:
        details.append("Brand Spoofing Check: No known typosquatting or Punycode homograph signatures matched.")

    # 3. Suspicious Top-Level Domains (TLDs) & Unmasked URL Shorteners
    high_risk_tlds = ('.xyz', '.top', '.zip', '.mov', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.work', '.loan', '.icu', '.buzz')
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'rb.gy', 'cutt.ly', 'goo.gl', 'shorturl.at']
    matched_shorteners = [s for s in shorteners if s in lower_content]
    matched_tld = hostname.endswith(high_risk_tlds)

    if matched_tld or matched_shorteners:
        score += 25
        reason = f"shortener ({', '.join(matched_shorteners)})" if matched_shorteners else f"high-risk TLD ({hostname.split('.')[-1]})"
        details.append(f"Domain Reputation Alert: High-abuse {reason} identified in URL.")
    else:
        details.append("Domain TLD & Shortener Check: Standard top-level domain with no link-masking service.")

    # 4. Subdomain Depth, Hyphen Abuse & Structural Length Check
    subdomain_count = hostname.count('.')
    hyphen_count = hostname.count('-')
    if subdomain_count >= 3 or hyphen_count >= 3 or len(raw_target) > 95:
        score += 20
        details.append(f"Structural Anomaly: Excessive subdomain chaining ({subdomain_count} dots), hyphenation ({hyphen_count} hyphens), or abnormal URL length.")
    else:
        details.append("URL Structure Check: Domain nesting depth and length are within safe thresholds.")

    # 5. Phishing Path / Query Keywords & Malicious File Extensions
    phish_path_keywords = ['login', 'signin', 'verify', 'kyc', 'password', 'reset', 'update', 'confirm', 'wallet', 'auth', 'token', '.apk', '.exe', '.scr']
    matched_paths = [k for k in phish_path_keywords if k in path_and_query]
    if matched_paths:
        score += 20
        details.append(f"Endpoint Payload Inspection: High-risk credential harvesting or executable path markers found ({', '.join(matched_paths[:4])}).")
    else:
        details.append("Endpoint Path Check: URI path contains no credential-harvesting lures.")

    # 6. Transport Encryption Check (HTTP vs HTTPS)
    if raw_target.lower().startswith('http://'):
        score += 15
        details.append("Transport Security Warning: URL uses unencrypted HTTP protocol (missing TLS/SSL certificate).")
    elif raw_target.lower().startswith('https://'):
        details.append("Transport Protocol Note: HTTPS present (Note: Phishing sites frequently use free SSL certificates).")

    return score, details


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

    elif vector_type == "url":
        score, details = analyze_url_phishing(content)

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
    content = (data.get('content') or '').strip()[:MAX_PAYLOAD_LENGTH]
    vector_type = (data.get('vector_type') or 'email').lower()
    if vector_type not in ('email', 'sms', 'url'):
        vector_type = 'email'

    human_Override = bool(data.get('human_Override', False))
    analystNotes = (data.get('analystNotes') or '').strip()[:500]

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
        email = (data.get('email') or '').strip()[:150]
        category = (data.get('issue_type') or data.get('category') or 'General System Support').strip()[:100]
        description = (data.get('message') or data.get('description') or '').strip()[:2000]

        if not email or not description:
            return flask.jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO support_tickets (email, category, description)
                VALUES (?, ?, ?)
            ''', (email, category, description))
            conn.commit()

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
        indicator = (data.get('indicator') or '').strip()[:255]
        scam_type = (data.get('scam_type') or 'Suspicious Indicator').strip()[:100]
        reporter = ((data.get('reporter') or 'Anonymous Citizen').strip() or 'Anonymous Citizen')[:100]

        if not indicator:
            return flask.jsonify({'status': 'error', 'message': 'Scam indicator is required.'}), 400

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scam_radar (indicator, scam_type, reporter)
                VALUES (?, ?, ?)
            ''', (indicator, scam_type, reporter))
            conn.commit()

        return flask.jsonify({
            'status': 'success',
            'message': 'Threat indicator broadcast to Regional Scam Radar feed.'
        })
    except Exception as e:
        return flask.jsonify({'status': 'error', 'message': f'Server Error: {str(e)}'}), 500


@app.route('/get-scams', methods=['GET'])
def get_scams():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, indicator, scam_type, reporter, timestamp
                FROM scam_radar
                ORDER BY id DESC
                LIMIT 50
            ''')
            rows = cursor.fetchall()

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
    data = flask.request.get_json(silent=True)
    if data is not None:
        passcode = (data.get('passcode') or data.get('password') or '').strip()
        if hmac.compare_digest(passcode, ADMIN_PASSCODE):
            flask.session['admin_authenticated'] = True
            return flask.jsonify({'status': 'success', 'redirect': '/admin/dashboard'})
        return flask.jsonify({'status': 'error', 'message': 'Invalid SOC Admin Passcode. Access Denied.'}), 401
    else:
        passcode = (flask.request.form.get('passcode') or flask.request.form.get('password') or '').strip()
        if hmac.compare_digest(passcode, ADMIN_PASSCODE):
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
    if not flask.session.get('admin_authenticated'):
        arg_pass = (flask.request.args.get('passcode') or '').strip()
        if arg_pass and hmac.compare_digest(arg_pass, ADMIN_PASSCODE):
            flask.session['admin_authenticated'] = True
        else:
            return flask.redirect(flask.url_for('home', auth_required='1'))

    try:
        with sqlite3.connect(DB_PATH) as conn:
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

        return flask.render_template('admin.html', ledger=ledger, tickets=tickets)
    except Exception as e:
        return f"Database Error: {str(e)}", 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
