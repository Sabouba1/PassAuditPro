from flask import Flask, render_template, request, jsonify, session, send_file
from eval_utils import evaluate_password_file_from_john
from ad_utils import (
    connect_to_ad,
    load_users_from_ad,
    fetch_password_policy,
    set_best_practice_policy,
    enforce_password_reset_all,
    enforce_password_reset_selected
)
from report_utils import generate_pdf_report
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = 'your-strong-secret-key'

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/evaluate')
def evaluate():
    return render_template('evaluate.html')

@app.route('/users')
def users():
    return render_template('users.html')

@app.route('/policy')
def policy():
    return render_template('policy.html')

@app.route('/set-config', methods=['POST'])
def set_config():
    data = request.json
    required = ['dc_ip', 'ldap_user', 'password', 'base_dn']
    if not all(k in data for k in required):
        return jsonify({'success': False, 'error': 'Missing fields'}), 400

    override = {
        'DC_IP': data['dc_ip'],
        'LDAP_USER': data['ldap_user'],
        'PASSWORD': data['password'],
        'BASE_DN': data['base_dn']
    }

    session['override_config'] = override  # ✅ Always save config

    # Optional: Validate connection (but don't block saving)
    try:
        conn = connect_to_ad(override)
        conn.unbind()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': True, 'warning': str(e)})

@app.route('/api/current-config')
def get_current_config():
    from config import DC_IP, LDAP_USER, PASSWORD, BASE_DN
    override = session.get('override_config')
    if override:
        return jsonify(override)
    return jsonify({
        'DC_IP': DC_IP,
        'LDAP_USER': LDAP_USER,
        'PASSWORD': PASSWORD,
        'BASE_DN': BASE_DN
    })

@app.route('/api/users')
def get_users():
    try:
        _, user_info = load_users_from_ad(session.get('override_config'))
    except Exception as e:
        return jsonify({'error': str(e), 'users': []}), 500

    now = datetime.now()
    formatted_users = []
    for username, data in user_info.items():
        full_name = f"{data['givenName']} {data['sn']}".strip()
        last_login = data['lastLogon']
        pwd_set = data['pwdLastSet']
        last_login_str = last_login.strftime('%Y-%m-%d') if last_login else '—'
        pwd_set_str = pwd_set.strftime('%Y-%m-%d') if pwd_set else '—'
        pwd_age = (now - pwd_set).days if pwd_set else None
        login_stale = (not last_login) or (now - last_login).days > 90
        pwd_stale = (not pwd_set) or (now - pwd_set).days > 180

        formatted_users.append({
            'username': username,
            'full_name': full_name,
            'last_login': last_login_str,
            'pwd_set': pwd_set_str,
            'pwd_set_days': pwd_age,
            'login_stale': login_stale,
            'pwd_stale': pwd_stale,
            'ou': data['ou']
        })

    return jsonify(formatted_users)

@app.route('/api/policy')
def api_policy():
    try:
        policy_text, compliance_lines = fetch_password_policy(session.get('override_config'))
        return {'policy': policy_text, 'compliance': compliance_lines}
    except Exception as e:
        return jsonify({'error': str(e), 'policy': '', 'compliance': []}), 500

@app.route('/api/apply-best-policy', methods=['POST'])
def apply_best_policy():
    success, msg = set_best_practice_policy(session.get('override_config'))
    return jsonify({'success': success, 'message': msg})

@app.route('/upload-hashes', methods=['POST'])
def upload_hashes():
    uploaded_file = request.files.get('hashfile')
    if not uploaded_file:
        return {'success': False, 'error': 'No file uploaded'}, 400

    print(f"📥 Received file: {uploaded_file.filename}")
    save_path = 'ntlm_hashes.txt'
    uploaded_file.save(save_path)

    try:
        results = evaluate_password_file_from_john()
        result_file = 'static/data/eval_results.json'
        os.makedirs("static/data", exist_ok=True)
        with open(result_file, 'w') as f:
            json.dump(results, f)
        return {'success': True, 'results': results}
    except Exception as e:
        print("❌ Cracking error:", str(e))
        return {'success': False, 'error': str(e)}, 500

@app.route('/api/re-evaluate', methods=['POST'])
def re_evaluate():
    try:
        results = evaluate_password_file_from_john()
        result_file = 'static/data/eval_results.json'
        os.makedirs("static/data", exist_ok=True)
        with open(result_file, 'w') as f:
            json.dump(results, f)
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/generate-report')
def generate_report():
    result_file = 'static/data/eval_results.json'
    if not os.path.exists(result_file):
        return "❌ No evaluation results found. Please evaluate hashes first.", 404

    with open(result_file, 'r') as f:
        eval_results = json.load(f)

    _, user_info = load_users_from_ad(session.get('override_config'))
    now = datetime.now()
    stale_accounts = []
    for username, info in user_info.items():
        login_age = (now - info['lastLogon']).days if info['lastLogon'] else 999
        pwd_age = (now - info['pwdLastSet']).days if info['pwdLastSet'] else 999
        if login_age > 90 or pwd_age > 180:
            stale_accounts.append(f"{username} - Last Login: {login_age}d, Pwd Age: {pwd_age}d")

    policy_text, compliance = fetch_password_policy(session.get('override_config'))
    output_path = "static/reports/report.pdf"
    os.makedirs("static/reports", exist_ok=True)
    generate_pdf_report(eval_results, policy_text, compliance, output_path)

    return send_file(output_path, as_attachment=True)

from flask import session  # ⬅ Make sure this is imported
from ad_utils import fetch_password_policy

@app.route('/generate-html-report')
def html_report():
    try:
        with open("static/data/eval_results.json", "r") as f:
            eval_results = json.load(f)
    except:
        eval_results = []

    total = len(eval_results)
    cracked = [r for r in eval_results if r[2] != "Uncracked"]
    weak = [r for r in cracked if r[2] == "Weak"]
    cracked_pct = round(len(cracked) / total * 100, 1) if total else 0
    weak_pct = round(len(weak) / total * 100, 1) if total else 0

    risks = []
    if weak_pct >= 30:
        risks.append("High number of weak passwords detected.")
    if cracked_pct >= 50:
        risks.append("Over half of user passwords were cracked.")
    if any("admin" in r[0].lower() for r in cracked):
        risks.append("Cracked passwords include administrative usernames.")
    if not risks:
        risks.append("Password hygiene appears acceptable.")

    # ✅ Use session override config if present
    config_override = session.get('override_config')

    try:
        policy_text, compliance_lines = fetch_password_policy(config_override=config_override)
    except:
        policy_text = "No policy data found."
        compliance_lines = ["❌ Missing compliance data."]

    best_practice = {
        "Minimum Password Length": "12",
        "Password History Length": "5",
        "Maximum Password Age (days)": "90",
        "Minimum Password Age (days)": "0",
        "Account Lockout Threshold": "5"
    }

    policy_dict = {}
    for line in policy_text.splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            policy_dict[k.strip()] = v.strip()

    policy_rows = []
    for key in best_practice:
        current = policy_dict.get(key, "—")
        policy_rows.append([key, current, best_practice[key]])

    return render_template("report.html",
        total=total,
        cracked_pct=cracked_pct,
        weak_pct=weak_pct,
        risks=risks,
        policy_table=policy_rows,
        compliance=compliance_lines,
        results=eval_results
    )

@app.route('/api/enforce-reset', methods=['POST'])
def enforce_reset():
    data = request.get_json()
    users = data.get('users', [])
    if users:
        success, msg = enforce_password_reset_selected(users, session.get('override_config'))
    else:
        success, msg = enforce_password_reset_all(session.get('override_config'))
    return jsonify({'success': success, 'message': msg})

if __name__ == '__main__':
    result_file = 'static/data/eval_results.json'
    if os.path.exists(result_file):
        os.remove(result_file)
        print("✅ Old evaluation results cleared.")
    app.run(debug=True)
