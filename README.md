# 🛡️ AD Password Audit Tool – PassAudit Pro

A professional, modern web-based tool for auditing Active Directory password strength and compliance. Built for security professionals and administrators, it includes full NTLM hash extraction, offline cracking, password policy evaluation, and PDF/HTML reporting.

---

## 🚀 Features

- 🗂 **NTLM Hash Extraction** using VSS + DiskShadow + Impacket (extract_hashes.py)
- 🔐 **Offline Cracking Engine** in pure Python (no John the Ripper)
- 📈 **Entropy-based Password Strength Evaluation** with classification
- 🧠 **Risk Scoring** per user with cracked password analysis
- 📋 **Password Policy Fetching & Best Practice Compliance Check**
- 🧓 **Stale Account Detection** (login > 90d or pwd > 180d)
- 🔁 **One-click Password Reset Enforcement** (per user or all)
- 📄 **Professional PDF + HTML Reports** (including metrics, risks, and policy checks)
- 🌐 **Modern Flask-based Web Interface** with Chart.js Dashboard

---

## 🧰 Technologies Used

- Python 3.x
- Flask
- LDAP3
- Crypto.Hash.MD4
- ReportLab (for PDF)
- Chart.js + Bootstrap (for web UI)
- Impacket (for secretsdump)

---

## 🗂 Project Structure
ad-password-audit-tool/
│
├── app.py # Flask web app
├── config.py # AD connection config
├── ad_utils.py # Active Directory LDAP logic
├── eval_utils.py # Password evaluation and cracking
├── extract_hashes.py # NTLM hash extraction using VSS + secretsdump
├── report_utils.py # PDF report generator
├── wordlist.txt # Wordlist for offline cracking
│
├── static/ # CSS, charts, images, eval_results.json
└── templates/ # HTML templates (dashboard, users, policy, reports)
## 📦 Key Script: `extract_hashes.py`

> 📌 **Used to extract NTDS.dit and SYSTEM, dump hashes using secretsdump, and save username:NTLM format.**

**Usage:**
Run on the domain controller as Administrator:

python extract_hashes.py
Output:

C:\NTDSDump\hashes.txt (full secretsdump output)

C:\NTDSDump\user_hashes.txt (clean username:hash format)


📷 Screenshots
<img width="1886" height="938" alt="image" src="https://github.com/user-attachments/assets/06d3e893-f243-42b0-b58b-c8ff5256e594" />

⚙️ Setup Instructions
Clone the repo:
git clone https://github.com/your-username/ad-password-audit-tool.git
cd ad-password-audit-tool
pip install -r requirements.txt

Set up config.py with your AD environment:
DC_IP = '192.168.1.10'
LDAP_USER = 'MYDOMAIN\\Administrator'
PASSWORD = 'your-password'
BASE_DN = 'dc=mydomain,dc=local'


- Extract hashes (on DC):
python extract_hashes.py
- Start the web app:
python app.py




📄 License & Disclaimer
This tool is for educational and authorized use only. Do not use in production without proper permission.

© 2025 — Yousef Emad Sabouba

👨‍💻 Author
Yousef Emad Sabouba
Cybersecurity Graduate | AD Security | 
---

Would you like me to:

- Add a clean `requirements.txt` for all modules?
- Suggest screenshots to include in the repo?
- Help deploy it on a local server or cloud?

Let me know what’s next 💪


