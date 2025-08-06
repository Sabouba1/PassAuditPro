🛡️ AD Password Audit Tool – PassAudit Pro

A professional, modern web-based tool for auditing Active Directory password strength and compliance. Built for security professionals and administrators, it includes full NTLM hash extraction, offline cracking, password policy evaluation, and PDF/HTML reporting.

🚀 Features

🗂 NTLM Hash Extraction using VSS + DiskShadow + Impacket (extract_hashes.py)

🔐 Offline Cracking Engine in pure Python (no John the Ripper required)

📈 Entropy-based Password Strength Evaluation with classification

🧠 Risk Scoring per user based on password analysis and usage patterns

📋 Password Policy Fetching & Best Practice Compliance Check

🦳 Stale Account Detection (login > 90 days or password > 180 days)

🔁 One-click Password Reset Enforcement (per user or all)

📄 Professional PDF and HTML Reports (metrics, risks, policy summary)

🌐 Modern Flask-based Web Interface with Chart.js Dashboard

🧰 Technologies Used

Python 3.x

Flask

LDAP3

Crypto.Hash.MD4

ReportLab

Chart.js

Impacket (secretsdump.py)

🗂 Project Structure

ad-password-audit-tool/
|
├── app.py               # Flask web server
├── config.py            # AD configuration settings
├── ad_utils.py          # Active Directory LDAP functions
├── eval_utils.py        # NTLM cracking + strength evaluation
├── extract_hashes.py    # NTDS & SYSTEM extraction + secretsdump
├── report_utils.py      # PDF report generation
├── wordlist.txt         # Wordlist used for offline cracking
|
├── static/              # Static files: logo, eval_results.json
└── templates/           # HTML pages for the web interface

📆 Key Script: extract_hashes.py

This script is responsible for NTLM hash extraction from a domain controller.

How it works:

Creates a shadow copy of C: using DiskShadow

Copies ntds.dit and SYSTEM hive from the shadow volume

Executes Impacket's secretsdump.py to extract NTLM hashes

Filters valid username:hash pairs into user_hashes.txt

Output:

C:\NTDSDump\hashes.txt – full secretsdump output

C:\NTDSDump\user_hashes.txt – cleaned username:NTLM hash pairs



⚙️ Setup Instructions

Clone the repo:

git clone https://github.com/your-username/ad-password-audit-tool.git
cd ad-password-audit-tool

Install required packages:

pip install -r requirements.txt

Edit config.py:

DC_IP = '192.168.1.10'
LDAP_USER = 'MYDOMAIN\\Administrator'
PASSWORD = 'your-password'
BASE_DN = 'dc=mydomain,dc=local'

Extract hashes (on the DC):

python extract_hashes.py

Launch the web app:

python app.py

📄 License & Disclaimer

This tool is for educational and authorized use only. Do not use in production environments without explicit permission.

️© 2025 — Yousef Emad Sabouba

👨‍💼 Author

Yousef Emad SaboubaCybersecurity Graduate | AD Security | Linkedin: Yousef Sabouba