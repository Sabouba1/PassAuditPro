from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPSocketOpenError
from config import DC_IP as DEFAULT_IP, LDAP_USER as DEFAULT_USER, PASSWORD as DEFAULT_PASS, BASE_DN as DEFAULT_DN
from datetime import datetime, timedelta

def connect_to_ad(override=None):
    dc_ip = override['DC_IP'] if override else DEFAULT_IP
    ldap_user = override['LDAP_USER'] if override else DEFAULT_USER
    password = override['PASSWORD'] if override else DEFAULT_PASS

    try:
        print(f"🔌 Connecting to LDAP server: {dc_ip}")
        server = Server(dc_ip, get_info=ALL, use_ssl=False, port=389)
        conn = Connection(server, user=ldap_user, password=password, authentication=NTLM)

        if not conn.bind():
            print("❌ BIND FAILED")
            print("LDAP bind result:", conn.result)  # 🔍 Shows error like invalidCredentials
            raise Exception(f"❌ LDAP bind failed: {conn.result['description']}")
        
        print("✅ LDAP bind successful!")
        return conn

    except LDAPSocketOpenError as e:
        print("❌ LDAP socket error:", str(e))
        raise Exception(f"❌ Cannot connect to {dc_ip}. Socket error: {str(e)}")

def load_users_from_ad(config_override=None):
    conn = connect_to_ad(config_override)
    base_dn = config_override['BASE_DN'] if config_override else DEFAULT_DN
    conn.search(base_dn, '(&(objectClass=user)(sAMAccountName=*))', attributes=[
        'sAMAccountName', 'givenName', 'sn', 'distinguishedName',
        'lastLogonTimestamp', 'pwdLastSet'
    ])

    users = {}
    user_info = {}

    for entry in conn.entries:
        username = entry['sAMAccountName'].value
        if not username:
            continue

        dn = entry.entry_dn
        ou = extract_ou(dn)
        given = entry['givenName'].value or ''
        surname = entry['sn'].value or ''

        last_login = convert_filetime(entry['lastLogonTimestamp'].value)
        pwd_set = convert_filetime(entry['pwdLastSet'].value)

        users[username] = dn
        user_info[username] = {
            'givenName': given,
            'sn': surname,
            'lastLogon': last_login,
            'pwdLastSet': pwd_set,
            'ou': ou
        }

    conn.unbind()
    return users, user_info

def fetch_password_policy(config_override=None):
    conn = connect_to_ad(config_override)
    base_dn = config_override['BASE_DN'] if config_override else DEFAULT_DN
    conn.search(base_dn, '(objectClass=domain)', attributes=[
        'minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge', 'lockoutThreshold'
    ])

    if not conn.entries:
        return "Unable to retrieve password policy.", []

    entry = conn.entries[0]
    raw = {
        'Minimum Password Length': entry['minPwdLength'].value,
        'Password History Length': entry['pwdHistoryLength'].value,
        'Maximum Password Age (days)': entry['maxPwdAge'].value.days,
        'Minimum Password Age (days)': entry['minPwdAge'].value.days,
        'Account Lockout Threshold': entry['lockoutThreshold'].value,
    }

    policy_text = "\n".join(f"{k}: {v}" for k, v in raw.items())

    compliance = []
    if raw['Minimum Password Length'] < 12:
        compliance.append("❌ Password length is below 12 characters.")
    else:
        compliance.append("✅ Password length meets best practice.")

    if raw['Password History Length'] < 5:
        compliance.append("❌ History length should be at least 5.")
    else:
        compliance.append("✅ Password history is sufficient.")

    if raw['Maximum Password Age (days)'] > 90:
        compliance.append("❌ Max password age should be ≤ 90 days.")
    else:
        compliance.append("✅ Max password age is compliant.")

    if raw['Account Lockout Threshold'] > 5:
        compliance.append("❌ Lockout threshold should be ≤ 5.")
    else:
        compliance.append("✅ Lockout threshold is good.")

    conn.unbind()
    return policy_text, compliance

def set_best_practice_policy(config_override=None):
    try:
        conn = connect_to_ad(config_override)
        base_dn = config_override['BASE_DN'] if config_override else DEFAULT_DN
        conn.search(base_dn, '(objectClass=domain)', attributes=['distinguishedName'])
        if not conn.entries:
            return False, "❌ Could not find domain object."

        dn = conn.entries[0].entry_dn

        # AD expects maxPwdAge/minPwdAge as negative 100-nanosecond intervals
        max_pwd_age_interval = -1 * (90 * 24 * 60 * 60 * 10**7)  # 90 days
        min_pwd_age_interval = 0  # no minimum age

        changes = {
            'minPwdLength': [(2, [12])],
            'pwdHistoryLength': [(2, [5])],
            'maxPwdAge': [(2, [max_pwd_age_interval])],
            'minPwdAge': [(2, [min_pwd_age_interval])],
            'lockoutThreshold': [(2, [5])]
        }

        success = conn.modify(dn, changes)
        conn.unbind()

        if success:
            return True, "✅ Best-practice policy applied successfully."
        else:
            return False, f"❌ LDAP error: {conn.result}"

    except Exception as e:
        return False, f"❌ Exception: {str(e)}"

def enforce_password_reset_all(config_override=None):
    try:
        users, _ = load_users_from_ad(config_override)
        conn = connect_to_ad(config_override)
        for username, dn in users.items():
            conn.modify(dn, {'pwdLastSet': [(2, [0])]})
        conn.unbind()
        return True, f"✅ Password reset enforced for ALL users."
    except Exception as e:
        return False, f"❌ Error: {str(e)}"

def enforce_password_reset_selected(usernames, config_override=None):
    try:
        users, _ = load_users_from_ad(config_override)
        conn = connect_to_ad(config_override)
        for username in usernames:
            dn = users.get(username)
            if dn:
                conn.modify(dn, {'pwdLastSet': [(2, [0])]})
        conn.unbind()
        return True, f"✅ Password reset enforced for {len(usernames)} user(s)."
    except Exception as e:
        return False, f"❌ Error: {str(e)}"

def convert_filetime(filetime):
    if not filetime:
        return None
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=int(filetime) / 10)
    except:
        return None

def extract_ou(dn):
    parts = dn.split(',')
    for part in parts:
        if part.strip().startswith('OU='):
            return part.strip().split('=')[1]
    return 'Unknown'
