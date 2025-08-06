import hashlib
import re
from config import HASHES_PATH, WORDLIST_PATH
from Crypto.Hash import MD4

def ntlm_hash(password):
    """
    Generate NTLM hash using MD4 over UTF-16LE encoding.
    Pure Python, no external executables required.
    """
    h = MD4.new()
    h.update(password.encode('utf-16le'))
    return h.hexdigest().lower()

def evaluate_password(username, password):
    """
    Enhanced password strength evaluator using strict enterprise logic + entropy-based estimation.
    Returns: (entropy_bits, status, reason)
    """
    reasons = []
    length = len(password)
    entropy = 0

    # === Length-based entropy ===
    if length < 8:
        entropy += 10
        reasons.append("Too short (<8 characters)")
    elif length < 12:
        entropy += 25
        reasons.append("Below recommended length (12+)")
    elif length < 16:
        entropy += 40
    else:
        entropy += 50

    # === Regex checks ===
    if re.search(r'[a-z]', password):
        entropy += 10
    else:
        reasons.append("Missing lowercase")

    if re.search(r'[A-Z]', password):
        entropy += 10
    else:
        reasons.append("Missing uppercase")

    if re.search(r'[0-9]', password):
        entropy += 10
    else:
        reasons.append("Missing digit")

    if re.search(r'[^A-Za-z0-9]', password):
        entropy += 10
    else:
        reasons.append("Missing symbol")

    # === Username in password ===
    if username.lower() in password.lower():
        entropy -= 15
        reasons.append("Contains username")

    # === Pattern detection ===
    sequences = ['1234', 'abcd', 'qwerty', 'password', '1111', '0000']
    for seq in sequences:
        if seq in password.lower():
            entropy -= 10
            reasons.append(f"Contains common pattern: {seq}")
            break

    # === Final classification ===
    entropy = max(entropy, 0)
    if entropy < 40:
        status = "Weak"
    elif entropy < 60:
        status = "Fair"
    elif entropy < 80:
        status = "Strong"
    else:
        status = "Very Strong"

    reason_text = ", ".join(reasons) if reasons else "Passes all checks"
    return entropy, status, reason_text

def evaluate_password_file_from_john():
    """
    Simulate cracking NTLM hashes using a wordlist in pure Python.
    Evaluate strength with strict enterprise rules.
    Output: List of (username, password, status, score, reason)
    """
    user_hashes = {}
    with open(HASHES_PATH, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                username = parts[0].strip()
                hash_part = parts[1].strip().lower().replace('$nt$', '')
                user_hashes[username] = hash_part

    with open(WORDLIST_PATH, 'r', encoding='utf-8') as f:
        wordlist = [line.strip() for line in f if line.strip()]

    cracked = {}
    for word in wordlist:
        h = ntlm_hash(word)
        cracked[h] = word

    results = []
    for user, stored_hash in user_hashes.items():
        password = cracked.get(stored_hash)
        if password:
            score, status, reason = evaluate_password(user, password)
            results.append((user, password, status, score, reason))
        else:
            results.append((user, "—", "Uncracked", 0, "Password not cracked"))

    return results
