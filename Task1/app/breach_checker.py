import os
import hmac
import re

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "common_passwords.txt")

def load_common_passwords():
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

COMMON_PASSWORDS = load_common_passwords()

def check_breach(password: str) -> bool:
    """
    Checks if password is in the common passwords database.
    Uses timing-safe comparison to prevent timing attacks.
    """
    encoded_pass = password.encode('utf-8')
    
    for cp in COMMON_PASSWORDS:
        # hmac.compare_digest prevents timing attacks that could reveal the password length or characters
        if hmac.compare_digest(encoded_pass, cp.encode('utf-8')):
            return True
            
    return False

def check_weak_patterns(password: str) -> dict:
    """
    Detects weak patterns like sequences, repeated characters, and keyboard patterns.
    """
    password_lower = password.lower()
    
    # 1. Repeated characters (e.g., aaaaa, 11111)
    if re.search(r'(.)\1{2,}', password_lower):
        return {"found": True, "type": "Repeated characters", "feedback": "Avoid repeating the same character (e.g., aaaa)."}
        
    # 2. Sequential characters (e.g., abcdef, 123456)
    sequences = ["abcdefghijklmnopqrstuvwxyz", "01234567890", "zyxwvutsrqponmlkjihgfedcba", "09876543210"]
    for seq in sequences:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in password_lower:
                return {"found": True, "type": "Sequential characters", "feedback": "Avoid sequential characters (e.g., 1234, abcd)."}
                
    # 3. Keyboard patterns
    keyboard_patterns = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
        "qazwsxedc", "rfvtgbyhn", "ujmikolp"
    ]
    for pattern in keyboard_patterns:
        for i in range(len(pattern) - 3):
            if pattern[i:i+4] in password_lower:
                return {"found": True, "type": "Keyboard pattern", "feedback": "Avoid common keyboard patterns (e.g., qwer)."}
                
    return {"found": False}
