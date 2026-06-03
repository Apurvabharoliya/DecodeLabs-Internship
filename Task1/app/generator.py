import string
import secrets

def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True, 
                      use_numbers: bool = True, use_symbols: bool = True) -> str:
    """
    Generates a secure password using the secrets module (cryptographically strong).
    Ensures at least one character from each selected pool is included.
    """
    pool = ""
    password_chars = []
    
    if use_upper:
        pool += string.ascii_uppercase
        if length > len(password_chars):
            password_chars.append(secrets.choice(string.ascii_uppercase))
            
    if use_lower:
        pool += string.ascii_lowercase
        if length > len(password_chars):
            password_chars.append(secrets.choice(string.ascii_lowercase))
            
    if use_numbers:
        pool += string.digits
        if length > len(password_chars):
            password_chars.append(secrets.choice(string.digits))
            
    if use_symbols:
        pool += string.punctuation
        if length > len(password_chars):
            password_chars.append(secrets.choice(string.punctuation))
            
    if not pool:
        pool = string.ascii_lowercase
        if length > len(password_chars):
            password_chars.append(secrets.choice(string.ascii_lowercase))
        
    remaining_length = length - len(password_chars)
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(pool))
        
    # Shuffle using cryptographically secure RNG
    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)
    
    return "".join(password_chars)
