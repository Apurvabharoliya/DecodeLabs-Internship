import math

def calculate_pool_size(password: str) -> int:
    """Calculates the character pool size used in the password."""
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    
    # Check for symbols and unicode
    has_symbols = any(not c.isalnum() and ord(c) <= 127 for c in password)
    has_unicode = any(ord(c) > 127 for c in password)
    
    if has_symbols:
        pool_size += 32
    if has_unicode:
        pool_size += 144697 # Approximate number of valid unicode characters
        
    if pool_size == 0 and len(password) > 0:
        pool_size = 256 # Fallback
        
    return pool_size

def calculate_entropy(password: str) -> float:
    """Calculates Shannon entropy for the password."""
    if not password:
        return 0.0
    pool_size = calculate_pool_size(password)
    entropy = len(password) * math.log2(pool_size)
    return entropy

def estimate_crack_time(entropy: float) -> dict:
    """
    Estimates the time to crack a password based on entropy.
    Assumes a powerful offline cracking rig (e.g., 100 billion guesses per second).
    """
    guesses_per_second = 100_000_000_000
    combinations = 2 ** entropy
    
    seconds = (combinations * 0.5) / guesses_per_second
    
    if seconds < 1:
        time_str = "Instantly"
    elif seconds < 60:
        time_str = f"{int(seconds)} seconds"
    elif seconds < 3600:
        time_str = f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        time_str = f"{int(seconds / 3600)} hours"
    elif seconds < 31536000:
        time_str = f"{int(seconds / 86400)} days"
    elif seconds < 31536000 * 100:
        time_str = f"{int(seconds / 31536000)} years"
    else:
        time_str = "Centuries"
        
    return {
        "seconds": seconds,
        "display": time_str
    }
