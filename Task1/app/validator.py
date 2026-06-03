import unicodedata
from .entropy import calculate_entropy, estimate_crack_time
from .breach_checker import check_breach, check_weak_patterns

def validate_password(password: str) -> dict:
    """
    Advanced password validation using entropy, pattern detection, and breach checking.
    """
    if not password:
        return {
            "strength": "None",
            "score": 0,
            "entropy": 0.0,
            "crack_time": {"seconds": 0, "display": "0 seconds"},
            "feedback": ["Please enter a password."],
            "color": "#6c757d"
        }
        
    # Unicode-aware: normalize string to NFKC
    password = unicodedata.normalize('NFKC', password)
    
    feedback = []
    score = 0
    
    # 1. Entropy & Crack Time Calculation
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    
    # Base score on entropy
    if entropy >= 100:
        score += 5
    elif entropy >= 75:
        score += 4
    elif entropy >= 50:
        score += 3
    elif entropy >= 30:
        score += 2
    else:
        score += 1
        
    # 2. Check Breach Database
    if check_breach(password):
        feedback.append("⚠️ LEAKED: This password appears in known data breaches!")
        score = 0
        
    # 3. Check Weak Patterns
    pattern_check = check_weak_patterns(password)
    if pattern_check["found"]:
        feedback.append(f"⚠️ PATTERN: {pattern_check['feedback']}")
        score = max(0, score - 2)
        
    # 4. Standard Validations
    if not any(c.isupper() for c in password):
        feedback.append("Add uppercase letters to increase entropy.")
    if not any(c.islower() for c in password):
        feedback.append("Add lowercase letters to increase entropy.")
    if not any(c.isdigit() for c in password):
        feedback.append("Add numbers to increase entropy.")
    if not any(not c.isalnum() for c in password):
        feedback.append("Add special symbols to increase entropy.")
        
    if len(password) < 12:
        feedback.append("Consider a longer password (12+ characters recommended).")
        
    # 5. Determine Strength Levels
    if score == 0 or entropy < 30:
        strength = "Very Weak"
        color = "#ff3333" # Neon Red
    elif score <= 2 or entropy < 50:
        strength = "Weak"
        color = "#ff9933" # Neon Orange
    elif score <= 3 or entropy < 70:
        strength = "Medium"
        color = "#ffff33" # Neon Yellow
    elif score <= 4 or entropy < 90:
        strength = "Strong"
        color = "#33cc33" # Neon Green
    else:
        strength = "Very Strong"
        color = "#00ffcc" # Neon Cyan
        
    if len(feedback) == 0:
        feedback.append("✓ Excellent password. Meets all security policies.")
        
    return {
        "strength": strength,
        "score": min(max(score, 0), 5),
        "entropy": round(entropy, 2),
        "crack_time": crack_time,
        "feedback": feedback,
        "color": color
    }
