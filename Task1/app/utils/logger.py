import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "audit.log")

def log_audit(results: dict):
    """
    Saves an audit log entry locally.
    Does NOT save the actual password to prevent security risks (RAM persistence risks, etc.).
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = (
        f"[{timestamp}] "
        f"Strength: {results['strength']} | "
        f"Score: {results['score']} | "
        f"Entropy: {results['entropy']} | "
        f"Crack Time: {results['crack_time']['display']}\n"
    )
    
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry)
