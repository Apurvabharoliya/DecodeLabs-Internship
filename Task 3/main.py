#!/usr/bin/env python3
"""
Task 3: Phishing Awareness Analysis Program
============================================
Analyzes sample emails/messages to identify phishing attempts.
Detects suspicious links, keywords, and red flags.
Explains why messages are unsafe.

Author: Buffy (Codebuff AI Assistant)
Date: June 8, 2026
"""

import re
import sys
import argparse
from dataclasses import dataclass, field
from urllib.parse import urlparse


# Fix encoding for Windows cp1252 console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        # Python < 3.7 doesn't have reconfigure
        import io
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )


# =============================================================================
# COLOR SYSTEM
# =============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    # Reset
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    # Foreground
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"

    @staticmethod
    def supports_color():
        """Check if terminal supports colors."""
        if not hasattr(sys.stdout, "isatty"):
            return False
        if not sys.stdout.isatty():
            return False
        return True


# Disable colors if terminal doesn't support them
USE_COLORS = Colors.supports_color()


def c(text, color):
    """Wrap text with color if colors are enabled."""
    if USE_COLORS:
        return f"{color}{text}{Colors.RESET}"
    return text


def bold(text):
    """Make text bold."""
    return c(text, Colors.BOLD)


def dim(text):
    """Make text dim."""
    return c(text, Colors.DIM)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PhishingEmail:
    """Represents a sample phishing email for analysis."""
    name: str
    category: str
    sender: str
    sender_email: str
    subject: str
    body: str
    display_url: str
    actual_url: str
    legitimate_url: str
    attack_type: str
    explanation: str


@dataclass
class RedFlag:
    """A detected red flag in a message."""
    name: str
    explanation: str


@dataclass
class AnalysisResult:
    """Complete analysis result for a single email."""
    email: PhishingEmail
    red_flags: list = field(default_factory=list)
    suspicious_keywords_found: list = field(default_factory=list)
    url_analysis: dict = field(default_factory=dict)
    threat_level: str = "LOW"
    summary: str = ""


# =============================================================================
# SUSPICIOUS KEYWORDS DATABASE
# =============================================================================

URGENCY_KEYWORDS = {
    "immediate action required": "Bypasses careful consideration",
    "action required": "Bypasses careful consideration",
    "account will be suspended": "Fear of loss drives hasty clicks",
    "final warning": "Implies irreversible consequences",
    "within 24 hours": "Artificial deadline prevents verification",
    "today only": "Artificial deadline prevents verification",
    "do not share this message": "Prevents the victim from asking for help",
    "unauthorized access detected": "Triggers panic about account compromise",
    "expires today": "Artificial deadline prevents verification",
    "expires in 2 hours": "Extreme urgency with artificial deadline",
    "before end of business today": "Prevents following approval workflows",
    "will be permanently locked": "Fear of irreversible loss",
}

FINANCIAL_KEYWORDS = {
    "wire transfer": "Direct financial theft",
    "urgent payment": "Direct financial theft",
    "confidential": "Isolates victim from advisors",
    "do not discuss": "Isolates victim from advisors",
    "verify your identity": "Usually precedes credential harvesting",
    "update your payment information": "Classic pretext for stealing financial data",
    "tax document": "Seasonal lures for identity theft",
    "w-2": "Seasonal lures for identity theft",
}

TECHNICAL_KEYWORDS = {
    "suspicious sign-in detected": "Mimics legitimate security alerts",
    "reset your password": "Credential phishing vector",
    "mfa verification required": "MFA bypass / AiTM attack setup",
    "grant access to view": "OAuth consent abuse setup",
    "scan qr code": "Quishing - bypasses URL scanning",
    "verify my identity": "Usually precedes credential harvesting",
    "additional authentication": "Pre-justifies OAuth consent request",
}

GENERIC_GREETINGS = [
    "dear employee",
    "dear user",
    "dear team",
    "dear customer",
    "dear valued customer",
    "dear account holder",
    "dear sir/madam",
    "hello there",
    "greetings",
]

# Known legitimate sender domains
LEGITIMATE_DOMAINS = {
    "microsoft.com": "Microsoft",
    "google.com": "Google",
    "zoom.us": "Zoom",
    "slack.com": "Slack",
    "acmecorp.com": "Acme Corp",
}


# =============================================================================
# THREAT LANDSCAPE OVERVIEW
# =============================================================================

THREAT_LANDSCAPE = [
    "83% of phishing emails now use AI-generated content, making them",
    "grammatically correct and highly personalized.",
    "",
    "Multi-channel attacks blend email with voice calls (vishing) and",
    "SMS (smishing) for added legitimacy.",
    "",
    "Quishing (QR code phishing) bypasses traditional email link scanners.",
    "",
    "OAuth abuse tricks users into granting persistent cloud access",
    "without stealing passwords.",
]


# =============================================================================
# PHISHING EMAIL SAMPLES
# =============================================================================

SAMPLE_PHISHING_EMAILS = [
    PhishingEmail(
        name="Sample 1: Corporate Password Reset Scam",
        category="Credential Harvesting",
        sender="IT Security Team",
        sender_email="security@company-support.com",
        subject="ACTION REQUIRED: Your Password Expires Today",
        body=(
            "Dear Employee,\n\n"
            "Our system has detected unusual sign-in activity on your account. "
            "Your current password will expire in 2 hours. Failure to reset your "
            "password will result in immediate account suspension and loss of "
            "access to all Acme Corp systems.\n\n"
            "Please reset your password immediately by clicking the link below:\n\n"
            "[Reset My Password Now]\n\n"
            "If you do not act within the next 2 hours, your account will be "
            "permanently locked and you will need to contact IT support to "
            "regain access.\n\n"
            "This is an automated message. Please do not reply.\n\n"
            "Best regards,\nAcme Corp IT Security Team"
        ),
        display_url="[Reset My Password Now]",
        actual_url="https://acme-corp-secure-login.com/auth/reset",
        legitimate_url="https://login.acmecorp.com/auth",
        attack_type="Credential Harvesting",
        explanation=(
            "Clicking the link would redirect to a fake login page that visually "
            "mimics Acme Corp's SSO portal. Any credentials entered are captured "
            "by the attacker. The urgency is designed to prevent the victim from "
            "pausing to verify the request through an official channel. Once "
            "credentials are stolen, the attacker can access email, internal "
            "systems, and sensitive data."
        ),
    ),
    PhishingEmail(
        name="Sample 2: Fake IT Support / MFA Bypass",
        category="MFA Bypass",
        sender="Azure Security Alerts",
        sender_email="no-reply@microsoft365-security.net",
        subject="Suspicious Sign-In Detected on Your Microsoft 365 Account",
        body=(
            "Microsoft Security Alert\n\n"
            "We detected a sign-in attempt from an unrecognized device:\n\n"
            "  Device: iPhone 15 - Sao Paulo, Brazil\n"
            "  Time: June 7, 2026, 3:42 AM (UTC)\n"
            "  Browser: Safari Mobile\n"
            "  Status: Blocked\n\n"
            "If this wasn't you, your account may be compromised. Please verify "
            "your identity immediately to secure your account:\n\n"
            "[Verify My Identity]\n\n"
            "If you do not verify within 24 hours, we will temporarily disable "
            "your account to protect your data.\n\n"
            "Microsoft Account Security Team"
        ),
        display_url="[Verify My Identity]",
        actual_url="https://microsoft-365-verify.com/signin",
        legitimate_url="https://accountprotection.microsoft.com",
        attack_type="Credential Theft + MFA Bypass",
        explanation=(
            "The fake verification page requests Microsoft 365 credentials and "
            "MFA codes. Advanced variants use real-time phishing proxies (AiTM) "
            "that relay credentials and MFA tokens in real time, allowing "
            "attackers to hijack active sessions. Once inside, attackers can "
            "access emails, OneDrive, SharePoint, and internal communications."
        ),
    ),
    PhishingEmail(
        name="Sample 3: CEO Fraud / Business Email Compromise",
        category="Business Email Compromise (BEC)",
        sender="David Chen",
        sender_email="d.chen@company-internal.com",
        subject="Confidential - Urgent Wire Transfer Needed",
        body=(
            "Hi,\n\n"
            "I need you to handle something confidentially. We're finalizing an "
            "acquisition and need to wire $47,500 to our legal counsel's trust "
            "account before end of business today. The deal cannot proceed "
            "without this transfer.\n\n"
            "Please initiate the wire to the following:\n\n"
            "  Bank: First National Trust\n"
            "  Account Name: Meridian Legal Services LLC\n"
            "  Account Number: 9876543210\n"
            "  Routing Number: 021000021\n"
            "  Amount: $47,500.00\n\n"
            "Do NOT discuss this with anyone - it's under NDA until the "
            "acquisition is public. I'm in back-to-back meetings and can't take "
            "calls. Just handle it and confirm when done.\n\n"
            "Thanks,\nDavid\n\n"
            "David Chen | CEO"
        ),
        display_url="[Wire Transfer Request]",
        actual_url="N/A - Financial transfer request",
        legitimate_url="N/A",
        attack_type="Business Email Compromise (BEC)",
        explanation=(
            "One of the most financially damaging cybercrime types. The attacker "
            "impersonates the CEO to leverage authority and bypass approval "
            "processes. The wire transfer would go to an account controlled by "
            "the attacker. Once transferred, funds are rapidly moved through "
            "multiple accounts and are nearly impossible to recover."
        ),
    ),
    PhishingEmail(
        name="Sample 4: Quishing (QR Code Phishing)",
        category="Quishing / QR Code Phishing",
        sender="HR Benefits Department",
        sender_email="benefits@corp-hr-notifications.com",
        subject="Open Enrollment - Complete Your Benefits Selection",
        body=(
            "Dear Team,\n\n"
            "It's time to select your benefits for the upcoming plan year. "
            "Please review your options and make your selections by June 15, 2026.\n\n"
            "We've attached a QR code below for quick access to the benefits "
            "portal. Simply scan it with your phone camera to log in and make "
            "your selections.\n\n"
            "[QR CODE IMAGE]\n\n"
            "If you have questions about your benefits package, please contact HR.\n\n"
            "Best,\nHuman Resources"
        ),
        display_url="[QR CODE IMAGE]",
        actual_url="https://acme-benefits-portal.com/enroll",
        legitimate_url="https://benefits.acmecorp.com/enroll",
        attack_type="Quishing (QR Code Phishing)",
        explanation=(
            "The QR code encodes a URL to a fake benefits portal that harvests "
            "login credentials, Social Security numbers, bank account details, "
            "and other sensitive PII. The QR code URL cannot be inspected before "
            "scanning, and mobile devices have weaker security controls. Benefits "
            "data is extremely valuable for identity theft."
        ),
    ),
    PhishingEmail(
        name="Sample 5: OAuth Consent Phishing",
        category="OAuth Abuse",
        sender="Zoom Support",
        sender_email="support@zoom-us-apps.com",
        subject="You've Been Invited to a Shared Recording",
        body=(
            "A colleague has shared a meeting recording with you:\n\n"
            "  Meeting: Q2 Financial Review - CONFIDENTIAL\n"
            "  Shared by: Sarah Mitchell (Finance)\n"
            "  Date: June 5, 2026\n"
            "  Duration: 47 minutes\n\n"
            "To view this recording, please grant access through our secure "
            "portal:\n\n"
            "[Access Recording]\n\n"
            "Note: This recording contains confidential financial data and "
            "requires additional authentication to view."
        ),
        display_url="[Access Recording]",
        actual_url="https://zoom-app-share.com/record/view",
        legitimate_url="https://zoom.us/rec/share/...",
        attack_type="OAuth Consent Abuse",
        explanation=(
            "The victim is tricked into granting a malicious third-party "
            "application access to their Microsoft 365 or Google Workspace "
            "account. This grants the attacker persistent access to read/send "
            "emails, access cloud storage, calendar, and contacts - even after "
            "password changes."
        ),
    ),
]


# =============================================================================
# URL EXTRACTION FROM BODY
# =============================================================================

def extract_urls_from_body(body):
    """Extract all URLs from email body text."""
    # Match http/https URLs
    url_pattern = r'https?://[^\s<>"\')\]]+'
    urls = re.findall(url_pattern, body)
    # Also match URLs inside square brackets like [https://example.com]
    bracket_pattern = r'\[(https?://[^\]]+)\]'
    urls.extend(re.findall(bracket_pattern, body))
    # Deduplicate while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        # Clean up trailing punctuation
        url = url.rstrip('.,;:!?')
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    return unique_urls


# =============================================================================
# URL ANALYSIS FUNCTIONS
# =============================================================================

def extract_domain_from_email(email_str):
    """Extract domain from an email address."""
    match = re.search(r"@(.+)$", email_str)
    return match.group(1) if match else ""


def check_domain_spoofing(sender_email):
    """Check if the sender domain is spoofed or lookalike."""
    flags = []
    domain = extract_domain_from_email(sender_email)

    if not domain:
        return flags

    suspicious_patterns = [
        "company-support",
        "company-internal",
        "corp-hr",
        "microsoft365-security",
        "zoom-us-apps",
        "secure-login",
        "verify",
        "support",
        "notifications",
        "alert",
    ]

    is_known_legitimate = any(domain == d for d in LEGITIMATE_DOMAINS)

    if not is_known_legitimate:
        for pattern in suspicious_patterns:
            if pattern in domain:
                flags.append(RedFlag(
                    name="Sender Domain Mismatch",
                    explanation=(
                        f"The sender domain '{domain}' mimics a legitimate "
                        f"service but is not an official domain. This is a "
                        f"classic spoofed domain technique."
                    ),
                ))
                break
        else:
            if any(kw in domain for kw in ["security", "support", "verify", "alert"]):
                flags.append(RedFlag(
                    name="Suspicious Sender Domain",
                    explanation=(
                        f"The domain '{domain}' contains trust-inducing keywords "
                        f"(security, support, verify) but is not from the "
                        f"claimed organization's official domain."
                    ),
                ))

    return flags


def analyze_url(display_url, actual_url, legitimate_url, extracted_urls=None):
    """Analyze URLs for phishing indicators."""
    result = {
        "display_url": display_url,
        "actual_url": actual_url,
        "legitimate_url": legitimate_url,
        "extracted_urls": extracted_urls or [],
        "issues": [],
        "is_suspicious": False,
    }

    # Handle N/A URLs (like BEC attacks)
    if actual_url in ("N/A - Financial transfer request", "N/A"):
        if "Financial" in actual_url:
            result["issues"].append("No URL - this is a direct financial transfer request")
            result["is_suspicious"] = True
        return result

    # If we have actual_url, analyze it
    if actual_url:
        parsed = urlparse(actual_url)
        actual_domain = parsed.netloc

        lookalike_indicators = [
            "secure-login", "verify", "confirm", "update",
            "auth", "login", "signin", "account",
        ]

        for indicator in lookalike_indicators:
            if indicator in actual_domain.lower():
                result["issues"].append(
                    f"Domain contains '{indicator}' - common in phishing URLs"
                )

        if actual_domain.count("-") >= 2:
            result["issues"].append(
                f"Domain has multiple hyphens ({actual_domain.count('-')}), "
                f"common in lookalike domains"
            )

        if legitimate_url and legitimate_url != "N/A":
            legit_parsed = urlparse(legitimate_url)
            legit_domain = legit_parsed.netloc
            if actual_domain != legit_domain and legit_domain:
                result["issues"].append(
                    f"URL domain '{actual_domain}' does not match "
                    f"legitimate domain '{legit_domain}'"
                )

        suspicious_tlds = [".xyz", ".top", ".buzz", ".club", ".info", ".tk", ".ml"]
        for tld in suspicious_tlds:
            if actual_domain.endswith(tld):
                result["issues"].append(f"Uses suspicious TLD: {tld}")
                break

    # Analyze extracted URLs from body
    if extracted_urls:
        for url in extracted_urls:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain:
                continue

            # Check for suspicious patterns in extracted URLs
            for indicator in ["secure-login", "verify", "confirm", "update", "auth", "login"]:
                if indicator in domain.lower():
                    result["issues"].append(
                        f"Body URL contains '{indicator}' in domain: {domain}"
                    )

            # Check for lookalike domains
            for known_domain in LEGITIMATE_DOMAINS:
                # Check if domain is a lookalike (e.g., acme-corp vs acme)
                if known_domain.split(".")[0] in domain and domain != known_domain:
                    if domain != actual_url:
                        result["issues"].append(
                            f"URL '{url}' mimics legitimate domain '{known_domain}'"
                        )

    result["is_suspicious"] = len(result["issues"]) > 0
    return result


# =============================================================================
# KEYWORD SCANNING
# =============================================================================

def scan_keywords(body):
    """Scan email body for suspicious keywords."""
    found = []
    body_lower = body.lower()

    all_categories = {
        "Urgency/Threat": URGENCY_KEYWORDS,
        "Financial": FINANCIAL_KEYWORDS,
        "Technical/IT": TECHNICAL_KEYWORDS,
    }

    for category, keywords in all_categories.items():
        for keyword, reason in keywords.items():
            if keyword in body_lower:
                found.append({
                    "keyword": keyword,
                    "category": category,
                    "reason": reason,
                })

    for greeting in GENERIC_GREETINGS:
        if greeting in body_lower:
            found.append({
                "keyword": greeting,
                "category": "Social Engineering",
                "reason": "Generic greeting suggests mass distribution",
            })

    return found


# =============================================================================
# RED FLAG DETECTION
# =============================================================================

def detect_red_flags(email):
    """Detect all red flags in a phishing email."""
    flags = []
    body_lower = email.body.lower()

    # 1. Domain spoofing
    flags.extend(check_domain_spoofing(email.sender_email))

    # 2. Urgency/fear tactics
    urgency_words = [
        "immediately", "urgent", "expires", "suspended", "locked",
        "deadline", "within", "before end of", "will be permanently",
    ]
    urgency_found = [w for w in urgency_words if w in body_lower]
    if urgency_found:
        flags.append(RedFlag(
            name="Urgency and Fear Tactics",
            explanation=(
                f"Message uses urgency language ({', '.join(urgency_found[:3])}...) "
                f"to pressure quick action and bypass rational thinking."
            ),
        ))

    # 3. Vague/generic greeting
    for greeting in GENERIC_GREETINGS:
        if greeting in body_lower:
            flags.append(RedFlag(
                name="Generic Greeting",
                explanation=(
                    f"Uses '{greeting}' instead of the recipient's actual name, "
                    f"suggesting a mass-sent phishing email."
                ),
            ))
            break

    # 4. Suspicious link
    if email.actual_url and email.actual_url != "N/A" and "Financial" not in email.actual_url:
        url_result = analyze_url(email.display_url, email.actual_url, email.legitimate_url)
        if url_result["is_suspicious"]:
            flags.append(RedFlag(
                name="Suspicious Link",
                explanation=(
                    f"The displayed link points to '{email.actual_url}', "
                    f"which does not match the expected legitimate URL. "
                    f"Issues: {'; '.join(url_result['issues'])}"
                ),
            ))

    # 5. No-reply / prevent verification
    if "do not reply" in body_lower or "no-reply" in email.sender_email:
        flags.append(RedFlag(
            name="Prevents Verification",
            explanation=(
                "Tells recipient not to reply, preventing them from verifying "
                "the request through the supposed sender."
            ),
        ))

    # 6. Artificial deadline
    deadline_patterns = [
        r"within \d+ hours?",
        r"expires? (today|in \d+)",
        r"before end of (business )?today",
        r"permanently locked",
        r"will be disabled",
    ]
    for pattern in deadline_patterns:
        if re.search(pattern, body_lower):
            flags.append(RedFlag(
                name="Artificial Deadline",
                explanation=(
                    "Sets an unrealistic time pressure to prevent the victim "
                    "from verifying the request through an independent channel."
                ),
            ))
            break

    # 7. Secrecy request
    secrecy_phrases = [
        "do not discuss", "do not share", "do not tell",
        "confidential", "under nda", "keep this private",
    ]
    if any(phrase in body_lower for phrase in secrecy_phrases):
        flags.append(RedFlag(
            name="Secrecy / Isolation Tactic",
            explanation=(
                "Requests secrecy or confidentiality to isolate the victim "
                "from colleagues who might recognize the scam."
            ),
        ))

    # 8. Financial transfer request
    financial_phrases = [
        "wire transfer", "wire $", "account number", "routing number",
        "initiate the wire", "send payment", "bank account",
    ]
    if any(phrase in body_lower for phrase in financial_phrases):
        flags.append(RedFlag(
            name="Financial Transfer Request",
            explanation=(
                "Requests a wire transfer or financial transaction, which "
                "should always require verbal verification through an "
                "independent channel."
            ),
        ))

    # 9. Can't take calls
    call_prevention = ["can't take calls", "in meetings", "not available by phone"]
    if any(phrase in body_lower for phrase in call_prevention):
        flags.append(RedFlag(
            name="Preempts Verification Call",
            explanation=(
                "Preemptively shuts down the most common verification method "
                "(a phone call) to prevent the victim from confirming."
            ),
        ))

    # 10. QR code usage
    if "qr code" in body_lower or "[qr code" in body_lower:
        flags.append(RedFlag(
            name="QR Code in Email",
            explanation=(
                "QR codes bypass email security scanners that check text-based "
                "links. The encoded URL is invisible to the scanner and cannot "
                "be inspected before scanning."
            ),
        ))

    # 11. OAuth / grant access
    oauth_phrases = ["grant access", "oauth", "consent", "additional authentication"]
    if any(phrase in body_lower for phrase in oauth_phrases):
        flags.append(RedFlag(
            name="OAuth Consent Trap",
            explanation=(
                "May trick you into granting a malicious application access "
                "to your cloud account (Microsoft 365, Google Workspace), "
                "providing persistent access to email, files, and data."
            ),
        ))

    # 12. Authority impersonation
    authority_titles = ["ceo", "cto", "cfo", "president", "director", "vp"]
    if any(title in body_lower for title in authority_titles):
        flags.append(RedFlag(
            name="Authority Impersonation",
            explanation=(
                "Impersonates a senior executive to leverage authority and "
                "bypass normal approval processes."
            ),
        ))

    return flags


# =============================================================================
# THREAT LEVEL ASSESSMENT
# =============================================================================

def assess_threat_level(flags, keywords):
    """Assess the overall threat level based on detected indicators."""
    score = len(flags) * 2 + len(keywords)

    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    else:
        return "LOW"


# =============================================================================
# FULL ANALYSIS
# =============================================================================

def analyze_email(email):
    """Perform complete analysis on a phishing email."""
    flags = detect_red_flags(email)
    keywords = scan_keywords(email.body)

    # Extract URLs from body for analysis
    extracted_urls = extract_urls_from_body(email.body)
    url_result = analyze_url(email.display_url, email.actual_url, email.legitimate_url, extracted_urls)

    threat_level = assess_threat_level(flags, keywords)

    summary = (
        f"Attack Type: {email.attack_type}\n"
        f"Threat Level: {threat_level}\n"
        f"Red Flags Detected: {len(flags)}\n"
        f"Suspicious Keywords Found: {len(keywords)}\n"
        f"Explanation: {email.explanation}"
    )

    return AnalysisResult(
        email=email,
        red_flags=flags,
        suspicious_keywords_found=[kw["keyword"] for kw in keywords],
        url_analysis=url_result,
        threat_level=threat_level,
        summary=summary,
    )


# =============================================================================
# DISPLAY FUNCTIONS (REDESIGNED UI)
# =============================================================================

def print_separator(char="=", length=70):
    """Print a visual separator with color."""
    if USE_COLORS:
        print(f"{Colors.DIM}{char * length}{Colors.RESET}")
    else:
        print(char * length)


def print_header(text):
    """Print a formatted header with styling."""
    print()
    print_separator("=", 70)
    print(f"  {c(text, Colors.CYAN + Colors.BOLD)}")
    print_separator("=", 70)
    print()


def print_section_header(text, icon=""):
    """Print a section header with icon."""
    prefix = f"{icon} " if icon else ""
    print(f"  {c(f'{prefix}{text}', Colors.YELLOW + Colors.BOLD)}")
    print(f"  {c('─' * 50, Colors.DIM)}")


def print_threat_badge(level):
    """Print a colored threat level badge."""
    badges = {
        "CRITICAL": (Colors.BG_RED + Colors.WHITE + Colors.BOLD, "[!!! CRITICAL !!!]"),
        "HIGH": (Colors.RED + Colors.BOLD, "[!! HIGH !!]"),
        "MEDIUM": (Colors.YELLOW + Colors.BOLD, "[! MEDIUM !]"),
        "LOW": (Colors.GREEN, "[LOW]"),
    }
    style, label = badges.get(level, (Colors.RESET, "[UNKNOWN]"))
    print(f"  THREAT LEVEL: {c(label, style)}")


def print_analysis(result):
    """Print a complete analysis result with improved UI."""
    email = result.email

    print_header(email.name)

    # Email metadata
    print(f"  {c('Category:', Colors.BOLD)}  {email.category}")
    print(f"  {c('From:', Colors.BOLD)}      {email.sender} {c(f'<{email.sender_email}>', Colors.DIM)}")
    print(f"  {c('Subject:', Colors.BOLD)}   {email.subject}")
    print()

    # Email body
    print_section_header("EMAIL BODY", "📧")
    print(f"  {c('─' * 60, Colors.DIM)}")
    for line in email.body.split("\n"):
        print(f"  {line}")
    print(f"  {c('─' * 60, Colors.DIM)}")
    print()

    # Threat level badge
    print_threat_badge(result.threat_level)
    print()

    # URL Analysis (only show if there's data)
    has_url_data = (
        result.url_analysis.get("actual_url") and
        result.url_analysis["actual_url"] not in ("", "N/A - Financial transfer request", "N/A")
    ) or (
        result.url_analysis.get("extracted_urls") and
        len(result.url_analysis["extracted_urls"]) > 0
    ) or (
        result.url_analysis.get("issues") and
        len(result.url_analysis["issues"]) > 0
    )

    if has_url_data:
        print_section_header("URL ANALYSIS", "🔗")
        actual = result.url_analysis["actual_url"]

        if actual in ("N/A - Financial transfer request", "N/A"):
            print(f"  {c('Display:', Colors.BOLD)}    {result.url_analysis['display_url']}")
            print(f"  {c('Note:', Colors.BOLD)}       {c(actual, Colors.YELLOW)}")
        else:
            print(f"  {c('Displayed:', Colors.BOLD)}  {result.url_analysis['display_url']}")
            print(f"  {c('Actual:', Colors.BOLD)}     {c(actual, Colors.RED)}")
            if result.url_analysis["legitimate_url"] and result.url_analysis["legitimate_url"] != "N/A":
                print(f"  {c('Legitimate:', Colors.BOLD)} {c(result.url_analysis['legitimate_url'], Colors.GREEN)}")

            if result.url_analysis["issues"]:
                print()
                print(f"    {c('Issues Found:', Colors.RED + Colors.BOLD)}")
                for issue in result.url_analysis["issues"]:
                    print(f"      {c('✗', Colors.RED)} {issue}")

        # Show extracted URLs if any
        if result.url_analysis.get("extracted_urls"):
            print()
            print(f"  {c('URLs Found in Body:', Colors.BOLD)}")
            for url in result.url_analysis["extracted_urls"]:
                # Check if URL is in issues (suspicious)
                is_suspicious = any(url in issue for issue in result.url_analysis.get("issues", []))
                if is_suspicious:
                    print(f"    {c('✗', Colors.RED)} {url} {c('[SUSPICIOUS]', Colors.RED)}")
                else:
                    print(f"    {c('○', Colors.GREEN)} {url}")
        print()

    # Red Flags
    if result.red_flags:
        print_section_header("RED FLAGS DETECTED", "🚩")
        for i, flag in enumerate(result.red_flags, 1):
            print(f"  {c(str(i) + '.', Colors.BOLD + Colors.RED)} {c(flag.name, Colors.RED + Colors.BOLD)}")
            print(f"     {c('→', Colors.DIM)} {flag.explanation}")
        print()

    # Suspicious Keywords
    if result.suspicious_keywords_found:
        print_section_header("SUSPICIOUS KEYWORDS FOUND", "🔍")
        for kw in result.suspicious_keywords_found:
            print(f"    {c('•', Colors.YELLOW)} '{kw}'")
        print()

    # Why Unsafe
    print_section_header("WHY THIS MESSAGE IS UNSAFE", "⚠️")
    print(f"  {email.explanation}")
    print()


def print_red_flags_checklist():
    """Print the common red flags checklist with visual indicators."""
    print_header("COMMON RED FLAGS CHECKLIST")
    checklist = [
        ("Sender domain doesn't match the claimed organization", "🔴"),
        ("Urgency, fear, or artificial deadlines pressure quick action", "🔴"),
        ("Requests for credentials, MFA codes, or financial transfers", "🔴"),
        ("Links that, when hovered, reveal unexpected URLs", "🟡"),
        ("Generic greetings ('Dear User,' 'Dear Employee,' 'Dear Team')", "🟡"),
        ("Requests to bypass normal procedures or keep things secret", "🔴"),
        ("Unexpected attachments (especially .exe, .svg, .html)", "🔴"),
        ("Emotional manipulation (fear, greed, curiosity, authority)", "🟡"),
        ("QR codes embedded in emails", "🟡"),
        ("Grammar or formatting inconsistencies", "🟢"),
        ("Requests arriving outside normal business hours", "🟡"),
        ("Pressure to act before you can verify independently", "🔴"),
    ]

    for item, indicator in checklist:
        print(f"  {indicator}  {item}")
    print()


def print_protection_guide():
    """Print the protection guide with visual hierarchy."""
    print_header("HOW TO PROTECT YOURSELF")

    print(f"  {c('IMMEDIATE ACTIONS:', Colors.GREEN + Colors.BOLD)}")
    print(f"    {c('1.', Colors.BOLD)} Hover before clicking - check the actual URL destination")
    print(f"    {c('2.', Colors.BOLD)} Verify independently - contact sender through a known channel")
    print(f"    {c('3.', Colors.BOLD)} Don't scan QR codes from emails - type URLs directly")
    print(f"    {c('4.', Colors.BOLD)} Never share MFA codes via email or phone")
    print(f"    {c('5.', Colors.BOLD)} Check email headers (Return-Path, SPF, DKIM)")
    print(f"        {c('•', Colors.DIM)} Return-Path mismatch (doesn't match the From address)")
    print(f"        {c('•', Colors.DIM)} Received-SPF: Fail or SoftFail")
    print(f"        {c('•', Colors.DIM)} X-Originating-IP from unexpected country/ISP")
    print(f"        {c('•', Colors.DIM)} DKIM: fail (email signature verification failed)")
    print()

    print(f"  {c('ORGANIZATIONAL BEST PRACTICES:', Colors.BLUE + Colors.BOLD)}")
    print(f"    {c('1.', Colors.BOLD)} Enable MFA everywhere")
    print(f"    {c('2.', Colors.BOLD)} Implement DMARC/DKIM/SPF")
    print(f"    {c('3.', Colors.BOLD)} Conduct regular phishing simulations")
    print(f"    {c('4.', Colors.BOLD)} Enforce multi-person approval for financial transactions")
    print(f"    {c('5.', Colors.BOLD)} Review OAuth app permissions regularly")
    print(f"    {c('6.', Colors.BOLD)} Use email security gateways")
    print()

    print(f"  {c('IF YOU SUSPECT PHISHING:', Colors.RED + Colors.BOLD)}")
    print(f"    {c('1.', Colors.BOLD)} Do NOT click links or download attachments")
    print(f"    {c('2.', Colors.BOLD)} Report to IT security team immediately")
    print(f"    {c('3.', Colors.BOLD)} Delete the email after reporting")
    print(f"    {c('4.', Colors.BOLD)} If you clicked: change password, enable MFA, monitor accounts")
    print(f"    {c('5.', Colors.BOLD)} If you transferred funds: contact your bank immediately")
    print()


def print_references():
    """Print the references section."""
    print_header("REFERENCES")
    refs = [
        "NIST Special Publication 800-50 - Security Awareness Training",
        "SANS Security Awareness - Phishing Training Resources",
        "OWASP - Social Engineering Attack Vectors",
        "Microsoft Digital Defense Report (2025)",
        "Anti-Phishing Working Group (APWG) - Trends Report",
        "Hoxhunt Phishing Trends Report (2026)",
        "CloudSEK - 16 Phishing Techniques to Know in 2026",
    ]
    for ref in refs:
        print(f"  {c('→', Colors.CYAN)} {ref}")
    print()


def print_verdict(indicators):
    """Print the final verdict with appropriate styling."""
    print_separator("─", 70)

    if indicators >= 5:
        verdict = "HIGH LIKELIHOOD OF PHISHING"
        style = Colors.RED + Colors.BOLD
        icon = "🚨"
    elif indicators >= 3:
        verdict = "SUSPICIOUS - VERIFY BEFORE ACTING"
        style = Colors.YELLOW + Colors.BOLD
        icon = "⚠️"
    elif indicators >= 1:
        verdict = "SOME INDICATORS FOUND - EXERCISE CAUTION"
        style = Colors.YELLOW
        icon = "⚡"
    else:
        verdict = "NO OBVIOUS INDICATORS - STILL BE CAUTIOUS"
        style = Colors.GREEN
        icon = "ℹ️"

    print(f"  {icon} {c(f'>>> VERDICT: {verdict} <<<', style)}")
    print_separator("─", 70)
    print()


# =============================================================================
# INTERACTIVE MODE
# =============================================================================

def run_interactive_mode():
    """Run the program in interactive mode."""
    print_header("PHISHING AWARENESS ANALYSIS - INTERACTIVE MODE")
    print()
    print(f"  {c('Paste a suspicious email message to analyze it.', Colors.WHITE)}")
    print(f"  {c('You can paste raw email text, full headers + body, or just the body.', Colors.DIM)}")
    print()
    print(f"  {c('How to submit:', Colors.BOLD)}")
    print(f"    {c('•', Colors.CYAN)} Type/paste your text, then type '{c('END', Colors.YELLOW + Colors.BOLD)}' on its own line.")
    print(f"    {c('•', Colors.CYAN)} Or paste a multi-line block and type '{c('END', Colors.YELLOW + Colors.BOLD)}' after it.")
    print(f"    {c('•', Colors.CYAN)} Type '{c('QUIT', Colors.YELLOW + Colors.BOLD)}' at any time to exit.")
    print()

    while True:
        print(f"  {c('Paste your email (or type QUIT to exit):', Colors.CYAN)}")
        sender_email = ""
        subject = "(pasted content)"
        body_lines = []
        in_headers = True
        found_blank_line = False

        while True:
            try:
                line = input(f"  {c('>', Colors.GREEN)} ")
            except (EOFError, KeyboardInterrupt):
                print(f"\n  {c('Goodbye!', Colors.CYAN)}")
                return
            if line.strip().upper() == "QUIT":
                print(f"  {c('Goodbye!', Colors.CYAN)}")
                return
            if line.strip().upper() == "END":
                break

            # --- Header parsing (only while we haven't seen a blank line) ---
            if in_headers:
                # Extract From: header
                if line.lower().startswith("from:"):
                    match = re.search(r"<(.+?)>", line)
                    if match:
                        sender_email = match.group(1)
                    elif "@" in line:
                        sender_email = line.split(":", 1)[1].strip()
                    continue

                # Extract Subject: header
                if line.lower().startswith("subject:"):
                    subject = line.split(":", 1)[1].strip()
                    continue

                # Blank line ends header section
                if line.strip() == "":
                    in_headers = False
                    found_blank_line = True
                    continue

                # If we get here, it's not a recognized header and not blank.
                in_headers = False
                # Fall through to body collection below

            body_lines.append(line)

        body = "\n".join(body_lines)

        if not body.strip():
            print()
            print(f"  {c('[!] No text detected. Please paste an email message.', Colors.YELLOW)}")
            print()
            continue

        print()
        print_separator()
        print(f"  {c('ANALYZING YOUR INPUT...', Colors.CYAN + Colors.BOLD)}")
        print_separator()
        print()

        # Build a PhishingEmail object from user input
        user_email = PhishingEmail(
            name="User Submitted Email",
            category="Pending Analysis",
            sender="Unknown",
            sender_email=sender_email or "unknown@unknown.com",
            subject=subject,
            body=body,
            display_url="",
            actual_url="",
            legitimate_url="",
            attack_type="Pending Analysis",
            explanation="",
        )

        # Run full analysis pipeline
        result = analyze_email(user_email)

        # Print results using the same format as sample analyses
        print_analysis(result)

        # Print overall verdict
        total_indicators = len(result.red_flags) + len(result.suspicious_keywords_found)
        print_verdict(total_indicators)


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Phishing Awareness Analysis Program",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py                  Run samples + interactive mode\n"
            "  python main.py --no-interactive Run samples only (no prompts)\n"
            "  python main.py --interactive    Run interactive mode only\n"
        ),
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Run sample analyses only, then exit (no interactive prompt).",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Skip sample analyses and go straight to interactive mode.",
    )
    return parser.parse_args()


def run_sample_analyses():
    """Run all sample phishing email analyses and print results."""
    # Print threat landscape overview
    print_header("THREAT LANDSCAPE OVERVIEW (2025-2026)")
    for line in THREAT_LANDSCAPE:
        if line:
            print(f"  {line}")
        else:
            print()
    print()

    # Run all sample analyses
    print(f"  {c('Running analysis on 5 sample phishing emails...', Colors.CYAN)}")
    print()
    results = []
    for email in SAMPLE_PHISHING_EMAILS:
        result = analyze_email(email)
        results.append(result)
        print_analysis(result)

    # Print summary statistics
    print_header("ANALYSIS SUMMARY")
    total_red_flags = sum(len(r.red_flags) for r in results)
    total_keywords = sum(len(r.suspicious_keywords_found) for r in results)
    critical = sum(1 for r in results if r.threat_level == "CRITICAL")
    high = sum(1 for r in results if r.threat_level == "HIGH")
    medium = sum(1 for r in results if r.threat_level == "MEDIUM")
    low = sum(1 for r in results if r.threat_level == "LOW")

    print(f"  {c('Emails Analyzed:', Colors.BOLD)}      {len(results)}")
    print(f"  {c('Total Red Flags:', Colors.BOLD)}      {total_red_flags}")
    print(f"  {c('Total Keywords Found:', Colors.BOLD)} {total_keywords}")
    print()
    print(f"    {c('CRITICAL:', Colors.BG_RED + Colors.WHITE + Colors.BOLD)} {critical}")
    print(f"    {c('HIGH:', Colors.RED + Colors.BOLD)}     {high}")
    print(f"    {c('MEDIUM:', Colors.YELLOW + Colors.BOLD)}   {medium}")
    print(f"    {c('LOW:', Colors.GREEN)}      {low}")
    print()

    # Print reference materials
    print_red_flags_checklist()
    print_protection_guide()
    print_references()


def main():
    """Main entry point for the phishing awareness analysis program."""
    args = parse_args()

    print()
    print(c("=" * 70, Colors.CYAN))
    print(c("       TASK 3: PHISHING AWARENESS ANALYSIS PROGRAM", Colors.CYAN + Colors.BOLD))
    print(c("=" * 70, Colors.CYAN))
    print()
    print(f"  {c('Analyze sample emails to identify phishing attempts.', Colors.WHITE)}")
    print(f"  {c('Detect suspicious links, keywords, and red flags.', Colors.WHITE)}")
    print(f"  {c('Learn why phishing messages are unsafe.', Colors.WHITE)}")
    print()

    # Run sample analyses unless --interactive was passed
    if not args.interactive:
        run_sample_analyses()

    # Enter interactive mode unless --no-interactive was passed
    if not args.no_interactive:
        print_header("INTERACTIVE ANALYSIS MODE")
        print(f"  {c('You can now analyze your own suspicious emails.', Colors.CYAN)}")
        print()
        try:
            run_interactive_mode()
        except KeyboardInterrupt:
            print(f"\n  {c('Goodbye!', Colors.CYAN)}")


if __name__ == "__main__":
    main()
