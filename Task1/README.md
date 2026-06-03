# Sentinel Password Analyzer

A professional, cybersecurity-focused password analysis and generation tool with a modern SOC (Security Operations Center) dashboard interface, built with Python and CustomTkinter.

## Features

- **Advanced Entropy Calculation** — Accurately measures password strength using Shannon entropy, accounting for character pools and Unicode support.
- **Crack Time Estimation** — Provides realistic offline crack time estimates based on 100 billion guesses per second (GPU-accelerated cracking rig simulation).
- **Breach Detection** — Checks passwords against a local database of 10,000+ known leaked passwords using timing-safe comparisons (`hmac.compare_digest`) to prevent side-channel attacks.
- **Pattern Recognition** — Detects weak patterns including repeated characters (e.g., `aaaa`), sequential characters (e.g., `abcdef`, `123456`), and keyboard walks (e.g., `qwerty`, `asdfgh`).
- **Secure Generator** — Uses Python's cryptographically secure `secrets` module to generate robust passwords with customizable length (8–64) and character types.
- **Professional SOC Dashboard** — Built with CustomTkinter for a sleek, dark-mode, cyberpunk-style interface with real-time telemetry and terminal-style logs.
- **Audit Logging** — Saves analysis results locally for auditing (stores only metrics — never the actual password).
- **PDF Export** — Generates professional PDF reports of password security audits via ReportLab.

## Architecture

```
Task1/
├── app/
│   ├── __init__.py          # Module initialization
│   ├── main.py              # Entry point & app launcher
│   ├── validator.py         # Core validation engine (entropy, patterns, breach)
│   ├── entropy.py           # Shannon entropy & crack time calculations
│   ├── breach_checker.py    # Breach database lookup & weak pattern detection
│   ├── generator.py         # Secure password generation (secrets module)
│   ├── ui/
│   │   ├── __init__.py
│   │   └── main_window.py   # CustomTkinter SOC dashboard UI
│   └── utils/
│       ├── __init__.py
│       ├── exporter.py      # PDF report generation (ReportLab)
│       └── logger.py        # Audit logging to file
├── database/
│   └── common_passwords.txt # 10,000+ known breached passwords
├── tests/
│   └── test_entropy.py      # Unit tests for entropy calculations
├── audit.log                # Generated audit log (created at runtime)
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

## Getting Started

### Prerequisites

- Python 3.8 or higher

### Installation

1. Clone or download the project:
   ```bash
   git clone <repository-url>
   cd Task1
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

Launch the SOC Dashboard GUI:
```bash
python app/main.py
```

### Running Tests

```bash
python -m unittest discover -s tests -v
```

## Usage

1. **Analyze a password** — Type or paste a password into the payload input field. Metrics update in real-time: strength rating, entropy score, crack time estimate, and detailed feedback appear in the terminal log.
2. **Toggle visibility** — Click the 👁 button to reveal/hide the entered password.
3. **Generate a password** — Use the Secure Generator panel to set length (8–64) and character types, then click **GENERATE & COPY** — the password is automatically copied to your clipboard.
4. **Export a report** — Click **EXPORT PDF REPORT** to save a professional PDF audit summary.

## Security Considerations

- **Weak passwords are dangerous.** Attackers use GPU clusters to try billions of combinations per second. A low-entropy password can be cracked instantly.
- **Timing attack protection.** The breach checker uses `hmac.compare_digest()` for constant-time string comparison, preventing attackers from deducing password characters based on response timing.
- **No plaintext storage.** Passwords are never written to logs or disk. The audit log only records analysis results (strength, score, entropy, crack time), never the password itself.
- **Cryptographically secure generation.** The password generator uses `secrets.SystemRandom` and `secrets.choice` — backed by the OS's CSPRNG — for truly unpredictable output.

## Dependencies

| Package          | Version | Purpose                      |
|------------------|---------|------------------------------|
| customtkinter    | 5.2.2   | Modern UI framework          |
| reportlab        | 4.1.0   | PDF report generation        |

## Project Status

This is a demonstration project developed as part of the DecodeLabs internship program (Task 1).
