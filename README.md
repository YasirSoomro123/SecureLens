# SecureLens - Automated Secure Code Review & Vulnerability Detector

> **Final Year Project (FYP)**  
> **Developer:** Muhammad Yasir Soomro  
> **Registration:** ARZ-2026-2LPS  

---

## Overview

SecureLens is a Static Application Security Testing (SAST) tool that automatically scans source code to identify security vulnerabilities, hardcoded secrets, injection flaws, weak cryptography, and security misconfigurations. It provides developers with detailed, actionable security reports before code goes live.

## Features

- **Multi-Language Support:** Scans Python, JavaScript, TypeScript, Java, PHP, Go, Ruby, C#, HTML, and configuration files
- **6 Vulnerability Scanners:**
  - Injection Detection (SQL, Command, Code Injection)
  - Cross-Site Scripting (XSS) Detection
  - Hardcoded Secrets & Credentials Detection
  - Weak Cryptography Detection
  - Security Misconfiguration Detection
  - Sensitive Data Exposure Detection
- **OWASP Top 10 Coverage:** Aligned with the latest OWASP Top 10 (2021) categories
- **Professional Dashboard:** Modern, responsive web interface with dark theme
- **Detailed Reports:** Severity-classified findings with code context, descriptions, and remediation steps
- **Multiple Input Methods:** Upload files or paste code directly
- **Downloadable Reports:** Generate HTML security reports

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| Analysis Engine | Regular Expressions, Pattern Matching |
| Frontend | HTML5, CSS3, JavaScript |
| Icons | Font Awesome 6 |
| Fonts | Inter, JetBrains Mono |
| Version Control | Git, GitHub |

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YasirSoomro123/SecureLens.git
   cd SecureLens
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Open in browser:**
   Navigate to `http://localhost:5000`

## Usage

### Scanning Files
1. Open the web interface at `http://localhost:5000`
2. Drag & drop code files into the upload zone, or click to browse
3. Click "Start Security Scan"
4. Review the findings in the dashboard

### Pasting Code
1. Switch to the "Paste Code" tab
2. Select the programming language
3. Paste your code into the text area
4. Click "Start Security Scan"

### Downloading Reports
1. After a scan completes, click "Download Report" to get an HTML report
2. The report includes all findings with severity, descriptions, and remediation steps

## Vulnerability Detection Categories

### 1. Injection Vulnerabilities
- SQL Injection (string formatting, f-strings, concatenation)
- OS Command Injection (os.system, os.popen, subprocess)
- Code Injection (eval, exec)
- Insecure Deserialization (pickle, yaml.load)

### 2. Cross-Site Scripting (XSS)
- DOM-based XSS (innerHTML, outerHTML, document.write)
- Reflected XSS
- Server-Side Template Injection (SSTI)
- jQuery XSS vectors

### 3. Hardcoded Secrets
- Passwords and API keys
- AWS credentials
- Private keys
- Database connection strings
- GitHub tokens, OpenAI/Stripe keys

### 4. Weak Cryptography
- MD5, SHA-1 usage
- DES, RC4, Blowfish
- ECB mode
- Insecure random number generators
- Disabled SSL verification

### 5. Security Misconfiguration
- Debug mode enabled
- Permissive CORS
- Weak secret keys
- Disabled security features
- Insecure server bindings

### 6. Sensitive Data Exposure
- Credentials in logs
- Hardcoded PII (SSN, credit cards)
- Sensitive data in API responses
- Hardcoded file paths

## Project Structure

```
ARZENS PROJECT/
├── app.py                      # Flask application (main entry point)
├── config.py                   # Configuration settings
├── requirements.txt            # Python dependencies
├── scanner/
│   ├── __init__.py             # Scanner module exports
│   ├── base.py                 # Base scanner class
│   ├── engine.py               # Scan orchestration engine
│   ├── models.py               # Data models (Finding, ScanResult)
│   ├── injection.py            # Injection vulnerability scanner
│   ├── xss.py                  # XSS vulnerability scanner
│   ├── hardcoded_secrets.py    # Hardcoded secrets scanner
│   ├── weak_crypto.py          # Weak cryptography scanner
│   ├── misconfiguration.py     # Security misconfiguration scanner
│   └── sensitive_data.py       # Sensitive data exposure scanner
├── templates/
│   ├── index.html              # Main dashboard template
│   └── report.html             # Security report template
├── static/
│   ├── css/
│   │   └── style.css           # Application styles
│   └── js/
│       └── main.js             # Frontend JavaScript
└── uploads/                    # Temporary upload directory
```

## Scope

### In-Scope
- Python and JavaScript/TypeScript code analysis
- Injection vulnerability detection
- Hardcoded credential detection
- Weak cryptography identification
- Security misconfiguration detection
- OWASP Top 10 coverage

### Out-of-Scope
- Dynamic Application Security Testing (DAST)
- Penetration testing / active exploitation
- Network security assessment
- Runtime vulnerability detection

## Timeline

| Week | Milestone |
|------|-----------|
| Week 1 | Requirements collection, security rule definition, bug targeting |
| Week 2 | Core analysis engine development |
| Week 3 | Report system and web UI implementation |
| Week 4 | Testing, bug fixes, final documentation |

## License

This project is developed as part of a Final Year Project (FYP) for academic purposes.

---

**Developed by Muhammad Yasir Soomro** | ARZ-2026-2LPS
