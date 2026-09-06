from typing import List
from scanner.base import BaseScanner
from scanner.models import Finding


class SensitiveDataScanner(BaseScanner):
    name = "SensitiveDataScanner"
    category = "Sensitive Data Exposure"

    PATTERNS = [
        {
            "pattern": r'''(?i)(?:print|logging\.\w+)\s*\(.*(?:password|secret|token|key|credential|ssn|credit.?card)''',
            "vulnerability": "Sensitive Data in Logs",
            "severity": "high",
            "confidence": "medium",
            "description": "Sensitive data (passwords, tokens, keys) appears to be logged or printed. Log files are often accessible to multiple people and may be stored insecurely.",
            "remediation": "Never log sensitive data. Use log sanitization filters. Mask sensitive values before logging: log(f'User {user} logged in') instead of including credentials.",
            "owasp_ref": "A04:2021 - Insecure Design",
            "cwe_id": "CWE-532",
        },
        {
            "pattern": r'''(?i)console\.log\s*\(.*(?:password|secret|token|key|credential|ssn|credit)''',
            "vulnerability": "Sensitive Data in Console Logs",
            "severity": "medium",
            "confidence": "medium",
            "description": "Sensitive data is being logged to the browser console. Console output can be accessed by browser extensions or XSS attacks.",
            "remediation": "Remove console.log statements that output sensitive data. Use a logging framework with log levels and sanitization.",
            "owasp_ref": "A04:2021 - Insecure Design",
            "cwe_id": "CWE-532",
        },
        {
            "pattern": r'''(?i)(?:TODO|FIXME|HACK|XXX|BUG)\s*:.*(?:password|secret|key|token|auth|hack|temp)''',
            "vulnerability": "Security-Related TODO/FIXME Comment",
            "severity": "info",
            "confidence": "medium",
            "description": "A TODO/FIXME comment references security-sensitive items. This may indicate unresolved security issues or temporary insecure implementations.",
            "remediation": "Address security TODOs before deployment. Remove temporary insecure implementations and replace with proper security controls.",
            "owasp_ref": "A05:2021 - Security Misconfiguration",
            "cwe_id": "CWE-546",
        },
        {
            "pattern": r'''(?i)(?:social_security|ssn| SIN)\s*[=:]\s*["']?\d{3}[-.]?\d{2}[-.]?\d{4}''',
            "vulnerability": "Social Security Number in Code",
            "severity": "critical",
            "confidence": "high",
            "description": "A Social Security Number (or similar national ID) was found in the source code. This is highly sensitive PII that must be protected.",
            "remediation": "Remove all hardcoded PII from source code. Use test data that is clearly fake (e.g., SSN: 000-00-0000). Store real PII only in secure, encrypted databases.",
            "owasp_ref": "A04:2021 - Insecure Design",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)(?:credit_card|card_number|cc_number)\s*[=:]\s*["']?\d{13,19}''',
            "vulnerability": "Credit Card Number in Code",
            "severity": "critical",
            "confidence": "high",
            "description": "A credit card number was found in the source code. Storing card numbers in code violates PCI DSS requirements.",
            "remediation": "Remove all hardcoded card numbers. Use PCI-compliant payment processors. Never store full card numbers in source code or logs.",
            "owasp_ref": "A04:2021 - Insecure Design",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)(?:ip_address|server_ip|host)\s*[=:]\s*["']?(?:\d{1,3}\.){3}\d{1,3}["']?''',
            "vulnerability": "Hardcoded IP Address",
            "severity": "low",
            "confidence": "low",
            "description": "A hardcoded IP address was found. Internal IP addresses in source code can reveal network topology to attackers.",
            "remediation": "Use environment variables or configuration files for IP addresses. Use hostnames instead of IPs where possible.",
            "owasp_ref": "A05:2021 - Security Misconfiguration",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)(?:email|mail)\s*[=:]\s*["'][^"']+@[^"']+\.[^"']+["']''',
            "vulnerability": "Hardcoded Email Address",
            "severity": "info",
            "confidence": "low",
            "description": "A hardcoded email address was found in the source code. While not critical, exposed emails can be targeted for phishing.",
            "remediation": "Use environment variables for email addresses. Use contact forms instead of exposing email addresses directly.",
            "owasp_ref": "A04:2021 - Insecure Design",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)(?:response|return).*\b(?:password|secret|token|key|ssn|credit_card)\b.*\b(?:json|send|return|render)''',
            "vulnerability": "Sensitive Data in API Response",
            "severity": "high",
            "confidence": "low",
            "description": "Sensitive data fields may be included in API responses. Over-exposing data in API responses is a common security issue.",
            "remediation": "Implement response filtering to exclude sensitive fields. Use DTOs (Data Transfer Objects) to control what data is exposed via APIs.",
            "owasp_ref": "A01:2021 - Broken Access Control",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)\.env\b|dotenv|load_dotenv''',
            "vulnerability": "Environment File Usage Detected",
            "severity": "info",
            "confidence": "low",
            "description": "The code uses .env files for configuration. While this is a good practice, ensure the .env file is in .gitignore and never committed.",
            "remediation": "Verify .env is in .gitignore. Use .env.example (without real values) as a template for required environment variables.",
            "owasp_ref": "A05:2021 - Security Misconfiguration",
            "cwe_id": "CWE-200",
        },
        {
            "pattern": r'''(?i)(?:path|file|dir|directory)\s*[=:]\s*["'](?:/etc/|/var/|/home/|/root/|C:\\|/Users/)''',
            "vulnerability": "Hardcoded File System Path",
            "severity": "low",
            "confidence": "low",
            "description": "A hardcoded absolute file system path was found. Hardcoded paths can reveal server structure and may not work across environments.",
            "remediation": "Use relative paths or environment variables for file system paths. Use os.path.join() or pathlib for cross-platform compatibility.",
            "owasp_ref": "A05:2021 - Security Misconfiguration",
            "cwe_id": "CWE-200",
        },
    ]

    def scan_file(self, file_path: str, content: str, language: str) -> List[Finding]:
        return self._search_patterns(
            self.PATTERNS, content, file_path, language,
            "Sensitive Data Exposure", "medium",
            "Potential sensitive data exposure detected.",
            "Never expose sensitive data in code, logs, or responses.",
            "A04:2021 - Insecure Design", "CWE-200",
        )
