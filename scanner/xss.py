from typing import List
from scanner.base import BaseScanner
from scanner.models import Finding


class XSSScanner(BaseScanner):
    name = "XSSScanner"
    category = "Cross-Site Scripting (XSS)"

    PYTHON_PATTERNS = [
        {
            "pattern": r'''Markup\s*\(.*\.format\s*\(''',
            "vulnerability": "XSS (Markup with format)",
            "severity": "high",
            "confidence": "high",
            "description": "Creating Markup from formatted strings can allow XSS if user input is included without sanitization.",
            "remediation": "Use template engines with auto-escaping enabled (e.g., Jinja2 with autoescape=True).",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''return\s+.*request\.\w+\s*[\+].*<''',
            "vulnerability": "Reflected XSS",
            "severity": "high",
            "confidence": "medium",
            "description": "Request data concatenated with HTML tags and returned directly. This is a reflected XSS vulnerability.",
            "remediation": "Use template engines with auto-escaping. Never concatenate user input directly into HTML responses.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''render_template_string\s*\(''',
            "vulnerability": "Server-Side Template Injection (SSTI)",
            "severity": "critical",
            "confidence": "high",
            "description": "render_template_string() with user input allows Server-Side Template Injection, enabling remote code execution.",
            "remediation": "Use render_template() with template files instead of render_template_string(). Never pass user input as template content.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-1336",
        },
        {
            "pattern": r'''\.send\s*\(.*request\.(args|form|data|json|values)''',
            "vulnerability": "Reflected XSS (Direct Response)",
            "severity": "high",
            "confidence": "medium",
            "description": "Sending request parameters directly in the response without sanitization enables reflected XSS.",
            "remediation": "Sanitize all user input before including it in responses. Use proper output encoding.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
    ]

    JS_PATTERNS = [
        {
            "pattern": r'''\.innerHTML\s*=''',
            "vulnerability": "DOM XSS (innerHTML)",
            "severity": "high",
            "confidence": "medium",
            "description": "Setting innerHTML with potentially unsanitized data enables DOM-based XSS attacks.",
            "remediation": "Use textContent instead of innerHTML, or sanitize HTML with DOMPurify before setting innerHTML.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''\.innerHTML\s*\+=''',
            "vulnerability": "DOM XSS (innerHTML append)",
            "severity": "high",
            "confidence": "medium",
            "description": "Appending to innerHTML can introduce XSS if the appended content contains user-controlled data.",
            "remediation": "Use DOM methods like createElement() and textContent, or sanitize with DOMPurify.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''\.outerHTML\s*=''',
            "vulnerability": "DOM XSS (outerHTML)",
            "severity": "high",
            "confidence": "medium",
            "description": "Setting outerHTML parses and executes any HTML/script content, enabling XSS if input is user-controlled.",
            "remediation": "Use DOM manipulation methods (createElement, textContent) instead of outerHTML.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''document\.write\s*\(''',
            "vulnerability": "DOM XSS (document.write)",
            "severity": "high",
            "confidence": "medium",
            "description": "document.write() can inject scripts into the page. If user input reaches this call, it enables XSS.",
            "remediation": "Replace document.write() with DOM manipulation: document.createElement() and element.textContent.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''\.insertAdjacentHTML\s*\(''',
            "vulnerability": "DOM XSS (insertAdjacentHTML)",
            "severity": "high",
            "confidence": "medium",
            "description": "insertAdjacentHTML() parses HTML and can execute scripts. User-controlled input enables XSS.",
            "remediation": "Use insertAdjacentText() or DOM manipulation methods instead of insertAdjacentHTML().",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''location\.hash''',
            "vulnerability": "DOM XSS (location.hash)",
            "severity": "medium",
            "confidence": "medium",
            "description": "location.hash is user-controlled and can be used as an XSS vector if used in HTML/DOM operations without sanitization.",
            "remediation": "Never use location.hash directly in HTML output. Sanitize with a proper HTML sanitizer library.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''location\.search''',
            "vulnerability": "DOM XSS (location.search)",
            "severity": "medium",
            "confidence": "medium",
            "description": "location.search (query string) is user-controlled. Using it in DOM operations without sanitization enables XSS.",
            "remediation": "Parse query parameters safely and sanitize before using in any HTML context.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''document\.URL''',
            "vulnerability": "DOM XSS (document.URL)",
            "severity": "medium",
            "confidence": "medium",
            "description": "document.URL is user-controlled. Using it in HTML/DOM operations without sanitization enables XSS.",
            "remediation": "Never use document.URL directly in HTML output. Validate and sanitize URL values.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''dangerouslySetInnerHTML''',
            "vulnerability": "XSS (dangerouslySetInnerHTML in React)",
            "severity": "high",
            "confidence": "medium",
            "description": "dangerouslySetInnerHTML bypasses React's XSS protection. If user input reaches this prop, it enables XSS.",
            "remediation": "Sanitize HTML content with DOMPurify before passing to dangerouslySetInnerHTML. Avoid it when possible.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''\$\(\s*['"`]#.*\$\{''',
            "vulnerability": "jQuery XSS",
            "severity": "high",
            "confidence": "medium",
            "description": "jQuery selector with template literal containing user input can lead to XSS if the input is not sanitized.",
            "remediation": "Use jQuery's text() method instead of html(). Sanitize user input before using in jQuery selectors.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''\.html\s*\(.*[\+].*(req\.|request\.|params|query)''',
            "vulnerability": "jQuery XSS (.html() with user input)",
            "severity": "high",
            "confidence": "medium",
            "description": "jQuery .html() with user-controlled input enables DOM-based XSS.",
            "remediation": "Use .text() instead of .html() when inserting user data, or sanitize with DOMPurify.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
    ]

    HTML_PATTERNS = [
        {
            "pattern": r'''<script>.*\bvar\b.*=.*<%''',
            "vulnerability": "Inline Script XSS",
            "severity": "high",
            "confidence": "medium",
            "description": "Server-side template output inside a <script> tag can enable XSS if the output is not properly encoded.",
            "remediation": "Use JSON.stringify() for embedding server data in JavaScript, and apply proper context-aware encoding.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''on\w+\s*=\s*["'][^"']*<%''',
            "vulnerability": "Event Handler XSS",
            "severity": "high",
            "confidence": "medium",
            "description": "Server-side output in an HTML event handler attribute can break out and execute arbitrary JavaScript.",
            "remediation": "Use addEventListener() in JavaScript instead of inline event handlers. Apply proper attribute encoding.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
        {
            "pattern": r'''href\s*=\s*["']\s*javascript:''',
            "vulnerability": "JavaScript Protocol XSS",
            "severity": "high",
            "confidence": "high",
            "description": "Using javascript: in href attributes allows script execution. If user input controls the href value, it enables XSS.",
            "remediation": "Never use javascript: URIs. Use proper event handlers with sanitized data instead.",
            "owasp_ref": "A03:2021 - Injection",
            "cwe_id": "CWE-79",
        },
    ]

    def scan_file(self, file_path: str, content: str, language: str) -> List[Finding]:
        if language == "py":
            return self._search_patterns(
                self.PYTHON_PATTERNS, content, file_path, language,
                "XSS Vulnerability", "high",
                "Potential Cross-Site Scripting vulnerability detected.",
                "Use auto-escaping templates and sanitize output.",
                "A03:2021 - Injection", "CWE-79",
            )
        elif language in ("js", "jsx", "ts", "tsx"):
            return self._search_patterns(
                self.JS_PATTERNS, content, file_path, language,
                "XSS Vulnerability", "high",
                "Potential DOM-based Cross-Site Scripting vulnerability detected.",
                "Use textContent, sanitize with DOMPurify, avoid dangerous DOM APIs.",
                "A03:2021 - Injection", "CWE-79",
            )
        elif language == "html":
            return self._search_patterns(
                self.HTML_PATTERNS, content, file_path, language,
                "XSS Vulnerability", "high",
                "Potential Cross-Site Scripting vulnerability in HTML template.",
                "Use context-aware output encoding and auto-escaping templates.",
                "A03:2021 - Injection", "CWE-79",
            )
        return []
