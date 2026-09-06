import re
from abc import ABC, abstractmethod
from typing import List
from scanner.models import Finding


class BaseScanner(ABC):
    name = "BaseScanner"
    category = "General"

    def __init__(self):
        self.findings: List[Finding] = []

    @abstractmethod
    def scan_file(self, file_path: str, content: str, language: str) -> List[Finding]:
        pass

    def _make_finding(self, vulnerability, severity, confidence, file_path,
                      line_number, line_content, description, remediation,
                      owasp_ref="", cwe_id=""):
        return Finding(
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence,
            category=self.category,
            file_path=file_path,
            line_number=line_number,
            line_content=line_content,
            description=description,
            remediation=remediation,
            owasp_ref=owasp_ref,
            cwe_id=cwe_id,
        )

    def _search_patterns(self, patterns, content, file_path, language,
                         vulnerability, severity, description, remediation,
                         owasp_ref="", cwe_id="", confidence="high"):
        results = []
        lines = content.split("\n")
        for pattern_info in patterns:
            if isinstance(pattern_info, dict):
                pattern = pattern_info["pattern"]
                pat_vuln = pattern_info.get("vulnerability", vulnerability)
                pat_desc = pattern_info.get("description", description)
                pat_remediation = pattern_info.get("remediation", remediation)
                pat_severity = pattern_info.get("severity", severity)
                pat_owasp = pattern_info.get("owasp_ref", owasp_ref)
                pat_cwe = pattern_info.get("cwe_id", cwe_id)
                pat_confidence = pattern_info.get("confidence", confidence)
            else:
                pattern = pattern_info
                pat_vuln = vulnerability
                pat_desc = description
                pat_remediation = remediation
                pat_severity = severity
                pat_owasp = owasp_ref
                pat_cwe = cwe_id
                pat_confidence = confidence

            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("/*") or stripped.startswith("*"):
                    if "password" not in pat_vuln.lower() and "secret" not in pat_vuln.lower() and "key" not in pat_vuln.lower():
                        continue
                if regex.search(line):
                    results.append(self._make_finding(
                        vulnerability=pat_vuln,
                        severity=pat_severity,
                        confidence=pat_confidence,
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line,
                        description=pat_desc,
                        remediation=pat_remediation,
                        owasp_ref=pat_owasp,
                        cwe_id=pat_cwe,
                    ))
        return results
