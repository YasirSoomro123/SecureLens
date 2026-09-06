from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class Finding:
    vulnerability: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    category: str
    file_path: str
    line_number: int
    line_content: str
    description: str
    remediation: str
    owasp_ref: str = ""
    cwe_id: str = ""

    def to_dict(self):
        return {
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "description": self.description,
            "remediation": self.remediation,
            "owasp_ref": self.owasp_ref,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    files_scanned: int
    total_lines: int
    findings: List[Finding] = field(default_factory=list)
    language_stats: dict = field(default_factory=dict)

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self):
        return sum(1 for f in self.findings if f.severity == "low")

    @property
    def info_count(self):
        return sum(1 for f in self.findings if f.severity == "info")

    @property
    def risk_score(self):
        if not self.findings:
            return 0
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        max_possible = self.files_scanned * 50
        return min(100, round((total / max(max_possible, 1)) * 100))

    @property
    def risk_level(self):
        score = self.risk_score
        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        elif score > 0:
            return "Low"
        return "Clean"

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "files_scanned": self.files_scanned,
            "total_lines": self.total_lines,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "language_stats": self.language_stats,
            "findings": [f.to_dict() for f in self.findings],
        }
