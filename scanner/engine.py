import os
import uuid
from datetime import datetime, timezone
from typing import List
from scanner.models import Finding, ScanResult
from scanner.base import BaseScanner
from config import Config


class ScanEngine:
    def __init__(self):
        self.scanners: List[BaseScanner] = []

    def register_scanner(self, scanner: BaseScanner):
        self.scanners.append(scanner)

    def scan_directory(self, directory_path: str) -> ScanResult:
        scan_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        all_findings: List[Finding] = []
        files_scanned = 0
        total_lines = 0
        language_stats = {}

        for root, _dirs, files in os.walk(directory_path):
            for filename in files:
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext not in Config.SCAN_EXTENSIONS:
                    continue
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, directory_path)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                if not content.strip():
                    continue

                files_scanned += 1
                lines = content.count("\n") + 1
                total_lines += lines

                lang = Config.SUPPORTED_LANGUAGES.get(ext, ext.upper())
                language_stats[lang] = language_stats.get(lang, 0) + 1

                for scanner in self.scanners:
                    findings = scanner.scan_file(rel_path, content, ext)
                    all_findings.extend(findings)

        all_findings.sort(key=lambda f: {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }.get(f.severity, 5))

        return ScanResult(
            scan_id=scan_id,
            timestamp=timestamp,
            files_scanned=files_scanned,
            total_lines=total_lines,
            findings=all_findings,
            language_stats=language_stats,
        )

    def scan_single_file(self, file_path: str, original_name: str) -> ScanResult:
        scan_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        all_findings: List[Finding] = []

        ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
        lang = Config.SUPPORTED_LANGUAGES.get(ext, ext.upper())

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            content = ""

        total_lines = content.count("\n") + 1 if content else 0

        if content.strip():
            for scanner in self.scanners:
                findings = scanner.scan_file(original_name, content, ext)
                all_findings.extend(findings)

        all_findings.sort(key=lambda f: {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }.get(f.severity, 5))

        return ScanResult(
            scan_id=scan_id,
            timestamp=timestamp,
            files_scanned=1,
            total_lines=total_lines,
            findings=all_findings,
            language_stats={lang: 1} if content.strip() else {},
        )
