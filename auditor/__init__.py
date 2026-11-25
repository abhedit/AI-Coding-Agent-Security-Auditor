"""AI Coding Agent Security Auditor - static analysis engine."""
from .models import Finding, Rule, Severity, SourceFile
from .scanner import scan_path, scan_files, ScanResult

__version__ = "0.1.0"
__all__ = ["Finding", "Rule", "Severity", "SourceFile", "scan_path", "scan_files", "ScanResult", "__version__"]
