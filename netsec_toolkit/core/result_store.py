"""
Centralized result storage for NetSec Toolkit Pro.

Provides a shared ResultStore that modules write to and the reporter reads from.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """A single scan finding."""
    module: str
    target: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    finding: str
    details: Dict[str, Any] = None
    timestamp: str = ""


class ResultStore:
    """Central store for all scan results across modules."""

    SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self):
        self._results: List[ScanResult] = []
        self._scan_start: str = ""
        self._scan_end: str = ""

    def start_scan(self) -> None:
        self._scan_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Scan started at {self._scan_start}")

    def end_scan(self) -> None:
        self._scan_end = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"Scan ended at {self._scan_end}")

    def add(self, module: str, target: str, severity: str, finding: str,
            details: Dict[str, Any] = None) -> None:
        """Add a finding to the result store."""
        result = ScanResult(
            module=module,
            target=target,
            severity=severity if severity in self.SEVERITY_ORDER else "MEDIUM",
            finding=finding,
            details=details or {},
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self._results.append(result)
        logger.info(f"[{module}] {severity}: {finding} (target: {target})")

    def get_all(self) -> List[Dict[str, Any]]:
        """Get all results as dicts."""
        return [asdict(r) for r in self._results]

    def get_by_module(self, module: str) -> List[Dict[str, Any]]:
        """Get results filtered by module name."""
        return [asdict(r) for r in self._results if r.module == module]

    def get_by_target(self, target: str) -> List[Dict[str, Any]]:
        """Get results filtered by target."""
        return [asdict(r) for r in self._results if r.target == target]

    def get_summary(self) -> Dict[str, Any]:
        """Generate a summary of all results."""
        summary = {
            "total_findings": len(self._results),
            "by_severity": {s: 0 for s in self.SEVERITY_ORDER},
            "by_module": {},
            "scan_start": self._scan_start,
            "scan_end": self._scan_end,
            "risk_score": 0,
            "risk_level": "SAFE",
        }

        for result in self._results:
            summary["by_severity"][result.severity] = summary["by_severity"].get(result.severity, 0) + 1
            summary["by_module"][result.module] = summary["by_module"].get(result.module, 0) + 1

        # Calculate overall risk score
        weights = {"INFO": 5, "LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 50}
        score = sum(weights.get(r.severity, 0) for r in self._results)
        score = min(score, 100)

        summary["risk_score"] = score
        summary["risk_level"] = self._risk_level(score)

        return summary

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "SAFE"

    def clear(self) -> None:
        """Clear all results."""
        self._results.clear()
        self._scan_start = ""
        self._scan_end = ""
        logger.info("Result store cleared")
