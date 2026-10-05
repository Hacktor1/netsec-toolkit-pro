"""Output formatting utilities for NetSec Toolkit Pro."""

import logging
from typing import Dict, Any
from dataclasses import asdict

logger = logging.getLogger(__name__)


class ConsoleFormatter:
    """Formats scan output for console display with colors."""

    SEVERITY_COLORS = {
        "INFO": "\033[94m",     # Blue
        "LOW": "\033[92m",      # Green
        "MEDIUM": "\033[93m",   # Yellow
        "HIGH": "\033[91m",     # Red
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    @classmethod
    def format_seeds(cls, count: int, seed_type: str = "passwords") -> str:
        """Format seed/wordlist count output."""
        return f"🌱 Generated {count:,} {seed_type}"

    @classmethod
    def format_findings(cls, summary: Dict[str, Any]) -> str:
        """Format summary findings for console output."""
        lines = []
        lines.append(f"  🔍 Total findings: {summary.get('total_findings', 0)}")
        lines.append(f"  ⚠️  Critical: {summary.get('by_severity', {}).get('CRITICAL', 0)}")
        lines.append(f"  ⚠️  High:     {summary.get('by_severity', {}).get('HIGH', 0)}")
        lines.append(f"  ⚠️  Medium:   {summary.get('by_severity', {}).get('MEDIUM', 0)}")
        lines.append(f"  ℹ️  Low:      {summary.get('by_severity', {}).get('LOW', 0)}")
        lines.append(f"  ℹ️  Info:     {summary.get('by_severity', {}).get('INFO', 0)}")
        lines.append(f"  🎯 Risk:     {summary.get('risk_level', 'SAFE')} ({summary.get('risk_score', 0)}/100)")
        return "\n".join(lines)

    @classmethod
    def format_progress(cls, current: int, total: int, target: str = "") -> str:
        """Format progress indicator."""
        pct = (current / total * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_len - filled)
        target_str = f" [{target}]" if target else ""
        return f"\r  {bar} {pct:5.1f}% ({current}/{total}){target_str}"

    @classmethod
    def colorize_severity(cls, severity: str) -> str:
        """Wrap severity text with ANSI color codes."""
        color = cls.SEVERITY_COLORS.get(severity, "")
        return f"{color}{severity}{cls.RESET}" if color else severity


def format_json(data: Any, indent: int = 2) -> str:
    """Format data as pretty JSON."""
    import json

    if hasattr(data, '__dict__'):
        data = asdict(data) if hasattr(data, '__dataclass_fields__') else data.__dict__
    return json.dumps(data, indent=indent, default=str, ensure_ascii=False)
