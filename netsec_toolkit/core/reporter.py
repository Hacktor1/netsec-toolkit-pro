"""
Unified HTML report engine for NetSec Toolkit Pro.

Generates comprehensive HTML reports from all scan results across modules.
"""

import os
import html
import logging
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSec Toolkit Pro - Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0a; color: #e0e0e0; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            text-align: center; color: #00ff88; font-size: 2.8em; margin-bottom: 30px;
            text-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }
        .header-info {
            text-align: center; color: #888; margin-bottom: 30px; font-size: 0.95em;
        }
        .summary-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px; margin-bottom: 30px;
        }
        .stat-card {
            background: #1a1a1a; border-radius: 10px; padding: 20px;
            text-align: center; border: 1px solid #333;
        }
        .stat-card .label { font-size: 0.85em; color: #888; margin-bottom: 8px; }
        .stat-card .value { font-size: 2.2em; font-weight: bold; }
        .stat-card.total .value { color: #00ff88; }
        .stat-card.info .value { color: #00aaff; }
        .stat-card.low .value { color: #00ffaa; }
        .stat-card.medium .value { color: #ffbb33; }
        .stat-card.high .value { color: #ff8800; }
        .stat-card.critical .value { color: #ff4444; }
        .stat-card.safe .value { color: #55ff55; }
        .risk-bar-container {
            background: #1a1a1a; border-radius: 10px; padding: 15px 20px; margin-bottom: 30px;
            border: 1px solid #333;
        }
        .risk-label { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .risk-bar { height: 25px; border-radius: 12px; background: #333; overflow: hidden; }
        .risk-fill {
            height: 100%; border-radius: 12px; transition: width 0.5s;
            background: linear-gradient(90deg, #00ff88, #ffbb33, #ff8800, #ff4444);
        }
        h2 { color: #fff; margin-bottom: 15px; border-bottom: 1px solid #333; padding-bottom: 8px; }
        .finding-item {
            background: #1a1a1a; border-radius: 8px; padding: 15px; margin-bottom: 10px;
            border-left: 3px solid #333;
        }
        .finding-item.critical { border-left-color: #ff4444; }
        .finding-item.high { border-left-color: #ff8800; }
        .finding-item.medium { border-left-color: #ffbb33; }
        .finding-item.low { border-left-color: #00aaff; }
        .finding-item.info { border-left-color: #555; }
        .finding-header {
            display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;
        }
        .finding-title { font-size: 1.1em; font-weight: bold; color: #fff; }
        .finding-meta { font-size: 0.8em; color: #888; display: flex; gap: 15px; flex-wrap: wrap; }
        .finding-meta span { color: #aaa; }
        .finding-meta strong { color: #ccc; }
        .finding-details { margin-top: 8px; font-size: 0.85em; color: #aaa; }
        .finding-details pre {
            background: #0d0d0d; padding: 8px; border-radius: 4px; overflow-x: auto;
            margin-top: 5px; font-size: 0.8em;
        }
        .severity-badge {
            padding: 3px 12px; border-radius: 12px; font-size: 0.75em;
            font-weight: bold; text-transform: uppercase;
        }
        .severity-badge.CRITICAL { background: #ff4444; color: #fff; }
        .severity-badge.HIGH { background: #ff8800; color: #fff; }
        .severity-badge.MEDIUM { background: #ffbb33; color: #000; }
        .severity-badge.LOW { background: #00aaff; color: #fff; }
        .severity-badge.INFO { background: #555; color: #fff; }
        .module-badge {
            background: #333; color: #aaa; padding: 2px 8px; border-radius: 4px; font-size: 0.75em;
        }
        .no-findings { color: #00ff88; text-align: center; padding: 30px; font-size: 1.1em; }
        footer { text-align: center; margin-top: 40px; color: #555; font-size: 0.85em; }
        .legend { display: flex; gap: 20px; justify-content: center; margin-bottom: 15px; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 5px; font-size: 0.85em; color: #aaa; }
        .legend-dot { width: 12px; height: 12px; border-radius: 50%; }
        .legend-dot.total { background: #00ff88; }
        .legend-dot.critical { background: #ff4444; }
        .legend-dot.high { background: #ff8800; }
        .legend-dot.medium { background: #ffbb33; }
        .legend-dot.low { background: #00aaff; }
        .legend-dot.safe { background: #00ff00; }
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ NetSec Toolkit Pro — Audit Report</h1>
    <div class="header-info">
        Generated: {{ generated_at }} | Scan ID: {{ scan_id }}
        {% if summary.scan_start %}| Duration: {{ summary.scan_start }} to {{ summary.scan_end }}{% endif %}
    </div>

    <div class="summary-grid">
        <div class="stat-card total">
            <div class="label">Total Findings</div>
            <div class="value">{{ summary.total_findings }}</div>
        </div>
        <div class="stat-card critical">
            <div class="label">Critical</div>
            <div class="value">{{ summary.by_severity.CRITICAL }}</div>
        </div>
        <div class="stat-card high">
            <div class="label">High</div>
            <div class="value">{{ summary.by_severity.HIGH }}</div>
        </div>
        <div class="stat-card medium">
            <div class="label">Medium</div>
            <div class="value">{{ summary.by_severity.MEDIUM }}</div>
        </div>
        <div class="stat-card low">
            <div class="label">Low/Info</div>
            <div class="value">{{ summary.by_severity.LOW + summary.by_severity.INFO }}</div>
        </div>
    </div>

    <div class="risk-bar-container">
        <div class="risk-label">
            <span>Risk Score: {{ summary.risk_score }}/100 — {{ summary.risk_level }}</span>
            <span>{{ "%.0f"|format((summary.risk_score / 100) * 100) }}%</span>
        </div>
        <div class="risk-bar">
            <div class="risk-fill" style="width: {{ summary.risk_score }}%;"></div>
        </div>
    </div>

    {% if summary.by_module %}
    <h2>🔍 Findings by Module</h2>
    <div class="legend">
        {% for module, count in summary.by_module.items() %}
        <div class="legend-item"><span class="module-badge">{{ module }}</span> {{ count }} finding{% if count > 1 %}s{% endif %}</div>
        {% endfor %}
    </div>
    {% endif %}

    {% for module_name in sorted_modules %}
    {% set module_results = results_by_module[module_name] %}
    <h2>📊 {{ module_name | upper }} <span class="module-badge">{{ module_results | length }}</span></h2>
    {% if module_results | length > 0 %}
        {% for result in module_results %}
        <div class="finding-item {{ result.severity | lower }}">
            <div class="finding-header">
                <span class="finding-title">{{ result.finding }}</span>
                <span class="severity-badge {{ result.severity }}">{{ result.severity }}</span>
            </div>
            <div class="finding-meta">
                <span>🎯 Target: <strong>{{ result.target }}</strong></span>
                <span>⏰ Time: <strong>{{ result.timestamp }}</strong></span>
            </div>
            {% if result.details %}
            <div class="finding-details">
                <strong>Details:</strong>
                {% if result.details is mapping and result.details %}
                <pre>{{ result.details | tojson(indent=2) }}</pre>
                {% else %}
                {{ result.details }}
                {% endif %}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    {% else %}
        <div class="no-findings">✅ No findings from this module.</div>
    {% endif %}
    {% endfor %}

    {% if raw_data_enabled %}
    <h2>📋 Raw Data</h2>
    <div class="finding-details">
        <pre>{{ raw_json | tojson(indent=2) }}</pre>
    </div>
    {% endif %}

    <footer>
        NetSec Toolkit Pro v2.0.0 | Security Audit Report | MIT License
    </footer>
</div>
</body>
</html>"""


class ReportEngine:
    """Generates unified HTML reports from scan results."""

    def __init__(self, output_dir: str = "reports", include_raw_data: bool = True):
        self.output_dir = output_dir
        self.include_raw_data = include_raw_data
        self._template = Template(REPORT_TEMPLATE)

    def generate(self, summary: Dict[str, Any], results_by_module: Dict[str, List[Dict]],
                 all_results: List[Dict]) -> str:
        """Generate an HTML report and return the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"nst_audit_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        sorted_modules = sorted(results_by_module.keys())

        html_content = self._template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_id=scan_id,
            summary=summary,
            results_by_module=results_by_module,
            sorted_modules=sorted_modules,
            all_results=all_results,
            raw_json=all_results if self.include_raw_data else [],
            raw_data_enabled=self.include_raw_data,
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Report generated: {filepath}")
        return filepath
