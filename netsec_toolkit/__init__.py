"""
NetSec Toolkit Pro - A modular network security auditing toolkit.

Modules:
  - WiFi Scanner: Discover and analyze WiFi networks
  - Port Scanner: TCP/UDP port scanning with banner grabbing
  - Network Sniffer: Packet capture and analysis
  - Password Auditor: Wordlist generation and hash cracking
  - Vulnerability Detector: CVE lookup and service fingerprinting

Usage:
    netsec --help
    netsec scan-ports --target 192.168.1.1 --ports 1-1000
    netsec wifi-scan
    netsec audit --target 192.168.1.0/24

License: MIT
"""

__version__ = "2.0.0"
__author__ = "Hacktor"
__license__ = "MIT"

from .config import Config
from .core.result_store import ResultStore
from .core.reporter import ReportEngine

__all__ = ["Config", "ResultStore", "ReportEngine", "__version__"]
