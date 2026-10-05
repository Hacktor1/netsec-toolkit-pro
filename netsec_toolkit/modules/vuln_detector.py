"""
Vulnerability Detector Module for NetSec Toolkit Pro.

Performs service banner analysis, CVE lookup, and known-vulnerability checks.
"""

import logging
import re
import socket
import requests
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class KnownVulnerability:
    """A known vulnerability from the local database."""
    service: str
    version_pattern: str
    cve: str
    description: str
    severity: str


class VulnerabilityDetector:
    """Detects vulnerabilities via service fingerprinting and CVE lookup."""

    def __init__(self, cve_api: str = "https://cve.circl.lu/api", timeout: float = 10.0,
                 known_vulns_db: List[Dict] = None):
        self.cve_api = cve_api
        self.timeout = timeout
        self._known_vulns: List[KnownVulnerability] = []

        # Load known vulnerabilities from config
        if known_vulns_db:
            for item in known_vulns_db:
                self._known_vulns.append(KnownVulnerability(
                    service=item.get("service", ""),
                    version_pattern=item.get("version_pattern", ""),
                    cve=item.get("cve", ""),
                    description=item.get("description", ""),
                    severity=item.get("severity", "MEDIUM"),
                ))

    def fingerprint_service(self, host: str, port: int) -> Optional[Dict]:
        """Attempt to fingerprint a service by connecting and analyzing the banner."""
        result = {
            "host": host,
            "port": port,
            "banner": "",
            "service": "",
            "version": "",
            "server_header": "",
        }

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Determine if port is open
            if sock.connect_ex((host, port)) != 0:
                sock.close()
                return None

            # Try to get banner for various services
            if port in (21, 22, 25, 23, 110, 143, 3306, 5432, 6379):
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore")
                    result["banner"] = banner.strip()
                    result["service"] = self._identify_service(banner)
                    result["version"] = self._extract_version(banner)
                except (socket.timeout, OSError):
                    pass
            elif port in (80, 8080, 443, 8443):
                try:
                    # Send HTTP HEAD request
                    sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    response = sock.recv(4096).decode("utf-8", errors="ignore")
                    result["banner"] = response.split("\n")[0] if response else ""
                    result["server_header"] = self._extract_server_header(response)
                    result["service"] = self._identify_http_service(response)
                    result["version"] = self._extract_version(response)
                except (socket.timeout, OSError):
                    pass

            sock.close()
        except Exception as e:
            logger.debug(f"Fingerprinting {host}:{port} failed: {e}")
            return None

        return result

    def _identify_service(self, banner: str) -> str:
        """Identify service from banner text."""
        banner_lower = banner.lower()
        services = {
            "ssh": "OpenSSH" if "openssh" in banner_lower else "SSH",
            "ftp": "vsftpd" if "vsftpd" in banner_lower else "ProFTPD" if "proftpd" in banner_lower else "FTP",
            "smtp": "SMTP",
            "mysql": "MySQL",
            "postgresql": "PostgreSQL",
            "redis": "Redis",
        }
        for key, service in services.items():
            if key in banner_lower:
                return service
        return "Unknown"

    def _extract_version(self, banner: str) -> str:
        """Extract version from banner using regex."""
        # Match version patterns like x.y.z
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
        if match:
            return match.group(1)
        return ""

    def _extract_server_header(self, http_response: str) -> str:
        """Extract Server header from HTTP response."""
        match = re.search(r'Server:\s*(.+)', http_response, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _identify_http_service(self, http_response: str) -> str:
        """Identify HTTP service from response."""
        server_header = self._extract_server_header(http_response)
        if "apache" in server_header.lower():
            return "Apache"
        elif "nginx" in server_header.lower():
            return "nginx"
        elif "microsoft" in server_header.lower() or "iis" in server_header.lower():
            return "Microsoft-IIS"
        elif "lighttpd" in server_header.lower():
            return "Lighttpd"
        return "HTTP"

    def check_known_vulnerabilities(self, fingerprint: Dict) -> List[KnownVulnerability]:
        """Check a service fingerprint against the known vulnerabilities database."""
        findings = []
        version = fingerprint.get("version", "")
        service = fingerprint.get("service", "")

        if not version or not service:
            return findings

        for known in self._known_vulns:
            if known.service.lower() in service.lower() or service.lower() in known.service.lower():
                if re.search(known.version_pattern, version):
                    findings.append(known)
                    logger.warning(f"VULNERABILITY: {known.cve} on {service} {version}")

        return findings

    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """Lookup CVE details from the CIRCL API."""
        if not cve_id.startswith("CVE-"):
            return None

        url = f"{self.cve_api}/cve/{cve_id}"
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return {
                    "id": data.get("id", cve_id),
                    "summary": data.get("summary", ""),
                    "cvss": data.get("cvss", 0),
                    "cwe": data.get("cwe", ""),
                    "references": data.get("references", []),
                }
        except requests.RequestException as e:
            logger.warning(f"CVE lookup failed for {cve_id}: {e}")

        return None

    def lookup_cve_by_service(self, service: str, version: str) -> List[Dict]:
        """Look up CVEs for a service/version via the CIRCL API."""
        url = f"{self.cve_api}/search/{service}/{version}"
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    return data[:5]  # Return top 5
        except requests.RequestException as e:
            logger.warning(f"CVE bulk lookup failed for {service}/{version}: {e}")

        return []

    def comprehensive_audit(self, host: str, ports: List[int]) -> List[Dict]:
        """Run a full vulnerability audit on a host across multiple ports."""
        findings = []

        for port in ports:
            if port in (21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 5900, 6379, 8080):
                fingerprint = self.fingerprint_service(host, port)
                if fingerprint:
                    # Check known vulnerabilities
                    known_vulns = self.check_known_vulnerabilities(fingerprint)
                    for vuln in known_vulns:
                        findings.append({
                            "host": host,
                            "port": port,
                            "type": "known_vulnerability",
                            "service": fingerprint.get("service", ""),
                            "version": fingerprint.get("version", ""),
                            "cve": vuln.cve,
                            "description": vuln.description,
                            "severity": vuln.severity,
                            "banner": fingerprint.get("banner", "")[:120],
                        })

                    # Try CVE lookup if no known vulns and version exists
                    if not known_vulns and fingerprint.get("version"):
                        cve_results = self.lookup_cve_by_service(
                            fingerprint.get("service", ""),
                            fingerprint.get("version", "")
                        )
                        for cve in cve_results:
                            findings.append({
                                "host": host,
                                "port": port,
                                "type": "cve_lookup",
                                "service": fingerprint.get("service", ""),
                                "version": fingerprint.get("version", ""),
                                "cve": cve.get("id", "Unknown"),
                                "description": cve.get("summary", "")[:200],
                                "severity": "HIGH" if cve.get("cvss", 0) >= 7 else "MEDIUM",
                                "banner": fingerprint.get("banner", "")[:120],
                            })

        return findings
