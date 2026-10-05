"""
Port Scanner Module for NetSec Toolkit Pro.

Performs TCP connect scanning with banner grabbing and service detection.
"""

import socket
import concurrent.futures
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re

from ..utils.validators import resolve_target

logger = logging.getLogger(__name__)


@dataclass
class ScanPort:
    """Represents a single scanned port."""
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    protocol: str = "tcp"


# Common port to service mapping
PORT_SERVICE_MAP = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps",
    873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 9049: "oracle-uagent", 9090: "zeus-admin",
    9200: "elasticsearch", 27017: "mongodb",
}

# Banner grab patterns for known vulnerable services
VULNERABLE_BANNERS = {
    "vsftpd": {
        "pattern": r"vsftpd\s+(\S+)",
        "versions": {"2.3.4": {"cve": "CVE-2011-2523", "description": "vsftpd 2.3.4 backdoor RCE", "severity": "CRITICAL"}},
    },
    "OpenSSH": {
        "pattern": r"OpenSSH_(\S+)",
        "versions": {"7.4p1": {"cve": "CVE-2018-15473", "description": "Username enumeration", "severity": "HIGH"}},
    },
    "Apache": {
        "pattern": r"Apache/(\S+)",
        "versions": {"2.4.49": {"cve": "CVE-2021-41773", "description": "Path traversal", "severity": "CRITICAL"}},
    },
    "nginx": {
        "pattern": r"nginx/(\S+)",
        "versions": {},
    },
    "ProFTPD": {
        "pattern": r"ProFTPD\s+(\S+)",
        "versions": {"1.3.5": {"cve": "CVE-2015-3306", "description": "Mod_copyfile RCE", "severity": "HIGH"}},
    },
}


class PortScanner:
    """TCP port scanner with banner grabbing and service detection."""

    def __init__(self, timeout: float = 3.0, max_threads: int = 100, banner_grab: bool = True):
        self.timeout = timeout
        self.max_threads = max_threads
        self.banner_grab = banner_grab

    def scan_port(self, host: str, port: int, protocol: str = "tcp") -> ScanPort:
        """Scan a single port on a target host."""
        result = ScanPort(port=port, state="closed", protocol=protocol)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((host, port))

            if result_code == 0:
                result.state = "open"
                service = PORT_SERVICE_MAP.get(port, "unknown")
                result.service = service

                # Grab banner if enabled
                if self.banner_grab:
                    banner = self._grab_banner(sock, service)
                    if banner:
                        result.banner = banner.strip()

                sock.close()
            else:
                result.state = "closed"
        except socket.timeout:
            result.state = "filtered"
        except PermissionError:
            result.state = "filtered"
            logger.warning(f"Permission denied scanning port {port} on {host}")
        except OSError as e:
            logger.debug(f"Port {port} scan error: {e}")
            result.state = "closed"
        except Exception as e:
            logger.debug(f"Unexpected error on port {port}: {e}")
            result.state = "filtered"

        return result

    def _grab_banner(self, sock: socket.socket, service: str) -> str:
        """Attempt to retrieve a service banner."""
        try:
            # Some services send banner immediately (FTP, SSH, SMTP)
            if service in ("ssh", "smtp", "ftp", "pop3", "imap"):
                # Set a short timeout for banner grab
                old_timeout = sock.gettimeout()
                sock.settimeout(2.0)
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore")
                    sock.settimeout(old_timeout)
                    return banner
                except (socket.timeout, OSError):
                    pass

            # For HTTP services, send a HEAD request
            if service in ("http", "https", "http-proxy"):
                try:
                    old_timeout = sock.gettimeout()
                    sock.settimeout(2.0)
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                    response = sock.recv(2048).decode("utf-8", errors="ignore")
                    sock.settimeout(old_timeout)
                    return response.split("\n")[0] if response else ""
                except (socket.timeout, OSError):
                    pass
        except Exception as e:
            logger.debug(f"Banner grab failed: {e}")
            return ""

        return ""

    def scan_range(self, host: str, start_port: int, end_port: int) -> List[ScanPort]:
        """Scan a range of ports on a target host."""
        logger.info(f"Starting port scan on {host}:{start_port}-{end_port}")
        results = []
        ports = list(range(start_port, end_port + 1))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result.state == "open":
                        logger.info(f"  Port {port} is OPEN ({result.service})")
                        if result.banner:
                            logger.debug(f"    Banner: {result.banner[:80]}")
                    results.append(result)
                except Exception as e:
                    logger.error(f"  Port {port} scan failed: {e}")
                    results.append(ScanPort(port=port, state="error"))

        return results

    def scan_port_list(self, host: str, ports: List[int]) -> List[ScanPort]:
        """Scan a list of specific ports."""
        logger.info(f"Starting port scan on {host} (ports: {len(ports)} total)")
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, host, port): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    if result.state == "open":
                        logger.info(f"  Port {port} is OPEN ({result.service})")
                        if result.banner:
                            logger.debug(f"    Banner: {result.banner[:80]}")
                    results.append(result)
                except Exception as e:
                    logger.error(f"  Port {port} scan failed: {e}")
                    results.append(ScanPort(port=port, state="error"))

        return results

    def scan(self, target: str, port_range: str = "1-1000") -> List[ScanPort]:
        """Scan ports on a target. Parses port range string."""
        host = resolve_target(target)
        if not host:
            logger.error(f"Could not resolve target: {target}")
            return []

        # Parse port range
        if "-" in port_range:
            parts = port_range.split("-")
            start, end = int(parts[0]), int(parts[1])
            return self.scan_range(host, start, end)
        elif "," in port_range:
            ports = [int(p.strip()) for p in port_range.split(",")]
            return self.scan_port_list(host, ports)
        else:
            port = int(port_range)
            return [self.scan_port(host, port)]

    @staticmethod
    def check_vulnerable_banners(results: List[ScanPort]) -> List[Dict]:
        """Check banners for known vulnerable service versions."""
        findings = []
        for result in results:
            if not result.banner:
                continue
            for service_name, vuln_info in VULNERABLE_BANNERS.items():
                match = re.search(vuln_info["pattern"], result.banner)
                if match:
                    version = match.group(1)
                    vulns = vuln_info.get("versions", {})
                    if version in vulns:
                        vuln = vulns[version]
                        findings.append({
                            "port": result.port,
                            "service": service_name,
                            "version": version,
                            "cve": vuln["cve"],
                            "description": vuln["description"],
                            "severity": vuln["severity"],
                            "banner": result.banner[:120],
                        })
        return findings
