"""
WiFi Scanner Module for NetSec Toolkit Pro.

Discovers WiFi networks using system tools (iw/nmcli) with simulated fallback,
and analyzes them for security vulnerabilities.
"""

import subprocess
import re
import logging
import shutil
import copy
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class WiFiNetwork:
    """Represents a discovered WiFi network."""
    ssid: str
    bssid: str
    signal: int  # dBm
    frequency: float  # MHz
    encryption: str  # WPA2, WPA3, WEP, OPEN
    cipher: str
    channel: int
    timestamp: str = ""


SIMULATED_NETWORKS = [
    WiFiNetwork("HomeNetwork", "00:11:22:33:44:55", -45, 2437.0, "WPA2", "CCMP", 6, ""),
    WiFiNetwork("Free_Public_WiFi", "AA:BB:CC:DD:EE:FF", -72, 5180.0, "OPEN", "NONE", 36, ""),
    WiFiNetwork("OfficeSecure", "12:34:56:78:9A:BC", -55, 5240.0, "WPA3", "CCMP", 44, ""),
    WiFiNetwork("Legacy_Device", "DE:AD:BE:EF:CA:FE", -68, 2462.0, "WEP", "WEP", 11, ""),
    WiFiNetwork("Guest_Network", "01:23:45:67:89:AB", -78, 2412.0, "WPA2", "TKIP", 1, ""),
    WiFiNetwork("Neighbor_WiFi", "FE:DC:BA:98:76:54", -85, 5500.0, "WPA2", "CCMP", 100, ""),
]

DEFAULT_SSIDS = [
    "xfinitywifi", "attwifi", "linksys", "netgear", "tplink",
    "dlink", "asus", "wifi", "default", "home",
]


class Vulnerability:
    """Represents a detected vulnerability."""
    LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self, name, description, severity, recommendation):
        self.name = name
        self.description = description
        self.severity = severity if severity in self.LEVELS else "MEDIUM"
        self.recommendation = recommendation

    def to_dict(self):
        return {"name": self.name, "description": self.description,
                "severity": self.severity, "recommendation": self.recommendation}


class WiFiScanner:
    """WiFi network scanner with security analysis."""

    def __init__(self, interface="wlan0", use_simulated=True, signal_threshold=-70):
        self.interface = interface
        self.use_simulated = use_simulated
        self.signal_threshold = signal_threshold

    def scan(self) -> List[WiFiNetwork]:
        """Scan for WiFi networks."""
        if self.use_simulated:
            return self._scan_simulated()
        networks = self._scan_real()
        if networks:
            return networks
        logger.warning("Real scan returned no results; using simulated data")
        return self._scan_simulated()

    def _scan_real(self) -> List[WiFiNetwork]:
        """Attempt real WiFi scan via nmcli or iw."""
        networks = []
        if shutil.which("nmcli"):
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY,CHAN", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        parts = line.split(":")
                        if len(parts) >= 6:
                            networks.append(WiFiNetwork(
                                ssid=parts[0], bssid=parts[1],
                                signal=-int(parts[2]) if parts[2].isdigit() else -50,
                                frequency=float(parts[3]) * 1000,
                                encryption=self._parse_security(parts[4]),
                                cipher="CCMP" if "WPA" in parts[4] else "NONE",
                                channel=int(parts[5]) if parts[5].isdigit() else 1,
                                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            ))
                    if networks:
                        return networks
            except Exception as e:
                logger.error(f"nmcli scan failed: {e}")

        if shutil.which("iw"):
            try:
                result = subprocess.run(
                    ["iw", self.interface, "scan"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    networks = self._parse_iw_output(result.stdout)
                    if networks:
                        return networks
            except Exception as e:
                logger.error(f"iw scan failed: {e}")

        return networks

    def _parse_security(self, s):
        s = s.upper()
        for enc in ["WPA3", "WPA2", "WEP", "WPA"]:
            if enc in s:
                return enc
        return "OPEN"

    def _parse_iw_output(self, output):
        networks = []
        cells = re.split(r"Cell\s+\d+\s+-\s+Address:", output)
        for cell in cells[1:]:
            try:
                bssid = re.search(r"([0-9A-F:]{17})", cell)
                if not bssid:
                    continue
                bssid = bssid.group(1)
                ssid_m = re.search(r"SSID:\s+(.+)", cell)
                ssid = ssid_m.group(1).strip() if ssid_m else "Unknown"
                signal_m = re.search(r"signal:\s+(-?\d+\.?\d*)", cell)
                signal = int(float(signal_m.group(1))) if signal_m else -50
                channel_m = re.search(r"DS Parameter set: channel\s+(\d+)", cell)
                channel = int(channel_m.group(1)) if channel_m else 1
                freq_m = re.search(r"frequency:\s+(\d+)", cell)
                frequency = float(freq_m.group(1)) if freq_m else 2437.0
                if "Privacy" in cell:
                    if "WPA3" in cell:
                        enc, cipher = "WPA3", "CCMP"
                    elif "WPA2" in cell:
                        enc, cipher = "WPA2", "CCMP"
                    elif "WEP" in cell:
                        enc, cipher = "WEP", "WEP"
                    else:
                        enc, cipher = "WPA", "TKIP"
                else:
                    enc, cipher = "OPEN", "NONE"
                networks.append(WiFiNetwork(
                    ssid=ssid, bssid=bssid, signal=signal, frequency=frequency,
                    encryption=enc, cipher=cipher, channel=channel,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
            except Exception as e:
                logger.warning(f"Failed to parse cell: {e}")
        return networks

    def _scan_simulated(self):
        networks = copy.deepcopy(SIMULATED_NETWORKS)
        for net in networks:
            net.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return networks

    def analyze_security(self, networks: List[WiFiNetwork]) -> Dict[str, Any]:
        """Analyze networks for security vulnerabilities."""
        results = []
        SEVERITY_WEIGHTS = {"INFO": 5, "LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 50}

        for net in networks:
            vulns = []
            # WEP check
            if net.encryption == "WEP":
                vulns.append(Vulnerability("Weak Encryption (WEP)",
                    f"Network '{net.ssid}' uses WEP, trivially crackable.",
                    "CRITICAL", "Upgrade to WPA3 or WPA2 with AES."))
            elif net.encryption == "WPA":
                vulns.append(Vulnerability("Outdated Encryption (WPA)",
                    f"Network '{net.ssid}' uses legacy WPA.", "HIGH",
                    "Upgrade to WPA2/WPA3."))
            # TKIP cipher check
            if net.cipher == "TKIP":
                vulns.append(Vulnerability("Weak Cipher (TKIP)",
                    f"Network '{net.ssid}' uses TKIP cipher.", "HIGH",
                    "Switch to CCMP (AES)."))
            elif net.cipher == "WEP":
                vulns.append(Vulnerability("Weak Cipher (WEP)",
                    f"Network '{net.ssid}' uses WEP cipher.", "CRITICAL",
                    "Upgrade to AES/CCMP."))
            # Signal check
            if net.signal < self.signal_threshold:
                vulns.append(Vulnerability("Weak Signal Strength",
                    f"Network '{net.ssid}' has weak signal ({net.signal} dBm).",
                    "INFO", "Reduce transmission power."))
            # Open network
            if net.encryption == "OPEN":
                vulns.append(Vulnerability("Open Network",
                    f"Network '{net.ssid}' has no encryption.", "CRITICAL",
                    "Enable WPA3/WPA2 encryption."))
            # Default SSID
            ssid_lower = net.ssid.lower().strip()
            if any(d in ssid_lower for d in DEFAULT_SSIDS):
                vulns.append(Vulnerability("Default SSID",
                    f"SSID '{net.ssid}' matches a router default.", "MEDIUM",
                    "Rename SSID."))
            # Hidden SSID
            if not net.ssid or len(net.ssid.strip()) == 0:
                vulns.append(Vulnerability("Hidden SSID",
                    "SSID is hidden.", "LOW", "Use proper encryption instead."))

            score = min(sum(SEVERITY_WEIGHTS.get(v.severity, 10) for v in vulns), 100)
            if net.signal < -80:
                score += 5
            elif net.signal < -70:
                score += 3
            score = min(score, 100)

            if score >= 80:
                level = "CRITICAL"
            elif score >= 60:
                level = "HIGH"
            elif score >= 40:
                level = "MEDIUM"
            elif score >= 20:
                level = "LOW"
            else:
                level = "SAFE"

            results.append({
                "ssid": net.ssid,
                "bssid": net.bssid,
                "signal": net.signal,
                "frequency": net.frequency,
                "encryption": net.encryption,
                "cipher": net.cipher,
                "channel": net.channel,
                "timestamp": net.timestamp,
                "vulnerabilities": [v.to_dict() for v in vulns],
                "risk_score": score,
                "risk_level": level,
            })

        critical = sum(1 for r in results if r["risk_level"] == "CRITICAL")
        high = sum(1 for r in results if r["risk_level"] == "HIGH")
        medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
        low = sum(1 for r in results if r["risk_level"] == "LOW")
        safe = sum(1 for r in results if r["risk_level"] == "SAFE")
        total = len(results)

        return {
            "networks": results,
            "summary": {
                "total_networks": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "safe": safe,
                "risk_level": "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "SAFE",
                "risk_score": min(critical * 50 + high * 30 + medium * 20 + low * 10, 100),
            },
        }
