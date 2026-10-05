"""
Network Sniffer Module for NetSec Toolkit Pro.

Captures and analyzes network packets using simulated data
(root access may be required for raw packet capture on real interfaces).
"""

import logging
import struct
import random
import ipaddress
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Packet:
    """Represents a captured network packet."""
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str  # TCP, UDP, ICMP, ARP
    src_port: int
    dst_port: int
    length: int
    flags: List[str]
    raw_data: str
    info: str


# Protocol numbers
PROTOCOL_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF",
}

# Common services to simulate
SUSPICIOUS_PORTS = {23, 2323, 5555, 7547, 8080, 8888, 9999, 12345, 31337, 54321}
SCAN_PORTS = list(range(1, 1024)) + [1433, 1521, 3306, 5432, 6379, 27017, 27018]

# Simulated traffic patterns
TRAFFIC_PATTERNS = [
    {"src": "192.168.1.100", "dst": "192.168.1.1", "ports": [53, 67, 68], "proto": "UDP", "type": "DNS"},
    {"src": "192.168.1.100", "dst": "172.217.16.142", "ports": [443, 80], "proto": "TCP", "type": "HTTPS"},
    {"src": "192.168.1.50", "dst": "1.1.1.1", "ports": [53], "proto": "UDP", "type": "DNS"},
    {"src": "192.168.1.100", "dst": "192.168.1.1", "ports": [5353], "proto": "UDP", "type": "mDNS"},
    {"src": "10.0.0.1", "dst": "192.168.1.100", "ports": [22, 80], "proto": "TCP", "type": "SSH/HTTP"},
]


class PacketSniffer:
    """Network packet sniffer with real and simulated modes."""

    def __init__(self, interface: str = "any", promiscuous: bool = False, max_packets: int = 100):
        self.interface = interface
        self.promiscuous = promiscuous
        self.max_packets = max_packets

    def sniff_real(self) -> List[Packet]:
        """Attempt to sniff packets using raw sockets (requires root)."""
        packets = []
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(5)

            for _ in range(self.max_packets):
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    packet = self._parse_packet(raw_data)
                    if packet:
                        packets.append(packet)
                except socket.timeout:
                    break

            sock.close()
        except PermissionError:
            logger.warning("Raw socket requires root privileges; falling back to simulated mode")
            return []
        except Exception as e:
            logger.warning(f"Raw socket capture failed: {e}")
            return []

        return packets

    def _parse_packet(self, raw_data: bytes) -> Optional[Packet]:
        """Parse raw packet bytes into a Packet object."""
        try:
            # Parse Ethernet header
            if len(raw_data) < 14:
                return None

            dest_mac, src_mac, eth_proto = struct.unpack(
                "! 6s 6s H", raw_data[:14]
            )

            # Parse IP header
            if eth_proto == 8:  # IPv4
                ip_header = raw_data[14:34]
                version = ip_header[0] >> 4
                ihl = (ip_header[0] & 0xF) * 4
                protocol = ip_header[9]
                src_ip = self._int_to_ip(struct.unpack("!I", ip_header[12:16])[0])
                dst_ip = self._int_to_ip(struct.unpack("!I", ip_header[16:20])[0])

                proto_name = PROTOCOL_MAP.get(protocol, "OTHER")
                packet_data = raw_data[14 + ihl:]

                if proto_name == "TCP":
                    src_port, dst_port = struct.unpack("! HH", packet_data[:4])
                    flags = self._parse_tcp_flags(packet_data[12:14])
                    length = len(raw_data)
                    info = f"TCP {src_port} → {dst_port}"
                elif proto_name == "UDP":
                    src_port, dst_port = struct.unpack("! HH", packet_data[:4])
                    flags = []
                    length = len(raw_data)
                    info = f"UDP {src_port} → {dst_port}"
                else:
                    src_port, dst_port = 0, 0
                    flags = []
                    length = len(raw_data)
                    info = f"{proto_name} packet"

                return Packet(
                    timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto_name,
                    src_port=src_port,
                    dst_port=dst_port,
                    length=length,
                    flags=flags,
                    raw_data=raw_data.hex()[:160],
                    info=info,
                )
        except Exception as e:
            logger.debug(f"Packet parse error: {e}")

        return None

    @staticmethod
    def _int_to_ip(ip_int: int) -> str:
        """Convert integer to IP string."""
        return ".".join(str((ip_int >> (i * 8)) & 0xFF) for i in range(4))

    @staticmethod
    def _parse_tcp_flags(flags_bytes: bytes) -> List[str]:
        """Parse TCP flags from 2-byte flags field."""
        flags = []
        flag_bits = [
            ("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
            ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20),
            ("ECE", 0x40), ("CWR", 0x80),
        ]
        value = (flags_bytes[0] << 8) | flags_bytes[1]
        for name, bit in flag_bits:
            if value & bit:
                flags.append(name)
        return flags

    def sniff_simulated(self) -> List[Packet]:
        """Generate simulated network traffic for analysis."""
        packets = []
        logger.info("Using simulated packet capture")

        for i in range(self.max_packets):
            pattern = random.choice(TRAFFIC_PATTERNS)
            proto = pattern["proto"]

            if proto == "UDP":
                protocol = "UDP"
                flags = []
                port = random.choice(pattern["ports"])
                src_port = random.randint(1024, 65535)
            else:
                protocol = "TCP"
                # Generate realistic TCP flags
                if random.random() < 0.1:
                    flags = ["SYN"]  # Connection attempt
                elif random.random() < 0.05:
                    flags = ["SYN", "ACK"]  # Response
                elif random.random() < 0.05:
                    flags = ["RST"]  # Reset
                else:
                    flags = ["ACK"]  # Normal traffic
                port = random.choice(pattern["ports"])
                src_port = random.randint(1024, 65535)

            pkt = Packet(
                timestamp=f"14:{random.randint(23, 59)}:{random.randint(0, 59):02d}.{random.randint(100, 999):03d}",
                src_ip=pattern["src"],
                dst_ip=pattern["dst"],
                protocol=protocol,
                src_port=src_port,
                dst_port=port,
                length=random.randint(40, 1500),
                flags=flags,
                raw_data=f"{random.randint(0, 255):02x}" * 40,
                info=f"{protocol} {src_port} → {port}",
            )
            packets.append(pkt)

            # Occasionally generate suspicious traffic
            if i % 20 == 0:
                suspicious_port = random.choice(list(SUSPICIOUS_PORTS))
                pkt = Packet(
                    timestamp=f"14:{random.randint(23, 59)}:{random.randint(0, 59):02d}.{random.randint(100, 999):03d}",
                    src_ip=f"192.168.{random.randint(1, 10)}.{random.randint(2, 254)}",
                    dst_ip=f"10.0.0.{random.randint(1, 254)}",
                    protocol="TCP",
                    src_port=random.randint(1024, 65535),
                    dst_port=suspicious_port,
                    length=random.randint(40, 200),
                    flags=["SYN"],
                    raw_data="00" * 40,
                    info=f"SUSPICIOUS: TCP SYN to port {suspicious_port}",
                )
                packets.append(pkt)

        return packets

    def analyze_packets(self, packets: List[Packet]) -> List[Dict[str, Any]]:
        """Analyze captured packets for suspicious patterns."""
        findings = []

        # Check for SYN scans (many SYN packets without completion)
        syn_packets = [p for p in packets if p.protocol == "TCP" and "SYN" in p.flags and "ACK" not in p.flags]
        unique_ports = set(p.dst_port for p in syn_packets)

        if len(syn_packets) > 10 and len(unique_ports) > 5:
            findings.append({
                "type": "Possible SYN Scan",
                "description": f"Detected {len(syn_packets)} SYN packets to {len(unique_ports)} unique ports — possible port scanning activity",
                "severity": "HIGH",
                "details": {
                    "scan_source": syn_packets[0].src_ip,
                    "target": syn_packets[0].dst_ip,
                    "ports_scanned": sorted(list(unique_ports))[:20],
                    "total_ports": len(unique_ports),
                },
            })

        # Check for connections to suspicious ports
        susp_packets = [p for p in packets if p.dst_port in SUSPICIOUS_PORTS]
        if susp_packets:
            findings.append({
                "type": "Suspicious Port Access",
                "description": f"Detected {len(susp_packets)} connections to commonly exploited ports",
                "severity": "MEDIUM",
                "details": {
                    "ports": list(set(p.dst_port for p in susp_packets)),
                    "sources": list(set(p.src_ip for p in susp_packets))[:5],
                },
            })

        # Check for connections to external IPs
        external_packets = [p for p in packets if not p.dst_ip.startswith(("192.168.", "10.", "172."))]
        if external_packets:
            findings.append({
                "type": "Outbound Traffic",
                "description": f"Detected {len(external_packets)} packets to external IP addresses",
                "severity": "LOW",
                "details": {
                    "external_destinations": list(set(p.dst_ip for p in external_packets))[:10],
                },
            })

        return findings

    def sniff(self) -> List[Packet]:
        """Run packet capture, using real or simulated mode."""
        if self.promiscuous:
            packets = self.sniff_real()
            if packets:
                return packets
            logger.warning("Real capture failed; falling back to simulated mode")

        return self.sniff_simulated()


# Need socket for real mode
import socket
