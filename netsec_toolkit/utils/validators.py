"""Input validation utilities for NetSec Toolkit Pro."""

import ipaddress
import re
import socket
import argparse
import logging

logger = logging.getLogger(__name__)


def validate_target(target: str) -> bool:
    """Validate if target is a valid IP address or hostname."""
    if not target:
        return False

    # Check if it's a CIDR network
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    # Check if it's a bare IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Check if it's a valid hostname
    hostname_pattern = r"^(?=.{1,253}$)(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]{0,61}[A-Za-z0-9])$"
    if re.match(hostname_pattern, target):
        return True

    return False


def resolve_target(target: str):
    """Resolve a hostname to an IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def validate_port_range(port_range: str) -> tuple:
    """Parse and validate a port range string like '1-1000' or '80,443,8080'."""
    result = []

    if "-" in port_range and "," not in port_range:
        try:
            parts = port_range.split("-")
            start = int(parts[0])
            end = int(parts[1])
            if 1 <= start <= 65535 and 1 <= end <= 65535:
                return start, end
        except (ValueError, IndexError):
            pass
    elif "," in port_range:
        try:
            ports = [int(p.strip()) for p in port_range.split(",") if p.strip()]
            valid = all(1 <= p <= 65535 for p in ports)
            if valid:
                return ports, len(ports)
        except ValueError:
            pass
    else:
        try:
            port = int(port_range)
            if 1 <= port <= 65535:
                return (port, port)
        except ValueError:
            pass

    raise ValueError(f"Invalid port range: {port_range}")


def validate_interface(interface: str) -> bool:
    """Check if a network interface exists."""
    try:
        result = __import__("subprocess").run(
            ["ip", "link", "show", interface],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return True  # Assume valid if we can't check


def argparse_target():
    """Return an argparse type function for target validation."""
    def _validate(value):
        if not validate_target(value):
            raise argparse.ArgumentTypeError(f"Invalid target: {value}")
        return value
    return _validate
