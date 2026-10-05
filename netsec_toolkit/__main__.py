#!/usr/bin/env python3
"""
NetSec Toolkit Pro - Main CLI Entry Point.

A modular network security auditing toolkit with multiple submodules.

Usage:
    netsec --help
    netsec scan-ports --target 192.168.1.1 --ports 1-1000
    netsec wifi-scan
    netsec sniff --packets 50
    netsec crack-hash --hash <hash> --wordlist <file>
    netsec generate-wordlist --words "admin,password,test" --output list.txt
    netsec audit --target 192.168.1.1

Modules:
    scan-ports       TCP port scanner with banner grabbing
    wifi-scan        WiFi network discovery and security analysis
    sniff            Network packet capture and analysis
    crack-hash       Password hash cracker using wordlists
    generate-wordlist  Generate targeted password wordlists
    vuln-detect      Vulnerability detection via service fingerprinting
    audit            Run a comprehensive security audit on a target

License: MIT
"""

import argparse
import sys
import logging
import os
from pathlib import Path
from datetime import datetime

# Ensure package is importable
sys.path.insert(0, str(Path(__file__).parent))

from .config import Config
from .core.result_store import ResultStore
from .core.reporter import ReportEngine

# Lazy imports for modules
from .modules.port_scanner import PortScanner
from .modules.sniffer import PacketSniffer
from .modules.password_auditor import WordlistGenerator, HashCracker, generate_common_passwords
from .modules.vuln_detector import VulnerabilityDetector

# WiFi modules (optional import)
try:
    from .modules.wifi_scanner import WiFiScanner as WiFiModule
    HAS_WIFI = True
except ImportError:
    HAS_WIFI = False

logger = logging.getLogger("netsec")


def setup_logging(verbose: bool = False):
    """Configure logging for the CLI."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_scan_ports(args, config: Config, results: ResultStore):
    """Run port scanner."""
    print(f"\n📡 Port Scanner — Target: {args.target}, Ports: {args.ports}")
    print("=" * 60)

    scanner = PortScanner(
        timeout=config.get("port_scanner.timeout", 3.0),
        max_threads=config.get("port_scanner.max_threads", 100),
        banner_grab=not args.no_banner,
    )

    results.start_scan()
    scan_results = scanner.scan(args.target, args.ports)
    results.end_scan()

    open_ports = [r for r in scan_results if r.state == "open"]
    print(f"\n  📊 Results: {len(open_ports)} open ports out of {len(scan_results)} scanned")

    for port in open_ports:
        banner_info = f" | Banner: {port.banner[:60]}" if port.banner else ""
        print(f"  🟢 Port {port.port}/{port.protocol} — {port.service}{banner_info}")

        # Log to result store
        results.add(
            "port_scanner",
            f"{args.target}:{port.port}",
            "HIGH" if port.port in (22, 21) else "INFO",
            f"Open port {port.port} ({port.service})",
            {"port": port.port, "service": port.service, "banner": port.banner[:120]},
        )

    # Check for vulnerable banners
    vuln_findings = PortScanner.check_vulnerable_banners(open_ports)
    for finding in vuln_findings:
        print(f"\n  ⚠️  VULNERABILITY: {finding['cve']} on {finding['service']} {finding['version']}")
        results.add(
            "port_scanner",
            f"{args.target}:{finding['port']}",
            finding["severity"],
            f"Vulnerable service: {finding['cve']}",
            finding,
        )

    print()


def cmd_wifi_scan(args, config: Config, results: ResultStore):
    """Run WiFi scanner."""
    if not HAS_WIFI:
        print("❌ WiFi scanner module not available")
        sys.exit(1)

    print(f"\n📡 WiFi Scanner — Interface: {args.interface or 'auto'}, Simulated: {args.simulated}")
    print("=" * 60)

    scanner = WiFiModule(
        interface=args.interface or config.get("scanner.interface", "wlan0"),
        use_simulated=args.simulated,
        signal_threshold=config.get("thresholds.signal_strength", -70),
    )

    results.start_scan()
    networks = scanner.scan()
    report_data = scanner.analyze_security(networks)
    results.end_scan()

    for net in report_data["networks"]:
        vuln_count = len(net["vulnerabilities"])
        if vuln_count > 0:
            print(f"  ⚠️  {net['ssid']} — {net['encryption']} — {vuln_count} vuln(s)")
        else:
            print(f"  ✅ {net['ssid']} — {net['encryption']} — secure")

    results.add("wifi_scanner", "local", report_data["summary"]["risk_level"],
                "WiFi scan completed", {"scan_summary": report_data["summary"]})

    # Generate report
    print(f"\n📊 WiFi Scan Summary:")
    print(f"  Total networks:   {report_data['summary']['total_networks']}")
    print(f"  Critical:         {report_data['summary']['critical']}")
    print(f"  High:             {report_data['summary']['high']}")
    print(f"  Medium:           {report_data['summary']['medium']}")
    print(f"  Low:              {report_data['summary']['low']}")
    print(f"  Safe:             {report_data['summary']['safe']}")
    print(f"  Overall risk:     {report_data['summary']['risk_level']} ({report_data['summary']['risk_score']}/100)")

    # Build proper summary for report engine
    summary_for_report = {
        "total_findings": len(report_data["networks"]),
        "by_severity": {
            "INFO": report_data["summary"]["low"],  # Map low to INFO in standard format
            "LOW": report_data["summary"]["low"],
            "MEDIUM": report_data["summary"]["medium"],
            "HIGH": report_data["summary"]["high"],
            "CRITICAL": report_data["summary"]["critical"],
        },
        "risk_score": report_data["summary"]["risk_score"],
        "risk_level": report_data["summary"]["risk_level"],
        "scan_start": results._scan_start if results._scan_start else "",
        "scan_end": results._scan_end if results._scan_end else "",
    }

    report_path = config.get("report.output_dir", "reports")
    ReportEngine(output_dir=report_path).generate(
        summary_for_report,
        {"wifi_scanner": results.get_all()},
        results.get_all(),
    )
    print(f"\n📄 Report saved to: {report_path}/")
    print()


def cmd_sniff(args, config: Config, results: ResultStore):
    """Run network sniffer."""
    print(f"\n🕵️  Network Sniffer — Interface: {args.interface}, Packets: {args.packets}")
    print("=" * 60)

    sniffer = PacketSniffer(
        interface=args.interface,
        promiscuous=args.promiscuous,
        max_packets=args.packets,
    )

    results.start_scan()
    packets = sniffer.sniff()
    findings = sniffer.analyze_packets(packets)
    results.end_scan()

    print(f"\n  📊 Captured: {len(packets)} packets")
    print(f"  🔍 Found: {len(findings)} suspicious patterns")

    for f in findings:
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f["severity"], "⚪")
        print(f"  {severity_emoji} [{f['severity']}] {f['type']}")
        print(f"     {f['description']}")
        results.add("sniffer", f["type"], f["severity"], f["description"], f)

    print()


def cmd_crack_hash(args, config: Config, results: ResultStore):
    """Crack a hash using a wordlist."""
    print(f"\n🔐 Hash Cracker — Algorithm: {args.algorithm}")
    print("=" * 60)

    cracker = HashCracker()

    # Load wordlist
    if args.wordlist:
        if os.path.isfile(args.wordlist):
            with open(args.wordlist, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"  📖 Loaded wordlist: {len(wordlist)} entries")
        else:
            print(f"❌ Wordlist not found: {args.wordlist}")
            print(f"  Generating common password list instead...")
            wordlist = generate_common_passwords()
    else:
        wordlist = generate_common_passwords()
        print(f"  🔤 Using built-in common passwords: {len(wordlist)} entries")

    # Crack the hash
    results.start_scan()
    found, plaintext = cracker.crack(args.hash, wordlist)
    results.end_scan()

    if found:
        print(f"\n  ✅ CRACKED! Plaintext: '{plaintext}'")
        results.add("password_auditor", args.hash, "CRITICAL", "Hash successfully cracked",
                    {"hash": args.hash, "plaintext": plaintext, "algorithm": "auto-detected"})
    else:
        print(f"\n  ❌ Hash not cracked with provided wordlist")
        results.add("password_auditor", args.hash, "INFO", "Hash not crackable with wordlist",
                    {"hash": args.hash})

    print()


def cmd_generate_wordlist(args, config: Config, results: ResultStore):
    """Generate a targeted password wordlist."""
    print(f"\n🌱 Wordlist Generator")
    print("=" * 60)

    if args.words:
        base_words = [w.strip() for w in args.words.split(",") if w.strip()]
    else:
        base_words = ["admin", "password", "welcome", "root", "user"]

    min_len = config.get("password_auditor.min_length", 8)
    max_len = config.get("password_auditor.max_length", 16)

    generator = WordlistGenerator(min_length=min_len, max_length=max_len)
    passwords = generator.generate_from_words(base_words, variations=True)

    print(f"  📖 Base words: {base_words}")
    print(f"  🔤 Generated: {len(passwords)} password candidates")

    if args.output:
        path = generator.save_wordlist(passwords, args.output)
        print(f"  💾 Saved to: {path}")
    else:
        print(f"\n  Sample passwords:")
        for p in passwords[:20]:
            print(f"    {p}")
        if len(passwords) > 20:
            print(f"    ... and {len(passwords) - 20} more")

    results.add("password_auditor", "wordlist", "INFO",
                f"Generated {len(passwords)} password candidates",
                {"base_words": base_words, "generated_count": len(passwords)})

    print()


def cmd_vuln_detect(args, config: Config, results: ResultStore):
    """Run vulnerability detection."""
    print(f"\n🔍 Vulnerability Detector — Target: {args.target}")
    print("=" * 60)

    detector = VulnerabilityDetector(
        cve_api=config.get("vuln_detector.cve_api", "https://cve.circl.lu/api"),
        timeout=config.get("vuln_detector.timeout", 10),
        known_vulns_db=config.get("vuln_detector.known_vulns_db", []),
    )

    # Use default ports or specified
    ports = args.ports.split(",") if args.ports else ["22", "80", "443", "3306", "5432", "6379", "8080"]
    port_list = [int(p) for p in ports]

    results.start_scan()
    findings = detector.comprehensive_audit(args.target, port_list)
    results.end_scan()

    print(f"\n  🔍 Found {len(findings)} vulnerability findings:")
    for f in findings:
        print(f"  ⚠️  [{f['severity']}] {f['service']} {f['version']} on port {f['port']}")
        print(f"     {f['cve']}: {f['description'][:80]}")
        results.add("vuln_detector", f"{args.target}:{f['port']}", f["severity"],
                    f"{f['cve']} — {f['service']} {f['version']}", f)

    print()


def cmd_audit(args, config: Config, results: Config) -> ResultStore:
    """Run a comprehensive security audit."""
    print(f"\n🛡️  COMPREHENSIVE AUDIT — Target: {args.target}")
    print("=" * 60)

    report_dir = config.get("report.output_dir", "reports")
    os.makedirs(report_dir, exist_ok=True)
    all_results = ResultStore()
    all_results.start_scan()

    # 1. Port scan
    print("\n  🔹 Phase 1: Port Scanning...")
    port_scanner = PortScanner(
        timeout=config.get("port_scanner.timeout", 3.0),
        max_threads=config.get("port_scanner.max_threads", 100),
        banner_grab=True,
    )
    open_ports = []
    scan_results = port_scanner.scan(args.target, "1-1000")
    open_ports = [r for r in scan_results if r.state == "open"]

    for port in open_ports:
        all_results.add("port_scanner", f"{args.target}:{port.port}",
                        "HIGH" if port.port in (22, 21, 23) else "INFO",
                        f"Open port {port.port} ({port.service})",
                        {"port": port.port, "service": port.service, "banner": port.banner[:120]})

    # Check banners for vulnerabilities
    vuln_banners = PortScanner.check_vulnerable_banners(open_ports)
    for v in vuln_banners:
        all_results.add("port_scanner", f"{args.target}:{v['port']}", v["severity"],
                        f"Vulnerable: {v['cve']}", v)

    print(f"    Found {len(open_ports)} open ports")

    # 2. Vulnerability detection
    print("\n  🔹 Phase 2: Vulnerability Detection...")
    detector = VulnerabilityDetector(
        known_vulns_db=config.get("vuln_detector.known_vulns_db", []),
    )
    vuln_findings = detector.comprehensive_audit(args.target, [p.port for p in open_ports])
    for f in vuln_findings:
        all_results.add("vuln_detector", f"{args.target}:{f['port']}",
                        f["severity"], f["cve"], f)

    print(f"    Found {len(vuln_findings)} vulnerabilities")

    # 3. Packet sniff (simulated for target)
    print("\n  🔹 Phase 3: Traffic Analysis...")
    sniffer = PacketSniffer(max_packets=50)
    packets = sniffer.sniff_simulated()
    suspicious = sniffer.analyze_packets(packets)
    for s in suspicious:
        all_results.add("sniffer", s["type"], s["severity"], s["description"], s)

    print(f"    Analyzed {len(packets)} packets, {len(suspicious)} findings")

    all_results.end_scan()

    # 4. Generate report
    print("\n  🔹 Phase 4: Report Generation...")
    summary = all_results.get_summary()
    results_by_module = {}
    for mod in ["port_scanner", "vuln_detector", "sniffer", "wifi_scanner", "password_auditor"]:
        mod_results = all_results.get_by_module(mod)
        if mod_results:
            results_by_module[mod] = mod_results

    report_engine = ReportEngine(
        output_dir=report_dir,
        include_raw_data=config.get("report.include_raw_data", True),
    )
    report_path = report_engine.generate(summary, results_by_module, all_results.get_all())

    print(f"\n  📄 Report saved to: {report_path}")
    print(f"\n{'=' * 60}")
    print(f"  Audit Summary:")
    print(f"  Total findings:    {summary['total_findings']}")
    print(f"  Risk score:        {summary['risk_score']}/100 ({summary['risk_level']})")
    print(f"  Critical:          {summary['by_severity']['CRITICAL']}")
    print(f"  High:              {summary['by_severity']['HIGH']}")
    print(f"  Medium:            {summary['by_severity']['MEDIUM']}")
    print(f"  Low/Info:          {summary['by_severity']['LOW'] + summary['by_severity']['INFO']}")
    print(f"{'=' * 60}\n")

    return all_results


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="netsec",
        description="NetSec Toolkit Pro — A modular network security auditing toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  scan-ports        TCP port scanner with banner grabbing
  wifi-scan         WiFi network discovery and security analysis
  sniff             Network packet capture and analysis
  crack-hash        Password hash cracker using wordlists
  generate-wordlist Generate targeted password wordlists
  vuln-detect       Vulnerability detection via service fingerprinting
  audit             Run comprehensive security audit on a target

Examples:
  netsec scan-ports --target 192.168.1.1 --ports 1-1000
  netsec sniff --packets 50 --promiscuous
  netsec crack-hash --hash 5f4dcc3b5aa765d61d8327deb882cf99 --algorithm md5
  netsec generate-wordlist --words "admin,password,root" --output mylist.txt
  netsec audit --target 192.168.1.1

        """,
    )
    parser.add_argument("--config", "-c", default=None, help="Path to config YAML file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version="netsec 2.0.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan-ports
    p_sp = subparsers.add_parser("scan-ports", help="TCP port scanner with banner grabbing")
    p_sp.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    p_sp.add_argument("--ports", "-p", default="1-1000", help="Port range or list (e.g. 1-1000 or 22,80,443)")
    p_sp.add_argument("--no-banner", action="store_true", help="Disable banner grabbing")
    p_sp.set_defaults(func=cmd_scan_ports)

    # wifi-scan
    if HAS_WIFI:
        p_wifi = subparsers.add_parser("wifi-scan", help="WiFi network discovery and security analysis")
        p_wifi.add_argument("--interface", "-i", default=None, help="WiFi interface (default: wlan0)")
        p_wifi.add_argument("--simulated", action="store_true", default=True, help="Use simulated data")
        p_wifi.set_defaults(func=cmd_wifi_scan)

    # sniff
    p_sn = subparsers.add_parser("sniff", help="Network packet capture and analysis")
    p_sn.add_argument("--interface", "-i", default="any", help="Network interface (default: any)")
    p_sn.add_argument("--packets", "-n", type=int, default=100, help="Number of packets to capture")
    p_sn.add_argument("--promiscuous", action="store_true", help="Use real promiscuous mode (requires root)")
    p_sn.set_defaults(func=cmd_sniff)

    # crack-hash
    p_crack = subparsers.add_parser("crack-hash", help="Password hash cracker")
    p_crack.add_argument("--hash", required=True, help="Hash to crack")
    p_crack.add_argument("--wordlist", "-w", default=None, help="Wordlist file (default: built-in common passwords)")
    p_crack.add_argument("--algorithm", "-a", choices=["md5", "sha1", "sha256", "auto"], default="auto",
                         help="Hash algorithm (default: auto-detect)")
    p_crack.set_defaults(func=cmd_crack_hash)

    # generate-wordlist
    p_gw = subparsers.add_parser("generate-wordlist", help="Generate targeted password wordlists")
    p_gw.add_argument("--words", "-w", default=None, help="Comma-separated base words")
    p_gw.add_argument("--output", "-o", default=None, help="Output file path")
    p_gw.set_defaults(func=cmd_generate_wordlist)

    # vuln-detect
    p_vd = subparsers.add_parser("vuln-detect", help="Vulnerability detection")
    p_vd.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    p_vd.add_argument("--ports", "-p", default=None, help="Comma-separated ports to check")
    p_vd.set_defaults(func=cmd_vuln_detect)

    # audit
    p_audit = subparsers.add_parser("audit", help="Run comprehensive security audit")
    p_audit.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main():
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    setup_logging(args.verbose)

    config = Config(args.config)
    results = ResultStore()

    try:
        args.func(args, config, results)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Command failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
