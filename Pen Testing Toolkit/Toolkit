#!/usr/bin/env python3
"""
PenToolkit - Modular Penetration Testing Framework
====================================================
LEGAL NOTICE: This tool is intended for authorized penetration testing, 
security research, and educational purposes ONLY. You must have explicit 
written permission from the system owner before running any module against 
any target. Unauthorized use may violate computer crime laws in your 
jurisdiction. The authors assume no liability for misuse.

Usage:
    python toolkit.py --help
    python toolkit.py portscan --target 192.168.1.1 --ports 1-1000
    python toolkit.py enumerate --target 192.168.1.1
    python toolkit.py webprobe --target http://192.168.1.1
    python toolkit.py credcheck --target 192.168.1.1 --service ssh --users users.txt --passwords passwords.txt
    python toolkit.py report --input scan_results.json --output report.html
"""

import argparse
import sys
import json
import os
from datetime import datetime

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "modules"))

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║          PenToolkit v1.0 - Modular Security Framework        ║
║   FOR AUTHORIZED USE ONLY - GET WRITTEN PERMISSION FIRST    ║
╚══════════════════════════════════════════════════════════════╝
"""

MODULES = {
    "portscan":  "modules.port_scanner",
    "enumerate": "modules.service_enumerator",
    "webprobe":  "modules.web_prober",
    "credcheck": "modules.credential_checker",
    "report":    "modules.report_generator",
}


def get_module(name):
    import importlib
    return importlib.import_module(MODULES[name])


def build_parser():
    parser = argparse.ArgumentParser(
        prog="toolkit.py",
        description="PenToolkit - Modular Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'python toolkit.py <module> --help' for module-specific options."
    )
    parser.add_argument("--version", action="version", version="PenToolkit v1.0")
    parser.add_argument("--output-dir", default="./results",
                        help="Directory to save scan results (default: ./results)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON to stdout")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--confirm", action="store_true",
                        help="Confirm you have authorization to scan the target")

    subparsers = parser.add_subparsers(dest="module", title="Modules")

    # --- Port Scanner ---
    ps = subparsers.add_parser("portscan", help="TCP/UDP port scanner")
    ps.add_argument("--target", required=True, help="Target IP or hostname")
    ps.add_argument("--ports", default="1-1024",
                    help="Port range (e.g. '1-1024', '80,443,8080', 'top100')")
    ps.add_argument("--timeout", type=float, default=1.0,
                    help="Connection timeout in seconds (default: 1.0)")
    ps.add_argument("--threads", type=int, default=100,
                    help="Number of concurrent threads (default: 100)")
    ps.add_argument("--udp", action="store_true",
                    help="Also perform UDP scan (requires root)")
    ps.add_argument("--banner", action="store_true",
                    help="Attempt banner grabbing on open ports")

    # --- Service Enumerator ---
    se = subparsers.add_parser("enumerate", help="Service version & OS detection")
    se.add_argument("--target", required=True, help="Target IP or hostname")
    se.add_argument("--ports", default=None,
                    help="Specific ports to enumerate (default: common ports)")
    se.add_argument("--timeout", type=float, default=3.0,
                    help="Probe timeout in seconds (default: 3.0)")

    # --- Web Prober ---
    wp = subparsers.add_parser("webprobe", help="Web application reconnaissance")
    wp.add_argument("--target", required=True, help="Target URL (include http/https)")
    wp.add_argument("--wordlist", default=None,
                    help="Path to directory wordlist for fuzzing")
    wp.add_argument("--headers", action="store_true",
                    help="Dump response headers and security headers analysis")
    wp.add_argument("--forms", action="store_true",
                    help="Enumerate HTML forms and input fields")
    wp.add_argument("--timeout", type=float, default=5.0,
                    help="Request timeout in seconds (default: 5.0)")
    wp.add_argument("--user-agent", default=None,
                    help="Custom User-Agent string")

    # --- Credential Checker ---
    cc = subparsers.add_parser("credcheck",
                               help="Test credential lists against services (OWN systems only)")
    cc.add_argument("--target", required=True, help="Target IP or hostname")
    cc.add_argument("--service", required=True,
                    choices=["ssh", "ftp", "http-basic", "http-form"],
                    help="Service protocol to test")
    cc.add_argument("--users", required=True,
                    help="Path to username wordlist file")
    cc.add_argument("--passwords", required=True,
                    help="Path to password wordlist file")
    cc.add_argument("--port", type=int, default=None,
                    help="Service port (uses protocol default if not set)")
    cc.add_argument("--delay", type=float, default=0.5,
                    help="Delay between attempts in seconds (default: 0.5)")
    cc.add_argument("--stop-on-success", action="store_true",
                    help="Stop after first successful credential pair")
    cc.add_argument("--login-url", default=None,
                    help="Login URL for http-form service")
    cc.add_argument("--user-field", default="username",
                    help="Form field name for username (http-form)")
    cc.add_argument("--pass-field", default="password",
                    help="Form field name for password (http-form)")
    cc.add_argument("--fail-string", default=None,
                    help="String in response body indicating login failure (http-form)")

    # --- Report Generator ---
    rg = subparsers.add_parser("report", help="Generate HTML/JSON report from scan results")
    rg.add_argument("--input", required=True,
                    help="Path to scan results JSON file or directory of JSON files")
    rg.add_argument("--output", default="report.html",
                    help="Output report filename (default: report.html)")
    rg.add_argument("--format", choices=["html", "json", "text"], default="html",
                    help="Report format (default: html)")
    rg.add_argument("--title", default="Penetration Test Report",
                    help="Report title")

    return parser


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(0)

    # Require explicit authorization confirmation for active scanning modules
    active_modules = {"portscan", "enumerate", "webprobe", "credcheck"}
    if args.module in active_modules and not args.confirm:
        print("⚠️  AUTHORIZATION REQUIRED")
        print("   You must confirm you have written authorization to test this target.")
        print("   Re-run with --confirm to proceed.\n")
        print("   Example: python toolkit.py portscan --target <ip> --confirm\n")
        sys.exit(1)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Load and run module
    try:
        mod = get_module(args.module)
        results = mod.run(args)

        # Save JSON results
        if results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = os.path.join(
                args.output_dir,
                f"{args.module}_{timestamp}.json"
            )
            with open(out_file, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n✅ Results saved to: {out_file}")

            if args.json:
                print(json.dumps(results, indent=2, default=str))

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error in module '{args.module}': {e}")
        if hasattr(args, "verbose") and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
