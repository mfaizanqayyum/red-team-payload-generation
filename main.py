import argparse
import sys
import json
import time
import signal
from typing import List, Dict, Any

from colorama import init, Fore, Style
from tabulate import tabulate
import urllib.parse
import urllib3

# Suppress SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

from modules import xss, sqli, command

MODULES = {
    "xss": xss,
    "sqli": sqli,
    "command": command
}


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments with clear help messages."""
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}{Style.BRIGHT}Advanced Payload Testing Framework{Style.RESET_ALL}\n"
                    "Supports payload generation (--testing) and live testing (--live).",
        epilog="Examples:\n"
               "  python main.py --testing --module xss --type all --context all --obfuscate --encode url --double-encode --output json --file payloads.json\n"
               "  python main.py --live --host https://example.com/search.php --param q --module xss --obfuscate --encode url --output json --file results.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true", help="Perform live testing against target")
    mode.add_argument("--testing", action="store_true", help="Generate payloads only (no requests)")

    parser.add_argument("--host", metavar="URL", help="Target base URL (required for --live)")
    parser.add_argument("--param", metavar="NAME", help="Vulnerable parameter name (required for --live)")
    parser.add_argument("--module", required=True, choices=["xss", "sqli", "command"], help="Injection module to use")

    # Module-specific filters
    parser.add_argument("--type", default="all", help="Payload type/subtype (mainly for XSS)")
    parser.add_argument("--context", default="all", help="Context filter (mainly for XSS)")
    parser.add_argument("--db", default="all", help="Database type filter (mainly for SQLi)")
    parser.add_argument("--sqli-type", default="all", help="SQLi technique filter")
    parser.add_argument("--os", default="both", choices=["linux", "windows", "both"], help="OS target for command injection")
    parser.add_argument("--goal", default="all", help="Goal/purpose filter for command injection")

    # Encoding & obfuscation options
    parser.add_argument("--encode", default=None, help="Apply encoding: url, base64, html, hex, unicode")
    parser.add_argument("--double-encode", action="store_true", help="Apply encoding twice")
    parser.add_argument("--obfuscate", action="store_true", help="Apply obfuscation techniques")

    # Output control
    parser.add_argument("--output", default="cli", choices=["cli", "json", "txt", "html"], help="Output format")
    parser.add_argument("--file", metavar="PATH", help="Save output to file (json/txt/html)")

    args = parser.parse_args()

    # Validation for live mode
    if args.live and not (args.host and args.param):
        print(f"{Fore.RED}Error: --live mode requires both --host and --param.{Style.RESET_ALL}")
        sys.exit(1)

    return args


def generate_payloads(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Generate payloads using the selected module."""
    module = MODULES.get(args.module)
    if not module:
        print(f"{Fore.RED}Error: Unknown module '{args.module}'.{Style.RESET_ALL}")
        sys.exit(1)

    payloads = []

    if args.module == "xss":
        payloads = module.generate_xss_payloads(
            xss_type=args.type,
            context=args.context,
            encode_type=args.encode,
            double_encode=args.double_encode,
            obfuscate=args.obfuscate
        )
    elif args.module == "sqli":
        payloads = module.generate_sqli_payloads(
            db_type=args.db,
            sqli_type=args.sqli_type,
            encode_type=args.encode,
            double_encode=args.double_encode,
            obfuscate=args.obfuscate
        )
    elif args.module == "command":
        payloads = module.generate_command_payloads(
            os_type=args.os,
            goal=args.goal,
            encode_type=args.encode,
            double_encode=args.double_encode,
            obfuscate=args.obfuscate
        )

    if not payloads:
        print(f"{Fore.RED}No payloads generated. Check your filter parameters.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"\n{Fore.GREEN}Generated {len(payloads)} payloads for module: {args.module.upper()}{Style.RESET_ALL}")
    return payloads


def handle_testing_mode(args: argparse.Namespace, payloads: List[Dict[str, Any]]) -> None:
    """Handle --testing mode: generate and display/export payloads."""
    module = MODULES[args.module]
    export_data = module.get_payloads_for_export(payloads)

    if args.file:
        if args.output == "json":
            content = json.dumps(export_data, indent=4, ensure_ascii=False)
        elif args.output == "txt":
            content = "\n".join(
                f"Payload: {p['payload']}\nDescription: {p.get('description', '')}\n{'─' * 80}"
                for p in export_data
            )
        elif args.output == "html":
            content = "<html><body><h1>Generated Payloads – " + args.module.upper() + "</h1>"
            content += "<table border='1'><tr><th>#</th><th>Payload</th><th>Description</th></tr>"
            for i, p in enumerate(export_data, 1):
                content += f"<tr><td>{i}</td><td><pre>{p['payload']}</pre></td><td>{p.get('description','')}</td></tr>"
            content += "</table></body></html>"

        with open(args.file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"{Fore.GREEN}Payloads saved to: {args.file}{Style.RESET_ALL}")
    else:
        if args.output == "cli":
            table = [[i+1, p["payload"][:120] + "..." if len(p["payload"]) > 120 else p["payload"],
                      p.get("description", "")[:90]] for i, p in enumerate(export_data)]
            print(tabulate(table, headers=["#", "Payload", "Description"], tablefmt="grid"))
        else:
            print(f"{Fore.YELLOW}Use --file to export in json/txt/html format.{Style.RESET_ALL}")


def handle_live_mode(args: argparse.Namespace, payloads: List[Dict[str, Any]]) -> None:
    """Handle --live mode: perform actual requests and show real-time feedback."""
    print(f"\n{Fore.RED}LIVE TESTING STARTED → {args.host}?{args.param}=[PAYLOAD]{Style.RESET_ALL}")
    print(f"Testing {len(payloads)} payloads. Progress shown in real time.\n")

    module = MODULES[args.module]
    start_time = time.time()

    if args.module == "xss":
        results = module.run_live_xss(args.host, args.param, payloads)
    elif args.module == "sqli":
        results = module.run_live_sqli(args.host, args.param, payloads)
    elif args.module == "command":
        results = module.run_live_command(args.host, args.param, payloads)
    else:
        results = []

    elapsed = time.time() - start_time
    vulnerable_count = sum(1 for r in results if "Vulnerable" in r.get("status", "") or "Potential" in r.get("status", ""))

    print(f"\n{Fore.GREEN}Testing completed{Style.RESET_ALL} | "
          f"Duration: {elapsed:.1f}s | Total tested: {len(results)} | Hits: {vulnerable_count}\n")

    # Save results if requested
    if args.file:
        export_data = results if results else [{"note": "No findings", "host": args.host, "param": args.param}]
        if args.output == "json":
            content = json.dumps(export_data, indent=4, ensure_ascii=False)
        elif args.output == "txt":
            content = "\n".join(
                f"URL: {r.get('url','N/A')}\nPayload: {r.get('payload','')}\nStatus: {r.get('status','')}\nReason: {r.get('reason','N/A')}\n{'─'*80}"
                for r in export_data
            )
        elif args.output == "html":
            content = "<html><body><h1>Live Test Results – " + args.module.upper() + "</h1>"
            content += "<table border='1'><tr><th>URL</th><th>Payload</th><th>Status</th><th>Reason</th></tr>"
            for r in export_data:
                content += f"<tr><td>{r.get('url','N/A')}</td><td><pre>{r.get('payload','')}</pre></td><td>{r.get('status','')}</td><td>{r.get('reason','N/A')}</td></tr>"
            content += "</table></body></html>"

        with open(args.file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"{Fore.GREEN}Results saved to: {args.file}{Style.RESET_ALL}")

    # Show summary of findings
    if vulnerable_count > 0:
        print(f"\n{Fore.RED}Potential findings:{Style.RESET_ALL}")
        for r in results:
            if "Vulnerable" in r.get("status", "") or "Potential" in r.get("status", ""):
                print(f"  {r.get('status')} → {r.get('payload','')[:90]}...")
                print(f"     Reason: {r.get('reason','N/A')}")
                print(f"     URL:    {r.get('url','')}\n")


def graceful_shutdown(sig, frame):
    print(f"\n{Fore.RED}Interrupt received – shutting down cleanly...{Style.RESET_ALL}")
    sys.exit(0)


def main():
    # Register Ctrl+C handler
    signal.signal(signal.SIGINT, graceful_shutdown)

    args = parse_arguments()

    payloads = generate_payloads(args)

    if args.testing:
        handle_testing_mode(args, payloads)
    else:
        handle_live_mode(args, payloads)


if __name__ == "__main__":
    main()