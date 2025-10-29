"""Command-line interface for dns-check."""

import argparse
import sys
import json
from typing import List
from dns_check import DNSChecker, __version__


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="DNS Check - A cross-platform DNS analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "domain",
        help="Domain name to check",
    )
    
    parser.add_argument(
        "-t", "--type",
        dest="record_types",
        action="append",
        default=None,
        help="DNS record type to query (can be specified multiple times). "
             "Examples: A, AAAA, MX, TXT, NS, CNAME, SOA",
    )
    
    parser.add_argument(
        "-s", "--server",
        dest="nameservers",
        action="append",
        help="DNS server to use (can be specified multiple times)",
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Timeout for DNS queries in seconds (default: 5.0)",
    )
    
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"dns-check {__version__}",
    )
    
    args = parser.parse_args()
    
    # Default to checking A records if no type specified
    if args.record_types is None:
        args.record_types = ["A"]
    
    try:
        checker = DNSChecker(nameservers=args.nameservers, timeout=args.timeout)
        results = checker.check_multiple(args.domain, args.record_types)
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print(f"DNS Check Results for: {args.domain}")
            print("=" * 60)
            for record_type, result in results.items():
                print(f"\n{record_type} Records:")
                if result["success"]:
                    for record in result["records"]:
                        print(f"  - {record}")
                else:
                    print(f"  Error: {result['error']}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
