#!/usr/bin/env python3
"""
HSHA — HTTP Security Header Analyzer
OWASP-based checker with optional Google CSP Evaluator integration.

Usage:
    python check_headers.py response.txt
    python check_headers.py response.txt --config profiles/extended.yaml
    python check_headers.py - < response.txt
    python check_headers.py response.txt --format json
"""
import argparse
import json
import sys
from pathlib import Path

from lib.config import load_config
from lib.csp_evaluator import get_csp_engine
from lib.models import Severity
from lib.parser import parse_http_response
from lib.reporter import console, report
from lib.rules import analyze_headers


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HSHA — HTTP Security Header Analyzer — OWASP-based",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        'response_file',
        help="Raw HTTP response file (use '-' to read from stdin)",
    )
    parser.add_argument(
        '--config', '-c',
        default=None,
        metavar='FILE',
        help="YAML config for custom rules (default: config.yaml in current dir)",
    )
    parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'list'],
        default='text',
        help="text: rich output (default); json: machine-readable; list: failed header names only",
    )
    parser.add_argument(
        '--mode', '-m',
        choices=['severity', 'simple'],
        default='simple',
        help="simple: pass/fail only (default); severity: risk levels per finding",
    )
    parser.add_argument(
        '--no-nodejs-csp',
        action='store_true',
        help="Skip Google CSP Evaluator via Node.js; use built-in Python evaluator only",
    )
    args = parser.parse_args()

    # Read response
    if args.response_file == '-':
        content = sys.stdin.read()
    else:
        path = Path(args.response_file)
        if not path.exists():
            console.print(f"[red]Error: file not found: {args.response_file}[/red]")
            return 2
        content = path.read_text(encoding='utf-8', errors='replace')

    raw_headers = parse_http_response(content)
    config = load_config(args.config)
    results = analyze_headers(raw_headers, config, use_nodejs_csp=not args.no_nodejs_csp)

    if args.format == 'json':
        output = [
            {
                'header': r.canonical_name,
                'present': r.is_present,
                'value': r.value,
                'severity': r.worst_severity.name,
                'findings': [
                    {
                        'severity': f.severity.name,
                        'title': f.title,
                        'description': f.description,
                        'recommendation': f.recommendation,
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
    elif args.format == 'list':
        report(results, mode='list', csp_engine=get_csp_engine())
    else:
        report(results, mode=args.mode, csp_engine=get_csp_engine())

    worst = max(
        (f.severity for r in results for f in r.findings),
        default=Severity.OK,
    )
    # Exit code: 0 = clean or info only, 1 = at least one LOW/MEDIUM/HIGH/CRITICAL
    return 0 if worst <= Severity.INFO else 1


if __name__ == '__main__':
    sys.exit(main())
