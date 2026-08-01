#!/usr/bin/env python3
"""
HSHA — HTTP Security Header Analyzer
Parses a raw HTTP response and evaluates its security headers.

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

from lib.config import CONTEXTS, CONTEXT_AUTHENTICATED, load_config
from lib.parser import parse_http_response
from lib.reporter import console, report, set_context_note
from lib.rules import analyze_headers


def main() -> int:
    parser = argparse.ArgumentParser(
        description="HSHA — HTTP Security Header Analyzer",
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
        help="YAML config for custom rules (default: profiles/basic.yaml)",
    )
    parser.add_argument(
        '--format', '-f',
        choices=['text', 'json', 'list'],
        default='text',
        help="text: rich output (default); json: machine-readable; list: failed header names only",
    )
    parser.add_argument(
        '--context',
        choices=list(CONTEXTS),
        default=CONTEXT_AUTHENTICATED,
        help="what the response is assumed to carry (default: authenticated). "
             "'authenticated': data belonging to a signed-in user; "
             "'public': nothing user-specific. Only affects checks whose correct "
             "value depends on it — caching",
    )
    parser.add_argument(
        '--mode', '-m',
        choices=['severity', 'simple'],
        default='simple',
        help="simple: pass/fail only (default); severity: risk levels per finding",
    )
    args = parser.parse_args()

    # Read response
    if args.response_file == '-':
        content = sys.stdin.read()
    else:
        try:
            content = Path(args.response_file).read_text(encoding='utf-8', errors='replace')
        except OSError as e:
            console.print(f"[red]Error: cannot read '{args.response_file}': {e.strerror}[/red]")
            return 2

    raw_headers = parse_http_response(content)
    try:
        config = load_config(args.config)
        config.context = args.context
        results = analyze_headers(raw_headers, config)
    except OSError as e:
        console.print(f"[red]Error: cannot read config file '{args.config}': {e.strerror}[/red]")
        return 2
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return 2

    if args.format not in ('json', 'list'):
        set_context_note(args.context)

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
                        'verify': f.verify,
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
    elif args.format == 'list':
        report(results, mode='list')
    else:
        report(results, mode=args.mode)

    # The analysis ran, so the tool did its job: 0. Findings are read from the
    # report, not from the exit status — grading a response is a judgement the
    # reader makes, not a pass/fail this program is in a position to declare.
    # A non-zero exit is reserved for not being able to produce a report at all.
    return 0


if __name__ == '__main__':
    sys.exit(main())
