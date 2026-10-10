"""deepjs.cli — command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from deepjs import __version__
from deepjs.engine import Engine, Options
from deepjs import report

EPILOG = """\
examples:
  deepjs scan app.example.com                          crawl the site: pages, forms, robots, sitemaps, every chunk, source maps
  deepjs scan https://app.example.com/login --no-crawl just this page and its scripts
  deepjs scan https://app.example.com -o out/          also write report.json / report.md / endpoints.txt / hosts.txt
  deepjs scan dist/ bundle.js traffic.har              analyse local files, a build directory, or a HAR capture
  deepjs scan -l urls.txt --proxy http://127.0.0.1:8080   send every request through Burp / ZAP
  deepjs scan https://app.example.com --sources src/   write the original sources recovered from source maps
  deepjs scan https://app.example.com --check-npm      check bundled package names against the public npm registry
  deepjs diff old/report.json new/report.json          what changed between two scans

Only scan applications you own or are authorised to test.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deepjs",
        description="Deep static analysis of front-end JavaScript: API calls, secrets, hidden chunks, source maps.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"deepjs {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="analyse URLs, files, directories or HAR captures",
                       epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("targets", nargs="*", help="URL, file, directory or .har")
    s.add_argument("-l", "--list", metavar="FILE", help="file with one target per line")
    s.add_argument("-o", "--output", metavar="DIR", help="write report.json, report.md, endpoints.txt, hosts.txt here")
    s.add_argument("--json", action="store_true", help="print the JSON report to stdout instead of the summary")
    s.add_argument("--reveal", action="store_true", help="include full secret values (masked by default)")
    s.add_argument("--sources", metavar="DIR", help="write original sources recovered from source maps here")

    g = s.add_argument_group("discovery")
    g.add_argument("--no-crawl", action="store_true",
                   help="analyse only the given page(s); do not follow links, forms, robots.txt or sitemaps")
    g.add_argument("--max-pages", type=int, default=40, help="maximum pages to crawl (default 40)")
    g.add_argument("--crawl-depth", type=int, default=2, help="link depth to follow from each target page (default 2)")
    g.add_argument("--max-files", type=int, default=300, help="maximum scripts to fetch (default 300)")
    g.add_argument("--depth", type=int, default=4, help="how many levels of script→script references to follow (default 4)")
    g.add_argument("--no-chunks", action="store_true", help="do not follow chunks named by the bundler runtime")
    g.add_argument("--no-maps", action="store_true", help="do not fetch source maps")
    g.add_argument("--no-probe-maps", action="store_true", help="only fetch source maps a script explicitly references")
    g.add_argument("--scope", metavar="DOMAIN", action="append", default=[], help="additional in-scope domain (repeatable)")
    g.add_argument("--strict-scope", action="store_true", help="never fetch from hosts outside the target's domain")

    g = s.add_argument_group("analysis")
    g.add_argument("--check-npm", action="store_true",
                   help="ask the public npm registry whether each bundled package name exists (dependency confusion)")
    g.add_argument("--entropy", action="store_true", help="also report unlabelled random-looking strings (noisy)")

    g = s.add_argument_group("network")
    g.add_argument("-H", "--header", metavar="'Name: value'", action="append", default=[], help="extra request header (repeatable)")
    g.add_argument("--proxy", metavar="URL", help="upstream proxy, e.g. http://127.0.0.1:8080")
    g.add_argument("--user-agent", metavar="UA", help="User-Agent header (default: a current desktop Chrome)")
    g.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    g.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds (default 15)")
    g.add_argument("--threads", type=int, default=8, help="concurrent requests (default 8)")
    g.add_argument("--delay", type=float, default=0.0, help="minimum seconds between requests (default 0)")

    g = s.add_argument_group("output")
    g.add_argument("--limit", type=int, default=25, help="rows per section in the terminal summary (default 25)")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    g.add_argument("--no-color", action="store_true", help="disable coloured output")

    w = sub.add_parser("serve", help="analysis worker on stdin/stdout — used by the Burp Suite extension")
    w.add_argument("--reveal", action="store_true", help="send full secret values instead of masked ones")
    w.add_argument("--entropy", action="store_true", help="also report unlabelled random-looking strings")

    d = sub.add_parser("diff", help="compare two report.json files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true", help="print the difference as JSON")
    d.add_argument("--no-color", action="store_true")
    return p


def _headers(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items:
        name, sep, value = item.partition(":")
        if sep and name.strip():
            out[name.strip()] = value.strip()
    return out


def _targets(args) -> List[str]:
    targets = list(args.targets)
    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="replace") as fh:
            targets += [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    if not targets and not sys.stdin.isatty():
        targets += [ln.strip() for ln in sys.stdin if ln.strip()]
    return targets


def cmd_scan(args) -> int:
    targets = _targets(args)
    if not targets:
        print("deepjs: no targets. Try: deepjs scan https://app.example.com", file=sys.stderr)
        return 2
    opts = Options(
        max_files=args.max_files, depth=args.depth, threads=args.threads, timeout=args.timeout,
        delay=args.delay, headers=_headers(args.header), proxy=args.proxy, insecure=args.insecure,
        scope=args.scope, strict_scope=args.strict_scope, follow_chunks=not args.no_chunks,
        crawl=not args.no_crawl, max_pages=args.max_pages, crawl_depth=args.crawl_depth, user_agent=args.user_agent,
        source_maps=not args.no_maps, probe_maps=not args.no_probe_maps, check_npm=args.check_npm,
        entropy=args.entropy, sources_dir=args.sources,
    )
    quiet = args.quiet or args.json
    log = (lambda m: None) if quiet else (lambda m: print(f"  · {m}", file=sys.stderr))
    if not quiet:
        print("deepjs: only scan applications you own or are authorised to test.", file=sys.stderr)
    result = Engine(opts, log=log).run(targets)

    if args.json:
        print(json.dumps(result.to_dict(args.reveal), indent=2, ensure_ascii=False))
    else:
        colour = report.use_colour() and not args.no_color
        print(report.terminal(result, limit=args.limit, colour=colour, reveal=args.reveal))
    if args.output:
        for path in report.write_all(result, args.output, args.reveal):
            if not quiet:
                print(f"  wrote {path}", file=sys.stderr)
    return 0 if (result.files or not result.errors) else 1


def cmd_diff(args) -> int:
    docs = []
    for path in (args.old, args.new):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs.append(json.load(fh))
        except (OSError, ValueError) as exc:
            print(f"deepjs: cannot read {path}: {exc}", file=sys.stderr)
            return 2
    delta = report.diff(docs[0], docs[1])
    if args.json:
        print(json.dumps(delta, indent=2, ensure_ascii=False))
    else:
        print(report.diff_text(delta, colour=report.use_colour() and not args.no_color))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")       # never crash on a console that cannot encode a character
        except Exception:
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    # `deepjs https://…` is shorthand for `deepjs scan https://…`
    if argv and argv[0] not in ("scan", "diff", "serve", "-h", "--help", "--version"):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "diff":
        return cmd_diff(args)
    if args.command == "serve":
        from deepjs.serve import serve
        return serve(reveal=args.reveal, entropy=args.entropy)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
