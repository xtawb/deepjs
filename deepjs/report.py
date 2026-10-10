"""deepjs.report — terminal summary, JSON, Markdown, plain lists, and report diffing."""

from __future__ import annotations

import json
import os
import sys
from typing import Dict, List, Tuple

from deepjs import __version__
from deepjs.engine import Result


class Style:
    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _w(self, code: str, s: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if self.on else s

    def bold(self, s: str) -> str: return self._w("1", s)
    def dim(self, s: str) -> str: return self._w("2", s)
    def red(self, s: str) -> str: return self._w("31", s)
    def yellow(self, s: str) -> str: return self._w("33", s)
    def green(self, s: str) -> str: return self._w("32", s)
    def cyan(self, s: str) -> str: return self._w("36", s)
    def magenta(self, s: str) -> str: return self._w("35", s)

    def severity(self, sev: str) -> str:
        label = f"{sev.upper():<8}"
        return {"critical": self.red, "high": self.red, "medium": self.yellow,
                "low": self.cyan, "info": self.dim}.get(sev, self.dim)(label)

    def method(self, m: str) -> str:
        label = f"{m or '?':<7}"
        return {"GET": self.green, "POST": self.yellow, "PUT": self.yellow, "PATCH": self.yellow,
                "DELETE": self.red}.get(m, self.dim)(label)


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if not getattr(stream, "isatty", lambda: False)() or os.environ.get("NO_COLOR"):
        return False
    return os.name != "nt" or _windows_console_takes_colour(stream)


def _windows_console_takes_colour(stream) -> bool:
    """
    An old Windows console prints escape sequences as text unless it is asked to interpret
    them. Ask; where that cannot be done, there is no colour rather than a line of `←[1m`.
    """
    try:
        import ctypes
        import msvcrt

        kernel32 = ctypes.windll.kernel32
        handle = ctypes.c_void_p(msvcrt.get_osfhandle(stream.fileno()))
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        interprets = 0x0004                 # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(mode.value & interprets) or bool(kernel32.SetConsoleMode(handle, mode.value | interprets))
    except Exception:
        return False


def _detail(ep) -> str:
    bits = []
    if ep.params:
        bits.append("query: " + ", ".join(ep.params[:8]))
    if ep.body:
        bits.append("body: " + ", ".join(ep.body[:8]))
    if ep.headers:
        bits.append("headers: " + ", ".join(ep.headers[:6]))
    return "   ".join(bits)


def terminal(result: Result, limit: int = 25, colour: bool = False, reveal: bool = False) -> str:
    st = Style(colour)
    s = result.stats
    out: List[str] = []

    def section(title: str, count: int) -> None:
        out.append("")
        out.append(st.bold(f"── {title} ({count}) " + "─" * max(4, 58 - len(title) - len(str(count)))))

    out.append(st.bold(f"DeepJS {__version__}") + st.dim(
        f"  ·  {s.get('pages', 0)} page(s), {s.get('files', 0)} script(s), {s.get('bytes', 0) / 1e6:.1f} MB, "
        f"{s.get('requests', 0)} request(s), {s.get('seconds', 0)}s"))

    secrets = [x for x in result.secrets if not x.public]
    public = [x for x in result.secrets if x.public]
    if secrets:
        section("Secrets", len(secrets))
        for x in secrets[:limit]:
            out.append(f"  {st.severity(x.severity)} {x.kind:<28} {x.value if reveal else x.masked}")
            out.append(st.dim(f"           {x.file}:{x.line}" + (f"  key: {x.key}" if x.key else "")))
            out.append(st.dim(f"           {x.note}"))
        if len(secrets) > limit:
            out.append(st.dim(f"  … {len(secrets) - limit} more in the report"))
    if public:
        section("Public-by-design keys (verify configuration, not leaks)", len(public))
        for x in public[:10]:
            out.append(f"  {st.dim('INFO    ')} {x.kind:<28} {x.masked}  {st.dim(x.note[:70])}")

    calls = [e for e in result.endpoints if e.is_call]
    strings = [e for e in result.endpoints if not e.is_call]
    if calls:
        section("API calls", len(calls))
        for e in calls[:limit]:
            out.append(f"  {st.method(e.method)} {result.full_url(e)}")
            d = _detail(e)
            if d:
                out.append(st.dim(f"           {d}"))
        if len(calls) > limit:
            out.append(st.dim(f"  … {len(calls) - limit} more in the report"))
    if strings:
        section("Other URLs / paths (seen as strings)", len(strings))
        for e in strings[:min(limit, 15)]:
            out.append(f"  {st.dim('?      ')} {e.url}")
        if len(strings) > 15:
            out.append(st.dim(f"  … {len(strings) - min(limit, 15)} more in the report"))

    if result.graphql:
        section("GraphQL operations", len(result.graphql))
        out.append("  " + ", ".join(f"{t} {n}" for t, n in result.graphql[:30]))
    if result.routes:
        section("Client routes", len(result.routes))
        out.append("  " + "  ".join(result.routes[:40]) + (st.dim("  …") if len(result.routes) > 40 else ""))

    interesting = [h for h in result.hosts if h.kind != "third-party"]
    if interesting:
        section("Hosts", len(result.hosts))
        for h in interesting[:limit]:
            tag = {"in-scope": st.green("in-scope     "), "cloud-storage": st.yellow("cloud-storage"),
                   "internal": st.red("internal     ")}[h.kind]
            extra = (" " + st.dim(h.service)) if h.service else ""
            nonprod = st.magenta("  non-production") if h.nonprod else ""
            out.append(f"  {tag} {h.name}{extra}{nonprod}")
        third = len(result.hosts) - len(interesting)
        if third:
            out.append(st.dim(f"  + {third} third-party host(s) in the report"))

    if result.sourcemaps:
        section("Source maps exposed", len(result.sourcemaps))
        for m in result.sourcemaps[:10]:
            out.append(f"  {m['url']}")
            out.append(st.dim(f"           {m['sources']} sources, {m['app_sources']} application files, "
                              f"{m['packages']} packages" + (f", {m['written']} written" if m.get("written") else "")))
    unclaimed = [n for n in result.npm if n.status == "unclaimed"]
    if unclaimed:
        section("Packages not on the public npm registry", len(unclaimed))
        for n in unclaimed[:limit]:
            out.append(f"  {st.yellow(n.name)}")
        out.append(st.dim("  Internal package names. Claim them publicly or pin the scope to your private registry."))
    if result.unvisited:
        section("Scripts referenced but not fetched", len(result.unvisited))
        for u in result.unvisited[:8]:
            out.append(st.dim(f"  {u}"))
    if result.errors:
        section("Errors", len(result.errors))
        for e in result.errors[:8]:
            out.append(st.dim(f"  {e}"))
    if not (secrets or calls or strings):
        out.append("")
        if result.errors and not result.files:
            out.append("  Nothing was analysed: the target could not be loaded (see the errors above).")
        else:
            out.append("  Nothing found. If the target is a single-page app, pass the page URL (not a script) so chunks "
                       "can be discovered.")
    out.append("")
    return "\n".join(out)


def markdown(result: Result, reveal: bool = False) -> str:
    s = result.stats
    md: List[str] = [
        "# DeepJS report", "",
        f"**Targets:** {', '.join(f'`{t}`' for t in result.targets)}  ",
        f"**Analysed:** {s.get('pages', 0)} pages, {s.get('files', 0)} scripts ({s.get('bytes', 0) / 1e6:.1f} MB) "
        f"in {s.get('seconds', 0)}s  ",
        f"**Tool:** DeepJS {__version__}", "",
        "| | |", "|---|---|",
        f"| API calls | {s.get('api_calls', 0)} |",
        f"| Other URLs / paths | {s.get('endpoints', 0) - s.get('api_calls', 0)} |",
        f"| Secrets | {s.get('secrets', 0)} |",
        f"| Public-by-design keys | {s.get('public_keys', 0)} |",
        f"| Hosts | {s.get('hosts', 0)} |",
        f"| Source maps exposed | {s.get('source_maps', 0)} ({s.get('recovered_sources', 0)} application files) |",
        f"| Packages | {s.get('packages', 0)} |", "",
    ]
    secrets = [x for x in result.secrets if not x.public]
    if secrets:
        md += ["## Secrets", "", "| Severity | Type | Value | Key | Location | Note |", "|---|---|---|---|---|---|"]
        for x in secrets:
            val = (x.value if reveal else x.masked).replace("|", "\\|")
            md.append(f"| {x.severity} | {x.kind} | `{val}` | {x.key or ''} | `{x.file}:{x.line}` | {x.note} |")
        md.append("")
    public = [x for x in result.secrets if x.public]
    if public:
        md += ["## Public-by-design keys", "", "Not leaks — but each depends on a configuration worth verifying.", "",
               "| Type | Value | Location | What to verify |", "|---|---|---|---|"]
        md += [f"| {x.kind} | `{x.masked}` | `{x.file}:{x.line}` | {x.note} |" for x in public]
        md.append("")
    calls = [e for e in result.endpoints if e.is_call]
    if calls:
        md += ["## API calls", "", "| Method | URL | Query | Body | Headers | Source |", "|---|---|---|---|---|---|"]
        for e in calls:
            md.append(f"| {e.method or '?'} | `{result.full_url(e)}` | {', '.join(e.params)} | {', '.join(e.body)} | "
                      f"{', '.join(e.headers)} | `{e.file}:{e.line}` |")
        md.append("")
    strings = [e for e in result.endpoints if not e.is_call]
    if strings:
        md += ["## Other URLs / paths", "", "Seen as strings, not at a recognised call site.", ""]
        md += [f"- `{e.url}`" for e in strings]
        md.append("")
    if result.graphql:
        md += ["## GraphQL operations", ""] + [f"- {t} `{n}`" for t, n in result.graphql] + [""]
    if result.routes:
        md += ["## Client routes", ""] + [f"- `{r}`" for r in result.routes] + [""]
    if result.hosts:
        md += ["## Hosts", "", "| Host | Class | Service | Non-production |", "|---|---|---|---|"]
        md += [f"| `{h.name}` | {h.kind} | {h.service} | {'yes' if h.nonprod else ''} |" for h in result.hosts]
        md.append("")
    if result.sourcemaps:
        md += ["## Source maps", "", "| Map | Sources | Application files | Packages |", "|---|---|---|---|"]
        md += [f"| `{m['url']}` | {m['sources']} | {m['app_sources']} | {m['packages']} |" for m in result.sourcemaps]
        md.append("")
    unclaimed = [n for n in result.npm if n.status == "unclaimed"]
    if unclaimed:
        md += ["## Packages not on the public npm registry", "",
               "Internal names. Claim them publicly or pin the scope to a private registry.", ""]
        md += [f"- `{n.name}`" for n in unclaimed] + [""]
    if result.unvisited:
        md += ["## Scripts referenced but not fetched", ""] + [f"- `{u}`" for u in result.unvisited[:200]] + [""]
    return "\n".join(md)


def write_all(result: Result, out_dir: str, reveal: bool = False) -> List[str]:
    """Write report.json, report.md, endpoints.txt, hosts.txt. Returns the paths written."""
    os.makedirs(out_dir, exist_ok=True)
    written: List[str] = []

    def put(name: str, text: str) -> None:
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", errors="replace", newline="\n") as fh:
            fh.write(text)
        written.append(path)

    put("report.json", json.dumps(result.to_dict(reveal), indent=2, ensure_ascii=False))
    put("report.md", markdown(result, reveal))
    put("endpoints.txt", "\n".join(sorted({(e.method + " " if e.method else "") + result.full_url(e)
                                           for e in result.endpoints})) + "\n")
    put("hosts.txt", "\n".join(h.name for h in result.hosts) + "\n")
    return written


# ── diff ───────────────────────────────────────────────────────────────────────

def _index(doc: dict) -> Dict[str, set]:
    return {
        "endpoints": {(e.get("method") or "?") + " " + e.get("url", "") for e in doc.get("endpoints", [])},
        "secrets": {e.get("kind", "") + " " + e.get("fingerprint", "") for e in doc.get("secrets", [])},
        "hosts": {h.get("host", "") for h in doc.get("hosts", [])},
        "routes": set(doc.get("routes", [])),
        "graphql": {g.get("type", "") + " " + g.get("name", "") for g in doc.get("graphql", [])},
        "packages": set(doc.get("packages", [])),
        "scripts": {f.get("name", "") for f in doc.get("files", []) if f.get("kind") == "script"},
    }


def diff(old: dict, new: dict) -> Dict[str, Dict[str, List[str]]]:
    """What appeared and what disappeared between two report.json documents."""
    a, b = _index(old), _index(new)
    return {k: {"added": sorted(b[k] - a[k]), "removed": sorted(a[k] - b[k])} for k in a}


def diff_text(delta: Dict[str, Dict[str, List[str]]], colour: bool = False) -> str:
    st = Style(colour)
    out: List[str] = []
    for section, change in delta.items():
        if not change["added"] and not change["removed"]:
            continue
        out.append(st.bold(f"{section}: +{len(change['added'])} / -{len(change['removed'])}"))
        out += [st.green(f"  + {x}") for x in change["added"][:200]]
        out += [st.red(f"  - {x}") for x in change["removed"][:200]]
    return "\n".join(out) if out else "No differences."
