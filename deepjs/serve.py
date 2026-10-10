"""
deepjs.serve — a long-running analysis worker (`deepjs serve`).

This is how DeepJS plugs into other tools — the Burp Suite extension in
`burp/` is the first client. The host tool already has the traffic; the worker
never makes a network request. It reads responses on stdin, analyses them, and
writes what is *new* on stdout.

Line protocol (UTF-8, tab-separated, one message per line; `\\t`, `\\n`, `\\r`
and `\\\\` are escaped inside fields):

  host → worker
      A <id> <kind> <url> <base64 body>      analyse; kind = auto | script | html | map
      RESET                                  forget everything
      PING
      QUIT

  worker → host
      READY deepjs <version>
      E <method> <full url> <url> <kind> <query,…> <body,…> <headers,…> <file> <line> <confidence>
      W <method> <url>                       withdraw that endpoint: a better one replaces it
      S <severity> <kind> <shown value> <key> <file> <line> <note> <fingerprint> <public 0|1>
      C <script url>                         referenced by the code, not seen yet (a hidden chunk)
      M <map url> <referenced 0|1>           a source map worth fetching
      H <host> <class> <service> <nonprod 0|1>
      R <route>     G <type> <name>     B <api base>     P <package>
      X <message>                            a problem with one input (never fatal)
      D <id>                                 everything for <id> has been written
      PONG | OK

Only findings that are new (or whose details grew) since the previous message
are written, so the host can simply append.
"""

from __future__ import annotations

import base64
import re
import sys
from typing import Dict, Optional, Set, TextIO, Tuple
from urllib.parse import urlsplit

from deepjs import __version__
from deepjs.engine import Engine, Options

_ESC = {"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r"}
_ESC_RE = re.compile(r"[\\\t\n\r]")
_UNESC_RE = re.compile(r"\\([\\tnr])")
_UNESC = {"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}


def esc(value: object) -> str:
    return _ESC_RE.sub(lambda m: _ESC[m.group(0)], str(value))


def unesc(value: str) -> str:
    return _UNESC_RE.sub(lambda m: _UNESC[m.group(1)], value)


class Worker:
    def __init__(self, out: TextIO, options: Optional[Options] = None, reveal: bool = False) -> None:
        self.out = out
        self.reveal = reveal
        self._options = options or Options()
        self._new_engine()

    def _new_engine(self) -> None:
        self.engine = Engine(self._options)
        self._endpoints: Dict[Tuple[str, str], str] = {}
        self._secrets: Set[Tuple[str, str]] = set()
        self._sent: Dict[str, Set[str]] = {k: set() for k in "CMHRGBP"}

    def send(self, *fields: object) -> None:
        self.out.write("\t".join(esc(f) for f in fields) + "\n")
        self.out.flush()

    # ── protocol ──────────────────────────────────────────────────────────────

    def handle(self, line: str) -> bool:
        """Process one input line. Returns False when the worker should stop."""
        parts = line.rstrip("\r\n").split("\t")
        cmd = parts[0]
        if cmd == "A" and len(parts) >= 5:
            ident, kind, url = parts[1], parts[2], unesc(parts[3])
            try:
                body = base64.b64decode(parts[4])
                self.engine.feed(url, body, kind if kind in ("auto", "script", "html", "map") else "auto")
                self.flush_new()
            except Exception as exc:                       # one bad input must not stop the worker
                self.send("X", f"{url}: {type(exc).__name__}: {exc}"[:300])
            self.send("D", ident)
        elif cmd == "PING":
            self.send("PONG")
        elif cmd == "RESET":
            self._new_engine()
            self.send("OK")
        elif cmd == "QUIT":
            return False
        elif cmd:
            self.send("X", f"unknown command: {cmd[:40]}")
        return True

    def _full_url(self, ep) -> str:
        u = ep.url
        if u.startswith("{"):
            return self._guess_base(ep)
        if re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
            return u
        if u.startswith("//"):
            return "https:" + u
        src = urlsplit(ep.file) if ep.file.startswith(("http://", "https://")) else None
        origin = f"{src.scheme}://{src.netloc}" if src else self.engine.result.origin
        if u.startswith("/"):
            return origin + u
        bases = self.engine._bases
        base = next(iter(bases)) if len(bases) == 1 else ""
        if base:
            base = base if re.match(r"^https?://", base, re.I) else origin + base
            return base.rstrip("/") + "/" + u.lstrip("./")
        return origin + "/" + u.lstrip("./") if origin else u

    def _origin_of(self, ep) -> str:
        src = urlsplit(ep.file) if ep.file.startswith(("http://", "https://")) else None
        return f"{src.scheme}://{src.netloc}" if src else self.engine.result.origin

    def _guess_base(self, ep) -> str:
        """`{apiUrl}/users`: the one absolute API base the code names, else the script's own site."""
        u = ep.url
        end = u.find("}") + 1
        if end <= 1 or not u[end:].startswith("/"):
            return u
        bases = [b for b in self.engine._bases if re.match(r"^https?://", b, re.I)]
        guess = bases[0].rstrip("/") if len(bases) == 1 else self._origin_of(ep)
        return guess + u[end:] if guess else u

    def flush_new(self) -> None:
        eng = self.engine
        eng.resolve_bases()
        # an endpoint the engine replaced: a bare string that turned out to be a call, or a
        # `{base}/path` whose base another file has just revealed
        for key in [k for k in self._endpoints if k not in eng._endpoints]:
            del self._endpoints[key]
            self.send("W", key[0], key[1])
        for key, ep in list(eng._endpoints.items()):
            sig = "|".join((ep.kind, ",".join(ep.params), ",".join(ep.body), ",".join(ep.headers)))
            if self._endpoints.get(key) != sig:
                self._endpoints[key] = sig
                self.send("E", ep.method, self._full_url(ep), ep.url, ep.kind, ",".join(ep.params), ",".join(ep.body),
                          ",".join(ep.headers), ep.file, ep.line, f"{ep.confidence:.2f}")
        for key, s in list(eng._secrets.items()):
            if key not in self._secrets:
                self._secrets.add(key)
                self.send("S", s.severity, s.kind, s.value if self.reveal else s.masked, s.key, s.file, s.line,
                          s.note, s.fingerprint, 1 if s.public else 0)

        def once(tag: str, ident: str, *fields: object) -> None:
            if ident not in self._sent[tag]:
                self._sent[tag].add(ident)
                self.send(tag, *fields)

        for url in sorted(eng._unvisited):
            if url not in eng._seen_urls and re.match(r"^https?://", url, re.I):
                once("C", url, url)
        for url, referenced in sorted(eng.map_candidates.items()):
            once("M", url, url, 1 if referenced else 0)
        for h in list(eng.hosts.hosts.values()):
            once("H", h.name, h.name, h.kind, h.service, 1 if h.nonprod else 0)
        for route in sorted(eng._routes):
            once("R", route, route)
        for kind, name in sorted(eng._graphql):
            once("G", f"{kind} {name}", kind, name)
        for base in sorted(eng._bases):
            once("B", base, base)
        for pkg in sorted(eng._packages):
            once("P", pkg, pkg)


def serve(stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None, reveal: bool = False,
          entropy: bool = False) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for stream in (stdin, stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace", newline="\n")
        except Exception:
            pass
    worker = Worker(stdout, Options(entropy=entropy), reveal=reveal)
    worker.send("READY", "deepjs", __version__)
    for line in stdin:
        if not worker.handle(line):
            break
    return 0
