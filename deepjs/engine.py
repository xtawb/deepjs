"""
deepjs.engine — orchestration.

    targets ──► collect scripts ──► tokenize ──► endpoints · secrets · hosts
                    ▲                   │
                    │                   ├──► chunk discovery ──► more scripts
                    └───────────────────┘
                                        └──► source maps ──► recovered sources ──► same analysis
                                                                └──► package list ──► npm check (opt-in)

Targets can be URLs (pages or scripts), local files / directories, or HAR files.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from deepjs import __version__
from deepjs import chunks as chunks_mod
from deepjs import sourcemap as sm
from deepjs.endpoints import Endpoint, extract
from deepjs.fetch import Fetcher, Response
from deepjs.hosts import Host, HostCollector, registrable
from deepjs.jseval import Program, is_static, render
from deepjs.lexer import K, STR, TPL, V
from deepjs.npmcheck import PackageStatus, check_packages
from deepjs.secrets import SEVERITIES, Secret, scan_program

MAX_ANALYSE_BYTES = 30 * 1024 * 1024
LOCAL_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".map", ".har")
SKIP_DIRS = {"node_modules", ".git", ".svn", ".hg", "__pycache__", ".venv", "venv"}

# Third-party script hosts that are never the application's own code.
_VENDOR_HOSTS = re.compile(
    r"(?:^|\.)(?:google-analytics\.com|googletagmanager\.com|googlesyndication\.com|doubleclick\.net|gstatic\.com"
    r"|googleapis\.com|google\.com|recaptcha\.net|hcaptcha\.com|facebook\.net|facebook\.com|fbcdn\.net|twitter\.com"
    r"|x\.com|linkedin\.com|licdn\.com|stripe\.com|paypal\.com|paypalobjects\.com|braintreegateway\.com"
    r"|cloudflareinsights\.com|cloudflare\.com|hotjar\.com|intercom\.io|intercomcdn\.com|segment\.com|segment\.io"
    r"|sentry-cdn\.com|sentry\.io|jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|jquery\.com|bootstrapcdn\.com"
    r"|newrelic\.com|nr-data\.net|datadoghq\.com|datadoghq-browser-agent\.com|clarity\.ms|bing\.com|hs-scripts\.com"
    r"|hubspot\.com|hsforms\.net|zendesk\.com|zdassets\.com|crisp\.chat|tawk\.to|optimizely\.com|mixpanel\.com"
    r"|amplitude\.com|fullstory\.com|onetrust\.com|cookielaw\.org|cookiebot\.com|youtube\.com|ytimg\.com|vimeo\.com"
    r"|tiktok\.com|snapchat\.com|pinterest\.com|addthis\.com|disqus\.com|trustpilot\.com|typekit\.net|fontawesome\.com"
    r"|polyfill\.io|mxpnl\.com|launchdarkly\.com|pendo\.io|heapanalytics\.com|appcues\.com|drift\.com|driftt\.com)$",
    re.I)


@dataclass
class Options:
    max_files:     int = 300
    depth:         int = 4
    threads:       int = 8
    timeout:       float = 15.0
    max_bytes:     int = 20 * 1024 * 1024
    delay:         float = 0.0
    headers:       Dict[str, str] = field(default_factory=dict)
    proxy:         Optional[str] = None
    insecure:      bool = False
    scope:         List[str] = field(default_factory=list)   # extra in-scope domains
    strict_scope:  bool = False                              # never leave the target's own domain
    follow_chunks: bool = True
    source_maps:   bool = True
    probe_maps:    bool = True                               # try <script>.map when no reference is present
    check_npm:     bool = False
    entropy:       bool = False
    sources_dir:   Optional[str] = None                      # write recovered sources here


@dataclass
class FileRecord:
    name:   str
    kind:   str            # html | script | inline | source | har-entry
    origin: str            # target | html | chunk-map | sourcemap | local | har
    size:   int = 0

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "kind": self.kind, "origin": self.origin, "size": self.size}


@dataclass
class Result:
    targets:    List[str] = field(default_factory=list)
    files:      List[FileRecord] = field(default_factory=list)
    endpoints:  List[Endpoint] = field(default_factory=list)
    secrets:    List[Secret] = field(default_factory=list)
    hosts:      List[Host] = field(default_factory=list)
    routes:     List[str] = field(default_factory=list)
    graphql:    List[Tuple[str, str]] = field(default_factory=list)
    bases:      List[str] = field(default_factory=list)
    sourcemaps: List[Dict[str, object]] = field(default_factory=list)
    packages:   List[str] = field(default_factory=list)
    npm:        List[PackageStatus] = field(default_factory=list)
    unvisited:  List[str] = field(default_factory=list)      # scripts referenced but not fetched (HAR / local / limits)
    errors:     List[str] = field(default_factory=list)
    stats:      Dict[str, object] = field(default_factory=dict)
    origin:     str = ""                                     # scheme://host of the first URL target

    def full_url(self, ep: Endpoint) -> str:
        u = ep.url
        if re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
            return u
        if u.startswith("//"):
            return "https:" + u
        if u.startswith("{"):
            return u
        if u.startswith("/"):
            return (self.origin + u) if self.origin else u
        base = self.bases[0] if len(self.bases) == 1 else ""
        if base:
            return base.rstrip("/") + "/" + u.lstrip("./")
        return (self.origin + "/" + u.lstrip("./")) if self.origin else u

    def to_dict(self, reveal: bool = False) -> Dict[str, object]:
        return {
            "tool": "deepjs", "version": __version__, "targets": self.targets, "origin": self.origin,
            "stats": self.stats,
            "endpoints": [dict(e.to_dict(), full=self.full_url(e)) for e in self.endpoints],
            "secrets": [s.to_dict(reveal) for s in self.secrets],
            "hosts": [h.to_dict() for h in self.hosts],
            "routes": self.routes,
            "graphql": [{"type": t, "name": n} for t, n in self.graphql],
            "api_bases": self.bases,
            "source_maps": self.sourcemaps,
            "packages": self.packages,
            "npm": [s.to_dict() for s in self.npm],
            "unvisited_scripts": self.unvisited,
            "files": [f.to_dict() for f in self.files],
            "errors": self.errors,
        }


class Engine:
    def __init__(self, options: Optional[Options] = None, fetcher: Optional[Fetcher] = None, log=None) -> None:
        self.opt = options or Options()
        self.fetcher = fetcher or Fetcher(
            timeout=self.opt.timeout, max_bytes=self.opt.max_bytes, delay=self.opt.delay,
            headers=self.opt.headers, proxy=self.opt.proxy, insecure=self.opt.insecure,
        )
        self.log = log or (lambda msg: None)
        self.result = Result()
        self.scope: Set[str] = {s.lower().lstrip(".") for s in self.opt.scope}
        self.asset_hosts: Set[str] = set()
        self.hosts = HostCollector(self.scope)
        self._endpoints: Dict[Tuple[str, str], Endpoint] = {}
        self._called: Set[str] = set()
        self._secrets: Dict[Tuple[str, str], Secret] = {}
        self._routes: Set[str] = set()
        self._graphql: Set[Tuple[str, str]] = set()
        self._bases: Set[str] = set()
        self._packages: Set[str] = set()
        self._seen_urls: Set[str] = set()
        self._seen_maps: Set[str] = set()
        self._queue: deque = deque()
        self._unvisited: Set[str] = set()
        self._bytes = 0

    # ── public ────────────────────────────────────────────────────────────────

    def run(self, targets: Iterable[str]) -> Result:
        t0 = time.time()
        targets = [t.strip() for t in targets if t and t.strip()]
        self.result.targets = list(targets)
        urls = [t for t in targets if re.match(r"^https?://", t, re.I)]
        for u in urls:
            parts = urlsplit(u)
            host = (parts.hostname or "").lower()
            self.scope.add(registrable(host))
            self.scope.add(host)
            if not self.result.origin:
                self.result.origin = f"{parts.scheme}://{parts.netloc}"
        self.hosts.scope = set(self.scope)

        for t in targets:
            if t in urls:
                self._enqueue(t, 0, "target")
            elif os.path.isdir(t):
                self._scan_directory(t)
            elif os.path.isfile(t):
                self._scan_local_file(t, "local")
            else:
                self.result.errors.append(f"target not found: {t}")
        self._crawl()

        if self.opt.check_npm and self._packages:
            self.log(f"checking {len(self._packages)} package name(s) against the public npm registry")
            self.result.npm = check_packages(self._packages, self.fetcher, self.opt.threads)

        self._finish(time.time() - t0)
        return self.result

    # ── crawling ──────────────────────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            return False
        if host in self.scope or registrable(host) in self.scope or any(host.endswith("." + s) for s in self.scope):
            return True
        return not self.opt.strict_scope and host in self.asset_hosts

    def _enqueue(self, url: str, depth: int, origin: str) -> None:
        url = url.split("#", 1)[0]
        if url in self._seen_urls:
            return
        if len(self._seen_urls) >= self.opt.max_files or depth > self.opt.depth:
            self._unvisited.add(url)
            return
        self._seen_urls.add(url)
        self._queue.append((url, depth, origin))

    def _crawl(self) -> None:
        if not self._queue:
            return
        with ThreadPoolExecutor(max_workers=max(1, self.opt.threads)) as pool:
            while self._queue:
                batch = [self._queue.popleft() for _ in range(min(len(self._queue), self.opt.threads * 2))]
                for (url, depth, origin), resp in zip(batch, pool.map(lambda item: self.fetcher.get(item[0]), batch)):
                    self._handle_response(url, depth, origin, resp)

    def _handle_response(self, url: str, depth: int, origin: str, resp: Response) -> None:
        if not resp.ok:
            # a guessed chunk that is not there is expected; a target that fails is worth reporting
            if origin == "target" or resp.status not in (0, 403, 404, 410):
                self.result.errors.append(f"{url}: {resp.error or 'HTTP ' + str(resp.status)}")
            return
        text = resp.text()
        final = resp.url or url
        ctype = resp.content_type
        head = text[:400].lstrip().lower()
        is_html = "html" in ctype or head.startswith(("<!doctype", "<html")) or \
            (head.startswith("<") and "<script" in text[:20000].lower())
        if is_html:
            if origin != "target" and not final.lower().split("?")[0].endswith((".html", ".htm", "/")):
                return                                   # a chunk guess answered by the SPA's index.html
            self._handle_html(text, final, depth)
        else:
            self._analyse_script(text, final, "script", origin, depth, url=final)

    def _handle_html(self, html: str, url: str, depth: int) -> None:
        self.result.files.append(FileRecord(url, "html", "target", len(html)))
        found = chunks_mod.scripts_from_html(html, url)
        self.log(f"{url}: {len(found.urls)} script(s), {len(found.inline)} inline")
        for src in found.urls:
            host = (urlsplit(src).hostname or "").lower()
            if not self._in_scope(src):
                if self.opt.strict_scope or _VENDOR_HOSTS.search(host):
                    self.hosts.add(host, url)
                    continue
                self.asset_hosts.add(host)               # the app's own CDN / asset host
            self._enqueue(src, depth + 1, "html")
        for n, body in enumerate(found.inline, 1):
            self._analyse_script(body, f"{url}#inline-{n}", "inline", "html", depth, url=url)

    # ── analysis ──────────────────────────────────────────────────────────────

    def _analyse_script(self, text: str, name: str, kind: str, origin: str, depth: int,
                        url: str = "", follow: bool = True) -> None:
        if not text or len(text) > MAX_ANALYSE_BYTES:
            return
        self._bytes += len(text)
        self.result.files.append(FileRecord(name, kind, origin, len(text)))
        try:
            p = Program(text, name)
        except Exception as exc:                          # the tokenizer is tolerant; this is belt and braces
            self.result.errors.append(f"{name}: could not tokenize ({type(exc).__name__})")
            return

        ex = extract(p, name)
        for ep in ex.endpoints:
            self._merge_endpoint(ep)
        self._routes.update(ex.routes)
        self._graphql.update(ex.graphql)
        self._bases.update(ex.bases)

        for s in scan_program(p, name, self.opt.entropy):
            key = (s.kind, s.value)
            old = self._secrets.get(key)
            if old is None or (name.startswith("map:") and not old.file.startswith("map:")):
                self._secrets[key] = s

        for t in p.tokens:
            if t[K] == STR:
                if len(t[V]) > 3:
                    self.hosts.feed(t[V], name)
            elif t[K] == TPL:
                for seg in t[V]:
                    if isinstance(seg, str) and len(seg) > 3:
                        self.hosts.feed(seg, name)

        if kind == "source":
            return

        disc = chunks_mod.discover(p, url)
        self._routes.update(disc.routes)
        for ref in disc.scripts:
            if not re.match(r"^https?://", ref, re.I):
                self._unvisited.add(ref)
            elif not follow or not self.opt.follow_chunks:
                if ref not in self._seen_urls:
                    self._unvisited.add(ref)
            elif self._in_scope(ref):
                self._enqueue(ref, depth + 1, "chunk-map")

        if self.opt.source_maps and kind == "script":
            self._handle_source_map(text, name, url, follow)

    def _merge_endpoint(self, ep: Endpoint) -> None:
        key = ep.key()
        old = self._endpoints.get(key)
        if old is None:
            if ep.is_call:
                # a bare string seen in another file turns out to be a real call
                stale = self._endpoints.get(("", ep.url))
                if stale is not None and not stale.is_call:
                    del self._endpoints[("", ep.url)]
                self._called.add(ep.url)
            elif ep.url in self._called:
                return
            self._endpoints[key] = ep
            return
        for attr in ("params", "body", "headers"):
            setattr(old, attr, list(dict.fromkeys(getattr(old, attr) + getattr(ep, attr))))
        if ep.confidence > old.confidence:
            old.confidence, old.kind = ep.confidence, ep.kind
        if ep.file.startswith("map:") and not old.file.startswith("map:"):
            old.file, old.line = ep.file, ep.line         # the original source is the better pointer

    # ── source maps ───────────────────────────────────────────────────────────

    def _handle_source_map(self, text: str, name: str, url: str, online: bool) -> None:
        ref = sm.find_map_reference(text)
        data: Optional[bytes] = None
        where = ""
        if ref and ref.startswith("data:"):
            data, where = sm.decode_inline_map(ref), name + " (inline)"
        elif url and re.match(r"^https?://", url, re.I):
            if not online:
                return
            candidate = urljoin(url, ref) if ref else (url.split("?", 1)[0] + ".map" if self.opt.probe_maps else "")
            if not candidate or candidate in self._seen_maps or not self._in_scope(candidate):
                return
            self._seen_maps.add(candidate)
            resp = self.fetcher.get(candidate)
            if not resp.ok or resp.text()[:200].lstrip().lower().startswith(("<!doctype", "<html")):
                return
            data, where = resp.body, candidate
        elif os.path.isfile(name):
            local = os.path.join(os.path.dirname(name), ref) if ref else name + ".map"
            if os.path.isfile(local) and local not in self._seen_maps:
                self._seen_maps.add(local)
                try:
                    with open(local, "rb") as fh:
                        data, where = fh.read(sm.MAX_MAP_BYTES + 1), local
                except OSError:
                    return
        if data:
            self._ingest_map(data, where, referenced=bool(ref))

    def _ingest_map(self, data: bytes, where: str, referenced: bool = True) -> None:
        smap = sm.parse_source_map(data)
        if smap is None:
            return
        app = smap.app_sources
        self._packages.update(smap.packages)
        written = 0
        if self.opt.sources_dir:
            written, _ = sm.write_sources(smap, self.opt.sources_dir)
        self.result.sourcemaps.append({
            "url": where, "referenced": referenced, "sources": len(smap.sources),
            "with_content": sum(1 for s in smap.sources if s.content is not None),
            "app_sources": len(app), "packages": len(smap.packages), "written": written,
        })
        embedded = sum(1 for s in smap.sources if s.content is not None)
        self.log(f"source map {where}: {len(smap.sources)} sources, {embedded} with content, "
                 f"{len(app)} application files" + ("" if embedded else " (file names only — no source text embedded)"))
        for src in app[:5000]:
            self._analyse_script(src.content or "", "map:" + src.path, "source", "sourcemap", 0)

    # ── local input ───────────────────────────────────────────────────────────

    def _scan_directory(self, root: str) -> None:
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in sorted(filenames):
                if fn.lower().endswith(LOCAL_EXTENSIONS):
                    if count >= self.opt.max_files:
                        self.result.errors.append(f"{root}: stopped at --max-files {self.opt.max_files}")
                        return
                    count += 1
                    self._scan_local_file(os.path.join(dirpath, fn), "local")

    def _scan_local_file(self, path: str, origin: str) -> None:
        try:
            with open(path, "rb") as fh:
                raw = fh.read(MAX_ANALYSE_BYTES + 1)
        except OSError as exc:
            self.result.errors.append(f"{path}: {exc.strerror or exc}")
            return
        low = path.lower()
        if low.endswith(".har"):
            self._scan_har(raw, path)
        elif low.endswith(".map"):
            if path not in self._seen_maps:
                self._seen_maps.add(path)
                self._ingest_map(raw, path)
        else:
            text = raw.decode("utf-8", errors="replace")
            if low.endswith((".html", ".htm")):
                self.result.files.append(FileRecord(path, "html", origin, len(text)))
                found = chunks_mod.scripts_from_html(text, "")
                self._unvisited.update(u for u in found.urls)
                for n, body in enumerate(found.inline, 1):
                    self._analyse_script(body, f"{path}#inline-{n}", "inline", origin, 0, follow=False)
            else:
                self._analyse_script(text, path, "script", origin, 0, follow=False)

    def _scan_har(self, raw: bytes, path: str) -> None:
        try:
            entries = json.loads(raw.decode("utf-8", errors="replace"))["log"]["entries"]
        except Exception:
            self.result.errors.append(f"{path}: not a HAR file")
            return
        have: Set[str] = set()
        todo: List[Tuple[str, str, str]] = []
        for e in entries if isinstance(entries, list) else []:
            try:
                url = e["request"]["url"]
                content = e["response"]["content"]
                body = content.get("text") or ""
                if content.get("encoding") == "base64":
                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                mime = (content.get("mimeType") or "").lower()
            except Exception:
                continue
            if not body:
                continue
            have.add(url.split("#", 1)[0])
            parts = urlsplit(url)
            if not self.result.origin and parts.scheme in ("http", "https") and "html" in mime:
                self.result.origin = f"{parts.scheme}://{parts.netloc}"
                self.scope.update({registrable(parts.hostname or ""), (parts.hostname or "").lower()})
                self.hosts.scope = set(self.scope)
            if "javascript" in mime or "ecmascript" in mime or re.search(r"\.m?js(?:\?|$)", url):
                todo.append((url, body, "script"))
            elif "html" in mime:
                todo.append((url, body, "html"))
        self._seen_urls.update(have)
        for url, body, kind in todo:
            if kind == "html":
                self.result.files.append(FileRecord(url, "html", "har", len(body)))
                found = chunks_mod.scripts_from_html(body, url)
                self._unvisited.update(u for u in found.urls if u not in have)
                for n, inline in enumerate(found.inline, 1):
                    self._analyse_script(inline, f"{url}#inline-{n}", "inline", "har", 0, url=url, follow=False)
            else:
                self._analyse_script(body, url, "script", "har", 0, url=url, follow=False)

    # ── wrap-up ───────────────────────────────────────────────────────────────

    def _finish(self, seconds: float) -> None:
        r = self.result
        for ep in self._endpoints.values():
            if ep.host:
                self.hosts.add(ep.host, ep.file)
        r.endpoints = sorted(self._endpoints.values(), key=lambda e: (not e.is_call, e.url, e.method))
        sev = {s: i for i, s in enumerate(SEVERITIES)}
        r.secrets = sorted(self._secrets.values(), key=lambda s: (sev.get(s.severity, 9), -s.confidence, s.kind))
        r.hosts = self.hosts.sorted()
        r.routes = sorted(self._routes)
        r.graphql = sorted(self._graphql)
        r.bases = sorted(self._bases)
        r.packages = sorted(self._packages)
        r.unvisited = sorted(u for u in self._unvisited if u not in self._seen_urls)
        calls = sum(1 for e in r.endpoints if e.is_call)
        r.stats = {
            "files": len([f for f in r.files if f.kind != "html"]),
            "pages": len([f for f in r.files if f.kind == "html"]),
            "bytes": self._bytes,
            "requests": self.fetcher.requests,
            "seconds": round(seconds, 2),
            "endpoints": len(r.endpoints),
            "api_calls": calls,
            "secrets": len([s for s in r.secrets if not s.public]),
            "public_keys": len([s for s in r.secrets if s.public]),
            "hosts": len(r.hosts),
            "source_maps": len(r.sourcemaps),
            "recovered_sources": sum(int(m["app_sources"]) for m in r.sourcemaps),
            "packages": len(r.packages),
            "unclaimed_packages": len([n for n in r.npm if n.status == "unclaimed"]),
        }
