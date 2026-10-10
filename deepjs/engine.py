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
import hashlib
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
from deepjs.endpoints import Endpoint, extract, normalise_url
from deepjs.fetch import Fetcher, Response
from deepjs.hosts import Host, HostCollector, registrable
from deepjs.jseval import Program, is_static, render
from deepjs.lexer import K, STR, TPL, V
from deepjs.npmcheck import PackageStatus, check_packages
from deepjs.secrets import SEVERITIES, Secret, scan_program

MAX_ANALYSE_BYTES = 30 * 1024 * 1024
LOCAL_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".html", ".htm", ".map", ".har")
SKIP_DIRS = {"node_modules", ".git", ".svn", ".hg", "__pycache__", ".venv", "venv"}

_NOT_A_PAGE_EXT = re.compile(
    r"\.(?:js|mjs|css|map|json|xml|rss|atom|txt|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3"
    r"|wav|ogg|pdf|zip|gz|tgz|rar|7z|exe|dmg|apk|ipa|docx?|xlsx?|pptx?|csv|wasm)$", re.I)
# Links a crawler must never follow: a GET that changes state.
_STATE_CHANGING = re.compile(
    r"(?:log|sign)[-_]?(?:out|off)|logoff|delete|remove|destroy|unsubscribe|deactivate|revoke|purge|reset|cancel", re.I)

# `{apiUrl}/users`: a URL that starts with one unresolved name — a base URL variable
_LEADING_BASE = re.compile(r"^\{([A-Za-z_$][\w$]*)\}(?=/|$)")
# values worth remembering across files as a possible base URL:  "."  "/api"  "https://api.example.com/v2"
_BASE_VALUE = re.compile(r"^(?:\.{0,2}|(?:\.{0,2}/|https?://|//)[^\s\"'<>{}]{0,300})$")
_PER_REQUEST = re.compile(r"""\b(?:nonce|content|value|data-[\w\-]+)\s*=\s*(?:"[^"]*"|'[^']*')""", re.I)
# a server that keeps answering like this is overloaded or rate limiting: stop asking
GIVE_UP_AFTER = 8
_LOCAL_FILE_NAME = re.compile(r"\.(?:m?js|cjs|jsx|tsx?|vue|json|html?|har|map|txt|css)$", re.I)
_TRACKING_PARAMS = frozenset({
    "ref", "source", "src", "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "_ga", "_gl", "igshid",
})

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
    r"|polyfill\.io|mxpnl\.com|launchdarkly\.com|pendo\.io|heapanalytics\.com|appcues\.com|drift\.com|driftt\.com"
    r"|instagram\.com|cdninstagram\.com|threads\.net|whatsapp\.com|whatsapp\.net|messenger\.com|fbsbx\.com|twimg\.com"
    r"|tiktokcdn\.com|reddit\.com|redditstatic\.com|vk\.com|yandex\.ru|yandex\.net|googleadservices\.com"
    r"|googletagservices\.com|criteo\.com|criteo\.net|taboola\.com|outbrain\.com|amazon-adsystem\.com|adsrvr\.org"
    r"|adnxs\.com|rubiconproject\.com|pubmatic\.com|scorecardresearch\.com|quantserve\.com|mouseflow\.com"
    r"|crazyegg\.com|trustarc\.com|usercentrics\.eu|klaviyo\.com|list-manage\.com|chimpstatic\.com|hsappstatic\.net"
    r"|livechatinc\.com|olark\.com|zopim\.com|tidio\.co|calendly\.com|typeform\.com|spotify\.com|soundcloud\.com"
    r"|wistia\.com|wistia\.net|onesignal\.com|appsflyer\.com|branch\.io|userway\.org)$",
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
    crawl:         bool = True                               # follow page links, forms, robots.txt, sitemaps
    max_pages:     int = 40
    crawl_depth:   int = 2
    user_agent:    Optional[str] = None
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
            # `{apiUrl}/users`: the base is a runtime value. Best guess: the one API base
            # the code names, else the site itself — the report keeps the placeholder.
            m = _LEADING_BASE.match(u)
            if not m or not u[m.end():].startswith("/"):
                return u
            known = self.bases[0] if len(self.bases) == 1 and re.match(r"^https?://", self.bases[0], re.I) else ""
            guess = known.rstrip("/") or self.origin
            return guess + u[m.end():] if guess else u
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
            **({"user_agent": self.opt.user_agent} if self.opt.user_agent else {}),
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
        self.page_hosts: Set[str] = set()          # hosts whose pages may be crawled
        self._page_keys: Set[str] = set()
        self._script_count = 0
        self._pages_skipped = 0
        self._refused = 0                          # 401 / 403 / 429 responses
        self.map_candidates: Dict[str, bool] = {}  # source-map URL → explicitly referenced? (proxy mode)
        # property name → base-URL-like values, over every file: `environment.apiUrl` is
        # usually defined in one chunk and used in another
        self._base_props: Dict[str, Set[str]] = {}
        self._base_tainted: Set[str] = set()
        self._page_sigs: Set[str] = set()
        self._failing = 0                          # consecutive 5xx / 429 answers
        self._server_errors: Dict[int, int] = {}   # status → count, for requests that were not a target
        self._gave_up = False
        self._route_dupes = 0                      # client routes answered with a page already seen
        self.spa_shell = False

    # ── public ────────────────────────────────────────────────────────────────

    def run(self, targets: Iterable[str]) -> Result:
        t0 = time.time()
        targets = [self._normalise_target(t) for t in targets if t and t.strip()]
        self.result.targets = list(targets)
        urls = [t for t in targets if re.match(r"^https?://", t, re.I)]
        for u in urls:
            parts = urlsplit(u)
            host = (parts.hostname or "").lower()
            self.scope.add(registrable(host))
            self.scope.add(host)
            self.page_hosts.add(host)
            if not self.result.origin:
                self.result.origin = f"{parts.scheme}://{parts.netloc}"
        self.hosts.scope = set(self.scope)

        for t in targets:
            if t in urls:
                self._enqueue(t, 0, "target", page=True)
            elif os.path.isdir(t):
                self._scan_directory(t)
            elif os.path.isfile(t):
                self._scan_local_file(t, "local")
            else:
                self.result.errors.append(f"target not found: {t}")
        if urls and self.opt.crawl:
            self._seed_from_robots_and_sitemaps(urls)
        self._crawl()

        if self.opt.check_npm and self._packages:
            self.log(f"checking {len(self._packages)} package name(s) against the public npm registry")
            self.result.npm = check_packages(self._packages, self.fetcher, self.opt.threads)

        self._finish(time.time() - t0)
        return self.result

    @staticmethod
    def _normalise_target(t: str) -> str:
        """`app.example.com/login` → `https://app.example.com/login` (unless it is a local path)."""
        t = t.strip()
        if re.match(r"^https?://", t, re.I) or os.path.exists(t):
            return t
        if _LOCAL_FILE_NAME.search(t.split("?", 1)[0]) and "/" not in t.replace("\\", "/").strip("./"):
            return t                                 # a mistyped local file, not a host called "bundle.js"
        if re.match(r"^(?:[\w\-]+\.)+[A-Za-z]{2,24}(?::\d+)?(?:[/?#].*)?$", t) or re.match(r"^localhost(?::\d+)?(?:/.*)?$", t):
            return "https://" + t
        return t

    # ── crawling ──────────────────────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            return False
        if host in self.scope or registrable(host) in self.scope or any(host.endswith("." + s) for s in self.scope):
            return True
        return not self.opt.strict_scope and host in self.asset_hosts

    def _page_allowed(self, url: str) -> bool:
        """May this URL be requested as a *page* by the crawler?"""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or len(url) > 2000:
            return False
        if host not in self.page_hosts and not any(host == s or host.endswith("." + s) for s in self.opt.scope):
            return False
        if _NOT_A_PAGE_EXT.search(parts.path) or _STATE_CHANGING.search(parts.path + "?" + parts.query):
            return False
        return True

    @staticmethod
    def _page_key(url: str) -> str:
        """Pages that differ only in query *values* are the same page to the crawler."""
        parts = urlsplit(url)
        names = sorted({q.split("=", 1)[0] for q in parts.query.split("&") if q} - _TRACKING_PARAMS)
        return f"{parts.netloc.lower()}{parts.path.rstrip('/')}?{'&'.join(names)}"

    def _enqueue(self, url: str, depth: int, origin: str, page: bool = False) -> None:
        url = url.split("#", 1)[0]
        if url in self._seen_urls or self._gave_up:
            return
        if page:
            key = self._page_key(url)
            if key in self._page_keys:
                return
            if len(self._page_keys) >= self.opt.max_pages:
                self._pages_skipped += 1
                return
            self._page_keys.add(key)
        else:
            if self._script_count >= self.opt.max_files or depth > self.opt.depth:
                self._unvisited.add(url)
                return
            self._script_count += 1
        self._seen_urls.add(url)
        self._queue.append((url, depth, origin, page))

    def _seed_from_robots_and_sitemaps(self, urls: List[str]) -> None:
        """robots.txt names paths the owner did not want indexed; sitemaps name pages nobody links to."""
        origins = list(dict.fromkeys(f"{urlsplit(u).scheme}://{urlsplit(u).netloc}" for u in urls))
        for origin in origins[:5]:
            sitemaps: List[str] = []
            resp = self.fetcher.get(origin + "/robots.txt")
            text = resp.text() if resp.ok else ""
            if text and "<html" not in text[:500].lower():
                paths = 0
                for line in text.splitlines():
                    name, _, value = line.partition(":")
                    name, value = name.strip().lower(), value.split("#", 1)[0].strip()
                    if name == "sitemap" and value:
                        sitemaps.append(urljoin(origin + "/", value))
                    elif name in ("disallow", "allow") and value.startswith("/") and len(value) > 1 and paths < 200:
                        path = value.split("*", 1)[0].rstrip("$")
                        if len(path) > 1:
                            paths += 1
                            self._merge_endpoint(Endpoint(url=path, kind="string", file=origin + "/robots.txt",
                                                          confidence=0.5))
                if paths or sitemaps:
                    self.log(f"robots.txt: {paths} path(s), {len(sitemaps)} sitemap(s)")
            todo = deque(sitemaps or [origin + "/sitemap.xml"])
            fetched = pages = 0
            while todo and fetched < 6:
                sm_url = todo.popleft()
                fetched += 1
                resp = self.fetcher.get(sm_url)
                if not resp.ok:
                    continue
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text()[:5_000_000]):
                    loc = loc.replace("&amp;", "&")
                    if loc.lower().split("?")[0].endswith((".xml", ".xml.gz")):
                        todo.append(loc)
                    elif self._page_allowed(loc) and pages < max(5, self.opt.max_pages // 2):
                        pages += 1
                        self._enqueue(loc, 1, "sitemap", page=True)
            if pages:
                self.log(f"sitemap: {pages} page(s) queued")

    def _enqueue_routes(self, limit: int = 30) -> int:
        """Client-side routes found in the scripts are pages too — server-rendered apps ship different chunks per route."""
        if not self.result.origin:
            return 0
        added = 0
        for route in sorted(self._routes):
            if added >= limit:
                break
            if re.fullmatch(r"/[\w\-./~]*", route) and route != "/":
                url = self.result.origin + route
                if self._page_allowed(url) and url not in self._seen_urls:
                    before = len(self._queue)
                    self._enqueue(url, 1, "route", page=True)
                    added += len(self._queue) - before
        if added:
            self.log(f"visiting {added} client route(s) found in the scripts")
        return added

    def _crawl(self) -> None:
        if not self._queue:
            return
        # 0: targets, links, sitemaps · 1: a few client routes probed · 2: the rest queued
        stage, probes = 0, 0
        with ThreadPoolExecutor(max_workers=max(1, self.opt.threads)) as pool:
            while True:
                if self._gave_up:
                    break
                if not self._queue:
                    if stage == 2 or not self.opt.crawl:
                        break
                    if stage == 0:
                        stage = 1
                        probes = self._enqueue_routes(3)
                    else:
                        stage = 2
                        if probes and self._route_dupes * 2 > probes:
                            # a single-page app answers every route with the same shell: the
                            # scripts are already known, further requests would teach nothing
                            self.spa_shell = True
                            self.log("client routes all return the same HTML shell (single-page app): "
                                     "not requesting the others")
                        else:
                            self._enqueue_routes(30)
                    if not self._queue:
                        continue
                batch = [self._queue.popleft() for _ in range(min(len(self._queue), self.opt.threads * 2))]
                for item, resp in zip(batch, pool.map(lambda it: self.fetcher.get(it[0]), batch)):
                    self._handle_response(*item, resp)

    def _handle_response(self, url: str, depth: int, origin: str, page: bool, resp: Response) -> None:
        if not resp.ok:
            if resp.status in (401, 403, 429):
                self._refused += 1
            overloaded = resp.status == 429 or 500 <= resp.status < 600
            self._failing = self._failing + 1 if overloaded else 0
            if overloaded and origin != "target":
                self._server_errors[resp.status] = self._server_errors.get(resp.status, 0) + 1
            # a guessed chunk / route that is not there is expected; a target that fails is worth reporting
            elif origin == "target" or resp.status not in (0, 401, 403, 404, 410, 429):
                self.result.errors.append(f"{url}: {resp.error or 'HTTP ' + str(resp.status)}")
            if self._failing >= GIVE_UP_AFTER and self._queue and not self._gave_up:
                self._gave_up = True
                left = len(self._queue)
                self._queue.clear()
                self.result.errors.append(
                    f"stopped early: {self._failing} requests in a row were answered HTTP {resp.status} — the server is "
                    f"overloaded or rate limiting ({left} queued request(s) dropped). Retry later with --delay 1 --threads 2.")
            return
        self._failing = 0
        text = resp.text()
        final = resp.url or url
        ctype = resp.content_type
        head = text[:400].lstrip().lower()
        is_html = "html" in ctype or head.startswith(("<!doctype", "<html")) or \
            (head.startswith("<") and "<script" in text[:20000].lower())
        if is_html:
            if page:
                # a redirect may have left the site (SSO, marketing domain): analyse, but do not crawl from there
                on_site = (urlsplit(final).hostname or "").lower() in self.page_hosts
                self._handle_html(text, final, depth, origin, crawl=on_site)
            # else: a chunk guess answered by the SPA's index.html — nothing to learn
        else:
            self._analyse_script(text, final, "script", origin, depth, url=final)

    def _handle_html(self, html: str, url: str, depth: int, origin: str = "target", crawl: bool = True,
                     online: bool = True) -> None:
        self.result.files.append(FileRecord(url, "html", origin, len(html)))
        found = chunks_mod.scripts_from_html(html, url)
        for src in found.urls:
            host = (urlsplit(src).hostname or "").lower()
            if not self._in_scope(src):
                if self.opt.strict_scope or _VENDOR_HOSTS.search(host):
                    self.hosts.add(host, url)
                    continue
                self.asset_hosts.add(host)               # the app's own CDN / asset host
            if online:
                self._enqueue(src, depth + 1, "html")
            elif src not in self._seen_urls:
                self._unvisited.add(src)
        for n, body in enumerate(found.inline, 1):
            self._analyse_script(body, f"{url}#inline-{n}", "inline", "html", depth, url=url, follow=online)

        links = chunks_mod.links_from_html(html, url)
        # the same document again (per-request nonces and tokens aside): a single-page app's shell
        sig = hashlib.sha1(_PER_REQUEST.sub("", html).encode("utf-8", "replace")).hexdigest()
        if sig in self._page_sigs and origin == "route":
            self._route_dupes += 1
        self._page_sigs.add(sig)
        queued = 0
        if online and crawl and self.opt.crawl and depth < self.opt.crawl_depth:
            for href in links.pages:
                if self._page_allowed(href):
                    before = len(self._queue)
                    self._enqueue(href, depth + 1, "link", page=True)
                    queued += len(self._queue) - before
        page_host = urlsplit(url).netloc
        for form in links.forms:
            fp = urlsplit(form.action)
            action = fp.path or "/" if fp.netloc == page_host else form.action.split("?", 1)[0]
            query = [q.split("=", 1)[0] for q in fp.query.split("&") if q]
            is_get = form.method == "GET"
            self._merge_endpoint(Endpoint(
                url=action, method=form.method, kind="form", file=url, confidence=0.9,
                params=list(dict.fromkeys(query + (form.fields if is_get else []))),
                body=[] if is_get else form.fields,
            ))
        self.log(f"{url}: {len(found.urls)} script(s), {len(found.inline)} inline, {len(links.forms)} form(s)"
                 + (f", {queued} new page(s) queued" if queued else ""))

    def feed(self, url: str, body, kind: str = "auto") -> None:
        """
        Analyse content obtained elsewhere — a proxy, a browser extension — without
        making any request. Scripts and source maps the content points to are
        recorded (``result.unvisited``, ``map_candidates``) for the caller to fetch.
        """
        raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "replace")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host and kind != "map" and _VENDOR_HOSTS.search(host):
            self.hosts.add(host, url)               # analytics / widget code is not the application
            return
        if host and not _VENDOR_HOSTS.search(host):
            self.scope.update({host, registrable(host)})
            self.page_hosts.add(host)
            self.hosts.scope = set(self.scope)
            if not self.result.origin:
                self.result.origin = f"{parts.scheme}://{parts.netloc}"
        self._seen_urls.add(url.split("#", 1)[0])
        self._unvisited.discard(url)
        if kind == "map":
            self.map_candidates.pop(url, None)
            if url not in self._seen_maps:
                self._seen_maps.add(url)
                self._ingest_map(bytes(raw), url)
            return
        text = bytes(raw).decode("utf-8", errors="replace")
        head = text[:400].lstrip().lower()
        if kind == "html" or (kind == "auto" and (head.startswith(("<!doctype", "<html")) or
                                                  (head.startswith("<") and "<script" in text[:20000].lower()))):
            self._handle_html(text, url, 0, "proxy", crawl=False, online=False)
        else:
            self._analyse_script(text, url, "script", "proxy", 0, url=url, follow=False)

    def snapshot(self) -> Result:
        """Sort and total what has been collected so far (used with `feed`)."""
        self._finish(0.0)
        return self.result

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

        for prop, values in p.props.items():
            keep = {v for v in values if _BASE_VALUE.match(v)}
            if keep:
                self._base_props.setdefault(prop, set()).update(keep)
            if len(keep) != len(values):
                self._base_tainted.add(prop)
        self._base_tainted.update(p.tainted_props)

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

    def resolve_bases(self) -> None:
        """
        `{hostServer}/rest/user/login` → `/rest/user/login` once some file — often
        another chunk — has shown that `hostServer` is only ever "." (or one URL).
        """
        for key, ep in list(self._endpoints.items()):
            m = _LEADING_BASE.match(ep.url)
            if not m:
                continue
            name = m.group(1)
            values = self._base_props.get(name)
            if name in self._base_tainted or not values or len(values) != 1:
                continue
            base = next(iter(values)).rstrip("/")
            rest = ep.url[m.end():]
            if base in ("", "."):
                base = ""
                if not rest:
                    continue
            del self._endpoints[key]
            ep.url = normalise_url(base + rest)
            self._merge_endpoint(ep)

    # ── source maps ───────────────────────────────────────────────────────────

    def _handle_source_map(self, text: str, name: str, url: str, online: bool) -> None:
        ref = sm.find_map_reference(text)
        data: Optional[bytes] = None
        where = ""
        if ref and ref.startswith("data:"):
            data, where = sm.decode_inline_map(ref), name + " (inline)"
        elif url and re.match(r"^https?://", url, re.I):
            candidate = urljoin(url, ref) if ref else (url.split("?", 1)[0] + ".map" if self.opt.probe_maps else "")
            if not candidate or candidate in self._seen_maps:
                return
            if not online:
                self.map_candidates.setdefault(candidate, bool(ref))     # the caller decides whether to fetch it
                return
            if not self._in_scope(candidate):
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
        self.resolve_bases()
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
        if self._refused and not any("refused" in e for e in r.errors):
            r.errors.append(
                f"{self._refused} request(s) were refused (HTTP 401/403/429). The site may require a session or be "
                "blocking automated clients: try -H 'Cookie: …', --proxy through your browser's proxy, or --delay.")
        if self._server_errors and not any("server error" in e for e in r.errors):
            detail = ", ".join(f"{n} × HTTP {code}" for code, n in sorted(self._server_errors.items()))
            r.errors.append(f"server errors while fetching pages / scripts: {detail}. Results may be incomplete.")
        if self._pages_skipped and not any("--max-pages" in e for e in r.errors):
            r.errors.append(f"{self._pages_skipped} more page(s) were found but not visited (raise --max-pages, now "
                            f"{self.opt.max_pages}).")
        calls = sum(1 for e in r.endpoints if e.is_call)
        r.stats = {
            "files": len([f for f in r.files if f.kind != "html"]),
            "pages": len([f for f in r.files if f.kind == "html"]),
            "pages_skipped": self._pages_skipped,
            "refused": self._refused,
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
