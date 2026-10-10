"""
deepjs.endpoints — what the application actually calls.

A regex over a bundle finds strings that look like paths. This module finds
*requests*: it recognises the call sites of the common HTTP clients, rebuilds
the URL the code assembles, and reads the method, query parameters, body
fields and header names from the same call:

    fetch(API + "/users/" + id, {method: "PUT", body: JSON.stringify({name, role})})
        →  PUT https://api.example.com/users/{id}    body: name, role

Recognised: fetch, axios (all forms), jQuery ajax/get/post, XMLHttpRequest.open,
any `<client>.get/post/put/patch/delete(...)` (Angular HttpClient, ky, got,
superagent, custom wrappers), request-config objects ({url, method, …} — RTK
Query, axios configs), WebSocket, EventSource, sendBeacon, GraphQL operations,
and client-side route tables.

Strings that merely look like paths are still collected, but separately and
with lower confidence, so the report can tell "this is called" from "this
appears".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from deepjs.jseval import ALT, Part, Program, expand, is_static, render
from deepjs.lexer import ID, K, PUNC, STR, TPL, V

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
_METHOD_CALLS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
                 "del": "DELETE", "head": "HEAD", "options": "OPTIONS", "getJSON": "GET", "getScript": "GET",
                 # @nuxtjs/axios:  this.$axios.$get("/articles")
                 "$get": "GET", "$post": "POST", "$put": "PUT", "$patch": "PATCH", "$delete": "DELETE", "$head": "HEAD"}
_HTTPISH = re.compile(r"axios|https?|api|client|request|ajax|rest|fetch|service|backend|instance|superagent|^ky$|^got$|^\$$", re.I)
_REQUEST_FUNCS = frozenset({"axios", "request", "ajax", "$http", "superagent", "ky", "got", "wretch", "needle"})

_ABSOLUTE = re.compile(r"^(?:https?:|wss?:)?//[A-Za-z0-9{][^\s\"'<>\\^`|]*$")
# scheme://{anything} with nothing else known: not worth a line in a report
_OPAQUE_ABSOLUTE = re.compile(r"^(?:https?:|wss?:)?//\{[^{}]*\}/?$")
_STATIC_ASSET = re.compile(
    r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|ogg|pdf|zip|gz"
    r"|wasm|txt|md|scss|sass|less|vue|tsx?|jsx|html?)(?:[?#].*)?$", re.I)
_PATH_CHARS = re.compile(r"^[A-Za-z0-9_\-./~%{}:@!$&'()*+,;=?#\[\]]+$")
_APIISH_PREFIX = re.compile(r"^(?:api|v\d+|rest|graphql|gql|rpc|services?|auth|oauth2?|admin|internal|ajax|backend|wp-json)/", re.I)
_APIISH_ANY = re.compile(r"(?:^|/)(?:api|v\d+|rest|graphql|gql|rpc|oauth2?|auth|admin|internal|ajax|backend|wp-json)(?:/|$)"
                         r"|\.(?:php|aspx?|jsp|do|action|json|xml|cgi|ashx|asmx|svc)(?:[?#]|$)", re.I)
_GRAPHQL_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*[({]")
_ROUTE_SIBLINGS = frozenset({"component", "element", "children", "loadChildren", "loadComponent", "redirectTo",
                             "redirect", "Component", "lazy", "beforeEnter", "canActivate", "render", "exact"})
_NAV_CALLS = frozenset({"navigate", "push", "replace", "navigateByUrl", "redirect", "go"})

# Library / spec URLs that every bundle carries and nobody wants in a report.
NOISE_HOSTS = re.compile(
    r"(?:^|\.)(?:w3\.org|reactjs\.org|react\.dev|fb\.me|facebook\.github\.io|github\.com|githubusercontent\.com"
    r"|npmjs\.com|mozilla\.org|developer\.mozilla\.org|schema\.org|json-schema\.org|momentjs\.com|lodash\.com"
    r"|angular\.io|angular\.dev|vuejs\.org|nextjs\.org|webpack\.js\.org|babeljs\.io|redux\.js\.org|mui\.com"
    r"|material-ui\.com|ant\.design|getbootstrap\.com|jquery\.com|stackoverflow\.com|wikipedia\.org|xml\.org"
    r"|ietf\.org|whatwg\.org|ecma-international\.org|tc39\.es|purl\.org|openxmlformats\.org|apache\.org"
    r"|creativecommons\.org|example\.com|example\.org|localhost\.example|sentry\.io/api|feross\.org|zloirock\.ru"
    r"|opencollective\.com|goo\.gl|bit\.ly|tailwindcss\.com|typescriptlang\.org|eslint\.org|rxjs\.dev|formatjs\.io)$",
    re.I)


@dataclass
class Endpoint:
    url:        str
    method:     str = ""            # "" = unknown
    kind:       str = "string"      # fetch | axios | xhr | ajax | client | config | websocket | eventsource | beacon | string
    params:     List[str] = field(default_factory=list)     # query parameter names
    body:       List[str] = field(default_factory=list)     # request body field names
    headers:    List[str] = field(default_factory=list)     # request header names
    file:       str = ""
    line:       int = 0
    confidence: float = 0.5

    @property
    def is_call(self) -> bool:
        return self.kind != "string"

    @property
    def host(self) -> str:
        m = re.match(r"^(?:[a-z]+:)?//([^/?#{}]+)", self.url, re.I)
        return m.group(1).split("@")[-1].split(":")[0].lower() if m else ""

    def key(self) -> Tuple[str, str]:
        return (self.method, self.url)

    def to_dict(self) -> Dict[str, object]:
        return {"method": self.method, "url": self.url, "kind": self.kind, "params": self.params,
                "body": self.body, "headers": self.headers, "file": self.file, "line": self.line,
                "confidence": round(self.confidence, 2)}


@dataclass
class Extraction:
    endpoints: List[Endpoint] = field(default_factory=list)
    graphql:   List[Tuple[str, str]] = field(default_factory=list)      # (operation type, name)
    routes:    List[str] = field(default_factory=list)                   # client-side routes
    bases:     List[str] = field(default_factory=list)                   # API base URLs (baseURL: …)


# ── URL helpers ────────────────────────────────────────────────────────────────

def split_query(url: str) -> Tuple[str, List[str]]:
    """'/a?x=1&y={v}' → ('/a', ['x', 'y'])"""
    base, sep, query = url.partition("?")
    if not sep:
        return url, []
    query = query.split("#", 1)[0]
    names = []
    for chunk in query.split("&"):
        name = chunk.split("=", 1)[0].strip()
        if name and re.fullmatch(r"[\w.\-\[\]]{1,60}", name) and name not in names:
            names.append(name)
    return base, names


def normalise_url(url: str) -> str:
    url = url.strip()
    scheme, sep, rest = url.partition("://")
    if sep:
        return scheme + "://" + re.sub(r"/{2,}", "/", rest)
    if url.startswith("//"):
        return "//" + re.sub(r"/{2,}", "/", url[2:])
    return re.sub(r"/{2,}", "/", url)


_BASE_NAME = re.compile(r"base|url|uri|api|host|server|endpoint|origin|root|prefix|domain|backend|gateway|service", re.I)


def _weak_noise(text: str) -> bool:
    """
    Shapes that are not worth listing when only the string itself suggests a
    URL (it is not the argument of a request): regex fragments, the one-letter
    hosts and paths of URL-parser tests in polyfills.
    """
    if "(" in text or ")" in text:
        return True
    head = text.split("?", 1)[0].split("#", 1)[0]
    scheme, sep, rest = head.partition("://")
    if sep:
        host, _, path = rest.partition("/")
        literal_host = re.sub(r"\{[^{}]*\}", "", host)
        if "." in literal_host or literal_host.startswith("localhost") or literal_host.startswith("["):
            return False
        if len(literal_host.strip("-:")) <= 1 and "{" not in host:
            return True                                    # https://a   http://f
        if "{" in host and len(literal_host.strip("-:")) <= 1:
            # https://{param}{param}   https://{teamId}-   — unless a real path follows
            return not any(len(x) >= 3 and "{" not in x for x in path.split("/"))
        return False
    if head.startswith("/"):
        segs = [x for x in head.split("/") if x]
        return bool(segs) and all(len(x) <= 1 for x in segs)   # /a/b
    return False


_WRAPPER_URL = re.compile(r"^(https?://[^/{}?#\s]+(?:/[^{}?#\s]*[^/{}?#\s])?|/(?:api|rest|v\d+)(?:/v?\d+)?)\{[^{}]+\}$", re.I)


def url_like(text: str, parts: List[Part], strong: bool, bare: bool = False) -> bool:
    """
    Is this built string a URL / path?  `strong` = it is the URL argument of a
    recognised HTTP call, so less evidence is needed.
    """
    if not (1 < len(text) <= 2048) or " " in text or "\n" in text:
        return False
    literal = "".join(t for is_var, t in parts if not is_var)
    if not literal.strip("/?&=.:"):
        return False                      # fetch(url): nothing known about the URL
    if bare and re.fullmatch(r"[\w\-{}.]+", text):
        return True                       # {url: "posts", method: "POST"} — relative to a base URL
    if "<" in text or ">" in text or "\\" in text or "^" in text or "*" in text.replace("/*", ""):
        return False
    if _OPAQUE_ABSOLUTE.match(text):
        return False
    if not strong and _weak_noise(text):
        return False
    if _ABSOLUTE.match(text):
        # scheme://user:secret@host belongs in the secrets report, not here
        return "@" not in text.split("//", 1)[-1].split("/", 1)[0]
    if text.startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "about:", "chrome:")):
        return False
    if not _PATH_CHARS.match(text):
        return False
    if text.startswith("/"):
        if text.startswith("/*") or text in ("/", "//", "/.", "/..") or re.fullmatch(r"/[gimsuy]{1,4}", text):
            return False
        if strong:
            return True
        segs = [s for s in split_query(text)[0].split("/") if s]
        if not segs or _STATIC_ASSET.search(text):
            return False
        return len(segs) >= 2 or bool(_APIISH_ANY.search(text)) or "?" in text or "{" in text
    if text.startswith("{") and "}/" in text:
        if strong:
            return True                   # {baseUrl}/users
        name, _, rest = text[1:].partition("}")
        literal_segs = [x for x in rest.split("?", 1)[0].split("/") if len(x) >= 2 and "{" not in x]
        return bool(_BASE_NAME.search(name)) or bool(_APIISH_ANY.search(rest)) or len(literal_segs) >= 2
    if text.startswith(("./", "../")):
        return strong and not _STATIC_ASSET.search(text)
    if _APIISH_PREFIX.match(text):
        return True
    return strong and "/" in text and not _STATIC_ASSET.search(text) and "." not in text.split("/")[0]


# ── extraction ─────────────────────────────────────────────────────────────────

class _Extractor:
    def __init__(self, p: Program, file: str) -> None:
        self.p = p
        self.file = file
        self.out = Extraction()
        self.claimed: Set[int] = set()
        self._by_key: Dict[Tuple[str, str], Endpoint] = {}
        self.enclosing = self._enclosing()

    def _enclosing(self) -> List[int]:
        p = self.p
        enc = [-1] * p.n
        stack: List[int] = []
        for i, t in enumerate(p.tokens):
            enc[i] = stack[-1] if stack else -1
            if t[K] == PUNC:
                v = t[V]
                if v in ("(", "[", "{"):
                    stack.append(i)
                elif v in (")", "]", "}"):
                    o = p.pairs[i]
                    if o >= 0:
                        while stack and stack[-1] != o:
                            stack.pop()
                        if stack:
                            stack.pop()
        return enc

    # ── recording ─────────────────────────────────────────────────────────────

    def add(self, url_parts: List[Part], method: str, kind: str, tok: int, conf: float,
            params: Optional[List[str]] = None, body: Optional[List[str]] = None,
            headers: Optional[List[str]] = None, strong: bool = True, bare: bool = False) -> bool:
        if any(v and t.startswith(ALT) for v, t in url_parts):
            # "/articles" + (feed ? "/feed" : ""): one endpoint per branch
            variants = expand(url_parts)
            if len(variants) > 1:
                return any([self.add(v, method, kind, tok, conf, params, body, headers, strong, bare) for v in variants])
        text = render(url_parts)
        if not url_like(text, url_parts, strong, bare):
            return False
        wrapper = _WRAPPER_URL.match(text) if kind != "string" else None
        if wrapper and len(url_parts) == 2:
            # get(path) { return this.http.get(`${environment.api_url}${path}`) }: an API client's
            # own plumbing. What it tells us is the base URL; the real paths are at its call sites.
            self.out.bases.append(wrapper.group(1))
            return True
        base, query_names = split_query(normalise_url(text))
        if not base:
            return False
        ep = Endpoint(url=base, method=method, kind=kind, file=self.file, line=self.p.line(tok), confidence=conf,
                      params=list(dict.fromkeys(query_names + (params or []))),
                      body=list(dict.fromkeys(body or [])), headers=list(dict.fromkeys(headers or [])))
        if ep.host and NOISE_HOSTS.search(ep.host):
            return False
        old = self._by_key.get(ep.key())
        if old is None and ep.is_call:
            # a bare string seen earlier turns out to be a real call: upgrade it
            stale = self._by_key.pop(("", ep.url), None)
            if stale is not None and not stale.is_call:
                self.out.endpoints.remove(stale)
        elif old is None and any(k[1] == ep.url for k in self._by_key):
            return True                             # already known as a call
        if old is None:
            self._by_key[ep.key()] = ep
            self.out.endpoints.append(ep)
        else:                                       # same request seen again: merge what we learned
            for attr in ("params", "body", "headers"):
                merged = list(dict.fromkeys(getattr(old, attr) + getattr(ep, attr)))
                setattr(old, attr, merged)
            if ep.confidence > old.confidence:
                old.confidence, old.kind = ep.confidence, ep.kind
        return True

    def claim(self, a: int, b: int) -> None:
        self.claimed.update(range(a, b))

    def _eval_range(self, a: int, b: int) -> List[Part]:
        """Evaluate the expression occupying tokens [a, b); empty if it is not a string build."""
        parts, end = self.p.eval_expr(a)
        if parts and end >= b:
            self.claim(a, b)
            return parts
        # `cond ? "/a" : "/b"`, `x || "/default"`: fall back to nothing (literals stay unclaimed)
        return []

    def _object_keys(self, a: int, b: int) -> List[str]:
        """Keys of an object literal value at [a, b), also through JSON.stringify({…})."""
        p = self.p
        i = a
        if p.kind(i) == ID and p.val(i) == "JSON" and p.is_punc(i + 1, ".") and p.val(i + 2) == "stringify" \
                and p.is_punc(i + 3, "("):
            i += 4
        if p.kind(i) == ID and p.val(i) == "new" and p.val(i + 1) in ("URLSearchParams", "FormData") \
                and p.is_punc(i + 2, "("):
            i += 3
        if p.kind(i) == ID and i + 1 >= b:
            # post(url, n) where  n = {privateKey: t}  was assigned just before
            literal = p.local_object(i)
            if literal >= 0:
                i = literal
        if p.is_punc(i, "{"):
            return [k for k in p.object_at(i).keys() if re.fullmatch(r"[\w.\-$\[\]]{1,60}", k)]
        return []

    def _static(self, a: int, b: int) -> str:
        parts, end = self.p.eval_expr(a)
        return parts[0][1] if is_static(parts) and end >= b else ""

    def _from_config(self, brace: int, kind: str, tok: int, url_parts: Optional[List[Part]] = None,
                     default_method: str = "", conf: float = 0.85) -> bool:
        """Read {url, method, params, data, headers} from an object literal."""
        p = self.p
        props = p.object_at(brace)
        if url_parts is None:
            for name in ("url", "uri", "endpoint", "path"):
                if name in props:
                    url_parts = self._eval_range(*props[name])
                    break
        if not url_parts:
            return False
        method = default_method
        either: List[str] = []
        has_method = False
        for name in ("method", "type", "verb"):
            if name in props:
                has_method = True
                m = self._static(*props[name]).upper()
                if m in HTTP_METHODS:
                    method = m
                else:
                    # method: favorited ? "DELETE" : "POST"
                    branches = p._literal_branches(props[name][0], -1, 0) or []
                    either = [b.upper() for b in branches if b.upper() in HTTP_METHODS]
                break
        params: List[str] = []
        for name in ("params", "query", "qs", "searchParams", "search"):
            if name in props:
                params += self._object_keys(*props[name])
        body: List[str] = []
        for name in ("data", "body", "json", "form", "payload"):
            if name in props:
                body += self._object_keys(*props[name])
        headers = self._object_keys(*props["headers"]) if "headers" in props else []
        if not method and (body and kind != "config"):
            method = "POST"
        if len(either) == 2:
            return any([self.add(url_parts, m, kind, tok, conf, params, body, headers, bare=True) for m in either])
        if not method and not has_method and not body and p.is_punc(brace - 1, "(") \
                and not (p.kind(brace - 3) == ID and p.val(brace - 3) == "new"):
            # request({url, headers}) with no method: GET in axios, fetch-likes and jQuery alike
            method, conf = "GET", min(conf, 0.75)
        return self.add(url_parts, method, kind, tok, conf, params, body, headers, bare=bool(method))

    # ── passes ────────────────────────────────────────────────────────────────

    def run(self) -> Extraction:
        p = self.p
        tokens = p.tokens
        for i in range(p.n):
            t = tokens[i]
            if t[K] == ID:
                if p.is_punc(i + 1, "("):
                    self._call(i, i + 1)
                elif p.is_punc(i + 1, "<") and t[V] in _METHOD_CALLS:
                    # TypeScript generics in recovered sources:  http.post<User>(url, body)
                    j = i + 2
                    while j < min(p.n, i + 14) and (p.kind(j) == ID or (p.kind(j) == PUNC and p.val(j) in (".", ",", "[", "]", "|", "<"))):
                        j += 1
                    while p.is_punc(j, ">") or p.is_punc(j, ">>"):
                        j += 1
                    if p.is_punc(j, "(") and j > i + 2:
                        self._call(i, j)
                elif p.is_punc(i + 1, ":") and i > 0 and tokens[i - 1][K] == PUNC and tokens[i - 1][V] in ("{", ","):
                    self._property(i)
            elif t[K] == STR and p.is_punc(i + 1, ":") and i > 0 and tokens[i - 1][K] == PUNC \
                    and tokens[i - 1][V] in ("{", ","):
                self._property(i)
        self._strings()
        self.out.endpoints.sort(key=lambda e: (not e.is_call, e.url, e.method))
        self.out.graphql = sorted(set(self.out.graphql))
        self.out.routes = sorted(set(self.out.routes))
        self.out.bases = sorted(set(self.out.bases))
        return self.out

    def _call(self, i: int, paren: int) -> None:
        p = self.p
        name = p.val(i)
        member = i > 0 and (p.is_punc(i - 1, ".") or p.is_punc(i - 1, "?."))
        receiver = str(p.val(i - 2)) if member and p.kind(i - 2) == ID else ""
        args = p.call_args(paren)
        if not args:
            return
        a0, b0 = args[0]

        # fetch(url, {method, headers, body})
        if name == "fetch" and (not member or receiver in ("window", "self", "globalThis", "this", "global")):
            url = self._eval_range(a0, b0)
            if receiver == "this":
                # a class's own fetch(module, params) (ethers' EtherscanProvider): only an unmistakable URL counts
                literal, text = "".join(t for v, t in url if not v), render(url)
                if not (literal.startswith(("/", "http://", "https://", "//")) or
                        (text.startswith("{") and "}/" in text) or _APIISH_PREFIX.match(literal)):
                    return
            if len(args) > 1 and p.is_punc(args[1][0], "{"):
                if self._from_config(args[1][0], "fetch", i, url, default_method="GET", conf=0.92):
                    return
            self.add(url, "GET", "fetch", i, 0.9)
            return

        # client.get("/x") · axios.post(url, data, cfg) · $.getJSON(…) · this.http.put(…)
        if member and name in _METHOD_CALLS:
            httpish = bool(_HTTPISH.search(receiver)) or (p.is_punc(i - 2, ")") if member else False) \
                or name.startswith("$")
            url = self._eval_range(a0, b0)
            if not url:
                return
            literal = "".join(t for v, t in url if not v)
            if not httpish:
                # map.get("a/b"), params.get("id"), i18n.get("errors/notFound"): an unknown
                # receiver must be handed something that is unmistakably a URL.
                text = render(url)
                if not (literal.startswith(("/", "http://", "https://", "//")) or
                        (text.startswith("{") and "}/" in text) or _APIISH_PREFIX.match(literal)):
                    return
            method = _METHOD_CALLS[name]
            body: List[str] = []
            params: List[str] = []
            headers: List[str] = []
            rest = args[1:]
            if method in ("POST", "PUT", "PATCH") and rest:
                body = self._object_keys(*rest[0])
                rest = rest[1:]
            if rest and p.is_punc(rest[0][0], "{"):
                cfg = p.object_at(rest[0][0])
                if "params" in cfg:
                    params = self._object_keys(*cfg["params"])
                if "headers" in cfg:
                    headers = self._object_keys(*cfg["headers"])
            kind = "axios" if "axios" in receiver.lower() else "ajax" if receiver == "$" else "client"
            self.add(url, method, kind, i, 0.9 if httpish else 0.8, params, body, headers, strong=True)
            return

        # axios({url, method}) · $.ajax({...}) · request({...}) · axios(url, cfg)
        if name in _REQUEST_FUNCS or (member and name in ("ajax", "request") and _HTTPISH.search(receiver or "$")):
            kind = "axios" if "axios" in (name + receiver).lower() else "ajax" if name == "ajax" else "client"
            if p.is_punc(a0, "{"):
                self._from_config(a0, kind, i, conf=0.9)
            else:
                url = self._eval_range(a0, b0)
                if url and len(args) > 1 and p.is_punc(args[1][0], "{"):
                    self._from_config(args[1][0], kind, i, url, conf=0.9)
                elif url:
                    self.add(url, "", kind, i, 0.85)
            return

        # xhr.open("POST", url)
        if member and name == "open" and len(args) >= 2:
            method = self._static(a0, b0).upper()
            if method in HTTP_METHODS:
                self.add(self._eval_range(*args[1]), method, "xhr", i, 0.92)
            return

        # new WebSocket(url) · new EventSource(url) · navigator.sendBeacon(url)
        if name in ("WebSocket", "EventSource") and p.kind(i - 1) == ID and p.val(i - 1) == "new":
            self.add(self._eval_range(a0, b0), "GET", name.lower(), i, 0.9)
            return
        if name == "sendBeacon":
            self.add(self._eval_range(a0, b0), "POST", "beacon", i, 0.9)
            return

        # router.push("/x") · navigate("/x"): client-side routes, not requests
        if name in _NAV_CALLS:
            text = self._static(a0, b0)
            if text.startswith("/") and url_like(text, [(False, text)], strong=True) and not _STATIC_ASSET.search(text):
                self.out.routes.append(split_query(text)[0])
                self.claim(a0, b0)

    def _property(self, i: int) -> None:
        """A property key inside an object literal: request configs, route tables, base URLs."""
        p = self.p
        key = str(p.val(i))
        brace = self.enclosing[i]
        if brace < 0 or not p.is_punc(brace, "{"):
            return
        if key in ("baseURL", "baseUrl", "apiUrl", "apiURL", "apiBase", "apiBaseUrl", "API_URL", "API_BASE_URL",
                   "apiEndpoint", "serverUrl", "backendUrl"):
            parts, _ = p.eval_expr(i + 2)
            text = render(parts)
            if parts and (_ABSOLUTE.match(text) or text.startswith("/")) and len(text) > 1:
                host = re.match(r"^(?:[a-z]+:)?//([^/?#{}:]+)", text)
                if not (host and NOISE_HOSTS.search(host.group(1))):
                    self.out.bases.append(text)
            return
        if key in ("url", "uri", "endpoint"):
            props = p.object_at(brace)
            if any(k in props for k in ("method", "type", "verb", "data", "body", "params", "headers")):
                self._from_config(brace, "config", i, conf=0.85)
            elif key == "url" and len(props) == 1 and p.is_punc(brace - 1, "(") and p.kind(brace - 2) == ID \
                    and not (p.kind(brace - 3) == ID and p.val(brace - 3) == "new"):
                # request({url: "/api/tags"}) — the whole config is the URL
                parts, end = p.eval_expr(i + 2)
                text = render(parts)
                literal = "".join(t for v, t in parts if not v)
                if parts and end >= p.pairs[brace] and not _STATIC_ASSET.search(text) and (
                        _APIISH_ANY.search(text) or literal.startswith("/") and literal.count("/") >= 2):
                    self._from_config(brace, "config", i, conf=0.7)
            return
        if key in ("to", "href", "routerLink", "pathname", "redirectTo", "returnTo"):
            # <Link to="/settings">, {href: "/pricing"}: navigation inside the app, not a request
            a, b = i + 2, p._value_end(i + 2, p.pairs[brace] if p.pairs[brace] > 0 else p.n)
            text = self._static(a, b)
            if text.startswith("/") and not text.startswith("//") and len(text) < 200 \
                    and url_like(text, [(False, text)], strong=True) and not _STATIC_ASSET.search(text) \
                    and not _APIISH_ANY.search(text):
                self.out.routes.append(split_query(text)[0])
                self.claim(a, b)
            return
        if key == "path":
            props = p.object_at(brace)
            if _ROUTE_SIBLINGS & props.keys():
                text = self._static(*props["path"])
                if text and len(text) < 200 and re.fullmatch(r"[\w\-./:*()?{}@~]*", text):
                    self.out.routes.append(text if text.startswith("/") else "/" + text)
                    self.claim(*props["path"])

    def _strings(self) -> None:
        """Everything not already explained by a call site: GraphQL documents and bare URL-like strings."""
        p = self.p
        tokens = p.tokens
        i = 0
        while i < p.n:
            t = tokens[i]
            if t[K] not in (STR, TPL):
                i += 1
                continue
            raw = t[V] if t[K] == STR else "".join(s for s in t[V] if isinstance(s, str))
            if len(raw) > 20 and "{" in raw:
                for m in _GRAPHQL_OP.finditer(raw):
                    self.out.graphql.append((m.group(1), m.group(2)))
            if i in self.claimed:
                i += 1
                continue
            start = p.expr_start(i)
            parts, end = p.eval_expr(start)
            if end <= i:                      # could not evaluate through this literal
                parts, end = p.eval_expr(i)
                start = i
            covered = range(start, max(end, i + 1))
            if not any(k in self.claimed for k in covered):
                text = render(parts)
                api_like = bool(_APIISH_ANY.search(text)) or bool(_ABSOLUTE.match(text))
                self.add(parts, "", "string", i, 0.65 if api_like else 0.45, strong=False)
            self.claimed.update(covered)
            i = max(end, i + 1)


def extract(p: Program, file: str = "") -> Extraction:
    """All requests, GraphQL operations, routes and API bases in one tokenized file."""
    return _Extractor(p, file).run()
