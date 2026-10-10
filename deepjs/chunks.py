"""
deepjs.chunks — find the JavaScript a browser never loads.

A crawler (or a proxy history) only sees the chunks that the pages you visited
needed. A single-page app usually ships many more — admin screens, feature-
flagged flows, rarely used dialogs — and the bundler leaves a complete index of
them in the entry bundle. This module reads that index:

  * webpack 4/5 (and Next.js): the runtime's chunk-filename function, e.g.
        r.u = e => "static/js/" + ({3:"admin"}[e] || e) + "." + {3:"9f1c",7:"02ab"}[e] + ".chunk.js"
    is evaluated for every chunk id it knows.
  * Vite / Rollup / ES modules: dynamic `import("./Admin-4f2a.js")` and
    `__vite__mapDeps([...])` lists are plain strings ending in `.js`.
  * Next.js `_buildManifest.js`: every route and the chunks it needs.
  * HTML: `<script src>`, module preloads, and inline scripts.
"""

from __future__ import annotations

import html as html_lib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from deepjs.jseval import Program, is_static, render
from deepjs.lexer import ID, K, NUM, PUNC, STR, TPL, V

_SCRIPT_SRC = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s>]+))", re.I)
_LINK_TAG = re.compile(r"<link\b[^>]*>", re.I)
_ATTR = re.compile(r"\b([a-zA-Z\-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")
_INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)([^>]*)>(.*?)</script\s*>", re.I | re.S)
# a real file name: at least one name character before the extension (".chunk.js" alone is a suffix)
_JS_FILE = re.compile(r"^(?:[\w.\-~@+%\[\]]*/)*[\w\[@~][\w.\-~@+%\[\]]*\.m?js(?:\?[\w.\-=&%]*)?$")
_BASE_TAG = re.compile(r"<base\b[^>]*?\bhref\s*=\s*[\"']([^\"']+)[\"']", re.I)

MAX_CHUNKS_PER_FILE = 1500
MAX_INLINE_BYTES = 2 * 1024 * 1024


@dataclass
class HtmlScripts:
    urls:   List[str] = field(default_factory=list)
    inline: List[str] = field(default_factory=list)


def scripts_from_html(html: str, base_url: str = "") -> HtmlScripts:
    """External script URLs (absolute) and inline script bodies of an HTML page."""
    out = HtmlScripts()
    m = _BASE_TAG.search(html)
    base = urljoin(base_url, m.group(1)) if m else base_url
    seen: Set[str] = set()

    def push(ref: str) -> None:
        ref = ref.strip()
        if not ref or ref.startswith(("data:", "javascript:", "blob:", "about:")):
            return
        url = urljoin(base, ref) if base else ref
        if url not in seen:
            seen.add(url)
            out.urls.append(url)

    for m in _SCRIPT_SRC.finditer(html):
        push(m.group(1) or m.group(2) or m.group(3) or "")
    for tag in _LINK_TAG.findall(html):
        attrs = {k.lower(): (a or b or c) for k, a, b, c in _ATTR.findall(tag)}
        rel = attrs.get("rel", "").lower()
        href = attrs.get("href", "")
        if href and (rel in ("modulepreload",) or (rel in ("preload", "prefetch") and
                                                   (attrs.get("as", "").lower() == "script" or re.search(r"\.m?js(?:\?|$)", href)))):
            push(href)
    for attrs, body in _INLINE_SCRIPT.findall(html):
        kind = re.search(r"\btype\s*=\s*[\"']?([^\"'\s>]+)", attrs, re.I)
        mime = kind.group(1).lower() if kind else ""
        if mime in ("text/template", "text/html", "text/x-template", "text/css"):
            continue
        body = body.strip()
        if body and len(body) <= MAX_INLINE_BYTES:
            out.inline.append(body)
    return out


# ── page links and forms (for the crawler) ─────────────────────────────────────

_HREF = re.compile(r"<(?:a|area)\b[^>]*?\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_FRAME = re.compile(r"<i?frame\b[^>]*?\bsrc\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form\s*>", re.I | re.S)
_FIELD = re.compile(r"<(?:input|select|textarea|button)\b[^>]*?\bname\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))", re.I)
_NOT_A_PAGE = re.compile(r"^(?:mailto:|tel:|sms:|javascript:|data:|blob:|about:|#|whatsapp:|skype:)", re.I)


@dataclass
class Form:
    method: str
    action: str
    fields: List[str] = field(default_factory=list)


@dataclass
class PageLinks:
    pages: List[str] = field(default_factory=list)
    forms: List[Form] = field(default_factory=list)


def links_from_html(html: str, base_url: str = "") -> PageLinks:
    """Navigable links (absolute, fragment-free) and forms of an HTML page."""
    out = PageLinks()
    m = _BASE_TAG.search(html)
    base = urljoin(base_url, m.group(1)) if m else base_url
    seen: Set[str] = set()

    def absolute(ref: str) -> str:
        ref = html_lib.unescape(ref).strip()
        if not ref or _NOT_A_PAGE.match(ref):
            return ""
        return (urljoin(base, ref) if base else ref).split("#", 1)[0]

    for rx in (_HREF, _FRAME):
        for m in rx.finditer(html):
            url = absolute(m.group(1) or m.group(2) or m.group(3) or "")
            if url and url not in seen:
                seen.add(url)
                out.pages.append(url)
    for attrs, body in _FORM.findall(html):
        a = {k.lower(): (x or y or z) for k, x, y, z in _ATTR.findall(attrs)}
        action = absolute(a.get("action", "")) or base_url.split("#", 1)[0].split("?", 1)[0]
        method = (a.get("method") or "GET").strip().upper()
        names = [html_lib.unescape(x or y or z) for x, y, z in _FIELD.findall(body)]
        if action:
            out.forms.append(Form(method if method in ("GET", "POST", "PUT", "PATCH", "DELETE") else "GET",
                                  action, list(dict.fromkeys(n for n in names if n))))
    return out


# ── webpack chunk-filename function ────────────────────────────────────────────

def _static_map(p: Program, brace: int) -> Optional[Dict[str, str]]:
    """{1:"a", 2:"b"} → {"1": "a", "2": "b"}; None if any value is not a literal."""
    out: Dict[str, str] = {}
    for key, (a, b) in p.object_at(brace).items():
        if b - a != 1:
            return None
        t = p.tokens[a]
        if t[K] == STR:
            out[key] = t[V]
        elif t[K] == NUM:
            out[key] = str(t[V])
        else:
            return None
    return out or None


def _lookup_at(p: Program, i: int, param: Optional[str] = None) -> Optional[Tuple[Dict[str, str], str, int]]:
    """
    A chunk-map lookup starting at token `i`, in either spelling:
        {1:"a"}[e]        ({1:"a"})[e]
    Returns (map, parameter name, index after the lookup) or None.
    """
    brace = i
    wrapped = False
    if p.is_punc(i, "(") and p.is_punc(i + 1, "{") and p.pairs[i + 1] > 0 and p.pairs[i] == p.pairs[i + 1] + 1:
        brace, wrapped = i + 1, True
    if not p.is_punc(brace, "{"):
        return None
    close = p.pairs[brace]
    if close < 0:
        return None
    j = close + (2 if wrapped else 1)
    if not (p.is_punc(j, "[") and p.kind(j + 1) == ID and p.is_punc(j + 2, "]")):
        return None
    name = p.val(j + 1)
    if param is not None and name != param:
        return None
    m = _static_map(p, brace)
    if m is None:
        return None
    return m, name, j + 3


def _term_bounds_left(p: Program, end: int) -> int:
    """Start index of the term that ends at token `end` (inclusive)."""
    t = p.tokens[end]
    if t[K] == PUNC and t[V] in (")", "]"):
        o = p.pairs[end]
        if o < 0:
            return end
        if t[V] == "]" and o > 0:
            if p.is_punc(o - 1, "}") and p.pairs[o - 1] >= 0:
                return p.pairs[o - 1]                 # {map}[e]
            if p.is_punc(o - 1, ")") and p.pairs[o - 1] >= 0:
                return p.pairs[o - 1]                 # ({map})[e]
        return o
    if t[K] == ID:
        k = end
        while k >= 2 and p.is_punc(k - 1, ".") and p.kind(k - 2) == ID:
            k -= 2
        return k
    return end


def _term_end_right(p: Program, start: int) -> int:
    """Index after the term that starts at token `start`."""
    t = p.tokens[start]
    if t[K] == PUNC and t[V] in ("{", "("):
        c = p.pairs[start]
        if c < 0:
            return start + 1
        if p.is_punc(c + 1, "[") and p.pairs[c + 1] > 0:
            return p.pairs[c + 1] + 1
        return c + 1
    if t[K] == ID:
        k = start + 1
        while p.is_punc(k, ".") and p.kind(k + 1) == ID:
            k += 2
        return k
    return start + 1


def _eval_chunk_expr(p: Program, a: int, b: int, param: str, chunk: str) -> Optional[str]:
    """Evaluate the filename expression over tokens [a, b) for one chunk id."""
    out: List[str] = []
    i = a
    while i < b:
        t = p.tokens[i]
        if t[K] == PUNC and t[V] == "+":
            i += 1
            continue
        if t[K] == STR:
            out.append(t[V])
            i += 1
            continue
        if t[K] == NUM:
            out.append(str(t[V]))
            i += 1
            continue
        if t[K] == ID and t[V] == param and not p.is_punc(i + 1, "."):
            out.append(chunk)
            i += 1
            continue
        if t[K] == PUNC and t[V] in ("{", "("):
            look = _lookup_at(p, i, param)
            if look is not None:                        # {map}[e]  /  ({map})[e]
                m, _, end = look
                if chunk not in m:
                    return None
                out.append(m[chunk])
                i = end
                continue
            if t[V] == "(":
                c = p.pairs[i]
                if c < 0:
                    return None
                inner = _lookup_at(p, i + 1, param)
                if inner is not None:                   # ({map}[e] || e)
                    m, _, end = inner
                    has_default = p.is_punc(end, "||") or p.is_punc(end, "??")
                    if chunk in m:
                        out.append(m[chunk])
                    elif has_default:
                        out.append(chunk)
                    else:
                        return None
                else:
                    sub = _eval_chunk_expr(p, i + 1, c, param, chunk)
                    if sub is None:
                        return None
                    out.append(sub)
                i = c + 1
                continue
            return None
        if t[K] == ID:
            # public path (r.p) and friends contribute nothing we can know here
            i = _term_end_right(p, i)
            continue
        return None
    return "".join(out)


def webpack_chunks(p: Program) -> List[str]:
    """Filenames produced by the bundler's chunk-filename function, for every known chunk id."""
    found: List[str] = []
    seen_expr: Set[int] = set()
    for i in range(p.n - 3):
        if not (p.is_punc(i, "{") or (p.is_punc(i, "(") and p.is_punc(i + 1, "{"))):
            continue
        look = _lookup_at(p, i)
        if look is None:
            continue
        m, param, lookup_end = look
        if not m or len(m) > 5000:
            continue
        # grow the concatenation around the lookup
        start = i
        if start > 0 and p.is_punc(start - 1, "(") and p.pairs[start - 1] >= lookup_end:
            start -= 1                                  # ({map}[e] || e)
        while start >= 2 and p.is_punc(start - 1, "+"):
            start = _term_bounds_left(p, start - 2)
        end = _term_end_right(p, start)
        while p.is_punc(end, "+") and end + 1 < p.n:
            end = _term_end_right(p, end + 1)
        if end < lookup_end or start in seen_expr:
            continue
        seen_expr.add(start)
        text_tokens = [p.tokens[k][V] for k in range(start, end) if p.tokens[k][K] == STR]
        if not any(isinstance(x, str) and re.search(r"\.(?:m?js|css)$", x) for x in text_tokens):
            continue                                    # not a filename expression
        ids: Set[str] = set()
        for k in range(start, end):
            inner = _lookup_at(p, k, param)
            if inner is not None:
                ids.update(inner[0].keys())
        for cid in sorted(ids):
            name = _eval_chunk_expr(p, start, end, param, cid)
            if name and name.endswith((".js", ".mjs")) and len(name) < 300:
                found.append(name)
                if len(found) >= MAX_CHUNKS_PER_FILE:
                    return list(dict.fromkeys(found))
    return list(dict.fromkeys(found))


def public_path(p: Program) -> str:
    """webpack's `__webpack_require__.p = "/static/"` when it is a single literal."""
    vals = p.props.get("p")
    if vals and len(vals) == 1:
        v = next(iter(vals))
        if v.startswith(("/", "http://", "https://", "//")) or v == "":
            return v
    return ""


@dataclass
class Discovery:
    scripts: List[str] = field(default_factory=list)       # absolute URLs (or relative paths for local input)
    routes:  List[str] = field(default_factory=list)       # routes named by a build manifest


def _resolve(ref: str, script_url: str, pub: str) -> str:
    """Resolve a chunk reference the way the bundler would."""
    if not script_url:
        return ref
    if re.match(r"^(?:https?:)?//", ref) or ref.startswith("/"):
        return urljoin(script_url, ref)
    if pub:
        return urljoin(urljoin(script_url, pub), ref)
    parts = urlsplit(script_url)
    # Next.js: chunk names are relative to /_next/, wherever the referring script lives
    if "/_next/" in parts.path and ref.startswith("static/"):
        prefix = parts.path.split("/_next/", 1)[0] + "/_next/"
        return urljoin(f"{parts.scheme}://{parts.netloc}{prefix}", ref)
    return urljoin(script_url, ref)


def discover(p: Program, script_url: str = "") -> Discovery:
    """Other scripts (and manifest routes) referenced by one tokenized script."""
    out = Discovery()
    pub = public_path(p)
    refs: List[str] = []

    refs.extend(webpack_chunks(p))

    manifest = any(t[K] == ID and t[V] in ("__BUILD_MANIFEST", "__SSG_MANIFEST") for t in p.tokens[:400])
    for i, t in enumerate(p.tokens):
        if t[K] == STR:
            s = t[V]
            if 4 < len(s) < 300 and s.endswith((".js", ".mjs")) or (".js?" in s and len(s) < 300):
                if _JS_FILE.match(s) and not s.startswith(("node_modules/", "webpack/")):
                    refs.append(s)
            if manifest and s.startswith("/") and p.is_punc(i + 1, ":") and len(s) < 200:
                out.routes.append(s)
        elif t[K] == TPL:
            parts, _ = p.eval_expr(i)
            if is_static(parts):
                s = render(parts)
                if 4 < len(s) < 300 and _JS_FILE.match(s):
                    refs.append(s)

    seen: Set[str] = set()
    for ref in refs:
        url = _resolve(ref, script_url, pub)
        if url not in seen:
            seen.add(url)
            out.scripts.append(url)
    out.routes = sorted(set(out.routes))
    return out
