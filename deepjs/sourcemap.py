"""
deepjs.sourcemap — recover original sources from exposed source maps.

A production bundle that ships its `.map` ships its source: original file
tree, real identifier names, comments, and the exact list of npm packages.
This module finds the map reference, parses the map (including indexed maps),
and returns the embedded sources with *safe* output paths.

Source names in a map are attacker-controlled input from the scanned site
(`webpack:///../../../../etc/cron.d/x`). Every path is sanitised so that
recovered files can only ever be written inside the chosen output directory.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote

_MAP_REF = re.compile(r"(?://|/\*)[#@]\s*sourceMappingURL=([^\s'\"*]+)")
_SCHEME = re.compile(r"^(?:webpack(?:-internal)?|ng|rollup|vite|turbopack|file|rsc|parcel|\w+-webpack)://+", re.I)
_PACKAGE = re.compile(r"node_modules/((?:@[\w.\-~]+/)?[\w.\-~]+)")
_UNSAFE = re.compile(r"[^\w.\-@+ ()\[\]]")
_RUNTIME_SOURCE = re.compile(r"^(?:\(webpack\)|webpack/|external |ignored\||multi |\(lazy\)|<anon|~/)|\$_lazy_route|/webpack/(?:bootstrap|runtime)")

MAX_SOURCES = 20000
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_MAP_BYTES = 80 * 1024 * 1024


@dataclass
class RecoveredSource:
    name:    str            # original name from the map
    path:    str            # sanitised relative path (safe to join to an output directory)
    content: Optional[str]  # None when the map lists the file without embedding it

    @property
    def is_dependency(self) -> bool:
        return "node_modules/" in self.name.replace("\\", "/")

    @property
    def is_runtime(self) -> bool:
        return bool(_RUNTIME_SOURCE.search(self.name))


@dataclass
class SourceMap:
    sources:  List[RecoveredSource] = field(default_factory=list)
    packages: Set[str] = field(default_factory=set)
    version:  int = 0

    @property
    def app_sources(self) -> List[RecoveredSource]:
        return [s for s in self.sources if s.content and not s.is_dependency and not s.is_runtime]


def find_map_reference(js: str) -> Optional[str]:
    """The last `//# sourceMappingURL=` in a script (only the tail is searched)."""
    tail = js[-4096:] if len(js) > 4096 else js
    refs = _MAP_REF.findall(tail)
    return refs[-1] if refs else None


def decode_inline_map(ref: str) -> Optional[bytes]:
    """`data:application/json;base64,…` → bytes."""
    if not ref.startswith("data:"):
        return None
    head, _, payload = ref.partition(",")
    try:
        if ";base64" in head:
            return base64.b64decode(payload + "=" * (-len(payload) % 4))
        return unquote(payload).encode("utf-8")
    except Exception:
        return None


def safe_relative_path(name: str) -> str:
    """
    Turn a source name from a map into a relative path that cannot escape the
    directory it is joined to: no scheme, no drive, no absolute root, no `..`.
    """
    n = _SCHEME.sub("", name.strip().replace("\\", "/"))
    n = n.split("?", 1)[0].split("#", 1)[0]
    n = re.sub(r"^[A-Za-z]:", "", n)                 # C:/…
    parts: List[str] = []
    for seg in n.split("/"):
        seg = seg.strip()
        if seg in ("", ".", ".."):
            continue                                  # '..' is dropped, never honoured
        seg = _UNSAFE.sub("_", seg).strip(". ") or "_"
        parts.append(seg[:120])
    if not parts:
        return "unnamed"
    path = "/".join(parts[-12:])                      # bound depth
    return path[:400]


def is_inside(base: str, target: str) -> bool:
    base_real = os.path.realpath(base)
    target_real = os.path.realpath(target)
    return target_real == base_real or target_real.startswith(base_real + os.sep)


def parse_source_map(data) -> Optional[SourceMap]:
    """Parse a source map (bytes or str). Returns None if it is not one."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_MAP_BYTES:
            return None
        text = bytes(data).decode("utf-8", errors="replace")
    else:
        text = data
    text = text.lstrip("\ufeff")
    if text.startswith(")]}'"):                       # XSSI guard some servers prepend
        text = text.split("\n", 1)[-1]
    try:
        doc = json.loads(text)
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None

    out = SourceMap(version=int(doc.get("version", 0) or 0) if str(doc.get("version", "")).isdigit() else 0)
    seen: Dict[str, int] = {}

    def take(section: dict) -> None:
        sources = section.get("sources")
        if not isinstance(sources, list):
            return
        contents = section.get("sourcesContent")
        contents = contents if isinstance(contents, list) else []
        root = section.get("sourceRoot") if isinstance(section.get("sourceRoot"), str) else ""
        for i, name in enumerate(sources):
            if len(out.sources) >= MAX_SOURCES:
                return
            if not isinstance(name, str) or not name:
                continue
            full = (root.rstrip("/") + "/" + name) if root and not _SCHEME.match(name) else name
            for m in _PACKAGE.finditer(full.replace("\\", "/")):
                out.packages.add(m.group(1))
            content = contents[i] if i < len(contents) and isinstance(contents[i], str) else None
            if content is not None and len(content) > MAX_SOURCE_BYTES:
                content = content[:MAX_SOURCE_BYTES]
            path = safe_relative_path(full)
            n = seen.get(path, 0)
            seen[path] = n + 1
            if n:                                      # two sources sanitised to the same path
                stem, dot, ext = path.rpartition(".")
                path = f"{stem}~{n}.{ext}" if dot else f"{path}~{n}"
            out.sources.append(RecoveredSource(name=full, path=path, content=content))

    if isinstance(doc.get("sections"), list):          # indexed map
        for sec in doc["sections"]:
            if isinstance(sec, dict) and isinstance(sec.get("map"), dict):
                take(sec["map"])
    take(doc)
    return out if out.sources else None


def write_sources(smap: SourceMap, out_dir: str) -> Tuple[int, int]:
    """Write embedded sources under `out_dir`. Returns (written, skipped)."""
    written = skipped = 0
    os.makedirs(out_dir, exist_ok=True)
    for src in smap.sources:
        if src.content is None:
            continue
        target = os.path.join(out_dir, *src.path.split("/"))
        if not is_inside(out_dir, target):             # defence in depth; sanitising already prevents this
            skipped += 1
            continue
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w", encoding="utf-8", errors="replace", newline="") as fh:
                fh.write(src.content)
            written += 1
        except OSError:
            skipped += 1
    return written, skipped
