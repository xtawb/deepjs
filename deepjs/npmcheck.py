"""
deepjs.npmcheck — dependency-confusion exposure (opt-in: --check-npm).

A source map lists every package bundled into the application. If one of those
names is *not* registered on the public npm registry, it is an internal
package — and anyone can register that name publicly. A build that is not
pinned to a private registry may then install the public impostor.

This module only asks the public registry whether each name exists (one GET
per package). It never registers, publishes or installs anything.

What to do with a hit (defensive): claim the name / scope on the public
registry yourself, and pin the scope to your private registry in `.npmrc`.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, Iterable, List
from urllib.parse import quote

REGISTRY = "https://registry.npmjs.org/"
_VALID = re.compile(r"^(?:@[a-z0-9][a-z0-9._~\-]*/)?[a-z0-9][a-z0-9._~\-]*$")
_BUILTIN = frozenset({
    "fs", "path", "os", "http", "https", "url", "util", "events", "stream", "crypto", "buffer", "zlib", "net",
    "tls", "dns", "child_process", "assert", "querystring", "process", "timers", "vm", "module", "worker_threads",
})


@dataclass
class PackageStatus:
    name:   str
    status: str        # "public" | "unclaimed" | "unknown"
    detail: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {"package": self.name, "status": self.status, "detail": self.detail}


def candidate_names(packages: Iterable[str]) -> List[str]:
    out = []
    for name in sorted(set(packages)):
        n = name.strip()
        if n and n not in _BUILTIN and len(n) <= 214 and _VALID.match(n):
            out.append(n)
    return out


def check_packages(packages: Iterable[str], fetcher, workers: int = 8, limit: int = 2000) -> List[PackageStatus]:
    """Ask the public npm registry whether each package name exists."""
    names = candidate_names(packages)[:limit]

    def one(name: str) -> PackageStatus:
        resp = fetcher.get(REGISTRY + quote(name, safe="@"))
        if resp.status == 200:
            return PackageStatus(name, "public")
        if resp.status == 404:
            return PackageStatus(name, "unclaimed", "not registered on the public npm registry")
        return PackageStatus(name, "unknown", resp.error or f"HTTP {resp.status}")

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, names))
