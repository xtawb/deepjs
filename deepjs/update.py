"""
deepjs.update — say so when a newer release exists.

One anonymous GET to GitHub's releases API, at most once a day; the answer is
kept in the user's cache directory. Nothing is downloaded or installed, and
nothing about the scan is sent. Not used in `serve` mode (the host tool makes
its own check through its own networking), with `--no-update-check`, or when
DEEPJS_NO_UPDATE_CHECK is set. Every failure — offline, rate-limited, an
unwritable cache — is silent: a scan never fails or waits because of this.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from typing import Callable, Optional, Tuple

from deepjs import __version__

RELEASES_API = "https://api.github.com/repos/xtawb/deepjs/releases/latest"
RELEASES_PAGE = "https://github.com/xtawb/deepjs/releases/latest"
UPGRADE = "pip install --upgrade git+https://github.com/xtawb/deepjs"
CHECK_EVERY = 24 * 3600
TIMEOUT = 3.0

_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)$")


def parse_version(text: str) -> Tuple[int, ...]:
    """'v0.10.1' → (0, 10, 1); () for anything that is not a plain dotted version."""
    m = _VERSION.match((text or "").strip())
    return tuple(int(part) for part in m.group(1).split(".")) if m else ()


def is_newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def cache_file() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
    elif sys.platform == "darwin":
        base = os.path.join(os.path.expanduser("~"), "Library", "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "deepjs", "update.json")


def _fetch_latest() -> str:
    request = urllib.request.Request(RELEASES_API, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"deepjs/{__version__}"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        tag = json.loads(response.read(200_000).decode("utf-8", "replace")).get("tag_name", "")
    return ".".join(map(str, parse_version(tag)))


def latest_version(now: Optional[float] = None, fetch: Callable[[], str] = _fetch_latest,
                   path: Optional[str] = None) -> str:
    """The latest released version, from the cache when it is fresh. '' when it cannot be known."""
    now = time.time() if now is None else now
    path = path or cache_file()
    try:
        with open(path, encoding="utf-8") as fh:
            cached = json.load(fh)
        if now - float(cached["checked"]) < CHECK_EVERY and float(cached["checked"]) <= now:
            return str(cached.get("latest", ""))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        latest = fetch()
    except Exception:                       # offline, proxy, rate limit, bad JSON: try again tomorrow, quietly
        latest = ""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"checked": now, "latest": latest}, fh)
    except OSError:
        pass
    return latest


def notice(current: str = __version__, **kwargs) -> str:
    """One line to show the user, or '' when there is nothing newer (or checking is switched off)."""
    if os.environ.get("DEEPJS_NO_UPDATE_CHECK"):
        return ""
    latest = latest_version(**kwargs)
    if not is_newer(latest, current):
        return ""
    return f"deepjs {latest} is available (this is {current}):  {UPGRADE}   ·   {RELEASES_PAGE}"
