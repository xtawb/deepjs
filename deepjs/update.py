"""
deepjs.update — newer releases: say so, and install one when asked.

The notice. After a scan, one anonymous GET to GitHub's releases API, at most
once a day; the answer is kept in the user's cache directory. Nothing is
downloaded or installed, and nothing about the scan is sent. Not used in
`serve` mode (the host tool makes its own check through its own networking),
with `--no-update-check`, or when DEEPJS_NO_UPDATE_CHECK is set. Every failure
— offline, rate-limited, an unwritable cache — is silent: a scan never fails
or waits because of this.

The update. `deepjs update` shows what changed in the latest release and the
exact command it is about to run, asks, and then lets pip install that
release. Nothing is ever installed without being asked for: a tool that
replaces its own code unprompted is a tool whose behaviour you cannot pin.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, List, Optional, TextIO, Tuple

from deepjs import __version__

RELEASES_API = "https://api.github.com/repos/xtawb/deepjs/releases/latest"
RELEASES_PAGE = "https://github.com/xtawb/deepjs/releases/latest"
# a release is installed from its own tagged archive: no git needed, and not whatever `main` is today
RELEASE_ARCHIVE = "https://github.com/xtawb/deepjs/archive/refs/tags/v{version}.zip"
MAX_NOTES_LINES = 40
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


@dataclass
class Release:
    version: str        # "0.4.2", or "" when the tag is not a plain version
    notes: str = ""     # the release's description, as written
    url: str = RELEASES_PAGE


def fetch_release(timeout: float = 10.0) -> Release:
    """The latest release, straight from GitHub. Raises when it cannot be reached or read."""
    request = urllib.request.Request(RELEASES_API, headers={
        "Accept": "application/vnd.github+json", "User-Agent": f"deepjs/{__version__}"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read(1_000_000).decode("utf-8", "replace"))
    return Release(version=".".join(map(str, parse_version(str(data.get("tag_name", ""))))),
                   notes=str(data.get("body") or ""), url=str(data.get("html_url") or RELEASES_PAGE))


def _fetch_latest() -> str:
    return fetch_release(TIMEOUT).version


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
    return f"deepjs {latest} is available (this is {current}) — `deepjs update` shows what changed and installs it."


# ── installing a release ───────────────────────────────────────────────────────

def printable(text: str, max_lines: int = MAX_NOTES_LINES) -> List[str]:
    """Release notes as lines safe to print: nothing that drives a terminal, bounded length."""
    lines = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        lines.append("".join(c for c in raw if c == "\t" or c.isprintable())[:300])
    while lines and not lines[-1].strip():
        lines.pop()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["…"]
    return lines


def install_command(version: str) -> List[str]:
    """What `deepjs update` runs: pip, for the interpreter that is running deepjs, on that release's archive."""
    numbers = parse_version(version)
    if not numbers:                         # the tag comes from the network: only digits and dots reach pip
        raise ValueError(f"not a version: {version!r}")
    archive = RELEASE_ARCHIVE.format(version=".".join(map(str, numbers)))
    return [sys.executable, "-m", "pip", "install", "--upgrade", archive]


def as_typed(command: List[str]) -> str:
    """A command as it would be typed into this platform's shell."""
    return subprocess.list2cmdline(command) if os.name == "nt" else shlex.join(command)


def is_source_checkout() -> bool:
    """Is this copy running from a git checkout rather than an installed package?"""
    package = os.path.dirname(os.path.abspath(__file__))
    return os.path.exists(os.path.join(os.path.dirname(package), ".git"))


def run_update(assume_yes: bool = False, out: Optional[TextIO] = None, current: str = __version__,
               fetch: Callable[[], Release] = fetch_release, ask: Callable[[str], str] = input,
               run: Callable[[List[str]], int] = subprocess.call, interactive: Optional[bool] = None,
               checkout: Optional[bool] = None) -> int:
    """
    Look for a newer release, show what changed, and install it if the user agrees.
    Returns a process exit status. The injectable pieces exist for the tests.
    """
    out = out or sys.stdout

    def say(line: str = "") -> None:
        print(line, file=out, flush=True)   # pip writes to the same place: keep the lines in order

    try:
        release = fetch()
    except Exception as exc:
        say(f"deepjs: could not ask GitHub for the latest release ({type(exc).__name__}). Nothing was changed.")
        return 1
    if not release.version:
        say(f"deepjs: the latest release has no version this copy understands — see {RELEASES_PAGE}")
        return 1
    if not is_newer(release.version, current):
        say(f"deepjs {current} is the latest release.")
        return 0

    say(f"deepjs {release.version} is available (this is {current}).")
    notes = printable(release.notes)
    if notes:
        say()
        say("What changed:")
        for line in notes:
            say("  " + line)
    say()
    say(f"Release page: {release.url if release.url.startswith('https://github.com/xtawb/deepjs/') else RELEASES_PAGE}")

    if is_source_checkout() if checkout is None else checkout:
        say("This copy runs from a source checkout, so there is nothing for pip to replace: update it with `git pull`.")
        return 0
    command = install_command(release.version)
    say("To install it, this will run:")
    say("  " + as_typed(command))
    if not assume_yes:
        unattended = "Nothing was changed. Run `deepjs update --yes` to install without being asked."
        if not (sys.stdin.isatty() if interactive is None else interactive):
            say(unattended)
            return 0
        try:
            answer = ask("Install it now? [y/N] ")
        except EOFError:                    # nobody there after all: Windows calls NUL a terminal
            say()
            say(unattended)
            return 0
        except KeyboardInterrupt:
            say()
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            say("Nothing was changed.")
            return 0
    status = run(command)
    if status == 0:
        say(f"deepjs is now {release.version}.")
    else:
        say(f"pip exited with status {status}. deepjs may not have been updated — run the command above to see why.")
    return status
