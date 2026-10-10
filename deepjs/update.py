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

Where the operating system manages Python (PEP 668: Kali, Debian, Ubuntu…)
pip refuses to change it unless told to. A copy that pip put there can only
be replaced the way it was installed — with --break-system-packages — and the
update says so before it asks. --no-deps goes with it, so that the one thing
pip touches in the system's Python is deepjs itself.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import sysconfig
import time
import urllib.request
from dataclasses import dataclass
from importlib import metadata
from typing import Callable, List, Optional, TextIO, Tuple

from deepjs import __author__, __version__
from deepjs.report import Style, use_colour

RELEASES_API = "https://api.github.com/repos/xtawb/deepjs/releases/latest"
RELEASES_PAGE = "https://github.com/xtawb/deepjs/releases/latest"
MADE_BY = f"by {__author__} · https://github.com/xtawb/deepjs"
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


_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*$")
_BULLET = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_SPAN = re.compile(r"`([^`]+)`|\*\*([^*]+)\*\*")


def _spans(text: str, st: Style) -> str:
    return _SPAN.sub(lambda m: st.cyan(m.group(1)) if m.group(1) else st.bold(m.group(2)), text)


def coloured(lines: List[str], st: Style) -> List[str]:
    """
    Release notes are Markdown. In colour they are shown as a terminal would show them: headings,
    bullets, `code` and **emphasis** by colour instead of by their marks. Without colour they are
    left exactly as written. `lines` come from `printable`, so no escape sequence in them is theirs.
    """
    if not st.on:
        return lines
    out, fenced = [], False
    for line in lines:
        if line.lstrip().startswith("```"):
            fenced = not fenced             # the fence itself says nothing once its lines are coloured
            continue
        heading, bullet = _HEADING.match(line), _BULLET.match(line)
        if fenced:
            out.append(st.cyan(line))
        elif heading:
            out.append(st.bold(st.cyan(heading.group(1))))
        elif bullet:
            out.append(bullet.group(1) + st.green("-") + " " + _spans(bullet.group(2), st))
        else:
            out.append(_spans(line, st))
    return out


def install_command(version: str, into_system: bool = False) -> List[str]:
    """
    What `deepjs update` runs: pip, for the interpreter that is running deepjs, on that release's archive.
    `into_system`: this interpreter is the operating system's (see `externally_managed`).
    """
    numbers = parse_version(version)
    if not numbers:                         # the tag comes from the network: only digits and dots reach pip
        raise ValueError(f"not a version: {version!r}")
    archive = RELEASE_ARCHIVE.format(version=".".join(map(str, numbers)))
    options = ["--no-deps", "--break-system-packages"] if into_system else []
    return [sys.executable, "-m", "pip", "install", "--upgrade", *options, archive]


def externally_managed() -> bool:
    """Is this the operating system's own Python (PEP 668), which pip will not change unless told to?"""
    if sys.prefix != sys.base_prefix:
        return False                        # a virtual environment — pipx's included — is nobody's but its owner's
    try:
        return os.path.isfile(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED"))
    except Exception:
        return False


def installed_by() -> str:
    """What installed this copy — "pip", "debian", … — or "" when it left no record."""
    try:
        return (metadata.distribution("deepjs").read_text("INSTALLER") or "").strip().lower()
    except Exception:
        return ""


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
               checkout: Optional[bool] = None, managed: Optional[bool] = None, installer: Optional[str] = None,
               colour: Optional[bool] = None) -> int:
    """
    Look for a newer release, show what changed, and install it if the user agrees. With nothing
    newer, what is shown is what the release already installed changed.
    Returns a process exit status. `colour`: None decides by where `out` goes (a terminal, and
    NO_COLOR not set). The other injectable pieces exist for the tests.
    """
    out = out or sys.stdout
    st = Style(use_colour(out) if colour is None else colour)

    def say(line: str = "") -> None:
        print(line, file=out, flush=True)   # pip writes to the same place: keep the lines in order

    try:
        release = fetch()
    except Exception as exc:
        say(st.red(f"deepjs: could not ask GitHub for the latest release ({type(exc).__name__}). Nothing was changed."))
        return 1
    if not release.version:
        say(st.red(f"deepjs: the latest release has no version this copy understands — see {RELEASES_PAGE}"))
        return 1

    def what_changed() -> None:
        notes = coloured(printable(release.notes), st)
        if notes:
            say()
            say(st.bold("What changed:"))
            for line in notes:
                say("  " + line)
        say()
        say("Release page: " + st.cyan(release.url if release.url.startswith("https://github.com/xtawb/deepjs/") else RELEASES_PAGE))

    if is_newer(current, release.version):              # a copy built from the repository, ahead of any release
        say(st.green(f"deepjs {current} is ahead of the latest release, {release.version}."))
        say(st.dim(MADE_BY))
        return 0
    if not is_newer(release.version, current):
        say(st.green(f"deepjs {current} is the latest release."))
        say(st.dim(MADE_BY))
        what_changed()
        return 0

    say(st.bold(st.green(f"deepjs {release.version}")) + f" is available (this is {current}).")
    say(st.dim(MADE_BY))
    what_changed()

    if is_source_checkout() if checkout is None else checkout:
        say("This copy runs from a source checkout, so there is nothing for pip to replace: update it with `git pull`.")
        return 0
    into_system = externally_managed() if managed is None else managed
    if into_system:
        by = installed_by() if installer is None else installer
        say(st.yellow("This Python belongs to the operating system (PEP 668): pip does not change it unless told to."))
        if by != "pip":
            say(f"deepjs was put there by {by or 'something other than pip'}, so it is not pip's to replace. "
                "Update it the way it was installed.")
            return 1
        say("deepjs was installed into it with pip, so replacing it takes the same --break-system-packages. With "
            "--no-deps, deepjs's own files are all that the command below replaces.")
    command = install_command(release.version, into_system)
    say("To install it, this will run:")
    say("  " + st.bold(as_typed(command)))
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
        say(st.green(f"deepjs is now {release.version}."))
    else:
        say(st.red(f"pip exited with status {status}. deepjs may not have been updated — run the command above to see why."))
    return status
