"""
deepjs.fetch — a small, polite HTTP client (standard library only).

GET only. Honours a size cap, a timeout, an optional delay between requests,
custom headers, and an upstream proxy — point `--proxy` at Burp or ZAP and
every request DeepJS makes shows up in your proxy history.
"""

from __future__ import annotations

import gzip
import ssl
import threading
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlsplit

from deepjs import __version__

DEFAULT_UA = f"DeepJS/{__version__} (+https://github.com/xtawb/deepjs)"


@dataclass
class Response:
    url:      str                    # final URL after redirects
    status:   int = 0
    headers:  Dict[str, str] = field(default_factory=dict)
    body:     bytes = b""
    error:    str = ""
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.error

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    def text(self) -> str:
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        if "charset=" in ctype.lower():
            charset = ctype.lower().split("charset=", 1)[1].split(";")[0].strip().strip("\"'") or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class Fetcher:
    def __init__(
        self,
        timeout: float = 15.0,
        max_bytes: int = 20 * 1024 * 1024,
        delay: float = 0.0,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        insecure: bool = False,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.delay = delay
        self.headers = {"User-Agent": user_agent, "Accept": "*/*", "Accept-Encoding": "gzip, deflate"}
        self.headers.update(headers or {})
        self.requests = 0
        self._lock = threading.Lock()
        self._last = 0.0

        handlers = []
        ctx = ssl.create_default_context()
        if insecure or proxy:
            # An intercepting proxy re-signs TLS with its own CA; verification
            # is the proxy's job in that setup.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))      # ignore ambient proxy env for predictability
        self._opener = urllib.request.build_opener(*handlers)

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        with self._lock:
            wait = self._last + self.delay - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def get(self, url: str) -> Response:
        if urlsplit(url).scheme not in ("http", "https"):
            return Response(url=url, error="unsupported scheme")
        self._throttle()
        with self._lock:
            self.requests += 1
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(self.max_bytes + 1)
                truncated = len(raw) > self.max_bytes
                raw = raw[: self.max_bytes]
                headers = {k.lower(): v for k, v in resp.headers.items()}
                enc = headers.get("content-encoding", "").lower()
                try:
                    if "gzip" in enc:
                        raw = gzip.decompress(raw) if not truncated else zlib.decompressobj(31).decompress(raw)
                    elif "deflate" in enc:
                        try:
                            raw = zlib.decompress(raw)
                        except zlib.error:
                            raw = zlib.decompress(raw, -15)
                except Exception:
                    pass                                          # serve what we got
                return Response(url=resp.geturl(), status=resp.status, headers=headers,
                                body=raw[: self.max_bytes * 4], truncated=truncated)
        except urllib.error.HTTPError as exc:
            headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
            exc.close()
            return Response(url=url, status=exc.code, headers=headers, error=f"HTTP {exc.code}")
        except Exception as exc:
            reason = getattr(exc, "reason", exc)
            return Response(url=url, error=f"{type(exc).__name__}: {reason}"[:200])
