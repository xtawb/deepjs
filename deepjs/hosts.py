"""
deepjs.hosts — every host a bundle mentions, sorted into what it means.

  in-scope       a (sub)domain of the target
  cloud-storage  S3 / GCS / Azure Blob / Firebase / Spaces / R2 / OSS buckets
  internal       private addresses, localhost, *.internal / *.corp / *.local
  third-party    everything else

Non-production markers (dev., staging., uat., …) are flagged on any class.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from deepjs.endpoints import NOISE_HOSTS

_URL_HOST = re.compile(
    r"(?:(?:https?|wss?|ftp)://|(?<![\w:/])//)"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,30}[A-Za-z]{2,24}|localhost|\d{1,3}(?:\.\d{1,3}){3})"
    r"(?::(\d{2,5}))?"
)
_BARE_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")

# Suffixes under which registrations happen one level deeper (enough for scoping).
_TWO_LEVEL = frozenset("""
co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp ne.jp or.jp co.kr co.in net.in org.in com.br com.mx
com.ar com.tr com.sa com.eg com.sg com.my com.hk com.tw com.cn net.cn org.cn co.za co.il com.ua com.pl com.co
com.pe com.ph com.pk com.ng co.id co.th com.vn github.io herokuapp.com vercel.app netlify.app pages.dev
web.app firebaseapp.com azurewebsites.net cloudfront.net amazonaws.com appspot.com
""".split())

_CLOUD = [
    ("aws-s3",          re.compile(r"(?:^|\.)s3[.\-][\w.\-]*amazonaws\.com(?:\.cn)?$|\.s3\.amazonaws\.com$|^s3\.amazonaws\.com$")),
    ("gcs",             re.compile(r"(?:^|\.)storage\.googleapis\.com$|(?:^|\.)storage\.cloud\.google\.com$")),
    ("firebase",        re.compile(r"\.firebaseio\.com$|^firebasestorage\.googleapis\.com$|\.firebasedatabase\.app$")),
    ("azure-blob",      re.compile(r"\.(?:blob|file|dfs|table|queue)\.core\.windows\.net$")),
    ("do-spaces",       re.compile(r"\.digitaloceanspaces\.com$")),
    ("cloudflare-r2",   re.compile(r"\.r2\.cloudflarestorage\.com$|\.r2\.dev$")),
    ("aliyun-oss",      re.compile(r"\.oss-[\w\-]+\.aliyuncs\.com$")),
    ("backblaze-b2",    re.compile(r"\.backblazeb2\.com$")),
    ("supabase",        re.compile(r"\.supabase\.(?:co|in)$")),
]
_INTERNAL_SUFFIX = re.compile(r"\.(?:local|internal|intranet|corp|lan|home|localdomain|private|cluster\.local|svc)$")
_NONPROD = re.compile(r"(?:^|[.\-])(?:dev|develop|development|staging|stage|stg|uat|qa|test|testing|sandbox|preprod|pre-prod|"
                      r"preview|beta|alpha|demo|int|integration|local)(?:[.\-\d]|$)", re.I)


@dataclass
class Host:
    name:    str
    kind:    str                       # in-scope | cloud-storage | internal | third-party
    service: str = ""                  # cloud provider, when kind == cloud-storage
    nonprod: bool = False
    ports:   List[str] = field(default_factory=list)
    files:   List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"host": self.name, "kind": self.kind, "service": self.service, "non_production": self.nonprod,
                "ports": self.ports, "files": self.files[:5]}


def registrable(host: str) -> str:
    """Naive eTLD+1 — good enough to decide "same organisation"."""
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def classify_host(host: str, scope: Iterable[str]) -> Host:
    h = host.lower().strip(".")
    kind, service = "third-party", ""
    for name, rx in _CLOUD:
        if rx.search(h):
            kind, service = "cloud-storage", name
            break
    else:
        if h == "localhost" or is_private_ip(h) or _INTERNAL_SUFFIX.search(h):
            kind = "internal"
        else:
            reg = registrable(h)
            if any(reg == s or h == s or h.endswith("." + s) for s in scope):
                kind = "in-scope"
    return Host(name=h, kind=kind, service=service, nonprod=bool(_NONPROD.search(h)) and kind != "internal")


class HostCollector:
    """Accumulates hosts across files."""

    def __init__(self, scope: Iterable[str]) -> None:
        self.scope: Set[str] = {s.lower() for s in scope if s}
        self.hosts: Dict[str, Host] = {}

    def add(self, host: str, file: str = "", port: Optional[str] = None) -> None:
        h = host.lower().strip(".")
        if not h or NOISE_HOSTS.search(h):
            return
        entry = self.hosts.get(h)
        if entry is None:
            entry = self.hosts[h] = classify_host(h, self.scope)
        if port and port not in entry.ports:
            entry.ports.append(port)
        if file and file not in entry.files and len(entry.files) < 5:
            entry.files.append(file)

    def feed(self, text: str, file: str = "") -> None:
        """Pull every host out of one string literal."""
        if "//" in text:
            for m in _URL_HOST.finditer(text):
                self.add(m.group(1), file, m.group(2))
        elif self.scope and len(text) < 254 and "." in text and _BARE_HOST.match(text):
            # a bare hostname only counts when it belongs to the target
            if any(text.lower() == s or text.lower().endswith("." + s) for s in self.scope):
                self.add(text, file)

    def sorted(self) -> List[Host]:
        order = {"in-scope": 0, "cloud-storage": 1, "internal": 2, "third-party": 3}
        return sorted(self.hosts.values(), key=lambda h: (order[h.kind], h.name))
