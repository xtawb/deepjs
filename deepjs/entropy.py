"""
deepjs.entropy — is this string a secret, a label, or filler?

A front-end bundle is full of strings that sit under secret-sounding names and
are nothing of the kind: `password: "Password"` is a form label, `token:
"auth_token"` is a storage key, `apiKey: "YOUR_API_KEY"` is a placeholder.
This module scores a value on how machine-generated it looks and recognises
the common kinds of filler, so that only credible values are reported.
"""

from __future__ import annotations

import math
import re
from typing import Tuple

# ── placeholders ───────────────────────────────────────────────────────────────

_WORDS = (
    "your my the some a an insert enter put add replace change example sample dummy fake test testing "
    "demo placeholder redacted removed hidden masked secret password passwd token apikey key value "
    "string none null nil undefined true false todo tbd fixme changeme changeit default empty foo bar "
    "baz xxx here own real actual api access private auth client pass id goes this me it name user "
    "username not set unset required optional go new old confirm current repeat again type field"
).split()
_ALT = "|".join(sorted(set(_WORDS), key=len, reverse=True))
# possessive quantifiers: linear time on any input
_PLACEHOLDER = re.compile(rf"^(?:{_ALT})(?:[\W_]*+(?:{_ALT}|\d{{1,4}}+(?!\d)))*+[\W_]*+$", re.I)
_FILLER = re.compile(
    r"^(?:x{4,}|\*{3,}|\.{3,}|-{3,}|_{3,}|#{3,}|0{6,}|1234567890?|123456(?:78)?|abc(?:d(?:e(?:f\w*)?)?)?(?:123\w*)?"
    r"|qwerty\w*|asdf\w*|password\d*|letmein\d*)$",
    re.I,
)
_TEMPLATE = re.compile(
    r"""(?ix)
      ^<[^>]*>$ | ^\[[^\]]*\]$ | \{\{.*\}\} | \$\{[^}]*\} | ^\$[A-Za-z_]\w*$ | ^%[A-Za-z_]\w*%$
    | ^\{[A-Za-z_][\w.]*\}$ | ^:[A-Za-z_]\w*$ | ^__[A-Z_]+__$
    | ^(?:process\.env|import\.meta\.env|window\.|env\.)
    """
)
_HINTS = ("example", "placeholder", "changeme", "dummy", "redacted", "your_", "your-", "<your", "xxxxx", "*****")
_LEET = (
    str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}),
    str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}),
)


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("\"'`")
    if not v:
        return True
    low = v.lower()
    if _FILLER.match(v) or _PLACEHOLDER.match(v) or _TEMPLATE.search(v):
        return True
    if any(h in low for h in _HINTS):
        return True
    if len(v) >= 4 and len(set(low)) <= 2:
        return True
    if len(v) <= 24 and any(c in "013457@$" for c in v):
        for table in _LEET:
            plain = low.translate(table)
            if _PLACEHOLDER.match(plain) or _FILLER.match(plain):
                return True
    return False


# ── language model ─────────────────────────────────────────────────────────────

# The most frequent English letter bigrams: identifiers and prose hit this table
# ~85% of the time, uniformly random letters ~34%.
_BIGRAMS = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me
de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot
il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai
sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag
if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba
ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki
rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc oa dd nf nk ok nn ft sk sy lf ps nv sq eq
ws ks aw ze iz az gs ja jo je ju ya xt xp
""".split())
_ALPHA_RUN = re.compile(r"[A-Za-z]{3,}")


def wordiness(token: str) -> float:
    """0..1 — how much the token reads like words rather than random characters."""
    runs = _ALPHA_RUN.findall(token or "")
    if not runs:
        return 0.0
    covered = sum(len(r) for r in runs)
    hits = total = flips = 0
    for run in runs:
        low = run.lower()
        for i in range(len(low) - 1):
            total += 1
            if low[i:i + 2] in _BIGRAMS:
                hits += 1
            if run[i].isupper() != run[i + 1].isupper():
                flips += 1
    if not total:
        return 0.0
    lang = max(0.0, min(1.0, (hits / total - 0.38) / 0.42))
    case_penalty = max(0.0, 1.0 - max(0.0, flips / total - 0.22) * 2.5)
    return round(lang * (covered / len(token)) * case_penalty, 3)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((k / n) * math.log2(k / n) for k in counts.values())


def _cls(c: str) -> int:
    return 0 if c.islower() else 1 if c.isupper() else 2 if c.isdigit() else 3


def randomness(token: str) -> float:
    """0..1 — how machine-generated the token looks."""
    n = len(token)
    if n < 6:
        return 0.0
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        alphabet = 16
    elif re.fullmatch(r"[A-Za-z0-9+/=_\-]+", token):
        alphabet = 64
    else:
        alphabet = 94
    norm = min(shannon(token) / (math.log2(min(n, alphabet)) or 1.0), 1.0)
    norm = max(0.0, min(1.0, (norm - 0.60) / 0.35))
    trans = sum(1 for i in range(n - 1) if _cls(token[i]) != _cls(token[i + 1])) / (n - 1)
    return round(0.40 * norm + 0.35 * (1.0 - wordiness(token)) + 0.25 * min(trans / 0.45, 1.0), 3)


# ── benign shapes ──────────────────────────────────────────────────────────────

_BENIGN = [
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),          # uuid
    re.compile(r"^(?:sha(?:1|256|384|512)|md5)[-:=]", re.I),                                              # integrity
    re.compile(r"^[+-]?[\d.,_]+(?:e[+-]?\d+)?[a-zA-Z%]{0,3}$"),                                           # number / unit
    re.compile(r"^[v^~<>=]*\d+(?:\.\d+){1,3}(?:[-+.][\w.]+)*$"),                                          # version
    re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$"),   # date
    re.compile(r"^(?:[a-z][a-z0-9+.\-]*:)?//[^\s:@/]+(?::\d+)?(?:[/?#]\S*)?$", re.I),                     # url, no creds
    re.compile(r"^data:[\w/+.\-]+[;,]", re.I),                                                            # data uri
    re.compile(r"^#[0-9a-fA-F]{3,8}$"),                                                                   # colour
    re.compile(r"^(?:[A-Za-z]:)?[\w.\-@~/\\]*\.(?:js|mjs|css|map|json|html?|png|jpe?g|gif|svg|ico|webp|woff2?|ttf)$", re.I),
    re.compile(r"^[MmLlHhVvCcSsQqTtAaZz0-9\s,.\-]+$"),                                                    # svg path data
    re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),                                                       # CONSTANT_NAME
]
# kebab / snake / dotted / event:name — benign only when it also reads like words
_IDENTIFIERISH = re.compile(r"^[A-Za-z][A-Za-z0-9]*(?:[-_.:/][A-Za-z0-9]+)+$")


def classify(value: str, strong_key: bool = False) -> Tuple[str, float]:
    """
    Returns (label, score). label ∈ {"secret", "uncertain", "weak", "benign", "placeholder"}.
    `strong_key` means the value sits under an unambiguous secret-bearing name.
    """
    v = (value or "").strip()
    if not v or is_placeholder(v):
        return "placeholder", 0.0
    if " " in v and (v.count(" ") >= 2 or not strong_key):
        return "benign", 0.05                      # prose / label
    if not strong_key and re.fullmatch(r"[0-9a-fA-F]{16,}", v):
        return "benign", 0.15                      # digest / id with no secret-bearing name
    words = wordiness(v)
    for rx in _BENIGN:
        if rx.match(v):
            return "benign", 0.05
    if words >= 0.45 and _IDENTIFIERISH.match(v):
        return "benign", 0.06
    has_digit_or_symbol = bool(re.search(r"[\d!@#$%^&*+=/\\|~?]", v))
    if not has_digit_or_symbol and (not v.isascii() or words >= 0.45):
        return "benign", 0.08                      # a word, a label, a translation, an identifier
    score = randomness(v)
    if len(v) < 12:
        score -= 0.25
    elif len(v) >= 32:
        score += 0.05
    if strong_key:
        score += 0.22
    score = round(max(0.0, min(1.0, score)), 3)
    if score >= 0.62:
        return "secret", score
    if score >= 0.50:
        return "uncertain", score
    return "weak", score
