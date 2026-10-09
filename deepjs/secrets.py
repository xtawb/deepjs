"""
deepjs.secrets — credentials in front-end code, with judgement.

Three things a regex list cannot do, and this module does:

  1. **Know what is public by design.** A Stripe `pk_live_`, a Firebase web
     config, a Sentry DSN, a Supabase *anon* JWT are meant to ship to the
     browser. They are reported as informational, with what to check instead —
     not as leaks. A Supabase *service_role* JWT in the same shape is critical.
  2. **Use the name the value is assigned to.** Because the tokenizer knows the
     property / variable / header a literal belongs to, `clientSecret: "…"` is
     judged differently from `label: "…"`.
  3. **Reject filler.** Placeholders, form labels, storage-key names and
     translations under secret-sounding names are not reported.

Values are masked unless the caller asks for them; a SHA-256 fingerprint lets two scans be compared without storing the secret.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from deepjs.entropy import classify, is_placeholder
from deepjs.jseval import Program, is_static, render
from deepjs.lexer import ID, K, PUNC, STR, TPL, V

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Secret:
    kind:       str
    severity:   str
    confidence: float
    value:      str                 # raw value — removed from reports unless revealed
    key:        str = ""            # property / variable / header the value belongs to
    file:       str = ""
    line:       int = 0
    note:       str = ""
    public:     bool = False        # public by design (not a leak)

    @property
    def masked(self) -> str:
        v = self.value
        if len(v) <= 8:
            return v[:2] + "…"
        if len(v) <= 20:
            return v[:4] + "…" + v[-2:]
        return v[:8] + "…" + v[-4:]

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self, reveal: bool = False) -> Dict[str, object]:
        d = {
            "kind": self.kind, "severity": self.severity, "confidence": round(self.confidence, 2),
            "value": self.value if reveal else self.masked, "fingerprint": self.fingerprint,
            "key": self.key, "file": self.file, "line": self.line, "note": self.note, "public": self.public,
        }
        return d


# ── typed patterns ─────────────────────────────────────────────────────────────
# (kind, regex, severity, public_by_design, note)

_B = r"(?<![A-Za-z0-9_\-])"
_E = r"(?![A-Za-z0-9_\-])"

_TYPED: List[Tuple[str, "re.Pattern[str]", str, bool, str]] = [
    (k, re.compile(rx), sev, pub, note) for k, rx, sev, pub, note in [
        ("AWS_ACCESS_KEY", r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", "critical", False,
         "AWS access key ID in front-end code. Long-lived keys must never ship to a browser."),
        ("GOOGLE_API_KEY", _B + r"(AIza[0-9A-Za-z_\-]{35})" + _E, "low", True,
         "Google API key. Normal in web apps — confirm it is restricted by HTTP referrer and to the APIs it needs."),
        ("GOOGLE_OAUTH_CLIENT_SECRET", _B + r"(GOCSPX-[A-Za-z0-9_\-]{28})" + _E, "high", False,
         "Google OAuth client secret. Web clients must not embed it."),
        ("GOOGLE_OAUTH_ACCESS_TOKEN", _B + r"(ya29\.[0-9A-Za-z_\-]{40,})", "high", False, "Google OAuth access token."),
        ("FIREBASE_FCM_SERVER_KEY", _B + r"(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140})" + _E, "high", False,
         "Firebase Cloud Messaging server key — allows sending push notifications as the app."),
        ("GITHUB_TOKEN", _B + r"(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})" + _E, "critical", False,
         "GitHub token."),
        ("GITLAB_TOKEN", _B + r"(glpat-[A-Za-z0-9_\-]{20})" + _E, "critical", False, "GitLab personal access token."),
        ("SLACK_TOKEN", _B + r"(xox[abeposr]-(?:[0-9A-Za-z]+-)+[0-9A-Za-z]{6,})" + _E, "high", False, "Slack token."),
        ("SLACK_WEBHOOK", r"(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})", "medium", False,
         "Slack incoming webhook — anyone with the URL can post to the channel."),
        ("DISCORD_WEBHOOK", r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[A-Za-z0-9_\-]{40,})", "medium", False,
         "Discord webhook URL."),
        ("STRIPE_SECRET_KEY", _B + r"((?:sk|rk)_live_[0-9A-Za-z]{20,})" + _E, "critical", False, "Stripe live secret key."),
        ("STRIPE_TEST_SECRET_KEY", _B + r"((?:sk|rk)_test_[0-9A-Za-z]{20,})" + _E, "low", False, "Stripe test-mode secret key."),
        ("STRIPE_PUBLISHABLE_KEY", _B + r"(pk_(?:live|test)_[0-9A-Za-z]{20,})" + _E, "info", True,
         "Stripe publishable key — public by design."),
        ("OPENAI_API_KEY", _B + r"(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})" + _E, "critical", False,
         "OpenAI API key in front-end code — usable by anyone who loads the page."),
        ("ANTHROPIC_API_KEY", _B + r"(sk-ant-[A-Za-z0-9_\-]{40,})" + _E, "critical", False,
         "Anthropic API key in front-end code — usable by anyone who loads the page."),
        ("SENDGRID_API_KEY", _B + r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})" + _E, "high", False, "SendGrid API key."),
        ("MAILCHIMP_API_KEY", _B + r"([0-9a-f]{32}-us\d{1,2})" + _E, "high", False, "Mailchimp API key."),
        ("TWILIO_API_KEY", r"\b(SK[0-9a-f]{32})\b", "high", False, "Twilio API key SID (check for its secret nearby)."),
        ("NPM_TOKEN", r"\b(npm_[A-Za-z0-9]{36})\b", "high", False, "npm access token."),
        ("HUGGINGFACE_TOKEN", r"\b(hf_[A-Za-z0-9]{34,})\b", "high", False, "Hugging Face token."),
        ("DIGITALOCEAN_TOKEN", r"\b(do[opr]_v1_[a-f0-9]{64})\b", "critical", False, "DigitalOcean token."),
        ("SHOPIFY_TOKEN", r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b", "high", False, "Shopify access token."),
        ("TELEGRAM_BOT_TOKEN", r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})" + _E, "high", False, "Telegram bot token."),
        ("SQUARE_TOKEN", _B + r"(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43})" + _E, "high", False, "Square token."),
        ("BRAINTREE_TOKEN", r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})", "critical", False, "PayPal / Braintree production access token."),
        ("FACEBOOK_ACCESS_TOKEN", r"\b(EAA[A-Za-z0-9]{80,})\b", "medium", False, "Facebook access token."),
        ("MAPBOX_SECRET_TOKEN", _B + r"(sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,})", "high", False, "Mapbox secret token."),
        ("MAPBOX_PUBLIC_TOKEN", _B + r"(pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,})", "info", True,
         "Mapbox public token — public by design; confirm URL restrictions."),
        ("SENTRY_DSN", r"(https?://[0-9a-f]{32}@[\w.\-]*sentry[\w.\-]*/\d+)", "info", True, "Sentry DSN — public by design."),
        ("RECAPTCHA_KEY", _B + r"(6L[0-9A-Za-z_\-]{38})" + _E, "info", True,
         "reCAPTCHA key. Site keys are public; a *secret* key has the same shape — check which one this is."),
        ("PRIVATE_KEY", r"(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)", "critical", False, "Private key material."),
        ("AZURE_STORAGE_KEY", r"(?i)AccountKey=([A-Za-z0-9+/=]{80,})", "critical", False, "Azure storage account key."),
        ("URL_CREDENTIALS", r"\b[a-z][a-z0-9+.\-]{1,12}://[^/\s:@'\"<>{}]{1,64}:([^/\s:@'\"<>{}]{3,128})@[\w.\-]+", "high", False,
         "URL with an embedded password."),
        ("BEARER_TOKEN", r"(?i)^bearer\s+([A-Za-z0-9_\-.~+/=]{20,})$", "high", False, "Hardcoded bearer token."),
        ("BASIC_AUTH", r"(?i)^basic\s+([A-Za-z0-9+/]{12,}={0,2})$", "high", False, "Hardcoded HTTP Basic credentials."),
    ]
]

# One cheap test decides whether a string is worth running the list above on.
_PREFILTER = re.compile(
    r"AKIA|ASIA|AIza|GOCSPX-|ya29\.|AAAA[A-Za-z0-9_\-]{7}:|gh[pousr]_|github_pat_|glpat-|xox[abeposr]-|hooks\.slack\.com"
    r"|discord(?:app)?\.com/api/webhooks|[sr]k_(?:live|test)_|pk_(?:live|test)_|sk-(?:proj|svcacct|admin|ant)-|T3BlbkFJ"
    r"|SG\.|-us\d{1,2}\b|SK[0-9a-f]{32}|npm_|hf_|do[opr]_v1_|shp(?:at|ca|pa|ss)_|:AA[A-Za-z0-9_\-]{33}|sq0|access_token\$"
    r"|EAA[A-Za-z0-9]{20}|[ps]k\.eyJ|sentry|6L[0-9A-Za-z_\-]{38}|-----BEGIN|AccountKey=|://[^/\s:@]{1,64}:[^/\s@]{3,}@"
    r"|^[Bb]earer\s|^[Bb]asic\s|eyJ[A-Za-z0-9_\-]{8,}\.eyJ"
)
_JWT = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,})\.(eyJ[A-Za-z0-9_\-]{8,})\.([A-Za-z0-9_\-]*)")

# ── key-name semantics (camelCase / kebab-case normalised to snake_case) ───────

_STRONG_KEY = re.compile(
    r"(?:^|_)(?:pass(?:word|wd|phrase)?|pwd|secret|api_?secret|client_?secret|app_?secret|consumer_?secret|"
    r"api_?key|apikey|x_api_key|access_?token|auth_?token|bearer_?token|refresh_?token|private_?key|secret_?key|"
    r"signing_?key|encryption_?key|master_?key|authorization|aws_?secret\w*|access_?key_?secret|credentials?)(?:_|$|\d)"
)
_WEAK_KEY = re.compile(r"(?:^|_)(?:token|auth|jwt|bearer|sas|salt|hmac|signature|license_?key|access_?key)(?:_|$|\d)")
_NEGATIVE_KEY = re.compile(
    r"""(?x)
      public | publishable | (?:^|_)pub(?:_|$) | site_?key | client_?id | app_?id | project_?id | sender_?id
    | measurement | tracking | analytics | (?:^|_)dsn(?:_|$) | (?:^|_)anon(?:_|$)
    | (?:storage|cache|query|sort|primary|foreign|partition|row|map|object|translation|i18n|locale|session|cookie
        |local_storage|header|param|field|form|input|test|data|react|event|route|error|message|option)_?(?:key|token)s?(?:_|$)
    | (?:key|token|password|secret|auth)_(?:name|id|ids|type|url|uri|endpoint|path|file|field|label|title|placeholder
        |hint|prefix|suffix|header|param|key|length|len|min\w*|max\w*|regex|pattern|policy|strength|expir\w*|ttl
        |required|enabled|error|message|msg|text|input|form|reset\w*|confirm\w*|changed?|visible|mask|icon|class|style)
    | (?:^|_)(?:next|prev|previous|page|continuation|csrf|xsrf|nonce)_?(?:page_?)?token
    | (?:max|min|num|total|input|output|prompt|completion)_tokens? | tokeniz
    | (?:^|_)(?:label|title|placeholder|hint|help|text|message|msg|description|desc|name|type|regex|pattern|format
        |selector|class_?name|style|icon|event|action|route|path|url|uri|endpoint|href|src|error|warning)$
    | keyword | keyboard | keyframe | hotkey | passive | bypass | compass
    """
)
_FIREBASE_SIBLINGS = frozenset({"authDomain", "projectId", "storageBucket", "messagingSenderId", "databaseURL", "appId"})


def normalise_key(key: str) -> str:
    k = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key or "")
    return re.sub(r"[\s.\-]+", "_", k).lower().strip("_")


def key_strength(key: str) -> int:
    """2 strong secret-bearing name, 1 weak, 0 neutral, -1 reference / label / public."""
    k = normalise_key(key)
    if not k:
        return 0
    if _NEGATIVE_KEY.search(k):
        return -1
    if _STRONG_KEY.search(k):
        return 2
    if _WEAK_KEY.search(k):
        return 1
    return 0


# ── JWT ────────────────────────────────────────────────────────────────────────

def _b64json(seg: str) -> Optional[dict]:
    try:
        data = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8", "replace"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def inspect_jwt(token: str, now: Optional[float] = None) -> Optional[Tuple[str, str, bool, str]]:
    """(kind, severity, public, note) for a JWT, or None if it is not one. Decode only."""
    m = _JWT.search(token or "")
    if not m:
        return None
    header, payload = _b64json(m.group(1)), _b64json(m.group(2))
    if header is None or payload is None or not ("alg" in header or "typ" in header):
        return None
    now = time.time() if now is None else now
    role = str(payload.get("role", ""))
    iss = str(payload.get("iss", ""))
    exp = payload.get("exp")
    exp = float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
    when = time.strftime("%Y-%m-%d", time.gmtime(exp)) if exp else ""

    if "supabase" in iss or ("ref" in payload and role in ("anon", "service_role")):
        if role == "service_role":
            return ("SUPABASE_SERVICE_ROLE_KEY", "critical", False,
                    "Supabase service_role key — bypasses Row Level Security. Must never reach a browser.")
        return ("SUPABASE_ANON_KEY", "info", True,
                "Supabase anon key — public by design; data protection depends on Row Level Security policies.")
    if str(header.get("alg", "")).lower() == "none" or not m.group(3):
        return ("JWT_UNSIGNED", "medium", False, "Hardcoded JWT with no signature (alg=none).")
    if exp is not None and exp < now:
        return ("JWT_EXPIRED", "low", False, f"Hardcoded JWT, expired {when}.")
    if exp is None:
        return ("JWT_HARDCODED", "high", False, f"Hardcoded JWT with no expiry{f' (issuer {iss[:60]})' if iss else ''}.")
    return ("JWT_HARDCODED", "medium", False, f"Hardcoded JWT, valid until {when}{f' (issuer {iss[:60]})' if iss else ''}.")


# ── scanning ───────────────────────────────────────────────────────────────────

def _typed_matches(text: str) -> List[Tuple[str, str, str, bool, str]]:
    """All typed-pattern hits in `text` as (kind, value, severity, public, note)."""
    if len(text) < 12 or not _PREFILTER.search(text):
        return []
    out: List[Tuple[str, str, str, bool, str]] = []
    for kind, rx, sev, pub, note in _TYPED:
        for m in rx.finditer(text):
            value = m.group(1)
            if kind not in ("PRIVATE_KEY",) and is_placeholder(value):
                continue
            if kind == "BASIC_AUTH":
                try:
                    decoded = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
                except Exception:
                    continue
                if ":" not in decoded or is_placeholder(decoded.split(":", 1)[1]):
                    continue
                note = f"Hardcoded HTTP Basic credentials for user '{decoded.split(':', 1)[0][:40]}'."
            out.append((kind, value, sev, pub, note))
    j = inspect_jwt(text)
    if j and not any(k.startswith("MAPBOX") for k, *_ in out):
        m = _JWT.search(text)
        out.append((j[0], m.group(0), j[1], j[2], j[3]))
    return out


def _key_context(p: Program, i: int) -> str:
    """The property / variable / header name the literal at token `i` belongs to."""
    t = p.tokens
    if i >= 2 and t[i - 1][K] == PUNC:
        op = t[i - 1][V]
        if op in (":", "=") and t[i - 2][K] in (ID, STR):
            return str(t[i - 2][V])
        # setRequestHeader("X-Api-Key", "…")  /  headers.append("Authorization", "…")
        if op == "," and t[i - 2][K] == STR and i >= 3 and p.is_punc(i - 3, "("):
            return str(t[i - 2][V])
    return ""


def _near_firebase(p: Program, i: int) -> bool:
    lo, hi = max(0, i - 40), min(p.n, i + 40)
    return any(p.tokens[k][K] in (ID, STR) and p.tokens[k][V] in _FIREBASE_SIBLINGS for k in range(lo, hi))


def scan_program(p: Program, file: str = "", entropy: bool = False) -> List[Secret]:
    """Find credentials in one tokenized file."""
    out: List[Secret] = []
    seen: set = set()

    def add(s: Secret) -> None:
        k = (s.kind, s.value)
        if k not in seen:
            seen.add(k)
            out.append(s)

    for i, tok in enumerate(p.tokens):
        kind = tok[K]
        if kind == STR:
            text = tok[V]
        elif kind == TPL:
            parts, _ = p.eval_expr(i)
            text = render(parts) if is_static(parts) else "".join(s for s in tok[V] if isinstance(s, str))
        else:
            continue
        if len(text) < 8 or len(text) > 8192:
            continue
        key = _key_context(p, i)
        line = 0

        typed = _typed_matches(text)
        for tk, value, sev, pub, note in typed:
            if tk == "GOOGLE_API_KEY" and _near_firebase(p, i):
                tk, sev, note = "FIREBASE_WEB_CONFIG", "info", (
                    "Firebase web API key — public by design. Security depends on Firebase Security Rules "
                    "and App Check, so review those.")
            if tk == "TWILIO_API_KEY" and "twilio" not in p.lex.src[max(0, tok[2] - 300):tok[3] + 300].lower():
                continue
            line = line or p.line(i)
            add(Secret(tk, sev, 0.95 if not pub else 0.9, value, key, file, line, note, pub))
        if typed:
            continue

        # ── semantic: a credible value under a secret-bearing name ───────────
        strength = key_strength(key) if key else 0
        if strength <= 0 and not entropy:
            continue
        value = re.sub(r"^(?:Bearer|Token|Basic|ApiKey)\s+", "", text.strip(), flags=re.I)
        if len(value) < 8 or len(value) > 512 or "\n" in value:
            continue
        label, score = classify(value, strong_key=strength == 2)
        if label in ("placeholder", "benign"):
            continue
        if strength == 2:
            if label == "weak" and not re.search(r"[\d!@#$%^&*+=/\\|~?]", value):
                continue
            conf = 0.45 + 0.4 * score
            sev = "high" if conf >= 0.72 else "medium"
            add(Secret("HARDCODED_SECRET", sev, min(conf, 0.92), value, key, file, p.line(i),
                       f"Literal value assigned to '{key[:60]}'."))
        elif strength == 1:
            if label == "secret":
                add(Secret("HARDCODED_SECRET", "medium", 0.4 + 0.4 * score, value, key, file, p.line(i),
                           f"Random-looking value assigned to '{key[:60]}'."))
        elif entropy and label == "secret" and 32 <= len(value) <= 128 and strength == 0 \
                and not re.fullmatch(r"[0-9a-fA-F]+", value) and not key.isdigit():
            add(Secret("HIGH_ENTROPY_STRING", "low", 0.3 + 0.3 * score, value, key, file, p.line(i),
                       "Unlabelled random-looking string (enabled by --entropy; expect noise)."))

    # comments survive in recovered sources and un-minified files
    for pos, text in p.lex.comments:
        for tk, value, sev, pub, note in _typed_matches(text):
            add(Secret(tk, sev, 0.85, value, "(comment)", file, p.lex.line_of(pos), note, pub))
    return out
