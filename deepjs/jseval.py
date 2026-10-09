"""
deepjs.jseval — light static evaluation on top of the token stream.

No full parser is needed to answer the questions that matter for recon:

  * what string does this expression build?
        "/api/" + ver + "/users/" + id        →  /api/v2/users/{id}
        `${BASE}/orders/${o.id}`              →  https://api.example.com/orders/{id}
        "".concat(base, "/items/").concat(n)  →  (what Babel emits for templates)
  * what are the keys of this object literal, and where are their values?
  * what are the arguments of this call?

Identifiers are resolved through a constant table, but only when a name has
exactly one string value in the file — in minified code `a`, `e`, `t` are
reused in every scope, and guessing would invent URLs that do not exist.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from deepjs.lexer import ID, K, NUM, PUNC, REGEX, S, STR, TPL, V, Lexed, tokenize

# A built string is a list of parts: (is_variable, text)
Part = Tuple[bool, str]

_SIMPLE_REF = re.compile(r"^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)*$")
_WRAPPERS = frozenset({
    "encodeURIComponent", "encodeURI", "String", "Number", "parseInt", "escape", "toString",
    "trim", "toLowerCase", "toUpperCase", "toFixed", "valueOf", "stringify",
})
_ENV_ROOTS = ("process.env.", "import.meta.env.", "window.env.", "window._env_.", "window.__env.")
MAX_CONST_LEN = 2000
MAX_DEPTH = 12


def render(parts: List[Part]) -> str:
    return "".join("{" + t + "}" if is_var else t for is_var, t in parts)


def is_static(parts: List[Part]) -> bool:
    return bool(parts) and not any(is_var for is_var, _ in parts)


def var_name(name: str) -> str:
    """Placeholder name for an unresolved identifier (minified names carry no meaning)."""
    name = name.strip("_$")
    if len(name) > 2 or name.lower() in ("id", "pk", "ip", "qs", "tx"):
        return name
    return "param"


class Program:
    """One tokenized source file plus the helpers the analyzers share."""

    def __init__(self, src: str, name: str = "") -> None:
        self.name = name
        self.lex: Lexed = tokenize(src)
        self.tokens = self.lex.tokens
        self.pairs = self.lex.pairs
        self.n = len(self.tokens)
        self.consts: Dict[str, Set[str]] = defaultdict(set)   # identifier → string values assigned to it
        self.props: Dict[str, Set[str]] = defaultdict(set)    # property name → string values
        # Names that also hold something other than one constant string (function
        # parameters, values computed at runtime). Never resolved.
        self.tainted: Set[str] = set()
        self.tainted_props: Set[str] = set()
        self.params: Set[str] = set()
        # Variables assigned exactly once to a URL-shaped string that still has
        # unknown pieces:  const url = `${API}/orders/${id}`;  fetch(url)
        self.templates: Dict[str, List[Part]] = {}
        self._assignments: Dict[str, int] = defaultdict(int)
        self._collect_parameters()
        self._collect_constants(final=False)
        self._collect_constants(final=True)   # second pass resolves constants built from constants

    # ── small accessors ───────────────────────────────────────────────────────

    def kind(self, i: int) -> str:
        return self.tokens[i][K] if 0 <= i < self.n else ""

    def val(self, i: int):
        return self.tokens[i][V] if 0 <= i < self.n else None

    def is_punc(self, i: int, v: str) -> bool:
        return 0 <= i < self.n and self.tokens[i][K] == PUNC and self.tokens[i][V] == v

    def line(self, i: int) -> int:
        return self.lex.token_line(i)

    # ── structure ─────────────────────────────────────────────────────────────

    def call_args(self, open_paren: int) -> List[Tuple[int, int]]:
        """Token ranges [start, end) of each top-level argument of the call at `(`."""
        close = self.pairs[open_paren] if 0 <= open_paren < self.n else -1
        if close < 0:
            return []
        args: List[Tuple[int, int]] = []
        start = i = open_paren + 1
        while i < close:
            t = self.tokens[i]
            if t[K] == PUNC:
                v = t[V]
                if v in ("(", "[", "{"):
                    j = self.pairs[i]
                    if j > i:
                        i = j + 1
                        continue
                elif v == ",":
                    args.append((start, i))
                    start = i + 1
            i += 1
        if start < close:
            args.append((start, close))
        return args

    def object_at(self, open_brace: int) -> Dict[str, Tuple[int, int]]:
        """
        Top-level properties of the object literal at `{`:
        ``{key: (value_start, value_end)}``. Shorthand `{a, b}` maps a key to
        its own token; methods and spreads are skipped.
        """
        close = self.pairs[open_brace] if 0 <= open_brace < self.n else -1
        out: Dict[str, Tuple[int, int]] = {}
        if close < 0:
            return out
        i = open_brace + 1
        while i < close:
            t = self.tokens[i]
            key: Optional[str] = None
            if t[K] in (ID, STR, NUM):
                key = str(t[V])
            elif t[K] == PUNC and t[V] == "[":          # computed key: skip it
                j = self.pairs[i]
                i = j + 1 if j > i else i + 1
                continue
            if key is not None and self.is_punc(i + 1, ":"):
                vs = i + 2
                ve = self._value_end(vs, close)
                out[key] = (vs, ve)
                i = ve + 1
                continue
            if key is not None and (self.is_punc(i + 1, ",") or i + 1 == close) and t[K] == ID:
                out[key] = (i, i + 1)                    # shorthand property
                i += 2
                continue
            # anything else (method, spread, getter): skip to the next top-level comma
            i = self._value_end(i, close) + 1
        return out

    def _value_end(self, i: int, limit: int) -> int:
        """Index of the top-level `,` ending the value that starts at `i` (or `limit`)."""
        while i < limit:
            t = self.tokens[i]
            if t[K] == PUNC:
                v = t[V]
                if v in ("(", "[", "{"):
                    j = self.pairs[i]
                    if j > i:
                        i = j + 1
                        continue
                elif v == ",":
                    return i
            i += 1
        return limit

    # ── string expression evaluation ──────────────────────────────────────────

    def eval_expr(self, i: int, depth: int = 0) -> Tuple[List[Part], int]:
        """
        Evaluate the string-building expression starting at token `i`.
        Returns (parts, next_index). `parts` is empty if `i` does not start
        something that can be part of a string.
        """
        parts: List[Part] = []
        while True:
            term, j = self._eval_term(i, depth)
            if j == i:
                break
            parts.extend(term)
            i = j
            # "".concat(a, "/x").concat(b) — Babel's output for template literals
            while self.is_punc(i, ".") and self.kind(i + 1) == ID and self.val(i + 1) == "concat" \
                    and self.is_punc(i + 2, "("):
                close = self.pairs[i + 2]
                if close < 0:
                    break
                for a, b in self.call_args(i + 2):
                    sub, end = self.eval_expr(a, depth + 1)
                    parts.extend(sub if (sub and end >= b) else [(True, "param")])
                i = close + 1
            if self.is_punc(i, "+"):
                i += 1
                continue
            break
        return self._merge(parts), i

    @staticmethod
    def _merge(parts: List[Part]) -> List[Part]:
        out: List[Part] = []
        for is_var, text in parts:
            if not is_var and out and not out[-1][0]:
                out[-1] = (False, out[-1][1] + text)
            elif text or is_var:
                out.append((is_var, text))
        return out

    def _eval_term(self, i: int, depth: int) -> Tuple[List[Part], int]:
        if i >= self.n or depth > MAX_DEPTH:
            return [], i
        kind, val = self.tokens[i][K], self.tokens[i][V]

        if kind == STR:
            return [(False, val)], i + 1
        if kind == NUM:
            return [(False, str(val))], i + 1
        if kind == TPL:
            return self._eval_template(val), i + 1
        if kind == PUNC and val == "(":
            close = self.pairs[i]
            if close < 0:
                return [], i
            inner, end = self.eval_expr(i + 1, depth + 1)
            if inner and end == close:
                return inner, close + 1
            # (a || "/fallback"), (cond ? x : y): an opaque value
            return [(True, "param")], close + 1
        if kind == ID:
            return self._eval_reference(i, depth)
        return [], i

    def _eval_reference(self, i: int, depth: int) -> Tuple[List[Part], int]:
        """identifier, member chain, optional call / index."""
        if self.val(i) in ("function", "return", "typeof", "new", "await", "void", "delete", "class",
                           "if", "for", "while", "var", "let", "const", "case", "in", "of", "else"):
            return [], i
        chain = [self.val(i)]
        j = i + 1
        while (self.is_punc(j, ".") or self.is_punc(j, "?.")) and self.kind(j + 1) == ID:
            chain.append(self.val(j + 1))
            j += 2

        resolved = self._resolve(chain)
        name = chain[-1]
        if resolved is None and len(chain) == 1 and name in self.templates                 and self._assignments.get(name, 0) == 1 and name not in self.params                 and not (self.is_punc(j, "(") or self.is_punc(j, "[") or self.is_punc(j, ".")):
            return list(self.templates[name]), j

        # trailing call / index chains: a.b(c)[d].e()
        guard = 0
        while guard < 8:
            guard += 1
            if self.is_punc(j, "("):
                close = self.pairs[j]
                if close < 0:
                    break
                if name in _WRAPPERS:
                    args = self.call_args(j)
                    if args:
                        inner, end = self.eval_expr(args[0][0], depth + 1)
                        if inner and end >= args[0][1]:
                            return inner, close + 1
                    # x.toString(): keep the receiver's name
                    if len(chain) >= 2:
                        name = chain[-2]
                resolved = None
                j = close + 1
            elif self.is_punc(j, "["):
                close = self.pairs[j]
                if close < 0:
                    break
                resolved = None
                j = close + 1
            elif (self.is_punc(j, ".") or self.is_punc(j, "?.")) and self.kind(j + 1) == ID \
                    and self.val(j + 1) != "concat":
                nxt = self.val(j + 1)
                if nxt not in _WRAPPERS:
                    name = nxt
                chain.append(nxt)
                resolved = None
                j += 2
            else:
                break

        if resolved is not None:
            return [(False, resolved)], j
        return [(True, var_name(name))], j

    def _resolve(self, chain: List[str]) -> Optional[str]:
        if len(chain) == 1:
            if chain[0] in self.tainted:
                return None
            vals = self.consts.get(chain[0])
        else:
            if chain[-1] in self.tainted_props:
                return None
            vals = self.props.get(chain[-1])
        if vals and len(vals) == 1:
            return next(iter(vals))
        return None

    def _eval_template(self, segments: List[object]) -> List[Part]:
        parts: List[Part] = []
        for seg in segments:
            if isinstance(seg, str):
                parts.append((False, seg))
                continue
            expr = seg[1]
            if _SIMPLE_REF.match(expr):
                chain = [p for p in re.split(r"\??\.", expr) if p]
                val = self._resolve(chain)
                if val is None and any(expr.startswith(r) for r in _ENV_ROOTS):
                    vals = self.props.get(chain[-1]) or self.consts.get(chain[-1])
                    val = next(iter(vals)) if vals and len(vals) == 1 else None
                parts.append((False, val) if val is not None else (True, var_name(chain[-1])))
            else:
                m = re.search(r"([A-Za-z_$][\w$]*)\s*\)*\s*$", expr)
                inner = re.match(r"^(?:encodeURIComponent|encodeURI|String)\(\s*([\w$.?]+)\s*\)$", expr)
                if inner:
                    parts.append((True, var_name(re.split(r"\??\.", inner.group(1))[-1])))
                else:
                    parts.append((True, var_name(m.group(1)) if m else "param"))
        return parts

    def expr_start(self, i: int) -> int:
        """Walk left from token `i` to the first token of its `a + b + c` chain."""
        j = i
        guard = 0
        while j >= 2 and guard < 64 and self.is_punc(j - 1, "+"):
            guard += 1
            k = j - 2
            t = self.tokens[k]
            if t[K] in (STR, TPL, NUM):
                j = k
            elif t[K] == ID:
                # include a leading member chain: a.b.c + "…"
                while k >= 2 and self.is_punc(k - 1, ".") and self.kind(k - 2) == ID:
                    k -= 2
                j = k
            elif t[K] == PUNC and t[V] == ")":
                o = self.pairs[k]
                if o < 0:
                    break
                k = o
                # f(x) + "…": include the callee name / chain
                while k >= 1 and self.kind(k - 1) == ID:
                    k -= 1
                    if k >= 1 and self.is_punc(k - 1, "."):
                        k -= 1
                    else:
                        break
                j = k
            else:
                break
        return j

    # ── constants ─────────────────────────────────────────────────────────────

    def _collect_parameters(self) -> None:
        """Function / arrow / catch parameters are runtime values, never constants."""
        tokens, n = self.tokens, self.n

        def taint_group(open_paren: int) -> None:
            close = self.pairs[open_paren]
            if close < 0:
                return
            depth = 0
            for k in range(open_paren + 1, close):
                tk = tokens[k]
                if tk[K] == PUNC:
                    if tk[V] in ("(", "[", "{"):
                        depth += 1
                    elif tk[V] in (")", "]", "}"):
                        depth -= 1
                elif tk[K] == ID and depth <= 1:
                    self.tainted.add(tk[V])
                    self.params.add(tk[V])

        for i in range(n):
            t = tokens[i]
            if t[K] == ID and t[V] in ("function", "catch"):
                j = i + 1
                if t[V] == "function":
                    if self.is_punc(j, "*"):
                        j += 1
                    if self.kind(j) == ID:
                        j += 1
                if self.is_punc(j, "("):
                    taint_group(j)
            elif t[K] == PUNC and t[V] == "=>" and i > 0:
                p = tokens[i - 1]
                if p[K] == ID:
                    self.tainted.add(p[V])
                    self.params.add(p[V])
                elif p[K] == PUNC and p[V] == ")" and self.pairs[i - 1] >= 0:
                    taint_group(self.pairs[i - 1])
            elif t[K] == PUNC and t[V] == "(" and i > 0 and tokens[i - 1][K] == ID \
                    and self.pairs[i] > 0 and self.is_punc(self.pairs[i] + 1, "{") \
                    and i > 1 and self.is_punc(i - 2, ",") is False and self.kind(i - 2) not in (ID,) \
                    and tokens[i - 1][V] not in ("if", "for", "while", "switch", "with"):
                # method shorthand in a class / object literal:  name(a, b) { … }
                taint_group(i)

    def _collect_constants(self, final: bool = True) -> None:
        tokens, n = self.tokens, self.n
        for i in range(n - 2):
            t = tokens[i]
            kind = t[K]
            if kind != ID and kind != STR:
                continue
            nxt = tokens[i + 1]
            if nxt[K] != PUNC:
                continue
            op = nxt[V]
            is_prop = False
            if op == "=" and kind == ID:
                is_prop = i > 0 and self.is_punc(i - 1, ".")
            elif op == ":" and i > 0 and tokens[i - 1][K] == PUNC and tokens[i - 1][V] in ("{", ","):
                is_prop = True
            else:
                continue
            name = str(t[V])
            static_value: Optional[str] = None
            parts: List[Part] = []
            if final and not is_prop:
                self._assignments[name] += 1
            if tokens[i + 2][K] in (STR, TPL, ID):
                parts, end = self.eval_expr(i + 2)
                # the value must end the expression: a ternary / call continues past it
                continues = end < n and tokens[end][K] == PUNC and \
                    tokens[end][V] in ("?", "(", ".", "[", "||", "&&", "??")
                if is_static(parts) and not continues and 0 < len(parts[0][1]) <= MAX_CONST_LEN:
                    static_value = parts[0][1]
            if static_value is not None:
                (self.props if is_prop else self.consts)[name].add(static_value)
            elif final:
                (self.tainted_props if is_prop else self.tainted).add(name)
                if not is_prop and parts and not continues and any((not v) and "/" in t for v, t in parts):
                    self.templates[name] = parts
