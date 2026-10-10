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
from bisect import bisect_left, bisect_right
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
MAX_REF_LEN = 300                   # a `${…}` longer than this is not a plain reference


# A variable part that is one of a few known strings:  (feed ? "/feed" : "")
ALT = "\x00alt\x01"


def render(parts: List[Part]) -> str:
    return "".join(("{param}" if t.startswith(ALT) else "{" + t + "}") if is_var else t for is_var, t in parts)


def expand(parts: List[Part], limit: int = 6) -> List[List[Part]]:
    """Every string `parts` can be when it contains either/or pieces; `[parts]` when it has none."""
    out: List[List[Part]] = [[]]
    for is_var, text in parts:
        if is_var and text.startswith(ALT):
            choices = text[len(ALT):].split("\x01")
            if len(out) * len(choices) <= limit:
                out = [o + [(False, c)] for o in out for c in choices]
                continue
            text = "param"
        out = [o + [(is_var, text)] for o in out]
    return [Program._merge(o) for o in out]


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
        # `this.name = …` and class fields `name = …`: name → [(position, value index)].
        # Resolved per class, never file-wide: every service class has its own `this.host`.
        self._this_defs: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        self._class_bodies: Set[int] = set()
        self._this_cache: Dict[Tuple[str, int], Optional[List[Part]]] = {}
        self._encl: Optional[List[int]] = None
        # every `name = …` (declaration or assignment) and every parameter, by position:
        # a local is resolved from the nearest assignment that is in scope
        self._decl: Dict[str, List[int]] = defaultdict(list)
        self._param_pos: Dict[str, List[int]] = defaultdict(list)
        self._local_busy: Set[int] = set()
        self._appended: Dict[str, List[int]] = defaultdict(list)      # name → positions of `name += …`
        self._objects: Dict[int, Dict[str, Tuple[int, int]]] = {}
        self._collect_appends()
        self._collect_this()
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
        known = self._objects.get(open_brace)
        if known is not None:
            return known                      # asked for once per key of a large literal: read it once
        close = self.pairs[open_brace] if 0 <= open_brace < self.n else -1
        out: Dict[str, Tuple[int, int]] = {}
        if close < 0:
            return out
        self._objects[open_brace] = out
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
        run: List[str] = []                   # consecutive literal pieces, joined once
        for is_var, text in parts:
            if not is_var:
                if text:
                    run.append(text)
                continue
            if run:
                out.append((False, "".join(run)))
                run = []
            out.append((True, text))
        if run:
            out.append((False, "".join(run)))
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
            return self._eval_template(val, i, depth), i + 1
        if kind == PUNC and val == "(":
            close = self.pairs[i]
            if close < 0:
                return [], i
            inner, end = self.eval_expr(i + 1, depth + 1)
            if inner and end == close:
                return inner, close + 1
            branches = self._literal_branches(i + 1, close, depth)
            if branches is not None:
                return [(True, ALT + "\x01".join(branches))], close + 1      # (cond ? "/feed" : "")
            # (a || "/fallback"), (cond ? x : fn()): an opaque value
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

        if len(chain) == 2 and chain[0] == "this" and not (self.is_punc(j, "(") or self.is_punc(j, "[")):
            own = self._this_value(chain[1], i, depth)
            if own is not None:
                return list(own), j
        if len(chain) == 1 and not (self.is_punc(j, "(") or self.is_punc(j, "[")):
            local = self._local_value(chain[0], i, depth)
            if local is not None:
                return list(local), j

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

    def _eval_template(self, segments: List[object], at: int = -1, depth: int = 0) -> List[Part]:
        parts: List[Part] = []
        for seg in segments:
            if isinstance(seg, str):
                parts.append((False, seg))
                continue
            expr = seg[1]
            if len(expr) <= MAX_REF_LEN and _SIMPLE_REF.match(expr):
                chain = [p for p in re.split(r"\??\.", expr) if p]
                if len(chain) == 2 and chain[0] == "this" and at >= 0:
                    own = self._this_value(chain[1], at, depth)
                    if own is not None:
                        parts.extend(own)
                        continue
                val = self._resolve(chain)
                if val is None and any(expr.startswith(r) for r in _ENV_ROOTS):
                    vals = self.props.get(chain[-1]) or self.consts.get(chain[-1])
                    val = next(iter(vals)) if vals and len(vals) == 1 else None
                parts.append((False, val) if val is not None else (True, var_name(chain[-1])))
            else:
                # only the end of a long expression is looked at: the name is there, and the search stays linear
                m = re.search(r"([A-Za-z_$][\w$]*)\s*\)*\s*$", expr[-MAX_REF_LEN:])
                inner = re.match(r"^(?:encodeURIComponent|encodeURI|String)\(\s*([\w$.?]+)\s*\)$", expr) \
                    if len(expr) <= MAX_REF_LEN else None
                if inner:
                    parts.append((True, var_name(re.split(r"\??\.", inner.group(1))[-1])))
                else:
                    parts.append((True, var_name(m.group(1)) if m else "param"))
        return parts

    def template_parts(self, i: int) -> List[Part]:
        """The template literal at token `i` on its own — not the `a + b` chain it may be part of."""
        return self._merge(self._eval_template(self.tokens[i][V], i, 0))

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

    # ── `this.x` inside a class ───────────────────────────────────────────────

    def _collect_this(self) -> None:
        """Record where every `this.name = …` and class field `name = …` is."""
        tokens, n, pairs = self.tokens, self.n, self.pairs
        for i in range(n - 3):
            t = tokens[i]
            if t[K] != ID:
                continue
            if t[V] == "this":
                if self.is_punc(i + 1, ".") and tokens[i + 2][K] == ID and self.is_punc(i + 3, "="):
                    self._this_defs[tokens[i + 2][V]].append((i, i + 4))
            elif t[V] == "class" and not (i > 0 and self.is_punc(i - 1, ".")):
                # class [Name] [extends <expr>] {
                j, limit = i + 1, min(n, i + 40)
                while j < limit and not self.is_punc(j, "{"):
                    if tokens[j][K] == PUNC:
                        if tokens[j][V] in ("(", "[") and pairs[j] > j:
                            j = pairs[j]
                        elif tokens[j][V] in (";", "}", ")", ":", ",", "="):
                            break
                    j += 1
                if j < limit and self.is_punc(j, "{") and pairs[j] > j:
                    self._class_bodies.add(j)
                    self._class_fields(j)
        for defs in self._this_defs.values():
            defs.sort()

    def _class_fields(self, open_brace: int) -> None:
        """Field definitions directly in a class body:  host = this.hostServer + "/api/Users";"""
        tokens, pairs = self.tokens, self.pairs
        close = pairs[open_brace]
        i, at_member = open_brace + 1, True
        while i < close:
            t = tokens[i]
            if t[K] == PUNC:
                if t[V] in ("(", "[", "{") and pairs[i] > i:
                    at_member = t[V] == "{"            # a method body ends a member
                    i = pairs[i] + 1
                    continue
                at_member = t[V] == ";"
            elif at_member and t[K] == ID:
                k = i + 1 if t[V] == "static" and self.kind(i + 1) == ID else i
                if self.is_punc(k + 1, "="):
                    self._this_defs[tokens[k][V]].append((k, k + 2))
                at_member = False
            else:
                at_member = False
            i += 1

    def _enclosing(self) -> List[int]:
        """For every token, the index of the innermost `{` that contains it (-1 at top level)."""
        if self._encl is None:
            encl = [-1] * self.n
            stack = [-1]
            for i, t in enumerate(self.tokens):
                if t[K] == PUNC:
                    if t[V] == "{" and self.pairs[i] > i:
                        encl[i] = stack[-1]
                        stack.append(i)
                        continue
                    if t[V] == "}" and len(stack) > 1 and self.pairs[stack[-1]] == i:
                        stack.pop()
                encl[i] = stack[-1]
            self._encl = encl
        return self._encl

    def _this_value(self, name: str, at: int, depth: int) -> Optional[List[Part]]:
        """
        What `this.<name>` holds at token `at`: the one definition in the class
        (or constructor-function scope) around it. None when there is no
        definition, more than one, or it is not a string with known text.
        """
        defs = self._this_defs.get(name)
        if not defs or depth > MAX_DEPTH or not 0 <= at < self.n:
            return None
        encl = self._enclosing()
        block, hops = encl[at], 0
        while block >= 0 and hops < 10:
            hops += 1
            close = self.pairs[block]
            lo = bisect_right(defs, (block, self.n))
            hi = bisect_left(defs, (close, -1))
            if hi - lo > 1:
                return None
            if hi - lo == 1:
                key = (name, block)
                if key in self._this_cache:
                    return self._this_cache[key]
                self._this_cache[key] = None             # guards  this.a = this.a + "…"
                pos, value = defs[lo]
                owner = encl[pos]
                # outside a class, only a constructor function declared directly in this
                # scope counts:  function F(){ this.host = … }  F.prototype.get = function(){ … }
                if block in self._class_bodies or owner == block or (owner >= 0 and encl[owner] == block):
                    parts, end = self.eval_expr(value, depth + 1)
                    continues = end < self.n and self.tokens[end][K] == PUNC and \
                        self.tokens[end][V] in ("?", "(", ".", "[", "||", "&&", "??")
                    known = any(not is_var and text for is_var, text in parts)
                    # host = env.apiRoot: nothing known, but `apiRoot` is the name another file may define
                    alias = len(parts) == 1 and parts[0][0] and parts[0][1] != "param"
                    if parts and not continues and (known or alias) \
                            and sum(len(text) for _, text in parts) <= MAX_CONST_LEN:
                        self._this_cache[key] = parts
                return self._this_cache[key]
            if block in self._class_bodies:
                return None
            block = encl[block]
        return None

    # ── locals ────────────────────────────────────────────────────────────────

    def _local_value(self, name: str, at: int, depth: int) -> Optional[List[Part]]:
        """
        let r = this.host + "/submitKey", n = {…};  return this.http.post(r, n)

        The value of the nearest earlier `name = …` that is in scope at `at`.
        None when there is none, when a parameter called `name` is declared in
        between (it may shadow it), when it is appended to afterwards, or when
        the value is not a string with known text.
        """
        if depth > MAX_DEPTH:
            return None
        pos = self._local_decl(name, at)
        if pos < 0 or pos in self._local_busy:
            return None
        self._local_busy.add(pos)
        try:
            return self._assigned(pos + 2, depth)
        finally:
            self._local_busy.discard(pos)

    def _local_decl(self, name: str, at: int) -> int:
        """Position of the nearest earlier `name = …` in scope at `at`, or -1."""
        decls = self._decl.get(name)
        if not decls:
            return -1
        k = bisect_left(decls, at) - 1
        if k < 0:
            return -1
        pos = decls[k]
        if len(name) <= 2 and at - pos > 2500:
            return -1
        encl = self._enclosing()
        block, hops, home = encl[at], 0, encl[pos]
        while block != home:                              # the assignment's block must enclose the use
            if block < 0 or hops >= 8:
                return -1
            block, hops = encl[block], hops + 1
        params = self._param_pos.get(name)
        if params:
            lo = bisect_right(params, pos)
            if lo < len(params) and params[lo] < at:
                return -1
        appended = self._appended.get(name)               # r += "/more" — the value at `at` is not the one assigned
        if appended:
            lo = bisect_left(appended, pos + 2)
            if lo < len(appended) and appended[lo] < at:
                return -1
        return pos

    def local_object(self, at: int) -> int:
        """If the identifier at `at` was assigned an object literal in scope, the index of its `{`; else -1."""
        if self.kind(at) != ID:
            return -1
        pos = self._local_decl(str(self.val(at)), at)
        return pos + 2 if pos >= 0 and self.is_punc(pos + 2, "{") else -1

    def _assigned(self, value: int, depth: int) -> Optional[List[Part]]:
        parts, end = self.eval_expr(value, depth + 1)
        nxt = self.tokens[end] if end < self.n else None
        if nxt is not None and nxt[K] == PUNC and nxt[V] in ("?", "&&", "||", "??", ">", "<", "===", "==", "!==", "!="):
            suffix = self._query_suffix(value, depth)
            if suffix is not None:
                return suffix
            branches = self._literal_branches(value, -1, depth)            # u = feed ? "/articles/feed" : "/articles"
            return [(True, ALT + "\x01".join(branches))] if branches else None
        if nxt is not None and nxt[K] == PUNC and nxt[V] in ("(", ".", "["):
            return None
        if parts and any(not is_var and text for is_var, text in parts) \
                and sum(len(text) for _, text in parts) <= MAX_CONST_LEN:
            return parts
        return None

    def _ternary(self, start: int, close: int) -> Tuple[int, int, int]:
        """(index of `?`, index of `:`, end) of the conditional starting at `start`; -1s when it is not one."""
        i, question, colon, guard = start, -1, -1, 0
        limit = close if close >= 0 else self.n
        while i < limit and guard < 400:
            guard += 1
            t = self.tokens[i]
            if t[K] == PUNC:
                v = t[V]
                if v in ("(", "[", "{") and self.pairs[i] > i:
                    i = self.pairs[i] + 1
                    continue
                if v in (",", ";", ")", "]", "}"):
                    break
                if v == "?" and question < 0:
                    question = i
                elif v == ":" and question >= 0 and colon < 0:
                    colon = i
            i += 1
        return (question, colon, i) if question >= 0 and colon >= 0 and (close < 0 or i == close) else (-1, -1, -1)

    def _literal_branches(self, start: int, close: int, depth: int) -> Optional[List[str]]:
        """The two strings of  cond ? "a" : "b"  when both are constants (one may be empty) and they differ."""
        if depth > MAX_DEPTH:
            return None
        question, colon, end = self._ternary(start, close)
        if question < 0:
            return None
        first, e1 = self.eval_expr(question + 1, depth + 1)
        second, e2 = self.eval_expr(colon + 1, depth + 1)
        if e1 != colon or e2 != end or any(v for v, _ in first + second):
            return None
        a, b = render(first), render(second)
        if a == b or len(a) > 200 or len(b) > 200 or "\x00" in a + b or "\x01" in a + b:
            return None
        return [a, b]

    def _query_suffix(self, value: int, depth: int) -> Optional[List[Part]]:
        """t = fields && fields.length ? `?fields=${fields.join(",")}` : ""   →   ?fields={param}"""
        i, question, colon, guard = value, -1, -1, 0
        while i < self.n and guard < 400:
            guard += 1
            t = self.tokens[i]
            if t[K] == PUNC:
                v = t[V]
                if v in ("(", "[", "{") and self.pairs[i] > i:
                    i = self.pairs[i] + 1
                    continue
                if v in (",", ";", ")", "]", "}"):
                    break
                if v == "?" and question < 0:
                    question = i
                elif v == ":" and question >= 0 and colon < 0:
                    colon = i
            i += 1
        if question < 0 or colon < 0:
            return None
        end = i
        first, e1 = self.eval_expr(question + 1, depth + 1)
        second, e2 = self.eval_expr(colon + 1, depth + 1)
        if e1 != colon or e2 != end:
            return None
        branches = [b for b in (first, second) if render(b)]
        if branches and all(render(b)[:1] in ("?", "&") and not b[0][0] for b in branches):
            return branches[0]
        return None

    # ── constants ─────────────────────────────────────────────────────────────

    def _collect_appends(self) -> None:
        tokens = self.tokens
        for i in range(self.n - 1):
            if tokens[i][K] == ID and tokens[i + 1][K] == PUNC and tokens[i + 1][V] == "+=":
                self._appended[tokens[i][V]].append(i)

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
                    self._param_pos[tk[V]].append(k)

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
                    self._param_pos[p[V]].append(i - 1)
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
            if op == "+=" and kind == ID:
                # appended to afterwards: whatever it was assigned is not its final value
                (self.tainted_props if i > 0 and self.is_punc(i - 1, ".") else self.tainted).add(str(t[V]))
                continue
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
                if op == "=" and kind == ID:
                    self._decl[name].append(i)
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
