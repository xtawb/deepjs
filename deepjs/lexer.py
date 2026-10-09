"""
deepjs.lexer — a tolerant JavaScript tokenizer.

Regex-only tools read a bundle as one long string, so they cannot tell a string
literal from a comment or a regex, and cannot follow `a + "/users/" + id`.
This tokenizer gives every later stage real structure to work with:

  * string literals, decoded (escapes resolved)
  * template literals, split into text and `${expression}` segments
  * regex literals, told apart from division
  * identifiers, numbers, punctuators
  * comments, collected separately
  * a bracket-pair table, so "the matching `}`" is one lookup

It never raises on malformed input: minified, truncated or non-JS content just
produces fewer useful tokens.
"""

from __future__ import annotations

import bisect
import re
from typing import List, Optional, Tuple

STR, TPL, ID, NUM, PUNC, REGEX = "str", "tpl", "id", "num", "punc", "regex"

# Token = (kind, value, start, end)
K, V, S, E = 0, 1, 2, 3
Token = Tuple[str, object, int, int]

_MASTER = re.compile(
    r"""
     (?P<ws>[ \t\r\n\u00a0\ufeff\u2028\u2029]+)
    |(?P<lc>//[^\n]*)
    |(?P<bc>/\*[\s\S]*?\*/)
    |(?P<id>[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*)
    |(?P<num>0[xX][\da-fA-F_]+n?|0[bB][01_]+n?|0[oO][0-7_]+n?
            |(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?)
    |(?P<dq>"(?:[^"\\\n]|\\[\s\S])*")
    |(?P<sq>'(?:[^'\\\n]|\\[\s\S])*')
    |(?P<punc>\.\.\.|=>|\?\?=|\?\.(?!\d)|\?\?|\*\*=?|===|!==|==|!=|<<=|>>>=|>>=|>>>|<<|>>|<=|>=
             |&&=|\|\|=|&&|\|\||\+\+|--|[+\-*%&|^]=|[{}()\[\];,<>+\-*%&|^!~?:=.@\#])
    """,
    re.VERBOSE,
)

_REGEX_PREV_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await",
})

_ESCAPE = re.compile(r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(\r\n|[\s\S]))")
_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
    "\n": "", "\r\n": "", "\r": "", "\u2028": "", "\u2029": "",
}
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_TEMPLATE_RUN = re.compile(r"[^`\\$]+")
_BRACE_STOP = re.compile(r"[{}'\"`]")
_QUOTED = re.compile(r"\"(?:[^\"\\\n]|\\[\s\S])*\"|'(?:[^'\\\n]|\\[\s\S])*'")

MAX_REGEX_LEN = 4000


def unescape(raw: str) -> str:
    """Resolve JavaScript string escapes."""
    if "\\" not in raw:
        return raw

    def repl(m: "re.Match[str]") -> str:
        code = m.group(1) or m.group(2) or m.group(3)
        if code:
            try:
                return chr(int(code, 16))
            except (ValueError, OverflowError):
                return ""
        ch = m.group(4)
        return _SIMPLE_ESCAPES.get(ch, ch)

    out = _ESCAPE.sub(repl, raw)
    if _SURROGATE.search(out):
        # \ud83d\ude00 → one code point; lone surrogates become U+FFFD.
        out = out.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    return out


def _scan_regex(src: str, pos: int) -> int:
    """`pos` is at '/'. Returns the index after the literal (incl. flags), or -1."""
    i, n = pos + 1, len(src)
    limit = min(n, pos + MAX_REGEX_LEN)
    in_class = False
    while i < limit:
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            return -1
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            if i == pos + 1:
                return -1
            i += 1
            while i < n and (src[i].isalpha()):
                i += 1
            return i
        i += 1
    return -1


def _skip_braced(src: str, i: int) -> int:
    """`i` is just after `${`. Returns the index of the matching `}` (or len)."""
    depth, n = 1, len(src)
    while i < n:
        m = _BRACE_STOP.search(src, i)
        if not m:
            return n
        i = m.start()
        c = src[i]
        if c == "{":
            depth += 1
            i += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
            i += 1
        elif c == "`":
            _, i = _scan_template(src, i)
        else:
            q = _QUOTED.match(src, i)
            i = q.end() if q else i + 1
    return n


def _scan_template(src: str, pos: int) -> Tuple[List[object], int]:
    """
    `pos` is at a backtick. Returns (segments, end) where each segment is a
    decoded text `str` or an ``("expr", source)`` tuple for `${…}`.
    """
    segs: List[object] = []
    buf: List[str] = []
    i, n = pos + 1, len(src)

    def flush() -> None:
        if buf:
            segs.append(unescape("".join(buf)))
            buf.clear()

    while i < n:
        m = _TEMPLATE_RUN.match(src, i)
        if m:
            buf.append(m.group(0))
            i = m.end()
            continue
        c = src[i]
        if c == "\\":
            buf.append(src[i:i + 2])
            i += 2
        elif c == "`":
            flush()
            return segs, i + 1
        elif c == "$" and src[i + 1:i + 2] == "{":
            flush()
            j = _skip_braced(src, i + 2)
            segs.append(("expr", src[i + 2:j].strip()))
            i = j + 1
        else:
            buf.append(c)
            i += 1
    flush()
    return segs, n


class Lexed:
    """Result of tokenizing one source text."""

    __slots__ = ("src", "tokens", "comments", "pairs", "_line_starts")

    def __init__(self, src: str) -> None:
        self.src = src
        self.tokens: List[Token] = []
        self.comments: List[Tuple[int, str]] = []
        self.pairs: List[int] = []
        self._line_starts: Optional[List[int]] = None
        self._run()
        self._pair_brackets()

    def line_of(self, offset: int) -> int:
        if self._line_starts is None:
            self._line_starts = [0] + [m.end() for m in re.finditer(r"\n", self.src)]
        return bisect.bisect_right(self._line_starts, offset)

    def token_line(self, index: int) -> int:
        return self.line_of(self.tokens[index][S]) if 0 <= index < len(self.tokens) else 0

    # ── tokenizing ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        src, n = self.src, len(self.src)
        tokens, comments = self.tokens, self.comments
        append = tokens.append
        match = _MASTER.match
        pos = 0
        prev: Optional[Token] = None

        while pos < n:
            m = match(src, pos)
            if m is not None:
                kind = m.lastgroup
                end = m.end()
                if kind == "ws":
                    pos = end
                    continue
                if kind == "id":
                    prev = (ID, m.group(), pos, end)
                elif kind == "punc":
                    prev = (PUNC, m.group(), pos, end)
                elif kind == "dq" or kind == "sq":
                    prev = (STR, unescape(src[pos + 1:end - 1]), pos, end)
                elif kind == "num":
                    prev = (NUM, m.group(), pos, end)
                else:  # comment
                    comments.append((pos, m.group()))
                    pos = end
                    continue
                append(prev)
                pos = end
                continue

            c = src[pos]
            if c == "`":
                segs, end = _scan_template(src, pos)
                prev = (TPL, segs, pos, end)
                append(prev)
                pos = end
            elif c == "/":
                end = _scan_regex(src, pos) if self._regex_allowed(prev) else -1
                if end > 0:
                    prev = (REGEX, src[pos:end], pos, end)
                    append(prev)
                    pos = end
                else:
                    end = pos + 2 if src[pos + 1:pos + 2] == "=" else pos + 1
                    prev = (PUNC, src[pos:end], pos, end)
                    append(prev)
                    pos = end
            else:
                pos += 1        # unknown byte (binary junk, stray quote): skip

    @staticmethod
    def _regex_allowed(prev: Optional[Token]) -> bool:
        if prev is None:
            return True
        kind, val = prev[K], prev[V]
        if kind == PUNC:
            return val not in (")", "]", "++", "--")
        if kind == ID:
            return val in _REGEX_PREV_KEYWORDS
        return False

    def _pair_brackets(self) -> None:
        tokens = self.tokens
        pairs = [-1] * len(tokens)
        stack: List[int] = []
        closing = {")": "(", "]": "[", "}": "{"}
        for i, t in enumerate(tokens):
            if t[K] != PUNC:
                continue
            v = t[V]
            if v == "(" or v == "[" or v == "{":
                stack.append(i)
            elif v in closing:
                want = closing[v]
                # Tolerate imbalance: unwind to the nearest matching opener.
                j = len(stack) - 1
                while j >= 0 and tokens[stack[j]][V] != want:
                    j -= 1
                if j >= 0:
                    o = stack[j]
                    del stack[j:]
                    pairs[o] = i
                    pairs[i] = o
        self.pairs = pairs


def tokenize(src: str) -> Lexed:
    return Lexed(src)
