package deepjs.engine;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A tolerant JavaScript tokenizer.
 *
 * It gives the later stages structure a regular expression cannot: string
 * literals decoded, template literals split into text and `${…}` segments,
 * regex literals told apart from division, comments collected separately, and
 * a table of matching brackets. It never fails on malformed input — minified,
 * truncated or non-JavaScript content just yields fewer useful tokens.
 *
 * Tokens are held in parallel arrays; `value[i]` is a String for every kind
 * except TPL, where it is a List whose items are a String (text) or an
 * {@link Expr}.
 */
final class Lexer {

    static final byte STR = 1, TPL = 2, ID = 3, NUM = 4, PUNC = 5, REGEX = 6;

    /** The source of one `${…}` inside a template literal. */
    record Expr(String source) {
    }

    private static final int MAX_REGEX_LEN = 4000;
    /** `${`${…}`}` deeper than this is skipped, not followed. */
    private static final int MAX_TEMPLATE_DEPTH = 40;

    final String src;
    byte[] kind = new byte[1024];
    Object[] value = new Object[1024];
    int[] start = new int[1024];
    int[] end = new int[1024];
    int[] pairs;
    int n;
    final Py.Ints commentAt = new Py.Ints();
    final List<String> comments = new ArrayList<>();
    private int[] lineStarts;

    Lexer(String src) {
        this.src = src;
        run();
        pairBrackets();
    }

    /** 1-based line of a source offset. */
    int lineOf(int offset) {
        if (lineStarts == null) {
            Py.Ints starts = new Py.Ints();
            starts.add(0);
            for (int i = src.indexOf('\n'); i >= 0; i = src.indexOf('\n', i + 1)) {
                starts.add(i + 1);
            }
            lineStarts = new int[starts.size()];
            for (int i = 0; i < lineStarts.length; i++) {
                lineStarts[i] = starts.get(i);
            }
        }
        int lo = 0, hi = lineStarts.length;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (offset < lineStarts[mid]) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return lo;
    }

    int tokenLine(int index) {
        return index >= 0 && index < n ? lineOf(start[index]) : 0;
    }

    // ── tokenizing ───────────────────────────────────────────────────────────

    private void add(byte k, Object v, int from, int to) {
        if (n == kind.length) {
            int size = n * 2;
            kind = Arrays.copyOf(kind, size);
            value = Arrays.copyOf(value, size);
            start = Arrays.copyOf(start, size);
            end = Arrays.copyOf(end, size);
        }
        kind[n] = k;
        value[n] = v;
        start[n] = from;
        end[n] = to;
        n++;
    }

    private void run() {
        final String s = src;
        final int len = s.length();
        int pos = 0;
        while (pos < len) {
            char c = s.charAt(pos);
            if (isBlank(c)) {
                pos++;
                continue;
            }
            if (c == '/' && pos + 1 < len) {
                char d = s.charAt(pos + 1);
                if (d == '/') {
                    int stop = s.indexOf('\n', pos);
                    stop = stop < 0 ? len : stop;
                    commentAt.add(pos);
                    comments.add(s.substring(pos, stop));
                    pos = stop;
                    continue;
                }
                if (d == '*') {
                    int stop = s.indexOf("*/", pos + 2);
                    if (stop >= 0) {
                        commentAt.add(pos);
                        comments.add(s.substring(pos, stop + 2));
                        pos = stop + 2;
                        continue;
                    }
                }
            }
            if (isIdStart(c)) {
                int stop = pos + 1;
                while (stop < len && isIdPart(s.charAt(stop))) {
                    stop++;
                }
                add(ID, s.substring(pos, stop), pos, stop);
                pos = stop;
                continue;
            }
            if (isDigit(c) || (c == '.' && pos + 1 < len && isDigit(s.charAt(pos + 1)))) {
                int stop = number(pos);
                add(NUM, s.substring(pos, stop), pos, stop);
                pos = stop;
                continue;
            }
            if (c == '"' || c == '\'') {
                int stop = quoted(s, pos);
                if (stop > 0) {
                    add(STR, unescape(s.substring(pos + 1, stop - 1)), pos, stop);
                    pos = stop;
                } else {
                    pos++;                              // a stray quote: skip it
                }
                continue;
            }
            int width = punctuator(pos);
            if (width > 0) {
                add(PUNC, s.substring(pos, pos + width).intern(), pos, pos + width);
                pos += width;
                continue;
            }
            if (c == '`') {
                List<Object> segments = new ArrayList<>();
                int stop = template(s, pos, segments, 0);
                add(TPL, segments, pos, stop);
                pos = stop;
            } else if (c == '/') {
                int stop = regexAllowed() ? regex(s, pos) : -1;
                if (stop > 0) {
                    add(REGEX, s.substring(pos, stop), pos, stop);
                } else {
                    stop = pos + 1 < len && s.charAt(pos + 1) == '=' ? pos + 2 : pos + 1;
                    add(PUNC, s.substring(pos, stop).intern(), pos, stop);
                }
                pos = stop;
            } else {
                pos++;                                  // binary junk, a lone backslash: skip
            }
        }
    }

    private static boolean isBlank(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0xa0 || c == 0xfeff || c == 0x2028 || c == 0x2029;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isIdStart(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$' || c >= 0x80;
    }

    private static boolean isIdPart(char c) {
        return isIdStart(c) || isDigit(c);
    }

    /** `pos` is at a digit, or at a `.` followed by one. Returns the index after the literal. */
    private int number(int pos) {
        final String s = src;
        final int len = s.length();
        if (s.charAt(pos) == '0' && pos + 1 < len) {
            char x = s.charAt(pos + 1);
            int stop = pos + 2;
            if (x == 'x' || x == 'X') {
                while (stop < len && (isHex(s.charAt(stop)) || s.charAt(stop) == '_')) {
                    stop++;
                }
            } else if (x == 'b' || x == 'B') {
                while (stop < len && (s.charAt(stop) == '0' || s.charAt(stop) == '1' || s.charAt(stop) == '_')) {
                    stop++;
                }
            } else if (x == 'o' || x == 'O') {
                while (stop < len && ((s.charAt(stop) >= '0' && s.charAt(stop) <= '7') || s.charAt(stop) == '_')) {
                    stop++;
                }
            }
            if (stop > pos + 2) {
                return stop < len && s.charAt(stop) == 'n' ? stop + 1 : stop;
            }
        }
        int stop = pos + 1;                             // the leading digit, or the leading '.'
        if (s.charAt(pos) == '.') {
            stop++;                                     // the digit after it
        }
        while (stop < len && (isDigit(s.charAt(stop)) || s.charAt(stop) == '_')) {
            stop++;
        }
        if (s.charAt(pos) != '.' && stop < len && s.charAt(stop) == '.') {
            stop++;
            while (stop < len && (isDigit(s.charAt(stop)) || s.charAt(stop) == '_')) {
                stop++;
            }
        }
        if (stop < len && (s.charAt(stop) == 'e' || s.charAt(stop) == 'E')) {
            int digits = stop + 1;
            if (digits < len && (s.charAt(digits) == '+' || s.charAt(digits) == '-')) {
                digits++;
            }
            int after = digits;
            while (after < len && isDigit(s.charAt(after))) {
                after++;
            }
            if (after > digits) {
                stop = after;
            }
        }
        return stop < len && s.charAt(stop) == 'n' ? stop + 1 : stop;
    }

    /** `pos` is at a quote. Returns the index after the closing quote, or -1 when the literal is not terminated. */
    private static int quoted(String s, int pos) {
        final char quote = s.charAt(pos);
        final int len = s.length();
        int i = pos + 1;
        while (i < len) {
            char c = s.charAt(i);
            if (c == '\\') {
                if (i + 1 >= len) {
                    return -1;
                }
                i += 2;
            } else if (c == quote) {
                return i + 1;
            } else if (c == '\n') {
                return -1;
            } else {
                i++;
            }
        }
        return -1;
    }

    /** Length of the punctuator at `pos`, longest first; 0 when there is none. `/` is handled by the caller. */
    private int punctuator(int pos) {
        final String s = src;
        final int len = s.length();
        char c = s.charAt(pos);
        char d = pos + 1 < len ? s.charAt(pos + 1) : 0;
        char e = pos + 2 < len ? s.charAt(pos + 2) : 0;
        char f = pos + 3 < len ? s.charAt(pos + 3) : 0;
        switch (c) {
            case '.':
                return d == '.' && e == '.' ? 3 : 1;
            case '=':
                return d == '>' ? 2 : d == '=' ? (e == '=' ? 3 : 2) : 1;
            case '?':
                if (d == '?' && e == '=') {
                    return 3;
                }
                if (d == '.' && !isDigit(e)) {
                    return 2;
                }
                return d == '?' ? 2 : 1;
            case '*':
                return d == '*' ? (e == '=' ? 3 : 2) : d == '=' ? 2 : 1;
            case '!':
                return d == '=' ? (e == '=' ? 3 : 2) : 1;
            case '<':
                return d == '<' ? (e == '=' ? 3 : 2) : d == '=' ? 2 : 1;
            case '>':
                if (d == '>') {
                    if (e == '>') {
                        return f == '=' ? 4 : 3;
                    }
                    return e == '=' ? 3 : 2;
                }
                return d == '=' ? 2 : 1;
            case '&':
                return d == '&' ? (e == '=' ? 3 : 2) : d == '=' ? 2 : 1;
            case '|':
                return d == '|' ? (e == '=' ? 3 : 2) : d == '=' ? 2 : 1;
            case '+':
                return d == '+' || d == '=' ? 2 : 1;
            case '-':
                return d == '-' || d == '=' ? 2 : 1;
            case '%':
            case '^':
                return d == '=' ? 2 : 1;
            case '{':
            case '}':
            case '(':
            case ')':
            case '[':
            case ']':
            case ';':
            case ',':
            case '~':
            case ':':
            case '@':
            case '#':
                return 1;
            default:
                return 0;
        }
    }

    /** May a `/` here start a regex literal? Decided by the token before it. */
    private boolean regexAllowed() {
        if (n == 0) {
            return true;
        }
        byte k = kind[n - 1];
        String v = k == TPL ? "" : (String) value[n - 1];
        if (k == PUNC) {
            return !(v.equals(")") || v.equals("]") || v.equals("++") || v.equals("--"));
        }
        if (k == ID) {
            return switch (v) {
                case "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do",
                        "else", "yield", "await" -> true;
                default -> false;
            };
        }
        return false;
    }

    /** `pos` is at '/'. Returns the index after the literal (flags included), or -1 when it is not one. */
    private static int regex(String s, int pos) {
        final int len = s.length();
        final int limit = Math.min(len, pos + MAX_REGEX_LEN);
        boolean inClass = false;
        int i = pos + 1;
        while (i < limit) {
            char c = s.charAt(i);
            if (c == '\\') {
                i += 2;
                continue;
            }
            if (c == '\n') {
                return -1;
            }
            if (inClass) {
                if (c == ']') {
                    inClass = false;
                }
            } else if (c == '[') {
                inClass = true;
            } else if (c == '/') {
                if (i == pos + 1) {
                    return -1;
                }
                i++;
                while (i < len && Character.isLetter(s.charAt(i))) {
                    i++;
                }
                return i;
            }
            i++;
        }
        return -1;
    }

    /** `pos` is at a backtick. Fills `segments` and returns the index after the closing backtick (or the end). */
    private static int template(String s, int pos, List<Object> segments, int nesting) {
        final int len = s.length();
        StringBuilder text = new StringBuilder();
        int i = pos + 1;
        while (i < len) {
            char c = s.charAt(i);
            if (c == '\\') {
                text.append(s, i, Math.min(i + 2, len));
                i += 2;
            } else if (c == '`') {
                flush(text, segments);
                return i + 1;
            } else if (c == '$' && i + 1 < len && s.charAt(i + 1) == '{') {
                flush(text, segments);
                int close = closingBrace(s, i + 2, nesting);
                segments.add(new Expr(Py.strip(s.substring(i + 2, close))));
                i = close + 1;
            } else {
                text.append(c);
                i++;
            }
        }
        flush(text, segments);
        return len;
    }

    private static void flush(StringBuilder text, List<Object> segments) {
        if (text.length() > 0) {
            segments.add(unescape(text.toString()));
            text.setLength(0);
        }
    }

    /** `i` is just after `${`. Returns the index of the matching `}` (or the end of the source). */
    private static int closingBrace(String s, int i, int nesting) {
        final int len = s.length();
        int depth = 1;
        while (i < len) {
            char c = s.charAt(i);
            if (c == '{') {
                depth++;
                i++;
            } else if (c == '}') {
                if (--depth == 0) {
                    return i;
                }
                i++;
            } else if (c == '`') {
                i = nesting < MAX_TEMPLATE_DEPTH ? template(s, i, new ArrayList<>(), nesting + 1) : i + 1;
            } else if (c == '"' || c == '\'') {
                int stop = quoted(s, i);
                i = stop > 0 ? stop : i + 1;
            } else {
                i++;
            }
        }
        return len;
    }

    private void pairBrackets() {
        pairs = new int[n];
        Arrays.fill(pairs, -1);
        int[] stack = new int[16];
        int depth = 0;
        for (int i = 0; i < n; i++) {
            if (kind[i] != PUNC) {
                continue;
            }
            String v = (String) value[i];
            if (v.length() != 1) {
                continue;
            }
            char c = v.charAt(0);
            if (c == '(' || c == '[' || c == '{') {
                if (depth == stack.length) {
                    stack = Arrays.copyOf(stack, depth * 2);
                }
                stack[depth++] = i;
            } else if (c == ')' || c == ']' || c == '}') {
                char want = c == ')' ? '(' : c == ']' ? '[' : '{';
                // tolerate imbalance: unwind to the nearest matching opener
                int j = depth - 1;
                while (j >= 0 && ((String) value[stack[j]]).charAt(0) != want) {
                    j--;
                }
                if (j >= 0) {
                    int open = stack[j];
                    depth = j;
                    pairs[open] = i;
                    pairs[i] = open;
                }
            }
        }
    }

    // ── string escapes ───────────────────────────────────────────────────────

    /** Resolve JavaScript string escapes. */
    static String unescape(String raw) {
        if (raw.indexOf('\\') < 0) {
            return raw;
        }
        final int len = raw.length();
        StringBuilder out = new StringBuilder(len);
        boolean surrogates = false;
        int i = 0;
        while (i < len) {
            char c = raw.charAt(i);
            if (c != '\\' || i + 1 >= len) {
                out.append(c);
                i++;
                continue;
            }
            char d = raw.charAt(i + 1);
            if (d == 'u') {
                if (i + 2 < len && raw.charAt(i + 2) == '{') {
                    int j = i + 3;
                    while (j < len && j - (i + 3) < 6 && isHex(raw.charAt(j))) {
                        j++;
                    }
                    if (j > i + 3 && j < len && raw.charAt(j) == '}') {
                        int cp = Integer.parseInt(raw, i + 3, j, 16);
                        if (cp <= Character.MAX_CODE_POINT) {
                            out.appendCodePoint(cp);
                            surrogates |= cp >= 0xd800 && cp <= 0xdfff;
                        }
                        i = j + 1;
                        continue;
                    }
                }
                if (i + 5 < len && isHex(raw.charAt(i + 2)) && isHex(raw.charAt(i + 3)) && isHex(raw.charAt(i + 4))
                        && isHex(raw.charAt(i + 5))) {
                    char unit = (char) Integer.parseInt(raw, i + 2, i + 6, 16);
                    out.append(unit);
                    surrogates |= Character.isSurrogate(unit);
                    i += 6;
                    continue;
                }
            } else if (d == 'x' && i + 3 < len && isHex(raw.charAt(i + 2)) && isHex(raw.charAt(i + 3))) {
                out.append((char) Integer.parseInt(raw, i + 2, i + 4, 16));
                i += 4;
                continue;
            }
            if (d == '\r' && i + 2 < len && raw.charAt(i + 2) == '\n') {
                i += 3;                                 // a line continuation
                continue;
            }
            switch (d) {
                case 'n' -> out.append('\n');
                case 't' -> out.append('\t');
                case 'r' -> out.append('\r');
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'v' -> out.append('\u000b');
                case '0' -> out.append('\0');
                case '\n', '\r', ' ', ' ' -> { }
                default -> out.append(d);
            }
            i += 2;
        }
        return surrogates ? repairSurrogates(out) : out.toString();
    }

    /** 😀 stays one character; a surrogate without its partner becomes U+FFFD. */
    private static String repairSurrogates(StringBuilder s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                i++;
            } else if (Character.isSurrogate(c)) {
                s.setCharAt(i, '�');
            }
        }
        return s.toString();
    }
}
