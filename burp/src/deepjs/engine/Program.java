package deepjs.engine;

import static deepjs.engine.Lexer.ID;
import static deepjs.engine.Lexer.NUM;
import static deepjs.engine.Lexer.PUNC;
import static deepjs.engine.Lexer.STR;
import static deepjs.engine.Lexer.TPL;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One tokenized source file and light static evaluation on top of it.
 *
 * No full parser is needed to answer the questions that matter here: what
 * string does this expression build, what are the keys of this object literal,
 * what are the arguments of this call.
 *
 *     "/api/" + ver + "/users/" + id        →  /api/v2/users/{id}
 *     `${BASE}/orders/${o.id}`              →  https://api.example.com/orders/{id}
 *     "".concat(base, "/items/").concat(n)  →  (what Babel emits for templates)
 *
 * Identifiers are resolved through a table of constants, but only when a name
 * has exactly one string value in the file: in minified code `a`, `e`, `t` are
 * reused in every scope, and guessing would invent URLs that do not exist.
 * `this.x` is resolved inside its own class, and a local from the nearest
 * assignment that is in scope.
 */
final class Program {

    /** One piece of a built string: literal text, or a value that is not known. */
    record Part(boolean variable, String text) {
    }

    /** What an expression evaluates to, and the index of the token after it. */
    record Eval(List<Part> parts, int next) {
    }

    /** Marks a variable part that is one of a few known strings:  (feed ? "/feed" : "") */
    static final String ALT = "\u0000alt\u0001";
    static final int MAX_CONST_LEN = 2000;
    private static final int MAX_DEPTH = 12;
    /** A `${…}` longer than this is not a plain reference. */
    private static final int MAX_REF_LEN = 300;

    private static final Pattern SIMPLE_REF = Py.rx("^[A-Za-z_$][\\w$]*(?:\\??\\.[A-Za-z_$][\\w$]*)*$");
    private static final Pattern MEMBER_DOT = Py.rx("\\??\\.");
    private static final Pattern LAST_NAME = Py.rx("([A-Za-z_$][\\w$]*)\\s*\\)*\\s*$");
    private static final Pattern WRAPPED_NAME = Py.rx("^(?:encodeURIComponent|encodeURI|String)\\(\\s*([\\w$.?]+)\\s*\\)$");
    private static final Set<String> WRAPPERS = Set.of(
            "encodeURIComponent", "encodeURI", "String", "Number", "parseInt", "escape", "toString",
            "trim", "toLowerCase", "toUpperCase", "toFixed", "valueOf", "stringify");
    private static final String[] ENV_ROOTS = {"process.env.", "import.meta.env.", "window.env.", "window._env_.", "window.__env."};
    private static final Set<String> NOT_A_REFERENCE = Set.of(
            "function", "return", "typeof", "new", "await", "void", "delete", "class",
            "if", "for", "while", "var", "let", "const", "case", "in", "of", "else");
    private static final List<Part> UNKNOWN = List.of();            // cached "no value" for this.x

    final String name;
    final Lexer lex;
    final byte[] kind;
    final Object[] value;
    final int[] pairs;
    final int n;

    /** identifier → the string values assigned to it; property name → string values. */
    final Map<String, Set<String>> consts = new HashMap<>();
    final Map<String, Set<String>> props = new HashMap<>();
    /** Names that also hold something other than one constant string. Never resolved. */
    final Set<String> tainted = new HashSet<>();
    final Set<String> taintedProps = new HashSet<>();
    final Set<String> params = new HashSet<>();
    /** Variables assigned once to a URL-shaped string that still has unknown pieces. */
    private final Map<String, List<Part>> templates = new HashMap<>();
    private final Map<String, Integer> assignments = new HashMap<>();
    /** `this.name = …` and class fields: name → (position, value index), sorted. */
    private final Map<String, List<int[]>> thisDefs = new HashMap<>();
    private final BitSet classBodies = new BitSet();
    private final Map<String, Map<Integer, List<Part>>> thisCache = new HashMap<>();
    private int[] enclosing;
    /** Every `name = …` and every parameter, by position. */
    private final Map<String, Py.Ints> declared = new HashMap<>();
    private final Map<String, Py.Ints> paramAt = new HashMap<>();
    private final Set<Integer> localBusy = new HashSet<>();
    /** name → positions of `name += …`. */
    private final Map<String, Py.Ints> appended = new HashMap<>();
    private final Map<Integer, Map<String, int[]>> objects = new HashMap<>();

    Program(String src, String name) {
        this.name = name;
        this.lex = new Lexer(src);
        this.kind = lex.kind;
        this.value = lex.value;
        this.pairs = lex.pairs;
        this.n = lex.n;
        collectAppends();
        collectThis();
        collectParameters();
        collectConstants(false);
        collectConstants(true);              // the second pass resolves constants built from constants
    }

    // ── small accessors ──────────────────────────────────────────────────────

    byte kind(int i) {
        return i >= 0 && i < n ? kind[i] : 0;
    }

    /** The token's text; null for a template literal or an index outside the file. */
    String text(int i) {
        return i >= 0 && i < n && kind[i] != TPL ? (String) value[i] : null;
    }

    boolean isPunc(int i, String v) {
        return i >= 0 && i < n && kind[i] == PUNC && v.equals(value[i]);
    }

    boolean isId(int i, String v) {
        return i >= 0 && i < n && kind[i] == ID && v.equals(value[i]);
    }

    private boolean isPuncIn(int i, String... options) {
        return i >= 0 && i < n && kind[i] == PUNC && Py.in((String) value[i], options);
    }

    private boolean opens(int i) {
        return isPuncIn(i, "(", "[", "{");
    }

    int line(int i) {
        return lex.tokenLine(i);
    }

    // ── rendering ────────────────────────────────────────────────────────────

    static String render(List<Part> parts) {
        StringBuilder b = new StringBuilder();
        for (Part p : parts) {
            if (!p.variable()) {
                b.append(p.text());
            } else if (p.text().startsWith(ALT)) {
                b.append("{param}");
            } else {
                b.append('{').append(p.text()).append('}');
            }
        }
        return b.toString();
    }

    /** Every string `parts` can be when it holds either/or pieces; just `parts` when it has none. */
    static List<List<Part>> expand(List<Part> parts) {
        final int limit = 6;
        List<List<Part>> out = new ArrayList<>();
        out.add(new ArrayList<>());
        for (Part p : parts) {
            Part part = p;
            if (p.variable() && p.text().startsWith(ALT)) {
                List<String> choices = Py.split(p.text().substring(ALT.length()), "\u0001");
                if (out.size() * choices.size() <= limit) {
                    List<List<Part>> next = new ArrayList<>();
                    for (List<Part> o : out) {
                        for (String c : choices) {
                            List<Part> grown = new ArrayList<>(o);
                            grown.add(new Part(false, c));
                            next.add(grown);
                        }
                    }
                    out = next;
                    continue;
                }
                part = new Part(true, "param");
            }
            for (List<Part> o : out) {
                o.add(part);
            }
        }
        out.replaceAll(Program::merge);
        return out;
    }

    static boolean isStatic(List<Part> parts) {
        if (parts.isEmpty()) {
            return false;
        }
        for (Part p : parts) {
            if (p.variable()) {
                return false;
            }
        }
        return true;
    }

    static String literal(List<Part> parts) {
        StringBuilder b = new StringBuilder();
        for (Part p : parts) {
            if (!p.variable()) {
                b.append(p.text());
            }
        }
        return b.toString();
    }

    /** Placeholder name for an unresolved identifier (minified names carry no meaning). */
    static String varName(String name) {
        String s = Py.strip(name, "_$");
        return s.length() > 2 || Py.in(Py.lower(s), "id", "pk", "ip", "qs", "tx") ? s : "param";
    }

    /** Consecutive literal pieces become one part (joined once, however many there are); empty ones vanish. */
    private static List<Part> merge(List<Part> parts) {
        List<Part> out = new ArrayList<>(parts.size());
        StringBuilder run = new StringBuilder();
        for (Part p : parts) {
            if (!p.variable()) {
                run.append(p.text());
                continue;
            }
            if (run.length() > 0) {
                out.add(new Part(false, run.toString()));
                run.setLength(0);
            }
            out.add(p);
        }
        if (run.length() > 0) {
            out.add(new Part(false, run.toString()));
        }
        return out;
    }

    private static boolean hasKnownText(List<Part> parts) {
        for (Part p : parts) {
            if (!p.variable() && !p.text().isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private static int totalLength(List<Part> parts) {
        int total = 0;
        for (Part p : parts) {
            total += p.text().length();
        }
        return total;
    }

    // ── structure ────────────────────────────────────────────────────────────

    /** Token ranges [start, end) of each top-level argument of the call at `(`. */
    List<int[]> callArgs(int openParen) {
        List<int[]> args = new ArrayList<>();
        int close = openParen >= 0 && openParen < n ? pairs[openParen] : -1;
        if (close < 0) {
            return args;
        }
        int start = openParen + 1, i = start;
        while (i < close) {
            if (kind[i] == PUNC) {
                if (opens(i)) {
                    if (pairs[i] > i) {
                        i = pairs[i] + 1;
                        continue;
                    }
                } else if (",".equals(value[i])) {
                    args.add(new int[]{start, i});
                    start = i + 1;
                }
            }
            i++;
        }
        if (start < close) {
            args.add(new int[]{start, close});
        }
        return args;
    }

    /**
     * Top-level properties of the object literal at `{`: key → [value start, value end).
     * Shorthand `{a, b}` maps a key to its own token; methods and spreads are skipped.
     */
    Map<String, int[]> objectAt(int openBrace) {
        Map<String, int[]> known = objects.get(openBrace);
        if (known != null) {
            return known;                                   // asked for once per key of a large literal: read it once
        }
        Map<String, int[]> out = new LinkedHashMap<>();
        int close = openBrace >= 0 && openBrace < n ? pairs[openBrace] : -1;
        if (close < 0) {
            return out;
        }
        objects.put(openBrace, out);
        int i = openBrace + 1;
        while (i < close) {
            byte k = kind[i];
            String key = k == ID || k == STR || k == NUM ? (String) value[i] : null;
            if (key == null && isPunc(i, "[")) {            // a computed key: skip it
                i = pairs[i] > i ? pairs[i] + 1 : i + 1;
                continue;
            }
            if (key != null && isPunc(i + 1, ":")) {
                int from = i + 2, to = valueEnd(from, close);
                out.put(key, new int[]{from, to});
                i = to + 1;
                continue;
            }
            if (key != null && k == ID && (isPunc(i + 1, ",") || i + 1 == close)) {
                out.put(key, new int[]{i, i + 1});          // shorthand property
                i += 2;
                continue;
            }
            i = valueEnd(i, close) + 1;                     // method, spread, getter
        }
        return out;
    }

    /** Index of the top-level `,` that ends the value starting at `i` (or `limit`). */
    int valueEnd(int i, int limit) {
        while (i < limit) {
            if (kind[i] == PUNC) {
                if (opens(i)) {
                    if (pairs[i] > i) {
                        i = pairs[i] + 1;
                        continue;
                    }
                } else if (",".equals(value[i])) {
                    return i;
                }
            }
            i++;
        }
        return limit;
    }

    // ── string expression evaluation ─────────────────────────────────────────

    Eval evalExpr(int i) {
        return evalExpr(i, 0);
    }

    /**
     * Evaluate the string-building expression that starts at token `i`. The
     * parts are empty when `i` does not start something that can be part of a string.
     */
    Eval evalExpr(int i, int depth) {
        List<Part> parts = new ArrayList<>();
        while (true) {
            Eval term = evalTerm(i, depth);
            if (term.next() == i) {
                break;
            }
            parts.addAll(term.parts());
            i = term.next();
            // "".concat(a, "/x").concat(b) — Babel's output for template literals
            while (isPunc(i, ".") && isId(i + 1, "concat") && isPunc(i + 2, "(")) {
                int close = pairs[i + 2];
                if (close < 0) {
                    break;
                }
                for (int[] arg : callArgs(i + 2)) {
                    Eval sub = evalExpr(arg[0], depth + 1);
                    if (!sub.parts().isEmpty() && sub.next() >= arg[1]) {
                        parts.addAll(sub.parts());
                    } else {
                        parts.add(new Part(true, "param"));
                    }
                }
                i = close + 1;
            }
            if (isPunc(i, "+")) {
                i++;
                continue;
            }
            break;
        }
        return new Eval(merge(parts), i);
    }

    @SuppressWarnings("unchecked")
    private Eval evalTerm(int i, int depth) {
        if (i >= n || depth > MAX_DEPTH) {
            return new Eval(List.of(), i);
        }
        switch (kind[i]) {
            case STR, NUM:
                return new Eval(List.of(new Part(false, (String) value[i])), i + 1);
            case TPL:
                return new Eval(evalTemplate((List<Object>) value[i], i, depth), i + 1);
            case ID:
                return evalReference(i, depth);
            case PUNC:
                if (!"(".equals(value[i])) {
                    break;
                }
                int close = pairs[i];
                if (close < 0) {
                    break;
                }
                Eval inner = evalExpr(i + 1, depth + 1);
                if (!inner.parts().isEmpty() && inner.next() == close) {
                    return new Eval(inner.parts(), close + 1);
                }
                List<String> branches = literalBranches(i + 1, close, depth);
                if (branches != null) {                     // (cond ? "/feed" : "")
                    return new Eval(List.of(new Part(true, ALT + String.join("\u0001", branches))), close + 1);
                }
                return new Eval(List.of(new Part(true, "param")), close + 1);   // (a || "/x"), (c ? x : f())
            default:
                break;
        }
        return new Eval(List.of(), i);
    }

    /** identifier, member chain, optional call / index. */
    private Eval evalReference(int i, int depth) {
        if (NOT_A_REFERENCE.contains((String) value[i])) {
            return new Eval(List.of(), i);
        }
        List<String> chain = new ArrayList<>();
        chain.add((String) value[i]);
        int j = i + 1;
        while ((isPunc(j, ".") || isPunc(j, "?.")) && kind(j + 1) == ID) {
            chain.add((String) value[j + 1]);
            j += 2;
        }
        boolean called = isPunc(j, "(") || isPunc(j, "[");

        if (chain.size() == 2 && chain.get(0).equals("this") && !called) {
            List<Part> own = thisValue(chain.get(1), i, depth);
            if (own != null) {
                return new Eval(new ArrayList<>(own), j);
            }
        }
        if (chain.size() == 1 && !called) {
            List<Part> local = localValue(chain.get(0), i, depth);
            if (local != null) {
                return new Eval(new ArrayList<>(local), j);
            }
        }

        String resolved = resolve(chain);
        String last = chain.get(chain.size() - 1);
        if (resolved == null && chain.size() == 1 && templates.containsKey(last)
                && assignments.getOrDefault(last, 0) == 1 && !params.contains(last) && !called && !isPunc(j, ".")) {
            return new Eval(new ArrayList<>(templates.get(last)), j);
        }

        // trailing call / index chains: a.b(c)[d].e()
        for (int guard = 0; guard < 8; guard++) {
            if (isPunc(j, "(")) {
                int close = pairs[j];
                if (close < 0) {
                    break;
                }
                if (WRAPPERS.contains(last)) {
                    List<int[]> args = callArgs(j);
                    if (!args.isEmpty()) {
                        Eval inner = evalExpr(args.get(0)[0], depth + 1);
                        if (!inner.parts().isEmpty() && inner.next() >= args.get(0)[1]) {
                            return new Eval(inner.parts(), close + 1);
                        }
                    }
                    if (chain.size() >= 2) {                // x.toString(): keep the receiver's name
                        last = chain.get(chain.size() - 2);
                    }
                }
                resolved = null;
                j = close + 1;
            } else if (isPunc(j, "[")) {
                int close = pairs[j];
                if (close < 0) {
                    break;
                }
                resolved = null;
                j = close + 1;
            } else if ((isPunc(j, ".") || isPunc(j, "?.")) && kind(j + 1) == ID && !"concat".equals(value[j + 1])) {
                String next = (String) value[j + 1];
                if (!WRAPPERS.contains(next)) {
                    last = next;
                }
                chain.add(next);
                resolved = null;
                j += 2;
            } else {
                break;
            }
        }
        return new Eval(List.of(resolved != null ? new Part(false, resolved) : new Part(true, varName(last))), j);
    }

    private String resolve(List<String> chain) {
        String key = chain.get(chain.size() - 1);
        Set<String> values;
        if (chain.size() == 1) {
            if (tainted.contains(key)) {
                return null;
            }
            values = consts.get(key);
        } else {
            if (taintedProps.contains(key)) {
                return null;
            }
            values = props.get(key);
        }
        return values != null && values.size() == 1 ? values.iterator().next() : null;
    }

    private List<Part> evalTemplate(List<Object> segments, int at, int depth) {
        List<Part> parts = new ArrayList<>();
        for (Object segment : segments) {
            if (segment instanceof String text) {
                parts.add(new Part(false, text));
                continue;
            }
            String expr = ((Lexer.Expr) segment).source();
            boolean brief = expr.length() <= MAX_REF_LEN;
            if (brief && Py.matches(SIMPLE_REF, expr)) {
                List<String> chain = new ArrayList<>();
                for (String piece : MEMBER_DOT.split(expr, -1)) {
                    if (!piece.isEmpty()) {
                        chain.add(piece);
                    }
                }
                if (chain.size() == 2 && chain.get(0).equals("this") && at >= 0) {
                    List<Part> own = thisValue(chain.get(1), at, depth);
                    if (own != null) {
                        parts.addAll(own);
                        continue;
                    }
                }
                String last = chain.get(chain.size() - 1);
                String known = resolve(chain);
                if (known == null && Py.startsWithAny(expr, ENV_ROOTS)) {
                    Set<String> values = props.get(last);
                    if (values == null || values.isEmpty()) {
                        values = consts.get(last);
                    }
                    known = values != null && values.size() == 1 ? values.iterator().next() : null;
                }
                parts.add(known != null ? new Part(false, known) : new Part(true, varName(last)));
            } else {
                Matcher wrapped = WRAPPED_NAME.matcher(expr);
                if (brief && wrapped.matches()) {
                    String[] pieces = MEMBER_DOT.split(wrapped.group(1), -1);
                    parts.add(new Part(true, varName(pieces[pieces.length - 1])));
                } else {
                    // only the end of a long expression is looked at: the name is there, and the search stays linear
                    Matcher tail = LAST_NAME.matcher(brief ? expr : expr.substring(expr.length() - MAX_REF_LEN));
                    parts.add(new Part(true, tail.find() ? varName(tail.group(1)) : "param"));
                }
            }
        }
        return parts;
    }

    /** The template literal at token `i` on its own — not the `a + b` chain it may be part of. */
    @SuppressWarnings("unchecked")
    List<Part> templateParts(int i) {
        return merge(evalTemplate((List<Object>) value[i], i, 0));
    }

    /** Walk left from token `i` to the first token of its `a + b + c` chain. */
    int exprStart(int i) {
        int j = i;
        for (int guard = 0; j >= 2 && guard < 64 && isPunc(j - 1, "+"); guard++) {
            int k = j - 2;
            byte kk = kind[k];
            if (kk == STR || kk == TPL || kk == NUM) {
                j = k;
            } else if (kk == ID) {
                while (k >= 2 && isPunc(k - 1, ".") && kind(k - 2) == ID) {     // a.b.c + "…"
                    k -= 2;
                }
                j = k;
            } else if (isPunc(k, ")")) {
                int open = pairs[k];
                if (open < 0) {
                    break;
                }
                k = open;
                while (k >= 1 && kind(k - 1) == ID) {                           // f(x) + "…": include the callee
                    k--;
                    if (k >= 1 && isPunc(k - 1, ".")) {
                        k--;
                    } else {
                        break;
                    }
                }
                j = k;
            } else {
                break;
            }
        }
        return j;
    }

    // ── `this.x` inside a class ──────────────────────────────────────────────

    /** Record where every `this.name = …` and class field `name = …` is. */
    private void collectThis() {
        for (int i = 0; i < n - 3; i++) {
            if (kind[i] != ID) {
                continue;
            }
            String v = (String) value[i];
            if (v.equals("this")) {
                if (isPunc(i + 1, ".") && kind[i + 2] == ID && isPunc(i + 3, "=")) {
                    thisDefs.computeIfAbsent((String) value[i + 2], k -> new ArrayList<>()).add(new int[]{i, i + 4});
                }
            } else if (v.equals("class") && !(i > 0 && isPunc(i - 1, "."))) {
                // class [Name] [extends <expr>] {
                int j = i + 1, limit = Math.min(n, i + 40);
                while (j < limit && !isPunc(j, "{")) {
                    if (kind[j] == PUNC) {
                        if (isPuncIn(j, "(", "[") && pairs[j] > j) {
                            j = pairs[j];
                        } else if (isPuncIn(j, ";", "}", ")", ":", ",", "=")) {
                            break;
                        }
                    }
                    j++;
                }
                if (j < limit && isPunc(j, "{") && pairs[j] > j) {
                    classBodies.set(j);
                    classFields(j);
                }
            }
        }
        Comparator<int[]> order = Comparator.<int[]>comparingInt(d -> d[0]).thenComparingInt(d -> d[1]);
        for (List<int[]> defs : thisDefs.values()) {
            defs.sort(order);
        }
    }

    /** Field definitions directly in a class body:  host = this.hostServer + "/api/Users"; */
    private void classFields(int openBrace) {
        int close = pairs[openBrace];
        boolean atMember = true;
        int i = openBrace + 1;
        while (i < close) {
            if (kind[i] == PUNC) {
                if (opens(i) && pairs[i] > i) {
                    atMember = "{".equals(value[i]);        // a method body ends a member
                    i = pairs[i] + 1;
                    continue;
                }
                atMember = ";".equals(value[i]);
            } else if (atMember && kind[i] == ID) {
                int k = "static".equals(value[i]) && kind(i + 1) == ID ? i + 1 : i;
                if (isPunc(k + 1, "=")) {
                    thisDefs.computeIfAbsent((String) value[k], x -> new ArrayList<>()).add(new int[]{k, k + 2});
                }
                atMember = false;
            } else {
                atMember = false;
            }
            i++;
        }
    }

    /** For every token, the index of the innermost `{` that contains it (-1 at top level). */
    private int[] enclosing() {
        if (enclosing == null) {
            int[] encl = new int[n];
            int[] stack = new int[16];
            int depth = 0;
            int current = -1;
            for (int i = 0; i < n; i++) {
                if (kind[i] == PUNC) {
                    if ("{".equals(value[i]) && pairs[i] > i) {
                        encl[i] = current;
                        if (depth == stack.length) {
                            stack = java.util.Arrays.copyOf(stack, depth * 2);
                        }
                        stack[depth++] = current;
                        current = i;
                        continue;
                    }
                    if ("}".equals(value[i]) && depth > 0 && pairs[current] == i) {
                        current = stack[--depth];
                    }
                }
                encl[i] = current;
            }
            enclosing = encl;
        }
        return enclosing;
    }

    /**
     * What `this.<name>` holds at token `at`: the one definition in the class
     * (or constructor-function scope) around it. Null when there is no
     * definition, more than one, or it is not a string with known text.
     */
    private List<Part> thisValue(String name, int at, int depth) {
        List<int[]> defs = thisDefs.get(name);
        if (defs == null || defs.isEmpty() || depth > MAX_DEPTH || at < 0 || at >= n) {
            return null;
        }
        int[] encl = enclosing();
        int block = encl[at];
        for (int hops = 0; block >= 0 && hops < 10; hops++) {
            int close = pairs[block];
            int lo = firstAfter(defs, block), hi = firstAtOrAfter(defs, close);
            if (hi - lo > 1) {
                return null;
            }
            if (hi - lo == 1) {
                Map<Integer, List<Part>> cached = thisCache.computeIfAbsent(name, k -> new HashMap<>());
                List<Part> known = cached.get(block);
                if (known != null) {
                    return known == UNKNOWN ? null : known;
                }
                cached.put(block, UNKNOWN);                 // guards  this.a = this.a + "…"
                int pos = defs.get(lo)[0], valueAt = defs.get(lo)[1];
                int owner = encl[pos];
                // outside a class, only a constructor function declared directly in this scope counts:
                //   function F(){ this.host = … }  F.prototype.get = function(){ … }
                if (classBodies.get(block) || owner == block || (owner >= 0 && encl[owner] == block)) {
                    Eval e = evalExpr(valueAt, depth + 1);
                    List<Part> parts = e.parts();
                    boolean continues = isPuncIn(e.next(), "?", "(", ".", "[", "||", "&&", "??");
                    // host = env.apiRoot: nothing known, but `apiRoot` is the name another file may define
                    boolean alias = parts.size() == 1 && parts.get(0).variable() && !parts.get(0).text().equals("param");
                    if (!parts.isEmpty() && !continues && (hasKnownText(parts) || alias) && totalLength(parts) <= MAX_CONST_LEN) {
                        cached.put(block, parts);
                    }
                }
                known = cached.get(block);
                return known == UNKNOWN ? null : known;
            }
            if (classBodies.get(block)) {
                return null;
            }
            block = encl[block];
        }
        return null;
    }

    /** Index of the first definition positioned after `position`. */
    private int firstAfter(List<int[]> defs, int position) {
        int lo = 0, hi = defs.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            int[] d = defs.get(mid);
            if (position < d[0] || (position == d[0] && n < d[1])) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        return lo;
    }

    /** Index of the first definition positioned at or after `position`. */
    private static int firstAtOrAfter(List<int[]> defs, int position) {
        int lo = 0, hi = defs.size();
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            int[] d = defs.get(mid);
            if (d[0] < position || (d[0] == position && d[1] < -1)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        return lo;
    }

    // ── locals ───────────────────────────────────────────────────────────────

    /**
     * let r = this.host + "/submitKey", n = {…};  return this.http.post(r, n)
     *
     * The value of the nearest earlier `name = …` that is in scope at `at`.
     * Null when there is none, when a parameter called `name` is declared in
     * between (it may shadow it), when it is appended to afterwards, or when
     * the value is not a string with known text.
     */
    private List<Part> localValue(String name, int at, int depth) {
        if (depth > MAX_DEPTH) {
            return null;
        }
        int pos = localDecl(name, at);
        if (pos < 0 || !localBusy.add(pos)) {
            return null;
        }
        try {
            return assigned(pos + 2, depth);
        } finally {
            localBusy.remove(pos);
        }
    }

    /** Position of the nearest earlier `name = …` in scope at `at`, or -1. */
    private int localDecl(String name, int at) {
        Py.Ints decls = declared.get(name);
        if (decls == null || decls.size() == 0) {
            return -1;
        }
        int k = decls.bisectLeft(at) - 1;
        if (k < 0) {
            return -1;
        }
        int pos = decls.get(k);
        if (name.length() <= 2 && at - pos > 2500) {
            return -1;
        }
        int[] encl = enclosing();
        int block = encl[at], home = encl[pos];
        for (int hops = 0; block != home; hops++) {         // the assignment's block must enclose the use
            if (block < 0 || hops >= 8) {
                return -1;
            }
            block = encl[block];
        }
        Py.Ints declaredParams = paramAt.get(name);
        if (declaredParams != null && declaredParams.size() > 0) {
            int lo = declaredParams.bisectRight(pos);
            if (lo < declaredParams.size() && declaredParams.get(lo) < at) {
                return -1;
            }
        }
        Py.Ints appends = appended.get(name);              // r += "/more": not the value that was assigned
        if (appends != null) {
            int lo = appends.bisectLeft(pos + 2);
            if (lo < appends.size() && appends.get(lo) < at) {
                return -1;
            }
        }
        return pos;
    }

    /** If the identifier at `at` was assigned an object literal in scope, the index of its `{`; else -1. */
    int localObject(int at) {
        if (kind(at) != ID) {
            return -1;
        }
        int pos = localDecl((String) value[at], at);
        return pos >= 0 && isPunc(pos + 2, "{") ? pos + 2 : -1;
    }

    private List<Part> assigned(int valueAt, int depth) {
        Eval e = evalExpr(valueAt, depth + 1);
        if (isPuncIn(e.next(), "?", "&&", "||", "??", ">", "<", "===", "==", "!==", "!=")) {
            List<Part> suffix = querySuffix(valueAt, depth);
            if (suffix != null) {
                return suffix;
            }
            List<String> branches = literalBranches(valueAt, -1, depth);     // u = feed ? "/a/feed" : "/a"
            return branches == null ? null : List.of(new Part(true, ALT + String.join("\u0001", branches)));
        }
        if (isPuncIn(e.next(), "(", ".", "[")) {
            return null;
        }
        List<Part> parts = e.parts();
        return !parts.isEmpty() && hasKnownText(parts) && totalLength(parts) <= MAX_CONST_LEN ? parts : null;
    }

    /** {index of `?`, index of `:`, end} of the conditional starting at `start`; null when it is not one. */
    private int[] ternary(int start, int close) {
        int i = start, question = -1, colon = -1;
        int limit = close >= 0 ? close : n;
        for (int guard = 0; i < limit && guard < 400; guard++) {
            if (kind[i] == PUNC) {
                String v = (String) value[i];
                if (opens(i) && pairs[i] > i) {
                    i = pairs[i] + 1;
                    continue;
                }
                if (Py.in(v, ",", ";", ")", "]", "}")) {
                    break;
                }
                if (v.equals("?") && question < 0) {
                    question = i;
                } else if (v.equals(":") && question >= 0 && colon < 0) {
                    colon = i;
                }
            }
            i++;
        }
        return question >= 0 && colon >= 0 && (close < 0 || i == close) ? new int[]{question, colon, i} : null;
    }

    /** The two strings of  cond ? "a" : "b"  when both are constants (one may be empty) and they differ. */
    List<String> literalBranches(int start, int close, int depth) {
        if (depth > MAX_DEPTH) {
            return null;
        }
        int[] t = ternary(start, close);
        if (t == null) {
            return null;
        }
        Eval first = evalExpr(t[0] + 1, depth + 1), second = evalExpr(t[1] + 1, depth + 1);
        if (first.next() != t[1] || second.next() != t[2]) {
            return null;
        }
        for (Part p : first.parts()) {
            if (p.variable()) {
                return null;
            }
        }
        for (Part p : second.parts()) {
            if (p.variable()) {
                return null;
            }
        }
        String a = render(first.parts()), b = render(second.parts());
        if (a.equals(b) || a.length() > 200 || b.length() > 200 || (a + b).indexOf('\u0000') >= 0 || (a + b).indexOf('\u0001') >= 0) {
            return null;
        }
        return List.of(a, b);
    }

    /** t = fields && fields.length ? `?fields=${fields.join(",")}` : ""   →   ?fields={param} */
    private List<Part> querySuffix(int valueAt, int depth) {
        int[] t = ternary(valueAt, -1);
        if (t == null) {
            return null;
        }
        Eval first = evalExpr(t[0] + 1, depth + 1), second = evalExpr(t[1] + 1, depth + 1);
        if (first.next() != t[1] || second.next() != t[2]) {
            return null;
        }
        List<Part> chosen = null;
        for (List<Part> branch : List.of(first.parts(), second.parts())) {
            String text = render(branch);
            if (text.isEmpty()) {
                continue;
            }
            if (!(text.startsWith("?") || text.startsWith("&")) || branch.get(0).variable()) {
                return null;
            }
            if (chosen == null) {
                chosen = branch;
            }
        }
        return chosen;
    }

    // ── constants ────────────────────────────────────────────────────────────

    private void collectAppends() {
        for (int i = 0; i < n - 1; i++) {
            if (kind[i] == ID && isPunc(i + 1, "+=")) {
                appended.computeIfAbsent((String) value[i], k -> new Py.Ints()).add(i);
            }
        }
    }

    /** Function / arrow / catch parameters are runtime values, never constants. */
    private void collectParameters() {
        for (int i = 0; i < n; i++) {
            if (kind[i] == ID) {
                String v = (String) value[i];
                boolean function = v.equals("function");
                if (function || v.equals("catch")) {
                    int j = i + 1;
                    if (function) {
                        if (isPunc(j, "*")) {
                            j++;
                        }
                        if (kind(j) == ID) {
                            j++;
                        }
                    }
                    if (isPunc(j, "(")) {
                        taintGroup(j);
                    }
                }
            } else if (kind[i] == PUNC) {
                String v = (String) value[i];
                if (v.equals("=>") && i > 0) {
                    if (kind[i - 1] == ID) {
                        declareParam((String) value[i - 1], i - 1);
                    } else if (isPunc(i - 1, ")") && pairs[i - 1] >= 0) {
                        taintGroup(pairs[i - 1]);
                    }
                } else if (v.equals("(") && i > 1 && kind[i - 1] == ID && pairs[i] > 0 && isPunc(pairs[i] + 1, "{")
                        && !isPunc(i - 2, ",") && kind[i - 2] != ID
                        && !Py.in((String) value[i - 1], "if", "for", "while", "switch", "with")) {
                    taintGroup(i);                          // method shorthand:  name(a, b) { … }
                }
            }
        }
    }

    private void declareParam(String name, int at) {
        tainted.add(name);
        params.add(name);
        paramAt.computeIfAbsent(name, k -> new Py.Ints()).add(at);
    }

    private void taintGroup(int openParen) {
        int close = pairs[openParen];
        if (close < 0) {
            return;
        }
        int depth = 0;
        for (int k = openParen + 1; k < close; k++) {
            if (kind[k] == PUNC) {
                if (opens(k)) {
                    depth++;
                } else if (isPuncIn(k, ")", "]", "}")) {
                    depth--;
                }
            } else if (kind[k] == ID && depth <= 1) {
                declareParam((String) value[k], k);
            }
        }
    }

    private void collectConstants(boolean last) {
        for (int i = 0; i < n - 2; i++) {
            byte k = kind[i];
            if ((k != ID && k != STR) || kind[i + 1] != PUNC) {
                continue;
            }
            String op = (String) value[i + 1];
            String key = (String) value[i];
            boolean isProp;
            if (op.equals("+=") && k == ID) {
                // appended to afterwards: whatever it was assigned is not its final value
                (i > 0 && isPunc(i - 1, ".") ? taintedProps : tainted).add(key);
                continue;
            }
            if (op.equals("=") && k == ID) {
                isProp = i > 0 && isPunc(i - 1, ".");
            } else if (op.equals(":") && i > 0 && isPuncIn(i - 1, "{", ",")) {
                isProp = true;
            } else {
                continue;
            }
            if (last && !isProp) {
                assignments.merge(key, 1, Integer::sum);
                if (op.equals("=")) {
                    declared.computeIfAbsent(key, x -> new Py.Ints()).add(i);
                }
            }
            String constant = null;
            List<Part> parts = List.of();
            boolean continues = false;
            byte vk = kind[i + 2];
            if (vk == STR || vk == TPL || vk == ID) {
                Eval e = evalExpr(i + 2, 0);
                parts = e.parts();
                // the value must end the expression: a ternary / call continues past it
                continues = isPuncIn(e.next(), "?", "(", ".", "[", "||", "&&", "??");
                if (isStatic(parts) && !continues && !parts.get(0).text().isEmpty()
                        && parts.get(0).text().length() <= MAX_CONST_LEN) {
                    constant = parts.get(0).text();
                }
            }
            if (constant != null) {
                (isProp ? props : consts).computeIfAbsent(key, x -> new HashSet<>()).add(constant);
            } else if (last) {
                (isProp ? taintedProps : tainted).add(key);
                if (!isProp && !parts.isEmpty() && !continues && hasSlashInKnownText(parts)) {
                    templates.put(key, parts);
                }
            }
        }
    }

    private static boolean hasSlashInKnownText(List<Part> parts) {
        for (Part p : parts) {
            if (!p.variable() && p.text().indexOf('/') >= 0) {
                return true;
            }
        }
        return false;
    }
}
