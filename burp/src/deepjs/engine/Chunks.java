package deepjs.engine;

import static deepjs.engine.Lexer.ID;
import static deepjs.engine.Lexer.NUM;
import static deepjs.engine.Lexer.PUNC;
import static deepjs.engine.Lexer.STR;
import static deepjs.engine.Lexer.TPL;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The scripts an application has that no page links to.
 *
 * A bundler's runtime holds a function that turns a chunk id into a file name:
 *
 *     r.u = e => "static/js/" + ({3:"admin",7:"billing"}[e] || e) + "." + {3:"9f1c",7:"02ab"}[e] + ".chunk.js"
 *
 * Evaluating it for every id in its maps names every lazy chunk of the
 * application — the admin panel included — without loading any of them.
 * Also read: script tags and inline scripts of an HTML page, plain references
 * to other scripts (Vite / Rollup dynamic imports), and the routes of a
 * Next.js build manifest.
 */
final class Chunks {

    /** External script URLs (absolute) and inline script bodies of an HTML page. */
    static final class HtmlScripts {
        final List<String> urls = new ArrayList<>();
        final List<String> inline = new ArrayList<>();
    }

    record Form(String method, String action, List<String> fields) {
    }

    /** Other scripts (absolute URLs when the referring script has one) and manifest routes. */
    static final class Discovery {
        final List<String> scripts = new ArrayList<>();
        List<String> routes = new ArrayList<>();
    }

    private record Lookup(Map<String, String> map, String parameter, int end) {
    }

    private static final int MAX_CHUNKS_PER_FILE = 1500;
    private static final int MAX_INLINE_CHARS = 2 * 1024 * 1024;

    private static final Pattern ATTRIBUTE = Py.rx("\\b([a-zA-Z\\-]+)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
    private static final Pattern SRC = Py.rxi("\\bsrc\\s*=\\s*(?:\"([^\"]+)\"|'([^']+)'|([^\\s>]+))");
    private static final Pattern BASE_HREF = Py.rxi("\\bhref\\s*=\\s*[\"']([^\"']+)[\"']");
    private static final Pattern NAME = Py.rxi("\\bname\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))");
    private static final Pattern HAS_SRC = Py.rxi("\\bsrc\\s*=");
    private static final Pattern SCRIPT_TYPE = Py.rxi("\\btype\\s*=\\s*[\"']?([^\"'\\s>]+)");
    private static final Pattern JS_HREF = Py.rx("\\.m?js(?:\\?|$)");
    /** A real file name: at least one name character before the extension (".chunk.js" alone is a suffix). */
    private static final Pattern JS_FILE = Py.rx("^(?:[\\w.\\-~@+%\\[\\]]*/)*[\\w\\[@~][\\w.\\-~@+%\\[\\]]*\\.m?js(?:\\?[\\w.\\-=&%]*)?$");
    private static final Pattern NOT_A_PAGE = Py.rxi("^(?:mailto:|tel:|sms:|javascript:|data:|blob:|about:|#|whatsapp:|skype:)");
    private static final Pattern OPEN_SCRIPT = Py.rxi("<(?:script)\\b"), CLOSE_SCRIPT = Py.rxi("</script\\s*>");
    private static final Pattern OPEN_FORM = Py.rxi("<(?:form)\\b"), CLOSE_FORM = Py.rxi("</form\\s*>");
    private static final Pattern OPEN_LINK = Py.rxi("<(?:link)\\b"), OPEN_BASE = Py.rxi("<(?:base)\\b");
    private static final Pattern OPEN_FIELD = Py.rxi("<(?:input|select|textarea|button)\\b");
    /** A start tag longer than this is not a tag. */
    private static final int MAX_TAG = 65536;
    private static final int MAX_CHUNK_NESTING = 40;
    private static final Pattern ASSET_NAME = Py.rx("\\.(?:m?js|css)$");
    private static final Pattern NETWORK_PATH = Py.rx("^(?:https?:)?//");
    private static final Pattern ENTITY = Py.rx("&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|(?:amp|lt|gt|quot|apos|nbsp);|(?:amp|lt|gt|quot))");

    private Chunks() {
    }

    // ── HTML ─────────────────────────────────────────────────────────────────

    private static String firstGroup(Matcher m, int from) {
        for (int g = from; g < from + 3; g++) {
            String v = m.group(g);
            if (v != null && !v.isEmpty()) {
                return v;
            }
        }
        return "";
    }

    /**
     * The attribute text of every start tag `opener` finds, in document order.
     *
     * One pass: the position of the next `>` is remembered between tags, so a
     * page with thousands of opening tags and no `>` costs one scan, not one per tag.
     */
    private static List<String> tags(String html, Pattern opener) {
        List<String> out = new ArrayList<>();
        Matcher m = opener.matcher(html);
        int pos = 0, gt = -2;
        while (m.find(pos)) {
            pos = m.end();
            if (gt < pos) {
                gt = html.indexOf('>', pos);
                if (gt < 0) {
                    break;                                  // no tag from here on is ever closed
                }
            }
            if (gt - pos <= MAX_TAG) {
                out.add(html.substring(pos, gt));
            }
        }
        return out;
    }

    /**
     * {attribute text, content} of every `<name …>…</name>`, in document order.
     * A start tag whose attributes match `skip` is passed over, content and all.
     * Linear for the same reason as {@link #tags}, and because the first element
     * left unclosed ends the search: nothing after it can be closed either.
     */
    private static List<String[]> elements(String html, Pattern opener, Pattern closer, Pattern skip) {
        List<String[]> out = new ArrayList<>();
        Matcher open = opener.matcher(html), close = closer.matcher(html);
        int pos = 0, gt = -2;
        while (open.find(pos)) {
            pos = open.end();
            if (gt < pos) {
                gt = html.indexOf('>', pos);
                if (gt < 0) {
                    break;
                }
            }
            if (gt - pos > MAX_TAG) {
                continue;
            }
            String attrs = html.substring(pos, gt);
            if (skip != null && Py.found(skip, attrs)) {
                continue;
            }
            if (!close.find(gt + 1)) {
                break;
            }
            out.add(new String[]{attrs, html.substring(gt + 1, close.start())});
            pos = close.end();
        }
        return out;
    }

    private static String documentBase(String html, String pageUrl) {
        for (String attrs : tags(html, OPEN_BASE)) {
            Matcher href = BASE_HREF.matcher(attrs);
            if (href.find()) {
                return Urls.join(pageUrl, href.group(1));
            }
        }
        return pageUrl;
    }

    static HtmlScripts scriptsFromHtml(String html, String pageUrl) {
        HtmlScripts out = new HtmlScripts();
        String base = documentBase(html, pageUrl);
        Set<String> seen = new HashSet<>();
        List<String> references = new ArrayList<>();

        for (String attrs : tags(html, OPEN_SCRIPT)) {
            Matcher src = SRC.matcher(attrs);
            if (src.find()) {
                references.add(firstGroup(src, 1));
            }
        }
        for (String tag : tags(html, OPEN_LINK)) {
            Map<String, String> attrs = attributes(tag);
            String rel = Py.lower(attrs.getOrDefault("rel", ""));
            String href = attrs.getOrDefault("href", "");
            boolean preloadedScript = Py.in(rel, "preload", "prefetch")
                    && (Py.lower(attrs.getOrDefault("as", "")).equals("script") || Py.found(JS_HREF, href));
            if (!href.isEmpty() && (rel.equals("modulepreload") || preloadedScript)) {
                references.add(href);
            }
        }
        for (String reference : references) {
            String ref = Py.strip(reference);
            if (ref.isEmpty() || Py.startsWithAny(ref, "data:", "javascript:", "blob:", "about:")) {
                continue;
            }
            String url = base.isEmpty() ? ref : Urls.join(base, ref);
            if (seen.add(url)) {
                out.urls.add(url);
            }
        }
        for (String[] element : elements(html, OPEN_SCRIPT, CLOSE_SCRIPT, HAS_SRC)) {
            Matcher type = SCRIPT_TYPE.matcher(element[0]);
            String mime = type.find() ? Py.lower(type.group(1)) : "";
            if (Py.in(mime, "text/template", "text/html", "text/x-template", "text/css")) {
                continue;
            }
            String body = Py.strip(element[1]);
            if (!body.isEmpty() && body.length() <= MAX_INLINE_CHARS) {
                out.inline.add(body);
            }
        }
        return out;
    }

    private static Map<String, String> attributes(String tag) {
        Map<String, String> attrs = new HashMap<>();
        for (Matcher m = ATTRIBUTE.matcher(tag); m.find(); ) {
            attrs.put(Py.lower(m.group(1)), firstGroup(m, 2));
        }
        return attrs;
    }

    /** The forms of a page: where each one submits, how, and the names of its fields. */
    static List<Form> formsFromHtml(String html, String pageUrl) {
        List<Form> forms = new ArrayList<>();
        String base = documentBase(html, pageUrl);
        for (String[] element : elements(html, OPEN_FORM, CLOSE_FORM, null)) {
            Map<String, String> attrs = attributes(element[0]);
            String action = absolute(attrs.getOrDefault("action", ""), base);
            if (action.isEmpty()) {
                action = Py.before(Py.before(pageUrl, "#"), "?");
            }
            String declared = attrs.get("method");
            String method = Py.upper(Py.strip(declared == null || declared.isEmpty() ? "GET" : declared));
            Set<String> names = new LinkedHashSet<>();
            for (String field : tags(element[1], OPEN_FIELD)) {
                Matcher name = NAME.matcher(field);
                if (name.find()) {
                    String unescaped = unescape(firstGroup(name, 1));
                    if (!unescaped.isEmpty()) {
                        names.add(unescaped);
                    }
                }
            }
            if (!action.isEmpty()) {
                forms.add(new Form(Py.in(method, "GET", "POST", "PUT", "PATCH", "DELETE") ? method : "GET", action,
                        new ArrayList<>(names)));
            }
        }
        return forms;
    }

    private static String absolute(String reference, String base) {
        String ref = Py.strip(unescape(reference));
        if (ref.isEmpty() || Py.startsWith(NOT_A_PAGE, ref)) {
            return "";
        }
        return Py.before(base.isEmpty() ? ref : Urls.join(base, ref), "#");
    }

    /** Character references as they occur in attribute values: numeric ones and the five XML names. */
    static String unescape(String s) {
        if (s.indexOf('&') < 0) {
            return s;
        }
        Matcher m = ENTITY.matcher(s);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String name = Py.rstrip(m.group(1), ";");
            String replacement;
            if (name.startsWith("#")) {
                int codePoint;
                try {
                    codePoint = name.charAt(1) == 'x' || name.charAt(1) == 'X'
                            ? Integer.parseInt(name.substring(2), 16) : Integer.parseInt(name.substring(1));
                } catch (NumberFormatException tooLarge) {
                    codePoint = -1;
                }
                boolean valid = codePoint > 0 && codePoint <= Character.MAX_CODE_POINT && !(codePoint >= 0xd800 && codePoint <= 0xdfff);
                replacement = valid ? new String(Character.toChars(codePoint)) : "\ufffd";
            } else {
                replacement = switch (name) {
                    case "amp" -> "&";
                    case "lt" -> "<";
                    case "gt" -> ">";
                    case "quot" -> "\"";
                    case "apos" -> "'";
                    default -> "\u00a0";
                };
            }
            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(out);
        return out.toString();
    }

    // ── the bundler's chunk-filename function ────────────────────────────────

    /** {1:"a", 2:"b"} → {"1": "a", "2": "b"}; null when any value is not a literal. */
    private static Map<String, String> staticMap(Program p, int brace) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, int[]> entry : p.objectAt(brace).entrySet()) {
            int a = entry.getValue()[0], b = entry.getValue()[1];
            if (b - a != 1 || (p.kind[a] != STR && p.kind[a] != NUM)) {
                return null;
            }
            out.put(entry.getKey(), (String) p.value[a]);
        }
        return out.isEmpty() ? null : out;
    }

    /**
     * A chunk-map lookup starting at token `i`, in either spelling:
     *     {1:"a"}[e]        ({1:"a"})[e]
     * `parameter`, when given, is the only index name accepted.
     */
    private static Lookup lookupAt(Program p, int i, String parameter) {
        int brace = i;
        boolean wrapped = false;
        if (p.isPunc(i, "(") && p.isPunc(i + 1, "{") && p.pairs[i + 1] > 0 && p.pairs[i] == p.pairs[i + 1] + 1) {
            brace = i + 1;
            wrapped = true;
        }
        if (!p.isPunc(brace, "{")) {
            return null;
        }
        int close = p.pairs[brace];
        if (close < 0) {
            return null;
        }
        int j = close + (wrapped ? 2 : 1);
        if (!(p.isPunc(j, "[") && p.kind(j + 1) == ID && p.isPunc(j + 2, "]"))) {
            return null;
        }
        String name = (String) p.value[j + 1];
        if (parameter != null && !name.equals(parameter)) {
            return null;
        }
        Map<String, String> map = staticMap(p, brace);
        return map == null ? null : new Lookup(map, name, j + 3);
    }

    /** Start index of the term that ends at token `end` (inclusive). */
    private static int termStart(Program p, int end) {
        if (p.isPunc(end, ")") || p.isPunc(end, "]")) {
            int open = p.pairs[end];
            if (open < 0) {
                return end;
            }
            if (p.isPunc(end, "]") && open > 0 && (p.isPunc(open - 1, "}") || p.isPunc(open - 1, ")"))
                    && p.pairs[open - 1] >= 0) {
                return p.pairs[open - 1];                   // {map}[e]  /  ({map})[e]
            }
            return open;
        }
        if (p.kind[end] == ID) {
            int k = end;
            while (k >= 2 && p.isPunc(k - 1, ".") && p.kind(k - 2) == ID) {
                k -= 2;
            }
            return k;
        }
        return end;
    }

    /** Index after the term that starts at token `start`. */
    private static int termEnd(Program p, int start) {
        if (p.isPunc(start, "{") || p.isPunc(start, "(")) {
            int close = p.pairs[start];
            if (close < 0) {
                return start + 1;
            }
            return p.isPunc(close + 1, "[") && p.pairs[close + 1] > 0 ? p.pairs[close + 1] + 1 : close + 1;
        }
        if (p.kind[start] == ID) {
            int k = start + 1;
            while (p.isPunc(k, ".") && p.kind(k + 1) == ID) {
                k += 2;
            }
            return k;
        }
        return start + 1;
    }

    /** Evaluate the filename expression over tokens [a, b) for one chunk id; null when it cannot be. */
    private static String evalChunkName(Program p, int a, int b, String parameter, String chunk, int nesting) {
        if (nesting > MAX_CHUNK_NESTING) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        int i = a;
        while (i < b) {
            byte k = p.kind[i];
            if (p.isPunc(i, "+")) {
                i++;
            } else if (k == STR || k == NUM) {
                out.append((String) p.value[i]);
                i++;
            } else if (k == ID && parameter.equals(p.value[i]) && !p.isPunc(i + 1, ".")) {
                out.append(chunk);
                i++;
            } else if (p.isPunc(i, "{") || p.isPunc(i, "(")) {
                Lookup direct = lookupAt(p, i, parameter);
                if (direct != null) {                       // {map}[e]  /  ({map})[e]
                    String name = direct.map().get(chunk);
                    if (name == null) {
                        return null;
                    }
                    out.append(name);
                    i = direct.end();
                    continue;
                }
                if (!p.isPunc(i, "(")) {
                    return null;
                }
                int close = p.pairs[i];
                if (close < 0) {
                    return null;
                }
                Lookup inner = lookupAt(p, i + 1, parameter);
                if (inner != null) {                        // ({map}[e] || e)
                    String name = inner.map().get(chunk);
                    if (name != null) {
                        out.append(name);
                    } else if (p.isPunc(inner.end(), "||") || p.isPunc(inner.end(), "??")) {
                        out.append(chunk);
                    } else {
                        return null;
                    }
                } else {
                    String sub = evalChunkName(p, i + 1, close, parameter, chunk, nesting + 1);
                    if (sub == null) {
                        return null;
                    }
                    out.append(sub);
                }
                i = close + 1;
            } else if (k == ID) {
                i = termEnd(p, i);                          // the public path (r.p) adds nothing knowable here
            } else {
                return null;
            }
        }
        return out.toString();
    }

    /** File names produced by the bundler's chunk-filename function, for every chunk id it knows. */
    static List<String> webpackChunks(Program p) {
        Set<String> found = new LinkedHashSet<>();
        Set<Integer> seenExpressions = new HashSet<>();
        int produced = 0;
        for (int i = 0; i < p.n - 3; i++) {
            if (!(p.isPunc(i, "{") || (p.isPunc(i, "(") && p.isPunc(i + 1, "{")))) {
                continue;
            }
            Lookup look = lookupAt(p, i, null);
            if (look == null || look.map().size() > 5000) {
                continue;
            }
            // grow the concatenation around the lookup
            int start = i;
            if (start > 0 && p.isPunc(start - 1, "(") && p.pairs[start - 1] >= look.end()) {
                start--;                                    // ({map}[e] || e)
            }
            while (start >= 2 && p.isPunc(start - 1, "+")) {
                start = termStart(p, start - 2);
            }
            int end = termEnd(p, start);
            while (p.isPunc(end, "+") && end + 1 < p.n) {
                end = termEnd(p, end + 1);
            }
            if (end < look.end() || !seenExpressions.add(start)) {
                continue;
            }
            boolean namesAFile = false;
            for (int k = start; k < end && !namesAFile; k++) {
                namesAFile = p.kind[k] == STR && Py.found(ASSET_NAME, (String) p.value[k]);
            }
            if (!namesAFile) {
                continue;
            }
            TreeSet<String> ids = new TreeSet<>(Py::compare);
            for (int k = start; k < end; k++) {
                Lookup inner = lookupAt(p, k, look.parameter());
                if (inner != null) {
                    ids.addAll(inner.map().keySet());
                }
            }
            for (String id : ids) {
                String name = evalChunkName(p, start, end, look.parameter(), id, 0);
                if (name != null && !name.isEmpty() && (name.endsWith(".js") || name.endsWith(".mjs")) && name.length() < 300) {
                    found.add(name);
                    if (++produced >= MAX_CHUNKS_PER_FILE) {
                        return new ArrayList<>(found);
                    }
                }
            }
        }
        return new ArrayList<>(found);
    }

    /** webpack's `__webpack_require__.p = "/static/"` when it is a single literal. */
    private static String publicPath(Program p) {
        Set<String> values = p.props.get("p");
        if (values != null && values.size() == 1) {
            String v = values.iterator().next();
            if (Py.startsWithAny(v, "/", "http://", "https://", "//")) {
                return v;
            }
        }
        return "";
    }

    /** Resolve a chunk reference the way the bundler would. */
    private static String resolve(String reference, String scriptUrl, String publicPath) {
        if (scriptUrl.isEmpty()) {
            return reference;
        }
        if (Py.startsWith(NETWORK_PATH, reference) || reference.startsWith("/")) {
            return Urls.join(scriptUrl, reference);
        }
        if (!publicPath.isEmpty()) {
            return Urls.join(Urls.join(scriptUrl, publicPath), reference);
        }
        Urls.Split parts = Urls.split(scriptUrl);
        // Next.js: chunk names are relative to /_next/, wherever the referring script lives
        if (parts.path().contains("/_next/") && reference.startsWith("static/")) {
            String prefix = Py.before(parts.path(), "/_next/") + "/_next/";
            return Urls.join(parts.scheme() + "://" + parts.netloc() + prefix, reference);
        }
        return Urls.join(scriptUrl, reference);
    }

    /** Other scripts (and manifest routes) referenced by one tokenized script. */
    static Discovery discover(Program p, String scriptUrl) {
        Discovery out = new Discovery();
        String publicPath = publicPath(p);
        List<String> references = new ArrayList<>(webpackChunks(p));

        boolean manifest = false;
        for (int i = 0; i < Math.min(p.n, 400) && !manifest; i++) {
            manifest = p.kind[i] == ID && Py.in((String) p.value[i], "__BUILD_MANIFEST", "__SSG_MANIFEST");
        }
        for (int i = 0; i < p.n; i++) {
            if (p.kind[i] == STR) {
                String s = (String) p.value[i];
                boolean looksLikeScript = (s.length() > 4 && s.length() < 300 && (s.endsWith(".js") || s.endsWith(".mjs")))
                        || (s.contains(".js?") && s.length() < 300);
                if (looksLikeScript && Py.startsWith(JS_FILE, s) && !Py.startsWithAny(s, "node_modules/", "webpack/")) {
                    references.add(s);
                }
                if (manifest && s.startsWith("/") && p.isPunc(i + 1, ":") && s.length() < 200) {
                    out.routes.add(s);
                }
            } else if (p.kind[i] == TPL) {
                List<Program.Part> parts = p.templateParts(i);
                if (Program.isStatic(parts)) {
                    String s = Program.render(parts);
                    if (s.length() > 4 && s.length() < 300 && Py.startsWith(JS_FILE, s)) {
                        references.add(s);
                    }
                }
            }
        }

        Set<String> seen = new HashSet<>();
        for (String reference : references) {
            String url = resolve(reference, scriptUrl, publicPath);
            if (seen.add(url)) {
                out.scripts.add(url);
            }
        }
        TreeSet<String> routes = new TreeSet<>(Py::compare);
        routes.addAll(out.routes);
        out.routes = new ArrayList<>(routes);
        return out;
    }
}
