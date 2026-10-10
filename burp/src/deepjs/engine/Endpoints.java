package deepjs.engine;

import static deepjs.engine.Lexer.ID;
import static deepjs.engine.Lexer.PUNC;
import static deepjs.engine.Lexer.STR;
import static deepjs.engine.Lexer.TPL;

import deepjs.engine.Program.Eval;
import deepjs.engine.Program.Part;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the requests a script makes.
 *
 * Call sites are read as calls: `fetch(url, {method})`, `client.post(url,
 * body)`, `axios({url, method})`, `xhr.open(method, url)`, `new WebSocket(url)`.
 * The URL argument is evaluated, so a path built from constants and variables
 * comes out as `/api/v2/users/{id}`; the body argument gives the field names.
 * Strings that only look like URLs are kept apart, as kind "string".
 */
final class Endpoints {

    /** One request (or, for kind "string", a path that merely appears in the code). */
    static final class Endpoint {
        String url;
        String method = "";                 // "" = unknown
        String kind = "string";             // fetch | axios | xhr | ajax | client | config | form | websocket | … | string
        List<String> params = new ArrayList<>();
        List<String> body = new ArrayList<>();
        List<String> headers = new ArrayList<>();
        String file = "";
        int line;
        double confidence = 0.5;

        boolean isCall() {
            return !kind.equals("string");
        }

        String host() {
            Matcher m = HOST_OF.matcher(url);
            if (!m.lookingAt()) {
                return "";
            }
            List<String> user = Py.split(m.group(1), "@");
            return Py.lower(Py.before(user.get(user.size() - 1), ":"));
        }

        String key() {
            return method + "\u0000" + url;
        }
    }

    /** What one file contributes. */
    static final class Extraction {
        final List<Endpoint> endpoints = new ArrayList<>();
        List<String[]> graphql = new ArrayList<>();         // {operation type, name}
        List<String> routes = new ArrayList<>();            // client-side routes
        List<String> bases = new ArrayList<>();             // API base URLs
    }

    static final Set<String> HTTP_METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");
    private static final Map<String, String> METHOD_CALLS = Map.ofEntries(
            Map.entry("get", "GET"), Map.entry("post", "POST"), Map.entry("put", "PUT"), Map.entry("patch", "PATCH"),
            Map.entry("delete", "DELETE"), Map.entry("del", "DELETE"), Map.entry("head", "HEAD"),
            Map.entry("options", "OPTIONS"), Map.entry("getJSON", "GET"), Map.entry("getScript", "GET"),
            // @nuxtjs/axios:  this.$axios.$get("/articles")
            Map.entry("$get", "GET"), Map.entry("$post", "POST"), Map.entry("$put", "PUT"), Map.entry("$patch", "PATCH"),
            Map.entry("$delete", "DELETE"), Map.entry("$head", "HEAD"));
    private static final Set<String> REQUEST_FUNCS = Set.of("axios", "request", "ajax", "$http", "superagent", "ky", "got", "wretch", "needle");
    private static final Set<String> ROUTE_SIBLINGS = Set.of("component", "element", "children", "loadChildren", "loadComponent",
            "redirectTo", "redirect", "Component", "lazy", "beforeEnter", "canActivate", "render", "exact");
    private static final Set<String> NAV_CALLS = Set.of("navigate", "push", "replace", "navigateByUrl", "redirect", "go");
    private static final Set<String> BASE_KEYS = Set.of("baseURL", "baseUrl", "apiUrl", "apiURL", "apiBase", "apiBaseUrl",
            "API_URL", "API_BASE_URL", "apiEndpoint", "serverUrl", "backendUrl");

    private static final Pattern HOST_OF = Py.rxi("^(?:[a-z]+:)?//([^/?#{}]+)");
    private static final Pattern BASE_HOST = Py.rx("^(?:[a-z]+:)?//([^/?#{}:]+)");
    private static final Pattern HTTPISH = Py.rxi("axios|https?|api|client|request|ajax|rest|fetch|service|backend|instance|superagent|^ky$|^got$|^\\$$");
    static final Pattern ABSOLUTE = Py.rx("^(?:https?:|wss?:)?//[A-Za-z0-9{][^\\s\"'<>\\\\^`|]*$");
    // scheme://{anything} with nothing else known: not worth a line in a report
    private static final Pattern OPAQUE_ABSOLUTE = Py.rx("^(?:https?:|wss?:)?//\\{[^{}]*\\}/?$");
    static final Pattern STATIC_ASSET = Py.rxi(
            "\\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|ogg|pdf|zip|gz"
                    + "|wasm|txt|md|scss|sass|less|vue|tsx?|jsx|html?)(?:[?#].*)?$");
    private static final Pattern PATH_CHARS = Py.rx("^[A-Za-z0-9_\\-./~%{}:@!$&'()*+,;=?#\\[\\]]+$");
    private static final Pattern APIISH_PREFIX = Py.rxi(
            "^(?:api|v\\d+|rest|graphql|gql|rpc|services?|auth|oauth2?|admin|internal|ajax|backend|wp-json)/");
    static final Pattern APIISH_ANY = Py.rxi(
            "(?:^|/)(?:api|v\\d+|rest|graphql|gql|rpc|oauth2?|auth|admin|internal|ajax|backend|wp-json)(?:/|$)"
                    + "|\\.(?:php|aspx?|jsp|do|action|json|xml|cgi|ashx|asmx|svc)(?:[?#]|$)");
    private static final Pattern GRAPHQL_OP = Py.rx("\\b(query|mutation|subscription)\\s+([A-Za-z_]\\w*)\\s*[({]");
    private static final Pattern BASE_NAME = Py.rxi("base|url|uri|api|host|server|endpoint|origin|root|prefix|domain|backend|gateway|service");
    private static final Pattern WRAPPER_URL = Py.rxi(
            "^(https?://[^/{}?#\\s]+(?:/[^{}?#\\s]*[^/{}?#\\s])?|/(?:api|rest|v\\d+)(?:/v?\\d+)?)\\{[^{}]+\\}$");
    private static final Pattern QUERY_NAME = Py.rx("[\\w.\\-\\[\\]]{1,60}");
    private static final Pattern OBJECT_KEY = Py.rx("[\\w.\\-$\\[\\]]{1,60}");
    private static final Pattern BARE_NAME = Py.rx("[\\w\\-{}.]+");
    private static final Pattern REGEX_FLAGS = Py.rx("/[gimsuy]{1,4}");
    private static final Pattern SLASHES = Py.rx("/{2,}");
    private static final Pattern BRACED = Py.rx("\\{[^{}]*\\}");
    private static final Pattern ROUTE_PATH = Py.rx("[\\w\\-./:*()?{}@~]*");

    /** Library / spec URLs that every bundle carries and nobody wants in a report. */
    static final Pattern NOISE_HOSTS = Py.rxi(
            "(?:^|\\.)(?:w3\\.org|reactjs\\.org|react\\.dev|fb\\.me|facebook\\.github\\.io|github\\.com|githubusercontent\\.com"
                    + "|npmjs\\.com|mozilla\\.org|developer\\.mozilla\\.org|schema\\.org|json-schema\\.org|momentjs\\.com|lodash\\.com"
                    + "|angular\\.io|angular\\.dev|vuejs\\.org|nextjs\\.org|webpack\\.js\\.org|babeljs\\.io|redux\\.js\\.org|mui\\.com"
                    + "|material-ui\\.com|ant\\.design|getbootstrap\\.com|jquery\\.com|stackoverflow\\.com|wikipedia\\.org|xml\\.org"
                    + "|ietf\\.org|whatwg\\.org|ecma-international\\.org|tc39\\.es|purl\\.org|openxmlformats\\.org|apache\\.org"
                    + "|creativecommons\\.org|example\\.com|example\\.org|localhost\\.example|sentry\\.io/api|feross\\.org|zloirock\\.ru"
                    + "|opencollective\\.com|goo\\.gl|bit\\.ly|tailwindcss\\.com|typescriptlang\\.org|eslint\\.org|rxjs\\.dev|formatjs\\.io)$");

    private Endpoints() {
    }

    /** All requests, GraphQL operations, routes and API bases in one tokenized file. */
    static Extraction extract(Program p, String file) {
        return new Extractor(p, file).run();
    }

    // ── URL helpers ──────────────────────────────────────────────────────────

    /** '/a?x=1&y={v}' → '/a' and the names ['x', 'y'] (added to `names`). */
    static String splitQuery(String url, List<String> names) {
        int q = url.indexOf('?');
        if (q < 0) {
            return url;
        }
        String query = Py.before(url.substring(q + 1), "#");
        for (String chunk : Py.split(query, "&")) {
            String name = Py.strip(Py.before(chunk, "="));
            if (!name.isEmpty() && Py.matches(QUERY_NAME, name) && !names.contains(name)) {
                names.add(name);
            }
        }
        return url.substring(0, q);
    }

    static String normaliseUrl(String url) {
        url = Py.strip(url);
        int scheme = url.indexOf("://");
        if (scheme >= 0) {
            return url.substring(0, scheme + 3) + SLASHES.matcher(url.substring(scheme + 3)).replaceAll("/");
        }
        if (url.startsWith("//")) {
            return "//" + SLASHES.matcher(url.substring(2)).replaceAll("/");
        }
        return SLASHES.matcher(url).replaceAll("/");
    }

    /**
     * Shapes that are not worth listing when only the string itself suggests a
     * URL (it is not the argument of a request): regex fragments, the
     * one-letter hosts and paths of URL-parser tests in polyfills.
     */
    private static boolean weakNoise(String text) {
        if (text.indexOf('(') >= 0 || text.indexOf(')') >= 0) {
            return true;
        }
        String head = Py.before(Py.before(text, "?"), "#");
        int scheme = head.indexOf("://");
        if (scheme >= 0) {
            String rest = head.substring(scheme + 3);
            String host = Py.before(rest, "/"), path = Py.after(rest, "/");
            String literalHost = BRACED.matcher(host).replaceAll("");
            if (literalHost.indexOf('.') >= 0 || literalHost.startsWith("localhost") || literalHost.startsWith("[")) {
                return false;
            }
            boolean bare = Py.strip(literalHost, "-:").length() <= 1;
            if (bare && host.indexOf('{') < 0) {
                return true;                                // https://a   http://f
            }
            if (bare) {
                // https://{param}{param}   https://{teamId}-   — unless a real path follows
                for (String segment : Py.split(path, "/")) {
                    if (segment.length() >= 3 && segment.indexOf('{') < 0) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        if (head.startsWith("/")) {
            boolean any = false;
            for (String segment : Py.split(head, "/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                if (segment.length() > 1) {
                    return false;
                }
                any = true;
            }
            return any;                                     // /a/b
        }
        return false;
    }

    /**
     * Is this built string a URL / path? `strong`: it is the URL argument of a
     * recognised HTTP call, so less evidence is needed.
     */
    static boolean urlLike(String text, List<Part> parts, boolean strong, boolean bare) {
        if (text.length() <= 1 || text.length() > 2048 || text.indexOf(' ') >= 0 || text.indexOf('\n') >= 0) {
            return false;
        }
        if (Py.strip(Program.literal(parts), "/?&=.:").isEmpty()) {
            return false;                                   // fetch(url): nothing known about the URL
        }
        if (bare && Py.matches(BARE_NAME, text)) {
            return true;                                    // {url: "posts", method: "POST"}: relative to a base URL
        }
        if (text.indexOf('<') >= 0 || text.indexOf('>') >= 0 || text.indexOf('\\') >= 0 || text.indexOf('^') >= 0
                || text.replace("/*", "").indexOf('*') >= 0) {
            return false;
        }
        if (Py.startsWith(OPAQUE_ABSOLUTE, text)) {
            return false;
        }
        if (!strong && weakNoise(text)) {
            return false;
        }
        if (Py.startsWith(ABSOLUTE, text)) {
            // scheme://user:secret@host belongs in the secrets report, not here
            int slashes = text.indexOf("//");
            return Py.before(text.substring(slashes + 2), "/").indexOf('@') < 0;
        }
        if (Py.startsWithAny(text, "data:", "blob:", "javascript:", "mailto:", "tel:", "about:", "chrome:")) {
            return false;
        }
        if (!Py.startsWith(PATH_CHARS, text)) {
            return false;
        }
        if (text.startsWith("/")) {
            if (text.startsWith("/*") || Py.in(text, "/", "//", "/.", "/..") || Py.matches(REGEX_FLAGS, text)) {
                return false;
            }
            if (strong) {
                return true;
            }
            int segments = 0;
            for (String segment : Py.split(splitQuery(text, new ArrayList<>()), "/")) {
                if (!segment.isEmpty()) {
                    segments++;
                }
            }
            if (segments == 0 || Py.found(STATIC_ASSET, text)) {
                return false;
            }
            return segments >= 2 || Py.found(APIISH_ANY, text) || text.indexOf('?') >= 0 || text.indexOf('{') >= 0;
        }
        if (text.startsWith("{") && text.contains("}/")) {
            if (strong) {
                return true;                                // {baseUrl}/users
            }
            String name = Py.before(text.substring(1), "}"), rest = Py.after(text.substring(1), "}");
            int literalSegments = 0;
            for (String segment : Py.split(Py.before(rest, "?"), "/")) {
                if (segment.length() >= 2 && segment.indexOf('{') < 0) {
                    literalSegments++;
                }
            }
            return Py.found(BASE_NAME, name) || Py.found(APIISH_ANY, rest) || literalSegments >= 2;
        }
        if (text.startsWith("./") || text.startsWith("../")) {
            return strong && !Py.found(STATIC_ASSET, text);
        }
        if (Py.startsWith(APIISH_PREFIX, text)) {
            return true;
        }
        return strong && text.indexOf('/') >= 0 && !Py.found(STATIC_ASSET, text) && Py.before(text, "/").indexOf('.') < 0;
    }

    /** `literal` and `text` are what a URL argument is known to be: is it unmistakably a URL? */
    private static boolean unmistakable(List<Part> url) {
        String literal = Program.literal(url), text = Program.render(url);
        return Py.startsWithAny(literal, "/", "http://", "https://", "//") || (text.startsWith("{") && text.contains("}/"))
                || Py.startsWith(APIISH_PREFIX, literal);
    }

    // ── extraction ───────────────────────────────────────────────────────────

    private static final class Extractor {
        private final Program p;
        private final String file;
        private final Extraction out = new Extraction();
        private final BitSet claimed = new BitSet();
        private final Map<String, Endpoint> byKey = new HashMap<>();
        private final int[] enclosing;

        Extractor(Program p, String file) {
            this.p = p;
            this.file = file;
            this.enclosing = enclosingBrackets();
        }

        /** For every token, the index of the innermost open bracket of any kind around it. */
        private int[] enclosingBrackets() {
            int[] enc = new int[p.n];
            int[] stack = new int[16];
            int depth = 0;
            for (int i = 0; i < p.n; i++) {
                enc[i] = depth > 0 ? stack[depth - 1] : -1;
                if (p.kind[i] != PUNC) {
                    continue;
                }
                String v = (String) p.value[i];
                if (v.equals("(") || v.equals("[") || v.equals("{")) {
                    if (depth == stack.length) {
                        stack = java.util.Arrays.copyOf(stack, depth * 2);
                    }
                    stack[depth++] = i;
                } else if (v.equals(")") || v.equals("]") || v.equals("}")) {
                    int open = p.pairs[i];
                    if (open >= 0) {
                        while (depth > 0 && stack[depth - 1] != open) {
                            depth--;
                        }
                        if (depth > 0) {
                            depth--;
                        }
                    }
                }
            }
            return enc;
        }

        // ── recording ────────────────────────────────────────────────────────

        boolean add(List<Part> url, String method, String kind, int token, double confidence,
                    List<String> params, List<String> body, List<String> headers, boolean strong, boolean bare) {
            for (Part part : url) {
                if (part.variable() && part.text().startsWith(Program.ALT)) {
                    // "/articles" + (feed ? "/feed" : ""): one endpoint per branch
                    List<List<Part>> variants = Program.expand(url);
                    if (variants.size() > 1) {
                        boolean any = false;
                        for (List<Part> variant : variants) {
                            any |= add(variant, method, kind, token, confidence, params, body, headers, strong, bare);
                        }
                        return any;
                    }
                    break;
                }
            }
            String text = Program.render(url);
            if (!urlLike(text, url, strong, bare)) {
                return false;
            }
            if (!kind.equals("string") && url.size() == 2) {
                // get(path) { return this.http.get(`${environment.api_url}${path}`) }: an API client's own
                // plumbing. What it tells us is the base URL; the real paths are at its call sites.
                Matcher wrapper = WRAPPER_URL.matcher(text);
                if (wrapper.lookingAt()) {
                    out.bases.add(wrapper.group(1));
                    return true;
                }
            }
            List<String> query = new ArrayList<>();
            String base = splitQuery(normaliseUrl(text), query);
            if (base.isEmpty()) {
                return false;
            }
            Endpoint ep = new Endpoint();
            ep.url = base;
            ep.method = method;
            ep.kind = kind;
            ep.file = file;
            ep.line = p.line(token);
            ep.confidence = confidence;
            ep.params = Py.unique(query, params);
            ep.body = Py.unique(body, List.of());
            ep.headers = Py.unique(headers, List.of());
            String host = ep.host();
            if (!host.isEmpty() && Py.found(NOISE_HOSTS, host)) {
                return false;
            }
            Endpoint old = byKey.get(ep.key());
            if (old == null && ep.isCall()) {
                // a bare string seen earlier turns out to be a real call: upgrade it
                Endpoint stale = byKey.remove("\u0000" + ep.url);
                if (stale != null && !stale.isCall()) {
                    out.endpoints.remove(stale);
                }
            } else if (old == null) {
                for (Endpoint known : byKey.values()) {
                    if (known.url.equals(ep.url)) {
                        return true;                        // already known as a call
                    }
                }
            }
            if (old == null) {
                byKey.put(ep.key(), ep);
                out.endpoints.add(ep);
            } else {                                        // the same request again: merge what was learned
                old.params = Py.unique(old.params, ep.params);
                old.body = Py.unique(old.body, ep.body);
                old.headers = Py.unique(old.headers, ep.headers);
                if (ep.confidence > old.confidence) {
                    old.confidence = ep.confidence;
                    old.kind = ep.kind;
                }
            }
            return true;
        }

        boolean add(List<Part> url, String method, String kind, int token, double confidence) {
            return add(url, method, kind, token, confidence, List.of(), List.of(), List.of(), true, false);
        }

        private void claim(int from, int to) {
            claimed.set(from, Math.max(from, to));
        }

        /** Evaluate the expression occupying tokens [a, b); empty when it is not a string build. */
        private List<Part> evalRange(int a, int b) {
            Eval e = p.evalExpr(a);
            if (!e.parts().isEmpty() && e.next() >= b) {
                claim(a, b);
                return e.parts();
            }
            return List.of();                               // `c ? "/a" : "/b"`, `x || "/default"`
        }

        private String staticText(int a, int b) {
            Eval e = p.evalExpr(a);
            return Program.isStatic(e.parts()) && e.next() >= b ? e.parts().get(0).text() : "";
        }

        /** Keys of an object literal value at [a, b), also through JSON.stringify({…}). */
        private List<String> objectKeys(int a, int b) {
            int i = a;
            if (p.isId(i, "JSON") && p.isPunc(i + 1, ".") && "stringify".equals(p.text(i + 2)) && p.isPunc(i + 3, "(")) {
                i += 4;
            }
            if (p.isId(i, "new") && Py.in(String.valueOf(p.text(i + 1)), "URLSearchParams", "FormData") && p.isPunc(i + 2, "(")) {
                i += 3;
            }
            if (p.kind(i) == ID && i + 1 >= b) {
                // post(url, n) where  n = {privateKey: t}  was assigned just before
                int literal = p.localObject(i);
                if (literal >= 0) {
                    i = literal;
                }
            }
            List<String> keys = new ArrayList<>();
            if (p.isPunc(i, "{")) {
                for (String key : p.objectAt(i).keySet()) {
                    if (Py.matches(OBJECT_KEY, key)) {
                        keys.add(key);
                    }
                }
            }
            return keys;
        }

        /** Read {url, method, params, data, headers} from an object literal. */
        private boolean fromConfig(int brace, String kind, int token, List<Part> url, String defaultMethod, double confidence) {
            Map<String, int[]> props = p.objectAt(brace);
            if (url == null) {
                for (String name : new String[]{"url", "uri", "endpoint", "path"}) {
                    int[] range = props.get(name);
                    if (range != null) {
                        url = evalRange(range[0], range[1]);
                        break;
                    }
                }
            }
            if (url == null || url.isEmpty()) {
                return false;
            }
            String method = defaultMethod;
            List<String> either = new ArrayList<>();
            boolean hasMethod = false;
            for (String name : new String[]{"method", "type", "verb"}) {
                int[] range = props.get(name);
                if (range == null) {
                    continue;
                }
                hasMethod = true;
                String m = Py.upper(staticText(range[0], range[1]));
                if (HTTP_METHODS.contains(m)) {
                    method = m;
                } else {
                    // method: favorited ? "DELETE" : "POST"
                    List<String> branches = p.literalBranches(range[0], -1, 0);
                    if (branches != null) {
                        for (String branch : branches) {
                            if (HTTP_METHODS.contains(Py.upper(branch))) {
                                either.add(Py.upper(branch));
                            }
                        }
                    }
                }
                break;
            }
            List<String> params = new ArrayList<>();
            for (String name : new String[]{"params", "query", "qs", "searchParams", "search"}) {
                int[] range = props.get(name);
                if (range != null) {
                    params.addAll(objectKeys(range[0], range[1]));
                }
            }
            List<String> body = new ArrayList<>();
            for (String name : new String[]{"data", "body", "json", "form", "payload"}) {
                int[] range = props.get(name);
                if (range != null) {
                    body.addAll(objectKeys(range[0], range[1]));
                }
            }
            int[] headerRange = props.get("headers");
            List<String> headers = headerRange != null ? objectKeys(headerRange[0], headerRange[1]) : List.of();
            if (method.isEmpty() && !body.isEmpty() && !kind.equals("config")) {
                method = "POST";
            }
            if (either.size() == 2) {
                boolean any = false;
                for (String m : either) {
                    any |= add(url, m, kind, token, confidence, params, body, headers, true, true);
                }
                return any;
            }
            if (method.isEmpty() && !hasMethod && body.isEmpty() && p.isPunc(brace - 1, "(") && !p.isId(brace - 3, "new")) {
                // request({url, headers}) with no method: GET in axios, fetch-likes and jQuery alike
                method = "GET";
                confidence = Math.min(confidence, 0.75);
            }
            return add(url, method, kind, token, confidence, params, body, headers, true, !method.isEmpty());
        }

        // ── passes ───────────────────────────────────────────────────────────

        Extraction run() {
            for (int i = 0; i < p.n; i++) {
                byte k = p.kind[i];
                if (k == ID) {
                    if (p.isPunc(i + 1, "(")) {
                        call(i, i + 1);
                    } else if (p.isPunc(i + 1, "<") && METHOD_CALLS.containsKey((String) p.value[i])) {
                        // TypeScript generics in recovered sources:  http.post<User>(url, body)
                        int j = i + 2, limit = Math.min(p.n, i + 14);
                        while (j < limit && (p.kind(j) == ID
                                || (p.kind(j) == PUNC && Py.in((String) p.value[j], ".", ",", "[", "]", "|", "<")))) {
                            j++;
                        }
                        while (p.isPunc(j, ">") || p.isPunc(j, ">>")) {
                            j++;
                        }
                        if (p.isPunc(j, "(") && j > i + 2) {
                            call(i, j);
                        }
                    } else if (isKey(i)) {
                        property(i);
                    }
                } else if (k == STR && isKey(i)) {
                    property(i);
                }
            }
            strings();
            out.endpoints.sort(Comparator.<Endpoint, Boolean>comparing(e -> !e.isCall())
                    .thenComparing(e -> e.url, Py::compare).thenComparing(e -> e.method, Py::compare));
            TreeSet<String[]> operations = new TreeSet<>(
                    Comparator.<String[], String>comparing(o -> o[0], Py::compare).thenComparing(o -> o[1], Py::compare));
            operations.addAll(out.graphql);
            out.graphql = new ArrayList<>(operations);
            out.routes = sortedUnique(out.routes);
            out.bases = sortedUnique(out.bases);
            return out;
        }

        private static List<String> sortedUnique(List<String> values) {
            TreeSet<String> set = new TreeSet<>(Py::compare);
            set.addAll(values);
            return new ArrayList<>(set);
        }

        /** Is token `i` the key of a `key: value` pair in an object literal? */
        private boolean isKey(int i) {
            return p.isPunc(i + 1, ":") && i > 0 && (p.isPunc(i - 1, "{") || p.isPunc(i - 1, ","));
        }

        private void call(int i, int paren) {
            String name = (String) p.value[i];
            boolean member = i > 0 && (p.isPunc(i - 1, ".") || p.isPunc(i - 1, "?."));
            String receiver = member && p.kind(i - 2) == ID ? (String) p.value[i - 2] : "";
            List<int[]> args = p.callArgs(paren);
            if (args.isEmpty()) {
                return;
            }
            int a0 = args.get(0)[0], b0 = args.get(0)[1];

            // fetch(url, {method, headers, body})
            if (name.equals("fetch") && (!member || Py.in(receiver, "window", "self", "globalThis", "this", "global"))) {
                List<Part> url = evalRange(a0, b0);
                // a class's own fetch(module, params) (ethers' EtherscanProvider): only an unmistakable URL counts
                if (receiver.equals("this") && !unmistakable(url)) {
                    return;
                }
                if (args.size() > 1 && p.isPunc(args.get(1)[0], "{")
                        && fromConfig(args.get(1)[0], "fetch", i, url, "GET", 0.92)) {
                    return;
                }
                add(url, "GET", "fetch", i, 0.9);
                return;
            }

            // client.get("/x") · axios.post(url, data, cfg) · $.getJSON(…) · this.http.put(…)
            if (member && METHOD_CALLS.containsKey(name)) {
                boolean httpish = Py.found(HTTPISH, receiver) || p.isPunc(i - 2, ")") || name.startsWith("$");
                List<Part> url = evalRange(a0, b0);
                if (url.isEmpty()) {
                    return;
                }
                // map.get("a/b"), params.get("id"), i18n.get("errors/notFound"): an unknown receiver
                // must be handed something that is unmistakably a URL
                if (!httpish && !unmistakable(url)) {
                    return;
                }
                String method = METHOD_CALLS.get(name);
                List<String> body = List.of(), params = List.of(), headers = List.of();
                int next = 1;
                if (Py.in(method, "POST", "PUT", "PATCH") && args.size() > 1) {
                    body = objectKeys(args.get(1)[0], args.get(1)[1]);
                    next = 2;
                }
                if (args.size() > next && p.isPunc(args.get(next)[0], "{")) {
                    Map<String, int[]> config = p.objectAt(args.get(next)[0]);
                    if (config.containsKey("params")) {
                        params = objectKeys(config.get("params")[0], config.get("params")[1]);
                    }
                    if (config.containsKey("headers")) {
                        headers = objectKeys(config.get("headers")[0], config.get("headers")[1]);
                    }
                }
                String kind = Py.lower(receiver).contains("axios") ? "axios" : receiver.equals("$") ? "ajax" : "client";
                add(url, method, kind, i, httpish ? 0.9 : 0.8, params, body, headers, true, false);
                return;
            }

            // axios({url, method}) · $.ajax({...}) · request({...}) · axios(url, cfg)
            if (REQUEST_FUNCS.contains(name)
                    || (member && Py.in(name, "ajax", "request") && Py.found(HTTPISH, receiver.isEmpty() ? "$" : receiver))) {
                String kind = Py.lower(name + receiver).contains("axios") ? "axios" : name.equals("ajax") ? "ajax" : "client";
                if (p.isPunc(a0, "{")) {
                    fromConfig(a0, kind, i, null, "", 0.9);
                } else {
                    List<Part> url = evalRange(a0, b0);
                    if (!url.isEmpty() && args.size() > 1 && p.isPunc(args.get(1)[0], "{")) {
                        fromConfig(args.get(1)[0], kind, i, url, "", 0.9);
                    } else if (!url.isEmpty()) {
                        add(url, "", kind, i, 0.85);
                    }
                }
                return;
            }

            // xhr.open("POST", url)
            if (member && name.equals("open") && args.size() >= 2) {
                String method = Py.upper(staticText(a0, b0));
                if (HTTP_METHODS.contains(method)) {
                    add(evalRange(args.get(1)[0], args.get(1)[1]), method, "xhr", i, 0.92);
                }
                return;
            }

            // new WebSocket(url) · new EventSource(url) · navigator.sendBeacon(url)
            if (Py.in(name, "WebSocket", "EventSource") && p.isId(i - 1, "new")) {
                add(evalRange(a0, b0), "GET", Py.lower(name), i, 0.9);
                return;
            }
            if (name.equals("sendBeacon")) {
                add(evalRange(a0, b0), "POST", "beacon", i, 0.9);
                return;
            }

            // router.push("/x") · navigate("/x"): client-side routes, not requests
            if (NAV_CALLS.contains(name)) {
                String text = staticText(a0, b0);
                if (text.startsWith("/") && urlLike(text, List.of(new Part(false, text)), true, false)
                        && !Py.found(STATIC_ASSET, text)) {
                    out.routes.add(splitQuery(text, new ArrayList<>()));
                    claim(a0, b0);
                }
            }
        }

        /** A property key inside an object literal: request configs, route tables, base URLs. */
        private void property(int i) {
            String key = (String) p.value[i];
            int brace = enclosing[i];
            if (brace < 0 || !p.isPunc(brace, "{")) {
                return;
            }
            if (BASE_KEYS.contains(key)) {
                List<Part> parts = p.evalExpr(i + 2).parts();
                String text = Program.render(parts);
                if (!parts.isEmpty() && (Py.startsWith(ABSOLUTE, text) || text.startsWith("/")) && text.length() > 1) {
                    Matcher host = BASE_HOST.matcher(text);
                    if (!(host.lookingAt() && Py.found(NOISE_HOSTS, host.group(1)))) {
                        out.bases.add(text);
                    }
                }
                return;
            }
            if (Py.in(key, "url", "uri", "endpoint")) {
                Map<String, int[]> props = p.objectAt(brace);
                boolean config = false;
                for (String sibling : new String[]{"method", "type", "verb", "data", "body", "params", "headers"}) {
                    config |= props.containsKey(sibling);
                }
                if (config) {
                    fromConfig(brace, "config", i, null, "", 0.85);
                } else if (key.equals("url") && props.size() == 1 && p.isPunc(brace - 1, "(") && p.kind(brace - 2) == ID
                        && !p.isId(brace - 3, "new")) {
                    // request({url: "/api/tags"}) — the whole config is the URL
                    Eval e = p.evalExpr(i + 2);
                    String text = Program.render(e.parts());
                    String literal = Program.literal(e.parts());
                    if (!e.parts().isEmpty() && e.next() >= p.pairs[brace] && !Py.found(STATIC_ASSET, text)
                            && (Py.found(APIISH_ANY, text) || (literal.startsWith("/") && count(literal, '/') >= 2))) {
                        fromConfig(brace, "config", i, null, "", 0.7);
                    }
                }
                return;
            }
            if (Py.in(key, "to", "href", "routerLink", "pathname", "redirectTo", "returnTo")) {
                // <Link to="/settings">, {href: "/pricing"}: navigation inside the app, not a request
                int a = i + 2, b = p.valueEnd(a, p.pairs[brace] > 0 ? p.pairs[brace] : p.n);
                String text = staticText(a, b);
                if (text.startsWith("/") && !text.startsWith("//") && text.length() < 200
                        && urlLike(text, List.of(new Part(false, text)), true, false)
                        && !Py.found(STATIC_ASSET, text) && !Py.found(APIISH_ANY, text)) {
                    out.routes.add(splitQuery(text, new ArrayList<>()));
                    claim(a, b);
                }
                return;
            }
            if (key.equals("path")) {
                Map<String, int[]> props = p.objectAt(brace);
                boolean route = false;
                for (String sibling : props.keySet()) {
                    route |= ROUTE_SIBLINGS.contains(sibling);
                }
                if (route) {
                    int[] range = props.get("path");
                    String text = staticText(range[0], range[1]);
                    if (!text.isEmpty() && text.length() < 200 && Py.matches(ROUTE_PATH, text)) {
                        out.routes.add(text.startsWith("/") ? text : "/" + text);
                        claim(range[0], range[1]);
                    }
                }
            }
        }

        private static int count(String s, char c) {
            int total = 0;
            for (int i = 0; i < s.length(); i++) {
                if (s.charAt(i) == c) {
                    total++;
                }
            }
            return total;
        }

        /** Everything not already explained by a call site: GraphQL documents and bare URL-like strings. */
        @SuppressWarnings("unchecked")
        private void strings() {
            int i = 0;
            while (i < p.n) {
                byte k = p.kind[i];
                if (k != STR && k != TPL) {
                    i++;
                    continue;
                }
                String raw;
                if (k == STR) {
                    raw = (String) p.value[i];
                } else {
                    StringBuilder b = new StringBuilder();
                    for (Object segment : (List<Object>) p.value[i]) {
                        if (segment instanceof String text) {
                            b.append(text);
                        }
                    }
                    raw = b.toString();
                }
                if (raw.length() > 20 && raw.indexOf('{') >= 0) {
                    Matcher m = GRAPHQL_OP.matcher(raw);
                    while (m.find()) {
                        out.graphql.add(new String[]{m.group(1), m.group(2)});
                    }
                }
                if (claimed.get(i)) {
                    i++;
                    continue;
                }
                int start = p.exprStart(i);
                Eval e = p.evalExpr(start);
                if (e.next() <= i) {                        // could not evaluate through this literal
                    e = p.evalExpr(i);
                    start = i;
                }
                int end = Math.max(e.next(), i + 1);
                int firstClaimed = claimed.nextSetBit(start);
                if (firstClaimed < 0 || firstClaimed >= end) {
                    String text = Program.render(e.parts());
                    boolean apiLike = Py.found(APIISH_ANY, text) || Py.startsWith(ABSOLUTE, text);
                    add(e.parts(), "", "string", i, apiLike ? 0.65 : 0.45, List.of(), List.of(), List.of(), false, false);
                }
                claimed.set(start, end);
                i = end;
            }
        }
    }
}
