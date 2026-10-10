package deepjs.engine;

import static deepjs.engine.Lexer.STR;
import static deepjs.engine.Lexer.TPL;

import deepjs.engine.Endpoints.Endpoint;
import deepjs.engine.Endpoints.Extraction;
import deepjs.engine.Secrets.Secret;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyses responses obtained elsewhere — by Burp — and accumulates what they
 * reveal across files. It never makes a request: scripts and source maps the
 * content refers to are reported for the caller to fetch.
 *
 * {@link #feed} takes one response; {@link #flush} returns what is new since
 * the previous call as records whose first field is a tag:
 *
 *   E method, full url, url, kind, query names, body fields, header names, file, line, confidence
 *   W method, url                       withdraw that endpoint: a better one replaces it
 *   S severity, kind, shown value, key, file, line, note, fingerprint, public (0|1)
 *   C script url                        referred to by the code, not seen yet
 *   M map url, referenced (0|1)         a source map worth fetching
 *   H host, class, service, non-production (0|1)
 *   R route     G type, name     B api base     P package
 *
 * An instance is not thread-safe: use it from one thread.
 */
public final class Engine {

    private static final int MAX_ANALYSE_CHARS = 30 * 1024 * 1024;

    /** `{apiUrl}/users`: a URL that starts with one unresolved name — a base URL variable. */
    private static final Pattern LEADING_BASE = Py.rx("^\\{([A-Za-z_$][\\w$]*)\\}(?=/|$)");
    /** Values worth remembering across files as a possible base URL:  "."  "/api"  "https://api.example.com/v2" */
    private static final Pattern BASE_VALUE = Py.rx("^(?:\\.{0,2}|(?:\\.{0,2}/|https?://|//)[^\\s\"'<>{}]{0,300})$");
    private static final Pattern HTTP_URL = Py.rxi("^https?://");
    private static final Pattern ANY_SCHEME = Py.rxi("^[a-z][a-z0-9+.\\-]*://");
    /** Third-party script hosts that are never the application's own code. */
    private static final Pattern VENDOR_HOSTS = Py.rxi(
            "(?:^|\\.)(?:google-analytics\\.com|googletagmanager\\.com|googlesyndication\\.com|doubleclick\\.net|gstatic\\.com"
                    + "|googleapis\\.com|google\\.com|recaptcha\\.net|hcaptcha\\.com|facebook\\.net|facebook\\.com|fbcdn\\.net|twitter\\.com"
                    + "|x\\.com|linkedin\\.com|licdn\\.com|stripe\\.com|paypal\\.com|paypalobjects\\.com|braintreegateway\\.com"
                    + "|cloudflareinsights\\.com|cloudflare\\.com|hotjar\\.com|intercom\\.io|intercomcdn\\.com|segment\\.com|segment\\.io"
                    + "|sentry-cdn\\.com|sentry\\.io|jsdelivr\\.net|unpkg\\.com|cdnjs\\.cloudflare\\.com|jquery\\.com|bootstrapcdn\\.com"
                    + "|newrelic\\.com|nr-data\\.net|datadoghq\\.com|datadoghq-browser-agent\\.com|clarity\\.ms|bing\\.com|hs-scripts\\.com"
                    + "|hubspot\\.com|hsforms\\.net|zendesk\\.com|zdassets\\.com|crisp\\.chat|tawk\\.to|optimizely\\.com|mixpanel\\.com"
                    + "|amplitude\\.com|fullstory\\.com|onetrust\\.com|cookielaw\\.org|cookiebot\\.com|youtube\\.com|ytimg\\.com|vimeo\\.com"
                    + "|tiktok\\.com|snapchat\\.com|pinterest\\.com|addthis\\.com|disqus\\.com|trustpilot\\.com|typekit\\.net|fontawesome\\.com"
                    + "|polyfill\\.io|mxpnl\\.com|launchdarkly\\.com|pendo\\.io|heapanalytics\\.com|appcues\\.com|drift\\.com|driftt\\.com)$");

    private final boolean entropy;
    private final Hosts hosts = new Hosts();
    private final Set<String> scope = new HashSet<>();
    private final Set<String> assetHosts = new HashSet<>();
    private final Map<String, Endpoint> endpoints = new LinkedHashMap<>();
    private final Set<String> called = new HashSet<>();
    private final Map<String, Secret> secrets = new LinkedHashMap<>();
    private final Set<String> routes = new TreeSet<>(Py::compare);
    private final Set<String[]> graphql = new TreeSet<>((a, b) -> a[0].equals(b[0]) ? Py.compare(a[1], b[1]) : Py.compare(a[0], b[0]));
    private final Set<String> bases = new TreeSet<>(Py::compare);
    private final Set<String> packages = new TreeSet<>(Py::compare);
    private final Set<String> seenUrls = new HashSet<>();
    private final Set<String> seenMaps = new HashSet<>();
    private final Set<String> unvisited = new TreeSet<>(Py::compare);
    private final Map<String, Boolean> mapCandidates = new TreeMap<>(Py::compare);
    /** Property name → base-URL-like values, over every file: `environment.apiUrl` is usually defined in one chunk and used in another. */
    private final Map<String, Set<String>> baseProps = new HashMap<>();
    private final Set<String> baseTainted = new HashSet<>();
    private String origin = "";                             // scheme://host of the first response seen

    // what flush() has already reported
    private final Map<String, String> sentEndpoints = new LinkedHashMap<>();
    private final Set<String> sentSecrets = new HashSet<>();
    private final Set<String> sentOther = new HashSet<>();

    /** @param entropy also report unlabelled random-looking strings (noisy) */
    public Engine(boolean entropy) {
        this.entropy = entropy;
    }

    // ── input ────────────────────────────────────────────────────────────────

    /** @param kind "script", "html", "map", or "auto" to decide from the content */
    public void feed(String url, byte[] body, String kind) {
        Urls.Split parts = Urls.split(url);
        String host = parts.hostname();
        boolean vendor = !host.isEmpty() && Py.found(VENDOR_HOSTS, host);
        if (vendor && !kind.equals("map")) {
            hosts.add(host, url, null);                     // analytics / widget code is not the application
            return;
        }
        if (!host.isEmpty() && !vendor) {
            scope.add(host);
            scope.add(Hosts.registrable(host));
            hosts.scope = new TreeSet<>(scope);
            if (origin.isEmpty()) {
                origin = parts.scheme() + "://" + parts.netloc();
            }
        }
        seenUrls.add(Py.before(url, "#"));
        unvisited.remove(url);
        if (kind.equals("map")) {
            mapCandidates.remove(url);
            if (seenMaps.add(url)) {
                ingestMap(body);
            }
            return;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        String head = Py.lower(Py.lstrip(text.substring(0, Math.min(400, text.length()))));
        boolean html = kind.equals("html") || (kind.equals("auto") && (Py.startsWithAny(head, "<!doctype", "<html")
                || (head.startsWith("<") && Py.lower(text.substring(0, Math.min(20000, text.length()))).contains("<script"))));
        if (html) {
            handleHtml(text, url);
        } else {
            analyse(text, url, "script", url);
        }
    }

    private boolean inScope(String url) {
        String host = Urls.split(url).hostname();
        if (host.isEmpty()) {
            return false;
        }
        if (scope.contains(host) || scope.contains(Hosts.registrable(host)) || assetHosts.contains(host)) {
            return true;
        }
        for (String s : scope) {
            if (host.endsWith("." + s)) {
                return true;
            }
        }
        return false;
    }

    private void handleHtml(String html, String url) {
        Chunks.HtmlScripts found = Chunks.scriptsFromHtml(html, url);
        for (String src : found.urls) {
            String host = Urls.split(src).hostname();
            if (!inScope(src)) {
                if (Py.found(VENDOR_HOSTS, host)) {
                    hosts.add(host, url, null);
                    continue;
                }
                assetHosts.add(host);                       // the application's own CDN / asset host
            }
            if (!seenUrls.contains(src)) {
                unvisited.add(src);
            }
        }
        for (int i = 0; i < found.inline.size(); i++) {
            analyse(found.inline.get(i), url + "#inline-" + (i + 1), "inline", url);
        }
        String pageHost = Urls.split(url).netloc();
        for (Chunks.Form form : Chunks.formsFromHtml(html, url)) {
            Urls.Split action = Urls.split(form.action());
            List<String> query = new ArrayList<>();
            for (String pair : Py.split(action.query(), "&")) {
                if (!pair.isEmpty()) {
                    query.add(Py.before(pair, "="));
                }
            }
            boolean get = form.method().equals("GET");
            Endpoint ep = new Endpoint();
            ep.url = action.netloc().equals(pageHost) ? (action.path().isEmpty() ? "/" : action.path()) : Py.before(form.action(), "?");
            ep.method = form.method();
            ep.kind = "form";
            ep.file = url;
            ep.confidence = 0.9;
            ep.params = Py.unique(query, get ? form.fields() : List.of());
            ep.body = get ? new ArrayList<>() : new ArrayList<>(form.fields());
            merge(ep);
        }
    }

    // ── analysis ─────────────────────────────────────────────────────────────

    /** @param kind "script" (a response), "inline" (a script element) or "source" (recovered from a source map) */
    @SuppressWarnings("unchecked")
    private void analyse(String text, String name, String kind, String url) {
        if (text.isEmpty() || text.length() > MAX_ANALYSE_CHARS) {
            return;
        }
        Program p = new Program(text, name);

        for (Map.Entry<String, Set<String>> prop : p.props.entrySet()) {
            int kept = 0;
            for (String v : prop.getValue()) {
                if (Py.startsWith(BASE_VALUE, v)) {
                    baseProps.computeIfAbsent(prop.getKey(), k -> new HashSet<>()).add(v);
                    kept++;
                }
            }
            if (kept != prop.getValue().size()) {
                baseTainted.add(prop.getKey());
            }
        }
        baseTainted.addAll(p.taintedProps);

        Extraction ex = Endpoints.extract(p, name);
        for (Endpoint ep : ex.endpoints) {
            merge(ep);
        }
        routes.addAll(ex.routes);
        graphql.addAll(ex.graphql);
        bases.addAll(ex.bases);

        boolean recovered = name.startsWith("map:");
        for (Secret s : Secrets.scan(p, name, entropy)) {
            String key = s.kind + "\u0000" + s.value;
            Secret old = secrets.get(key);
            if (old == null || (recovered && !old.file.startsWith("map:"))) {
                secrets.put(key, s);                        // the original source is the better pointer
            }
        }

        for (int i = 0; i < p.n; i++) {
            if (p.kind[i] == STR) {
                String s = (String) p.value[i];
                if (s.length() > 3) {
                    hosts.feed(s, name);
                }
            } else if (p.kind[i] == TPL) {
                for (Object segment : (List<Object>) p.value[i]) {
                    if (segment instanceof String s && s.length() > 3) {
                        hosts.feed(s, name);
                    }
                }
            }
        }
        if (kind.equals("source")) {
            return;
        }

        Chunks.Discovery discovery = Chunks.discover(p, url);
        routes.addAll(discovery.routes);
        for (String ref : discovery.scripts) {
            if (!Py.startsWith(HTTP_URL, ref) || !seenUrls.contains(ref)) {
                unvisited.add(ref);
            }
        }
        if (kind.equals("script")) {
            sourceMapOf(text, url);
        }
    }

    private void merge(Endpoint ep) {
        String key = ep.key();
        Endpoint old = endpoints.get(key);
        if (old == null) {
            if (ep.isCall()) {
                // a bare string seen in another file turns out to be a real call
                String asString = "\u0000" + ep.url;
                Endpoint stale = endpoints.get(asString);
                if (stale != null && !stale.isCall()) {
                    endpoints.remove(asString);
                }
                called.add(ep.url);
            } else if (called.contains(ep.url)) {
                return;
            }
            endpoints.put(key, ep);
            return;
        }
        old.params = Py.unique(old.params, ep.params);
        old.body = Py.unique(old.body, ep.body);
        old.headers = Py.unique(old.headers, ep.headers);
        if (ep.confidence > old.confidence) {
            old.confidence = ep.confidence;
            old.kind = ep.kind;
        }
        if (ep.file.startsWith("map:") && !old.file.startsWith("map:")) {
            old.file = ep.file;                             // the original source is the better pointer
            old.line = ep.line;
        }
    }

    /**
     * `{hostServer}/rest/user/login` → `/rest/user/login` once some file — often
     * another chunk — has shown that `hostServer` is only ever "." (or one URL).
     */
    private void resolveBases() {
        for (Map.Entry<String, Endpoint> entry : new ArrayList<>(endpoints.entrySet())) {
            Endpoint ep = entry.getValue();
            Matcher m = LEADING_BASE.matcher(ep.url);
            if (!m.lookingAt()) {
                continue;
            }
            String name = m.group(1);
            Set<String> values = baseProps.get(name);
            if (baseTainted.contains(name) || values == null || values.size() != 1) {
                continue;
            }
            String base = Py.rstrip(values.iterator().next(), "/");
            String rest = ep.url.substring(m.end());
            if (base.isEmpty() || base.equals(".")) {
                base = "";
                if (rest.isEmpty()) {
                    continue;
                }
            }
            if (endpoints.remove(entry.getKey()) == null) {
                continue;
            }
            ep.url = Endpoints.normaliseUrl(base + rest);
            merge(ep);
        }
    }

    // ── source maps ──────────────────────────────────────────────────────────

    private void sourceMapOf(String text, String url) {
        String ref = SourceMaps.findReference(text);
        if (ref != null && ref.startsWith("data:")) {
            byte[] inline = SourceMaps.decodeInline(ref);
            if (inline != null && inline.length > 0) {
                ingestMap(inline);
            }
        } else if (Py.startsWith(HTTP_URL, url)) {
            String candidate = ref != null ? Urls.join(url, ref) : Py.before(url, "?") + ".map";
            if (!candidate.isEmpty() && !seenMaps.contains(candidate)) {
                mapCandidates.putIfAbsent(candidate, ref != null);      // the caller decides whether to fetch it
            }
        }
    }

    private void ingestMap(byte[] data) {
        SourceMaps.SourceMap map = SourceMaps.parse(data);
        if (map == null) {
            return;
        }
        packages.addAll(map.packages);
        List<SourceMaps.Source> app = map.appSources();
        for (SourceMaps.Source source : app.subList(0, Math.min(app.size(), 5000))) {
            analyse(source.content(), "map:" + source.path(), "source", "");
        }
    }

    // ── output ───────────────────────────────────────────────────────────────

    /** Everything that is new, or has changed, since the previous call. `reveal`: secret values unmasked. */
    public List<String[]> flush(boolean reveal) {
        List<String[]> out = new ArrayList<>();
        resolveBases();
        // an endpoint the engine replaced: a bare string that turned out to be a call, or a
        // `{base}/path` whose base another file has just revealed
        for (String key : new ArrayList<>(sentEndpoints.keySet())) {
            if (!endpoints.containsKey(key)) {
                sentEndpoints.remove(key);
                int split = key.indexOf('\u0000');
                out.add(new String[]{"W", key.substring(0, split), key.substring(split + 1)});
            }
        }
        for (Map.Entry<String, Endpoint> entry : endpoints.entrySet()) {
            Endpoint ep = entry.getValue();
            String params = String.join(",", ep.params), body = String.join(",", ep.body), headers = String.join(",", ep.headers);
            String signature = ep.kind + "|" + params + "|" + body + "|" + headers;
            if (!signature.equals(sentEndpoints.put(entry.getKey(), signature))) {
                out.add(new String[]{"E", ep.method, fullUrl(ep), ep.url, ep.kind, params, body, headers, ep.file,
                        Integer.toString(ep.line), new BigDecimal(ep.confidence).setScale(2, RoundingMode.HALF_EVEN).toPlainString()});
            }
        }
        for (Map.Entry<String, Secret> entry : secrets.entrySet()) {
            if (sentSecrets.add(entry.getKey())) {
                Secret s = entry.getValue();
                out.add(new String[]{"S", s.severity, s.kind, reveal ? s.value : s.masked(), s.key, s.file,
                        Integer.toString(s.line), s.note, s.fingerprint(), s.isPublic ? "1" : "0"});
            }
        }
        for (String url : unvisited) {
            if (!seenUrls.contains(url) && Py.startsWith(HTTP_URL, url)) {
                once(out, "C", url, url);
            }
        }
        for (Map.Entry<String, Boolean> candidate : mapCandidates.entrySet()) {
            once(out, "M", candidate.getKey(), candidate.getKey(), candidate.getValue() ? "1" : "0");
        }
        for (Hosts.Host h : hosts.hosts.values()) {
            once(out, "H", h.name, h.name, h.kind, h.service, h.nonProduction ? "1" : "0");
        }
        for (String route : routes) {
            once(out, "R", route, route);
        }
        for (String[] operation : graphql) {
            once(out, "G", operation[0] + " " + operation[1], operation[0], operation[1]);
        }
        for (String base : bases) {
            once(out, "B", base, base);
        }
        for (String name : packages) {
            once(out, "P", name, name);
        }
        return out;
    }

    private void once(List<String[]> out, String tag, String identity, String... fields) {
        if (sentOther.add(tag + "\u0000" + identity)) {
            String[] record = new String[fields.length + 1];
            record[0] = tag;
            System.arraycopy(fields, 0, record, 1, fields.length);
            out.add(record);
        }
    }

    /** scheme://host of the file an endpoint was found in, or of the first response when it has no URL. */
    private String originOf(Endpoint ep) {
        if (ep.file.startsWith("http://") || ep.file.startsWith("https://")) {
            Urls.Split source = Urls.split(ep.file);
            return source.scheme() + "://" + source.netloc();
        }
        return origin;
    }

    /**
     * An absolute URL for an endpoint, for display and for Repeater. When the
     * base is a runtime value (`{apiUrl}/users`) this is a best guess — the one
     * absolute API base the code names, else the script's own site — and the
     * `url` field of the record still shows the placeholder.
     */
    private String fullUrl(Endpoint ep) {
        String u = ep.url;
        if (u.startsWith("{")) {
            int end = u.indexOf('}') + 1;
            if (end <= 1 || !u.startsWith("/", end)) {
                return u;
            }
            List<String> absolute = new ArrayList<>();
            for (String base : bases) {
                if (Py.startsWith(HTTP_URL, base)) {
                    absolute.add(base);
                }
            }
            String guess = absolute.size() == 1 ? Py.rstrip(absolute.get(0), "/") : originOf(ep);
            return guess.isEmpty() ? u : guess + u.substring(end);
        }
        if (Py.startsWith(ANY_SCHEME, u)) {
            return u;
        }
        if (u.startsWith("//")) {
            return "https:" + u;
        }
        String site = originOf(ep);
        if (u.startsWith("/")) {
            return site + u;
        }
        String base = bases.size() == 1 ? bases.iterator().next() : "";
        if (!base.isEmpty()) {
            base = Py.startsWith(HTTP_URL, base) ? base : site + base;
            return Py.rstrip(base, "/") + "/" + Py.lstrip(u, "./");
        }
        return site.isEmpty() ? u : site + "/" + Py.lstrip(u, "./");
    }
}
