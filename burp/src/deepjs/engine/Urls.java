package deepjs.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * URL splitting and reference resolution.
 *
 * java.net.URI rejects much of what appears in real pages and scripts (spaces,
 * `{placeholders}`, `|`), and resolves a few cases differently from browsers.
 * This is the RFC 3986 algorithm as browsers and most tooling apply it: it
 * never throws, and a reference it cannot make sense of is returned as it came.
 */
final class Urls {

    /** scheme://netloc/path?query#fragment — each piece without its delimiter, "" when absent. */
    record Split(String scheme, String netloc, String path, String query, String fragment) {

        /** The host, lower-cased, without credentials, port or IPv6 brackets. "" when there is none. */
        String hostname() {
            String host = netloc.substring(netloc.lastIndexOf('@') + 1);
            if (host.startsWith("[")) {
                int close = host.indexOf(']');
                return close < 0 ? "" : Py.lower(host.substring(1, close));
            }
            return Py.lower(Py.before(host, ":"));
        }
    }

    private static final Set<String> RELATIVE = Set.of("", "ftp", "http", "gopher", "nntp", "imap", "wais", "file", "https",
            "shttp", "mms", "prospero", "rtsp", "rtspu", "sftp", "svn", "svn+ssh", "ws", "wss");
    private static final Set<String> WITH_PARAMS = Set.of("", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp",
            "rtsp", "rtspu", "sip", "sips", "mms", "sftp", "tel");
    private static final String SCHEME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.";

    private Urls() {
    }

    static Split split(String url) {
        return split(url, "");
    }

    private static Split split(String url, String defaultScheme) {
        // leading control characters and spaces, and any tab or line break, are not part of a URL
        int from = 0;
        while (from < url.length() && url.charAt(from) <= ' ') {
            from++;
        }
        url = url.substring(from).replace("\t", "").replace("\r", "").replace("\n", "");
        String scheme = defaultScheme, netloc = "", query = "", fragment = "";
        int colon = url.indexOf(':');
        if (colon > 0 && isAsciiLetter(url.charAt(0))) {
            boolean valid = true;
            for (int i = 0; i < colon && valid; i++) {
                valid = SCHEME_CHARS.indexOf(url.charAt(i)) >= 0;
            }
            if (valid) {
                scheme = Py.lower(url.substring(0, colon));
                url = url.substring(colon + 1);
            }
        }
        if (url.startsWith("//")) {
            int end = url.length();
            for (char delimiter : new char[]{'/', '?', '#'}) {
                int at = url.indexOf(delimiter, 2);
                if (at >= 0 && at < end) {
                    end = at;
                }
            }
            netloc = url.substring(2, end);
            url = url.substring(end);
        }
        int hash = url.indexOf('#');
        if (hash >= 0) {
            fragment = url.substring(hash + 1);
            url = url.substring(0, hash);
        }
        int question = url.indexOf('?');
        if (question >= 0) {
            query = url.substring(question + 1);
            url = url.substring(0, question);
        }
        return new Split(scheme, netloc, url, query, fragment);
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static String unsplit(String scheme, String netloc, String path, String query, String fragment) {
        String url = path;
        if (!netloc.isEmpty()) {
            if (!url.isEmpty() && !url.startsWith("/")) {
                url = "/" + url;
            }
            url = "//" + netloc + url;
        } else if (url.startsWith("//")
                || (!scheme.isEmpty() && RELATIVE.contains(scheme) && (url.isEmpty() || url.startsWith("/")))) {
            url = "//" + url;                               // an empty authority must stay visible
        }
        if (!scheme.isEmpty()) {
            url = scheme + ":" + url;
        }
        if (!query.isEmpty()) {
            url = url + "?" + query;
        }
        if (!fragment.isEmpty()) {
            url = url + "#" + fragment;
        }
        return url;
    }

    /** The `;parameters` of the last path segment, split off: {path, params}. */
    private static String[] splitParams(String scheme, String path) {
        if (!WITH_PARAMS.contains(scheme) || path.indexOf(';') < 0) {
            return new String[]{path, ""};
        }
        int slash = path.lastIndexOf('/');
        int semi = path.indexOf(';', Math.max(slash, 0));
        return semi < 0 ? new String[]{path, ""} : new String[]{path.substring(0, semi), path.substring(semi + 1)};
    }

    private static String withParams(String path, String params) {
        return params.isEmpty() ? path : path + ";" + params;
    }

    /** Resolve `reference` against `base`, as a browser would for a link on the page `base`. */
    static String join(String base, String reference) {
        if (base.isEmpty()) {
            return reference;
        }
        if (reference.isEmpty()) {
            return base;
        }
        Split b = split(base);
        Split r = split(reference, b.scheme());
        if (!r.scheme().equals(b.scheme()) || !RELATIVE.contains(r.scheme())) {
            return reference;
        }
        String[] basePath = splitParams(b.scheme(), b.path());
        String[] refPath = splitParams(r.scheme(), r.path());
        String netloc = r.netloc();
        if (!netloc.isEmpty()) {
            return unsplit(r.scheme(), netloc, withParams(refPath[0], refPath[1]), r.query(), r.fragment());
        }
        netloc = b.netloc();
        if (refPath[0].isEmpty() && refPath[1].isEmpty()) {
            String query = r.query().isEmpty() ? b.query() : r.query();
            return unsplit(r.scheme(), netloc, withParams(basePath[0], basePath[1]), query, r.fragment());
        }

        List<String> baseParts = Py.split(basePath[0], "/");
        if (!baseParts.get(baseParts.size() - 1).isEmpty()) {
            baseParts.remove(baseParts.size() - 1);         // the base's own file name
        }
        List<String> segments;
        if (refPath[0].startsWith("/")) {
            segments = Py.split(refPath[0], "/");
        } else {
            List<String> all = new ArrayList<>(baseParts);
            all.addAll(Py.split(refPath[0], "/"));
            segments = new ArrayList<>();
            for (int i = 0; i < all.size(); i++) {          // empty segments survive only at the two ends
                if (i == 0 || i == all.size() - 1 || !all.get(i).isEmpty()) {
                    segments.add(all.get(i));
                }
            }
        }
        List<String> resolved = new ArrayList<>();
        for (String segment : segments) {
            if (segment.equals("..")) {
                if (!resolved.isEmpty()) {
                    resolved.remove(resolved.size() - 1);
                }
            } else if (!segment.equals(".")) {
                resolved.add(segment);
            }
        }
        String last = segments.get(segments.size() - 1);
        if (last.equals(".") || last.equals("..")) {
            resolved.add("");                               // "a/b/.." names a directory: keep the trailing slash
        }
        String path = String.join("/", resolved);
        return unsplit(r.scheme(), netloc, withParams(path.isEmpty() ? "/" : path, refPath[1]), r.query(), r.fragment());
    }
}
