package deepjs.engine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source maps: the original sources a bundle was built from.
 *
 * A map that embeds `sourcesContent` hands back the application's code with
 * real names, comments and TypeScript; one that does not still lists every
 * file and every npm package that went into the build. Source names in a map
 * are untrusted input — {@link #safeRelativePath} turns one into a path that
 * cannot leave the directory it is joined to.
 */
final class SourceMaps {

    /** One entry of a map's `sources`. `content` is null when the map lists the file without embedding it. */
    record Source(String name, String path, String content) {

        boolean isDependency() {
            return name.replace('\\', '/').contains("node_modules/");
        }

        boolean isRuntime() {
            return Py.found(RUNTIME_SOURCE, name);
        }
    }

    static final class SourceMap {
        final List<Source> sources = new ArrayList<>();
        final Set<String> packages = new TreeSet<>(Py::compare);

        /** The application's own files that came with their text. */
        List<Source> appSources() {
            List<Source> out = new ArrayList<>();
            for (Source s : sources) {
                if (s.content() != null && !s.content().isEmpty() && !s.isDependency() && !s.isRuntime()) {
                    out.add(s);
                }
            }
            return out;
        }
    }

    private static final Pattern MAP_REFERENCE = Py.rx("(?://|/\\*)[#@]\\s*sourceMappingURL=([^\\s'\"*]+)");
    private static final Pattern SCHEME = Py.rxi("^(?:webpack(?:-internal)?|ng|rollup|vite|turbopack|file|rsc|parcel|\\w+-webpack)://+");
    private static final Pattern PACKAGE = Py.rx("node_modules/((?:@[\\w.\\-~]+/)?[\\w.\\-~]+)");
    private static final Pattern UNSAFE = Py.rx("[^\\w.\\-@+ ()\\[\\]]");
    private static final Pattern RUNTIME_SOURCE = Py.rx(
            "^(?:\\(webpack\\)|webpack/|external |ignored\\||multi |\\(lazy\\)|<anon|~/)|\\$_lazy_route|/webpack/(?:bootstrap|runtime)");
    private static final Pattern DRIVE = Py.rx("^[A-Za-z]:");

    private static final int MAX_SOURCES = 20000;
    private static final int MAX_SOURCE_CHARS = 8 * 1024 * 1024;
    static final int MAX_MAP_BYTES = 80 * 1024 * 1024;

    private SourceMaps() {
    }

    /** The last `//# sourceMappingURL=` in a script (only the tail is searched), or null. */
    static String findReference(String js) {
        String tail = js.length() > 4096 ? js.substring(js.length() - 4096) : js;
        String last = null;
        for (Matcher m = MAP_REFERENCE.matcher(tail); m.find(); ) {
            last = m.group(1);
        }
        return last;
    }

    /** `data:application/json;base64,…` → bytes; null when it is not a data URL or cannot be decoded. */
    static byte[] decodeInline(String reference) {
        if (!reference.startsWith("data:")) {
            return null;
        }
        int comma = reference.indexOf(',');
        String head = comma < 0 ? reference : reference.substring(0, comma);
        String payload = comma < 0 ? "" : reference.substring(comma + 1);
        if (!head.contains(";base64")) {
            return percentDecode(payload);
        }
        try {
            String unpadded = Py.rstrip(payload, "=");
            return Base64.getDecoder().decode(unpadded + "=".repeat((4 - unpadded.length() % 4) % 4));
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
    }

    private static byte[] percentDecode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length() && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
                out.write(Integer.parseInt(s, i + 1, i + 3, 16));
                i += 3;
            } else {
                int cp = s.codePointAt(i);
                out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                i += Character.charCount(cp);
            }
        }
        return out.toByteArray();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * Turn a source name from a map into a relative path that cannot escape the
     * directory it is joined to: no scheme, no drive, no absolute root, no `..`.
     */
    static String safeRelativePath(String name) {
        String n = SCHEME.matcher(Py.strip(name).replace('\\', '/')).replaceFirst("");
        n = Py.before(Py.before(n, "?"), "#");
        n = DRIVE.matcher(n).replaceFirst("");
        List<String> parts = new ArrayList<>();
        for (String raw : Py.split(n, "/")) {
            String segment = Py.strip(raw);
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                continue;                                   // '..' is dropped, never honoured
            }
            segment = Py.strip(UNSAFE.matcher(segment).replaceAll("_"), ". ");
            if (segment.isEmpty()) {
                segment = "_";
            }
            parts.add(segment.length() > 120 ? segment.substring(0, 120) : segment);
        }
        if (parts.isEmpty()) {
            return "unnamed";
        }
        String path = String.join("/", parts.subList(Math.max(0, parts.size() - 12), parts.size()));   // bound depth
        return path.length() > 400 ? path.substring(0, 400) : path;
    }

    /** Parse a source map. Returns null when `data` is not one. */
    static SourceMap parse(byte[] data) {
        if (data.length > MAX_MAP_BYTES) {
            return null;
        }
        String text = Py.lstrip(new String(data, StandardCharsets.UTF_8), "﻿");
        if (text.startsWith(")]}'")) {                      // the XSSI guard some servers prepend
            int newline = text.indexOf('\n');
            text = newline < 0 ? text : text.substring(newline + 1);
        }
        Map<String, Object> doc;
        try {
            doc = Json.object(Json.parse(text));
        } catch (Json.Malformed notJson) {
            return null;
        }
        if (doc == null) {
            return null;
        }
        SourceMap out = new SourceMap();
        Map<String, Integer> seen = new HashMap<>();
        List<Object> sections = Json.array(doc.get("sections"));
        if (sections != null) {                             // an indexed map
            for (Object section : sections) {
                Map<String, Object> entry = Json.object(section);
                Map<String, Object> inner = entry == null ? null : Json.object(entry.get("map"));
                if (inner != null) {
                    take(inner, out, seen);
                }
            }
        }
        take(doc, out, seen);
        return out.sources.isEmpty() ? null : out;
    }

    private static void take(Map<String, Object> section, SourceMap out, Map<String, Integer> seen) {
        List<Object> sources = Json.array(section.get("sources"));
        if (sources == null) {
            return;
        }
        List<Object> contents = Json.array(section.get("sourcesContent"));
        String root = section.get("sourceRoot") instanceof String s ? s : "";
        for (int i = 0; i < sources.size(); i++) {
            if (out.sources.size() >= MAX_SOURCES) {
                return;
            }
            if (!(sources.get(i) instanceof String name) || name.isEmpty()) {
                continue;
            }
            String full = !root.isEmpty() && !Py.startsWith(SCHEME, name) ? Py.rstrip(root, "/") + "/" + name : name;
            for (Matcher m = PACKAGE.matcher(full.replace('\\', '/')); m.find(); ) {
                out.packages.add(m.group(1));
            }
            String content = contents != null && i < contents.size() && contents.get(i) instanceof String c ? c : null;
            if (content != null && content.length() > MAX_SOURCE_CHARS) {
                content = content.substring(0, MAX_SOURCE_CHARS);
            }
            String path = safeRelativePath(full);
            int count = seen.merge(path, 1, Integer::sum) - 1;
            if (count > 0) {                                // two sources sanitised to the same path
                int dot = path.lastIndexOf('.');
                path = dot >= 0 ? path.substring(0, dot) + "~" + count + "." + path.substring(dot + 1) : path + "~" + count;
            }
            out.sources.add(new Source(full, path, content));
        }
    }
}
