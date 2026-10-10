package deepjs.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A JSON reader for the two documents the engine has to open: source maps and
 * the header / payload of a JWT. Objects become {@code Map<String, Object>},
 * arrays {@code List<Object>}, numbers {@code Long} or {@code Double}.
 *
 * Input is untrusted: nesting depth is bounded and every error is the same
 * checked {@link Malformed}, never a stack overflow or an index error.
 */
final class Json {

    static final class Malformed extends Exception {
        private static final long serialVersionUID = 1L;

        Malformed(String message) {
            super(message);
        }
    }

    private static final int MAX_DEPTH = 400;

    private final String s;
    private int at;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) throws Malformed {
        Json reader = new Json(text);
        reader.blank();
        Object value = reader.value(0);
        reader.blank();
        if (reader.at != text.length()) {
            throw new Malformed("extra data");
        }
        return value;
    }

    /** `value` as an object, or null when it is anything else. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> object(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    static List<Object> array(Object value) {
        return value instanceof List ? (List<Object>) value : null;
    }

    private void blank() {
        while (at < s.length()) {
            char c = s.charAt(at);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return;
            }
            at++;
        }
    }

    private Object value(int depth) throws Malformed {
        if (at >= s.length()) {
            throw new Malformed("unexpected end");
        }
        if (depth > MAX_DEPTH) {
            throw new Malformed("nested too deeply");
        }
        char c = s.charAt(at);
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                return word("true", Boolean.TRUE);
            case 'f':
                return word("false", Boolean.FALSE);
            case 'n':
                return word("null", null);
            case 'N':
                return word("NaN", Double.NaN);
            case 'I':
                return word("Infinity", Double.POSITIVE_INFINITY);
            default:
                if (c == '-' && s.startsWith("-Infinity", at)) {
                    return word("-Infinity", Double.NEGATIVE_INFINITY);
                }
                return number();
        }
    }

    private Object word(String word, Object value) throws Malformed {
        if (!s.startsWith(word, at)) {
            throw new Malformed("unexpected token");
        }
        at += word.length();
        return value;
    }

    private Map<String, Object> object(int depth) throws Malformed {
        Map<String, Object> out = new LinkedHashMap<>();
        at++;
        blank();
        if (at < s.length() && s.charAt(at) == '}') {
            at++;
            return out;
        }
        while (true) {
            blank();
            if (at >= s.length() || s.charAt(at) != '"') {
                throw new Malformed("expected a property name");
            }
            String key = string();
            blank();
            expect(':');
            blank();
            out.put(key, value(depth + 1));
            blank();
            if (at < s.length() && s.charAt(at) == ',') {
                at++;
                continue;
            }
            expect('}');
            return out;
        }
    }

    private List<Object> array(int depth) throws Malformed {
        List<Object> out = new ArrayList<>();
        at++;
        blank();
        if (at < s.length() && s.charAt(at) == ']') {
            at++;
            return out;
        }
        while (true) {
            blank();
            out.add(value(depth + 1));
            blank();
            if (at < s.length() && s.charAt(at) == ',') {
                at++;
                continue;
            }
            expect(']');
            return out;
        }
    }

    private void expect(char c) throws Malformed {
        if (at >= s.length() || s.charAt(at) != c) {
            throw new Malformed("expected '" + c + "'");
        }
        at++;
    }

    private String string() throws Malformed {
        at++;                                               // the opening quote
        int from = at;
        StringBuilder out = null;
        while (at < s.length()) {
            char c = s.charAt(at);
            if (c == '"') {
                String text = out == null ? s.substring(from, at) : out.append(s, from, at).toString();
                at++;
                return text;
            }
            if (c < 0x20) {
                throw new Malformed("control character in a string");
            }
            if (c != '\\') {
                at++;
                continue;
            }
            if (out == null) {
                out = new StringBuilder(Math.min(s.length() - from, 1 << 16));
            }
            out.append(s, from, at);
            if (at + 1 >= s.length()) {
                break;
            }
            char e = s.charAt(at + 1);
            at += 2;
            switch (e) {
                case '"', '\\', '/' -> out.append(e);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (at + 4 > s.length()) {
                        throw new Malformed("truncated \\u escape");
                    }
                    try {
                        out.append((char) Integer.parseInt(s, at, at + 4, 16));
                    } catch (NumberFormatException bad) {
                        throw new Malformed("bad \\u escape");
                    }
                    at += 4;
                }
                default -> throw new Malformed("bad escape");
            }
            from = at;
        }
        throw new Malformed("unterminated string");
    }

    private Object number() throws Malformed {
        int from = at;
        boolean integer = true;
        if (at < s.length() && s.charAt(at) == '-') {
            at++;
        }
        int digits = at;
        while (at < s.length() && Character.isDigit(s.charAt(at)) && s.charAt(at) < 0x80) {
            at++;
        }
        if (at == digits || (s.charAt(digits) == '0' && at - digits > 1)) {
            throw new Malformed("bad number");
        }
        if (at < s.length() && s.charAt(at) == '.') {
            integer = false;
            int fraction = ++at;
            while (at < s.length() && s.charAt(at) >= '0' && s.charAt(at) <= '9') {
                at++;
            }
            if (at == fraction) {
                throw new Malformed("bad number");
            }
        }
        if (at < s.length() && (s.charAt(at) == 'e' || s.charAt(at) == 'E')) {
            integer = false;
            at++;
            if (at < s.length() && (s.charAt(at) == '+' || s.charAt(at) == '-')) {
                at++;
            }
            int exponent = at;
            while (at < s.length() && s.charAt(at) >= '0' && s.charAt(at) <= '9') {
                at++;
            }
            if (at == exponent) {
                throw new Malformed("bad number");
            }
        }
        String text = s.substring(from, at);
        try {
            if (integer && text.length() <= 18) {
                return Long.parseLong(text);
            }
            return Double.parseDouble(text);
        } catch (NumberFormatException bad) {
            throw new Malformed("bad number");
        }
    }
}
