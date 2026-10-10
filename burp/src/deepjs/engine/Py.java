package deepjs.engine;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The engine is a port of the `deepjs` Python package, and the two are kept
 * identical finding for finding (see burp/parity.py). This class holds the
 * handful of places where Java's defaults differ from the behaviour the rules
 * were written against: what counts as whitespace, how regular expressions
 * treat Unicode and line ends, how strings sort, how a float rounds.
 */
final class Py {

    private Py() {
    }

    // ── regular expressions ──────────────────────────────────────────────────

    /** `.`, `^` and `$` know only "\n"; `\w`, `\d`, `\s`, `\b` are Unicode-aware. */
    private static final int BASE = Pattern.UNIX_LINES | Pattern.UNICODE_CHARACTER_CLASS;

    static Pattern rx(String pattern) {
        return Pattern.compile(pattern, BASE);
    }

    /** Case-insensitive. */
    static Pattern rxi(String pattern) {
        return Pattern.compile(pattern, BASE | Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    }

    /** Case-insensitive, `.` also matches "\n". */
    static Pattern rxis(String pattern) {
        return Pattern.compile(pattern, BASE | Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.DOTALL);
    }

    static boolean matches(Pattern p, String s) {
        return p.matcher(s).matches();
    }

    /** The pattern matches at the start of `s`. */
    static boolean startsWith(Pattern p, String s) {
        return p.matcher(s).lookingAt();
    }

    static boolean found(Pattern p, String s) {
        return p.matcher(s).find();
    }

    // ── strings ──────────────────────────────────────────────────────────────

    static boolean isSpace(char c) {
        return c == ' ' || (c >= '\t' && c <= '\r') || (c >= 0x1c && c <= 0x1f) || c == 0x85 || c == 0xa0
                || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f
                || c == 0x205f || c == 0x3000;
    }

    static String strip(String s) {
        int a = 0, b = s.length();
        while (a < b && isSpace(s.charAt(a))) {
            a++;
        }
        while (b > a && isSpace(s.charAt(b - 1))) {
            b--;
        }
        return a == 0 && b == s.length() ? s : s.substring(a, b);
    }

    static String lstrip(String s) {
        int a = 0;
        while (a < s.length() && isSpace(s.charAt(a))) {
            a++;
        }
        return a == 0 ? s : s.substring(a);
    }

    /** Remove any of `chars` from both ends. */
    static String strip(String s, String chars) {
        int a = 0, b = s.length();
        while (a < b && chars.indexOf(s.charAt(a)) >= 0) {
            a++;
        }
        while (b > a && chars.indexOf(s.charAt(b - 1)) >= 0) {
            b--;
        }
        return a == 0 && b == s.length() ? s : s.substring(a, b);
    }

    static String rstrip(String s, String chars) {
        int b = s.length();
        while (b > 0 && chars.indexOf(s.charAt(b - 1)) >= 0) {
            b--;
        }
        return b == s.length() ? s : s.substring(0, b);
    }

    static String lstrip(String s, String chars) {
        int a = 0;
        while (a < s.length() && chars.indexOf(s.charAt(a)) >= 0) {
            a++;
        }
        return a == 0 ? s : s.substring(a);
    }

    /** Everything before the first `sep` (all of `s` when there is none). */
    static String before(String s, String sep) {
        int i = s.indexOf(sep);
        return i < 0 ? s : s.substring(0, i);
    }

    /** Everything after the first `sep` ("" when there is none). */
    static String after(String s, String sep) {
        int i = s.indexOf(sep);
        return i < 0 ? "" : s.substring(i + sep.length());
    }

    /** Split on every `sep`, keeping empty pieces at both ends. */
    static List<String> split(String s, String sep) {
        List<String> out = new ArrayList<>();
        int from = 0;
        while (true) {
            int i = s.indexOf(sep, from);
            if (i < 0) {
                out.add(s.substring(from));
                return out;
            }
            out.add(s.substring(from, i));
            from = i + sep.length();
        }
    }

    static boolean startsWithAny(String s, String... prefixes) {
        for (String p : prefixes) {
            if (s.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    static boolean in(String s, String... options) {
        for (String o : options) {
            if (o.equals(s)) {
                return true;
            }
        }
        return false;
    }

    static String lower(String s) {
        return s.toLowerCase(java.util.Locale.ROOT);
    }

    static String upper(String s) {
        return s.toUpperCase(java.util.Locale.ROOT);
    }

    static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) > 0x7f) {
                return false;
            }
        }
        return true;
    }

    /** Order by code point, the way Python compares strings. */
    static int compare(String a, String b) {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int x = a.codePointAt(i), y = b.codePointAt(j);
            if (x != y) {
                return Integer.compare(x, y);
            }
            i += Character.charCount(x);
            j += Character.charCount(y);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    }

    /** The values once each, first occurrence first. */
    static List<String> unique(List<String> a, List<String> b) {
        LinkedHashSet<String> seen = new LinkedHashSet<>(a);
        seen.addAll(b);
        return new ArrayList<>(seen);
    }

    // ── numbers ──────────────────────────────────────────────────────────────

    /** Round half to even on the exact value of the double. */
    static double round(double x, int digits) {
        if (Double.isNaN(x) || Double.isInfinite(x)) {
            return x;
        }
        return new BigDecimal(x).setScale(digits, RoundingMode.HALF_EVEN).doubleValue();
    }

    static double log2(double x) {
        return Math.log(x) / Math.log(2.0);
    }

    // ── sorted int lists ─────────────────────────────────────────────────────

    /** A growable int array. */
    static final class Ints {
        private int[] a = new int[8];
        private int size;

        void add(int v) {
            if (size == a.length) {
                a = Arrays.copyOf(a, size * 2);
            }
            a[size++] = v;
        }

        int get(int i) {
            return a[i];
        }

        int size() {
            return size;
        }

        /** First index whose value is not less than `x`. The search is a plain bisection: it does not require order. */
        int bisectLeft(int x) {
            int lo = 0, hi = size;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (a[mid] < x) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }

        /** First index whose value is greater than `x`. */
        int bisectRight(int x) {
            int lo = 0, hi = size;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (x < a[mid]) {
                    hi = mid;
                } else {
                    lo = mid + 1;
                }
            }
            return lo;
        }
    }
}
