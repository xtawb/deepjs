package deepjs.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Is this string a secret, a label, or filler?
 *
 * A front-end bundle is full of strings that sit under secret-sounding names
 * and are nothing of the kind: `password: "Password"` is a form label, `token:
 * "auth_token"` is a storage key, `apiKey: "YOUR_API_KEY"` is a placeholder.
 * This class scores a value on how machine-generated it looks and recognises
 * the common kinds of filler, so that only credible values are reported.
 */
final class Entropy {

    /** A label ("secret", "uncertain", "weak", "benign", "placeholder") and a score in 0..1. */
    record Verdict(String label, double score) {
    }

    private Entropy() {
    }

    // ── placeholders ─────────────────────────────────────────────────────────

    private static final String WORDS =
            "your my the some a an insert enter put add replace change example sample dummy fake test testing "
                    + "demo placeholder redacted removed hidden masked secret password passwd token apikey key value "
                    + "string none null nil undefined true false todo tbd fixme changeme changeit default empty foo bar "
                    + "baz xxx here own real actual api access private auth client pass id goes this me it name user "
                    + "username not set unset required optional go new old confirm current repeat again type field";
    private static final Pattern PLACEHOLDER;
    private static final Pattern FILLER = Py.rxi(
            "^(?:x{4,}|\\*{3,}|\\.{3,}|-{3,}|_{3,}|#{3,}|0{6,}|1234567890?|123456(?:78)?|abc(?:d(?:e(?:f\\w*)?)?)?(?:123\\w*)?"
                    + "|qwerty\\w*|asdf\\w*|password\\d*|letmein\\d*)$");
    private static final Pattern TEMPLATE = Py.rxi(
            "^<[^>]*>$|^\\[[^\\]]*\\]$|\\{\\{.*\\}\\}|\\$\\{[^}]*\\}|^\\$[A-Za-z_]\\w*$|^%[A-Za-z_]\\w*%$"
                    + "|^\\{[A-Za-z_][\\w.]*\\}$|^:[A-Za-z_]\\w*$|^__[A-Z_]+__$"
                    + "|^(?:process\\.env|import\\.meta\\.env|window\\.|env\\.)");
    private static final String[] HINTS = {"example", "placeholder", "changeme", "dummy", "redacted", "your_", "your-",
            "<your", "xxxxx", "*****"};
    /** Two readings of digits written for letters: 1 as "i", and 1 as "l". */
    private static final String LEET_FROM = "013457@$";
    private static final String[] LEET_TO = {"oieastas", "oleastas"};

    static {
        // longest word first, so that "password" is not read as "pass" + "word"
        TreeSet<String> words = new TreeSet<>(Comparator.comparingInt(String::length).reversed().thenComparing(Comparator.naturalOrder()));
        words.addAll(List.of(WORDS.split(" ")));
        String alt = String.join("|", words);
        // possessive quantifiers: linear time on any input
        PLACEHOLDER = Py.rxi("^(?:" + alt + ")(?:[\\W_]*+(?:" + alt + "|\\d{1,4}+(?!\\d)))*+[\\W_]*+$");
    }

    static boolean isPlaceholder(String value) {
        String v = Py.strip(Py.strip(value == null ? "" : value), "\"'`");
        if (v.isEmpty()) {
            return true;
        }
        String low = Py.lower(v);
        if (Py.startsWith(FILLER, v) || Py.startsWith(PLACEHOLDER, v) || Py.found(TEMPLATE, v)) {
            return true;
        }
        for (String hint : HINTS) {
            if (low.contains(hint)) {
                return true;
            }
        }
        if (v.length() >= 4 && distinct(low) <= 2) {
            return true;
        }
        if (v.length() <= 24 && containsAny(v, LEET_FROM)) {
            for (String reading : LEET_TO) {
                StringBuilder plain = new StringBuilder(low.length());
                for (int i = 0; i < low.length(); i++) {
                    int at = LEET_FROM.indexOf(low.charAt(i));
                    plain.append(at < 0 ? low.charAt(i) : reading.charAt(at));
                }
                if (Py.startsWith(PLACEHOLDER, plain.toString()) || Py.startsWith(FILLER, plain.toString())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static int distinct(String s) {
        Set<Integer> seen = new HashSet<>();
        s.codePoints().forEach(seen::add);
        return seen.size();
    }

    private static boolean containsAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    }

    // ── language model ───────────────────────────────────────────────────────

    /**
     * The most frequent English letter bigrams: identifiers and prose hit this
     * table about 85% of the time, uniformly random letters about 34%.
     */
    private static final Set<String> BIGRAMS = Set.of((
            "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me "
                    + "de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot "
                    + "il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai "
                    + "sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag "
                    + "if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba "
                    + "ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki "
                    + "rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc oa dd nf nk ok nn ft sk sy lf ps nv sq eq "
                    + "ws ks aw ze iz az gs ja jo je ju ya xt xp").split(" "));
    private static final Pattern ALPHA_RUN = Py.rx("[A-Za-z]{3,}");

    /** 0..1 — how much the token reads like words rather than random characters. */
    static double wordiness(String token) {
        if (token == null || token.isEmpty()) {
            return 0.0;
        }
        List<String> runs = new ArrayList<>();
        Matcher m = ALPHA_RUN.matcher(token);
        while (m.find()) {
            runs.add(m.group());
        }
        if (runs.isEmpty()) {
            return 0.0;
        }
        int covered = 0, hits = 0, total = 0, flips = 0;
        for (String run : runs) {
            covered += run.length();
            String low = Py.lower(run);
            for (int i = 0; i < low.length() - 1; i++) {
                total++;
                if (BIGRAMS.contains(low.substring(i, i + 2))) {
                    hits++;
                }
                if (Character.isUpperCase(run.charAt(i)) != Character.isUpperCase(run.charAt(i + 1))) {
                    flips++;
                }
            }
        }
        if (total == 0) {
            return 0.0;
        }
        double lang = Math.max(0.0, Math.min(1.0, ((double) hits / total - 0.38) / 0.42));
        double casePenalty = Math.max(0.0, 1.0 - Math.max(0.0, (double) flips / total - 0.22) * 2.5);
        return Py.round(lang * ((double) covered / token.codePointCount(0, token.length())) * casePenalty, 3);
    }

    static double shannon(String s) {
        if (s.isEmpty()) {
            return 0.0;
        }
        Map<Integer, Integer> counts = new LinkedHashMap<>();
        int n = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            counts.merge(cp, 1, Integer::sum);
            i += Character.charCount(cp);
            n++;
        }
        double sum = 0.0;
        for (int k : counts.values()) {
            double share = (double) k / n;
            sum += share * Py.log2(share);
        }
        return -sum;
    }

    private static int charClass(char c) {
        return Character.isLowerCase(c) ? 0 : Character.isUpperCase(c) ? 1 : Character.isDigit(c) ? 2 : 3;
    }

    private static final Pattern HEX = Py.rx("[0-9a-fA-F]+");
    private static final Pattern BASE64ISH = Py.rx("[A-Za-z0-9+/=_\\-]+");

    /** 0..1 — how machine-generated the token looks. */
    static double randomness(String token) {
        int n = token.length();
        if (n < 6) {
            return 0.0;
        }
        int alphabet = Py.matches(HEX, token) ? 16 : Py.matches(BASE64ISH, token) ? 64 : 94;
        double scale = Py.log2(Math.min(n, alphabet));
        double norm = Math.min(shannon(token) / (scale == 0.0 ? 1.0 : scale), 1.0);
        norm = Math.max(0.0, Math.min(1.0, (norm - 0.60) / 0.35));
        int changes = 0;
        for (int i = 0; i < n - 1; i++) {
            if (charClass(token.charAt(i)) != charClass(token.charAt(i + 1))) {
                changes++;
            }
        }
        double trans = (double) changes / (n - 1);
        return Py.round(0.40 * norm + 0.35 * (1.0 - wordiness(token)) + 0.25 * Math.min(trans / 0.45, 1.0), 3);
    }

    // ── benign shapes ────────────────────────────────────────────────────────

    private static final Pattern[] BENIGN = {
            Py.rx("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),          // uuid
            Py.rxi("^(?:sha(?:1|256|384|512)|md5)[-:=]"),                                                    // integrity
            Py.rx("^[+-]?[\\d.,_]+(?:e[+-]?\\d+)?[a-zA-Z%]{0,3}$"),                                          // number / unit
            Py.rx("^[v^~<>=]*\\d+(?:\\.\\d+){1,3}(?:[-+.][\\w.]+)*$"),                                       // version
            Py.rx("^\\d{4}-\\d{2}-\\d{2}(?:[T ]\\d{2}:\\d{2}(?::\\d{2})?(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?)?$"),   // date
            Py.rxi("^(?:[a-z][a-z0-9+.\\-]*:)?//[^\\s:@/]+(?::\\d+)?(?:[/?#]\\S*)?$"),                       // url, no creds
            Py.rxi("^data:[\\w/+.\\-]+[;,]"),                                                                // data uri
            Py.rx("^#[0-9a-fA-F]{3,8}$"),                                                                    // colour
            Py.rxi("^(?:[A-Za-z]:)?[\\w.\\-@~/\\\\]*\\.(?:js|mjs|css|map|json|html?|png|jpe?g|gif|svg|ico|webp|woff2?|ttf)$"),
            Py.rx("^[MmLlHhVvCcSsQqTtAaZz0-9\\s,.\\-]+$"),                                                   // svg path data
            Py.rx("^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"),                                                        // CONSTANT_NAME
    };
    /** kebab / snake / dotted / event:name — benign only when it also reads like words. */
    private static final Pattern IDENTIFIERISH = Py.rx("^[A-Za-z][A-Za-z0-9]*(?:[-_.:/][A-Za-z0-9]+)+$");
    private static final Pattern LONG_HEX = Py.rx("[0-9a-fA-F]{16,}");
    private static final Pattern DIGIT_OR_SYMBOL = Py.rx("[\\d!@#$%^&*+=/\\\\|~?]");

    static boolean hasDigitOrSymbol(String v) {
        return Py.found(DIGIT_OR_SYMBOL, v);
    }

    /** `strongKey`: the value sits under an unambiguous secret-bearing name. */
    static Verdict classify(String value, boolean strongKey) {
        String v = Py.strip(value == null ? "" : value);
        if (v.isEmpty() || isPlaceholder(v)) {
            return new Verdict("placeholder", 0.0);
        }
        int spaces = 0;
        for (int i = 0; i < v.length(); i++) {
            if (v.charAt(i) == ' ') {
                spaces++;
            }
        }
        if (spaces > 0 && (spaces >= 2 || !strongKey)) {
            return new Verdict("benign", 0.05);             // prose / label
        }
        if (!strongKey && Py.matches(LONG_HEX, v)) {
            return new Verdict("benign", 0.15);             // digest / id with no secret-bearing name
        }
        double words = wordiness(v);
        for (Pattern shape : BENIGN) {
            if (Py.startsWith(shape, v)) {
                return new Verdict("benign", 0.05);
            }
        }
        if (words >= 0.45 && Py.startsWith(IDENTIFIERISH, v)) {
            return new Verdict("benign", 0.06);
        }
        if (!hasDigitOrSymbol(v) && (!Py.isAscii(v) || words >= 0.45)) {
            return new Verdict("benign", 0.08);             // a word, a label, a translation, an identifier
        }
        double score = randomness(v);
        if (v.length() < 12) {
            score -= 0.25;
        } else if (v.length() >= 32) {
            score += 0.05;
        }
        if (strongKey) {
            score += 0.22;
        }
        score = Py.round(Math.max(0.0, Math.min(1.0, score)), 3);
        return new Verdict(score >= 0.62 ? "secret" : score >= 0.50 ? "uncertain" : "weak", score);
    }
}
