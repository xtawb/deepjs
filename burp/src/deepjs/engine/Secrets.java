package deepjs.engine;

import static deepjs.engine.Lexer.ID;
import static deepjs.engine.Lexer.PUNC;
import static deepjs.engine.Lexer.STR;
import static deepjs.engine.Lexer.TPL;

import deepjs.engine.Entropy.Verdict;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Credentials in front-end code.
 *
 * Two kinds of evidence: a value in a recognised format (an AWS key ID, a
 * GitHub token, a JWT), or a credible value assigned to a secret-bearing name
 * (`clientSecret`, `X-Api-Key`). Keys that are public by design — a Stripe
 * publishable key, a Firebase web configuration, a Supabase anon key — are
 * reported as such and never as leaks. Tokens are decoded, never used.
 */
final class Secrets {

    /** One finding. `value` is the raw value; show {@link #masked()} unless the user asked to see it. */
    static final class Secret {
        final String kind;
        final String severity;              // critical | high | medium | low | info
        final double confidence;
        final String value;
        final String key;                   // the property / variable / header the value belongs to
        final String file;
        final int line;
        final String note;
        final boolean isPublic;             // public by design, not a leak

        Secret(String kind, String severity, double confidence, String value, String key, String file, int line,
               String note, boolean isPublic) {
            this.kind = kind;
            this.severity = severity;
            this.confidence = confidence;
            this.value = value;
            this.key = key;
            this.file = file;
            this.line = line;
            this.note = note;
            this.isPublic = isPublic;
        }

        String masked() {
            int n = value.codePointCount(0, value.length());
            if (n <= 8) {
                return head(2) + "…";
            }
            if (n <= 20) {
                return head(4) + "…" + tail(2);
            }
            return head(8) + "…" + tail(4);
        }

        private String head(int codePoints) {
            return value.substring(0, value.offsetByCodePoints(0, Math.min(codePoints, value.codePointCount(0, value.length()))));
        }

        private String tail(int codePoints) {
            return value.substring(value.offsetByCodePoints(value.length(), -codePoints));
        }

        /** Stable across runs and safe to store: the first 16 hex digits of the value's SHA-256. */
        String fingerprint() {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
                StringBuilder hex = new StringBuilder(16);
                for (int i = 0; i < 8; i++) {
                    hex.append(String.format("%02x", digest[i]));
                }
                return hex.toString();
            } catch (NoSuchAlgorithmException impossible) {
                throw new IllegalStateException(impossible);
            }
        }
    }

    private record Typed(String kind, Pattern pattern, String severity, boolean isPublic, String note) {
    }

    private record Hit(String kind, String value, String severity, boolean isPublic, String note) {
    }

    /** Longer strings are data, not credentials. */
    private static final int MAX_SCANNED = 8192;

    private Secrets() {
    }

    // ── typed patterns ───────────────────────────────────────────────────────

    private static final String B = "(?<![A-Za-z0-9_\\-])";
    private static final String E = "(?![A-Za-z0-9_\\-])";

    private static final List<Typed> TYPED = List.of(
            typed("AWS_ACCESS_KEY", "\\b((?:AKIA|ASIA)[0-9A-Z]{16})\\b", "critical", false,
                    "AWS access key ID in front-end code. Long-lived keys must never ship to a browser."),
            typed("GOOGLE_API_KEY", B + "(AIza[0-9A-Za-z_\\-]{35})" + E, "low", true,
                    "Google API key. Normal in web apps — confirm it is restricted by HTTP referrer and to the APIs it needs."),
            typed("GOOGLE_OAUTH_CLIENT_SECRET", B + "(GOCSPX-[A-Za-z0-9_\\-]{28})" + E, "high", false,
                    "Google OAuth client secret. Web clients must not embed it."),
            typed("GOOGLE_OAUTH_ACCESS_TOKEN", B + "(ya29\\.[0-9A-Za-z_\\-]{40,})", "high", false, "Google OAuth access token."),
            typed("FIREBASE_FCM_SERVER_KEY", B + "(AAAA[A-Za-z0-9_\\-]{7}:[A-Za-z0-9_\\-]{140})" + E, "high", false,
                    "Firebase Cloud Messaging server key — allows sending push notifications as the app."),
            typed("GITHUB_TOKEN", B + "(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})" + E, "critical", false,
                    "GitHub token."),
            typed("GITLAB_TOKEN", B + "(glpat-[A-Za-z0-9_\\-]{20})" + E, "critical", false, "GitLab personal access token."),
            typed("SLACK_TOKEN", B + "(xox[abeposr]-(?:[0-9A-Za-z]+-)+[0-9A-Za-z]{6,})" + E, "high", false, "Slack token."),
            typed("SLACK_WEBHOOK", "(https://hooks\\.slack\\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})", "medium", false,
                    "Slack incoming webhook — anyone with the URL can post to the channel."),
            typed("DISCORD_WEBHOOK", "(https://(?:ptb\\.|canary\\.)?discord(?:app)?\\.com/api/webhooks/\\d{15,22}/[A-Za-z0-9_\\-]{40,})",
                    "medium", false, "Discord webhook URL."),
            typed("STRIPE_SECRET_KEY", B + "((?:sk|rk)_live_[0-9A-Za-z]{20,})" + E, "critical", false, "Stripe live secret key."),
            typed("STRIPE_TEST_SECRET_KEY", B + "((?:sk|rk)_test_[0-9A-Za-z]{20,})" + E, "low", false, "Stripe test-mode secret key."),
            typed("STRIPE_PUBLISHABLE_KEY", B + "(pk_(?:live|test)_[0-9A-Za-z]{20,})" + E, "info", true,
                    "Stripe publishable key — public by design."),
            typed("OPENAI_API_KEY", B + "(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})" + E,
                    "critical", false, "OpenAI API key in front-end code — usable by anyone who loads the page."),
            typed("ANTHROPIC_API_KEY", B + "(sk-ant-[A-Za-z0-9_\\-]{40,})" + E, "critical", false,
                    "Anthropic API key in front-end code — usable by anyone who loads the page."),
            typed("SENDGRID_API_KEY", B + "(SG\\.[A-Za-z0-9_\\-]{22}\\.[A-Za-z0-9_\\-]{43})" + E, "high", false, "SendGrid API key."),
            typed("MAILCHIMP_API_KEY", B + "([0-9a-f]{32}-us\\d{1,2})" + E, "high", false, "Mailchimp API key."),
            typed("TWILIO_API_KEY", "\\b(SK[0-9a-f]{32})\\b", "high", false, "Twilio API key SID (check for its secret nearby)."),
            typed("NPM_TOKEN", "\\b(npm_[A-Za-z0-9]{36})\\b", "high", false, "npm access token."),
            typed("HUGGINGFACE_TOKEN", "\\b(hf_[A-Za-z0-9]{34,})\\b", "high", false, "Hugging Face token."),
            typed("DIGITALOCEAN_TOKEN", "\\b(do[opr]_v1_[a-f0-9]{64})\\b", "critical", false, "DigitalOcean token."),
            typed("SHOPIFY_TOKEN", "\\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\\b", "high", false, "Shopify access token."),
            typed("TELEGRAM_BOT_TOKEN", "\\b(\\d{8,10}:AA[A-Za-z0-9_\\-]{33})" + E, "high", false, "Telegram bot token."),
            typed("SQUARE_TOKEN", B + "(sq0(?:atp|csp)-[A-Za-z0-9_\\-]{22,43})" + E, "high", false, "Square token."),
            typed("BRAINTREE_TOKEN", "(access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32})", "critical", false,
                    "PayPal / Braintree production access token."),
            typed("FACEBOOK_ACCESS_TOKEN", "\\b(EAA[A-Za-z0-9]{80,})\\b", "medium", false, "Facebook access token."),
            typed("MAPBOX_SECRET_TOKEN", B + "(sk\\.eyJ[A-Za-z0-9_\\-]{20,}\\.[A-Za-z0-9_\\-]{10,})", "high", false, "Mapbox secret token."),
            typed("MAPBOX_PUBLIC_TOKEN", B + "(pk\\.eyJ[A-Za-z0-9_\\-]{20,}\\.[A-Za-z0-9_\\-]{10,})", "info", true,
                    "Mapbox public token — public by design; confirm URL restrictions."),
            typed("SENTRY_DSN", "(https?://[0-9a-f]{32}@[\\w.\\-]*sentry[\\w.\\-]*/\\d+)", "info", true, "Sentry DSN — public by design."),
            typed("RECAPTCHA_KEY", B + "(6L[0-9A-Za-z_\\-]{38})" + E, "info", true,
                    "reCAPTCHA key. Site keys are public; a *secret* key has the same shape — check which one this is."),
            typed("PRIVATE_KEY", "(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)", "critical", false, "Private key material."),
            typedIgnoringCase("AZURE_STORAGE_KEY", "AccountKey=([A-Za-z0-9+/=]{80,})", "critical", false, "Azure storage account key."),
            typed("URL_CREDENTIALS", "\\b[a-z][a-z0-9+.\\-]{1,12}://[^/\\s:@'\"<>{}]{1,64}:([^/\\s:@'\"<>{}]{3,128})@[\\w.\\-]+", "high", false,
                    "URL with an embedded password."),
            typedIgnoringCase("BEARER_TOKEN", "^bearer\\s+([A-Za-z0-9_\\-.~+/=]{20,})$", "high", false, "Hardcoded bearer token."),
            typedIgnoringCase("BASIC_AUTH", "^basic\\s+([A-Za-z0-9+/]{12,}={0,2})$", "high", false, "Hardcoded HTTP Basic credentials."));

    private static Typed typed(String kind, String pattern, String severity, boolean isPublic, String note) {
        return new Typed(kind, Py.rx(pattern), severity, isPublic, note);
    }

    private static Typed typedIgnoringCase(String kind, String pattern, String severity, boolean isPublic, String note) {
        return new Typed(kind, Py.rxi(pattern), severity, isPublic, note);
    }

    /** One cheap test decides whether a string is worth running the list above on. */
    private static final Pattern PREFILTER = Py.rx(
            "AKIA|ASIA|AIza|GOCSPX-|ya29\\.|AAAA[A-Za-z0-9_\\-]{7}:|gh[pousr]_|github_pat_|glpat-|xox[abeposr]-|hooks\\.slack\\.com"
                    + "|discord(?:app)?\\.com/api/webhooks|[sr]k_(?:live|test)_|pk_(?:live|test)_|sk-(?:proj|svcacct|admin|ant)-|T3BlbkFJ"
                    + "|SG\\.|-us\\d{1,2}\\b|SK[0-9a-f]{32}|npm_|hf_|do[opr]_v1_|shp(?:at|ca|pa|ss)_|:AA[A-Za-z0-9_\\-]{33}|sq0|access_token\\$"
                    + "|EAA[A-Za-z0-9]{20}|[ps]k\\.eyJ|sentry|6L[0-9A-Za-z_\\-]{38}|-----BEGIN|AccountKey=|://[^/\\s:@]{1,64}:[^/\\s@]{3,}@"
                    + "|^[Bb]earer\\s|^[Bb]asic\\s|eyJ[A-Za-z0-9_\\-]{8,}\\.eyJ");
    private static final Pattern JWT = Py.rx("\\b(eyJ[A-Za-z0-9_\\-]{8,})\\.(eyJ[A-Za-z0-9_\\-]{8,})\\.([A-Za-z0-9_\\-]*)");

    // ── key-name semantics (camelCase / kebab-case normalised to snake_case) ──

    private static final Pattern STRONG_KEY = Py.rx(
            "(?:^|_)(?:pass(?:word|wd|phrase)?|pwd|secret|api_?secret|client_?secret|app_?secret|consumer_?secret|"
                    + "api_?key|apikey|x_api_key|access_?token|auth_?token|bearer_?token|refresh_?token|private_?key|secret_?key|"
                    + "signing_?key|encryption_?key|master_?key|authorization|aws_?secret\\w*|access_?key_?secret|credentials?)(?:_|$|\\d)");
    private static final Pattern WEAK_KEY = Py.rx(
            "(?:^|_)(?:token|auth|jwt|bearer|sas|salt|hmac|signature|license_?key|access_?key)(?:_|$|\\d)");
    private static final Pattern NEGATIVE_KEY = Py.rx(
            "public|publishable|(?:^|_)pub(?:_|$)|site_?key|client_?id|app_?id|project_?id|sender_?id"
                    + "|measurement|tracking|analytics|(?:^|_)dsn(?:_|$)|(?:^|_)anon(?:_|$)"
                    + "|(?:storage|cache|query|sort|primary|foreign|partition|row|map|object|translation|i18n|locale|session|cookie"
                    + "|local_storage|header|param|field|form|input|test|data|react|event|route|error|message|option)_?(?:key|token)s?(?:_|$)"
                    + "|(?:key|token|password|secret|auth)_(?:name|id|ids|type|url|uri|endpoint|path|file|field|label|title|placeholder"
                    + "|hint|prefix|suffix|header|param|key|length|len|min\\w*|max\\w*|regex|pattern|policy|strength|expir\\w*|ttl"
                    + "|required|enabled|error|message|msg|text|input|form|reset\\w*|confirm\\w*|changed?|visible|mask|icon|class|style)"
                    + "|(?:^|_)(?:next|prev|previous|page|continuation|csrf|xsrf|nonce)_?(?:page_?)?token"
                    + "|(?:max|min|num|total|input|output|prompt|completion)_tokens?|tokeniz"
                    + "|(?:^|_)token_(?:data|prec|table|groups?)$"
                    + "|(?:^|_)(?:label|title|placeholder|hint|help|text|message|msg|description|desc|name|type|regex|pattern|format"
                    + "|selector|class_?name|style|icon|event|action|route|path|url|uri|endpoint|href|src|error|warning)$"
                    + "|keyword|keyboard|keyframe|hotkey|passive|bypass|compass");
    private static final Set<String> FIREBASE_SIBLINGS = Set.of("authDomain", "projectId", "storageBucket", "messagingSenderId",
            "databaseURL", "appId");
    private static final Pattern CAMEL_BOUNDARY = Py.rx("(?<=[a-z0-9])(?=[A-Z])");
    private static final Pattern SEPARATORS = Py.rx("[\\s.\\-]+");
    private static final Pattern PASSWORD_KEY = Py.rx("(?:^|_)(?:pass(?:word|wd|phrase)?|pwd)(?:_|$|\\d)");
    private static final Pattern SELF_DESCRIBING = Py.rxi(
            "pass|pwd|secret|token|key|credential|login|sign|auth|user|enter|type|input|field|label|"
                    + "placeholder|required|invalid|error|confirm|forgot|reset|change|show|hide|strength");
    private static final Pattern LETTERS_ONLY = Py.rx("[A-Za-z]{10,48}");
    private static final Pattern CAPITALISED_WORD = Py.rx("[A-Z][a-z]+");
    private static final Pattern AUTH_SCHEME = Py.rxi("^(?:Bearer|Token|Basic|ApiKey)\\s+");
    private static final Pattern FUNCTION_SIGNATURE = Py.rx("[A-Za-z_$][\\w$]*\\([\\w\\[\\], ]*\\)");
    private static final Pattern HEX32 = Py.rx("[0-9a-f]{32}");
    private static final Pattern HEX = Py.rx("[0-9a-fA-F]+");

    static String normaliseKey(String key) {
        String k = CAMEL_BOUNDARY.matcher(key == null ? "" : key).replaceAll("_");
        return Py.strip(Py.lower(SEPARATORS.matcher(k).replaceAll("_")), "_");
    }

    /** 2 strong secret-bearing name, 1 weak, 0 neutral, -1 reference / label / public. */
    static int keyStrength(String key) {
        String k = normaliseKey(key);
        if (k.isEmpty()) {
            return 0;
        }
        return Py.found(NEGATIVE_KEY, k) ? -1 : Py.found(STRONG_KEY, k) ? 2 : Py.found(WEAK_KEY, k) ? 1 : 0;
    }

    // ── JWT ──────────────────────────────────────────────────────────────────

    private static Map<String, Object> decodeSegment(String segment) {
        try {
            String text = new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
            return Json.object(Json.parse(text));
        } catch (IllegalArgumentException | Json.Malformed notJson) {
            return null;
        }
    }

    /** A claim that is a string; "" for a missing claim or one of another type. */
    private static String claim(Map<String, Object> object, String name) {
        return object.get(name) instanceof String text ? text : "";
    }

    /** What kind of JWT `token` holds, or null when it holds none. The token is decoded, not verified or used. */
    static Hit inspectJwt(String token, double now) {
        Matcher m = JWT.matcher(token == null ? "" : token);
        if (!m.find()) {
            return null;
        }
        Map<String, Object> header = decodeSegment(m.group(1)), payload = decodeSegment(m.group(2));
        if (header == null || payload == null || !(header.containsKey("alg") || header.containsKey("typ"))) {
            return null;
        }
        String role = claim(payload, "role");
        String iss = claim(payload, "iss");
        Object rawExp = payload.get("exp");
        Double exp = rawExp instanceof Long || rawExp instanceof Double ? ((Number) rawExp).doubleValue() : null;
        String when = "";
        if (exp != null && exp != 0.0) {
            try {
                when = Instant.ofEpochSecond((long) Math.floor(exp)).atOffset(ZoneOffset.UTC).toLocalDate().toString();
            } catch (DateTimeException | ArithmeticException outOfRange) {
                when = "";
            }
        }
        String issuer = iss.isEmpty() ? "" : " (issuer " + iss.substring(0, Math.min(60, iss.length())) + ")";
        String value = m.group(0);

        if (iss.contains("supabase") || (payload.containsKey("ref") && Py.in(role, "anon", "service_role"))) {
            if (role.equals("service_role")) {
                return new Hit("SUPABASE_SERVICE_ROLE_KEY", value, "critical", false,
                        "Supabase service_role key — bypasses Row Level Security. Must never reach a browser.");
            }
            return new Hit("SUPABASE_ANON_KEY", value, "info", true,
                    "Supabase anon key — public by design; data protection depends on Row Level Security policies.");
        }
        if (Py.lower(claim(header, "alg")).equals("none") || m.group(3).isEmpty()) {
            return new Hit("JWT_UNSIGNED", value, "medium", false, "Hardcoded JWT with no signature (alg=none).");
        }
        if (exp != null && exp < now) {
            return new Hit("JWT_EXPIRED", value, "low", false, "Hardcoded JWT, expired " + when + ".");
        }
        if (exp == null) {
            return new Hit("JWT_HARDCODED", value, "high", false, "Hardcoded JWT with no expiry" + issuer + ".");
        }
        return new Hit("JWT_HARDCODED", value, "medium", false, "Hardcoded JWT, valid until " + when + issuer + ".");
    }

    // ── scanning ─────────────────────────────────────────────────────────────

    /** Every typed-pattern hit in `text`. */
    private static List<Hit> typedMatches(String text) {
        List<Hit> out = new ArrayList<>();
        if (text.length() < 12 || !Py.found(PREFILTER, text)) {
            return out;
        }
        boolean mapbox = false;
        for (Typed typed : TYPED) {
            Matcher m = typed.pattern().matcher(text);
            String note = typed.note();
            while (m.find()) {
                String value = m.group(1);
                if (!typed.kind().equals("PRIVATE_KEY") && Entropy.isPlaceholder(value)) {
                    continue;
                }
                if (typed.kind().equals("BASIC_AUTH")) {
                    String decoded;
                    try {
                        decoded = new String(Base64.getDecoder().decode(padded(value)), StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException notBase64) {
                        continue;
                    }
                    int colon = decoded.indexOf(':');
                    if (colon < 0 || Entropy.isPlaceholder(decoded.substring(colon + 1))) {
                        continue;
                    }
                    note = "Hardcoded HTTP Basic credentials for user '" + decoded.substring(0, Math.min(colon, 40)) + "'.";
                }
                out.add(new Hit(typed.kind(), value, typed.severity(), typed.isPublic(), note));
                mapbox |= typed.kind().startsWith("MAPBOX");
            }
        }
        Hit jwt = inspectJwt(text, System.currentTimeMillis() / 1000.0);
        if (jwt != null && !mapbox) {
            out.add(jwt);
        }
        return out;
    }

    private static String padded(String base64) {
        String unpadded = Py.rstrip(base64, "=");
        return unpadded + "=".repeat((4 - unpadded.length() % 4) % 4);
    }

    /** The property / variable / header name the literal at token `i` belongs to. */
    private static String keyContext(Program p, int i) {
        if (i >= 2 && p.kind[i - 1] == PUNC) {
            String op = (String) p.value[i - 1];
            byte k = p.kind[i - 2];
            if ((op.equals(":") || op.equals("=")) && (k == ID || k == STR)) {
                return (String) p.value[i - 2];
            }
            // setRequestHeader("X-Api-Key", "…")  /  headers.append("Authorization", "…")
            if (op.equals(",") && k == STR && i >= 3 && p.isPunc(i - 3, "(")) {
                return (String) p.value[i - 2];
            }
        }
        return "";
    }

    private static boolean nearFirebase(Program p, int i) {
        for (int k = Math.max(0, i - 40), hi = Math.min(p.n, i + 40); k < hi; k++) {
            if ((p.kind[k] == ID || p.kind[k] == STR) && FIREBASE_SIBLINGS.contains((String) p.value[k])) {
                return true;
            }
        }
        return false;
    }

    /** One token of three or more capitalised words that does not describe a form field. */
    private static boolean passphraseLike(String value) {
        if (!Py.matches(LETTERS_ONLY, value) || Py.found(SELF_DESCRIBING, value)) {
            return false;
        }
        int words = 0;
        for (Matcher m = CAPITALISED_WORD.matcher(value); m.find(); ) {
            words++;
        }
        return words >= 3;
    }

    private static boolean nearAlgolia(Program p, int i) {
        boolean app = false, index = false;
        for (int k = Math.max(0, i - 14), hi = Math.min(p.n, i + 14); k < hi; k++) {
            if (p.kind[k] == ID || p.kind[k] == STR) {
                String name = Py.lower((String) p.value[k]);
                app |= Py.in(name, "appid", "applicationid", "algolia_app_id");
                index |= Py.in(name, "indexname", "index_name");
            }
        }
        return app && index;
    }

    private static String truncated(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

    /** Find credentials in one tokenized file. `entropy`: also report unlabelled random-looking strings. */
    @SuppressWarnings("unchecked")
    static List<Secret> scan(Program p, String file, boolean entropy) {
        List<Secret> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (int i = 0; i < p.n; i++) {
            String text;
            if (p.kind[i] == STR) {
                text = (String) p.value[i];
            } else if (p.kind[i] == TPL) {
                List<Program.Part> parts = p.templateParts(i);
                if (Program.isStatic(parts)) {
                    text = Program.render(parts);
                } else {
                    StringBuilder b = new StringBuilder();
                    for (Object segment : (List<Object>) p.value[i]) {
                        if (segment instanceof String s) {
                            b.append(s);
                        }
                    }
                    text = b.toString();
                }
            } else {
                continue;
            }
            if (text.length() < 8 || text.length() > MAX_SCANNED) {
                continue;
            }
            String key = keyContext(p, i);

            List<Hit> typed = typedMatches(text);
            for (Hit hit : typed) {
                String kind = hit.kind(), severity = hit.severity(), note = hit.note();
                if (kind.equals("GOOGLE_API_KEY") && nearFirebase(p, i)) {
                    kind = "FIREBASE_WEB_CONFIG";
                    severity = "info";
                    note = "Firebase web API key — public by design. Security depends on Firebase Security Rules "
                            + "and App Check, so review those.";
                }
                if (kind.equals("TWILIO_API_KEY")) {
                    String around = p.lex.src.substring(Math.max(0, p.lex.start[i] - 300), Math.min(p.lex.src.length(), p.lex.end[i] + 300));
                    if (!Py.lower(around).contains("twilio")) {
                        continue;
                    }
                }
                add(out, seen, new Secret(kind, severity, hit.isPublic() ? 0.9 : 0.95, hit.value(), key, file, p.line(i), note, hit.isPublic()));
            }
            if (!typed.isEmpty()) {
                continue;
            }

            // a credible value under a secret-bearing name
            int strength = key.isEmpty() ? 0 : keyStrength(key);
            if (strength <= 0 && !entropy) {
                continue;
            }
            String value = AUTH_SCHEME.matcher(Py.strip(text)).replaceFirst("");
            if (value.length() < 8 || value.length() > 512 || value.indexOf('\n') >= 0) {
                continue;
            }
            if (Py.matches(FUNCTION_SIGNATURE, value)) {
                continue;                                   // OffchainLookup(address,string[],bytes)
            }
            String shownKey = truncated(key, 60);
            Verdict verdict = Entropy.classify(value, strength == 2);
            String label = verdict.label();
            double score = verdict.score();
            if (label.equals("benign") && strength == 2 && Py.found(PASSWORD_KEY, normaliseKey(key)) && passphraseLike(value)) {
                // testingPassword = "IamUsedForTesting": words, but written like a password, under a password's name
                add(out, seen, new Secret("HARDCODED_PASSWORD", "medium", 0.5, value, key, file, p.line(i),
                        "Passphrase-like value assigned to '" + shownKey + "' — often a default or test account's password.", false));
                continue;
            }
            if (label.equals("placeholder") || label.equals("benign")) {
                continue;
            }
            if (Py.matches(HEX32, value) && nearAlgolia(p, i)) {
                // {appId, apiKey, indexName}: what every site with Algolia search ships to the browser
                add(out, seen, new Secret("ALGOLIA_SEARCH_KEY", "info", 0.8, value, key, file, p.line(i),
                        "Algolia key next to appId / indexName — a search-only key is public by design. An admin key "
                                + "has the same shape: check its ACL in the Algolia dashboard.", true));
                continue;
            }
            if (strength == 2) {
                if (label.equals("weak") && !Entropy.hasDigitOrSymbol(value)) {
                    continue;
                }
                double confidence = 0.45 + 0.4 * score;
                add(out, seen, new Secret("HARDCODED_SECRET", confidence >= 0.72 ? "high" : "medium", Math.min(confidence, 0.92),
                        value, key, file, p.line(i), "Literal value assigned to '" + shownKey + "'.", false));
            } else if (strength == 1) {
                if (label.equals("secret")) {
                    add(out, seen, new Secret("HARDCODED_SECRET", "medium", 0.4 + 0.4 * score, value, key, file, p.line(i),
                            "Random-looking value assigned to '" + shownKey + "'.", false));
                }
            } else if (entropy && label.equals("secret") && value.length() >= 32 && value.length() <= 128 && strength == 0
                    && !Py.matches(HEX, value) && !isDigits(key)) {
                add(out, seen, new Secret("HIGH_ENTROPY_STRING", "low", 0.3 + 0.3 * score, value, key, file, p.line(i),
                        "Unlabelled random-looking string (enabled by --entropy; expect noise).", false));
            }
        }

        // comments survive in recovered sources and un-minified files
        for (int c = 0; c < p.lex.comments.size(); c++) {
            String comment = p.lex.comments.get(c);
            if (comment.length() < 12) {
                continue;
            }
            int line = p.lex.lineOf(p.lex.commentAt.get(c));
            // line by line, each bounded: a licence banner of megabytes costs what its lines cost
            List<String> rows = Py.split(comment, "\n");
            for (int r = 0; r < rows.size(); r++) {
                String row = rows.get(r);
                if (row.length() < 12) {
                    continue;
                }
                for (Hit hit : typedMatches(truncated(row, MAX_SCANNED))) {
                    add(out, seen, new Secret(hit.kind(), hit.severity(), 0.85, hit.value(), "(comment)", file, line + r,
                            hit.note(), hit.isPublic()));
                }
            }
        }
        return out;
    }

    private static void add(List<Secret> out, Set<String> seen, Secret s) {
        if (seen.add(s.kind + "\u0000" + s.value)) {
            out.add(s);
        }
    }

    private static boolean isDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
