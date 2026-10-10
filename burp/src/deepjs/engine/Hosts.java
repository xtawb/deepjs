package deepjs.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Every host the code mentions, sorted into what it means:
 *
 *   in-scope       a (sub)domain of the target
 *   cloud-storage  S3 / GCS / Azure Blob / Firebase / Spaces / R2 / OSS buckets
 *   internal       private addresses, localhost, *.internal / *.corp / *.local
 *   third-party    everything else
 *
 * Non-production markers (dev., staging., uat., …) are flagged on any class.
 */
final class Hosts {

    static final class Host {
        final String name;
        final String kind;
        final String service;               // the cloud provider, for cloud-storage
        final boolean nonProduction;
        final List<String> ports = new ArrayList<>();
        final List<String> files = new ArrayList<>();

        Host(String name, String kind, String service, boolean nonProduction) {
            this.name = name;
            this.kind = kind;
            this.service = service;
            this.nonProduction = nonProduction;
        }
    }

    private static final Pattern URL_HOST = Py.rx(
            "(?:(?:https?|wss?|ftp)://|(?<![\\w:/])//)"
                    + "((?:[A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?\\.){1,30}[A-Za-z]{2,24}|localhost|\\d{1,3}(?:\\.\\d{1,3}){3})"
                    + "(?::(\\d{2,5}))?");
    private static final Pattern BARE_HOST = Py.rx("^(?:[A-Za-z0-9](?:[A-Za-z0-9\\-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,24}$");

    /** Suffixes under which registrations happen one level deeper (enough for scoping). */
    private static final Set<String> TWO_LEVEL = Set.of((
            "co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.jp ne.jp or.jp co.kr co.in net.in org.in com.br com.mx "
                    + "com.ar com.tr com.sa com.eg com.sg com.my com.hk com.tw com.cn net.cn org.cn co.za co.il com.ua com.pl com.co "
                    + "com.pe com.ph com.pk com.ng co.id co.th com.vn github.io herokuapp.com vercel.app netlify.app pages.dev "
                    + "web.app firebaseapp.com azurewebsites.net cloudfront.net amazonaws.com appspot.com").split(" "));

    private static final String[] CLOUD_NAMES = {"aws-s3", "gcs", "firebase", "azure-blob", "do-spaces", "cloudflare-r2",
            "aliyun-oss", "backblaze-b2", "supabase"};
    private static final Pattern[] CLOUD = {
            Py.rx("(?:^|\\.)s3[.\\-][\\w.\\-]*amazonaws\\.com(?:\\.cn)?$|\\.s3\\.amazonaws\\.com$|^s3\\.amazonaws\\.com$"),
            Py.rx("(?:^|\\.)storage\\.googleapis\\.com$|(?:^|\\.)storage\\.cloud\\.google\\.com$"),
            Py.rx("\\.firebaseio\\.com$|^firebasestorage\\.googleapis\\.com$|\\.firebasedatabase\\.app$"),
            Py.rx("\\.(?:blob|file|dfs|table|queue)\\.core\\.windows\\.net$"),
            Py.rx("\\.digitaloceanspaces\\.com$"),
            Py.rx("\\.r2\\.cloudflarestorage\\.com$|\\.r2\\.dev$"),
            Py.rx("\\.oss-[\\w\\-]+\\.aliyuncs\\.com$"),
            Py.rx("\\.backblazeb2\\.com$"),
            Py.rx("\\.supabase\\.(?:co|in)$"),
    };
    private static final Pattern INTERNAL_SUFFIX = Py.rx("\\.(?:local|internal|intranet|corp|lan|home|localdomain|private|cluster\\.local|svc)$");
    private static final Pattern NON_PRODUCTION = Py.rxi(
            "(?:^|[.\\-])(?:dev|develop|development|staging|stage|stg|uat|qa|test|testing|sandbox|preprod|pre-prod|"
                    + "preview|beta|alpha|demo|int|integration|local)(?:[.\\-\\d]|$)");

    /** IPv4 networks that are not publicly routable: {network, prefix length}. */
    private static final int[][] PRIVATE_V4 = {
            {0x00000000, 8}, {0x0a000000, 8}, {0x7f000000, 8}, {0xa9fe0000, 16}, {0xac100000, 12}, {0xc0000000, 24},
            {0xc0000200, 24}, {0xc0a80000, 16}, {0xc6120000, 15}, {0xc6336400, 24}, {0xcb007100, 24}, {0xf0000000, 4},
    };

    Set<String> scope = new TreeSet<>();
    final Map<String, Host> hosts = new LinkedHashMap<>();

    /** Naive eTLD+1 — good enough to decide "same organisation". */
    static String registrable(String host) {
        host = Py.strip(Py.lower(host), ".");
        List<String> labels = Py.split(host, ".");
        int n = labels.size();
        if (n <= 2) {
            return host;
        }
        String lastTwo = labels.get(n - 2) + "." + labels.get(n - 1);
        return TWO_LEVEL.contains(lastTwo) ? labels.get(n - 3) + "." + lastTwo : lastTwo;
    }

    static boolean isPrivateIp(String host) {
        List<String> octets = Py.split(host, ".");
        if (octets.size() != 4) {
            return false;
        }
        int address = 0;
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3 || (octet.length() > 1 && octet.charAt(0) == '0')) {
                return false;
            }
            int v = 0;
            for (int i = 0; i < octet.length(); i++) {
                char c = octet.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
                v = v * 10 + (c - '0');
            }
            if (v > 255) {
                return false;
            }
            address = (address << 8) | v;
        }
        if (address == 0xc0000009 || address == 0xc000000a) {
            return false;                                   // 192.0.0.9 and .10 are globally reachable anycast
        }
        for (int[] network : PRIVATE_V4) {
            int mask = network[1] == 0 ? 0 : -1 << (32 - network[1]);
            if ((address & mask) == network[0]) {
                return true;
            }
        }
        return false;
    }

    static Host classify(String host, Set<String> scope) {
        String h = Py.strip(Py.lower(host), ".");
        boolean nonProduction = Py.found(NON_PRODUCTION, h);
        for (int i = 0; i < CLOUD.length; i++) {
            if (Py.found(CLOUD[i], h)) {
                return new Host(h, "cloud-storage", CLOUD_NAMES[i], nonProduction);
            }
        }
        if (h.equals("localhost") || isPrivateIp(h) || Py.found(INTERNAL_SUFFIX, h)) {
            return new Host(h, "internal", "", false);
        }
        String registered = registrable(h);
        for (String s : scope) {
            if (registered.equals(s) || h.equals(s) || h.endsWith("." + s)) {
                return new Host(h, "in-scope", "", nonProduction);
            }
        }
        return new Host(h, "third-party", "", nonProduction);
    }

    void add(String host, String file, String port) {
        String h = Py.strip(Py.lower(host), ".");
        if (h.isEmpty() || Py.found(Endpoints.NOISE_HOSTS, h)) {
            return;
        }
        Host entry = hosts.get(h);
        if (entry == null) {
            entry = classify(h, scope);
            hosts.put(h, entry);
        }
        if (port != null && !port.isEmpty() && !entry.ports.contains(port)) {
            entry.ports.add(port);
        }
        if (file != null && !file.isEmpty() && !entry.files.contains(file) && entry.files.size() < 5) {
            entry.files.add(file);
        }
    }

    /** Pull every host out of one string literal. */
    void feed(String text, String file) {
        if (text.contains("//")) {
            Matcher m = URL_HOST.matcher(text);
            while (m.find()) {
                add(m.group(1), file, m.group(2));
            }
        } else if (!scope.isEmpty() && text.length() < 254 && text.indexOf('.') >= 0 && Py.startsWith(BARE_HOST, text)) {
            // a bare hostname only counts when it belongs to the target
            String low = Py.lower(text);
            for (String s : scope) {
                if (low.equals(s) || low.endsWith("." + s)) {
                    add(text, file, null);
                    return;
                }
            }
        }
    }
}
