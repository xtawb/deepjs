package deepjs.burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.SwingUtilities;

/**
 * Exercises the extension without Burp: the protocol codec, the real engine
 * process started from the engine inside the built jar, the tab and its
 * models, the request skeletons sent to Repeater, and the extension class
 * itself against a mocked Burp API.
 *
 *   java -Ddeepjs.jar=<deepjs-burp.jar> -cp <classes>:<test-classes>:<montoya-api.jar> deepjs.burp.Harness [python…]
 *
 * Run it from a directory that has no `deepjs` package, so that the engine can
 * only come from the jar. Exits non-zero on the first failed check.
 */
public final class Harness {

    private static int checks;

    private static void check(boolean ok, String what) {
        checks++;
        if (!ok) {
            System.err.println("FAILED: " + what);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws Exception {
        // ── protocol codec ───────────────────────────────────────────────────
        String nasty = "a\tb\nc\\d\re";
        check(Worker.unesc(Worker.esc(nasty)).equals(nasty), "escape round trip");
        check(!Worker.esc(nasty).contains("\t") && !Worker.esc(nasty).contains("\n"), "escaped text has no separators");
        check(Worker.parse("E\tGET\ta\\tb\t").length == 4, "parse keeps empty trailing fields");
        check(Worker.splitCommand("python -m deepjs serve").equals(List.of("python", "-m", "deepjs", "serve")), "split");
        check(Worker.splitCommand("\"C:\\Program Files\\Python\\python.exe\" -m deepjs serve --reveal").get(0)
                .equals("C:\\Program Files\\Python\\python.exe"), "split honours quotes");

        // ── which interpreter to try ─────────────────────────────────────────
        check(DeepJsExtension.engineCommands("").size() >= 2
                        && DeepJsExtension.engineCommands("").stream().allMatch(c -> c.subList(c.size() - 3, c.size()).equals(List.of("-m", "deepjs", "serve"))),
                "with nothing configured, several interpreter names are tried");
        check(DeepJsExtension.engineCommands("\"C:\\Program Files\\Python\\python.exe\"")
                        .equals(List.of(List.of("C:\\Program Files\\Python\\python.exe", "-m", "deepjs", "serve"))),
                "a configured interpreter is the only one tried");
        check(DeepJsExtension.engineCommands("py -3 -m deepjs serve").equals(List.of(List.of("py", "-3", "-m", "deepjs", "serve"))),
                "a pasted command line keeps its interpreter");

        // ── update notice ────────────────────────────────────────────────────
        check(DeepJsExtension.latestTag("{\"url\":\"x\",\"tag_name\": \"v1.12.0\",\"name\":\"n\"}").equals("1.12.0"), "tag is read");
        check(DeepJsExtension.latestTag("<html>rate limited</html>").isEmpty(), "no tag in an error page");
        check(DeepJsExtension.isNewer("0.10.0", "0.9.9") && DeepJsExtension.isNewer("1.0", "0.99.99")
                && !DeepJsExtension.isNewer("0.3.0", "0.3.0") && !DeepJsExtension.isNewer("0.2.9", "0.3.0")
                && !DeepJsExtension.isNewer("", "0.3.0") && !DeepJsExtension.isNewer("nightly", "0.3.0"), "version comparison");

        // ── the real engine process, from the engine inside the jar ──────────
        String jar = System.getProperty("deepjs.jar", "");
        check(!jar.isEmpty() && new java.io.File(jar).isFile(), "-Ddeepjs.jar points at the built jar: " + jar);
        String enginePath = jar + java.io.File.separator + "engine";
        List<String> python = args.length > 0 ? List.of(args)
                : List.of(System.getProperty("os.name").toLowerCase().contains("win") ? "python" : "python3");
        List<String> command = new ArrayList<>(python);
        command.addAll(List.of("-m", "deepjs", "serve"));
        List<String[]> messages = Collections.synchronizedList(new ArrayList<>());
        List<String> states = Collections.synchronizedList(new ArrayList<>());
        Worker worker = new Worker(command, new Worker.Listener() {
            public void onMessage(String[] f) { messages.add(f); }
            public void onState(String text, boolean healthy) { states.add((healthy ? "ok: " : "BAD: ") + text); }
            public void onLog(String text) { System.out.println("  [log] " + text); }
        });
        worker.setEnginePath(enginePath);
        check(worker.start(), "worker starts (" + String.join(" ", command) + ") — states: " + states);
        check(worker.version().equals(DeepJsExtension.VERSION),
                "the engine that answers is the one in the jar: " + worker.version() + " vs " + DeepJsExtension.VERSION);
        System.out.println("engine: deepjs " + worker.version() + " (from " + enginePath + ")");

        String base = "https://app.acme.io";
        String runtime = "(()=>{var r={};r.p=\"/\";r.u=e=>\"static/js/\"+({3:\"admin\"}[e]||e)+\".\"+"
                + "{3:\"9f1c2a\",7:\"02ab3c\"}[e]+\".chunk.js\";})();";
        String main = "const API=\"/api/v1\";function login(e,t){return fetch(API+\"/auth/login\",{method:\"POST\","
                + "body:JSON.stringify({email:e,password:t})})}"
                + "const cfg={clientSecret:\"Zx9Qm2Lk8Pz4Rt6V\"+\"\",apiKey:\"YOUR_API_KEY\"};"
                + "var k=\"AKIA\"+\"\";function del(id){return axios.delete(`/api/v1/users/${id}`)}"
                + "\n//# sourceMappingURL=main.js.map\n";
        worker.submit("script", base + "/static/js/runtime.js", runtime.getBytes(StandardCharsets.UTF_8));
        worker.submit("script", base + "/static/js/main.js", main.getBytes(StandardCharsets.UTF_8));
        worker.submit("script", base + "/static/js/junk.js", new byte[]{0, 1, 2, '{', '{', '{'});
        check(worker.awaitIdle(30_000), "worker answers everything submitted");

        boolean login = false, delete = false, chunk = false, map = false, done = false;
        for (String[] f : messages) {
            switch (f[0]) {
                case "E" -> {
                    login |= f[1].equals("POST") && f[2].equals(base + "/api/v1/auth/login") && f[6].equals("email,password");
                    delete |= f[1].equals("DELETE") && f[3].equals("/api/v1/users/{id}");
                }
                case "C" -> chunk |= f[1].equals(base + "/static/js/admin.9f1c2a.chunk.js");
                case "M" -> map |= f[1].equals(base + "/static/js/main.js.map") && f[2].equals("1");
                case "D" -> done = true;
                default -> { }
            }
        }
        check(login, "POST /api/v1/auth/login with body fields arrives");
        check(delete, "DELETE /api/v1/users/{id} arrives");
        check(chunk, "the hidden admin chunk is named");
        check(map, "the source map is named as referenced");
        check(done, "completion markers arrive");

        int before = messages.size();
        worker.submit("script", base + "/static/js/main.js", main.getBytes(StandardCharsets.UTF_8));
        check(worker.awaitIdle(30_000), "second pass completes");
        long repeated = messages.subList(before, messages.size()).stream().filter(f -> !f[0].equals("D")).count();
        check(repeated == 0, "nothing is reported twice");
        worker.shutdown();
        check(!worker.alive(), "worker stops on shutdown");

        // ── a worker that cannot start is reported, not thrown ───────────────
        List<String> bad = new ArrayList<>();
        Worker broken = new Worker(List.of("definitely-not-a-real-command-xyz"), new Worker.Listener() {
            public void onMessage(String[] f) { }
            public void onState(String text, boolean healthy) { bad.add(text); }
            public void onLog(String text) { }
        });
        check(!broken.start() && !bad.isEmpty(), "a missing engine is reported as a state, not an exception");
        for (int i = 0; i < 5; i++) {
            check(!broken.submit("script", base + "/x.js", new byte[]{'1'}), "nothing is queued for an engine that cannot start");
        }
        Thread.sleep(300);
        check(bad.size() == 1, "…and the failure is reported once, not once per response: " + bad);
        broken.shutdown();

        // the interpreter is there but has no engine: the reason is the interpreter's own message
        List<String> noEngine = new ArrayList<>();
        List<String> bare = new ArrayList<>(python);
        bare.addAll(List.of("-m", "deepjs_is_not_installed_here", "serve"));
        Worker missing = new Worker(bare, new Worker.Listener() {
            public void onMessage(String[] f) { }
            public void onState(String text, boolean healthy) { noEngine.add(text); }
            public void onLog(String text) { }
        });
        long started = System.currentTimeMillis();
        check(!missing.start() && noEngine.size() == 1 && noEngine.get(0).contains("No module named")
                        && noEngine.get(0).contains("exited with code"),
                "a Python without the engine is reported with its own error: " + noEngine);
        check(System.currentTimeMillis() - started < 15_000, "…without waiting for the start timeout");
        missing.shutdown();

        // the first candidate fails, the second works
        List<String> fallback = new ArrayList<>();
        Worker second = new Worker(List.of(), new Worker.Listener() {
            public void onMessage(String[] f) { }
            public void onState(String text, boolean healthy) { fallback.add((healthy ? "ok: " : "BAD: ") + text); }
            public void onLog(String text) { }
        });
        second.setEnginePath(enginePath);
        second.setCommands(List.of(List.of("definitely-not-a-real-command-xyz", "-m", "deepjs", "serve"), command));
        check(second.start() && fallback.size() == 1 && fallback.get(0).startsWith("ok: "),
                "the next interpreter is tried when the first is missing: " + fallback);
        second.shutdown();

        // ── the tab and its models (no Burp, no display) ─────────────────────
        List<List<String[]>> toRepeater = new ArrayList<>();
        DeepJsTab[] holder = new DeepJsTab[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new DeepJsTab(new DeepJsTab.Actions() {
            public void sendToRepeater(List<String[]> rows) { toRepeater.add(rows); }
            public void fetchHiddenNow() { }
            public void analyseProxyHistory() { }
            public void clearAll() { }
            public void restartWorker(String python) { }
            public void settingsChanged() { }
        }));
        DeepJsTab tab = holder[0];
        String[] row = {"POST", base + "/api/v1/users/{id}/roles", "expand,fields", "role,reason", "X-CSRF", "fetch", "main.js:1"};
        tab.putEndpoint("POST /api/v1/users/{id}/roles", row);
        tab.putEndpoint("POST /api/v1/users/{id}/roles", row);                 // same key → still one row
        tab.putEndpoint(" /other", new String[]{"?", "/other", "", "", "", "string", "x.js:2"});
        tab.putSecret("AWS x", new String[]{"critical", "AWS_ACCESS_KEY", "AKIA…6N", "k", "a.js:1", "note"});
        tab.putScript(base + "/a.chunk.js", "script", "not fetched");
        tab.putScript(base + "/a.chunk.js", "script", "fetched (12 KB)");
        tab.putHost(new String[]{"api.acme.io", "in-scope", "", ""});
        tab.putOther("Client routes", "/admin");
        tab.log("hello");
        tab.setStatus("ok", true);
        SwingUtilities.invokeAndWait(() -> { });
        check(tab.endpoints.getRowCount() == 2, "endpoint rows are keyed (2 rows, got " + tab.endpoints.getRowCount() + ")");
        check(tab.scripts.getRowCount() == 1 && tab.scripts.getValueAt(0, 2).equals("fetched (12 KB)"), "script status updates in place");
        check(tab.secrets.getRowCount() == 1 && tab.hosts.getRowCount() == 1, "secrets and hosts tables fill");
        SwingUtilities.invokeAndWait(tab::clearTables);
        SwingUtilities.invokeAndWait(() -> { });
        check(tab.endpoints.getRowCount() == 0, "clear empties the tables");

        // ── request skeletons for Repeater ───────────────────────────────────
        check((base + "/api/v1/users/:id/roles?expand=&fields=").equals(DeepJsExtension.requestUrl(row)),
                "placeholders and query names become a URL: " + DeepJsExtension.requestUrl(row));
        check("{\"role\": \"\", \"reason\": \"\"}".equals(DeepJsExtension.requestBody(row)), "body fields become JSON");
        check(DeepJsExtension.requestUrl(new String[]{"GET", "{base}/users", "", "", "", "fetch", ""}) == null,
                "an endpoint with no known host is not sent");

        String pythonSetting = String.join(" ", python.stream().map(c -> c.contains(" ") ? "\"" + c + "\"" : c).toList());
        extensionAgainstMockedBurp(pythonSetting, jar);
        extensionRecoversFromAMissingEngine(pythonSetting, jar);

        System.out.println("harness: " + checks + " checks passed");
        System.exit(0);
    }

    private static String column(DeepJsTab.KeyedModel model, int col) {
        StringBuilder b = new StringBuilder();
        for (int r = 0; r < model.getRowCount(); r++) {
            b.append(model.getValueAt(r, col)).append('\n');
        }
        return b.toString();
    }

    private static void settle(DeepJsExtension ext, MockBurp fake, int expectRequests) throws Exception {
        long end = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < end) {
            Thread.sleep(150);
            SwingUtilities.invokeAndWait(() -> { });
            if (ext.worker.pending() == 0 && fake.requested.size() >= expectRequests) {
                Thread.sleep(300);                           // let the last answers reach the tables
                SwingUtilities.invokeAndWait(() -> { });
                if (ext.worker.pending() == 0) {
                    return;
                }
            }
        }
    }

    /**
     * Load the real extension class against a mocked Burp API and push traffic
     * through it: the handler, the engine bridge, the fetching of hidden
     * chunks and source maps "through Burp", Repeater, history, context menu.
     */
    private static void extensionAgainstMockedBurp(String python, String jar) throws Exception {
        String base = "https://app.acme.io";
        MockBurp fake = new MockBurp(python, jar);
        fake.site.put(DeepJsExtension.RELEASES_API, "{\"tag_name\":\"v99.1.0\",\"name\":\"DeepJS 99.1.0\"}");
        fake.site.put(base + "/static/js/admin.9f1c2a.chunk.js",
                "function del(e){return fetch(\"/api/v1/admin/users/\"+e,{method:\"DELETE\"})}");
        fake.site.put(base + "/static/js/main.js.map",
                "{\"version\":3,\"sources\":[\"webpack:///./src/audit.ts\",\"webpack:///./node_modules/@acme-internal/kit/i.js\"],"
                        + "\"sourcesContent\":[\"export const a = () => http.get(`/api/v1/audit/${id}`)\",\"x\"]}");

        DeepJsExtension ext = new DeepJsExtension();
        check(burp.api.montoya.BurpExtension.class.isAssignableFrom(DeepJsExtension.class), "implements BurpExtension");
        ext.initialize(fake.api());
        check(fake.suiteTab == ext.tab && fake.unloadHandler != null, "registers its tab and an unload handler");
        check(ext.tab.command.getText().equals(python), "reads the saved Python setting");
        long end = System.currentTimeMillis() + 30_000;
        while (!ext.worker.alive() || ext.worker.version().isEmpty()) {
            check(System.currentTimeMillis() < end, "engine starts under the extension");
            Thread.sleep(100);
        }
        check(ext.worker.version().equals(DeepJsExtension.VERSION), "the extension runs the engine it carries");
        end = System.currentTimeMillis() + 10_000;
        while (fake.output.stream().noneMatch(line -> line.contains("99.1.0 is available")) && System.currentTimeMillis() < end) {
            Thread.sleep(100);
        }
        check(fake.output.stream().anyMatch(line -> line.contains("DeepJS 99.1.0 is available")),
                "a newer release is announced: " + fake.output);

        // 1. the browser loads the runtime and the main bundle through the proxy
        String runtime = "(()=>{var r={};r.p=\"/\";r.u=e=>\"static/js/\"+({3:\"admin\"}[e]||e)+\".\"+"
                + "{3:\"9f1c2a\",7:\"02ab3c\"}[e]+\".chunk.js\";})();";
        String main = "function login(e,t){return fetch(\"/api/v1/auth/login\",{method:\"POST\","
                + "body:JSON.stringify({email:e,password:t})})}var k=\"AKIA\"+\"\";const c={clientSecret:\"Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua\"};"
                + "\n//# sourceMappingURL=main.js.map\n";
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/runtime.js", runtime, burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/main.js", main, burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/main.js", main, burp.api.montoya.http.message.MimeType.SCRIPT));   // again
        ext.handleHttpResponseReceived(fake.proxied(base + "/logo.png", "\u0089PNG", burp.api.montoya.http.message.MimeType.IMAGE_PNG));
        settle(ext, fake, 3);

        String urls = column(ext.tab.endpoints, DeepJsTab.E_URL);
        String methods = column(ext.tab.endpoints, DeepJsTab.E_METHOD);
        check(urls.contains(base + "/api/v1/auth/login") && methods.contains("POST"), "proxied bundle → API call in the tab");

        // 2. the extension fetched, through Burp, what the code named but the browser never loaded
        check(fake.requested.contains(base + "/static/js/admin.9f1c2a.chunk.js"), "hidden chunk requested through Burp: " + fake.requested);
        check(fake.requested.contains(base + "/static/js/main.js.map"), "source map requested through Burp");
        check(urls.contains(base + "/api/v1/admin/users/{param}") && methods.contains("DELETE"),
                "endpoint that exists only in the hidden chunk appears:\n" + urls);
        check(urls.contains("/api/v1/audit/{id}"), "endpoint that exists only in the recovered source appears:\n" + urls);
        String scriptStates = column(ext.tab.scripts, 2);
        check(scriptStates.contains("fetched (") && scriptStates.contains("HTTP 404"),
                "each hidden script shows what happened to it:\n" + scriptStates);
        check(fake.siteMapAdds.size() >= 2, "fetched files are added to Burp's site map");
        // two chunks the runtime names + one map per script seen (3) — and nothing that is not a script or a map
        check(fake.requested.stream().allMatch(u -> u.startsWith(base + "/static/js/") && (u.endsWith(".js") || u.endsWith(".js.map")))
                && fake.requested.size() == 5 && new java.util.HashSet<>(fake.requested).size() == 5,
                "only scripts and maps were requested, each once: " + fake.requested);

        // 3. secrets: listed, masked, and raised as an issue
        String secretValues = column(ext.tab.secrets, 2);
        check(column(ext.tab.secrets, 1).contains("HARDCODED_SECRET"), "secret listed");
        check(!secretValues.contains("Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua"), "secret value is masked in the tab");
        check(fake.siteMapAdds.stream().anyMatch(o -> String.valueOf(o).contains("AuditIssue")), "an issue is raised for the secret");

        // 4. Repeater skeleton
        for (int r = 0; r < ext.tab.endpoints.getRowCount(); r++) {
            if (ext.tab.endpoints.getValueAt(r, DeepJsTab.E_URL).equals(base + "/api/v1/auth/login")) {
                ext.sendToRepeater(java.util.Collections.singletonList(ext.tab.endpoints.row(r)));
            }
        }
        check(fake.repeater.size() == 1 && fake.repeater.get(0).startsWith("POST " + base + "/api/v1/auth/login")
                && fake.repeater.get(0).contains("\"email\": \"\""), "Repeater receives a POST with the body fields: " + fake.repeater);

        // 5. proxy history + context menu + clear
        fake.history.add(fake.pair(base + "/static/js/extra.js", "fetch(\"/api/v1/from-history\")", burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.analyseProxyHistory();
        settle(ext, fake, 3);
        Thread.sleep(500);
        settle(ext, fake, 3);
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains("/api/v1/from-history"), "proxy history is analysed on request");

        List<burp.api.montoya.http.message.HttpRequestResponse> selection =
                List.of(fake.pair(base + "/static/js/menu.js", "fetch(\"/api/v1/from-menu\")", burp.api.montoya.http.message.MimeType.SCRIPT));
        burp.api.montoya.ui.contextmenu.ContextMenuEvent event = MockBurp.mock(
                burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, java.util.Map.of("selectedRequestResponses", a -> selection));
        List<java.awt.Component> items = ext.provideMenuItems(event);
        check(items.size() == 1, "context menu offers \"Analyse with DeepJS\"");
        ((javax.swing.JMenuItem) items.get(0)).doClick();
        Thread.sleep(500);
        settle(ext, fake, 3);
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains("/api/v1/from-menu"), "context-menu analysis works");

        ext.clearAll();
        SwingUtilities.invokeAndWait(() -> { });
        Thread.sleep(200);
        SwingUtilities.invokeAndWait(() -> { });
        check(ext.tab.endpoints.getRowCount() == 0 && ext.tab.secrets.getRowCount() == 0, "Clear empties everything");

        // 6. "In-scope only" + a host no script came from: never requested
        int before = fake.requested.size();
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/loader.js",
                "const s=document.createElement(\"script\");s.src=\"https://cdn.unrelated-host.io/lib/other.js\";",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, before);
        check(fake.requested.stream().noneMatch(u -> u.contains("unrelated-host")), "a host that never served a script is not contacted");

        // 7. a base URL revealed by a later chunk replaces the placeholder row instead of adding a second one
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/svc.js",
                "class S{http=inject(H);root=env.gatewayRoot;host=this.root+`/rest/wallet`;"
                        + "get(){return this.http.get(this.host+`/balance`)}}",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, fake.requested.size());
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains(base + "/rest/wallet/balance"),
                "class service with an unknown base is listed against the site:\n" + column(ext.tab.endpoints, DeepJsTab.E_URL));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/env.js",
                "const env={production:!0,gatewayRoot:\"/gw/v2\"};",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, fake.requested.size());
        String resolved = column(ext.tab.endpoints, DeepJsTab.E_URL);
        check(resolved.contains(base + "/gw/v2/rest/wallet/balance") && !resolved.contains(base + "/rest/wallet/balance"),
                "the row is replaced once another chunk reveals the base:\n" + resolved);

        fake.unloadHandler.extensionUnloaded();
        Thread.sleep(300);
        check(!ext.worker.alive(), "unloading the extension stops the engine");
        System.out.println("extension against mocked Burp: ok (" + fake.requested.size() + " request(s) made through Burp)");
    }

    /**
     * What happened on a real machine: Burp's Python could not run the engine.
     * The failure must be explained once, nothing may be lost, and fixing the
     * setting must be enough — the traffic already in the proxy history is analysed.
     */
    private static void extensionRecoversFromAMissingEngine(String python, String jar) throws Exception {
        String base = "https://shop.acme.io";
        MockBurp fake = new MockBurp("definitely-not-a-real-command-xyz", jar);
        DeepJsExtension ext = new DeepJsExtension();
        ext.initialize(fake.api());
        String[] log = new String[1];
        long end = System.currentTimeMillis() + 30_000;
        do {
            Thread.sleep(150);
            SwingUtilities.invokeAndWait(() -> log[0] = ext.tab.logText());
        } while (!log[0].contains("engine not started") && System.currentTimeMillis() < end);
        check(log[0].contains("engine not started") && log[0].contains("full path"), "a missing interpreter is explained:\n" + log[0]);

        for (int i = 0; i < 6; i++) {
            String body = "fetch(\"/api/v1/orders/" + i + "\")";
            fake.history.add(fake.pair(base + "/static/js/o" + i + ".js", body, burp.api.montoya.http.message.MimeType.SCRIPT));
            ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/o" + i + ".js", body, burp.api.montoya.http.message.MimeType.SCRIPT));
        }
        Thread.sleep(500);
        SwingUtilities.invokeAndWait(() -> log[0] = ext.tab.logText());
        check(log[0].split("engine not started", -1).length - 1 == 1, "…once, however many responses pass:\n" + log[0]);
        check(ext.tab.endpoints.getRowCount() == 0, "nothing is analysed while the engine is down");

        ext.restartWorker(python);                               // the user enters a working interpreter
        end = System.currentTimeMillis() + 40_000;
        while (ext.tab.endpoints.getRowCount() < 6 && System.currentTimeMillis() < end) {
            Thread.sleep(200);
            SwingUtilities.invokeAndWait(() -> { });
        }
        String urls = column(ext.tab.endpoints, DeepJsTab.E_URL);
        check(urls.contains(base + "/api/v1/orders/0") && urls.contains(base + "/api/v1/orders/5"),
                "after the fix, what passed while the engine was down is analysed from the proxy history:\n" + urls);
        fake.unloadHandler.extensionUnloaded();
        System.out.println("recovery from a missing engine: ok");
    }
}
