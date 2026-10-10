package deepjs.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import java.awt.Component;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * A stand-in for Burp, built from dynamic proxies over the real Montoya
 * interfaces: enough of the API to load the extension and push traffic
 * through it without a Burp process.
 *
 * Unanswered methods return a harmless default (another proxy for an
 * interface, an empty list / Optional, zero, false, ""), so the extension's
 * real code paths run exactly as they would against Burp.
 */
final class MockBurp {

    /** url → body the fake "site" serves when the extension requests something through Burp. */
    final Map<String, String> site = new HashMap<>();
    final List<String> requested = Collections.synchronizedList(new ArrayList<>());
    final List<String> repeater = Collections.synchronizedList(new ArrayList<>());
    final List<String> output = Collections.synchronizedList(new ArrayList<>());
    final List<Object> siteMapAdds = Collections.synchronizedList(new ArrayList<>());
    final List<HttpRequestResponse> history = new ArrayList<>();
    volatile Component suiteTab;
    volatile ExtensionUnloadingHandler unloadHandler;
    private final String python;
    private final String jar;

    /** @param python the saved "Python" setting; @param jar what Burp reports as the extension's file */
    MockBurp(String python, String jar) {
        this.python = python;
        this.jar = jar;
        ObjectFactoryLocator.FACTORY = mock(MontoyaObjectFactory.class, Map.of(
                "httpRequestFromUrl", a -> request((String) a[0], "GET", new ArrayList<>())
        ));
    }

    @SuppressWarnings("unchecked")
    static <T> T mock(Class<T> type, Map<String, Function<Object[], Object>> answers) {
        InvocationHandler h = (proxy, method, args) -> {
            String name = method.getName();
            Function<Object[], Object> f = answers.get(name);
            if (f != null) {
                return f.apply(args == null ? new Object[0] : args);
            }
            if (name.equals("toString")) {
                return "mock(" + type.getSimpleName() + ")";
            }
            if (name.equals("hashCode")) {
                return System.identityHashCode(proxy);
            }
            if (name.equals("equals")) {
                return proxy == args[0];
            }
            return defaultFor(method);
        };
        return (T) Proxy.newProxyInstance(MockBurp.class.getClassLoader(), new Class<?>[]{type}, h);
    }

    private static Object defaultFor(Method m) {
        Class<?> r = m.getReturnType();
        if (r == void.class) {
            return null;
        }
        if (r == boolean.class) {
            return false;
        }
        if (r == int.class) {
            return 0;
        }
        if (r == short.class) {
            return (short) 0;
        }
        if (r == long.class) {
            return 0L;
        }
        if (r == byte.class) {
            return (byte) 0;
        }
        if (r == String.class) {
            return "";
        }
        if (r == Optional.class) {
            return Optional.empty();
        }
        if (r == List.class) {
            return new ArrayList<>();
        }
        if (r.isInterface()) {
            return mock(r, Map.of());
        }
        return null;                       // boxed types, enums, classes: "not set"
    }

    // ── message objects ──────────────────────────────────────────────────────

    HttpRequest request(String url, String method, List<String> notes) {
        return mock(HttpRequest.class, Map.of(
                "url", a -> url,
                "method", a -> method,
                "isInScope", a -> true,
                "withMethod", a -> request(url, (String) a[0], notes),
                "withAddedHeader", a -> { notes.add(a[0] + ": " + a[1]); return request(url, method, notes); },
                "withBody", a -> { notes.add("body " + a[0]); return request(url, method, notes); },
                "toString", a -> method + " " + url + (notes.isEmpty() ? "" : " " + notes)
        ));
    }

    static HttpResponse response(int status, String body, MimeType mime) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ByteArray array = mock(ByteArray.class, Map.of("getBytes", a -> bytes, "length", a -> bytes.length));
        return mock(HttpResponse.class, Map.of(
                "statusCode", a -> (short) status,
                "body", a -> array,
                "bodyToString", a -> body,
                "statedMimeType", a -> mime,
                "inferredMimeType", a -> mime
        ));
    }

    /** A response as Burp hands it to an HttpHandler (e.g. something the browser loaded through the proxy). */
    HttpResponseReceived proxied(String url, String body, MimeType mime) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ByteArray array = mock(ByteArray.class, Map.of("getBytes", a -> bytes, "length", a -> bytes.length));
        HttpRequest req = request(url, "GET", new ArrayList<>());
        return mock(HttpResponseReceived.class, Map.of(
                "initiatingRequest", a -> req,
                "statusCode", a -> (short) 200,
                "body", a -> array,
                "statedMimeType", a -> mime,
                "inferredMimeType", a -> mime
        ));
    }

    HttpRequestResponse pair(String url, String body, MimeType mime) {
        HttpRequest req = request(url, "GET", new ArrayList<>());
        HttpResponse resp = response(200, body, mime);
        return mock(HttpRequestResponse.class, Map.of("request", a -> req, "response", a -> resp));
    }

    // ── the API object ───────────────────────────────────────────────────────

    MontoyaApi api() {
        Object http = mock(burp.api.montoya.http.Http.class, Map.of(
                "sendRequest", a -> {
                    String url = ((HttpRequest) a[0]).url();
                    if (!url.startsWith("https://api.github.com/")) {
                        requested.add(url);                 // the update check is not a request to the target
                    }
                    String body = site.get(url);
                    HttpResponse resp = body == null ? response(404, "not found", MimeType.PLAIN_TEXT)
                            : response(200, body, url.endsWith(".map") ? MimeType.JSON : MimeType.SCRIPT);
                    return mock(HttpRequestResponse.class, Map.of("request", x -> a[0], "response", x -> resp));
                }
        ));
        Object prefs = mock(burp.api.montoya.persistence.Preferences.class, Map.of(
                "getString", a -> "deepjs.python".equals(a[0]) ? python : null,
                "getBoolean", a -> null
        ));
        Object persistence = mock(burp.api.montoya.persistence.Persistence.class, Map.of("preferences", a -> prefs));
        Object ui = mock(burp.api.montoya.ui.UserInterface.class, Map.of(
                "registerSuiteTab", a -> { suiteTab = (Component) a[1]; return mock(burp.api.montoya.core.Registration.class, Map.of()); }
        ));
        Object extension = mock(burp.api.montoya.extension.Extension.class, Map.of(
                "filename", a -> jar,
                "registerUnloadingHandler", a -> { unloadHandler = (ExtensionUnloadingHandler) a[0]; return mock(burp.api.montoya.core.Registration.class, Map.of()); }
        ));
        Object logging = mock(burp.api.montoya.logging.Logging.class, Map.of(
                "logToOutput", a -> { output.add(String.valueOf(a[0])); return null; },
                "logToError", a -> { output.add("ERROR " + a[0]); return null; }
        ));
        Object repeaterApi = mock(burp.api.montoya.repeater.Repeater.class, Map.of(
                "sendToRepeater", a -> { repeater.add(a[0] + (a.length > 1 ? "  [" + a[1] + "]" : "")); return null; }
        ));
        Object scope = mock(burp.api.montoya.scope.Scope.class, Map.of("isInScope", a -> true));
        Object siteMap = mock(burp.api.montoya.sitemap.SiteMap.class, Map.of("add", a -> { siteMapAdds.add(a[0]); return null; }));
        Object proxy = mock(burp.api.montoya.proxy.Proxy.class, Map.of("history", a -> {
            List<ProxyHttpRequestResponse> items = new ArrayList<>();
            for (HttpRequestResponse rr : history) {
                items.add(mock(ProxyHttpRequestResponse.class, Map.of(
                        "finalRequest", x -> rr.request(), "originalResponse", x -> rr.response())));
            }
            return items;
        }));
        return mock(MontoyaApi.class, Map.of(
                "http", a -> http, "persistence", a -> persistence, "userInterface", a -> ui,
                "extension", a -> extension, "logging", a -> logging, "repeater", a -> repeaterApi,
                "scope", a -> scope, "siteMap", a -> siteMap, "proxy", a -> proxy
        ));
    }
}
