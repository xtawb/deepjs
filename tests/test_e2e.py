"""
End-to-end: a small fake single-page-app build is served from localhost and
scanned exactly as a real target would be. No external network is used.

The build has what a real one has: an HTML page, a webpack-style runtime with
a chunk map, a main bundle with a source map, lazy chunks that no page links
to, an analytics script on a vendor host, and an inline config block.
"""

import base64
import functools
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

from deepjs import cli, report
from deepjs.engine import Engine, Options
from deepjs.fetch import Fetcher

os.environ["DEEPJS_NO_UPDATE_CHECK"] = "1"       # these tests use no external network

AWS_KEY = "AKIA" + "Q7ZP2MXL4RT9VB6N"
STRIPE_PK = "pk_" + "live_9aK2mQ7xL4pR8tY1wZ6nC3vB"
CLIENT_SECRET = "Zx9Qm2Lk8Pz4Rt6V" + "w1Yb5Nc7Hf0Jg3Ua"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

INDEX = """<!doctype html><html><head><title>Acme</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEF1234"></script>
<script>window.__CONFIG__ = {apiBase: "/api/v1", featureFlagsUrl: "/api/v1/flags"};</script>
</head><body><div id="root"></div>
<a href="/about.html">About</a> <a href="/about.html?ref=nav#team">About again</a>
<a href="/account/logout">Log out</a> <a href="/files/brochure.pdf">Brochure</a>
<a href="https://other.example.org/elsewhere">Elsewhere</a> <a href="mailto:hi@acme.io">Mail</a>
<script src="/static/js/runtime.js"></script>
<script src="/static/js/main.a1b2.js"></script>
</body></html>"""

RUNTIME = ('(()=>{var r={};r.p="/";r.u=e=>"static/js/"+({3:"admin",7:"billing"}[e]||e)+"."+'
           '{3:"9f1c2a",7:"02ab3c",11:"77aa88"}[e]+".chunk.js";})();')

MAIN = ('const API="/api/v1";'
        'function login(e,t){return fetch(API+"/auth/login",{method:"POST",body:JSON.stringify({email:e,password:t})})}'
        'function me(){return fetch(API+"/me")}'
        f'const cfg={{stripe:"{STRIPE_PK}",clientSecret:"{CLIENT_SECRET}",uploads:"https://acme-uploads.s3.eu-west-1.amazonaws.com/u/"}};'
        'const routes=[{path:"/dashboard",component:D},{path:"/admin",component:A}];'
        '\n//# sourceMappingURL=main.a1b2.js.map\n')

MAIN_MAP = {
    "version": 3,
    "sources": ["webpack:///./src/api/client.ts", "webpack:///./node_modules/@acme-internal/ui-kit/index.js",
                "webpack:///./node_modules/react/index.js", "webpack:///../../../../tmp/escape.txt"],
    "sourcesContent": [
        f"// deploy token (remove before release): {GH_TOKEN}\n"
        "export const audit = (id: string) => http.get(`/api/v1/audit/${id}/events`, {params: {limit: 50}});\n",
        "module.exports = {};", "module.exports = {};", "outside",
    ],
}

ADMIN_CHUNK = ('function del(e){return fetch("/api/v1/admin/users/"+e,{method:"DELETE"})}'
               'function imp(e){return axios.post("/api/v1/admin/impersonate",{userId:e})}'
               f'var k="{AWS_KEY}",internal="http://10.20.30.40:8080/health";')
BILLING_CHUNK = 'export const inv=()=>http.get("/api/v1/billing/invoices?status=open");'
ELEVEN_CHUNK = 'const Q="query AdminAudit($n:Int){ audit(first:$n){ id } }";'

ABOUT = """<html><body><a href="/deep/level2.html">deeper</a>
<form action="/api/v1/newsletter" method="post"><input name="email"><input name="csrf"><button name="go">Go</button></form>
<form action="/search"><input name="q"></form>
<script src="/static/js/about.js"></script></body></html>"""
LEVEL2 = '<html><body><a href="/deep/level3.html">too deep</a><script>fetch("/api/v1/level2")</script></body></html>'
LEVEL3 = '<html><body><script>fetch("/api/v1/level3")</script></body></html>'
PRICING = '<html><body><script>fetch("/api/v1/plans")</script></body></html>'
DASHBOARD = '<html><body><script>fetch("/api/v1/dashboard/widgets")</script></body></html>'
ROBOTS = "User-agent: *\nDisallow: /internal-admin/\nDisallow: /backup/*.zip\nAllow: /\nSitemap: /sitemap.xml\n"
SITEMAP = ('<?xml version="1.0"?><urlset><url><loc>{base}/pricing.html</loc></url>'
           '<url><loc>{base}/files/brochure.pdf</loc></url></urlset>')

FILES = {
    "index.html": INDEX,
    "about.html": ABOUT,
    "deep/level2.html": LEVEL2,
    "deep/level3.html": LEVEL3,
    "pricing.html": PRICING,
    "dashboard": DASHBOARD,
    "robots.txt": ROBOTS,
    "static/js/about.js": 'export const team=()=>http.get("/api/v1/team");',
    "account/logout": "<html>bye</html>",
    "files/brochure.pdf": "%PDF-1.4",
    "static/js/runtime.js": RUNTIME,
    "static/js/main.a1b2.js": MAIN,
    "static/js/main.a1b2.js.map": json.dumps(MAIN_MAP),
    "static/js/admin.9f1c2a.chunk.js": ADMIN_CHUNK,
    "static/js/billing.02ab3c.chunk.js": BILLING_CHUNK,
    "static/js/11.77aa88.chunk.js": ELEVEN_CHUNK,
}


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    requested = []                 # every path any test asked the fixture server for

    def log_message(self, *args):
        pass

    def do_GET(self):
        QuietHandler.requested.append(self.path)
        super().do_GET()

    def guess_type(self, path):
        if path.endswith("dashboard") or path.endswith("logout"):
            return "text/html"
        return super().guess_type(path)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.site = os.path.join(cls.tmp.name, "site")
        for rel, body in FILES.items():
            path = os.path.join(cls.site, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body)
        handler = functools.partial(QuietHandler, directory=cls.site)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        with open(os.path.join(cls.site, "sitemap.xml"), "w", encoding="utf-8") as fh:
            fh.write(SITEMAP.format(base=cls.base))
        QuietHandler.requested.clear()
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.sources = os.path.join(cls.tmp.name, "recovered")
        cls.result = Engine(Options(sources_dir=cls.sources)).run([cls.base + "/"])
        cls.first_run_requests = list(QuietHandler.requested)
        cls.calls = {(e.method, e.url) for e in cls.result.endpoints if e.is_call}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_no_errors(self):
        self.assertEqual(self.result.errors, [])

    # ── crawling ──────────────────────────────────────────────────────────────

    def test_crawler_follows_links_sitemap_and_routes(self):
        pages = {f.name.replace(self.base, ""): f.origin for f in self.result.files if f.kind == "html"}
        self.assertEqual(pages.get("/"), "target")
        self.assertEqual(pages.get("/about.html"), "link")
        self.assertEqual(pages.get("/deep/level2.html"), "link")              # depth 2
        self.assertEqual(pages.get("/pricing.html"), "sitemap")               # linked from nowhere
        self.assertEqual(pages.get("/dashboard"), "route")                    # a client route found in the bundle
        for call in (("GET", "/api/v1/team"), ("GET", "/api/v1/level2"), ("GET", "/api/v1/plans"),
                     ("GET", "/api/v1/dashboard/widgets")):
            self.assertIn(call, self.calls)

    def test_crawler_limits_and_safety(self):
        asked = self.first_run_requests
        self.assertNotIn("/deep/level3.html", asked)                          # beyond --crawl-depth
        self.assertNotIn(("GET", "/api/v1/level3"), self.calls)
        self.assertNotIn("/account/logout", asked)                            # never follow a state-changing link
        self.assertNotIn("/files/brochure.pdf", asked)                        # not a page
        self.assertEqual(asked.count("/about.html") + asked.count("/about.html?ref=nav"), 1)   # same page once
        self.assertFalse(any("other.example.org" in f.name for f in self.result.files))

    def test_forms_and_robots_become_endpoints(self):
        by_url = {e.url: e for e in self.result.endpoints}
        news = by_url["/api/v1/newsletter"]
        self.assertEqual((news.method, news.kind, news.body), ("POST", "form", ["email", "csrf", "go"]))
        self.assertEqual((by_url["/search"].method, by_url["/search"].params), ("GET", ["q"]))
        self.assertEqual(by_url["/internal-admin/"].file, self.base + "/robots.txt")
        self.assertIn("/backup/", by_url)

    def test_no_crawl_and_page_budget(self):
        r = Engine(Options(crawl=False)).run([self.base + "/"])
        self.assertEqual([f.name for f in r.files if f.kind == "html"], [self.base + "/"])
        r = Engine(Options(max_pages=2)).run([self.base + "/"])
        self.assertEqual(len([f for f in r.files if f.kind == "html"]), 2)
        self.assertTrue(any("--max-pages" in e for e in r.errors))

    def test_target_without_scheme(self):
        self.assertEqual(Engine._normalise_target("app.example.com/login"), "https://app.example.com/login")
        self.assertEqual(Engine._normalise_target("localhost:3000"), "https://localhost:3000")
        self.assertEqual(Engine._normalise_target(self.base), self.base)
        self.assertEqual(Engine._normalise_target("bundle.js"), "bundle.js")       # a mistyped file, not a host
        self.assertEqual(Engine._normalise_target("acme.js.org/docs"), "https://acme.js.org/docs")

    def test_refused_requests_are_explained(self):
        class Refusing:
            requests = 0

            def get(self, url):
                from deepjs.fetch import Response
                self.requests += 1
                return Response(url=url, status=403, error="HTTP 403")
        r = Engine(Options(), fetcher=Refusing()).run(["https://blocked.example.com/"])
        self.assertTrue(any("refused" in e and "Cookie" in e for e in r.errors), r.errors)

    def test_single_page_app(self):
        """Every route returns the same shell; the API base lives in another chunk."""
        from deepjs.fetch import Response
        shell = ('<html><head><meta name="csrf-token" content="{n}"></head><body><a href="#main">skip</a><app-root></app-root>'
                 '<script nonce="{n}" src="/main.js"></script><script nonce="{n}" src="/env.js"></script></body></html>')
        main = ("".join(f'h(Link,{{to:"/section-{n}"}});' for n in range(12))
                + "class Users{http=inject(H);root=env.apiRoot;host=this.root+`/users`;"
                  "all(){return this.http.get(this.host)}one(id){return this.http.delete(`${this.host}/${id}`)}}")
        env = 'const env={production:!0,apiRoot:"https://api.acme.io/v2"};'

        class Spa:
            asked = []
            requests = 0

            def get(self, url):
                self.requests += 1
                path = url.split("://", 1)[1].partition("/")[2]
                self.asked.append("/" + path)
                if path in ("robots.txt", "sitemap.xml"):
                    return Response(url=url, status=404, error="HTTP 404")
                if path.endswith(".js"):
                    body = main if path == "main.js" else env
                    return Response(url=url, status=200, headers={"content-type": "text/javascript"}, body=body.encode())
                page = shell.replace("{n}", f"r{self.requests:04d}")      # a fresh nonce on every request
                return Response(url=url, status=200, headers={"content-type": "text/html"}, body=page.encode())

        fetcher = Spa()
        engine = Engine(Options(), fetcher=fetcher)
        r = engine.run(["https://spa.acme.io/"])
        self.assertTrue(engine.spa_shell)
        pages = [p for p in fetcher.asked if p.startswith("/section-")]
        self.assertEqual(len(pages), 3, pages)                 # three probes, not all twelve routes
        self.assertEqual(r.errors, [])
        self.assertEqual({(e.method, e.url) for e in r.endpoints if e.is_call},
                         {("GET", "https://api.acme.io/v2/users"), ("DELETE", "https://api.acme.io/v2/users/{id}")})

    def test_overloaded_server_is_left_alone(self):
        from deepjs.fetch import Response
        home = "<html><body>" + "".join(f'<a href="/p{n}">p</a>' for n in range(30)) + "</body></html>"

        class Overloaded:
            requests = 0

            def get(self, url):
                self.requests += 1
                if url.rstrip("/").endswith("busy.acme.io"):
                    return Response(url=url, status=200, headers={"content-type": "text/html"}, body=home.encode())
                return Response(url=url, status=503, error="HTTP 503")

        fetcher = Overloaded()
        r = Engine(Options(threads=2), fetcher=fetcher).run(["https://busy.acme.io/"])
        self.assertLess(fetcher.requests, 20)                  # 30 pages were queued; it stopped long before
        self.assertTrue(any(e.startswith("stopped early") and "--delay" in e for e in r.errors), r.errors)
        self.assertEqual(len(r.errors), 2, r.errors)           # that, and one summary line — not one line per URL

    # ── worker protocol (what the Burp extension talks to) ────────────────────

    def test_serve_protocol(self):
        import base64 as b64
        from deepjs.serve import Worker, esc, unesc
        self.assertEqual(unesc(esc("a\tb\nc\\d")), "a\tb\nc\\d")
        out = io.StringIO()
        w = Worker(out)

        def feed(ident, kind, url, body):
            out.seek(0), out.truncate()
            w.handle("\t".join(["A", ident, kind, url, b64.b64encode(body.encode()).decode()]) + "\n")
            return [ln.split("\t") for ln in out.getvalue().splitlines()]

        base = "https://app.acme.io"
        lines = feed("1", "auto", base + "/", INDEX)
        self.assertEqual(lines[-1], ["D", "1"])
        hidden = {ln[1] for ln in lines if ln[0] == "C"}
        self.assertEqual(hidden, {base + "/static/js/runtime.js", base + "/static/js/main.a1b2.js"})

        lines = feed("2", "script", base + "/static/js/runtime.js", RUNTIME)
        hidden = {ln[1] for ln in lines if ln[0] == "C"}
        self.assertEqual(len(hidden), 3)                                      # the three chunks no page links to
        self.assertIn(base + "/static/js/admin.9f1c2a.chunk.js", hidden)

        lines = feed("3", "script", base + "/static/js/main.a1b2.js", MAIN)
        login = next(ln for ln in lines if ln[0] == "E" and ln[3] == "/api/v1/auth/login")
        self.assertEqual(login[1:3], ["POST", base + "/api/v1/auth/login"])
        self.assertEqual(login[6], "email,password")
        self.assertIn(["M", base + "/static/js/main.a1b2.js.map", "1"], lines)
        secret = next(ln for ln in lines if ln[0] == "S" and ln[2] == "HARDCODED_SECRET")
        self.assertNotIn(CLIENT_SECRET, "\t".join(secret))                    # masked unless --reveal

        lines = feed("4", "map", base + "/static/js/main.a1b2.js.map", json.dumps(MAIN_MAP))
        self.assertTrue(any(ln[0] == "S" and ln[2] == "GITHUB_TOKEN" for ln in lines))
        self.assertIn(["P", "@acme-internal/ui-kit"], lines)

        lines = feed("5", "script", base + "/static/js/main.a1b2.js", MAIN)   # the same file again
        self.assertEqual(lines, [["D", "5"]])                                 # nothing new → nothing repeated

        # a service whose base URL lives in a chunk that arrives later: shown at once with the
        # placeholder, then replaced (W = withdrawn) when the other chunk reveals the base
        lines = feed("7", "script", base + "/static/js/svc.js",
                     "class S{http=inject(H);root=env.gatewayRoot;host=this.root+`/rest/wallet`;"
                     "get(){return this.http.get(this.host+`/balance`)}}")
        early = next(ln for ln in lines if ln[0] == "E" and ln[3].endswith("/rest/wallet/balance"))
        self.assertEqual(early[1:4], ["GET", base + "/rest/wallet/balance", "{gatewayRoot}/rest/wallet/balance"])
        lines = feed("8", "script", base + "/static/js/env.js", 'const env={production:!0,gatewayRoot:"/gw/v2"};')
        self.assertIn(["W", "GET", "{gatewayRoot}/rest/wallet/balance"], lines)
        late = next(ln for ln in lines if ln[0] == "E" and ln[3].endswith("/rest/wallet/balance"))
        self.assertEqual(late[1:4], ["GET", base + "/gw/v2/rest/wallet/balance", "/gw/v2/rest/wallet/balance"])

        lines = feed("6", "script", base + "/x.js", "\x00\x01 not javascript {{{")
        self.assertEqual(lines[-1], ["D", "6"])                               # junk never stops the worker
        out.seek(0), out.truncate()
        self.assertTrue(w.handle("PING\n") and out.getvalue() == "PONG\n")
        self.assertFalse(w.handle("QUIT\n"))

    def test_serve_process(self):
        import base64 as b64
        import subprocess
        import sys as _sys
        msg = "\t".join(["A", "7", "script", "https://app.acme.io/a.js",
                         b64.b64encode(b'fetch("/api/v1/from-worker",{method:"PUT"})').decode()])
        proc = subprocess.run([_sys.executable, "-m", "deepjs", "serve"], input=(msg + "\nQUIT\n").encode(),
                              capture_output=True, timeout=60,
                              cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        lines = proc.stdout.decode("utf-8").splitlines()
        self.assertTrue(lines[0].startswith("READY\tdeepjs\t"))
        self.assertIn("E\tPUT\thttps://app.acme.io/api/v1/from-worker", lines[1])
        self.assertEqual(lines[-1], "D\t7")

    def test_chunks_no_page_links_to_are_found(self):
        scripts = {f.name.rsplit("/", 1)[-1]: f.origin for f in self.result.files if f.kind == "script"}
        self.assertEqual(scripts.get("admin.9f1c2a.chunk.js"), "chunk-map")
        self.assertEqual(scripts.get("billing.02ab3c.chunk.js"), "chunk-map")
        self.assertEqual(scripts.get("11.77aa88.chunk.js"), "chunk-map")
        self.assertIn(("DELETE", "/api/v1/admin/users/{param}"), self.calls)      # only reachable through the chunk map
        self.assertIn(("POST", "/api/v1/admin/impersonate"), self.calls)

    def test_calls_carry_method_and_fields(self):
        self.assertIn(("POST", "/api/v1/auth/login"), self.calls)
        self.assertIn(("GET", "/api/v1/me"), self.calls)
        login = next(e for e in self.result.endpoints if e.url == "/api/v1/auth/login")
        self.assertEqual(login.body, ["email", "password"])
        inv = next(e for e in self.result.endpoints if e.url == "/api/v1/billing/invoices")
        self.assertEqual(inv.params, ["status"])
        self.assertEqual(self.result.full_url(login), self.base + "/api/v1/auth/login")

    def test_inline_config_is_analysed(self):
        self.assertIn("/api/v1/flags", {e.url for e in self.result.endpoints})

    def test_vendor_scripts_are_not_fetched(self):
        self.assertFalse(any("googletagmanager" in f.name for f in self.result.files))
        self.assertIn("www.googletagmanager.com", {h.name for h in self.result.hosts})

    def test_source_map_recovered_and_analysed(self):
        self.assertEqual(len(self.result.sourcemaps), 1)
        m = self.result.sourcemaps[0]
        self.assertEqual((m["sources"], m["packages"]), (4, 2))
        self.assertEqual(self.result.packages, ["@acme-internal/ui-kit", "react"])
        # an endpoint and a secret that exist only in the original source
        self.assertIn(("GET", "/api/v1/audit/{id}/events"), self.calls)
        gh = next(s for s in self.result.secrets if s.kind == "GITHUB_TOKEN")
        self.assertEqual((gh.file, gh.key), ("map:src/api/client.ts", "(comment)"))
        # recovered files are written inside the chosen directory — and only there
        self.assertTrue(os.path.isfile(os.path.join(self.sources, "src", "api", "client.ts")))
        self.assertTrue(os.path.isfile(os.path.join(self.sources, "tmp", "escape.txt")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, "escape.txt")))
        self.assertEqual(sorted(os.listdir(self.tmp.name)), ["recovered", "site"])

    def test_secrets_are_classified(self):
        kinds = {s.kind: s for s in self.result.secrets}
        self.assertEqual(kinds["AWS_ACCESS_KEY"].severity, "critical")
        self.assertEqual(kinds["HARDCODED_SECRET"].key, "clientSecret")
        self.assertTrue(kinds["STRIPE_PUBLISHABLE_KEY"].public)
        self.assertEqual(self.result.stats["secrets"], 3)
        self.assertEqual(self.result.stats["public_keys"], 1)

    def test_hosts_routes_graphql(self):
        hosts = {h.name: h for h in self.result.hosts}
        self.assertEqual(hosts["acme-uploads.s3.eu-west-1.amazonaws.com"].service, "aws-s3")
        self.assertEqual(hosts["10.20.30.40"].kind, "internal")
        self.assertEqual(self.result.routes, ["/admin", "/dashboard"])
        self.assertEqual(self.result.graphql, [("query", "AdminAudit")])

    def test_reports_mask_secrets_unless_revealed(self):
        with tempfile.TemporaryDirectory() as out:
            paths = report.write_all(self.result, out)
            self.assertEqual(sorted(os.path.basename(p) for p in paths),
                             ["endpoints.txt", "hosts.txt", "report.json", "report.md"])
            blob = "".join(read(p) for p in paths)
            for raw in (AWS_KEY, CLIENT_SECRET, GH_TOKEN):
                self.assertNotIn(raw, blob)
            self.assertIn("DELETE " + self.base + "/api/v1/admin/users/{param}", blob)
            report.write_all(self.result, out, reveal=True)
            self.assertIn(AWS_KEY, read(os.path.join(out, "report.json")))
        text = report.terminal(self.result)
        self.assertIn("API calls", text)
        self.assertNotIn(AWS_KEY, text)

    def test_no_chunks_option_shows_what_would_be_missed(self):
        r = Engine(Options(follow_chunks=False, source_maps=False)).run([self.base + "/"])
        self.assertNotIn(("DELETE", "/api/v1/admin/users/{param}"), {(e.method, e.url) for e in r.endpoints})
        self.assertEqual(len(r.unvisited), 3)

    def test_strict_limits(self):
        r = Engine(Options(max_files=2)).run([self.base + "/"])
        self.assertLessEqual(len([f for f in r.files if f.kind == "script"]), 2)

    def test_har_and_local_directory(self):
        har = {"log": {"entries": [
            {"request": {"url": self.base + "/"}, "response": {"content": {"mimeType": "text/html", "text": INDEX}}},
            {"request": {"url": self.base + "/static/js/runtime.js"},
             "response": {"content": {"mimeType": "application/javascript", "text": RUNTIME}}},
            {"request": {"url": self.base + "/static/js/main.a1b2.js"},
             "response": {"content": {"mimeType": "application/javascript", "encoding": "base64",
                                      "text": base64.b64encode(MAIN.encode()).decode()}}},
        ]}}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "traffic.har")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(har, fh)
            fetcher = Fetcher()
            r = Engine(Options(), fetcher=fetcher).run([path])
            self.assertEqual(fetcher.requests, 0)                           # a HAR is analysed offline
            self.assertIn(("POST", "/api/v1/auth/login"), {(e.method, e.url) for e in r.endpoints})
            # the chunks the browsing session never loaded are named, not silently dropped
            self.assertEqual(len([u for u in r.unvisited if u.endswith(".chunk.js")]), 3)

        fetcher = Fetcher()
        r = Engine(Options(), fetcher=fetcher).run([self.site])
        self.assertEqual(fetcher.requests, 0)
        self.assertIn(("DELETE", "/api/v1/admin/users/{param}"), {(e.method, e.url) for e in r.endpoints})
        self.assertEqual(len(r.sourcemaps), 1)                              # the .map next to the bundle is used

    def test_cli_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(cli.main(["scan", self.base + "/", "-o", a, "--no-chunks", "--no-color"]), 0)
                self.assertEqual(cli.main([self.base + "/", "-o", b, "-q"]), 0)          # `scan` is implied
            self.assertIn("API calls", out.getvalue())
            self.assertIn("authorised", err.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["diff", os.path.join(a, "report.json"), os.path.join(b, "report.json")]), 0)
            self.assertIn("+ DELETE /api/v1/admin/users/{param}", out.getvalue())
            out = io.StringIO()
            with redirect_stdout(out):
                cli.main(["scan", self.base + "/", "--json"])
            self.assertEqual(json.loads(out.getvalue())["tool"], "deepjs")

    def test_unreachable_target_is_reported_not_raised(self):
        r = Engine(Options(timeout=2)).run(["http://127.0.0.1:9/", "does-not-exist.js"])
        self.assertEqual(len(r.errors), 2)


if __name__ == "__main__":
    unittest.main()
