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

AWS_KEY = "AKIA" + "Q7ZP2MXL4RT9VB6N"
STRIPE_PK = "pk_" + "live_9aK2mQ7xL4pR8tY1wZ6nC3vB"
CLIENT_SECRET = "Zx9Qm2Lk8Pz4Rt6V" + "w1Yb5Nc7Hf0Jg3Ua"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

INDEX = """<!doctype html><html><head><title>Acme</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEF1234"></script>
<script>window.__CONFIG__ = {apiBase: "/api/v1", featureFlagsUrl: "/api/v1/flags"};</script>
</head><body><div id="root"></div>
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

FILES = {
    "index.html": INDEX,
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
    def log_message(self, *args):
        pass


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
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.sources = os.path.join(cls.tmp.name, "recovered")
        cls.result = Engine(Options(sources_dir=cls.sources)).run([cls.base + "/"])
        cls.calls = {(e.method, e.url) for e in cls.result.endpoints if e.is_call}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def test_no_errors(self):
        self.assertEqual(self.result.errors, [])

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
