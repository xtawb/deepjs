#!/usr/bin/env python3
"""
Are the two engines the same engine?

The Burp extension runs a Java port of this repository's Python analysis
engine. This script feeds identical input to both — over the same line
protocol (`deepjs serve` / `deepjs.engine.Serve`) — and compares everything
they report, record for record.

    python burp/parity.py --classpath burp/build/classes                  # the built-in inputs
    python burp/parity.py --classpath burp/build/classes DIR [DIR …]      # plus real applications

Built-in inputs: every snippet of the accuracy corpus and the fixture
application of the end-to-end tests. Each DIR is one application: its .js,
.html and .map files are fed in name order as responses from one site.

Exit status 0 only when no record differs.
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import shutil
import subprocess
import sys
from collections import Counter
from typing import Dict, Iterable, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.environ.setdefault("DEEPJS_NO_UPDATE_CHECK", "1")

from deepjs import corpus                                   # noqa: E402
from deepjs.serve import Worker, esc                        # noqa: E402

Request = Tuple[str, str, bytes]                            # kind, url, body


def builtin_inputs() -> Dict[str, List[Request]]:
    sets: Dict[str, List[Request]] = {}
    snippets: List[Request] = []
    for group in (corpus.POSITIVE, corpus.NEGATIVE, corpus.HOLDOUT_POSITIVE, corpus.HOLDOUT_NEGATIVE):
        for n, case in enumerate(group):
            code = case[1] if isinstance(case, (tuple, list)) else case
            snippets.append(("script", f"https://corpus.test/{len(snippets):03d}-{n}.js", str(code).encode("utf-8")))
    sets["accuracy corpus"] = snippets

    sys.path.insert(0, os.path.join(ROOT, "tests"))
    try:
        import test_e2e                                     # the fixture application of the end-to-end tests
        files = dict(test_e2e.FILES)
        base = "https://fixture.test"
        requests: List[Request] = []
        for rel in sorted(files):
            kind = "html" if rel.endswith((".html", ".htm")) else "map" if rel.endswith(".map") else "script"
            if rel.endswith((".js", ".html", ".map")):
                requests.append((kind, f"{base}/{rel}", files[rel].encode("utf-8")))
        sets["end-to-end fixture"] = requests
    except Exception as exc:                                # the tests directory is optional for this script
        print(f"  (end-to-end fixture not loaded: {type(exc).__name__}: {exc})")
    sets["generated shapes"] = generated_inputs()
    return sets


def generated_inputs() -> List[Request]:
    """
    Shapes the corpus and the fixture do not reach: every credential format, the
    JWT classes, key-name semantics, HTML forms and base tags, indexed source
    maps, odd URLs, every host class. Values are made here from a seeded
    generator — nothing credential-shaped is stored in the repository.
    """
    import json
    import random
    import string

    rnd = random.Random(20261010)
    upper, lower, digits = string.ascii_uppercase, string.ascii_lowercase, string.digits
    alnum, hexd, url64 = upper + lower + digits, "0123456789abcdef", upper + lower + digits + "_-"

    def pick(alphabet: str, n: int) -> str:
        return "".join(rnd.choice(alphabet) for _ in range(n))

    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    def jwt(payload: dict, alg: str = "HS256", sig: bool = True) -> str:
        return f"{b64({'alg': alg, 'typ': 'JWT'})}.{b64(payload)}.{pick(url64, 43) if sig else ''}"

    typed = [
        "AK" + "IA" + pick(upper + digits, 16), "AI" + "za" + pick(url64, 35), "GOC" + "SPX-" + pick(url64, 28),
        "ya" + "29." + pick(url64, 60), "gh" + "p_" + pick(alnum, 36), "github" + "_pat_" + pick(alnum, 22) + "_" + pick(alnum, 59),
        "gl" + "pat-" + pick(url64, 20), "xo" + "xb-" + pick(digits, 11) + "-" + pick(digits, 12) + "-" + pick(alnum, 24),
        "https://hooks.slack" + ".com/services/T" + pick(upper + digits, 9) + "/B" + pick(upper + digits, 9) + "/" + pick(alnum, 24),
        "https://discord" + ".com/api/webhooks/" + pick(digits, 18) + "/" + pick(url64, 60),
        "sk" + "_live_" + pick(alnum, 24), "rk" + "_test_" + pick(alnum, 24), "pk" + "_live_" + pick(alnum, 24),
        "sk-" + "proj-" + pick(url64, 48), "sk-" + "ant-" + pick(url64, 60), "SG" + "." + pick(url64, 22) + "." + pick(url64, 43),
        pick(hexd, 32) + "-us" + pick(digits, 1), "S" + "K" + pick(hexd, 32), "npm" + "_" + pick(alnum, 36), "hf" + "_" + pick(alnum, 36),
        "dop" + "_v1_" + pick(hexd, 64), "shp" + "at_" + pick(hexd, 32), pick("123456789", 9) + ":A" + "A" + pick(url64, 33),
        "sq0" + "atp-" + pick(url64, 22), "access" + "_token$production$" + pick(lower + digits, 16) + "$" + pick(hexd, 32),
        "EA" + "A" + pick(alnum, 90), "sk" + ".eyJ" + pick(url64, 40) + "." + pick(url64, 22), "pk" + ".eyJ" + pick(url64, 40) + "." + pick(url64, 22),
        "https://" + pick(hexd, 32) + "@o1.ingest.sentry" + ".io/42", "6L" + pick(url64, 38), "-----BEGIN RSA PRIVATE" + " KEY-----",
        "DefaultEndpointsProtocol=https;AccountName=acme;Account" + "Key=" + pick(alnum + "+/", 86) + "==",
        "postgres://app:" + pick(alnum, 14) + "@db.internal.acme.io:5432/app", "Bearer " + pick(url64, 40),
        "Basic " + base64.b64encode(("svc:" + pick(alnum, 16)).encode()).decode(), "Basic " + base64.b64encode(b"user:password").decode(),
        jwt({"sub": "1", "exp": 1500000000}), jwt({"sub": "1", "exp": 4102444800, "iss": "https://auth.acme.io"}), jwt({"sub": "1"}),
        jwt({"sub": "1"}, alg="none", sig=False), jwt({"iss": "supabase", "ref": "abcd", "role": "anon", "exp": 4102444800}),
        jwt({"iss": "supabase", "ref": "abcd", "role": "service_role", "exp": 4102444800}), jwt({"role": 5, "exp": "soon", "iss": ["x"]}),
    ]
    semantic = [
        ("clientSecret", pick(alnum, 32)), ("apiKey", pick(hexd, 32)), ("password", "Password"), ("password", "hunter2-" + pick(alnum, 6)),
        ("testingPassword", "Iam" + "Used" + "For" + "Checking"), ("authToken", "auth_token"), ("apiKey", "YOUR_API_KEY"),
        ("secretKey", pick(alnum + "!@#$", 20)), ("token", pick(url64, 40)), ("signature", "Lookup(address,string[],bytes)"),
        ("tokenData", pick(alnum + "$%~", 60)), ("sessionKey", pick(alnum, 30)), ("X-Api-Key", pick(alnum, 28)), ("salt", pick(hexd, 24)),
        ("passwordPlaceholder", "Enter your password"), ("refreshToken", "Bearer " + pick(url64, 30)), ("privateKey", "0x" + pick(hexd, 64)),
        ("access_key_secret", pick(alnum, 40)), ("pwd", "p4ssw0rd"), ("credentials", "omit"), ("api_secret", "changeme"),
        ("key", pick(alnum, 40)), ("id", pick(hexd, 40)), ("nonce", pick(alnum, 20)), ("licenseKey", pick(upper + digits + "-", 29)),
    ]
    q = json.dumps
    lines = [f"var t{n}={q(v)};" for n, v in enumerate(typed)]
    lines += [f"cfg.s{n}={{{q(k)}:{q(v)}}};" for n, (k, v) in enumerate(semantic)]
    lines += [
        f"firebase.initializeApp({{apiKey:{q('AI' + 'za' + pick(url64, 35))},authDomain:'acme.firebaseapp.com',projectId:'acme'}});",
        f"docsearch({{appId:'B1G2H3',apiKey:{q(pick(hexd, 32))},indexName:'docs'}});",
        f"// staging key {'AK' + 'IA' + pick(upper + digits, 16)} do not ship",
        f"/* twilio */ new Twilio.Device({q('S' + 'K' + pick(hexd, 32))});",
        f"xhr.setRequestHeader('Authorization',{q('Bearer ' + pick(url64, 44))});h.append(\"X-Api-Key\",{q(pick(alnum, 30))});",
        "const hosts=['https://acme-assets.s3.amazonaws.com/a','https://storage.googleapis.com/b','//10.0.0.8:8443/x',"
        "'https://dev.api.generated.test/v1','https://files.acme.blob.core.windows.net/c','http://localhost:3000/z',"
        "'https://billing.corp/q','wss://live.generated.test:9443/ws','https://x.r2.dev/k','generated.test','192.168.1.300'];",
        "fetch('//cdn.generated.test/v2/items?x=1&y[]=2#top');fetch(`${API_ROOT}/v1/users/${u.id}/roles?expand=perm`);"
        "fetch('../relative/thing');fetch('./api/local');axios.get('https://user:pw@secret.generated.test/a');",
        "const r=new XMLHttpRequest;r.open('put','/api/x/'+encodeURIComponent(name)+'/y');navigator.sendBeacon('/beacon?e=1');"
        "new WebSocket('wss://ws.generated.test/socket');new EventSource(`/events/${room}`);",
        "router.push('/settings/profile');h(Link,{to:'/billing?tab=1'});const routes=[{path:'users/:id',component:U},{path:'**',redirectTo:'/'}];",
        "const Q=`query ListOrders($n:Int){orders(first:$n){id}} mutation CancelOrder($id:ID!){cancel(id:$id){ok}}`;",
        "$.ajax({url:'/legacy/save.php',type:'post',data:{a:1,b:2}});$.getJSON('/legacy/list.json',{page:1});request({uri:base+'/v3/ping'});",
        "let s='it\\'s \\u0041\\x42\\u{1F600}\\ud83d\\ude00\\ud800 \\q\\0';let re=/[/\\]]+\\/\\d/gi.test(s)?a/b/c:x++ / y;",
    ]
    script = "\n".join(lines).encode("utf-8")

    page = (
        "<!doctype html><html><head><base href='/app/'><link rel=modulepreload href=\"chunks/a.js\">"
        "<link rel='preload' as='script' href='/static/b.js?v=2'><link rel=stylesheet href=x.css>"
        "<script src=main.js></script><script src=\"//www.googletagmanager.com/gtm.js\"></script>"
        "<script src='https://cdn.generated.test/lib.js'></script><script type='text/template'><b>{{x}}</b></script>"
        "<script>window.__CFG__={apiUrl:'https://api.generated.test/v2',routes:['/a']};fetch('/api/boot?lang=en')</script></head><body>"
        "<form action='search?q=1&amp;sort=asc#r'><input name=term><select name='cat'></select></form>"
        "<form method=post action='https://pay.generated.test/charge'><input name=\"card\"><textarea name=note></textarea>"
        "<button name='go'></button></form><form method='dialog'><input name=x></form><form action='javascript:void(0)'><input name=y></form>"
        "</body></html>"
    ).encode("utf-8")

    source_map = json.dumps({
        "version": 3, "sourceRoot": "webpack://",
        "sections": [{"offset": {"line": 0, "column": 0}, "map": {
            "version": 3, "sources": ["webpack:///./src/api/users.ts", "webpack:///./node_modules/@acme-internal/sdk/index.js"],
            "sourcesContent": ["export const del = (id: string) => http.delete<void>(`/api/v9/users/${id}`);\n// TODO remove", "x"]}}],
        "sources": ["../../src/../etc/pass wd?.ts", "C:\\\\work\\\\app\\\\src\\\\cfg.ts", "webpack/bootstrap", "./src/a.ts", "./src/a.ts", "", 7],
        "sourcesContent": ["fetch('/api/v9/escape')", "export const k = '/api/v9/cfg';", "boot()", "post('/api/v9/a')", None, "z"],
    }).encode("utf-8")

    base = "https://generated.test"
    inline_map = base64.b64encode(json.dumps({"version": 3, "sources": ["src/inline.ts"],
                                              "sourcesContent": ["api.patch('/api/v9/inline', {on: true})"]}).encode()).decode()
    with_inline = ("fetch('/api/v9/outer');\n//# sourceMappingURL=data:application/json;charset=utf-8;base64," + inline_map + "\n").encode()
    return [
        ("script", base + "/static/shapes.js", script),
        ("auto", base + "/app/index.html", page),
        ("html", base + "/deep/er/page", page),
        ("map", base + "/static/shapes.js.map", source_map),
        ("script", base + "/static/inline.js?v=3", with_inline),
        ("auto", base + "/static/empty.js", b""),
        ("auto", base + "/static/junk.js", bytes(range(256)) * 4 + b"\xff\xfe{{{`${`"),
        ("script", "https://www.google-analytics.com/analytics.js", b"fetch('/collect')"),
        ("map", base + "/static/not-a-map.js.map", b"<html>404</html>"),
    ]


def directory_input(path: str) -> List[Request]:
    name = os.path.basename(os.path.normpath(path)).lower().replace("_", "-") or "app"
    base = f"https://{name}.test"
    requests: List[Request] = []
    for entry in sorted(os.listdir(path)):
        full = os.path.join(path, entry)
        if not os.path.isfile(full) or not entry.lower().endswith((".js", ".mjs", ".html", ".htm", ".map")):
            continue
        kind = "html" if entry.lower().endswith((".html", ".htm")) else "map" if entry.lower().endswith(".map") else "script"
        with open(full, "rb") as fh:
            requests.append((kind, f"{base}/{entry}", fh.read()))
    return requests


def lines_for(ident: str, kind: str, url: str, body: bytes) -> str:
    return "\t".join(["A", ident, kind, esc(url), base64.b64encode(body).decode("ascii")]) + "\n"


def python_engine(requests: Iterable[Request]) -> List[List[str]]:
    out = io.StringIO()
    worker = Worker(out)
    answers: List[List[str]] = []
    for n, (kind, url, body) in enumerate(requests):
        out.seek(0)
        out.truncate()
        worker.handle(lines_for(str(n), kind, url, body))
        answers.append(out.getvalue().splitlines())
    return answers


class JavaEngine:
    def __init__(self, classpath: str) -> None:
        java = shutil.which("java")
        home = os.environ.get("JAVA_HOME")
        if home and os.path.isfile(os.path.join(home, "bin", "java" + (".exe" if os.name == "nt" else ""))):
            java = os.path.join(home, "bin", "java" + (".exe" if os.name == "nt" else ""))
        if not java:
            sys.exit("parity: `java` not found — put a JDK 17+ on PATH or set JAVA_HOME")
        self.proc = subprocess.Popen([java, "-Xss16m", "-cp", classpath, "deepjs.engine.Serve"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        ready = self.proc.stdout.readline().decode("utf-8").rstrip("\n").split("\t")
        if ready[:2] != ["READY", "deepjs"]:
            sys.exit(f"parity: the Java engine did not start: {ready}")
        self.version = ready[2] if len(ready) > 2 else "?"

    def run(self, requests: Iterable[Request]) -> List[List[str]]:
        self.proc.stdin.write(b"RESET\n")
        self.proc.stdin.flush()
        self.proc.stdout.readline()                         # OK
        answers: List[List[str]] = []
        for n, (kind, url, body) in enumerate(requests):
            self.proc.stdin.write(lines_for(str(n), kind, url, body).encode("utf-8"))
            self.proc.stdin.flush()
            lines: List[str] = []
            while True:
                raw = self.proc.stdout.readline()
                if not raw:
                    sys.exit("parity: the Java engine exited unexpectedly")
                line = raw.decode("utf-8").rstrip("\n")
                lines.append(line)
                if line == f"D\t{n}":
                    break
            answers.append(lines)
        return answers

    def close(self) -> None:
        try:
            self.proc.stdin.write(b"QUIT\n")
            self.proc.stdin.close()
            self.proc.wait(timeout=10)
        except Exception:
            self.proc.kill()


def compare(name: str, requests: List[Request], py: List[List[str]], jv: List[List[str]], show: int) -> int:
    different = records = 0
    shown = 0
    for (kind, url, _), a, b in zip(requests, py, jv):
        records += len(a)
        only_py, only_java = Counter(a) - Counter(b), Counter(b) - Counter(a)
        if not only_py and not only_java:
            continue
        different += sum(only_py.values()) + sum(only_java.values())
        if shown < show:
            shown += 1
            print(f"    {url}")
            for line in list(only_py)[:6]:
                print(f"      python only: {line[:230]}")
            for line in list(only_java)[:6]:
                print(f"      java only:   {line[:230]}")
    size = sum(len(body) for _, _, body in requests) / 1e6
    verdict = "identical" if not different else f"{different} record(s) differ"
    print(f"  {name}: {len(requests)} file(s), {size:.1f} MB, {records} record(s) — {verdict}")
    return different


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--classpath", required=True, help="where deepjs.engine.Serve is: a classes directory or the built jar")
    ap.add_argument("--show", type=int, default=5, help="differing files to print per input set (default 5)")
    ap.add_argument("dirs", nargs="*", help="directories of real application files")
    args = ap.parse_args()

    sets = builtin_inputs()
    for d in args.dirs:
        sets[os.path.basename(os.path.normpath(d))] = directory_input(d)

    java = JavaEngine(args.classpath)
    from deepjs import __version__
    print(f"python engine {__version__}, java engine {java.version}")
    total = 0
    try:
        for name, requests in sets.items():
            if requests:
                total += compare(name, requests, python_engine(requests), java.run(requests), args.show)
    finally:
        java.close()
    if java.version != __version__:
        print(f"  versions differ: python {__version__}, java {java.version}")
        total += 1
    print("parity: " + ("the engines agree on every record" if not total else f"{total} difference(s)"))
    return 0 if not total else 1


if __name__ == "__main__":
    sys.exit(main())
