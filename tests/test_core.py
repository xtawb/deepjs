"""Tokenizer, expression evaluation, endpoint extraction, secrets, hosts, source maps, chunk maps."""

import base64
import json
import os
import tempfile
import time
import unittest

from deepjs import chunks, corpus, sourcemap
from deepjs.endpoints import extract
from deepjs.entropy import classify, is_placeholder
from deepjs.hosts import HostCollector, classify_host, registrable
from deepjs.jseval import Program, render
from deepjs.lexer import ID, REGEX, STR, TPL, tokenize, unescape
from deepjs.secrets import inspect_jwt, key_strength, scan_program

# Credential-shaped test values are synthetic and assembled at runtime.
RANDOM_32 = "Zx9Qm2Lk8Pz4Rt6V" + "w1Yb5Nc7Hf0Jg3Ua"


def jwt(payload, alg="HS256", sig="c2lnbmF0dXJlX2J5dGVzXzEyMzQ1"):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': alg, 'typ': 'JWT'})}.{enc(payload)}.{sig}"


def endpoints(code):
    return {(e.method, e.url) for e in extract(Program(code)).endpoints}


def calls(code):
    return {(e.method, e.url) for e in extract(Program(code)).endpoints if e.is_call}


def secret_kinds(code, **kw):
    return {s.kind for s in scan_program(Program(code), "t.js", **kw)}


class LexerTests(unittest.TestCase):
    def test_strings_are_decoded(self):
        toks = tokenize(r"""var a = 'it\'s \u0041\x42', b = "tab\there";""").tokens
        self.assertEqual([t[1] for t in toks if t[0] == STR], ["it's AB", "tab\there"])
        self.assertEqual(unescape(r"\ud83d\ude00"), "\U0001F600")           # surrogate pair → one code point

    def test_regex_versus_division(self):
        toks = tokenize("var r = /ab+c\\/d/gi, x = a / b / c; if (x) /re/.test(y)").tokens
        self.assertEqual([t[1] for t in toks if t[0] == REGEX], ["/ab+c\\/d/gi"])
        toks = tokenize('return /\\/api\\/(\\d+)/.exec(u)').tokens
        self.assertEqual(len([t for t in toks if t[0] == REGEX]), 1)

    def test_comments_are_not_tokens(self):
        lexed = tokenize('// "/api/a"\n/* "/api/b" */ var x = "/api/c";')
        self.assertEqual([t[1] for t in lexed.tokens if t[0] == STR], ["/api/c"])
        self.assertEqual(len(lexed.comments), 2)

    def test_template_segments_and_nesting(self):
        toks = tokenize("x = `a/${b}/c/${fn({k: `in${1}`})}/d`").tokens
        tpl = [t for t in toks if t[0] == TPL][0][1]
        self.assertEqual(tpl[0], "a/")
        self.assertEqual(tpl[1], ("expr", "b"))
        self.assertEqual(tpl[-1], "/d")

    def test_malformed_input_never_raises(self):
        for junk in ("", "'unterminated", "`unterminated ${", "/* never closed", "}}}])){{{", "\x00\x01\x02<<<>>>",
                     "var a = '" + "x" * 5000):
            tokenize(junk)                                                  # must not raise
            Program(junk)

    def test_bracket_pairs_survive_imbalance(self):
        lexed = tokenize("f({a: [1, 2}, 3)")
        self.assertEqual(lexed.pairs[1], len(lexed.tokens) - 1)             # ( … )

    def test_speed(self):
        src = "function f(a){return fetch('/api/x/'+a)};var k={a:1,b:'str',c:[1,2,3]};" * 12000
        t0 = time.perf_counter()
        p = Program(src)
        self.assertGreater(p.n, 300000)
        self.assertLess(time.perf_counter() - t0, 20)


class EvalTests(unittest.TestCase):
    def build(self, code, needle):
        p = Program(code)
        for i, t in enumerate(p.tokens):
            if t[0] in (STR, TPL) and needle in (t[1] if t[0] == STR else "".join(s for s in t[1] if isinstance(s, str))):
                parts, _ = p.eval_expr(p.expr_start(i))
                return render(parts)
        self.fail("needle not found")

    def test_concatenation_and_constants(self):
        self.assertEqual(self.build('const A="https://x.io";var u=A+"/v1/users/"+id;', "/v1/users/"),
                         "https://x.io/v1/users/{id}")

    def test_template_literal(self):
        self.assertEqual(self.build("const A='/api';u=`${A}/o/${order.id}/i/${encodeURIComponent(sku)}`", "/o/"),
                         "/api/o/{id}/i/{sku}")

    def test_babel_concat(self):
        p = Program('u="".concat(base,"/items/").concat(n,"/detail")')
        first = next(i for i, t in enumerate(p.tokens) if t[0] == STR)
        self.assertEqual(render(p.eval_expr(first)[0]), "{base}/items/{param}/detail")

    def test_minified_names_are_not_resolved_across_scopes(self):
        # `e` is a string in one function and a parameter in another: resolving it would invent a URL
        code = 'function a(){var e="/wrong";return e}function b(e){return fetch("/api/"+e)}'
        self.assertEqual(endpoints(code) & {("GET", "/api/{param}")}, {("GET", "/api/{param}")})
        self.assertNotIn(("GET", "/api//wrong"), endpoints(code))

    def test_object_and_args(self):
        p = Program('f(a, {x: 1, "y": [1,2], z(){}, ...rest, w}, g(1,2))')
        args = p.call_args(1)
        self.assertEqual(len(args), 3)
        self.assertEqual(sorted(p.object_at(args[1][0]).keys()), ["w", "x", "y"])


class EndpointTests(unittest.TestCase):
    def test_request_details(self):
        code = ('fetch(API+"/auth/login?next="+n,{method:"POST",headers:{"Content-Type":"application/json",'
                'Authorization:"Bearer "+t},body:JSON.stringify({email:e,password:p})})')
        ep = extract(Program(code)).endpoints[0]
        self.assertEqual((ep.method, ep.url), ("POST", "{API}/auth/login"))
        self.assertEqual(ep.params, ["next"])
        self.assertEqual(ep.body, ["email", "password"])
        self.assertEqual(ep.headers, ["Content-Type", "Authorization"])

    def test_axios_params_and_body(self):
        ex = extract(Program('http.get("/users",{params:{page:1,q:s}});http.put("/users/"+id,{name:n,role:r})'))
        by = {e.method: e for e in ex.endpoints}
        self.assertEqual(by["GET"].params, ["page", "q"])
        self.assertEqual(by["PUT"].body, ["name", "role"])

    def test_string_upgraded_to_call(self):
        eps = endpoints('var E={u:"/api/v2/users"};fetch(E.u,{method:"DELETE"})')
        self.assertEqual(eps, {("DELETE", "/api/v2/users")})                # not also listed as a bare string

    def test_graphql_routes_and_bases(self):
        ex = extract(Program(
            'const Q=gql`query GetViewer($id: ID!) { viewer(id:$id){id} }`;'
            'const M="mutation UpdateEmail($e:String!){ updateEmail(email:$e){ok} }";'
            'const r=[{path:"/admin/users",component:A},{path:"billing/:id",element:B}];router.push("/settings");'
            'axios.create({baseURL:"https://api.acme.io/v2"})'))
        self.assertEqual(ex.graphql, [("mutation", "UpdateEmail"), ("query", "GetViewer")])
        self.assertEqual(ex.routes, ["/admin/users", "/billing/:id", "/settings"])
        self.assertEqual(ex.bases, ["https://api.acme.io/v2"])

    def test_credentials_in_url_are_not_an_endpoint(self):
        self.assertEqual(endpoints('var d="postgres://u:' + 'Qm7pLx92vRt4zK' + '@db.acme.io/x"'), set())

    def test_corpus_gate(self):
        r = corpus.score(corpus.deepjs_extractor)
        self.assertGreaterEqual(r["url_recall"], 0.94, r["missed"])
        self.assertGreaterEqual(r["method_accuracy"], 0.90, r["missed"])
        self.assertLessEqual(len(r["false_positives"]), 1, r["false_positives"])

    def test_holdout_gate(self):
        r = corpus.score(corpus.deepjs_extractor, corpus.HOLDOUT_POSITIVE, corpus.HOLDOUT_NEGATIVE)
        self.assertGreaterEqual(r["url_recall"], 0.90, r["missed"])
        self.assertGreaterEqual(r["method_accuracy"], 0.85, r["missed"])
        self.assertLessEqual(len(r["false_positives"]), 1, r["false_positives"])

    def test_typescript_generics_and_navigation_props(self):
        self.assertEqual(endpoints("this.http.post<User>(`${environment.apiUrl}/users`, body)"),
                         {("POST", "{apiUrl}/users")})
        ex = extract(Program('h(Link,{to:"/profile/settings"});h("a",{href:"/pricing"})'))
        self.assertEqual((ex.endpoints, ex.routes), ([], ["/pricing", "/profile/settings"]))

    def test_this_properties_resolve_inside_their_own_class(self):
        # Angular / esbuild: every service has its own `host`, built from a shared base
        code = ('const env={production:!0,hostServer:"."};'
                'var A=(()=>{class t{http=inject(H);hostServer=env.hostServer;host=this.hostServer+`/api/Feedbacks`;'
                'find(a){return this.http.get(this.host+`/`,{params:a})}'
                'del(a){return this.http.delete(`${this.host}/${a}`)}}return t})();'
                'var B=(()=>{class t{http=inject(H);hostServer=env.hostServer;host=this.hostServer+`/rest/products`;'
                'get(e){return this.http.get(`${this.host}/${e}/reviews`)}}return t})();')
        self.assertEqual(calls(code), {("GET", "./api/Feedbacks/"), ("DELETE", "./api/Feedbacks/{param}"),
                                           ("GET", "./rest/products/{param}/reviews")})
        # constructor assignments, TypeScript's ES5 output (constructor function + prototype methods)
        self.assertEqual(calls('class S{constructor(h){this.http=h;this.base="/api/v3/orders"}'
                                   'one(id){return this.http.get(this.base+"/"+id)}}'),
                         {("GET", "/api/v3/orders/{id}")})
        es5 = ('var U=function(){function f(h){this.http=h;this.url="/api/users"}'
               'f.prototype.all=function(){return this.http.get(this.url)};return f}();'
               'var O=function(){function f(h){this.http=h;this.url="/api/orders"}'
               'f.prototype.all=function(){return this.http.get(this.url)};return f}();')
        self.assertEqual(calls(es5), {("GET", "/api/users"), ("GET", "/api/orders")})

    def test_this_properties_are_never_guessed(self):
        # two assignments in one class, a value from a parameter, a base from elsewhere: left unresolved
        self.assertEqual(calls('class S{constructor(h,u){this.http=h;this.base="/api/a"}'
                                   'swap(){this.base="/api/b"}one(){return this.http.get(this.base+"/x")}}'),
                         {("GET", "{base}/x")})
        self.assertEqual(calls('class S{constructor(h,u){this.http=h;this.base=u}'
                                   'one(){return this.http.get(this.base+"/items")}}'), {("GET", "{base}/items")})
        self.assertEqual(calls('class A{base="/api/a"}class B{constructor(h){this.http=h}'
                                   'one(){return this.http.get(this.base+"/items")}}'), {("GET", "{base}/items")})

    # Each of the next five tests is a pattern DeepJS 0.2.0 missed in the comparison with JS Miner
    # on real applications (OWASP Juice Shop and RealWorld front-ends).

    def test_local_variables_are_followed(self):
        code = ('class W{http=inject(H);host="/rest/web3";'
                'submitKey(t){let r=this.host+`/submitKey`,n={privateKey:t};return this.http.post(r,n)}'
                'verify(t){let r=this.host+`/walletNFTVerify`,n={walletAddress:t};return this.http.post(r,n)}}')
        eps = {(e.method, e.url): e for e in extract(Program(code)).endpoints if e.is_call}
        self.assertEqual(set(eps), {("POST", "/rest/web3/submitKey"), ("POST", "/rest/web3/walletNFTVerify")})
        self.assertEqual(eps[("POST", "/rest/web3/submitKey")].body, ["privateKey"])
        # a parameter of the same name in between, or `+=`, and the value is no longer known
        self.assertEqual(calls('let u="/api/a";items.forEach(u=>fetch(u+"/x"))'), {("GET", "{param}/x")})
        self.assertEqual(calls('function f(){let u="/api/a";u+="/b";return fetch(u)}'), set())

    def test_conditional_pieces_give_one_endpoint_per_branch(self):
        self.assertEqual(calls('api.get("/articles"+("feed"===t.type?"/feed":""),{params:q})'),
                         {("GET", "/articles"), ("GET", "/articles/feed")})
        self.assertEqual(calls('api.post("/users"+("login"===t?"/login":""),{user:n})'),
                         {("POST", "/users"), ("POST", "/users/login")})
        self.assertEqual(calls('function f(a){const u=a?"/api/v2/items/archived":"/api/v2/items";return fetch(u)}'),
                         {("GET", "/api/v2/items/archived"), ("GET", "/api/v2/items")})
        # an optional query string held in a variable
        eps = extract(Program('class U{http=inject(H);who(e){let t=e&&e.length>0?`?fields=${e.join(",")}`:``;'
                              'return this.http.get("/rest/user/whoami"+t)}}')).endpoints
        self.assertEqual([(e.method, e.url, e.params) for e in eps if e.is_call], [("GET", "/rest/user/whoami", ["fields"])])

    def test_request_configs_without_a_fixed_method(self):
        self.assertEqual(calls('const d=await Qe({headers:i,method:r?"DELETE":"POST",url:`api/articles/${a}/favorite`})'),
                         {("DELETE", "api/articles/{param}/favorite"), ("POST", "api/articles/{param}/favorite")})
        self.assertEqual(calls('const d=await Qe({headers:i,url:`api/profiles/${a}`})'), {("GET", "api/profiles/{param}")})
        self.assertEqual(calls('this.$axios.$get("/articles/feed",{params:{limit:r}});o.$post("/articles",{article:t})'),
                         {("GET", "/articles/feed"), ("POST", "/articles")})

    def test_api_client_wrappers_give_a_base_not_an_endpoint(self):
        ex = extract(Program('const env={api_url:"https://conduit.acme.io/api"};'
                             'class Api{get(p){return this.http.get(`${env.api_url}${p}`)}}'
                             'svc.get("/articles/"+slug)'))
        self.assertEqual({(e.method, e.url) for e in ex.endpoints if e.is_call}, {("GET", "/articles/{slug}")})
        self.assertEqual(ex.bases, ["https://conduit.acme.io/api"])
        self.assertEqual(calls('http.put("https://svc.acme.io/thing/"+id,b)'), {("PUT", "https://svc.acme.io/thing/{id}")})

    def test_a_class_method_called_fetch_is_not_the_fetch_api(self):
        # ethers' EtherscanProvider: this.fetch("account", {action: "balance"})
        self.assertEqual(calls('class P{b(t){return this.fetch("account",{action:"balance",address:t})}}'), set())
        self.assertEqual(calls('class P{b(t){return this.fetch("/api/account/"+t)}}'), {("GET", "/api/account/{param}")})

    def test_strings_that_only_look_like_urls(self):
        # URL-parser tests in polyfills, regex fragments, schema paths of a JSON validator
        noise = ('var a="https://a",b="http://f",c="https://a/c%20d",d="/a/b",e="/(.+",'
                 'f=errSchemaPath+"/additionalItems",g=e+"/d",h="https://"+x+y;')
        self.assertEqual(endpoints(noise), set())
        kept = 'var a="https://api.acme.io/v2/users",b=apiBase+"/orders",c="/internal/reports/export",d="http://localhost:3000/api";'
        self.assertEqual(endpoints(kept), {("", "https://api.acme.io/v2/users"), ("", "{apiBase}/orders"),
                                           ("", "/internal/reports/export"), ("", "http://localhost:3000/api")})
        # the same shapes as the argument of a request are still reported
        self.assertEqual(calls('fetch("https://"+host+"/v1/items");fetch(root+"/d")'),
                         {("GET", "https://{host}/v1/items"), ("GET", "{root}/d")})

    def test_structure_beats_regex(self):
        ours, base = corpus.score(corpus.deepjs_extractor), corpus.score(corpus.regex_baseline)
        self.assertGreater(ours["url_recall"], base["url_recall"])
        self.assertLess(len(ours["false_positives"]), len(base["false_positives"]))


class SecretTests(unittest.TestCase):
    def test_typed_tokens(self):
        cases = {
            "AWS_ACCESS_KEY": "AKIA" + "Q7ZP2MXL4RT9VB6N",
            "STRIPE_SECRET_KEY": "sk_" + "live_" + "9aK2mQ7xL4pR8tY1wZ6nC3vB",
            "GITHUB_TOKEN": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
            "OPENAI_API_KEY": "sk-" + "proj-" + "aB3xK9mQ2pL7vR4tY8wZ1nC6dE0fG5hJ2kM8nP4qS7tV1x",
            "SLACK_TOKEN": "xox" + "b-" + "2048161234-" + "7Hq2LmN9pRsT4vWx",
        }
        for kind, value in cases.items():
            found = scan_program(Program(f'var k="{value}";'), "t.js")
            self.assertEqual([s.kind for s in found], [kind])
            self.assertNotIn(value, json.dumps(found[0].to_dict()))         # masked by default
            self.assertIn(value, json.dumps(found[0].to_dict(reveal=True)))

    def test_public_by_design_is_not_a_leak(self):
        code = ('const firebaseConfig={apiKey:"AIza' + 'SyD3x7Qm2Lk9Pz4Rt6Vw8Yb1Nc5Hf0Jg3Ua",authDomain:"a.firebaseapp.com",projectId:"a"};'
                'var s="pk_' + 'live_9aK2mQ7xL4pR8tY1wZ6nC3vB";'
                'var d="https://0123456789abcdef0123456789abcdef@o1.ingest.sentry.io/42";')
        found = scan_program(Program(code), "t.js")
        self.assertEqual({s.kind for s in found}, {"FIREBASE_WEB_CONFIG", "STRIPE_PUBLISHABLE_KEY", "SENTRY_DSN"})
        self.assertTrue(all(s.public and s.severity == "info" for s in found))

    def test_algolia_search_key_is_public_by_design(self):
        hex32 = "9f2c71ab04de38c5" + "6b1e0a7d43f859c2"          # synthetic
        found = scan_program(Program('var cfg={algolia:{appId:"1FCF9AYYAT",apiKey:"%s",indexName:"docs"}}' % hex32), "t.js")
        self.assertEqual([(s.kind, s.severity, s.public) for s in found], [("ALGOLIA_SEARCH_KEY", "info", True)])
        # the same value under the same name, without the Algolia siblings, is still a finding
        alone = scan_program(Program('var cfg={apiKey:"%s"}' % hex32), "t.js")
        self.assertEqual([(s.kind, s.public) for s in alone], [("HARDCODED_SECRET", False)])

    def test_passphrase_under_a_password_name(self):
        # found by JS Miner and missed by DeepJS 0.2.0 in OWASP Juice Shop: a test account's password
        phrase = "Iam" + "Used" + "For" + "Checking"
        found = scan_program(Program('class L{testingUsername=`qa@acme.io`;testingPassword=`%s`}' % phrase), "t.js")
        self.assertEqual([(s.kind, s.severity, s.key) for s in found], [("HARDCODED_PASSWORD", "medium", "testingPassword")])
        # labels, field names and messages under the same kind of name stay out
        for value in ("Password", "EnterYourPassword", "passwordComponent", "ForgotPasswordLink", "PleaseConfirmAgain"):
            self.assertEqual(secret_kinds('var f={password:"%s"}' % value), set(), value)

    def test_parser_tables_and_function_signatures_are_not_secrets(self):
        # both reported by DeepJS 0.2.0 in OWASP Juice Shop
        table = "$z~RXOYn" + "!bOX%ZXY+gYZ-yZ[+g[]%Z]^.c^p%Zpq+gqr/mrs3c" + "X~Y~"
        self.assertEqual(secret_kinds('var parser={repeatNodeCount:37,tokenData:"%s",tokenizers:[0,1]}' % table), set())
        self.assertEqual(secret_kinds('throwError("x",{name:"OffchainLookup",signature:"OffchainLookup(address,string[],bytes,bytes4,bytes)"})'), set())

    def test_supabase_roles(self):
        anon = jwt({"iss": "supabase", "ref": "abc", "role": "anon", "exp": int(time.time()) + 10 ** 8})
        svc = jwt({"iss": "supabase", "ref": "abc", "role": "service_role", "exp": int(time.time()) + 10 ** 8})
        self.assertEqual(inspect_jwt(anon)[:3], ("SUPABASE_ANON_KEY", "info", True))
        self.assertEqual(inspect_jwt(svc)[:3], ("SUPABASE_SERVICE_ROLE_KEY", "critical", False))
        self.assertEqual(inspect_jwt(jwt({"sub": "1", "exp": 1000}))[0], "JWT_EXPIRED")
        self.assertEqual(inspect_jwt(jwt({"sub": "1"}))[:2], ("JWT_HARDCODED", "high"))
        self.assertIsNone(inspect_jwt("eyJub3RfanNvbg.eyJub3RfanNvbg.abc"))

    def test_semantic_uses_the_key_name(self):
        self.assertEqual(secret_kinds(f'var c={{clientSecret:"{RANDOM_32}"}}'), {"HARDCODED_SECRET"})
        self.assertEqual(secret_kinds(f'xhr.setRequestHeader("X-Api-Key","{RANDOM_32}")'), {"HARDCODED_SECRET"})
        self.assertEqual(secret_kinds(f'var c={{label:"{RANDOM_32}"}}'), set())
        self.assertEqual(secret_kinds(f'var c={{blob:"{RANDOM_32}"}}'), set())
        self.assertEqual(secret_kinds(f'var c={{blob:"{RANDOM_32}"}}', entropy=True), {"HIGH_ENTROPY_STRING"})

    def test_filler_under_secret_names_is_ignored(self):
        code = ('var f={password:"Password",confirmPassword:"Confirm password",apiKey:"YOUR_API_KEY",'
                'tokenKey:"auth_token",secret:"s3cr3t",token:"",passwordPlaceholder:"Enter your password",'
                'clientId:"' + RANDOM_32 + '",publicKey:"' + RANDOM_32 + '",authToken:process.env.TOKEN}')
        self.assertEqual(secret_kinds(code), set())

    def test_key_strength(self):
        for k in ("clientSecret", "api_key", "X-Api-Key", "Authorization", "dbPassword"):
            self.assertEqual(key_strength(k), 2, k)
        for k in ("publicKey", "siteKey", "clientId", "tokenUrl", "passwordLabel", "storageKey", "nextPageToken", "maxTokens"):
            self.assertEqual(key_strength(k), -1, k)

    def test_url_credentials_and_basic_auth(self):
        self.assertIn("URL_CREDENTIALS", secret_kinds('var d="postgres://app:' + 'Qm7pLx92vRt4zK' + '@db.acme.io:5432/p"'))
        basic = base64.b64encode(b"svc:" + b"Qm7pLx92vRt4zK").decode()
        self.assertIn("BASIC_AUTH", secret_kinds(f'h={{Authorization:"Basic {basic}"}}'))
        self.assertEqual(secret_kinds('var u="https://user:password@example.com/x"'), set())

    def test_secret_in_comment(self):
        tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        found = scan_program(Program(f"// TODO remove {tok}\nvar x=1"), "t.js")
        self.assertEqual([(s.kind, s.key) for s in found], [("GITHUB_TOKEN", "(comment)")])

    def test_classifier(self):
        self.assertTrue(is_placeholder("your_api_key_here") and is_placeholder("p@ssw0rd") and is_placeholder("${TOKEN}"))
        self.assertEqual(classify(RANDOM_32, strong_key=True)[0], "secret")
        for benign in ("Enter your password", "auth_token", "user:profile:updated", "550e8400-e29b-41d4-a716-446655440000",
                       "/static/js/main.3f2a9c1b.js", "M12 2C6.48 2 2 6.48 2 12", "Mot de passe"):
            self.assertIn(classify(benign, strong_key=True)[0], ("benign", "placeholder"), benign)


class HostTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable("a.b.example.com"), "example.com")
        self.assertEqual(registrable("x.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable("app.vercel.app"), "app.vercel.app")

    def test_classification(self):
        scope = {"acme.io"}
        self.assertEqual(classify_host("api.acme.io", scope).kind, "in-scope")
        self.assertTrue(classify_host("staging-api.acme.io", scope).nonprod)
        self.assertEqual(classify_host("acme-uploads.s3.eu-west-1.amazonaws.com", scope).service, "aws-s3")
        self.assertEqual(classify_host("acme.blob.core.windows.net", scope).service, "azure-blob")
        self.assertEqual(classify_host("10.2.3.4", scope).kind, "internal")
        self.assertEqual(classify_host("jenkins.corp", scope).kind, "internal")
        self.assertEqual(classify_host("cdn.other.com", scope).kind, "third-party")

    def test_collector(self):
        hc = HostCollector({"acme.io"})
        for s in ("https://api.acme.io/v1", "wss://rt.acme.io:8443/s", "//cdn.acme.io/x.js", "internal.acme.io",
                  "http://www.w3.org/2000/svg", "not a host", "example.txt", "http://localhost:3000/api"):
            hc.feed(s, "t.js")
        names = {h.name: h for h in hc.sorted()}
        self.assertEqual(set(names), {"api.acme.io", "rt.acme.io", "cdn.acme.io", "internal.acme.io", "localhost"})
        self.assertEqual(names["rt.acme.io"].ports, ["8443"])


class SourceMapTests(unittest.TestCase):
    MAP = {
        "version": 3,
        "sources": ["webpack:///./src/api/client.ts", "webpack:///./node_modules/@acme-internal/ui-kit/index.js",
                    "webpack:///./node_modules/react/index.js", "webpack:///../../../../etc/evil.txt",
                    "webpack:///webpack/bootstrap", "C:\\build\\src\\win.ts"],
        "sourcesContent": ["export const a = fetch('/api/from-source')", "module.exports={}", "x", "pwned", "rt", "w"],
    }

    def test_reference_and_inline(self):
        self.assertEqual(sourcemap.find_map_reference("var a=1;\n//# sourceMappingURL=main.js.map\n"), "main.js.map")
        self.assertIsNone(sourcemap.find_map_reference("var a=1"))
        inline = "data:application/json;base64," + base64.b64encode(json.dumps(self.MAP).encode()).decode()
        self.assertEqual(len(sourcemap.parse_source_map(sourcemap.decode_inline_map(inline)).sources), 6)

    def test_parse_packages_and_app_sources(self):
        m = sourcemap.parse_source_map(json.dumps(self.MAP))
        self.assertEqual(m.packages, {"@acme-internal/ui-kit", "react"})
        self.assertIn("src/api/client.ts", [s.path for s in m.app_sources])
        self.assertNotIn("webpack/bootstrap", [s.path for s in m.app_sources])

    def test_paths_cannot_escape_the_output_directory(self):
        for hostile in ("webpack:///../../../../etc/passwd", "/etc/passwd", "C:\\Windows\\system32\\x.dll",
                        "..\\..\\x", "file:///root/.ssh/id_rsa", "a/../../b", "....//....//x", ""):
            path = sourcemap.safe_relative_path(hostile)
            self.assertFalse(path.startswith(("/", "\\")) or ".." in path.split("/") or ":" in path, (hostile, path))
        m = sourcemap.parse_source_map(json.dumps(self.MAP))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            written, skipped = sourcemap.write_sources(m, out)
            self.assertEqual((written, skipped), (6, 0))
            for dirpath, _, files in os.walk(tmp):
                for f in files:
                    self.assertTrue(sourcemap.is_inside(out, os.path.join(dirpath, f)))
            self.assertEqual(os.listdir(tmp), ["out"])                      # nothing was written beside it

    def test_not_a_map(self):
        for junk in (b"<html>", b"{}", b"[1,2]", b'{"sources": "x"}', b""):
            self.assertIsNone(sourcemap.parse_source_map(junk))


class ChunkTests(unittest.TestCase):
    def test_webpack5_runtime(self):
        rt = ('(()=>{var r={};r.p="/";r.u=e=>"static/js/"+({3:"admin",7:"billing"}[e]||e)+"."+'
              '{3:"9f1c2a",7:"02ab3c",11:"77aa88"}[e]+".chunk.js";r.miniCssF=e=>"static/css/"+e+"."+{3:"aaa"}[e]+".css"})();')
        self.assertEqual(chunks.webpack_chunks(Program(rt)),
                         ["static/js/11.77aa88.chunk.js", "static/js/admin.9f1c2a.chunk.js", "static/js/billing.02ab3c.chunk.js"])
        d = chunks.discover(Program(rt), "https://app.acme.io/static/js/runtime.js")
        self.assertIn("https://app.acme.io/static/js/admin.9f1c2a.chunk.js", d.scripts)

    def test_webpack4_runtime(self):
        rt = 'function jsonpScriptSrc(e){return o.p+""+({0:"vendors",5:"settings"}[e]||e)+"."+{0:"a1",5:"b2",9:"c3"}[e]+".js"}'
        self.assertEqual(sorted(chunks.webpack_chunks(Program(rt))), ["9.c3.js", "settings.b2.js", "vendors.a1.js"])

    def test_next_manifest_and_vite_imports(self):
        manifest = ('self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-1a.js"],'
                    '"/admin/[id]":["static/chunks/pages/admin/[id]-2b.js"]};')
        d = chunks.discover(Program(manifest), "https://x.io/_next/static/BUILD/_buildManifest.js")
        self.assertIn("https://x.io/_next/static/chunks/pages/index-1a.js", d.scripts)
        self.assertEqual(d.routes, ["/", "/admin/[id]"])
        vite = 'const A=()=>import("./Admin-4f2a.js");__vite__mapDeps(["assets/Chart-9c.js","assets/Chart-1d.css"])'
        d = chunks.discover(Program(vite), "https://x.io/assets/index-aa.js")
        self.assertEqual(sorted(d.scripts), ["https://x.io/assets/Admin-4f2a.js", "https://x.io/assets/assets/Chart-9c.js"])

    def test_html(self):
        html = ('<base href="/app/"><script src="static/main.js"></script><script src=\'//cdn.x.io/v.js\'></script>'
                '<link rel="modulepreload" href="/m.js"><link rel="stylesheet" href="/a.css">'
                '<script>window.__CFG__={api:"/api/boot"}</script><script type="text/template"><b></b></script>')
        found = chunks.scripts_from_html(html, "https://x.io/")
        self.assertEqual(found.urls, ["https://x.io/app/static/main.js", "https://cdn.x.io/v.js", "https://x.io/m.js"])
        self.assertEqual(found.inline, ['window.__CFG__={api:"/api/boot"}'])


if __name__ == "__main__":
    unittest.main()
