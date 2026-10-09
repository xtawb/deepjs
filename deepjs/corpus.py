"""
deepjs.corpus — a labelled corpus for measuring endpoint extraction.

Each positive case is a snippet of JavaScript and the requests it makes;
each negative case is a snippet that makes none. `score()` runs an extractor
over the corpus and reports URL recall, method accuracy and false positives,
and `regex_baseline()` is the classic "quoted string that looks like a path"
regular expression (the approach regex-based tools use), for comparison.

`python -m deepjs.corpus` prints both.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Set, Tuple

# (name, code, [(method, url)]) — method "" means "any / not asserted"
POSITIVE: List[Tuple[str, str, List[Tuple[str, str]]]] = [
    ("fetch-get", 'fetch("/api/users")', [("GET", "/api/users")]),
    ("fetch-post", 'fetch("/api/users",{method:"POST",body:JSON.stringify({name:n})})', [("POST", "/api/users")]),
    ("fetch-template", "fetch(`/api/users/${id}`)", [("GET", "/api/users/{}")]),
    ("fetch-concat", 'fetch("/api/items/"+id+"/tags")', [("GET", "/api/items/{}/tags")]),
    ("axios-get", 'axios.get("/api/orders")', [("GET", "/api/orders")]),
    ("axios-post", 'axios.post("/api/orders",{sku:s,qty:q})', [("POST", "/api/orders")]),
    ("axios-delete-tpl", "axios.delete(`/api/orders/${id}`)", [("DELETE", "/api/orders/{}")]),
    ("axios-config", 'axios({url:"/api/report",method:"put"})', [("PUT", "/api/report")]),
    ("axios-instance", 'const c=axios.create({baseURL:"https://api.x.io"});c.patch("/v1/profile",d)', [("PATCH", "/v1/profile")]),
    ("jquery-ajax", '$.ajax({url:"/legacy/save.php",type:"POST"})', [("POST", "/legacy/save.php")]),
    ("jquery-post", '$.post("/legacy/login.php",{u:u,p:p})', [("POST", "/legacy/login.php")]),
    ("xhr-open", 'var x=new XMLHttpRequest;x.open("GET","/api/ping")', [("GET", "/api/ping")]),
    ("const-base", 'const B="https://api.x.io/v3";fetch(B+"/me")', [("GET", "https://api.x.io/v3/me")]),
    ("babel-concat", 'const B="https://api.x.io/v3";fetch("".concat(B,"/teams/").concat(t,"/members"))',
     [("GET", "https://api.x.io/v3/teams/{}/members")]),
    ("angular-http", "this.http.get(`${this.base}/widgets`)", [("GET", "{}/widgets")]),
    ("url-in-variable", "const url=`/api/search?q=${q}&page=${p}`;fetch(url)", [("GET", "/api/search")]),
    ("minified-pair", 'function a(e){return fetch("/api/a/"+e)}function b(e){return fetch("/api/b/"+e,{method:"DELETE"})}',
     [("GET", "/api/a/{}"), ("DELETE", "/api/b/{}")]),
    ("websocket", 'new WebSocket("wss://ws.x.io/live")', [("GET", "wss://ws.x.io/live")]),
    ("beacon", 'navigator.sendBeacon("/metrics",d)', [("POST", "/metrics")]),
    ("rtk-query", 'b.mutation({query:t=>({url:"/api/todos",method:"POST",body:t})})', [("POST", "/api/todos")]),
    ("ky-post", 'ky.post("api/upload",{json:{file:f}})', [("POST", "api/upload")]),
    ("superagent", 'request.get("/api/sa").end(cb)', [("GET", "/api/sa")]),
    ("got-put", 'got.put("https://svc.x.io/thing/"+id)', [("PUT", "https://svc.x.io/thing/{}")]),
    ("swr-key", 'useSWR("/api/swr/key",fetcher)', [("", "/api/swr/key")]),
    ("endpoint-table", 'var E={users:"/api/v2/users",logout:"/api/v2/logout"}',
     [("", "/api/v2/users"), ("", "/api/v2/logout")]),
    ("table-lookup", 'var E={users:"/api/v2/users"};fetch(E.users)', [("GET", "/api/v2/users")]),
    ("url-object", 'fetch(new URL("/api/urlobj",location.origin))', [("", "/api/urlobj")]),
    ("window-fetch", 'window.fetch("/api/win")', [("GET", "/api/win")]),
    ("encode-uri", 'fetch("/api/files/"+encodeURIComponent(name)+"/meta")', [("GET", "/api/files/{}/meta")]),
    ("event-source", 'new EventSource("/api/stream")', [("GET", "/api/stream")]),
    ("post-with-query", 'http.post("/api/v1/import?dry_run=1",payload)', [("POST", "/api/v1/import")]),
    ("nested-template", "fetch(`${API_ROOT}/v2/accounts/${acct.id}/users/${u.id}`,{method:'PATCH'})",
     [("PATCH", "{}/v2/accounts/{}/users/{}")]),
]

# snippets that make no request and name no endpoint
NEGATIVE: List[Tuple[str, str]] = [
    ("map-get", 'var m=new Map;m.get("a/b");m.delete("x/y")'),
    ("params-get", 'params.get("id");headers.get("content-type")'),
    ("i18n", 'i18n.get("errors/notFound");t("common/buttons/save")'),
    ("mime", 'var a="text/html",b="application/json",c="image/svg+xml"'),
    ("svg-path", 'var d="M10 10/20 L5 5"'),
    ("html", 'var h="</div>",g="<a href=\\"/x\\">"'),
    ("date", 'var d="2024/01/02",f="MM/DD/YYYY"'),
    ("regex-source", 'var r="^/api/x$",s=new RegExp("\\\\/foo\\\\/bar")'),
    ("static-assets", 'var i="/static/logo.png",c="/assets/app.css",f="/fonts/a.woff2"'),
    ("module-paths", 'import("./pages/Home.js");require("../lib/util")'),
    ("comment", '// fetch("/api/commented")\n/* axios.get("/api/also-commented") */\nvar x=1'),
    ("regex-literal", 'var r=/\\/api\\/in-regex/.test(s)'),
    ("spec-urls", 'var ns="http://www.w3.org/2000/svg",d="https://reactjs.org/docs/error-decoder.html"'),
    ("division", 'var a=b/c/d,e=f/2'),
    ("css", 'var s="margin:0/auto",u="url(data:image/png;base64,AAAA/BBBB)"'),
    ("storage", 'localStorage.getItem("app/session");sessionStorage.removeItem("app/tmp")'),
]


# ── Hold-out set ───────────────────────────────────────────────────────────────
# Written after the extractor had been tuned on the cases above and scored once
# before anything else changed (README, "Accuracy"). It stays separate so the
# two numbers are never blended.

HOLDOUT_POSITIVE: List[Tuple[str, str, List[Tuple[str, str]]]] = [
    ("async-arrow", 'const load=async()=>{const r=await fetch("/api/h/items");return r.json()}', [("GET", "/api/h/items")]),
    ("method-variable", 'fetch("/api/h/save",{method:m,body:b})', [("", "/api/h/save")]),
    ("ternary-url", 'fetch(isAdmin?"/api/h/admin/list":"/api/h/list")', [("", "/api/h/admin/list"), ("", "/api/h/list")]),
    ("or-default", 'fetch((cfg.root||"/api/h/root")+"/ping")', [("", "/api/h/root")]),
    ("class-method", 'class S{get(id){return this.client.get("/api/h/things/"+id)}}', [("GET", "/api/h/things/{}")]),
    ("join-array", 'fetch(["/api/h","users",id].join("/"))', [("", "/api/h")]),
    ("axios-interceptor-instance", 'const api=axios.create({baseURL:"/api/h/v2"});api.interceptors.request.use(f);api.get("/orders")',
     [("GET", "/orders")]),
    ("jquery-method-option", '$.ajax("/api/h/legacy",{method:"PUT",data:{a:1}})', [("PUT", "/api/h/legacy")]),
    ("fetch-request-object", 'fetch(new Request("/api/h/req",{method:"POST"}))', [("", "/api/h/req")]),
    ("url-search-params", 'fetch("/api/h/search?"+new URLSearchParams({q:q,page:p}))', [("GET", "/api/h/search")]),
    ("string-replace", 'var u="/api/h/users/:id/posts".replace(":id",id);fetch(u)', [("", "/api/h/users/:id/posts")]),
    ("optional-chaining", 'fetch(`${cfg?.api?.base}/h/opt`)', [("GET", "{}/h/opt")]),
    ("angular-typed", 'this.http.post<User>(`${environment.apiUrl}/h/users`, body)', [("POST", "{}/h/users")]),
    ("vue-axios", 'this.$axios.$get("/api/h/nuxt")', [("", "/api/h/nuxt")]),
    ("graphql-endpoint", 'fetch("/graphql",{method:"POST",body:JSON.stringify({query:q,variables:v})})', [("POST", "/graphql")]),
    ("backtick-no-vars", "axios.get(`/api/h/static`)", [("GET", "/api/h/static")]),
    ("ws-template", "new WebSocket(`wss://${host}/h/socket`)", [("GET", "wss://{}/h/socket")]),
    ("minified-comma-seq", 'return e.next=4,fetch("/api/h/seq/".concat(t),{method:"POST",headers:n})', [("POST", "/api/h/seq/{}")]),
    ("await-in-try", 'try{await api.delete("/api/h/sessions/current")}catch(e){}', [("DELETE", "/api/h/sessions/current")]),
    ("object-method-key", 'const svc={list:()=>request({url:"/api/h/cfg/list",method:"get"}),del:id=>request({url:"/api/h/cfg/"+id,method:"delete"})}',
     [("GET", "/api/h/cfg/list"), ("DELETE", "/api/h/cfg/{}")]),
]
HOLDOUT_NEGATIVE: List[Tuple[str, str]] = [
    ("router-link", 'h(Link,{to:"/h/profile/settings"});h("a",{href:"/h/pricing/enterprise"})'),
    ("import-path", 'import x from "@/api/h/client";const y=require("~/services/h/users")'),
    ("test-id", 'el.setAttribute("data-testid","h/user/card")'),
    ("xml-ns", 'var a="http://www.w3.org/1999/xlink",b="urn:h:x/y"'),
    ("glob", 'var g="src/h/**/*.ts",ig="node_modules/h/"'),
    ("content-types", 'headers.set("Accept","application/vnd.h+json")'),
    ("css-url", 'el.style.background="url(/h/img/bg.png)"'),
    ("fraction", 'var t="1/2 cup",r="16/9"'),
    ("event-name", 'emitter.on("h/user/updated",fn);bus.emit("h/cart/add",x)'),
    ("regexp-string", 'new RegExp("^/h/(\\\\d+)/edit$")'),
]


def norm(url: str) -> str:
    """Compare URL templates without caring what a placeholder is called."""
    return re.sub(r"\{[^}]*\}", "{}", url)


Extractor = Callable[[str], Set[Tuple[str, str]]]


def deepjs_extractor(code: str) -> Set[Tuple[str, str]]:
    from deepjs.endpoints import extract
    from deepjs.jseval import Program
    return {(e.method, norm(e.url)) for e in extract(Program(code)).endpoints}


_LINKFINDER = re.compile(
    r"""(?:"|'|`)(
        ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
      | ((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})
      | ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|\#][^"|']{0,}|))
      | ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|\#][^"|']{0,}|))
      | ([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|\#][^"|']{0,}|))
    )(?:"|'|`)""",
    re.VERBOSE,
)


def regex_baseline(code: str) -> Set[Tuple[str, str]]:
    """The widely used 'quoted path' regular expression. It has no notion of method."""
    out = set()
    for m in _LINKFINDER.finditer(code):
        url = m.group(1).split("?", 1)[0]
        out.add(("", norm(re.sub(r"\$\{[^}]*\}", "{}", url))))
    return out


def score(extractor: Extractor, positive=None, negative=None) -> Dict[str, object]:
    positive = POSITIVE if positive is None else positive
    negative = NEGATIVE if negative is None else negative
    urls_expected = urls_found = methods_expected = methods_right = 0
    missed: List[str] = []
    for name, code, expected in positive:
        got = extractor(code)
        got_urls = {u for _, u in got}
        for method, url in expected:
            urls_expected += 1
            if norm(url) in got_urls:
                urls_found += 1
            else:
                missed.append(f"{name}: {method or '?'} {url}")
            if method:
                methods_expected += 1
                if (method, norm(url)) in got:
                    methods_right += 1
    false_positives: List[str] = []
    for name, code in negative:
        for method, url in sorted(extractor(code)):
            false_positives.append(f"{name}: {method or '?'} {url}")
    return {
        "url_recall": urls_found / urls_expected,
        "method_accuracy": methods_right / methods_expected,
        "urls": f"{urls_found}/{urls_expected}",
        "methods": f"{methods_right}/{methods_expected}",
        "false_positives": false_positives,
        "missed": missed,
    }


def main() -> None:
    sets = (("tuning set", POSITIVE, NEGATIVE), ("hold-out set", HOLDOUT_POSITIVE, HOLDOUT_NEGATIVE))
    for title, pos, neg in sets:
        print(f"{title}: {sum(len(e) for _, _, e in pos)} requests in {len(pos)} snippets, {len(neg)} clean snippets")
        _print_scores(pos, neg)
        print()


def _print_scores(pos, neg) -> None:
    for label, fn in (("regex baseline", regex_baseline), ("DeepJS", deepjs_extractor)):
        r = score(fn, pos, neg)
        print(f"  {label:<15} URL recall {r['url_recall']:.0%} ({r['urls']})   method known {r['method_accuracy']:.0%} "
              f"({r['methods']})   false positives {len(r['false_positives'])}")
        if label == "DeepJS":
            for m in r["missed"]:
                print(f"      missed  {m}")
            for f in r["false_positives"]:
                print(f"      false+  {f}")


if __name__ == "__main__":
    main()
