# DeepJS

**Deep static analysis of front-end JavaScript.** Point it at a web app, a build
directory or a HAR capture and it tells you what the application calls, what it
leaks, and what it ships that no page links to.

```text
$ deepjs scan https://app.example.com

── Secrets (3) ──────────────────────────────────────────────────
  CRITICAL AWS_ACCESS_KEY               AKIA…6N
           https://app.example.com/static/js/admin.9f1c2a.chunk.js:1  key: k
           AWS access key ID in front-end code. Long-lived keys must never ship to a browser.
  CRITICAL GITHUB_TOKEN                 ghp_A1b2…Q7r8
           map:src/api/client.ts:1  key: (comment)
  HIGH     HARDCODED_SECRET             Zx9Qm2Lk…g3Ua
           https://app.example.com/static/js/main.a1b2.js:1  key: clientSecret

── Public-by-design keys (verify configuration, not leaks) (1) ────
  INFO     STRIPE_PUBLISHABLE_KEY       pk_live_…C3vB  Stripe publishable key — public by design.

── API calls (6) ────────────────────────────────────────────────
  POST    https://app.example.com/api/v1/admin/impersonate
           body: userId
  DELETE  https://app.example.com/api/v1/admin/users/{param}
  GET     https://app.example.com/api/v1/audit/{id}/events
           query: limit
  POST    https://app.example.com/api/v1/auth/login
           body: email, password
  GET     https://app.example.com/api/v1/billing/invoices
           query: status
  GET     https://app.example.com/api/v1/me

── Hosts (3) ────────────────────────────────────────────────────
  cloud-storage acme-uploads.s3.eu-west-1.amazonaws.com aws-s3
  internal      10.20.30.40

── Source maps exposed (1) ──────────────────────────────────────
  https://app.example.com/static/js/main.a1b2.js.map
           4 sources, 2 application files, 2 packages
```

*(Output of the end-to-end test fixture in `tests/test_e2e.py`, host renamed. The admin endpoints come from a
chunk no page links to; the GitHub token and the audit endpoint exist only in the recovered source map.)*

Pure Python, **no dependencies** — `pip install` and run. Python 3.11+.

> Only scan applications you own or are authorised to test.

## Why another JavaScript recon tool

Most tools in this space — Burp extensions and command-line scanners alike —
run regular expressions over the bundle as if it were one long string. That
finds quoted things that look like paths. It cannot follow `API + "/users/" +
id`, cannot tell you the request is a `DELETE`, reports paths inside comments
and regex literals, and only ever sees the scripts that happened to be loaded.

DeepJS tokenizes the JavaScript and works on its structure.

| | Regex over text | DeepJS |
|---|---|---|
| URL built by concatenation / template / Babel `"".concat()` | fragments | the assembled URL, e.g. `/api/users/{id}/posts` |
| HTTP method, query params, body fields, header names | — | read from the call site |
| Paths in comments / regex literals / MIME types / asset names | reported | not reported |
| Chunks no visited page loads (admin screens, lazy routes) | invisible | found from the bundler's own chunk map |
| Source maps | fetch | fetch, recover sources safely, **analyse the originals too** |
| Publishable keys, Firebase config, Sentry DSN, Supabase anon key | "secret found" | classified *public by design*, with what to verify |
| `password: "Password"`, `apiKey: "YOUR_API_KEY"` | "secret found" | ignored |
| Needs | often a proxy suite | nothing — or put it behind one with `--proxy` |

## Install

```bash
pip install git+https://github.com/xtawb/deepjs
```

or from a checkout: `pip install .`

## Use

```bash
deepjs scan app.example.com                         # crawl the site, follow every chunk, read source maps
deepjs scan https://app.example.com/login --no-crawl   # just this page and its scripts
deepjs scan https://app.example.com -o out/         # + report.json, report.md, endpoints.txt, hosts.txt
deepjs scan dist/ bundle.js traffic.har             # a build directory, single files, or a HAR capture (offline)
deepjs scan -l urls.txt --proxy http://127.0.0.1:8080    # every request through Burp / ZAP
deepjs scan https://app.example.com --sources src/  # write the original sources recovered from source maps
deepjs scan https://app.example.com --check-npm     # are the bundled package names registered on public npm?
deepjs diff old/report.json new/report.json         # what appeared / disappeared between two scans
```

`deepjs <target>` is shorthand for `deepjs scan <target>`. Secret values are
masked in every output unless you pass `--reveal`.

## Burp Suite extension

DeepJS also runs inside Burp Suite, as an extension with its own repository:
**[xtawb/deepjs-burp](https://github.com/xtawb/deepjs-burp)** — one jar, no
dependencies, Community and Professional. Every JavaScript / HTML response
that passes through Burp is analysed with the same rules as this command line
(a Java port of them: see
[Two engines, one set of rules](#two-engines-one-set-of-rules)), and the
results appear in a **DeepJS** tab: API calls with *Send to Repeater*, secrets,
hosts, and the chunks and source maps the code names but your browsing never
loaded — which it can request through Burp.

Download `deepjs-burp.jar` from its
[latest release](https://github.com/xtawb/deepjs-burp/releases/latest), then in
Burp: **Extensions → Add → Extension type: Java →** select the file.

## Crawling

`deepjs scan <site>` now crawls: it follows same-host links (`--crawl-depth`,
default 2; `--max-pages`, default 40), reads `robots.txt` and sitemaps, turns
HTML forms into endpoints, and visits the client-side routes it finds in the
bundles — server-rendered apps ship different chunks per route. It never
follows links that look state-changing (logout, delete, unsubscribe…), never
leaves the target host unless you pass `--scope`, and `--no-crawl` restores
single-page behaviour. Requests use a desktop-browser User-Agent by default
because many CDNs refuse anything else (`--user-agent` to change it); when
requests are refused anyway the report says so and how to get past it.

After a scan, `deepjs` tells you when a newer release exists. That is one
anonymous request to GitHub's API at most once a day (the answer is cached),
it sends nothing about the scan, and nothing is downloaded or installed.
`--no-update-check` or `DEEPJS_NO_UPDATE_CHECK=1` turns it off.

`deepjs update` (or `deepjs --update`) does the updating: it prints what the
latest release changed and the exact `pip` command it is about to run, asks,
and installs that release's tagged archive. `--yes` skips the question; without
a terminal and without `--yes` it changes nothing. There is no silent
self-update — a scanner that replaces its own code unasked is one whose
results you cannot reproduce. A git checkout is left to `git pull`. On Windows
pip may end with a warning that it could not remove a temporary directory:
that is the `deepjs.exe` still running the command, and the update is done.

Two things keep it from wasting requests. A single-page app answers every
route with the same HTML shell, so DeepJS probes three routes and, if they come
back identical to a page it already has, does not request the rest — the
scripts are what matter and it has them. And if the server answers eight
requests in a row with HTTP 5xx / 429 it stops and says so, instead of pushing
an overloaded site further (`--delay`, `--threads` to go slower).

## What it finds

**API calls** — `fetch`, axios (every form), jQuery, `XMLHttpRequest`, any
`<client>.get/post/put/patch/delete(…)` (Angular `HttpClient`, ky, got,
superagent, your own wrapper), request-config objects (`{url, method}` — RTK
Query, axios configs), `WebSocket`, `EventSource`, `sendBeacon`. Each with its
method, query-parameter names, body field names and header names when the call
site shows them. Strings that only *look* like paths are listed separately.

Service classes are followed: `this.host` is resolved inside its own class
(class fields, constructor assignments, TypeScript's ES5 output), so Angular's
`host = this.hostServer + "/rest/products"` … `this.http.get(`${this.host}/${id}/reviews`)`
is reported as `GET /rest/products/{id}/reviews`, not `{host}/{id}/reviews`.
When the base lives in another chunk (`environment.apiUrl`), the call is shown
with the placeholder and completed once that chunk has been read.

**Hidden chunks** — the webpack 4/5 (and Next.js) chunk-filename function is
evaluated for every chunk id it knows; Vite/Rollup dynamic imports and Next.js
build manifests are read too. These are the scripts a crawl or a proxy history
never contains.

**Source maps** — referenced maps are fetched (and `<script>.map` is probed
unless `--no-probe-maps`). Embedded original sources are analysed with the
same engine — real names, comments, TypeScript — and can be written to disk.
Source names in a map are untrusted input; every path is sanitised so that
nothing can be written outside the directory you chose.

**Secrets** — 35 credential formats, plus any credible value assigned to a
secret-bearing name (`clientSecret`, `X-Api-Key`, `Authorization`…). JWTs are
decoded (never used): a Supabase `service_role` key is critical, an `anon` key
is public by design, an expired token is low. Placeholders, form labels,
storage-key names and translations are recognised and dropped. A token written
into an HTML page's own inline script is reported as `PAGE_TOKEN` (info): it
was put there for the visitor — a session, CSRF or API token — and is not a
secret shipped to everyone; the same value in a static bundle is. Pages of
third-party platforms embedded in the site (social embeds, ad and analytics
frames) are not analysed at all.

**Hosts** — every host mentioned, classified in-scope / cloud storage (S3,
GCS, Azure Blob, Firebase, Spaces, R2, OSS) / internal / third-party, with
non-production names flagged.

**Also** — GraphQL operation names, client-side routes (router tables, Next.js
manifest), API base URLs, the full npm package list from source maps and —
opt-in — which of those names are *not* registered on the public registry
(dependency-confusion exposure; the check is one read-only GET per name).

## Accuracy

Measured, not asserted. `python -m deepjs.corpus` runs a labelled corpus of
JavaScript snippets through DeepJS and through the classic "quoted path"
regular expression:

| Set | Extractor | URL recall | Method known | False positives |
|---|---|---|---|---|
| tuning (34 requests, 16 clean snippets) | regex | 74% | 0% | 18 |
| | DeepJS | 100% | 100% | 0 |
| **hold-out, first run** (22 requests, 10 clean snippets) | regex | 73% | 0% | 6 |
| | **DeepJS** | **95%** | **86%** | **2** |
| hold-out, after fixing what it found | DeepJS | 95% | 93% | 0 |

The tuning set was used while building the extractor, so its 100% is a
regression gate, not a claim. The hold-out set was written afterwards and
scored once before anything changed — that row is the honest estimate, and it
is on small synthetic snippets, not on your application. Both sets run in CI.

On real minified libraries (react-dom, vue, jquery, lodash, three.js, angular,
axios, moment, the 3.3 MB aws-sdk) the tokenizer consumed every byte with no
unbalanced brackets, reported zero secrets, and took about one second per MB.

One real application, for scale: the public OWASP Juice Shop demo (Angular,
3.1 MB of JavaScript in 23 files). 0.1.0 analysed the single page it was given.
0.2.0 before class resolution reported 51 calls, 41 of them with an unresolved
`{hostServer}` / `{host}` base and 13 of those with part of the path missing;
with it, 92 calls, none with an unresolved base. That is one application
and no ground truth for what was missed — an anecdote, not a benchmark.

### Compared with JS Miner

Seven open-source applications with a public demo, where the real routes are
known (OWASP Juice Shop's `server.ts`; the RealWorld API specification). Both
tools were given the same downloaded script files. The score is the number of
real routes — method and path — a tool identified.

| Application | Real routes | JS Miner 1.16 as shipped | JS Miner, loop fixed¹ | DeepJS, first run | DeepJS 0.2.1 |
|---|---|---|---|---|---|
| OWASP Juice Shop (Angular, 3.2 MB) | 140² | 1 | 27 | 82 | 86 |
| RealWorld — Angular | 19 | 6 | 19 | 15 | 19 |
| RealWorld — Vue 3, fetch client | 19 | 0 | 0 | 19 | 19 |
| RealWorld — demo.realworld.show | 19 | 18 | 19 | 17 | 19 |
| RealWorld — Next.js | 19 | 0 | 1 | 17 | 17 |
| RealWorld — Nuxt | 19 | 18 | 18 | 0 | 19 |
| RealWorld — React, axios instance | 19 | 0 | 0 | 6 | 13 |
| **Total** | **254** | **43** | **84** | **156** | **192** |

"First run" is the honest column: the version that existed before DeepJS had
seen that application (0.2.0 for the first four rows; 0.2.0 plus the fixes
from those four for the last three). The 0.2.1 column was measured after
fixing what each run exposed, on the same applications, so it is a regression
gate and not an independent result.

What the table shows: JS Miner's `.get(` / `.post(` patterns do well where an
app calls `client.get("/literal")` directly — it beat DeepJS on two of the
seven first runs — and find nothing when requests go through `fetch`, a
request-config object or Babel's `"".concat()`. DeepJS reads all of those but
had its own blind spots, each now a unit test: conditional path pieces, URLs
held in a local variable, Nuxt's `$get`, configs without a fixed method.

Secrets, on the one application that had any (Juice Shop): JS Miner reported
the hard-coded test-account password and three false positives; DeepJS 0.2.0
missed the password and reported two false positives of its own; 0.2.1 reports
the password and nothing else.

How it was measured, and what that limits: JS Miner is a Burp extension, so its
regular expressions were copied verbatim from its source (commit `420c566`)
and its scanner loops re-run in Python rather than inside Burp. Its output is
raw source text; it was credited with a route whenever a person could read the
full path out of the match. Not compared: source-map recovery, dependency
confusion, subdomain and cloud-URL discovery, which both tools have. Seven
applications, six of them implementations of one small API, is a small sample.

¹ As written, JS Miner's endpoint loop ends at the first match that has no `/`
in it, which on a large bundle is usually within the first few matches. The
second column filters such matches instead.
² Every route the server defines, including ones no front-end code calls, so
140 is not reachable from JavaScript alone.

## Limits

- **Static only.** URLs computed at runtime from server responses, or built by
  code paths the evaluator does not model (`[a, b].join("/")`, a URL returned
  from a helper function), are missed or left as `{param}`.
- **No full parser.** Identifiers are resolved only when a name has exactly one
  constant string value in the file (or, for `this.x`, one definition in its
  class); in minified code that is deliberately conservative, so some URLs keep
  a `{base}` placeholder instead of a host. For those, the full URL shown in
  JSON and in Burp is a best guess (the site's own origin) — the placeholder in
  the `url` field tells you it was guessed.
- **A "string" endpoint may be a client route** — only call sites are certain.
- **Source maps without `sourcesContent`** give file and package names, not code.
- **Obfuscated bundles** (string-array rotation, control-flow flattening)
  defeat this kind of analysis.
- JS/JSON/HTML only — no WebAssembly, no service-worker runtime behaviour.
- **The crawler does not run JavaScript.** Pages that only exist after client-side
  rendering are reached through routes and chunk maps, not by clicking. For an
  app behind a login, pass your session (`-H "Cookie: …"`) or use the Burp extension.

## How it works

```text
targets ─► collect scripts ─► tokenize ─► endpoints · secrets · hosts
               ▲                  │
               │                  ├─► chunk discovery ─► more scripts
               └──────────────────┘
                                  └─► source maps ─► recovered sources ─► same analysis
                                                         └─► package list ─► npm check (opt-in)
```

| Module | Role |
|---|---|
| `lexer.py` | tolerant tokenizer: strings, templates, regex vs division, comments, bracket pairs |
| `jseval.py` | evaluates string-building expressions; object-literal and call-argument structure |
| `endpoints.py` | call sites, request configs, GraphQL, routes |
| `secrets.py` / `entropy.py` | credential formats, key-name semantics, placeholder and randomness model |
| `chunks.py` | HTML scripts, webpack / Next.js / Vite chunk discovery |
| `sourcemap.py` | map parsing, safe source recovery |
| `hosts.py` | host extraction and classification |
| `npmcheck.py` | public-registry existence check |
| `engine.py` · `report.py` · `cli.py` | crawling and orchestration, output, command line |
| `serve.py` | stdin/stdout analysis worker for other tools |

### Two engines, one set of rules

The command line is Python; a Burp extension that needs a Python interpreter
is not a one-click install. So the analysis exists twice — `deepjs/*.py` here
and `deepjs.engine` in [deepjs-burp](https://github.com/xtawb/deepjs-burp), in
Java — and that repository's `tools/parity.py` keeps the two honest: it feeds
identical input to both over the same line protocol (`deepjs serve`) and
compares every record they produce. On the accuracy corpus, the end-to-end
fixture, a generated set of credential / HTML / source-map shapes, seven real
applications and nineteen well-known libraries (26 MB of JavaScript, 2,247
records) the two agree on every record. CI in both repositories builds the
extension and runs the built-in sets: a rule changed here and not there fails
the build.

### Input written to break a parser

Both engines analyse content from sites the user does not trust. A page of a
megabyte of unclosed `<form` tags, a 200,000-term string concatenation, five
thousand nested template literals or a megabyte licence comment must cost
what its size costs, not its square: HTML is read by a single-pass tag
scanner, not by whole-document regular expressions; nesting is followed to a
fixed depth; every regular expression that meets attacker-controlled text
runs on a bounded length. `tests/test_core.py` holds such input
(`HostileInputTests`), and the extension's harness feeds it to the Java engine
on every build.

## Development

```bash
python -m unittest discover -s tests -t .     # unit + end-to-end (a fake SPA served from localhost)
python -m deepjs.corpus                       # accuracy corpus vs. the regex baseline
```

## License

MIT — see [LICENSE](LICENSE).
