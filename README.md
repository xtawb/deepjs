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
deepjs scan https://app.example.com                 # crawl the page, follow every chunk, read source maps
deepjs scan https://app.example.com -o out/         # + report.json, report.md, endpoints.txt, hosts.txt
deepjs scan dist/ bundle.js traffic.har             # a build directory, single files, or a HAR capture (offline)
deepjs scan -l urls.txt --proxy http://127.0.0.1:8080    # every request through Burp / ZAP
deepjs scan https://app.example.com --sources src/  # write the original sources recovered from source maps
deepjs scan https://app.example.com --check-npm     # are the bundled package names registered on public npm?
deepjs diff old/report.json new/report.json         # what appeared / disappeared between two scans
```

`deepjs <target>` is shorthand for `deepjs scan <target>`. Secret values are
masked in every output unless you pass `--reveal`.

## What it finds

**API calls** — `fetch`, axios (every form), jQuery, `XMLHttpRequest`, any
`<client>.get/post/put/patch/delete(…)` (Angular `HttpClient`, ky, got,
superagent, your own wrapper), request-config objects (`{url, method}` — RTK
Query, axios configs), `WebSocket`, `EventSource`, `sendBeacon`. Each with its
method, query-parameter names, body field names and header names when the call
site shows them. Strings that only *look* like paths are listed separately.

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
storage-key names and translations are recognised and dropped.

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

## Limits

- **Static only.** URLs computed at runtime from server responses, or built by
  code paths the evaluator does not model (`[a, b].join("/")`, a URL returned
  from a helper function), are missed or left as `{param}`.
- **No full parser.** Identifiers are resolved only when a name has exactly one
  constant string value in the file; in minified code that is deliberately
  conservative, so some URLs keep a `{base}` placeholder instead of a host.
- **A "string" endpoint may be a client route** — only call sites are certain.
- **Source maps without `sourcesContent`** give file and package names, not code.
- **Obfuscated bundles** (string-array rotation, control-flow flattening)
  defeat this kind of analysis.
- JS/JSON/HTML only — no WebAssembly, no service-worker runtime behaviour.

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
| `engine.py` · `report.py` · `cli.py` | orchestration, output, command line |

## Development

```bash
python -m unittest discover -s tests -t .     # unit + end-to-end (a fake SPA served from localhost)
python -m deepjs.corpus                       # accuracy corpus vs. the regex baseline
```

## License

MIT — see [LICENSE](LICENSE).
