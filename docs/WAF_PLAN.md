# Part 2: the firewall

Part 1 produced a classifier. A classifier is not a firewall. This part puts the
model inline in real traffic, gives it the authority to refuse a request, and
builds the console an operator would actually need to trust it.

## What v0 got wrong, and what "done" means here

`Notebooks_jupyter/IPS proxy .ipynb` did this:

```python
if result['Cluster'][0] == "Cluster 1":
    print('Intrusion Detected !')
```

It printed, then forwarded the request anyway. No `return`, no `403`. It also read
GET paths only, so POST bodies, where most SQL injection actually travels, were
never inspected at all.

Done, for this part, means: an attacker running `sqlmap` against the protected app
finds nothing, a normal user notices no difference, and an operator can see exactly
why every decision was made.

## Architecture

```
                        ┌────────────────────┐
   client ─────────────▶│    mlwaf proxy     │────────▶  Juice Shop
                        │  FastAPI + httpx   │◀────────
                        └─────────┬──────────┘
                                  │ decision record
                        ┌─────────▼──────────┐
                        │  SQLite (WAL mode) │
                        └─────────┬──────────┘
                                  │ REST + SSE
                        ┌─────────▼──────────┐
                        │  operator console  │
                        └────────────────────┘
```

One process serves the proxy, the API and the console. SQLite in WAL mode holds the
decision log, so there is no second service to run and no data loss on restart.

### Why a reverse proxy and not mitmproxy

mitmproxy is built to intercept arbitrary TLS traffic, which means certificate
handling, a CA the client has to trust, and a heavier runtime. A WAF sits in front
of a known origin, so a plain reverse proxy is the correct shape: simpler to
containerise, no certificate story, full control over the request lifecycle, and
honest latency numbers.

## Modules

```
src/mlwaf/waf/
  config.py     env driven settings, one source of truth
  engine.py     scoring, decision, cache, latency budget, fail policy
  explain.py    why a request was blocked
  proxy.py      the reverse proxy itself
  store.py      decision log, retention, aggregate queries
  api.py        REST and server sent events for the console
  metrics.py    Prometheus counters and histograms
  console/      the operator UI
```

## The interesting part: every decision is explainable

Most WAFs answer "blocked" and nothing else. This one can answer "why", because the
model was built to be inspectable.

Two things are recorded per decision and shown in the console:

**The decode trace.** The normalisation chain from part 1 already peels encoding
layers one at a time. Recording each round turns it into an audit trail:

```
raw       q=1%2527%2520UNION%252FA%252A%252ASELECT
round 1   q=1%27%20UNION%2FA%2A%2ASELECT
round 2   q=1' UNION/A**SELECT
canonical q=1' union select
```

That is the single most convincing artefact the console can show: the operator
watches the obfuscation come apart.

**Feature contributions.** LightGBM computes exact per feature SHAP values through
`predict(X, pred_contrib=True)`, which is fast enough to run inline. Mapping the
largest contributions back to their n-gram names gives, for the request above:

```
"' un"      +0.31
"nion sel"  +0.28
sql_keywords +0.19
```

No extra library, no sampling, no approximation.

## Production concerns, decided up front

**Fail policy: fail open, and alert.** If scoring raises, or exceeds its latency
budget, the request is allowed, an alert counter increments and the event is logged
at error level. A broken model must not become a site outage. `WAF_FAIL_MODE=closed`
flips it for anyone who wants the opposite tradeoff.

**Latency budget.** Scoring runs under a deadline, default 10ms. Past that the
request is allowed and the timeout is counted. A slow model degrades protection,
never availability. Part 1 measured about 1ms per request, so the budget has an
order of magnitude of headroom.

**Decision cache.** An LRU over the hash of the normalised text. Repeated requests,
which is most traffic, skip scoring entirely.

**Body handling.** Bodies are read up to `WAF_MAX_BODY_BYTES` (default 1 MB) for
scoring and streamed through untouched. Anything larger is forwarded unscored and
counted, because buffering unbounded uploads is how a proxy becomes the outage.

**Also inspected:** method, path, query, body, headers and cookies. v0 read GET
paths only.

**Operational surface:** `/healthz` liveness, `/readyz` which fails until the model
is loaded and warmed, `/metrics` in Prometheus format, structured JSON logs with a
request id on every line, graceful shutdown that drains in flight requests.

## Console design

A dense operator console, not a marketing dashboard. Reference points are Datadog
and a good terminal, not a security vendor landing page.

- Near black base, one surface step above it, low contrast borders
- A single accent used only where it carries meaning: amber for a block
- Monospace with tabular numerals for all data, system sans for chrome only
- Inline SVG sparklines, no charting library
- No gradients, no glow, no neon, no animation beyond a row appearing

Screens:

1. **Live** stream of decisions over server sent events, filterable by verdict,
   class and path. Click a row for the decode trace and contributions.
2. **Threshold** slider. Because every stored decision keeps its score, moving the
   slider recomputes verdicts over recent traffic instantly and shows what would
   change: blocks gained, allows lost, the requests that flip. This is where part
   1's false positive budget becomes something you can feel.
3. **Review queue.** In detect mode nothing is blocked but `would_block` is still
   recorded, which is how a WAF gets deployed in reality: watch first, then enforce.
   The queue is that list, and each entry can be marked a false positive.

Feedback is written to `data/feedback.jsonl` in the same schema the training
pipeline reads, so the loop back to part 1 is a file, not an integration.

## Docker

Multi stage build, non root user, model baked into the image at build time so the
container has no runtime download. Compose brings up the proxy and OWASP Juice Shop
with healthchecks and a dependency ordering, so `docker compose up` is the whole
demo.

## The proof

```
sqlmap -u "http://localhost:3000/rest/products/search?q=1" --batch   # direct, finds injection
sqlmap -u "http://localhost:8080/rest/products/search?q=1" --batch   # through the WAF, finds nothing
```

Recorded as a terminal capture and put at the top of the README, next to the
console showing the blocks arriving live.

## Phases

| Phase | Delivers | Proof it works |
|---|---|---|
| 1 | config, engine, decision, fail policy, cache | unit tests on decisions and fail paths |
| 2 | reverse proxy, blocking, full request inspection | integration test: attack gets 403, benign gets 200 |
| 3 | store, explainability, metrics, health endpoints | decode trace and contributions asserted in tests |
| 4 | API and server sent events | API contract tests |
| 5 | operator console | manual, plus a screenshot in the README |
| 6 | Docker compose, Juice Shop, sqlmap demo | the recorded run above |

Each phase lands as its own commit and leaves the branch working.

## Out of scope

Rate limiting, bot detection, TLS termination, multi node coordination and session
tracking. All real WAF features, none of them what this project is demonstrating,
and each one would dilute the thing that makes it worth reading.
