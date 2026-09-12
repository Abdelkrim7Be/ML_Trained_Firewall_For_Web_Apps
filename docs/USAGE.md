# Using the platform

Two halves. Part 1 trains a model; part 2 puts it in front of an application.

---

## Setup, once

```sh
make install     # creates .venv and installs everything
make data        # downloads the corpora, parses and dedupes them (~40 MB)
make train       # trains the models, writes models/model.joblib
```

`make train` takes a couple of minutes and has to run before anything in part 2,
because the firewall loads `models/model.joblib` at startup.

---

## Part 1: the model

### Train and evaluate

```sh
make train       # rule baseline, logistic regression, LightGBM; picks the threshold
make evaluate    # robustness, error analysis, external benchmark, figures, tables
```

Results land in `reports/`:

| File | What it holds |
|---|---|
| `metrics.json` | every number from the run |
| `tables.md` | the same numbers as markdown, pasted into the README |
| `robustness.json` | recall under 13 obfuscation transforms |
| `errors.json` | what the model misses and whether it has a shape |
| `confusion_matrix.png`, `pr_curve.png`, `calibration.png` | figures |

### Score a single request from the shell

```sh
mlwaf predict "/item?id=1%27+UNION+SELECT+password+FROM+users--"
mlwaf predict "/account" --method POST --body "name=O'Brien&city=Cork"
```

```
BLOCK  attack_score=1.0000  threshold=0.6764   worst_unit=query:id
  benign  0.0000
  sqli    1.0000
  xss     0.0000
```

`worst_unit` names the parameter that drove the score: `model.joblib` scores each
value independently (see docs/FINDINGS.md), so the CLI reports which one lost.
Point `--model models/model_ecml.joblib` at the earlier request-level model to
compare against that architecture directly; it omits `worst_unit` and scores the
request as a whole.

### Explore interactively

```sh
make notebook    # opens notebooks/01_data_and_model.ipynb
```

### Slower checks, run when changing the design

```sh
make stability   # refits across 5 seeds, reports mean and standard deviation
make adversarial # trains on obfuscated payloads, scores on held out transforms
```

`make stability` is the one that decides whether a change actually helped. A
difference smaller than the spread across seeds is not a result.

---

## Part 2: the firewall

### The full demo

```sh
docker compose up --build
```

| URL | What |
|---|---|
| http://localhost:8080 | OWASP Juice Shop, protected |
| http://localhost:8080/_waf | the operator console |
| http://localhost:3000 | Juice Shop directly, for comparison |

### In front of your own application

```sh
WAF_UPSTREAM=http://localhost:3000 WAF_MODE=detect python -m mlwaf.waf.app
```

The firewall listens on 8080 and forwards everything except `/_waf/*` to the
upstream. Point your browser or client at the firewall instead of the application.

### Configuration

Every setting is an environment variable prefixed `WAF_`. A `.env` file works too.

| Variable | Default | What it does |
|---|---|---|
| `WAF_UPSTREAM` | `http://localhost:3000` | the application to protect |
| `WAF_PORT` | `8080` | what the firewall listens on |
| `WAF_MODE` | `detect` | `detect` records, `block` enforces |
| `WAF_THRESHOLD` | from training | score at or above which a request is refused |
| `WAF_FAIL_MODE` | `open` | what to do when scoring fails: `open` allows, `closed` refuses |
| `WAF_SCORING_BUDGET_MS` | `25` | past this a request is allowed and counted |
| `WAF_MAX_BODY_BYTES` | `1048576` | larger bodies are forwarded unscored |
| `WAF_DB_PATH` | `data/waf.db` | decision log |
| `WAF_FEEDBACK_PATH` | `data/feedback.jsonl` | where false positive marks are appended |
| `WAF_MODEL_PATH` | `models/model.joblib` | the model to serve |
| `WAF_ADMIN_TOKEN` | generated | token for the console and its API |
| `WAF_METRICS_PUBLIC` | `false` | serve `/_waf/metrics` without a token |

### The control plane token

The console and the proxy share a port, so anything that can reach your site can
reach `/_waf`. It therefore requires a token. Set one:

```sh
WAF_ADMIN_TOKEN=$(openssl rand -base64 32) python -m mlwaf.waf.app
```

Leave it unset and one is generated at startup and written to the log:

```
{"level":"warning","message":"no WAF_ADMIN_TOKEN set, generated one for this run",
 "admin_token":"xQ8f...."}
```

The console asks for it once and keeps it for the browser session. On the command
line, send it as a header:

```sh
curl -H "X-MLWAF-Token: $WAF_ADMIN_TOKEN" localhost:8080/_waf/status
curl -H "Authorization: Bearer $WAF_ADMIN_TOKEN" localhost:8080/_waf/status
```

`/_waf/healthz` and `/_waf/readyz` stay open, because orchestrators have to poll
them and they reveal nothing.

### Rolling it out properly

Start in detect mode. Nothing is refused, everything is scored, and the response
carries `X-MLWAF-Action: would-block` on requests enforcement would have stopped.

1. Run with `WAF_MODE=detect` in front of real traffic.
2. Open the console, set the filter to **flagged only**. That is the review queue:
   everything the firewall would have blocked.
3. Work through it. Anything that is not an attack, mark **false positive**. It is
   written to `data/feedback.jsonl` in the shape the training pipeline reads.
4. When the queue is quiet, promote to enforcing with the **BLOCK** toggle in the
   header, or restart with `WAF_MODE=block`.

Do not skip step 1. This model refuses `/users/42/profile`
(see [`FINDINGS.md`](FINDINGS.md)), and detect mode is how you find that out on
your own traffic before your users do.

---

## The console

`http://localhost:8080/_waf`

**Header** carries the connection state, the upstream, uptime, and the
detect/block toggle. Switching mode takes effect immediately, with no restart.

**Stat strip** shows requests, blocked, flagged, worst scoring latency and unscored
requests over the last five minutes. The sparkline is traffic volume, with the
amber portion being flagged requests.

**Threshold slider.** Drag it and the readout says what that threshold would have
done to the last hour of real traffic: how many requests would be blocked, the
change against the current setting, and how many flip. Nothing is applied until
you press **apply**. This is the false positive budget from part 1, made
adjustable.

**Decision table** streams live. Filter by verdict, class, or free text, or switch
to flagged only for the review queue. **pause** freezes the stream while you read.

**Detail pane**, on clicking a row:

- the request, its score against the threshold, latency, decode depth
- the **decode trace**, one line per normalisation round, showing the obfuscation
  coming apart
- **what drove the score**, the largest per feature contributions from the model
- **false positive** / **true positive** buttons, which record feedback

The decode trace is the thing worth looking at:

```
raw               id=1%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users--
decode round 1    id=1%27%20UNION%20SELECT%20password%20FROM%20users--
decode round 2    id=1' UNION SELECT password FROM users--
unicode and case  id=1' union select password from users--
```

---

## Operating it

```sh
curl localhost:8080/_waf/healthz   # liveness
curl localhost:8080/_waf/readyz    # readiness, 503 until the model is warm
curl -H "X-MLWAF-Token: $T" localhost:8080/_waf/metrics   # prometheus
curl -H "X-MLWAF-Token: $T" localhost:8080/_waf/status    # mode, threshold, counters
```

Logs are JSON, one object per line, with a request id on anything request scoped:

```sh
python -m mlwaf.waf.app | jq 'select(.message == "blocked")'
```

Metrics worth alerting on:

| Metric | Why |
|---|---|
| `mlwaf_degraded_total` | requests handled without a usable score, a hole in the firewall |
| `mlwaf_scoring_seconds` | if the budget is being approached, protection is at risk |
| `mlwaf_flagged_total` | a spike is either an attack or a bad threshold |
| `mlwaf_ready` | 0 means the model is not serving |

### API

Everything the console does is available directly.

All of these need the token. `export T=$WAF_ADMIN_TOKEN` first, then:

```sh
# recent decisions, filtered
curl -H "X-MLWAF-Token: $T" "localhost:8080/_waf/decisions?only_flagged=true&limit=50"

# one decision, with its explanation
curl -H "X-MLWAF-Token: $T" localhost:8080/_waf/decisions/42

# what a different threshold would have done
curl -H "X-MLWAF-Token: $T" "localhost:8080/_waf/threshold/impact?value=0.85"

# change the threshold, and the mode
curl -X POST localhost:8080/_waf/threshold -H "X-MLWAF-Token: $T" \
     -H 'content-type: application/json' -d '{"value":0.85}'
curl -X POST localhost:8080/_waf/mode -H "X-MLWAF-Token: $T" \
     -H 'content-type: application/json' -d '{"mode":"block"}'

# mark a false positive
curl -X POST localhost:8080/_waf/decisions/42/feedback -H "X-MLWAF-Token: $T" \
     -H 'content-type: application/json' -d '{"label":"false_positive"}'

# live stream
curl -N "localhost:8080/_waf/stream?token=$T"
```

Interactive docs at `http://localhost:8080/_waf/docs`.

---

## Tests

```sh
make test        # unit and integration, about 30 seconds
make e2e         # end to end against real server processes, several minutes
make lint
```

## Capacity

One process serves roughly **80 requests per second**, with scoring taking about
8 ms. Throughput is flat past four concurrent clients because scoring holds the
GIL. Past that, run several processes behind a load balancer; SQLite in WAL mode
handles multiple writers. Note that the console's live stream and the decision
cache are per process, so each console then sees only its own worker's traffic.
Numbers and method in [`FINDINGS.md`](FINDINGS.md).

The end to end suite starts real server processes and a real origin, then checks
blocking, origin isolation, obfuscation handling, concurrency, restart
persistence, graceful shutdown, structured logging and the live stream. It also
asserts the known misses and the known false positive, so a change in either
direction shows up.

---

## Closing the loop

False positives marked in the console accumulate in `data/feedback.jsonl`, in the
schema the training pipeline reads:

```json
{"ts": 1789, "decision_id": 42, "label": "false_positive",
 "method": "GET", "path": "/users/42/profile", "query": "",
 "canonical": "get\\n/users/42/profile", "score": 0.9996,
 "predicted_class": "sqli"}
```

Folding that back into training is deliberately a manual step. Retraining on
operator feedback without looking at it is how a firewall learns to allow whatever
an attacker patiently marks as a false positive.
