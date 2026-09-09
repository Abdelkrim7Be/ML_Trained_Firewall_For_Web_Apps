# ML WAF — SQL injection and XSS detection in HTTP requests

A supervised classifier that reads a full HTTP request — method, path, query and
body — and decides whether it is benign, SQL injection, or XSS. Built to sit
inline in a reverse proxy and refuse the requests it flags.

This is v1. The original student project (PFE, June 2024) is preserved at tag
`v0.1-pfe`, and [`POSTMORTEM.md`](POSTMORTEM.md) documents why its 52% attack
recall was measuring the wrong thing entirely.

---

<!-- RESULTS -->

---

## How it works

```
HTTP request
   ↓
normalise      recursive URL-decode → HTML entities → JS escapes →
               data: URI base64 → unicode NFKC → strip SQL comments
   ↓
features       char n-grams (3–5, TF-IDF)  +  25 numeric features
   ↓
LightGBM       P(benign), P(sqli), P(xss)
   ↓
decision       block if 1 − P(benign) ≥ threshold
```

### Normalisation comes first

Payloads do not arrive in the clear. Each of these is invisible to a naive
character count, and each is handled before features are computed:

| Sent | Naive view | After normalisation |
|---|---|---|
| `%2527%2520OR%25201%3D1` | no quote | `' OR 1=1` |
| `&#60;script&#62;` | no angle bracket | `<script>` |
| `\u003cimg src=x\u003e` | no angle bracket | `<img src=x>` |
| `un/**/ion sel/**/ect` | no keyword | `union select` |
| `＜script＞` (fullwidth) | no angle bracket | `<script>` |

The number of decoding rounds a request needed is kept as a feature. Ordinary
traffic needs zero or one.

### Why character n-grams

The previous version counted six things: quotes, double quotes, dashes, parens,
spaces, SQL keywords. Those counts cannot separate a surname from an auth bypass:

| Request | `single_q` | verdict under counting |
|---|---|---|
| `q=O'Brien` | 1 | identical |
| `q=admin' OR 1=1` | 1 | identical |

Character n-grams see `' or` and `nion sel` as features in their own right. The
counters are kept alongside — they are cheap, and they make the feature
importance plot readable — but they are no longer the whole model.

### Choosing the threshold

The model emits a probability; `0.5` is an arbitrary place to cut it. A WAF that
blocks 1% of real traffic is unusable, so the operating point is chosen by fixing
a false-positive budget on validation data and reading off the recall that budget
buys. The threshold is never tuned on the test set.

---

## Data

[ECML/PKDD 2007 Discovery Challenge](http://www.lirmm.fr/pkdd2007-challenge/index.html),
mirrored by [msudol/Web-Application-Attack-Datasets](https://github.com/msudol/Web-Application-Attack-Datasets).
It is the only public corpus with full HTTP requests *and* per-request attack
type labels.

| Split | Rows | Purpose |
|---|---|---|
| `benign` / `sqli` / `xss` | 14,507 | train / validate / test (60-20-20 stratified) |
| 5 other attack types | 9,724 | never trained on — generalisation check |
| CSIC 2010 | 25,060 | independent corpus — second generalisation check |

Three deliberate choices:

1. **Labels are ground truth, not derived.** v0 generated its labels with a rule
   over the same six features it then trained on, making the task circular. Here
   the attack type comes from the challenge organisers.
2. **Both classes come from one corpus.** Benign from dataset A and attacks from
   dataset B teaches a model to recognise the dataset, not the attack. A
   corpus-discrimination check is reported below to show how separable the two
   corpora are, so the cross-corpus number can be read honestly.
3. **Duplicates are removed before splitting.** Near-identical rows straddling the
   split leak the answer; CSIC alone contained 36,005 exact duplicates.

---

## Reproduce

```sh
make install     # uv venv + deps
make data        # download corpora, parse, dedupe   (~40 MB)
make train       # train all three models, write reports/metrics.json
make plots       # confusion matrix, PR curve, feature importance
make test        # 24 tests
```

Score a single request:

```sh
mlwaf predict "/item?id=1%27+UNION+SELECT+password+FROM+users--"
mlwaf predict "/account" --method POST --body "name=O'Brien&city=Cork"
```

Explore the data and model interactively:

```sh
make notebook    # notebooks/01_data_and_model.ipynb
```

---

## Layout

```
src/mlwaf/
  download.py   fetch the corpora
  parse.py      raw HTTP blocks → structured requests
  decode.py     the normalisation chain
  features.py   char n-grams + 25 numeric features
  dataset.py    labelling, dedupe, held-out splits
  model.py      rule baseline, logistic regression, LightGBM
  train.py      fit, compare, select threshold, persist
  evaluate.py   metrics
  plots.py      report figures
  report.py     README tables, generated from metrics.json
  cli.py        mlwaf <download|dataset|train|plots|predict>
notebooks/      exploration only — never runtime
models/         model.joblib + MODEL_CARD.md
reports/        metrics.json, tables.md, figures
```

Notebooks explore; `src/` runs. In v0 the notebooks *were* the runtime, which is
why nothing in it could be tested or deployed.

---

## Limitations

- ECML/PKDD 2007 is old, and its URLs and parameter values were randomised during
  sanitisation. Real traffic has structure this corpus does not.
- **No adversarial evaluation yet.** The model has not faced tools that mutate
  payloads specifically to evade ML classifiers. Recall against a motivated
  attacker will be lower than the numbers above.
- Two attack classes are trained; five more are only measured.
- Per-request only — no session state, so slow or distributed attacks that look
  benign one request at a time are invisible.

See [`models/MODEL_CARD.md`](models/MODEL_CARD.md) for the full card.

## Next

The classifier is the first half. The second half is the proxy that uses it:
inline blocking with a real `403`, POST/header/cookie inspection, structured
per-request logging, and a Docker Compose demo against a deliberately vulnerable
app. That is what turns a model into a firewall.
