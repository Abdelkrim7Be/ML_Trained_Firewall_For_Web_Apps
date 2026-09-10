# ML WAF — SQL injection and XSS detection in HTTP requests

A supervised classifier that reads a full HTTP request — method, path, query and
body — and decides whether it is benign, SQL injection, or XSS. Built to sit
inline in a reverse proxy and refuse the requests it flags.

This is v1. The original student project (PFE, June 2024) is preserved at tag
`v0.1-pfe`, and [`POSTMORTEM.md`](POSTMORTEM.md) documents why its 52% attack
recall was measuring the wrong thing entirely.

---

## Results

Trained on 14,507 labelled HTTP requests from ECML/PKDD 2007. The test split is
scored once, at the end.

### Model comparison (validation set)

| Model | macro-F1 | PR-AUC | SQLi recall | XSS recall | recall @ FPR | achieved FPR | ms/req |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rule baseline (v0 heuristic) | 0.335 | 0.392 | 0.932 | 0.000 | 0.920 | 0.522 | 0.01 |
| LogReg + char n-grams | 0.909 | 0.906 | 0.804 | 0.821 | 0.799 | 0.001 | 0.88 |
| **LightGBM + n-grams + numeric** | 0.916 | 0.908 | 0.829 | 0.824 | 0.811 | 0.001 | 1.01 |

### Final model, held-out test set

| Class | Precision | Recall | F1 | Support |
| --- | --- | --- | --- | --- |
| `benign` | 0.933 | 0.995 | 0.963 | 2101 |
| `sqli` | 0.971 | 0.802 | 0.878 | 455 |
| `xss` | 0.993 | 0.818 | 0.897 | 346 |

### Operating points

| FPR budget | Threshold | Recall | Precision | Achieved FPR | False blocks |
| --- | --- | --- | --- | --- | --- |
| 0.1% | 0.9165 | 0.803 | 0.997 | 0.10% | 2 / 2101 |
| 0.5% | 0.5431 | 0.811 | 0.985 | 0.48% | 10 / 2101 |
| 1.0% | 0.3925 | 0.814 | 0.969 | 1.00% | 21 / 2101 |

### Generalisation

- Unseen attack types (never trained on): **0.209** (2029/9724)
- CSIC 2010, separate corpus: recall **0.147**, FPR 0.003
- Corpus discrimination accuracy: **1.000**

![confusion matrix](reports/confusion_matrix.png)

The rule baseline row is the honest headline. It is v0's heuristic — flag anything
containing a quote, dash, paren, space or SQL keyword — and it catches 93% of SQL
injection. It also blocks **52% of legitimate traffic**, and has no concept of XSS
at all, which is why its macro-F1 is 0.335. Beating it is not about finding more
attacks; it is about not destroying the site in the process.

Note what the generalisation numbers say. Recall on the five attack types held out
of training is 0.209, and on CSIC 2010 it is 0.147 — both far below the 0.803 on
matched traffic. The corpus discrimination check explains the second one: a
throwaway classifier separates ECML from CSIC requests with **1.000** accuracy, so
the two corpora share almost no surface structure and that number measures domain
shift, not detection skill. Reporting it beats quietly hoping nobody checks.

## Robustness to obfuscation

Recall on clean corpus payloads answers a question no attacker asks. Every attack
the model catches is rewritten by thirteen transforms that preserve what the
payload does but change how it looks, and counted again.

| Transform | Family | Bypass before | Bypass after | Change |
| --- | --- | --- | --- | --- |
| `case_flip` | encoding | 0.0% | 0.0% | — |
| `url_encode` | encoding | 0.1% | 0.0% | — |
| `double_url_encode` | encoding | 0.3% | 0.3% | — |
| `html_entity_encode` | encoding | 0.0% | 0.0% | — |
| `js_unicode_escape` | encoding | 0.1% | 0.0% | — |
| `fullwidth` | encoding | 0.0% | 0.0% | — |
| `mysql_version_comment` | sql syntax | — | 0.0% | new |
| `space_to_comment` | sql syntax | 20.5% | 0.0% | -20.5% |
| `space_to_tab` | whitespace | 4.8% | 0.0% | -4.8% |
| `space_to_newline` | whitespace | 5.1% | 0.0% | -5.1% |
| `char_function` | literal | 6.5% | 1.4% | -5.1% |
| `hex_literal` | literal | 35.1% | 6.7% | -28.4% |
| `concat_quotes` | literal | 0.0% | 0.0% | — |

The `encoding` family is what the normalisation chain exists to undo, so a non-zero
bypass there is a bug in `decode.py`, not a property of the model. That is how the
chain is tested — and how three real defects were found and fixed:

| Defect | Symptom | Cost |
|---|---|---|
| Comments deleted instead of spaced | `union/**/select` → `unionselect`, destroying the n-gram | 20.5% bypass |
| Hex literals never decoded | `0x61646d696e` left as-is | 35.1% bypass |
| `CHAR()` pattern written `chr?` | matched `ch`/`chr`, never `char` | 6.5% bypass |

A fourth finding was about the harness rather than the model: the `hex_literal`
transform was matching across stray apostrophes in ECML's sanitised noise and
hex-encoding entire query strings, separators included — payloads no attacker would
ever send. Constraining it to literals of at most 32 characters containing no `&`
or `=` made it realistic, and the measured bypass fell from 28.7% to 6.7%.

## Adversarial training

Obfuscated copies of the attack rows are added to the training set. The transforms
are split four/nine: the model trains on four and is scored on nine it has never
seen, so the result measures generalisation rather than memorisation.

| Transform | Seen in training | Recall before | Recall after | Change |
| --- | --- | --- | --- | --- |
| `case_flip` | yes | 0.801 | 0.803 | +0.001 |
| `url_encode` | yes | 0.804 | 0.804 | +0.000 |
| `space_to_tab` | yes | 0.801 | 0.803 | +0.001 |
| `char_function` | yes | 0.790 | 0.805 | +0.015 |
| `double_url_encode` | **no** | 0.798 | 0.796 | -0.001 |
| `html_entity_encode` | **no** | 0.801 | 0.804 | +0.003 |
| `js_unicode_escape` | **no** | 0.804 | 0.804 | +0.000 |
| `fullwidth` | **no** | 0.803 | 0.803 | +0.000 |
| `mysql_version_comment` | **no** | 0.801 | 0.803 | +0.001 |
| `space_to_comment` | **no** | 0.801 | 0.803 | +0.001 |
| `space_to_newline` | **no** | 0.801 | 0.803 | +0.001 |
| `hex_literal` | **no** | 0.748 | 0.749 | +0.001 |
| `concat_quotes` | **no** | 0.803 | 0.803 | +0.000 |

**It barely moves the needle** — between +0.000 and +0.015. That is the honest
result, and it is explainable: normalisation already rewrites these payloads to
their canonical form before the model ever sees them, so the augmented rows are
near-duplicates of the originals. Adversarial training is worth having as
defence-in-depth for obfuscations the normaliser does not know about, but on this
transform set the normaliser is doing essentially all of the work.

## What it misses

|  | Caught | Missed |
| --- | --- | --- |
| Median length | 291 | 221 |
| Median decode depth | 1.0 | 0.0 |
| Share with a body | 0.131 | 0.431 |
| Median SQL keywords | 1.0 | 0.0 |
| Median XSS keywords | 1.0 | 0.0 |

Miss rate by class: sqli 21.5%, xss 17.9%.

Two things stand out. Missed attacks have a median SQL/XSS keyword count of zero
and a decode depth of zero — they carry no obvious signal at all. And they are
three times more likely to carry a POST body.

The body finding looked like a modelling problem, so URL and body were given
separate n-gram spaces on the theory that a long body dilutes a short payload. It
did not work: the miss rate for requests with a body was unchanged and held-out
attack recall fell from 0.34 to 0.21, so the change was reverted. The likelier
explanation is the corpus — ECML's sanitisation buried attack tokens inside random
strings (`ntcebetween4oaenq`, `ghaving`), leaving little to recover.


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
- **Fixed transform catalogue, not an adaptive attacker.** The evasion suite
  applies thirteen hand-written obfuscations. It does not *search* for a bypass the
  way a genetic mutation tool such as WAF-A-MoLE does, so these numbers are a floor
  on robustness, not a ceiling.
- **Generalisation is the weak point.** 0.803 recall on matched traffic, 0.209 on
  attack types held out of training, 0.147 on a separate corpus. The last figure is
  heavily confounded by domain shift (corpus discrimination accuracy 1.000), but
  the first two are not, and the gap is real.
- Two attack classes are trained; five more are only measured.
- Per-request only — no session state, so slow or distributed attacks that look
  benign one request at a time are invisible.

See [`models/MODEL_CARD.md`](models/MODEL_CARD.md) for the full card.

## Next

The classifier is the first half. The second half is the proxy that uses it:
inline blocking with a real `403`, POST/header/cookie inspection, structured
per-request logging, and a Docker Compose demo against a deliberately vulnerable
app. That is what turns a model into a firewall.
