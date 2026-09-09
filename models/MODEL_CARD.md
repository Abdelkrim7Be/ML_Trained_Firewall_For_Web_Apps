# Model card — mlwaf SQLi/XSS detector

## Intended use

Inline classification of HTTP requests inside a reverse proxy, to decide whether a
request should be forwarded or refused with `403`. It is a research and portfolio
project. It has not been run against production traffic and should not be the only
control in front of a real application.

## Task

Three-class classification of a single HTTP request:

| class | meaning |
|---|---|
| `benign` | ordinary traffic |
| `sqli` | SQL injection |
| `xss` | cross-site scripting |

The block decision is binary and derived from the class probabilities as
`1 - P(benign) >= threshold`. The predicted attack class is used only for logging
and reporting, so a confusion between `sqli` and `xss` does not change whether a
request is blocked.

## Training data

ECML/PKDD 2007 Discovery Challenge, test partition — the only public corpus that
carries full HTTP requests *and* a per-request attack type. Requests were recorded
from real traffic, then sanitised: URLs, parameter names and parameter values were
replaced with random strings.

Both the benign and the attack rows come from this single corpus. That is
deliberate: drawing benign traffic from one dataset and attacks from another
teaches a model to recognise the dataset — host names, header ordering, formatting
conventions — rather than the attack, and produces near-perfect scores that
collapse on contact with real traffic.

Exact duplicates of the normalised request text are removed before splitting, so
identical rows cannot appear on both sides of the train/test boundary.

## Features

Requests are normalised before any feature is computed: URL-decoded repeatedly
until stable, then HTML entities, JavaScript `\xNN`/`\uNNNN` escapes, base64 inside
`data:` URIs, unicode NFKC folding, and inline SQL comment removal. The number of
decoding rounds required is itself a feature.

Two blocks are fused:

- **Character n-grams (3–5, TF-IDF).** The main signal. Counts of quotes cannot
  distinguish `O'Brien` from `admin' OR 1=1`; the n-grams `' or`, `union sel`,
  `<scr`, `onerror=` can.
- **25 numeric features.** SQL-oriented (quotes, dashes, parens, keywords),
  XSS-oriented (angle brackets, tags, event handlers, entities), and generic
  (length, entropy, decode depth, character-class ratios).

Host, cookie and user-agent headers are deliberately excluded, because they
identify the corpus rather than the attack.

## Evaluation

Stratified 60/20/20 split. Models are compared on validation; the test split is
scored once, at the end. The operating threshold is selected on validation against
a false-positive budget and never tuned on test.

Accuracy is not reported. The corpus is ~72% benign, so a model that blocks nothing
scores 72%.

Reported instead: per-class precision/recall/F1, macro-F1, PR-AUC on the binary
attack-vs-benign view, and recall at fixed false-positive rates. Two
generalisation checks are also run: recall on five attack types that were never
trained on, and performance on CSIC 2010, an entirely separate corpus.

See `reports/metrics.json` for the numbers and the README for the summary table.

## Known limitations

- **Corpus age and sanitisation.** ECML/PKDD 2007 is old, and its URLs and
  parameter values are randomised. Real traffic has structure this corpus does not.
- **No adversarial evaluation.** The model has not been tested against tools that
  mutate payloads specifically to evade ML classifiers. Recall against a motivated
  attacker will be lower than the numbers reported here.
- **Two attack classes.** Path traversal, OS command injection, LDAP and XPath
  injection and SSI are measured but not trained on.
- **Per-request only.** No session state, so slow or distributed attacks that look
  benign request-by-request are invisible to it.
- **Encrypted or non-form bodies.** Multipart uploads and non-UTF-8 bodies are
  handled as raw text.

## Reproducing

```sh
make install
make data
make train
```
