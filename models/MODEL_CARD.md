# Model card, mlwaf SQLi/XSS detector

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

ECML/PKDD 2007 Discovery Challenge, test partition, the only public corpus that
carries full HTTP requests *and* a per-request attack type. Requests were recorded
from real traffic, then sanitised: URLs, parameter names and parameter values were
replaced with random strings.

Both the benign and the attack rows come from this single corpus. That is
deliberate: drawing benign traffic from one dataset and attacks from another
teaches a model to recognise the dataset, host names, header ordering, formatting
conventions, rather than the attack, and produces near-perfect scores that
collapse on contact with real traffic.

Exact duplicates of the normalised request text are removed before splitting, so
identical rows cannot appear on both sides of the train/test boundary.

## Features

Requests are normalised before any feature is computed: URL-decoded repeatedly
until stable, then HTML entities, JavaScript `\xNN`/`\uNNNN` escapes, base64 inside
`data:` URIs, unicode NFKC folding, and inline SQL comment removal. The number of
decoding rounds required is itself a feature.

Two blocks are fused:

- **Character n-grams (3-5, TF-IDF).** The main signal. Counts of quotes cannot
  distinguish `O'Brien` from `admin' OR 1=1`; the n-grams `' or`, `union sel`,
  `<scr`, `onerror=` can.
- **25 numeric features.** SQL-oriented (quotes, dashes, parens, keywords),
  XSS-oriented (angle brackets, tags, event handlers, entities), and generic
  (length, entropy, decode depth, character-class ratios).

Host, cookie and user-agent headers are deliberately excluded, because they
identify the corpus rather than the attack.

## Tried and rejected

Recorded because a negative result is still a result, and the next person to have
the same idea deserves the measurement rather than the intuition.

**Separate n-gram spaces for URL and body.** The error analysis shows attacks
carrying a POST body are missed roughly three times as often as those without one
(0.43 of misses have a body, against 0.13 of catches). The obvious explanation is
dilution: one bag of n-grams over the whole request lets a long body swamp a short
payload. Splitting them into two vectorisers did not help. The miss rate for
requests with a body was unchanged, and recall on attack types held out of training
fell from 0.34 to 0.21. The split was reverted.

The likelier explanation is that ECML's body payloads are simply harder: the
sanitisation buried attack tokens inside random strings (`ntcebetween4oaenq`,
`ghaving`), so many carry almost no recoverable signal. That is a property of the
corpus, not of the feature layout.

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

## Robustness

Recall on clean corpus payloads answers a question no attacker asks, so the model
is also scored against thirteen obfuscation transforms across four families:
encoding (URL, double-URL, HTML entity, JavaScript escape, unicode fullwidth,
case), SQL syntax (comment-as-whitespace, MySQL version comments), whitespace
substitution (tab, newline) and literal rewriting (`CHAR()`, hex literals, string
concatenation).

Transforms in the encoding family are what the normalisation chain exists to undo,
so a non-zero bypass rate there is a defect in `decode.py` rather than a property
of the model. Measuring them is how the chain is verified. Three real bypasses
found this way, comment stripping that deleted rather than spaced, hex literals
that were never decoded, and a `CHAR()` pattern that never matched, were fixed in
the normaliser; `reports/robustness.json` and `reports/robustness_baseline.json`
hold the before and after.

On top of normalisation, the model is also trained on obfuscated copies of its
attack rows. The transforms are split: four are used for augmentation and nine are
held out, so the reported robustness measures generalisation to obfuscations never
seen in training rather than memorisation of the ones that were.
`reports/adversarial.json` holds the comparison.

## Known limitations

- **Corpus age and sanitisation.** ECML/PKDD 2007 is old, and its URLs and
  parameter values are randomised. Real traffic has structure this corpus does not.
- **Hand-written transforms, not an adaptive attacker.** The evasion suite applies
  a fixed catalogue of obfuscations. It does not search for a bypass the way a
  genetic mutation tool such as WAF-A-MoLE does, so it establishes a floor on
  robustness, not a ceiling. An adaptive attacker will do better than these
  numbers suggest.
- **Two attack classes.** Path traversal, OS command injection, LDAP and XPath
  injection and SSI are measured but not trained on.
- **Per-request only.** No session state, so slow or distributed attacks that look
  benign request-by-request are invisible to it.
- **Encrypted or non-form bodies.** Multipart uploads and non-UTF-8 bodies are
  handled as raw text.

## Calibration

The operating point is quoted as "block above threshold t, and 0.1% of legitimate
requests pay for it". That claim only holds if the scores mean what they say, so
expected calibration error and Brier score are reported alongside the ranking
metrics, and `reports/calibration.png` plots predicted confidence against observed
attack rate. A model can rank well and still be badly calibrated, in which case the
chosen threshold does not mean what the table says it means.

## Measurement noise

Every headline number comes from one 60/20/20 split. Refitting an unchanged model
on a different seed moves macro-F1 by roughly half a point, so any comparison
decided by less than that was decided by the split rather than the model.
`mlwaf.stability` refits each candidate across five seeds and reports mean and
standard deviation; it is the tool that settles design choices here, and its
verdict lines mark a difference as real only when it exceeds twice the observed
spread.

## Reproducing

```sh
make install
make data
make train      # the model
make evaluate   # robustness, errors, external benchmark, adversarial, figures
```

`make stability` refits across seeds and is the one to run before believing that a
change helped.
