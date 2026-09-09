# Postmortem — v0 (PFE, June 2024)

The original submission is preserved at tag `v0.1-pfe`. It ran, and it produced a
number. The number was not measuring what it appeared to measure. This is what
went wrong, because the failures are more instructive than the code.

## 1. The labels were derived from the features

`Algo_generation_datasets/log_parse.py:87`:

```python
if single_q == 0 and double_q == 0 and dashes == 0 and braces == 0 \
        and spaces == 0 and badwords_count == 0:
    class_flag = "good"
```

A request was labelled `bad` when any of the six counters was non-zero — and those
same six counters were the model's only input. Verified across all 45,233 rows of
`Datasets/Dataset_du_projet/allall.csv`:

| | all counters zero | any counter non-zero |
|---|---|---|
| labelled `good` (36,518) | 36,518 | 0 |
| labelled `bad` (8,703) | 0 | 8,703 |

No exceptions. The label was a deterministic function of the features, so the
model could only rediscover a rule that had already been written by hand. Any
score it produced measured how well k-means approximated `sum(counters) > 0`,
not whether a request was an attack.

## 2. 45,000 rows carried 114 rows of information

The 45,233 labelled rows collapse to **114 unique feature vectors**. One vector —
all six counters zero, labelled `good` — accounts for 36,518 rows, 81% of the
dataset. The model could not distinguish more than 114 kinds of request no matter
which algorithm was used.

## 3. The model lost to the rule that generated its labels

From the project's own `Phase_testing_modèle/test_result_test_again.csv`:

| | Cluster 0 | Cluster 1 |
|---|---|---|
| `good` (36,518) | 36,518 | 0 |
| `bad` (8,703) | **4,175** | 4,528 |

Recall on attacks: **52%**. Precision 100%, false-positive rate 0%. Half of every
attack passed through. The one-line rule that produced the labels would have
scored 100% recall on the same data. k-means did worse because it clusters by
distance: low-signal injections (one quote, two spaces) sit numerically nearer to
benign traffic than to heavy payloads, so they landed in the benign cluster.

Choosing clustering was the root cause. Labels existed; an unsupervised method
threw them away.

## 4. The IPS detected but did not prevent

`Notebooks_jupyter/IPS proxy .ipynb`:

```python
if result['Cluster'][0] == "Cluster 1":
    print('Intrusion Detected !')
```

It printed, then proxied the request anyway. There was no `return`, no 403, no
block. Additional gaps: `do_GET` only, so POST bodies — where most SQL injection
actually travels — were never inspected; headers and cookies were ignored;
`parts[3]` on a split path raised `IndexError` for most real URLs; and the k-means
model was retrained from CSV on every startup.

## 5. The feature extractor corrupted its own output

`log_parse.py:110` calls `ExtractFeatures(method, body, path, headers)` against the
signature `ExtractFeatures(method, path_enc, body_enc, headers)` — the path and body
arguments are swapped. `ExtractFeatures` then counts characters from the *global*
`body` rather than its own parameter, so the counts do not correspond to the
arguments passed. Both errors are visible in the shipped data: in
`Datasets/requetes_malicieux/bad1.csv` the `path` column contains request bodies
and vice versa, and both `bad1.csv` and `bad2.csv` contain thousands of rows
labelled `good`.

## What v1 changes

| v0 | v1 |
|---|---|
| Labels derived from the features | Ground-truth labels from ECML/PKDD 2007, which tags attack type |
| 6 counters, 114 distinct values | Char n-grams (3–5) + 25 numeric features |
| Raw string, single URL decode | Recursive decode: URL, HTML entities, JS escapes, unicode, comments |
| k-means, unsupervised | Supervised 3-class LightGBM, benchmarked against the v0 rule |
| Accuracy on training data | Held-out test set, PR-AUC, recall at a fixed false-positive budget |
| No attack type | `benign` / `sqli` / `xss` |
| Detected, forwarded anyway | Threshold chosen against an explicit FPR budget, for a proxy that blocks |
