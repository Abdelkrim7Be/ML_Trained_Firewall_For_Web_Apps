## Model comparison (validation set)

| Model | macro-F1 | PR-AUC | SQLi recall | XSS recall | recall @ FPR | achieved FPR | ms/req |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rule baseline (v0 heuristic) | 0.333 | 0.391 | 0.932 | 0.000 | 0.921 | 0.526 | 0.01 |
| LogReg + char n-grams | 0.915 | 0.913 | 0.809 | 0.818 | 0.811 | 0.001 | 0.91 |
| **LightGBM + n-grams + numeric** | 0.919 | 0.909 | 0.831 | 0.818 | 0.824 | 0.001 | 0.96 |

## Final model, held-out test set

| Class | Precision | Recall | F1 | Support |
| --- | --- | --- | --- | --- |
| `benign` | 0.933 | 0.996 | 0.963 | 2101 |
| `sqli` | 0.981 | 0.804 | 0.884 | 455 |
| `xss` | 0.997 | 0.821 | 0.900 | 346 |

## Operating points

| FPR budget | Threshold | Recall | Precision | Achieved FPR | False blocks |
| --- | --- | --- | --- | --- | --- |
| 0.1% | 0.9690 | 0.801 | 0.997 | 0.10% | 2 / 2101 |
| 0.5% | 0.4163 | 0.813 | 0.985 | 0.48% | 10 / 2101 |
| 1.0% | 0.2412 | 0.815 | 0.969 | 1.00% | 21 / 2101 |

## Generalisation

- Unseen attack types (never trained on): **0.341** (3319/9724)
- CSIC 2010, separate corpus: recall **0.165**, FPR 0.031
- Corpus discrimination accuracy: **1.000**

## Robustness to obfuscation

| Transform | Family | Bypass before | Bypass after | Change |
| --- | --- | --- | --- | --- |
| `case_flip` | encoding | 0.0% | 0.0% | — |
| `url_encode` | encoding | 0.1% | 0.1% | — |
| `double_url_encode` | encoding | 0.3% | 0.3% | — |
| `html_entity_encode` | encoding | 0.0% | 0.0% | — |
| `js_unicode_escape` | encoding | 0.1% | 0.1% | — |
| `fullwidth` | encoding | 0.0% | 0.0% | — |
| `comment_split` |  | — | 0.0% | new |
| `space_to_comment` | sql syntax | 20.5% | 20.5% | — |
| `space_to_tab` | whitespace | 4.8% | 4.8% | — |
| `space_to_newline` | whitespace | 5.1% | 5.1% | — |
| `char_function` | literal | 6.5% | 6.5% | — |
| `hex_literal` | literal | 35.1% | 35.1% | — |
| `concat_quotes` | literal | 0.0% | 0.0% | — |
