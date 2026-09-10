## Model comparison (validation set)

| Model | macro-F1 | PR-AUC | SQLi recall | XSS recall | recall @ FPR | achieved FPR | ms/req |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rule baseline (v0 heuristic) | 0.335 | 0.392 | 0.932 | 0.000 | 0.920 | 0.522 | 0.01 |
| LogReg + char n-grams | 0.909 | 0.906 | 0.804 | 0.821 | 0.799 | 0.001 | 0.88 |
| **LightGBM + n-grams + numeric** | 0.916 | 0.908 | 0.829 | 0.824 | 0.811 | 0.001 | 1.01 |

## Final model, held-out test set

| Class | Precision | Recall | F1 | Support |
| --- | --- | --- | --- | --- |
| `benign` | 0.933 | 0.995 | 0.963 | 2101 |
| `sqli` | 0.971 | 0.802 | 0.878 | 455 |
| `xss` | 0.993 | 0.818 | 0.897 | 346 |

## Operating points

| FPR budget | Threshold | Recall | Precision | Achieved FPR | False blocks |
| --- | --- | --- | --- | --- | --- |
| 0.1% | 0.9165 | 0.803 | 0.997 | 0.10% | 2 / 2101 |
| 0.5% | 0.5431 | 0.811 | 0.985 | 0.48% | 10 / 2101 |
| 1.0% | 0.3925 | 0.814 | 0.969 | 1.00% | 21 / 2101 |

## Generalisation

- Unseen attack types (never trained on): **0.209** (2029/9724)
- CSIC 2010, separate corpus: recall **0.147**, FPR 0.003
- Corpus discrimination accuracy: **1.000**

## Robustness to obfuscation

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

## Adversarial training

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

## What it misses

|  | Caught | Missed |
| --- | --- | --- |
| Median length | 291 | 221 |
| Median decode depth | 1.0 | 0.0 |
| Share with a body | 0.131 | 0.431 |
| Median SQL keywords | 1.0 | 0.0 |
| Median XSS keywords | 1.0 | 0.0 |

Miss rate by class: sqli 21.5%, xss 17.9%.
