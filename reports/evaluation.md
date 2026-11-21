# Synthetic risk evaluation

Evaluation period ends at 2026-11-07 00:00 UTC.

FR-DEV event sequences with the completed synthetic IAM inventory and default cloud-v2.

The M=1 run recomputes the profiles and windows from the same events with all context weights removed. Numeric behavior signals and severity policies still apply.

| Metric | Value |
| --- | ---: |
| Evaluated windows | 855 |
| ROC AUC | 1.000000 |
| Precision | 1.000000 |
| Recall | 1.000000 |
| F1 | 1.000000 |
| F1 with M=1 | 0.952381 |
| F1 at high severity | 0.777778 |
| F1 at high severity with M=1 | 0.166667 |
| False high | 0 |
| False medium | 0 |
| Static false positives | 236 |

| Scenario | Windows | Max risk | Medium | High |
| --- | ---: | ---: | ---: | ---: |
| S1 | 1 | 50.98 | 0 | 1 |
| S2 | 1 | 52.10 | 0 | 1 |
| S3 | 2 | 52.96 | 1 | 1 |
| S4 | 1 | 52.00 | 0 | 1 |
| S5 | 1 | 50.19 | 0 | 1 |
| S6 | 1 | 41.27 | 1 | 0 |
| S7 | 1 | 59.16 | 0 | 1 |
| S8 | 2 | 49.38 | 2 | 0 |
| S9 | 1 | 37.93 | 0 | 1 |
| b1 | 24 | 17.91 | 0 | 0 |
| b2 | 3 | 2.68 | 0 | 0 |
| b3 | 6 | 3.07 | 0 | 0 |
| b4 | 33 | 9.03 | 0 | 0 |
| b5 | 11 | 4.39 | 0 | 0 |

## Acceptance criteria

- [x] ROC AUC ≥ 0.97
- [x] S1–S9 produce incidents
- [x] S1, S3, S4, S5, S7, S9 produce high incidents
- [x] b1–b5 produce zero high and at most three medium windows
- [x] Context improves F1 at the high threshold
- [x] Static baseline produces more false positives
- [x] S8 role receives risky_source
