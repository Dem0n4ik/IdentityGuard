# Independent CloudTrail evaluation

Source: [Ariel Cyber Innovation Center test split](https://github.com/ArielCyber/cloud_log_sampling/tree/18d3f248f4def592f4e86152c3fcb54506fbcbf6), commit `18d3f248f4def592f4e86152c3fcb54506fbcbf6`.
Archive SHA-256: `d5dce3dbdb61ffb935e16cb4728aaca933daa42201a672dfad7387fd168f6eb0`.
Evaluation period: 2026-04-04 UTC, the corpus's concurrent attack and benign capture.

The original identities and times are preserved. The earlier records are outside the 14-day lookback for April 4, and the corpus provides no IAM posture snapshots. This run therefore measures cold-start performance. April 4 is declared a collection boundary, so the gap between captures cannot supply dormancy evidence. An identity-hour is positive if it contains an attributed attack record. Multiple scenarios can share one window. A detected window counts for each scenario it contains.

Unique records: **24079** from 24087 source rows. Records in the evaluation period: **7315**. Scored windows: **25**. Positive windows: **3**. Unattributed attack records: **112**.

The extended run applies the existing `aws-sensitive-control-plane` rule, developed on Stratus. Rule SHA-256: `d12718119892d71ac38a30a1dc2a895cc6370cbb275658799ea0a530d96f33e0`.

Declaring the boundary changes base-model false positives from **14 to 0** and detected positive windows from **3/3 to 1/3**.

The M=1 run recomputes the profiles and windows from the same events with all context weights removed. Numeric behavior signals and severity policies still apply.

| Metric | Base cloud-v2 | With AWS rule |
| --- | ---: | ---: |
| ROC AUC | 0.666667 | 0.666667 |
| Precision | 1.000000 | 1.000000 |
| Recall | 0.333333 | 0.333333 |
| F1 | 0.500000 | 0.500000 |
| F1 with M=1 | 0.500000 | 0.500000 |
| F1 at high severity | 0.000000 | 0.000000 |
| F1 at high severity with M=1 | 0.000000 | 0.000000 |
| False medium | 0 | 0 |
| False high | 0 | 0 |
| Static baseline false positives | 0 | 0 |

| Scenario | Unique attack records | Unattributed | Positive windows | Detected base | Detected with rule |
| --- | ---: | ---: | ---: | ---: | ---: |
| `AnonymousS3Calls` | 17 | 12 | 1 | 1 | 1 |
| `AnonymousS3PentestWeirdAPIs` | 25 | 25 | 0 | 0 | 0 |
| `FullPersistenceCreationChain` | 10 | 0 | 1 | 1 | 1 |
| `MassDeleteMultipleBuckets` | 510 | 9 | 1 | 1 | 1 |
| `MassDeleteSingleBucket` | 302 | 1 | 1 | 1 | 1 |
| `MassGetMultipleBuckets` | 535 | 32 | 2 | 1 | 1 |
| `MassGetSingleBucket` | 123 | 2 | 1 | 1 | 1 |
| `MassPutMultipleBuckets` | 542 | 22 | 2 | 1 | 1 |
| `MassPutSingleBucket` | 520 | 9 | 3 | 1 | 1 |
| `RootFederationTokenGeneration` | 1 | 0 | 1 | 1 | 1 |
