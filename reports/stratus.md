# Stratus Red Team CloudTrail replay

Source: [DataDog/stratus-red-team at `df3316f6f73a219eba715a505f2b4742a9cce197`](https://github.com/DataDog/stratus-red-team/tree/df3316f6f73a219eba715a505f2b4742a9cce197/docs/detonation-logs).
Corpus SHA-256: `23a37d29c01cab62f1fd52787d3a97cacdc89f9df7aaa93e8296f12d3aa93260`.
Evaluation ends 2026-11-07 00:00 UTC. Model: `cloud-v2`.

Public CloudTrail events were replayed over the IdentityGuard synthetic background.
Techniques are ordered by identifier and assigned round-robin to baseline IAM users with a normal schedule.
Replay substitutes the scoring identity, account, time, and event ID. Operation, region, source address, and result are preserved.
Relative intervals are preserved unless the capture exceeds 55 minutes, in which case they are scaled proportionally.
S1–S9 are excluded. Evaluation labels are kept outside the risk engine.
Detection rules: base model only.

Evaluated windows: 850. Background false positives: 0 medium, 0 high.

The M=1 run recomputes the profiles and windows from the same events with all context weights removed. Numeric behavior signals and severity policies still apply.

| Metric | Value |
| --- | ---: |
| ROC AUC | 1.000000 |
| Precision | 1.000000 |
| Recall | 0.805556 |
| F1 | 0.892308 |
| F1 with M=1 | 0.875000 |
| F1 at high severity | 0.325581 |
| F1 at high severity with M=1 | 0.000000 |
| Static false positives | 230 |

## Acceptance

- [ ] R ≥ 25 for all techniques (29/36)
- [ ] R ≥ 30 for at least 30 techniques (26/36)
- [x] Zero high severity background windows (0)

## Results

| Technique | Replay identity | Events | B | M | R | Level |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `aws.credential-access.ec2-get-password-data` | alice-admin | 34 | 0.2962 | 1.14 | 33.76 | medium |
| `aws.credential-access.ec2-steal-instance-credentials` | bohdan-dev | 45 | 0.2783 | 1.38 | 38.40 | medium |
| `aws.credential-access.secretsmanager-batch-retrieve-secrets` | olena-analyst | 5 | 0.2792 | 1.00 | 27.92 | medium |
| `aws.credential-access.secretsmanager-retrieve-secrets` | marko-support | 21 | 0.2962 | 1.06 | 31.39 | medium |
| `aws.credential-access.ssm-retrieve-securestring-parameters` | nadia-sec | 10 | 0.2838 | 1.00 | 28.38 | medium |
| `aws.defense-evasion.cloudtrail-delete` | svc-backup | 1 | 0.4070 | 1.54 | 62.68 | high |
| `aws.defense-evasion.cloudtrail-event-selectors` | svc-etl | 1 | 0.4070 | 1.56 | 63.50 | high |
| `aws.defense-evasion.cloudtrail-stop` | svc-billing | 1 | 0.4070 | 1.00 | 40.70 | medium |
| `aws.defense-evasion.dns-delete-logs` | ci-deployer | 1 | 0.4070 | 1.48 | 60.24 | high |
| `aws.defense-evasion.organizations-leave` | svc-monitor | 3 | 0.4070 | 1.00 | 40.70 | medium |
| `aws.defense-evasion.vpc-remove-flow-logs` | alice-admin | 1 | 0.4070 | 1.14 | 46.40 | medium |
| `aws.discovery.ec2-download-user-data` | bohdan-dev | 19 | 0.2746 | 1.38 | 37.90 | medium |
| `aws.execution.ec2-launch-unusual-instances` | olena-analyst | 3 | 0.1862 | 1.00 | 18.62 | low |
| `aws.execution.ec2-user-data` | marko-support | 35 | 0.2326 | 1.06 | 24.66 | low |
| `aws.execution.ssm-send-command` | nadia-sec | 56 | 0.2058 | 1.00 | 20.58 | low |
| `aws.execution.ssm-start-session` | svc-backup | 29 | 0.1939 | 1.54 | 29.87 | medium |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | svc-etl | 1 | 0.3507 | 1.56 | 54.71 | high |
| `aws.exfiltration.ec2-share-ami` | svc-billing | 1 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.exfiltration.ec2-share-ebs-snapshot` | ci-deployer | 1 | 0.3311 | 1.48 | 49.00 | medium |
| `aws.exfiltration.ec2-share-ebs-volume` | svc-monitor | 1 | 0.1862 | 1.00 | 18.62 | low |
| `aws.exfiltration.rds-share-snapshot` | alice-admin | 1 | 0.3311 | 1.14 | 37.74 | medium |
| `aws.impact.bedrock-invoke-model` | bohdan-dev | 15 | 0.2687 | 1.38 | 37.09 | medium |
| `aws.initial-access.console-login-without-mfa` | olena-analyst | 1 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.lateral-movement.ec2-instance-connect` | marko-support | 3 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.lateral-movement.ec2-serial-console-send-ssh-public-key` | nadia-sec | 4 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.persistence.iam-backdoor-role` | svc-backup | 1 | 0.3311 | 1.54 | 50.98 | high |
| `aws.persistence.iam-backdoor-user` | svc-etl | 1 | 0.3311 | 1.56 | 51.64 | high |
| `aws.persistence.iam-create-admin-user` | svc-billing | 3 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.persistence.iam-create-backdoor-role` | ci-deployer | 2 | 0.3311 | 1.48 | 49.00 | medium |
| `aws.persistence.iam-create-user-login-profile` | svc-monitor | 3 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.persistence.lambda-backdoor-function` | alice-admin | 1 | 0.1862 | 1.14 | 21.22 | low |
| `aws.persistence.lambda-layer-extension` | bohdan-dev | 1 | 0.1683 | 1.38 | 23.22 | low |
| `aws.persistence.lambda-overwrite-code` | olena-analyst | 1 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.persistence.rolesanywhere-create-trust-anchor` | marko-support | 2 | 0.3311 | 1.00 | 33.11 | medium |
| `aws.persistence.sts-federation-token` | nadia-sec | 2 | 0.1862 | 1.00 | 18.62 | low |
| `aws.privilege-escalation.iam-update-user-login-profile` | svc-backup | 1 | 0.3311 | 1.54 | 50.98 | high |
