"""FR-DEV deterministic 21-day CloudTrail-shaped demonstration."""

import argparse
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from ipaddress import ip_network
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import numpy as np

from app.engine.adjustments import Adjustments
from app.engine.detections import Rule
from app.engine.events import Event, Identity, Network
from app.engine.model import CLOUD, DECRYPT_OPERATIONS
from app.engine.posture import Snapshot
from app.engine.scoring import Window, WindowKey, operation_key
from app.ingest import normalize
from app.pipeline import evaluate_events
from app.repository import Repository

PROD = "111122223333"
SHARED = "222233334444"
REGION = "eu-central-1"
US = "us-east-1"
CORP = (ip_network("203.0.113.0/24"), ip_network("198.51.100.0/24"))
ABLATION_METHOD = (
    "The M=1 run recomputes the profiles and windows from the same events with all "
    "context weights removed. Numeric behavior signals and severity policies still apply."
)


@dataclass(frozen=True, slots=True)
class Actor:
    name: str
    kind: str
    start: int
    end: int
    rate: float
    ops: tuple[str, ...]
    regions: tuple[str, ...] = (REGION,)
    human: bool = False
    account: str = PROD

    @property
    def identity(self) -> Identity:
        return Identity(self.account, self.kind, self.name)


ACTORS = (
    Actor(
        "alice-admin",
        "user",
        8,
        18,
        8,
        ("DescribeInstances", "ListUsers", "GetRole", "ListBuckets", "AssumeRole"),
        (REGION, US),
        True,
    ),
    Actor(
        "bohdan-dev",
        "user",
        9,
        20,
        10,
        (
            "GetFunction",
            "UpdateFunctionConfiguration",
            "PutObject",
            "GetObject",
            "FilterLogEvents",
        ),
        human=True,
    ),
    Actor(
        "olena-analyst",
        "user",
        8,
        18,
        6,
        ("StartQueryExecution", "GetQueryResults", "GetObject"),
        human=True,
    ),
    Actor(
        "marko-support",
        "user",
        10,
        19,
        0.2,
        ("DescribeInstances", "GetConsoleOutput"),
        human=True,
    ),
    Actor(
        "nadia-sec",
        "user",
        8,
        18,
        5,
        ("GetFindings", "ListFindings", "LookupEvents", "GetSecretValue"),
        human=True,
    ),
    Actor(
        "svc-backup",
        "user",
        0,
        5,
        40,
        ("CreateSnapshot", "CopySnapshot", "ListBuckets", "GetObject"),
        (REGION, US),
    ),
    Actor(
        "svc-etl",
        "user",
        1,
        6,
        60,
        ("StartJobRun", "GetObject", "PutObject", "GetTable"),
    ),
    Actor("svc-billing", "user", 6, 7, 15, ("GetCostAndUsage", "GetObject")),
    Actor("ci-deployer", "user", 9, 17, 12, ("AssumeRole", "GetCallerIdentity")),
    Actor("svc-monitor", "user", 0, 23, 3, ("GetMetricData", "DescribeAlarms")),
    Actor(
        "DeployRole",
        "role",
        9,
        17,
        8,
        ("CreateStack", "UpdateStack", "UpdateFunctionCode", "GetFunction"),
    ),
    Actor(
        "ProdAdminRole",
        "role",
        9,
        17,
        5,
        ("DescribeVpcs", "ListBuckets", "GetBucketPolicy"),
        account=SHARED,
    ),
    Actor(
        "VendorAuditRole",
        "role",
        11,
        12,
        7,
        ("LookupEvents", "ListUsers", "GetAccountSummary"),
        (US,),
    ),
    Actor(
        "app-ec2-role",
        "role",
        0,
        23,
        3,
        ("GetObject", "PutObject", "GetItem", "GetSecretValue"),
    ),
    Actor("legacy-reporting", "user", 0, 0, 0, ()),
    Actor("root", "root", 0, 0, 0, ()),
)
BY_NAME = {actor.name: actor for actor in ACTORS}
ENDPOINTS = {
    "GetObject": "s3",
    "PutObject": "s3",
    "AssumeRole": "sts",
    "ConsoleLogin": "signin",
    "StopLogging": "cloudtrail",
    "UpdateTrail": "cloudtrail",
    "GetSecretValue": "secretsmanager",
    "ListBuckets": "s3",
    "PutBucketPolicy": "s3",
    "GetBucketPolicy": "s3",
    "GetCallerIdentity": "sts",
}


def snapshots_at(when: datetime) -> dict[Identity, tuple[Snapshot, ...]]:
    admin = frozenset(("*",))
    deploy = frozenset(("iam:PassRole", "cloudformation:*"))
    dev = frozenset(("iam:PassRole", "lambda:*"))
    values = {
        "alice-admin": Snapshot(when, True, 30, admin),
        "bohdan-dev": Snapshot(when, False, 200, dev),
        "olena-analyst": Snapshot(when, True),
        "marko-support": Snapshot(when, True),
        "nadia-sec": Snapshot(when, True),
        "svc-backup": Snapshot(when, False, 410, critical=True),
        "svc-etl": Snapshot(
            when, False, 150, critical=True, unused_services_ratio=0.75
        ),
        "svc-billing": Snapshot(when, None, 60),
        "ci-deployer": Snapshot(when, False, 120, deploy),
        "svc-monitor": Snapshot(when, None, 45),
        "DeployRole": Snapshot(when, actions=dev | deploy),
        "ProdAdminRole": Snapshot(when, actions=admin, critical=True),
        "VendorAuditRole": Snapshot(when, external_trust=True),
        "app-ec2-role": Snapshot(when, critical=True, imds_v1=True, workload=True),
        "legacy-reporting": Snapshot(when, False, 512, last_used_days=74),
        "root": Snapshot(when, True),
    }
    # Complete the synthetic IAM inventory before scoring. Keep the initial
    # snapshots so existing demo databases can append the inventory idempotently.
    inventory_time = when + timedelta(hours=1)
    gathered = {
        "svc-backup": replace(
            values["svc-backup"],
            taken_at=inventory_time,
            actions=frozenset(
                {
                    "ec2:CreateSnapshot",
                    "ec2:CopySnapshot",
                    "s3:ListBucket",
                    "s3:GetObject",
                    "iam:CreateAccessKey",
                    "iam:AttachUserPolicy",
                    "backup:StartBackupJob",
                    "kms:CreateGrant",
                }
            ),
            # IAM service usage lists five allowed services. EC2 and S3 have
            # recent activity. The three unused grants remain in the policy.
            unused_services_ratio=3 / 5,
        ),
        "svc-etl": replace(
            values["svc-etl"],
            taken_at=inventory_time,
            actions=admin,
        ),
        # DeployRole can reach the critical customer bucket via the EC2 role
        # in the demo access graph, so the CI user inherits that exposure.
        "ci-deployer": replace(
            values["ci-deployer"],
            taken_at=inventory_time,
            critical=True,
        ),
        "DeployRole": replace(
            values["DeployRole"],
            taken_at=inventory_time,
            critical=True,
        ),
    }
    return {
        BY_NAME[name].identity: (snapshot, gathered[name])
        if name in gathered
        else (snapshot,)
        for name, snapshot in values.items()
    }


@dataclass(slots=True)
class Dataset:
    start: datetime
    score_from: datetime
    end: datetime
    events: list[Event]
    labels: dict[str, str]
    snapshots: dict[Identity, tuple[Snapshot, ...]]


def generate(
    end_day: date, *, include_attacks: bool = True, extended: bool = False
) -> Dataset:
    rng = np.random.default_rng(20260117)
    end = datetime.combine(end_day, time.min, UTC)
    start = end - timedelta(days=21)
    score_from = start + timedelta(days=14)
    dataset = Dataset(start, score_from, end, [], {}, snapshots_at(start))

    def emit(
        actor: Actor,
        when: datetime,
        op: str,
        region: str,
        address: str,
        label: str = "",
        target: str = "",
    ) -> None:
        index = len(dataset.events)
        event_id = str(
            uuid5(NAMESPACE_URL, f"identityguard-devdata:{start.date()}:{index}")
        )
        principal = {
            "type": {"user": "IAMUser", "role": "AssumedRole", "root": "Root"}[
                actor.kind
            ],
            "accountId": actor.account,
            "accessKeyId": f"demo-key-{actor.name}",
        }
        if actor.kind == "role":
            session = f"{label or actor.name}-{when:%Y%m%d%H}"
            principal["arn"] = (
                f"arn:aws:sts::{actor.account}:assumed-role/{actor.name}/{session}"
            )
        else:
            principal["userName"] = actor.name
        request = {}
        if target:
            role = BY_NAME[target]
            request["roleArn"] = f"arn:aws:iam::{role.account}:role/{role.name}"
        elif op == "CreateAccessKey" and label == "S7":
            request["userName"] = "svc-backup"
        record = {
            "eventID": event_id,
            "eventName": op,
            "eventTime": when.isoformat(),
            "eventSource": f"{ENDPOINTS.get(op, 'iam')}.amazonaws.com",
            "userIdentity": principal,
            "recipientAccountId": actor.account,
            "awsRegion": region,
            "sourceIPAddress": address,
            "eventCategory": "Data"
            if op in {"GetObject", "PutObject"}
            else "Management",
            "userAgent": "Boto3/demo",
            "requestParameters": request,
            "additionalEventData": {"MFAUsed": "No"} if op == "ConsoleLogin" else {},
            "vpcEndpointId": "vpce-demo" if address.startswith("172.31.") else "",
        }
        dataset.events.append(normalize(record))
        if label:
            dataset.labels[event_id] = label

    work_days = [
        day for day in range(14, 21) if (start + timedelta(days=day)).weekday() < 5
    ]
    for day in range(21):
        day_start = start + timedelta(days=day)
        for actor in ACTORS:
            if not actor.ops or (actor.human and day_start.weekday() >= 5):
                continue
            if actor.name == "VendorAuditRole" and day % 3:
                continue
            for hour in range(actor.start, actor.end + 1):
                label = ""
                rate = actor.rate
                if actor.name == "bohdan-dev" and day in work_days[:2]:
                    label = "b1"
                elif actor.name == "svc-etl" and day == 17:
                    label, rate = "b3", rate * 3
                elif actor.name == "olena-analyst" and day in work_days[2:]:
                    label = "b4"
                elif actor.name == "alice-admin" and day == work_days[-1]:
                    label = "b5"
                for _ in range(int(rng.poisson(rate))):
                    when = day_start + timedelta(
                        hours=hour, seconds=int(rng.integers(0, 3600))
                    )
                    op = (
                        "GetWorkGroup"
                        if label == "b4" and rng.random() < 0.3
                        else str(rng.choice(actor.ops))
                    )
                    region = (
                        "eu-north-1"
                        if label == "b1"
                        else str(rng.choice(actor.regions))
                    )
                    prefix = (
                        "172.31.4"
                        if actor.name == "app-ec2-role"
                        else "198.51.100"
                        if label == "b5"
                        else "203.0.113"
                    )
                    address = f"{prefix}.{rng.integers(2, 200)}"
                    target = ""
                    if op == "AssumeRole":
                        target = (
                            "ProdAdminRole"
                            if actor.name == "alice-admin"
                            else "DeployRole"
                        )
                    emit(actor, when, op, region, address, label, target)
    for hour in range(2, 5):
        for index in range(5):
            when = start + timedelta(days=work_days[2], hours=hour, minutes=index * 8)
            actor = BY_NAME["nadia-sec"]
            emit(
                actor,
                when,
                actor.ops[index % len(actor.ops)],
                REGION,
                "203.0.113.52",
                "b2",
            )

    if not include_attacks:
        return dataset

    def attack(
        label: str,
        name: str,
        day: int,
        hour: int,
        region: str,
        ops: list[str],
        *,
        address: str = "192.0.2.90",
        offset: int = 0,
        target: str = "",
    ) -> None:
        actor = BY_NAME[name]
        for index, op in enumerate(ops):
            when = start + timedelta(days=day, hours=hour, seconds=offset + index * 10)
            emit(
                actor,
                when,
                op,
                region,
                address,
                label,
                target if op == "AssumeRole" else "",
            )

    attack(
        "S1",
        "svc-backup",
        14,
        2,
        "us-west-2",
        [
            "GetCallerIdentity",
            "ListBuckets",
            "ListUsers",
            "ListRoles",
            "CreateAccessKey",
            "AttachUserPolicy",
        ],
    )
    attack(
        "S2",
        "bohdan-dev",
        15,
        3,
        "us-west-2",
        ["ConsoleLogin", "ListBuckets"] + ["GetObject"] * 60 + ["PutBucketPolicy"],
    )
    attack(
        "S3",
        "ci-deployer",
        16,
        4,
        "us-west-2",
        ["GetCallerIdentity", "ListRoles", "CreatePolicyVersion", "AssumeRole"],
        target="DeployRole",
    )
    attack("S3", "DeployRole", 16, 4, "us-west-2", ["UpdateFunctionCode"], offset=40)
    attack(
        "S4",
        "alice-admin",
        work_days[1],
        16,
        REGION,
        ["StopLogging", "UpdateTrail", "CreateUser", "AttachUserPolicy"],
        address="203.0.113.52",
    )
    attack(
        "S5",
        "svc-etl",
        18,
        20,
        "us-west-2",
        ["GetSecretValue"] * 6 + ["GetObject"] * 300,
    )
    attack(
        "S6",
        "app-ec2-role",
        19,
        10,
        REGION,
        ["GetCallerIdentity", "ListBuckets"] + ["GetObject"] * 3 + ["GetSecretValue"],
    )
    attack(
        "S7",
        "legacy-reporting",
        19,
        19,
        "us-west-2",
        ["GetCallerIdentity", "ListUsers", "ListBuckets", "CreateAccessKey"],
    )
    attack(
        "S8",
        "bohdan-dev",
        20,
        3,
        "us-west-2",
        ["GetCallerIdentity", "ListRoles", "CreateAccessKey", "AssumeRole"],
        target="ProdAdminRole",
    )
    attack(
        "S8",
        "ProdAdminRole",
        20,
        3,
        "us-west-2",
        ["ListBuckets", "GetBucketPolicy", "PutBucketPolicy", "GetObject", "GetObject"],
        offset=60,
    )
    attack(
        "S9",
        "root",
        20,
        22,
        US,
        ["ConsoleLogin", "GetAccountSummary", "CreateAccessKey"],
    )
    if extended:
        # Append test events so all original fixture event IDs and ground truth stay stable.
        attack("S1", "svc-backup", 14, 2, "us-west-2", ["StopLogging"], offset=60)
        attack("S3", "ci-deployer", 16, 4, "us-west-2", ["GetSecretValue"], offset=50)
        attack("S5", "svc-etl", 18, 20, "us-west-2", ["PutBucketPolicy"], offset=3200)
    return dataset


def classification_metrics(
    picks: Iterable[tuple[bool, bool]],
) -> tuple[float, float, float]:
    tp = fp = fn = 0
    for detected, attack in picks:
        tp += detected and attack
        fp += detected and not attack
        fn += not detected and attack
    return tp / max(1, tp + fp), tp / max(1, tp + fn), 2 * tp / max(1, 2 * tp + fp + fn)


def score_with_ablation(
    events: Iterable[Event],
    snapshots: Mapping[Identity, tuple[Snapshot, ...]],
    now: datetime,
    start: datetime,
    *,
    trusted: tuple[Network, ...] = (),
    rules: tuple[Rule, ...] = (),
    coverage_breaks: tuple[datetime, ...] = (),
) -> tuple[dict[WindowKey, Window], dict[WindowKey, Window]]:
    batch = tuple(events)
    results = [
        evaluate_events(
            batch,
            snapshots,
            now,
            model,
            start=start,
            trusted=trusted,
            coverage_breaks=coverage_breaks,
            adjust=Adjustments(rules, (), now) if rules else None,
        )
        for model in (CLOUD, replace(CLOUD, facts={}))
    ]
    return results[0], results[1]


def window_metrics(
    windows: Mapping[WindowKey, Window],
    ablated: Mapping[WindowKey, Window],
    attacks: set[WindowKey],
) -> dict[str, float]:
    if windows.keys() != ablated.keys():
        raise ValueError("Context ablation must score the same identity-hours")
    positive = [window.risk for key, window in windows.items() if key in attacks]
    negative = [window.risk for key, window in windows.items() if key not in attacks]
    auc = sum(
        (attack > normal) + 0.5 * (attack == normal)
        for attack in positive
        for normal in negative
    ) / (len(positive) * len(negative))
    precision, recall, f1 = classification_metrics(
        (window.level != "low", key in attacks) for key, window in windows.items()
    )
    f1_high = classification_metrics(
        (window.level == "high", key in attacks) for key, window in windows.items()
    )[2]
    return {
        "ROC AUC": auc,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "F1 with M=1": classification_metrics(
            (window.level != "low", key in attacks) for key, window in ablated.items()
        )[2],
        "F1 at high severity": f1_high,
        "F1 at high severity with M=1": classification_metrics(
            (window.level == "high", key in attacks) for key, window in ablated.items()
        )[2],
    }


def static_windows(events: Iterable[Event]) -> set[WindowKey]:
    operations = CLOUD.priv | CLOUD.evasion | CLOUD.secret
    return {
        (event.identity, event.hour)
        for event in events
        if event.identity is not None
        and (
            operation_key(event) in operations
            or (event.name in DECRYPT_OPERATIONS and event.with_decryption)
        )
    }


def evaluate(dataset: Dataset, *, extended: bool = False) -> tuple[str, bool]:
    windows, ablated = score_with_ablation(
        dataset.events,
        dataset.snapshots,
        dataset.end + timedelta(minutes=15),
        dataset.score_from,
        trusted=CORP,
    )
    labels: dict[WindowKey, set[str]] = defaultdict(set)
    for event in dataset.events:
        if event.identity is not None and event.event_id in dataset.labels:
            labels[event.identity, event.hour].add(dataset.labels[event.event_id])

    pairs = [
        (key, window, any(label.startswith("S") for label in labels[key]))
        for key, window in windows.items()
    ]
    metrics = window_metrics(
        windows, ablated, {key for key, _, attack in pairs if attack}
    )
    false = Counter(w.level for _, w, attack in pairs if not attack)
    static = static_windows(dataset.events)
    false_static = sum(key in static and not attack for key, _, attack in pairs)
    benign = Counter(w.level for key, w, attack in pairs if not attack and labels[key])
    by_scenario: dict[str, list[Window]] = defaultdict(list)
    for key, w, _ in pairs:
        for label in labels[key]:
            by_scenario[label].append(w)
    checks = {
        "ROC AUC ≥ 0.97": metrics["ROC AUC"] >= 0.97,
        "S1–S9 produce incidents": all(
            any(w.level != "low" for w in by_scenario[f"S{i}"]) for i in range(1, 10)
        ),
        "S1, S3, S4, S5, S7, S9 produce high incidents": all(
            any(w.level == "high" for w in by_scenario[f"S{i}"])
            for i in (1, 3, 4, 5, 7, 9)
        ),
        "b1–b5 produce zero high and at most three medium windows": benign["high"] == 0
        and benign["medium"] <= 3,
        "Context improves F1 at the high threshold": (
            metrics["F1 at high severity"] > metrics["F1 at high severity with M=1"]
        ),
        "Static baseline produces more false positives": false_static
        > false["high"] + false["medium"],
        "S8 role receives risky_source": any(
            w.identity.name == "ProdAdminRole" and "risky_source" in w.facts
            for w in by_scenario["S8"]
        ),
    }
    result = [
        "# Extended synthetic risk evaluation"
        if extended
        else "# Synthetic risk evaluation",
        "",
        f"Evaluation period ends at {dataset.end:%Y-%m-%d %H:%M} UTC.",
        "",
        (
            "Extended scenarios add StopLogging to S1, GetSecretValue to S3, and PutBucketPolicy to S5. "
            "The published AHP matrices, model, thresholds and benign background are shared with the original run."
            if extended
            else "FR-DEV event sequences with the completed synthetic IAM inventory and default cloud-v2."
        ),
        "",
        ABLATION_METHOD,
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Evaluated windows | {len(windows)} |",
        *(f"| {label} | {value:.6f} |" for label, value in metrics.items()),
        f"| False high | {false['high']} |",
        f"| False medium | {false['medium']} |",
        f"| Static false positives | {false_static} |",
        "",
        "| Scenario | Windows | Max risk | Medium | High |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for scenario, items in sorted(by_scenario.items()):
        result.append(
            f"| {scenario} | {len(items)} | {max(w.risk for w in items):.2f} | "
            f"{sum(w.level == 'medium' for w in items)} | {sum(w.level == 'high' for w in items)} |"
        )
    result += ["", "## Acceptance criteria", ""] + [
        f"- [{'x' if passed else ' '}] {label}" for label, passed in checks.items()
    ]
    return "\n".join(result) + "\n", all(checks.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seed", "evaluate"))
    parser.add_argument(
        "--end-day", type=date.fromisoformat, default=datetime.now(UTC).date()
    )
    parser.add_argument("--database", type=Path, default=Path("data/demo.sqlite"))
    parser.add_argument("--report", type=Path)
    parser.add_argument("--extended", action="store_true")
    args = parser.parse_args()
    data = generate(args.end_day, extended=args.extended)
    if args.command == "seed":
        repository = Repository(
            args.database,
            snapshots=data.snapshots,
            trusted=CORP,
        )
        print(
            repository.ingest(
                data.events, data.end + timedelta(minutes=15), seed_start=data.start
            )
        )
        return 0
    report, passed = evaluate(data, extended=args.extended)
    default_name = "evaluation-extended.md" if args.extended else "evaluation.md"
    destination = args.report or Path("reports") / default_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8", newline="\n")
    print(f"Evaluation written to {destination}.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
