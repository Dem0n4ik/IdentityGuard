"""Synthetic cloud inventory used by the reproducible demonstration."""

from datetime import datetime
from itertools import pairwise
from typing import Literal

from app.demo_incidents import SCENARIOS, actors_for, exercise_region, target_for
from app.engine.access import AccessNode, Check, CloudSnapshot, EdgeKind, NodeKind, edge
from app.engine.events import Identity

PROD = "111122223333"
SHARED = "222233334444"
DATA = "arn:aws:s3:::ig-demo-customer-data"
VAULT = "arn:aws:secretsmanager:eu-central-1:111122223333:secret:ig-demo-warehouse"


def fixture(when: datetime, identities: list[Identity]) -> CloudSnapshot:
    nodes = []
    for identity in identities:
        if identity.kind not in {"user", "role"}:
            continue
        kind: Literal["user", "role"] = "role" if identity.kind == "role" else "user"
        nodes.append(
            AccessNode(
                id=f"{identity.account_id}:{identity.kind}:{identity.name}",
                account_id=identity.account_id,
                name=identity.name,
                kind=kind,
            )
        )
    nodes.extend(
        (
            AccessNode(
                id=DATA,
                account_id=PROD,
                name="ig-demo-customer-data",
                kind="s3",
                critical=True,
                tags={"data-classification": "confidential"},
            ),
            AccessNode(
                id=VAULT,
                account_id=PROD,
                name="ig-demo-warehouse",
                kind="secret",
                critical=True,
                tags={"ig:critical": "true"},
            ),
            AccessNode(
                id=f"{PROD}:group:data-operators",
                account_id=PROD,
                name="data-operators",
                kind="group",
            ),
        )
    )
    by_name = {node.name: node.id for node in nodes}
    connections: list[tuple[str, str, EdgeKind, tuple[str, ...]]] = [
        ("svc-backup", "data-operators", "member_of", ()),
        ("data-operators", "ig-demo-customer-data", "has_access", ("s3:GetObject",)),
        (
            "svc-etl",
            "ig-demo-warehouse",
            "has_access",
            ("secretsmanager:GetSecretValue",),
        ),
        (
            "ProdAdminRole",
            "ig-demo-customer-data",
            "has_access",
            ("s3:GetObject", "s3:PutObject"),
        ),
        ("app-ec2-role", "ig-demo-customer-data", "has_access", ("s3:GetObject",)),
        ("ci-deployer", "DeployRole", "can_assume", ("sts:AssumeRole",)),
        (
            "DeployRole",
            "app-ec2-role",
            "can_escalate",
            ("iam:PassRole", "cloudformation:CreateStack"),
        ),
    ]
    resource_kinds: dict[str, tuple[NodeKind, str]] = {
        "GetSecretValue": ("secret", "secretsmanager:GetSecretValue"),
        "GetParameter": ("parameter", "ssm:GetParameter"),
        "GetObject": ("s3", "s3:GetObject"),
        "ModifyDBSnapshotAttribute": ("rds", "rds:ModifyDBSnapshotAttribute"),
    }
    for index, scenario in enumerate(SCENARIOS, 1):
        actors = actors_for(scenario)
        if len(actors) < 2 or any(actor.name not in by_name for actor in actors):
            continue
        connections.extend(
            (source.name, target.name, "can_assume", ("sts:AssumeRole",))
            for source, target in pairwise(actors)
        )
        for actor, (_, _, operation) in zip(actors, scenario.stages, strict=True):
            if operation not in resource_kinds:
                continue
            resource_kind, action = resource_kinds[operation]
            resource = target_for(
                operation, actor.account_id, actor.name, exercise_region(index)
            )
            name = resource.split(":", 5)[-1]
            nodes.append(
                AccessNode(
                    id=resource,
                    account_id=actor.account_id,
                    name=name,
                    kind=resource_kind,
                    critical=True,
                    tags={"ig:critical": "true"},
                )
            )
            by_name[name] = resource
            connections.append((actor.name, name, "has_access", (action,)))
    checks = [
        Check(id="root_mfa", level="critical", passed=True),
        Check(id="root_keys", level="critical", passed=True),
        Check(id="trail_logging", level="critical", passed=True),
        Check(id="trail_regions", level="high", passed=True),
        Check(id="trail_validation", level="medium", passed=True),
        Check(id="trail_data", level="medium", passed=False),
        Check(id="imds_v2", level="high", passed=False),
    ]
    return CloudSnapshot(
        account_id=PROD,
        region="eu-central-1",
        taken_at=when,
        source="demo",
        checks=checks,
        nodes=nodes,
        edges=[
            edge(by_name[source], by_name[target], kind, actions)
            for source, target, kind, actions in connections
            if source in by_name and target in by_name
        ],
    )
