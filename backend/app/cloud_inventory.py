"""Read-only regional AWS configuration and access inventory."""

import json
from collections import defaultdict
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any, Literal, cast
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from app.aws_history import verified_session
from app.aws_inventory import strings
from app.engine.access import (
    AccessEdge,
    AccessNode,
    Check,
    CloudSnapshot,
    NodeKind,
    critical,
    edge,
)
from app.engine.events import Identity
from app.engine.posture import escalation_paths
from app.repository import identity_id

RESOURCE_ACTIONS: dict[NodeKind, tuple[str, ...]] = {
    "s3": (
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket",
        "s3:DeleteObject",
        "s3:PutBucketPolicy",
    ),
    "kms": ("kms:Decrypt", "kms:Encrypt", "kms:CreateGrant"),
    "secret": ("secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"),
    "lambda": ("lambda:InvokeFunction", "lambda:UpdateFunctionCode"),
    "ec2": ("ec2:StartInstances", "ec2:StopInstances", "ssm:StartSession"),
}
FAILURES = (BotoCoreError, ClientError, ValueError, TypeError)


def statements(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, str):
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        return []
    rows = document.get("Statement", [])
    if isinstance(rows, dict):
        rows = [rows]
    return (
        [row for row in rows if isinstance(row, dict) and row.get("Effect") == "Allow"]
        if isinstance(rows, list)
        else []
    )


def grants(rows: list[dict[str, Any]], action: str, arns: list[str]) -> bool:
    return any(
        any(
            fnmatchcase(action.lower(), pattern.lower())
            for pattern in strings(row.get("Action"))
        )
        and any(
            fnmatchcase(arn, pattern)
            for arn in arns
            for pattern in strings(row.get("Resource"))
        )
        for row in rows
    )


def resource_grants(
    rows: list[dict[str, Any]], action: str, resource: AccessNode
) -> bool:
    if resource.kind != "s3" or action not in {
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
    }:
        return grants(rows, action, [resource.id])
    # Object permissions require an object ARN or a wildcard spanning object ARNs.
    return any(
        any(
            fnmatchcase(action.lower(), pattern.lower())
            for pattern in strings(row.get("Action"))
        )
        and any(
            pattern == "*"
            or (bool(path) and fnmatchcase(resource.id, bucket))
            or (not path and fnmatchcase(resource.id + "/example-object", pattern))
            for pattern in strings(row.get("Resource"))
            for bucket, _, path in (pattern.partition("/"),)
        )
        for row in rows
    )


def trusts(
    rows: list[dict[str, Any]], principal: str, account: str, action: str
) -> bool:
    partition = principal.split(":")[1] if principal.startswith("arn:") else "aws"
    accepted = {principal, account, f"arn:{partition}:iam::{account}:root", "*"}
    for row in rows:
        raw = row.get("Principal")
        allowed = strings(raw.get("AWS") if isinstance(raw, dict) else raw)
        if allowed & accepted and any(
            fnmatchcase(action.lower(), pattern.lower())
            for pattern in strings(row.get("Action"))
        ):
            return True
    return False


def entity_policies(
    entity: dict[str, Any], kind: str, managed: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    rows = [
        item
        for policy in entity.get(f"{kind.title()}PolicyList", [])
        for item in statements(policy.get("PolicyDocument"))
    ]
    rows.extend(
        item
        for policy in entity.get("AttachedManagedPolicies", [])
        for item in managed.get(policy.get("PolicyArn"), [])
    )
    return rows


def tags_from(values: Any) -> dict[str, str]:
    if isinstance(values, dict):
        return {str(key): str(value) for key, value in values.items()}
    return (
        {
            str(row["Key"]): str(row["Value"])
            for row in values
            if isinstance(row, dict) and "Key" in row and "Value" in row
        }
        if isinstance(values, list)
        else {}
    )


def build_cloud_graph(
    account: str,
    entities: dict[str, list[dict[str, Any]]],
    resources: list[AccessNode],
    resource_policies: dict[str, list[dict[str, Any]]],
    workload_roles: dict[str, str],
) -> tuple[list[AccessNode], list[AccessEdge]]:
    managed = {
        policy["Arn"]: statements(version["Document"])
        for policy in entities["Policies"]
        for version in policy.get("PolicyVersionList", [])
        if version.get("IsDefaultVersion")
    }
    nodes = list(resources)
    edges = []
    grants_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    arns: dict[str, str] = {}
    role_trust = {}
    users = {}
    groups = {}
    kinds: tuple[tuple[str, NodeKind], ...] = (
        ("User", "user"),
        ("Role", "role"),
        ("Group", "group"),
    )
    for name, kind in kinds:
        for entity in entities[f"{name}DetailList"]:
            identifier = entity[f"{name}Name"]
            key = identity_id(Identity(account, kind, identifier))
            nodes.append(
                AccessNode(id=key, name=identifier, kind=kind, account_id=account)
            )
            arns[key] = entity["Arn"]
            grants_by_node[key] = entity_policies(entity, kind, managed)
            if kind == "role":
                role_trust[key] = statements(entity.get("AssumeRolePolicyDocument"))
            if kind == "user":
                users[key] = entity.get("GroupList", [])
            if kind == "group":
                groups[identifier] = key
    for user, memberships in users.items():
        for group in memberships:
            if group in groups:
                edges.append(edge(user, groups[group], "member_of"))
    group_keys = set(groups.values())
    for source, arn in arns.items():
        direct = grants_by_node[source]
        inherited = [
            *direct,
            *(
                row
                for name in users.get(source, ())
                if name in groups
                for row in grants_by_node[groups[name]]
            ),
        ]
        actions = frozenset(
            action for row in inherited for action in strings(row.get("Action"))
        )
        allowed_escalations = escalation_paths(actions)
        for target, policy in role_trust.items():
            if source == target or source in group_keys:
                continue
            role = arns[target]
            if trusts(policy, arn, account, "sts:AssumeRole") and grants(
                inherited, "sts:AssumeRole", [role]
            ):
                edges.append(edge(source, target, "can_assume", ["sts:AssumeRole"]))
            if (
                15 in allowed_escalations
                and grants(inherited, "iam:PassRole", [role])
                and any(
                    "lambda.amazonaws.com"
                    in strings(row.get("Principal", {}).get("Service"))
                    for row in policy
                    if isinstance(row.get("Principal"), dict)
                )
            ):
                edges.append(
                    edge(
                        source,
                        target,
                        "can_escalate",
                        [
                            "iam:PassRole",
                            "lambda:CreateFunction",
                            "lambda:InvokeFunction",
                        ],
                    )
                )
        for resource in resources:
            actions_on_resource = [
                action
                for action in RESOURCE_ACTIONS.get(resource.kind, ())
                if resource_grants(direct, action, resource)
                or any(
                    source not in group_keys
                    and trusts([row], arn, account, action)
                    and resource_grants([row], action, resource)
                    for row in resource_policies.get(resource.id, [])
                )
            ]
            if actions_on_resource:
                edges.append(
                    edge(source, resource.id, "has_access", actions_on_resource)
                )
    by_arn = {arn: key for key, arn in arns.items()}
    for resource_id, arn in workload_roles.items():
        if arn in by_arn:
            edges.append(edge(resource_id, by_arn[arn], "runs_as"))
    return nodes, edges


def read_cloud(account: str, region: str, profile: str | None) -> CloudSnapshot:
    session, config = verified_session(account, region, profile)
    iam = session.client("iam", config=config)
    trail = session.client("cloudtrail", config=config)
    levels: tuple[tuple[str, Literal["critical", "high", "medium"]], ...] = (
        ("root_mfa", "critical"),
        ("root_keys", "critical"),
        ("trail_logging", "critical"),
        ("trail_regions", "high"),
        ("trail_validation", "medium"),
        ("trail_data", "medium"),
        ("imds_v2", "high"),
    )
    checks = {key: Check(id=key, level=level, passed=None) for key, level in levels}
    missing = []
    resources: list[AccessNode] = []
    resource_policies: dict[str, list[dict[str, Any]]] = {}
    workloads: dict[str, str] = {}
    partition = session.get_partition_for_region(region)
    entities: dict[str, list[dict[str, Any]]] = {
        key: []
        for key in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
    }

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if "AccountMFAEnabled" in summary:
            checks["root_mfa"].passed = bool(summary["AccountMFAEnabled"])
        if "AccountAccessKeysPresent" in summary:
            checks["root_keys"].passed = not summary["AccountAccessKeysPresent"]
        for page in iam.get_paginator("get_account_authorization_details").paginate(
            PaginationConfig={"PageSize": 100}
        ):
            data = cast(dict[str, Any], page)
            for key, records in entities.items():
                records.extend(data.get(key, []))
    except FAILURES:
        missing.append("IAM")

    def resource(arn: str, name: str, kind: NodeKind, tags: dict[str, str]) -> None:
        resources.append(
            AccessNode(
                id=arn,
                name=name,
                kind=kind,
                account_id=account,
                tags=tags,
                critical=critical(tags),
            )
        )

    try:
        s3: Any = session.client("s3", config=config)
        for page in s3.get_paginator("list_buckets").paginate(
            PaginationConfig={"MaxItems": 50}
        ):
            if len(page.get("Buckets", [])) >= 50 or page.get("NextToken"):
                missing.append("S3 inventory limit")
            for row in page.get("Buckets", []):
                name = row["Name"]
                arn = f"arn:{partition}:s3:::{name}"
                tags = {}
                try:
                    tags = tags_from(
                        s3.get_bucket_tagging(Bucket=name).get("TagSet", [])
                    )
                except ClientError as error:
                    if error.response.get("Error", {}).get("Code") != "NoSuchTagSet":
                        missing.append("S3 tags")
                resource(arn, name, "s3", tags)
                try:
                    resource_policies[arn] = statements(
                        s3.get_bucket_policy(Bucket=name).get("Policy")
                    )
                except ClientError as error:
                    if (
                        error.response.get("Error", {}).get("Code")
                        != "NoSuchBucketPolicy"
                    ):
                        missing.append("S3 policies")
    except FAILURES:
        missing.append("S3")

    try:
        secrets: Any = session.client("secretsmanager", config=config)
        for page in secrets.get_paginator("list_secrets").paginate(
            PaginationConfig={"MaxItems": 50}
        ):
            if len(page.get("SecretList", [])) >= 50 or page.get("NextToken"):
                missing.append("Secrets Manager inventory limit")
            for row in page.get("SecretList", []):
                arn = row["ARN"]
                resource(arn, row["Name"], "secret", tags_from(row.get("Tags")))
                try:
                    resource_policies[arn] = statements(
                        secrets.get_resource_policy(SecretId=arn).get("ResourcePolicy")
                    )
                except FAILURES:
                    missing.append("Secrets Manager policies")
    except FAILURES:
        missing.append("Secrets Manager")

    try:
        lambda_client: Any = session.client("lambda", config=config)
        for page in lambda_client.get_paginator("list_functions").paginate(
            PaginationConfig={"MaxItems": 50}
        ):
            if len(page.get("Functions", [])) >= 50 or page.get("NextMarker"):
                missing.append("Lambda inventory limit")
            for row in page.get("Functions", []):
                arn = row["FunctionArn"]
                tags = {}
                try:
                    tags = tags_from(lambda_client.list_tags(Resource=arn).get("Tags"))
                except FAILURES:
                    missing.append("Lambda tags")
                resource(arn, row["FunctionName"], "lambda", tags)
                if row.get("Role"):
                    workloads[arn] = row["Role"]
    except FAILURES:
        missing.append("Lambda")

    try:
        ec2: Any = session.client("ec2", config=config)
        profile_roles = {}
        for role in entities["RoleDetailList"]:
            for instance_profile in role.get("InstanceProfileList", []):
                profile_roles[instance_profile["Arn"]] = role["Arn"]
        imds_ok = True
        incomplete = False
        for page in ec2.get_paginator("describe_instances").paginate(
            PaginationConfig={"MaxItems": 100}
        ):
            incomplete = (
                incomplete
                or len(page.get("Reservations", [])) >= 100
                or bool(page.get("NextToken"))
            )
            for reservation in page.get("Reservations", []):
                for row in reservation.get("Instances", []):
                    instance = row["InstanceId"]
                    arn = f"arn:{partition}:ec2:{region}:{account}:instance/{instance}"
                    resource(arn, instance, "ec2", tags_from(row.get("Tags")))
                    profile_arn = row.get("IamInstanceProfile", {}).get("Arn")
                    if profile_arn in profile_roles:
                        workloads[arn] = profile_roles[profile_arn]
                    tokens = row.get("MetadataOptions", {}).get("HttpTokens")
                    imds_ok = imds_ok and tokens != "optional"
                    incomplete = incomplete or tokens not in {"optional", "required"}
        checks["imds_v2"].passed = None if imds_ok and incomplete else imds_ok
        if incomplete:
            missing.append("EC2 metadata inventory")
    except FAILURES:
        missing.append("EC2")

    try:
        trails = trail.describe_trails(includeShadowTrails=False).get("trailList", [])
        logging = []
        for row in trails:
            trail_arn = row.get("TrailARN")
            if not trail_arn or trail_arn.split(":")[4] != account:
                continue
            home = row.get("HomeRegion", region)
            home_client = session.client("cloudtrail", region_name=home, config=config)
            if home_client.get_trail_status(Name=trail_arn).get("IsLogging"):
                logging.append(row)
        checks["trail_logging"].passed = bool(logging)
        checks["trail_regions"].passed = any(
            row.get("IsMultiRegionTrail") for row in logging
        )
        checks["trail_validation"].passed = any(
            row.get("LogFileValidationEnabled") for row in logging
        )
    except FAILURES:
        missing.append("CloudTrail")
    # Advanced data selectors and KMS/SSM/EBS/RDS inventory require separate collectors.
    missing.extend(("KMS", "SSM", "EBS", "RDS", "CloudTrail data selectors"))
    nodes, edges = build_cloud_graph(
        account, entities, resources, resource_policies, workloads
    )
    return CloudSnapshot(
        account_id=account,
        region=region,
        taken_at=datetime.now(UTC),
        source="aws",
        checks=list(checks.values()),
        nodes=nodes,
        edges=edges,
        unavailable=sorted(set(missing)),
    )
