"""Read-only IAM posture snapshots for a verified AWS account."""

import argparse
import json
import logging
import sys
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from time import sleep
from typing import Any, cast
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

from app.aws_history import verified_session
from app.engine.events import Identity
from app.engine.posture import Snapshot
from app.repository import Repository

LOG = logging.getLogger(__name__)
AWS_ERRORS = (BotoCoreError, ClientError)
ASSUME_ACTIONS = (
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
)
DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def strings(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset((value,))
    if isinstance(value, list):
        return frozenset(item for item in value if isinstance(item, str))
    return frozenset()


def policy_statements(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, str):
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        raise TypeError("Malformed IAM policy document")
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise TypeError("Malformed IAM policy statements")
    return [statement for statement in statements if isinstance(statement, dict)]


def allowed_actions(document: Any) -> frozenset[str]:
    return frozenset().union(
        *(
            strings(row.get("Action"))
            for row in policy_statements(document)
            if row.get("Effect") == "Allow"
        )
    )


def effective_actions(
    entity: dict[str, Any],
    prefix: str,
    managed: dict[str, frozenset[str]],
) -> frozenset[str]:
    attached = (
        managed.get(policy["PolicyArn"], frozenset())
        for policy in entity.get("AttachedManagedPolicies", [])
    )
    inline = (
        allowed_actions(policy["PolicyDocument"])
        for policy in entity.get(f"{prefix}PolicyList", [])
    )
    return frozenset().union(*attached, *inline)


def organization_accounts(client: Any, account: str) -> frozenset[str] | None:
    try:
        accounts = frozenset(
            row["Id"]
            for page in client.get_paginator("list_accounts").paginate()
            for row in page.get("Accounts", [])
        )
    except ClientError as error:
        if (
            error.response.get("Error", {}).get("Code")
            == "AWSOrganizationsNotInUseException"
        ):
            return frozenset({account})
        LOG.info("Organizations membership unavailable for posture snapshot")
        return None
    except BotoCoreError:
        LOG.info("Organizations membership unavailable for posture snapshot")
        return None
    return accounts if account in accounts else None


def external_trust(document: Any, members: frozenset[str] | None) -> bool:
    if members is None or not document:
        return False
    statements = policy_statements(document)
    # Trust with conditions or explicit denies requires policy evaluation.
    if any(statement.get("Effect") == "Deny" for statement in statements):
        return False
    for statement in statements:
        principal = statement.get("Principal")
        if statement.get("Effect") != "Allow" or statement.get("Condition"):
            continue
        if not any(
            fnmatchcase(action, pattern.lower())
            for action in ASSUME_ACTIONS
            for pattern in strings(statement.get("Action"))
        ):
            continue
        aws_principals = (
            strings(principal.get("AWS"))
            if isinstance(principal, dict)
            else strings(principal)
        )
        for value in aws_principals:
            if value == "*":
                return True
            parts = value.split(":", 5)
            account = parts[4] if len(parts) == 6 and parts[0] == "arn" else value
            if (
                len(account) == 12
                and account.isascii()
                and account.isdigit()
                and account not in members
            ):
                return True
    return False


def roles_allowing_imds_v1(client: Any, roles: list[dict[str, Any]]) -> set[str]:
    by_profile = {
        profile["Arn"]: role["RoleName"]
        for role in roles
        for profile in role.get("InstanceProfileList", [])
    }
    if not by_profile:
        return set()
    exposed = set()
    try:
        for page in client.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "metadata-options.http-tokens", "Values": ["optional"]}],
            PaginationConfig={"MaxItems": 100},
        ):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    profile = instance.get("IamInstanceProfile", {}).get("Arn")
                    options = instance.get("MetadataOptions", {})
                    if (
                        profile in by_profile
                        and options.get("HttpEndpoint") == "enabled"
                        and options.get("HttpTokens") == "optional"
                        and instance.get("State", {}).get("Name")
                        in {"running", "stopped"}
                    ):
                        exposed.add(by_profile[profile])
    except AWS_ERRORS:
        LOG.info("EC2 metadata options unavailable for posture snapshot")
    return exposed


def service_usage(
    client: Any, arns: Iterable[str], now: datetime
) -> dict[str, tuple[float, float | None]]:
    jobs = {}
    for arn in arns:
        try:
            jobs[arn] = client.generate_service_last_accessed_details(Arn=arn)["JobId"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in DENIED:
                break
        except BotoCoreError:
            break

    usage: dict[str, tuple[float, float | None]] = {}
    cutoff = now - timedelta(days=90)
    for attempt in range(3):
        for arn, job in list(jobs.items()):
            try:
                services = []
                request = {"JobId": job}
                markers = set()
                while True:
                    page = client.get_service_last_accessed_details(**request)
                    status = page["JobStatus"]
                    if status != "COMPLETED":
                        break
                    services.extend(page.get("ServicesLastAccessed", []))
                    if not page.get("IsTruncated"):
                        break
                    marker = page.get("Marker")
                    if not marker or marker in markers:
                        status = "FAILED"
                        break
                    markers.add(marker)
                    request["Marker"] = marker
                if status == "IN_PROGRESS":
                    continue
                if status == "COMPLETED" and services:
                    timestamps = [
                        service.get("LastAuthenticated") for service in services
                    ]
                    unused = sum(time is None or time < cutoff for time in timestamps)
                    latest = max(
                        (time for time in timestamps if time is not None), default=None
                    )
                    usage[arn] = (
                        unused / len(timestamps),
                        max(0, (now - latest).total_seconds() / 86400)
                        if latest is not None
                        else None,
                    )
            except AWS_ERRORS:
                LOG.info(
                    "Service last accessed report unavailable for posture snapshot"
                )
            jobs.pop(arn)
        if not jobs:
            break
        if attempt < 2:
            sleep(0.5)
    return usage


def read_inventory(
    account: str,
    region: str,
    profile: str | None,
) -> dict[Identity, tuple[Snapshot, ...]]:
    session, config = verified_session(account, region, profile)
    iam = session.client("iam", config=config)
    now = datetime.now(UTC)
    entities: dict[str, list[dict[str, Any]]] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    for page in iam.get_paginator("get_account_authorization_details").paginate(
        PaginationConfig={"PageSize": 100}
    ):
        data = cast(dict[str, Any], page)
        for key, values in entities.items():
            values.extend(data.get(key, []))
    policies = {
        policy["Arn"]: allowed_actions(version["Document"])
        for policy in entities["Policies"]
        for version in policy.get("PolicyVersionList", [])
        if version["IsDefaultVersion"]
    }
    groups = {
        group["GroupName"]: effective_actions(group, "Group", policies)
        for group in entities["GroupDetailList"]
    }
    result: dict[Identity, tuple[Snapshot, ...]] = {}
    summary = iam.get_account_summary()["SummaryMap"]
    result[Identity(account, "root", "root")] = (
        Snapshot(
            now,
            mfa_enabled=bool(summary["AccountMFAEnabled"])
            if "AccountMFAEnabled" in summary
            else None,
        ),
    )
    for user in entities["UserDetailList"]:
        name: str = user["UserName"]
        actions = effective_actions(user, "User", policies).union(
            *(groups.get(group, frozenset()) for group in user.get("GroupList", []))
        )
        mfa = any(
            page["MFADevices"]
            for page in iam.get_paginator("list_mfa_devices").paginate(UserName=name)
        )
        active = [
            key["CreateDate"]
            for page in iam.get_paginator("list_access_keys").paginate(UserName=name)
            for key in page["AccessKeyMetadata"]
            if key["Status"] == "Active"
        ]
        key_age = (now - min(active)).total_seconds() / 86400 if active else None
        result[Identity(account, "user", name)] = (
            Snapshot(now, mfa, key_age, actions),
        )
    for role in entities["RoleDetailList"]:
        name = role["RoleName"]
        result[Identity(account, "role", name)] = (
            Snapshot(
                now,
                actions=effective_actions(role, "Role", policies),
                workload=bool(role.get("InstanceProfileList")),
            ),
        )
    roles = entities["RoleDetailList"]
    if roles:
        membership = organization_accounts(
            session.client("organizations", config=config), account
        )
        exposed = roles_allowing_imds_v1(session.client("ec2", config=config), roles)
        for role in roles:
            identity = Identity(account, "role", role["RoleName"])
            current = result[identity][0]
            result[identity] = (
                replace(
                    current,
                    external_trust=external_trust(
                        role.get("AssumeRolePolicyDocument"), membership
                    ),
                    imds_v1=identity.name in exposed,
                ),
            )

    principal_arns = {
        Identity(account, kind, entity[name_field]): entity["Arn"]
        for kind, name_field, items in (
            ("user", "UserName", entities["UserDetailList"]),
            ("role", "RoleName", roles),
        )
        for entity in items
    }
    usage = service_usage(
        iam,
        (
            arn
            for identity, arn in principal_arns.items()
            if result[identity][0].actions
        ),
        now,
    )
    for identity, arn in principal_arns.items():
        if arn in usage:
            unused, last_used = usage[arn]
            result[identity] = (
                replace(
                    result[identity][0],
                    unused_services_ratio=unused,
                    last_used_days=last_used,
                ),
            )
    return result


def summarize(identities: Iterable[Identity]) -> dict[str, int]:
    result: dict[str, int] = {}
    for identity in identities:
        result[identity.kind] = result.get(identity.kind, 0) + 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()
    try:
        inventory = read_inventory(args.account, args.region, args.profile)
        Repository(args.database, source="aws").save_posture(
            inventory, datetime.now(UTC)
        )
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "Unknown")
        print(f"AWS {error.operation_name} returned {code}.", file=sys.stderr)
        return 1
    except (BotoCoreError, TypeError, ValueError) as error:
        print(f"Inventory stopped ({type(error).__name__}).", file=sys.stderr)
        return 1
    print(json.dumps(summarize(inventory), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
