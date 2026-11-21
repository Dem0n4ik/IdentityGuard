from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.aws_inventory import external_trust, roles_allowing_imds_v1, service_usage

NOW = datetime(2026, 11, 7, tzinfo=UTC)
OWN = "111122223333"
MEMBER = "222233334444"
EXTERNAL = "333344445555"


def test_external_trust_requires_a_known_organization_boundary() -> None:
    members = frozenset({OWN, MEMBER})
    statement = {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL}:root"},
    }
    assert external_trust({"Statement": statement}, members)
    assert not external_trust({"Statement": statement}, None)
    assert not external_trust(
        {"Statement": statement | {"Principal": {"AWS": MEMBER}}}, members
    )
    assert not external_trust(
        {
            "Statement": statement
            | {"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}
        },
        members,
    )


def test_imds_snapshot_requires_optional_tokens_and_enabled_endpoint() -> None:
    role = {"RoleName": "worker", "InstanceProfileList": [{"Arn": "worker-profile"}]}
    instance = {
        "IamInstanceProfile": {"Arn": "worker-profile"},
        "State": {"Name": "running"},
        "MetadataOptions": {"HttpEndpoint": "enabled", "HttpTokens": "optional"},
    }

    def client_for(row):
        return SimpleNamespace(
            get_paginator=lambda name: SimpleNamespace(
                paginate=lambda **kwargs: [{"Reservations": [{"Instances": [row]}]}]
            )
        )

    assert roles_allowing_imds_v1(client_for(instance), [role]) == {"worker"}
    instance["MetadataOptions"]["HttpEndpoint"] = "disabled"
    assert roles_allowing_imds_v1(client_for(instance), [role]) == set()


def test_service_usage_accounts_for_all_pages_and_90_day_boundary() -> None:
    def details(JobId: str, Marker: str = "") -> dict:
        assert JobId == "role-arn"
        if Marker == "next":
            return {"JobStatus": "COMPLETED", "ServicesLastAccessed": [{}]}
        return {
            "JobStatus": "COMPLETED",
            "IsTruncated": True,
            "Marker": "next",
            "ServicesLastAccessed": [
                {"LastAuthenticated": NOW - timedelta(days=90)},
                {"LastAuthenticated": NOW - timedelta(days=91)},
            ],
        }

    client = SimpleNamespace(
        generate_service_last_accessed_details=lambda Arn: {"JobId": Arn},
        get_service_last_accessed_details=details,
    )
    assert service_usage(client, ("role-arn",), NOW) == {"role-arn": (2 / 3, 90)}
