import gzip
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

import pytest
from app import ingest
from app.api import create_app
from app.aws_inventory import allowed_actions
from app.engine.events import Identity
from app.engine.posture import Snapshot
from app.ingest import InvalidCloudTrail, normalize
from app.repository import Repository
from fastapi.testclient import TestClient

ACCOUNT = "111122223333"
NOW = datetime.now(UTC)
HEADERS = {"X-IdentityGuard-Local": "1"}


def record(
    index: int = 1,
    *,
    kind: str = "IAMUser",
    actor_account: str = ACCOUNT,
    **principal: str,
) -> dict[str, Any]:
    return {
        "eventID": f"event-{index}",
        "eventTime": (NOW - timedelta(hours=4)).isoformat(),
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "recipientAccountId": ACCOUNT,
        "awsRegion": "eu-central-1",
        "sourceIPAddress": "192.0.2.7",
        "userIdentity": {
            "type": kind,
            "accountId": actor_account,
            "userName": "example",
            **principal,
        },
    }


def payload(*records: dict[str, Any]) -> bytes:
    return json.dumps({"Records": records}).encode()


def test_fr_ing_attribution_service_role_sso_root_and_cross_account() -> None:
    session = "test-session"
    role = normalize(
        record(
            kind="AssumedRole",
            arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/TestRole/{session}",
        )
    )
    assert role.identity == Identity(ACCOUNT, "role", "TestRole")
    assert role.session_name == session
    sso = normalize(
        record(
            kind="AssumedRole",
            arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_Auditor_123/{session}",
        )
    )
    assert sso.identity == Identity(ACCOUNT, "sso_user", f"sso:{session}")
    assert normalize(record(kind="Root")).identity == Identity(ACCOUNT, "root", "root")
    assert normalize(record(kind="AWSService")).identity is None
    assert normalize(record(kind="", invokedBy="config.amazonaws.com")).identity is None
    other = normalize(
        record(
            kind="AssumedRole",
            actor_account="222233334444",
            arn="arn:aws:sts::222233334444:assumed-role/TestRole/other",
        )
    )
    assert other.identity == Identity("222233334444", "role", "TestRole")
    assert role.identity != other.identity


def test_fr_ing_gzip_limits_and_document_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert len(ingest.read_cloudtrail(gzip.compress(payload(record())))) == 1
    monkeypatch.setattr(ingest, "MAX_UNPACKED", 50)
    with pytest.raises(InvalidCloudTrail, match="Decompressed"):
        ingest.read_cloudtrail(gzip.compress(b"x" * 500))
    with pytest.raises(InvalidCloudTrail, match="Records"):
        ingest.read_cloudtrail(b'{"hello":"world"}')
    with pytest.raises(InvalidCloudTrail, match="decode"):
        ingest.read_cloudtrail(b"\x1f\x8b\x00")


def test_fr_post_iam_policy_decodes_both_shapes() -> None:
    document = {
        "Statement": [
            {"Effect": "Allow", "Action": ["iam:PassRole", "lambda:*"]},
            {"Effect": "Deny", "Action": "*"},
        ]
    }
    assert (
        allowed_actions(document)
        == allowed_actions(quote(json.dumps(document)))
        == {"iam:PassRole", "lambda:*"}
    )


def test_fr_post_persists_state_and_preserves_time(tmp_path: Path) -> None:
    path = tmp_path / "data.sqlite"
    repository = Repository(path, source="aws")
    identity = Identity(ACCOUNT, "user", "example")
    event = normalize(record())
    repository.save_posture(
        {identity: (Snapshot(NOW - timedelta(hours=1), mfa_enabled=False),)}, NOW
    )
    repository.ingest([event], NOW)
    assert "no_mfa" not in repository.incidents()[0]["facts"]
    assert "no_mfa" in Repository(path, source="aws").identities(NOW)[0]["facts"]


def test_fr_rescore_updates_in_place_and_eng_conflict(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "data.sqlite")
    client = TestClient(create_app(repository))
    response = client.post(
        "/api/v1/sources/upload", headers=HEADERS, content=payload(record())
    )
    assert response.status_code == 200, response.text
    assert response.json()["inserted"] == 1
    item = client.get("/api/v1/incidents").json()[0]
    path = "/api/v1/incidents/" + quote(item["id"], safe="")
    headers = HEADERS | {"If-Match": '"1"'}
    update = {
        "status": "closed",
        "note": "Review completed",
        "verdict": "false_positive",
        "reason": "Maintenance",
    }
    edited = client.patch(path, headers=headers, json=update)
    assert edited.status_code == 200
    assert edited.headers["etag"] == '"2"'
    assert client.patch(path, headers=headers, json=update).status_code == 412
    duplicate = client.post(
        "/api/v1/sources/upload", headers=HEADERS, content=payload(record())
    )
    assert duplicate.json()["inserted"] == 0
    rescored = client.get("/api/v1/incidents").json()[0]
    assert rescored["case_id"] == item["case_id"]
    assert rescored["note"] == update["note"]
    assert rescored["verdict"] == update["verdict"]


def test_fr_hunt_parameterized_cursor_range_and_key_mask(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "data.sqlite")
    repository.ingest(
        [normalize(record(i, accessKeyId="demo-access-1234")) for i in range(3)], NOW
    )
    client = TestClient(create_app(repository))
    first = client.get("/api/v1/events", params={"limit": 2}).json()
    second = client.get(
        "/api/v1/events", params={"limit": 2, "cursor": first["next_cursor"]}
    ).json()
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert {item["event_id"] for item in first["items"]}.isdisjoint(
        item["event_id"] for item in second["items"]
    )
    assert second["items"][0]["access_key_id"] == "…1234"
    assert "raw" not in second["items"][0]
    assert (
        client.get("/api/v1/events", params={"operation": "' OR 1=1 --"}).json()[
            "items"
        ]
        == []
    )
    assert (
        client.get("/api/v1/events", params={"since": NOW.isoformat()}).json()["items"]
        == []
    )


def test_sec_local_protection_readonly_and_audit_integrity(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "aws.sqlite", source="aws")
    repository.ingest([normalize(record())], NOW)
    token = "a" * 32
    client = TestClient(create_app(repository, token=token))
    response = client.get("/api/v1/overview")
    assert (
        response.status_code == 401 and response.headers["Cache-Control"] == "no-store"
    )
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    auth = HEADERS | {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/overview", headers=auth).json()["source"] == "aws"
    assert (
        client.post(
            "/api/v1/sources/upload", headers=auth, content=payload(record(2))
        ).status_code
        == 403
    )
    assert client.get("/api/v1/audit", headers=auth).json()["valid"]
    with repository.connect() as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit SET details='{}'")
        connection.execute("DROP TRIGGER audit_no_update")
        connection.execute("UPDATE audit SET details='{}'")
    assert not client.get("/api/v1/audit", headers=auth).json()["valid"]

    demo = TestClient(create_app(Repository(tmp_path / "demo.sqlite")))
    assert (
        demo.post("/api/v1/sources/upload", content=payload(record())).status_code
        == 403
    )
    cross = HEADERS | {"Origin": "https://invalid.example"}
    assert (
        demo.post(
            "/api/v1/sources/upload", headers=cross, content=payload(record())
        ).status_code
        == 403
    )


def test_fr_resp_isolation_confirm_and_replay(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "data.sqlite")
    repository.ingest([normalize(record())], NOW)
    client = TestClient(create_app(repository))
    key = client.get("/api/v1/incidents").json()[0]["id"]
    path = "/api/v1/incidents/" + quote(key, safe="") + "/isolation"
    headers = HEADERS | {"Idempotency-Key": str(uuid4())}
    assert (
        client.post(
            path, json={"confirmation": "different"}, headers=headers
        ).status_code
        == 422
    )
    response = client.post(path, json={"confirmation": "example"}, headers=headers)
    assert response.status_code == 200
    assert response.json()["mode"] == "dry_run"
    assert response.json()["api"] == "iam:AttachUserPolicy"
    assert response.json()["params"]["UserName"] == "example"
    assert (
        client.post(path, json={"confirmation": "example"}, headers=headers).json()
        == response.json()
    )
    assert (
        client.post(
            path, json={"confirmation": "different"}, headers=headers
        ).status_code
        == 409
    )
    assert client.get("/api/v1/incidents").json()[0]["status"] == "responded"
    rows = client.get("/api/v1/audit").json()["items"]
    assert sum(row["action"] == "response.isolation.dry_run" for row in rows) == 1
