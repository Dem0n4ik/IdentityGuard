import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from urllib.parse import quote

import pytest
from app import assistant, webhooks
from app.api import create_app
from app.engine.access import AccessNode, CloudSnapshot, Graph, edge
from app.engine.detections import InvalidRule, parse_rule
from app.engine.events import Event, Identity
from app.engine.posture import Snapshot
from app.repository import Repository, identity_id
from fastapi.testclient import TestClient

NOW = datetime.now(UTC)
ACCOUNT = "111122223333"
ACTOR = Identity(ACCOUNT, "user", "test-user")
LOCAL = {"X-IdentityGuard-Local": "1"}
RULE = """id: ig-test-custom
name: Custom IAM action
category: priv
value: 1
condition:
  all:
    - {field: event_name, op: regex, value: '^CustomAction$'}
    - {field: source_ip, op: cidr, value: 192.0.2.0/24}
tests:
  - event: {event_name: CustomAction, source_ip: 192.0.2.9}
    expect: match
  - event: {event_name: CustomAction, source_ip: 172.16.0.1}
    expect: no_match
"""


def event(name: str = "CustomAction", identifier: str = "sample") -> Event:
    return Event(
        identifier,
        NOW - timedelta(hours=4),
        ACCOUNT,
        name,
        "eu-central-1",
        "192.0.2.9",
        ACTOR,
    )


def test_fr_det_rejects_failed_tests_unsafe_patterns_and_aliases() -> None:
    assert parse_rule(RULE).definition.id == "ig-test-custom"
    with pytest.raises(InvalidRule, match=r"line .*rule test"):
        parse_rule(RULE.replace("expect: no_match", "expect: match"))
    with pytest.raises(InvalidRule, match=r"line .*invalid RE2"):
        parse_rule(RULE.replace("^CustomAction$", "(?<=x)CustomAction"))
    with pytest.raises(InvalidRule, match="aliases, anchors and tags"):
        parse_rule(RULE.replace("name: Custom", "name: &alias Custom"))


def test_fr_det_backtest_publish_and_fr_sup_preserve_incident(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    repo.ingest([event()], NOW)
    client = TestClient(create_app(repo))
    assert client.get("/api/v1/incidents").json() == []
    trial = client.post(
        "/api/v1/detections/backtest", headers=LOCAL, json={"yaml": RULE, "days": 7}
    )
    assert trial.status_code == 200, trial.text
    report = trial.json()
    assert report["matches"] == report["changed"] == report["new_incidents"] == 1
    assert client.get("/api/v1/incidents").json() == []
    published = client.post(
        "/api/v1/detections", headers=LOCAL, json={"yaml": RULE, "status": "enabled"}
    )
    assert published.status_code == 200
    row = client.get("/api/v1/incidents").json()[0]
    assert row["indicators"]["priv"] == 1
    assert row["model_version"].startswith("cloud-v2+")
    draft = client.post(
        "/api/v1/detections", headers=LOCAL, json={"yaml": RULE, "status": "draft"}
    )
    assert draft.json()["revision"] == 2
    path = "/api/v1/incidents/" + quote(row["id"], safe="")
    patched = client.patch(
        path,
        headers=LOCAL | {"If-Match": f'"{row["version"]}"'},
        json={"status": "investigating", "note": "Keep this note"},
    )
    assert patched.status_code == 200
    first = patched.json()["first_response_at"]

    body = {
        "identity_id": identity_id(ACTOR),
        "indicator": "priv",
        "field": "event_name",
        "value": "CustomAction",
        "days": 2,
        "case_id": row["case_id"],
        "reason": "Approved test window",
    }
    assert (
        client.post(
            "/api/v1/suppressions", headers=LOCAL, json=body | {"indicator": "evasion"}
        ).status_code
        == 422
    )
    saved = client.post("/api/v1/suppressions", headers=LOCAL, json=body)
    assert saved.status_code == 200, saved.text
    assert saved.json()["hits"] == 1
    after = client.get("/api/v1/incidents").json()[0]
    assert after["id"] == row["id"] and after["case_id"] == row["case_id"]
    assert after["status"] == "closed" and after["auto_resolution"] == "rescored_low"
    assert after["note"] == "Keep this note" and after["first_response_at"] == first
    assert after["risk"] < row["risk"] and after["indicators"]["priv"] == 0


def test_fr_gov_shadow_and_fr_sla_quality(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    repo.ingest([event("StopLogging")], NOW)
    client = TestClient(create_app(repo))
    version = client.get("/api/v1/models/baselines").json()[1]
    body = {
        "profile": "cloud-v2",
        "matrix": version["matrix"],
        "name": "Retrospective model",
        "thr_mid": 25,
        "thr_high": 48,
    }
    report = client.post(
        "/api/v1/models/ahp",
        headers=LOCAL,
        json={"profile": "cloud-v2", "matrix": version["matrix"]},
    ).json()
    assert report["consistent"] and report["cr"] < 0.1
    invalid = [[1.0] * 10 for _ in range(10)]
    for first, second, value in ((0, 1, 9), (1, 2, 9), (0, 2, 1 / 9)):
        invalid[first][second], invalid[second][first] = value, 1 / value
    assert (
        client.post(
            "/api/v1/models/drafts", headers=LOCAL, json=body | {"matrix": invalid}
        ).status_code
        == 422
    )
    created = client.post("/api/v1/models/drafts", headers=LOCAL, json=body)
    assert created.status_code == 200, created.text
    before = client.get("/api/v1/incidents").json()
    shadow = client.post(
        "/api/v1/models/drafts/" + created.json()["id"] + "/shadow",
        headers=LOCAL,
        json={"days": 7},
    )
    assert shadow.json()["shadow"]["evaluated"] == 1
    assert client.get("/api/v1/incidents").json() == before

    row = before[0]
    closed = client.patch(
        "/api/v1/incidents/" + quote(row["id"], safe=""),
        headers=LOCAL | {"If-Match": '"1"'},
        json={
            "status": "closed",
            "verdict": "true_positive",
            "reason": "Confirmed credential misuse",
        },
    )
    assert closed.status_code == 200
    metrics = client.get("/api/v1/sla").json()
    assert metrics["open_cases"] == 0 and metrics["mtta_median_hours"] > 0
    quality = client.get("/api/v1/quality").json()
    assert quality["by_week"][0]["precision"] == 1
    assert quality["recommended"]["precision"] >= 0.9


def test_fr_path_mandatory_links_include_longer_alternatives() -> None:
    nodes = [
        AccessNode(
            id=key,
            name=key,
            kind="role",
            account_id=ACCOUNT,
            critical=key == "destination",
        )
        for key in ("origin", "direct", "detour", "junction", "destination")
    ]
    shorter = edge("origin", "junction", "can_assume")
    mandatory = edge("junction", "destination", "has_access")
    graph = Graph(
        nodes,
        [
            shorter,
            mandatory,
            edge("origin", "detour", "can_assume"),
            edge("detour", "junction", "can_assume"),
        ],
    )
    path = graph.paths("origin")[0]
    assert path.hops == 2 and path.key_links == [mandatory.id]


def test_fr_path_grounding_and_cloud_fact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    origin = identity_id(ACTOR)
    resource = "arn:aws:s3:::test-bucket"
    nodes = [
        AccessNode(id=origin, name=ACTOR.name, kind="user", account_id=ACCOUNT),
        AccessNode(
            id=resource,
            name="test-bucket",
            kind="s3",
            account_id=ACCOUNT,
            critical=True,
        ),
    ]
    grant = edge(origin, resource, "has_access", ["s3:GetObject"])
    repo.save_posture(
        {ACTOR: (Snapshot(NOW - timedelta(hours=10), mfa_enabled=True),)}, NOW
    )
    repo.save_cloud_snapshot(
        CloudSnapshot(
            account_id=ACCOUNT,
            region="eu-central-1",
            taken_at=NOW - timedelta(hours=5),
            source="demo",
            checks=[],
            nodes=nodes,
            edges=[grant],
        )
    )
    repo.ingest([event("StopLogging")], NOW)
    client = TestClient(
        create_app(repo, ai_key=token_urlsafe(32), ai_model="mock-model")
    )
    paths = client.get("/api/v1/attack-paths", params={"origin": origin}).json()
    path = paths[0]
    assert path["explanation"]["source"] == "template" and path["key_links"] == [
        grant.id
    ]
    assert "critical" in client.get("/api/v1/incidents").json()[0]["facts"]

    def respond(_key: str, _model: str, _system: str, evidence: object) -> str:
        assert ACTOR.name not in str(evidence) and "test-bucket" not in str(evidence)
        return json.dumps(
            {
                "summary": "Unverified",
                "steps": [{"edge_id": "0" * 24, "text": "Invalid edge"}],
                "key_links": [],
            }
        )

    monkeypatch.setattr(assistant, "request_json", respond)
    result = client.post(
        "/api/v1/attack-paths/" + path["id"] + "/explain",
        headers=LOCAL,
        json={"origin": origin, "language": "uk", "consent": True},
    )
    assert result.json()["source"] == "template"
    assert result.json()["key_links"] == [grant.id]


def test_fr_int_webhook_denies_private_targets_and_signs_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(webhooks.UnsafeDestination):
        webhooks.resolve_destination("https://169.254.169.254/latest")
    secret = token_urlsafe(32)
    endpoint = "https://receiver.example/events"
    monkeypatch.setattr(
        webhooks, "resolve_destination", lambda url: (webhooks.urlsplit(url), "8.8.8.8")
    )

    class FakeConnection:
        def __init__(self, host: str, ip: str) -> None:
            assert host == "receiver.example" and ip == "8.8.8.8"

        def request(
            self, method: str, path: str, body: bytes, headers: dict[str, str]
        ) -> None:
            assert method == "POST" and path == "/events"
            expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
            assert headers["X-IdentityGuard-Signature"] == f"sha256={expected}"
            assert json.loads(body)["event"] == "identityguard.webhook.test"

        def getresponse(self) -> object:
            from types import SimpleNamespace

            return SimpleNamespace(status=202)

        def close(self) -> None:
            pass

    monkeypatch.setattr(webhooks, "PinnedHTTPS", FakeConnection)
    assert webhooks.send_test(endpoint, secret, NOW) == 202


def test_outbox_is_atomic_and_retry_safe(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    repo.ingest([event()], NOW)
    repo.backfill_outbox()
    repo.ingest([event()], NOW)
    assert repo.outbox_counts() == (1, 0)
    assert [item.event_id for item in repo.pending_events(1)] == ["sample"]
    repo.mark_published(["sample", "sample"])
    assert repo.outbox_counts() == (0, 1)
    repo.rescore(task_id="workflow-for-test")
    repo.rescore(task_id="workflow-for-test")
    assert sum(row["action"] == "risk.rescored" for row in repo.audit_entries()[1]) == 1


def test_fr_path_s3_object_grant_requires_matching_bucket_and_object() -> None:
    from app.cloud_inventory import resource_grants

    arn = "arn:aws:s3:::project-bucket"
    node = AccessNode(id=arn, name="project-bucket", kind="s3", account_id=ACCOUNT)

    def policy(resource: str) -> list[dict[str, str]]:
        return [{"Action": "s3:GetObject", "Resource": resource}]

    assert not resource_grants(policy(arn), "s3:GetObject", node)
    assert resource_grants(policy(arn + "/approved/report"), "s3:GetObject", node)
    assert resource_grants(policy("arn:aws:s3:::project-*/*"), "s3:GetObject", node)
    assert not resource_grants(
        policy("arn:aws:s3:::foreign-bucket/*"), "s3:GetObject", node
    )
