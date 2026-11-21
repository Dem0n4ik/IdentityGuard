from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from types import SimpleNamespace
from typing import Any
from urllib.parse import quote

import pytest
from app import analytics
from app.api import create_app
from app.engine.events import Event, Identity
from app.engine.posture import Snapshot
from app.repository import Repository
from clickhouse_connect.driver.exceptions import OperationalError
from fastapi.testclient import TestClient

ACCOUNT = "111122223333"
OTHER = "222233334444"
ACTOR = Identity(ACCOUNT, "user", "test-user")
HOUR = datetime(2026, 11, 7, 12, tzinfo=UTC)


def event(
    identifier: str,
    operation: str = "StopLogging",
    *,
    account: str = ACCOUNT,
    region: str = "eu-central-1",
    category: str = "Management",
) -> Event:
    return Event(
        identifier,
        HOUR + timedelta(minutes=5),
        account,
        operation,
        region,
        "192.0.2.5",
        Identity(account, "user", ACTOR.name),
        category=category,
        access_key_id="example-credential-1234",
        raw={"sensitive_test_payload": "must not be returned"},
    )


def test_open_hour_is_scored_once_after_the_lateness_boundary(tmp_path: Path) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    imported = repo.ingest([event("first")], HOUR + timedelta(minutes=10))
    assert imported["windows"] == 0
    assert not repo.close_due(HOUR + timedelta(minutes=74, seconds=59))
    assert repo.pending_boundary(HOUR + timedelta(minutes=75)) == HOUR + timedelta(
        hours=1
    )
    assert repo.close_due(HOUR + timedelta(minutes=75), task_id="automatic-run")
    assert not repo.close_due(HOUR + timedelta(minutes=76), task_id="automatic-run")
    incident = repo.incidents()[0]
    assert incident["events"] == 1
    assert repo.scoring_boundary() == HOUR + timedelta(hours=1)
    assert [
        row["details"]["workflow_id"]
        for row in repo.audit_entries()[1]
        if row["action"] == "risk.auto_scored"
    ] == ["automatic-run"]
    repo.ingest([event("late", "DeleteTrail")], HOUR + timedelta(minutes=85))
    rescored = repo.incidents()[0]
    assert rescored["id"] == incident["id"] and rescored["events"] == 2


def test_trace_reconciles_model_terms_with_recorded_incident(tmp_path: Path) -> None:
    snapshot = Snapshot(HOUR - timedelta(days=1), mfa_enabled=False)
    repo = Repository(tmp_path / "db.sqlite", snapshots={ACTOR: (snapshot,)})
    repo.ingest([event("winner")], HOUR + timedelta(minutes=90))
    client = TestClient(create_app(repo))
    item = client.get("/api/v1/incidents").json()[0]
    path = "/api/v1/incidents/" + quote(item["id"], safe="") + "/trace"
    response = client.get(path)
    assert response.status_code == 200
    trace = response.json()
    assert sum(signal["contribution"] for signal in trace["signals"]) == pytest.approx(
        item["behavior"]
    )
    assert trace["fact_weights"]["no_mfa"] > 0
    assert trace["behavior_without_context"] + trace["context_uplift"] == pytest.approx(
        item["risk"]
    )
    assert trace["baseline"]["snapshot_at"] == snapshot.taken_at.isoformat().replace(
        "+00:00", "Z"
    )
    assert any(signal["event_id"] == "winner" for signal in trace["signals"])
    assert trace["events"][0]["operation"] == "StopLogging"
    assert (
        "access_key" not in response.text
        and "sensitive_test_payload" not in response.text
    )


def test_clickhouse_hunt_binds_filters_and_preserves_masked_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Repository(tmp_path / "db.sqlite")
    repo.ingest(
        [event("one"), event("two"), event("other", account=OTHER)],
        HOUR + timedelta(hours=2),
    )
    monkeypatch.setenv("IG_CLICKHOUSE_HUNT", "1")
    queries = []
    expected_operation = "x' OR 1=1 --"

    class FakeReader:
        def query(self, query: str, parameters: dict[str, Any]) -> object:
            queries.append((query, parameters))
            assert "identityguard.events FINAL" in query
            assert expected_operation not in query
            if parameters["operation"] == expected_operation:
                return SimpleNamespace(result_rows=[])
            return SimpleNamespace(result_rows=[("two",), ("one",)])

        def close(self) -> None:
            pass

    monkeypatch.setattr(analytics, "reader", FakeReader)
    client = TestClient(create_app(repo))
    args = {
        "account": ACCOUNT,
        "operation": "StopLogging",
        "region": "eu-central-1",
        "category": "Management",
        "limit": 1,
    }
    result = client.get("/api/v1/events", params=args).json()
    assert result["engine"] == "clickhouse"
    assert (
        result["items"][0]["event_id"] == "two"
        and result["items"][0]["access_key_id"] == "…1234"
    )
    assert "raw" not in result["items"][0] and result["next_cursor"]
    assert queries[0][1] == {
        "account": ACCOUNT,
        "operation": "StopLogging",
        "region": "eu-central-1",
        "category": "Management",
        "page_size": 2,
    }
    result = client.get(
        "/api/v1/events", params=args | {"operation": expected_operation}
    ).json()
    assert not result["items"]
    assert queries[-1][1]["operation"] == expected_operation


def test_private_workspace_stays_isolated_and_readiness_reports_index_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> None:
        raise OperationalError("simulated failure")

    monkeypatch.setattr(analytics, "reader", unavailable)
    monkeypatch.setenv("IG_CLICKHOUSE_HUNT", "1")
    demo = TestClient(create_app(Repository(tmp_path / "demo.sqlite")))
    assert demo.get("/healthz").status_code == 200
    assert demo.get("/readyz").status_code == 503
    assert demo.get("/api/v1/events").status_code == 503

    repo = Repository(tmp_path / "private.sqlite", source="aws")
    repo.ingest([event("private")], HOUR + timedelta(hours=2))
    token = token_urlsafe(32)
    private = TestClient(create_app(repo, token=token))
    assert private.get("/api/v1/events").status_code == 401
    result = private.get(
        "/api/v1/events", headers={"Authorization": "Bearer " + token}
    ).json()
    assert result["engine"] == "local" and result["items"][0]["event_id"] == "private"
