from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.api import create_app
from app.demo_incidents import SCENARIOS, actors_for, replay
from app.devdata import CORP
from app.repository import Repository
from fastapi.testclient import TestClient


def test_synthetic_exercise_runs_through_scoring_and_case_correlation(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "exercise.sqlite", trusted=CORP)
    now = datetime.now(UTC)
    summary = replay(repository, now)
    assert summary["cases"] == 15
    assert summary["incidents"]["runner"] == 7
    assert "quiet-deploy" not in summary["incidents"]
    assert "quiet-audit" not in summary["incidents"]
    assert replay(repository, now) == {**summary, "already_loaded": True}

    client = TestClient(create_app(repository))
    cases = [
        item
        for item in client.get("/api/v1/overview").json()["cases"]
        if item["simulation"]
    ]
    runner = next(
        item
        for item in cases
        if item["simulation"]["title_en"] == "Compromised CI runner"
    )
    timeline = client.get(f"/api/v1/cases/{runner['id']}/timeline").json()
    assert timeline["total"] == len(timeline["items"])
    events = [item["event"] for item in timeline["items"]]
    assert events == sorted(events, key=lambda event: event["time"])
    transitions = [
        item["event"] for item in timeline["items"] if item["role_transition"]
    ]
    actors = actors_for(SCENARIOS[0])
    assert [event["identity"]["name"] for event in transitions] == [
        actor.name for actor in actors[:-1]
    ]
    assert [event["target"].split("/")[-1] for event in transitions] == [
        actor.name for actor in actors[1:]
    ]
    assert sum(event["error_code"] == "AccessDenied" for event in events) == 1
    final = next(
        item
        for item in runner["incidents"]
        if item["identity"]["name"] == actors[-1].name
    )
    trace = client.get(f"/api/v1/incidents/{final['id']}/trace").json()
    assert (
        final["behavior"]
        * (final["modifier"] - trace["fact_weights"]["risky_source"])
        * 100
        < 25
    )
    assert final["risk"] >= 25
    assert (
        sum(item["incidents"][0]["verdict"] == "false_positive" for item in cases) == 3
    )
    assert (
        sum(item["incidents"][0]["verdict"] == "benign_true_positive" for item in cases)
        == 3
    )
    assert client.get("/api/v1/cases/unknown/timeline").status_code == 404

    refreshed = replay(repository, now + timedelta(days=8), refresh=True)
    assert refreshed["cases"] == 15
    assert set(summary["latest_cases"]).isdisjoint(refreshed["latest_cases"])
    assert 0 < refreshed["inserted"] <= refreshed["events"]
    assert replay(repository, now + timedelta(days=8, hours=1), refresh=True) == {
        **refreshed,
        "already_loaded": True,
    }
    all_cases = client.get("/api/v1/overview").json()["cases"]
    assert len([item for item in all_cases if item["simulation"]]) == 30
    recent = [item for item in all_cases if item["id"] in refreshed["latest_cases"]]
    assert {item["status"] for item in recent} == {
        "new",
        "investigating",
        "responded",
        "closed",
    }

    scoped = client.get(
        "/api/v1/sla", params={"account": "111000001004", "range": "all"}
    )
    assert scoped.status_code == 200
    assert scoped.json()["open_cases"] > 0
    assert all(item["account"] == "111000001004" for item in scoped.json()["overdue"])
    empty = client.get("/api/v1/sla", params={"account": "111000009999", "range": "7"})
    assert empty.json()["open_cases"] == 0
    assert empty.json()["mtta_median_hours"] is None
