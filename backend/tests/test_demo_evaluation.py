from datetime import UTC, date, datetime, timedelta

from app.devdata import evaluate, generate, score_with_ablation, static_windows
from app.engine.events import Event, Identity
from app.engine.posture import Snapshot


def test_reference_scenarios_pass_acceptance_without_extra_events() -> None:
    end = date(2026, 11, 7)
    baseline = generate(end)
    extended = generate(end, extended=True)

    assert extended.events[: len(baseline.events)] == baseline.events
    assert extended.snapshots == baseline.snapshots
    assert {
        extended.labels[event.event_id]
        for event in extended.events[len(baseline.events) :]
    } == {"S1", "S3", "S5"}

    expected = {
        "S1": [
            "GetCallerIdentity",
            "ListBuckets",
            "ListUsers",
            "ListRoles",
            "CreateAccessKey",
            "AttachUserPolicy",
        ],
        "S3": [
            "GetCallerIdentity",
            "ListRoles",
            "CreatePolicyVersion",
            "AssumeRole",
            "UpdateFunctionCode",
        ],
        "S5": ["GetSecretValue"] * 6 + ["GetObject"] * 300,
    }
    for scenario, operations in expected.items():
        assert [
            event.name
            for event in baseline.events
            if baseline.labels.get(event.event_id) == scenario
        ] == operations

    report, passed = evaluate(baseline)
    assert passed, report


def test_context_ablation_rebuilds_history_using_its_own_risk_levels() -> None:
    first = datetime(2026, 11, 6, 9, tzinfo=UTC)
    repeat = first + timedelta(days=1)
    identity = Identity("111122223333", "user", "backup-operator")
    events = [
        Event(
            event_id=str(index),
            time=when,
            account_id=identity.account_id,
            identity=identity,
            name="ListBuckets",
            region="eu-central-1",
            source_ip="203.0.113.10",
        )
        for index, when in enumerate((first, first + timedelta(minutes=5), repeat))
    ]
    snapshots = {
        identity: (
            Snapshot(
                taken_at=first,
                mfa_enabled=False,
                active_key_age_days=180,
                actions=frozenset({"*"}),
            ),
        )
    }

    full, ablated = score_with_ablation(
        events, snapshots, repeat + timedelta(hours=2), first
    )

    assert full[identity, first].level == "medium"
    assert ablated[identity, first].level == "low"
    assert full[identity, repeat].behavior > 0
    assert ablated[identity, repeat].behavior == 0
    assert all(window.modifier == 1 for window in ablated.values())


def test_static_baseline_counts_parameter_reads_only_when_decrypted() -> None:
    first = datetime(2026, 11, 6, 9, tzinfo=UTC)
    identity = Identity("111122223333", "user", "config-reader")
    events = [
        Event(
            event_id=str(index),
            time=first + timedelta(hours=index),
            account_id=identity.account_id,
            identity=identity,
            name="GetParameters",
            region="eu-central-1",
            source_ip="203.0.113.10",
            with_decryption=decrypt,
        )
        for index, decrypt in enumerate((False, True))
    ]
    assert static_windows(events) == {(identity, events[1].hour)}
