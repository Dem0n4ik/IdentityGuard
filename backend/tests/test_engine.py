from dataclasses import replace
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network

import pytest
from app.engine.events import (
    Event,
    Identity,
    aws_public_networks,
    outside_networks,
    source_prefix,
)
from app.engine.model import (
    CLOUD,
    CLOUD_MATRIX,
    CORE,
    CORE_MATRIX,
    calculate_ahp,
    require_consistent_matrix,
)
from app.engine.posture import ESCALATION_PATHS, Snapshot, escalation_paths
from app.engine.scoring import (
    Profile,
    RoleEdge,
    active_risk,
    apply_role_risk,
    build_profile,
    exposure,
    modifier_for,
    risk_value,
    score_window,
)
from app.pipeline import dormant_ids
from hypothesis import given
from hypothesis import strategies as st

NOW = datetime(2026, 11, 7, 3, tzinfo=UTC)
USER = Identity("111122223333", "user", "test-user")
ROLE = Identity("222233334444", "role", "test-role")
PROFILE = Profile(
    frozenset(("eu-central-1",)),
    frozenset(("203.0.113",)),
    frozenset(("GetObject", "ListBuckets")),
    frozenset(range(9, 19)),
    10,
    2,
    100,
    14,
)


def event(index: int = 0, **fields: object) -> Event:
    defaults = {
        "event_id": f"event-{index}",
        "time": NOW,
        "account_id": USER.account_id,
        "name": "CreateAccessKey",
        "region": "us-west-2",
        "source_ip": "192.0.2.7",
        "identity": USER,
    }
    return Event(**(defaults | fields))


def test_fr_ex_a_core_score() -> None:
    window = score_window(
        [event(i) for i in range(30)], PROFILE, Snapshot(NOW, False, 91), CORE
    )
    assert window.indicators == {
        "geo": 1.0,
        "ip": 1.0,
        "time": 1.0,
        "seq": 1.0,
        "vol": 1.0,
        "priv": 1.0,
        "evasion": 0.0,
        "secret": 0.0,
    }
    expected = sum(
        CORE.weights[name] for name in ("geo", "ip", "time", "seq", "vol", "priv")
    )
    assert window.behavior == pytest.approx(expected)
    assert window.modifier == pytest.approx(1.45)
    assert window.risk == pytest.approx(79.895, abs=0.15)
    assert window.level == "high"
    assert sum(window.contributions.values()) == pytest.approx(1.0)


def test_fr_ex_b_known_privileged_operation() -> None:
    profile = replace(
        PROFILE, hours=frozenset((3,)), ops=frozenset(("CreateAccessKey",))
    )
    window = score_window(
        [event(region="eu-central-1", source_ip="203.0.113.1")],
        profile,
        Snapshot(NOW, actions=frozenset(("*",))),
        CORE,
    )
    assert window.indicators["priv"] == 0.5
    assert window.behavior == pytest.approx(CORE.weights["priv"] / 2)
    assert window.risk == pytest.approx(13.1875, abs=0.03)
    assert window.level == "low"


def test_aws_public_ranges_are_excluded_from_workload_egress() -> None:
    trusted = aws_public_networks(
        {
            "prefixes": [
                {"ip_prefix": "192.0.2.0/25"},
                {"ip_prefix": "192.0.2.128/25"},
            ],
            "ipv6_prefixes": [{"ipv6_prefix": "2001:db8:10::/48"}],
        }
    )
    assert len(trusted) == 2
    assert not outside_networks("192.0.2.170", trusted)
    assert not outside_networks("2001:db8:10::1", trusted)
    assert outside_networks("203.0.113.7", trusted)
    assert outside_networks("2001:db8:20::1", trusted)


def test_versioned_cloudtrail_lambda_api_uses_the_same_profile_and_privilege() -> None:
    name = "UpdateFunctionCode"
    versioned = event(name=name + "20150331v2", source="lambda.amazonaws.com")
    profile = replace(PROFILE, ops=frozenset({name}))
    window = score_window([versioned], profile)
    assert window.indicators["seq"] == 0
    assert window.indicators["priv"] == 0.5
    assert versioned.name != name


def test_fr_ex_c_d_e_f_zero_volume_cap_and_context() -> None:
    assert risk_value(0, 2) == 0
    assert (
        score_window([event(i) for i in range(18)], PROFILE, model=CORE).indicators[
            "vol"
        ]
        == 0.2
    )
    assert risk_value(0.8, 1.6) == 100
    assert risk_value(0.486, 1) == 48.6
    assert risk_value(0.486, 1.9) == pytest.approx(92.34)


def test_fr_ex_g_h_ahp() -> None:
    result = require_consistent_matrix(CORE_MATRIX)
    assert result.consistency_ratio == pytest.approx(0.021, abs=0.001)
    assert result.weights == tuple(CORE.weights.values())
    cloud_result = calculate_ahp(CLOUD_MATRIX)
    assert cloud_result.weights == tuple(CLOUD.weights.values())
    assert cloud_result.consistency_ratio == pytest.approx(0.019, abs=0.001)
    inconsistent = [list(row) for row in CORE_MATRIX]
    inconsistent[0][7], inconsistent[7][0] = 9, 1 / 9
    inconsistent[0][6], inconsistent[6][0] = 9, 1 / 9
    with pytest.raises(ValueError, match="consistency"):
        require_consistent_matrix(tuple(tuple(row) for row in inconsistent))


@given(
    st.floats(0, 1, allow_nan=False),
    st.floats(0, 1, allow_nan=False),
    st.sets(st.sampled_from(list(CLOUD.facts))),
)
def test_fr_risk_bounded_monotone_behavior_and_context(
    a: float, b: float, facts: set[str]
) -> None:
    low, high = sorted((a, b))
    modifier = modifier_for(facts)
    assert 1 <= modifier <= 2
    assert 0 <= risk_value(low, modifier) <= risk_value(high, modifier) <= 100
    assert risk_value(a, 1) <= risk_value(a, modifier)
    assert risk_value(0, modifier) == 0
    for fact in CLOUD.facts:
        assert risk_value(a, modifier) <= risk_value(a, modifier_for(facts | {fact}))


def test_fr_prof_support_population_deviation_and_boundaries() -> None:
    midnight = NOW.replace(hour=0)
    history = [
        event(1, time=midnight - timedelta(days=14), region="common"),
        event(2, time=midnight - timedelta(days=14, minutes=-3), region="common"),
        event(3, time=midnight - timedelta(days=1), region="singleton"),
        event(4, time=midnight - timedelta(days=14, seconds=1), region="too-old"),
        event(5, time=midnight, region="future"),
    ]
    profile = build_profile(history, NOW)
    assert profile is not None
    assert profile.regions == {"common"}
    assert profile.n_days == 2 and profile.n_events == 3
    assert profile.mean == 1.5 and profile.std == 1.0
    assert (
        build_profile(history, NOW, frozenset((history[0].hour, history[2].hour)))
        is None
    )
    assert source_prefix("2001:db8:0:1::5678") == "2001:db8:0:1::/64"
    assert source_prefix("ec2.amazonaws.com") == "ec2.amazonaws.com"


@pytest.mark.parametrize(
    ("address", "vpc", "expected"),
    [
        ("172.31.2.3", "", 0),
        ("192.0.2.5", "", 1),
        ("ec2.amazonaws.com", "", 0),
        ("198.51.100.5", "", 0),
        ("192.0.2.5", "vpce-example", 0),
    ],
)
def test_fr_ind_wexfil(address: str, vpc: str, expected: int) -> None:
    result = score_window(
        [event(source_ip=address, identity=ROLE, vpc_endpoint_id=vpc)],
        PROFILE,
        Snapshot(NOW, workload=True),
        trusted=(ip_network("198.51.100.0/24"),),
    )
    assert result.indicators["wexfil"] == expected


def test_fr_ind_dormant_and_ssm_decryption() -> None:
    events = [
        event(1, time=NOW),
        event(2, time=NOW + timedelta(days=30)),
        event(3, time=NOW + timedelta(days=31)),
    ]
    assert dormant_ids(events, ()) == {"event-2"}
    assert dormant_ids(
        events[:1], (Snapshot(NOW - timedelta(days=1), last_used_days=30),)
    ) == {"event-1"}
    operation = event(name="GetParameter")
    assert score_window([operation], PROFILE).indicators["secret"] == 0
    assert (
        score_window([replace(operation, with_decryption=True)], PROFILE).indicators[
            "secret"
        ]
        == 1
    )


def test_known_cloudtrail_gap_requires_new_evidence_of_dormancy() -> None:
    resumed = NOW + timedelta(days=35)
    first = event(1, time=NOW)
    resumed_event = event(2, time=resumed + timedelta(minutes=10))
    later_event = event(3, time=resumed + timedelta(days=30, minutes=10))
    old_snapshot = Snapshot(NOW + timedelta(days=1), last_used_days=50)

    assert dormant_ids(
        [first, resumed_event, later_event], (old_snapshot,), (resumed,)
    ) == {"event-3"}
    new_snapshot = Snapshot(resumed, last_used_days=40)
    assert dormant_ids(
        [first, resumed_event], (old_snapshot, new_snapshot), (resumed,)
    ) == {"event-2"}


@pytest.mark.parametrize(("index", "actions"), tuple(enumerate(ESCALATION_PATHS, 1)))
def test_fr_esc_all_paths_positive_and_partial(
    index: int, actions: tuple[str, ...]
) -> None:
    assert index in escalation_paths(frozenset(action.upper() for action in actions))
    assert index not in escalation_paths(frozenset(actions[:-1]))
    assert escalation_paths(frozenset(("*",))) == ()


def test_fr_ctx_roles_never_no_mfa_and_irs_does_not_inherit_exposure() -> None:
    assert "no_mfa" not in Snapshot(NOW, mfa_enabled=False).facts(ROLE)
    window = score_window([event()], PROFILE)
    assert active_risk([window], NOW + timedelta(days=1)) == pytest.approx(
        window.risk / 2
    )
    assert active_risk([window], NOW + timedelta(days=8)) == 0
    assert exposure(["risky_source", "critical"]) == 10


def test_fr_chain_only_propagates_in_time_and_at_the_threshold() -> None:
    first = score_window([event()], None, Snapshot(NOW, actions=frozenset(("*",))))
    second = score_window([event(identity=ROLE)], PROFILE)
    windows = {(USER, NOW): first, (ROLE, NOW): second}
    edge = RoleEdge(USER, ROLE, NOW + timedelta(minutes=15))
    assert edge.cross_account
    assert "risky_source" in apply_role_risk(windows, [edge])[(ROLE, NOW)].facts
    assert (
        "risky_source"
        not in apply_role_risk(windows, [replace(edge, time=NOW + timedelta(hours=4))])[
            (ROLE, NOW)
        ].facts
    )
    assert (
        "risky_source"
        not in apply_role_risk(
            windows | {(USER, NOW): replace(first, risk=24.99)}, [edge]
        )[(ROLE, NOW)].facts
    )
