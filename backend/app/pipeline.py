from bisect import bisect_right
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta

from app.engine.events import Event, Identity, Network, hour_start
from app.engine.model import CLOUD, Model
from app.engine.posture import Snapshot
from app.engine.scoring import (
    BENIGN,
    IndicatorAdjuster,
    Profile,
    Window,
    WindowKey,
    apply_role_risk,
    build_profile,
    role_edges,
    score_window,
)


def state_at(history: Iterable[Snapshot], time: datetime) -> Snapshot | None:
    return max(
        (snapshot for snapshot in history if snapshot.taken_at <= time),
        key=lambda snapshot: snapshot.taken_at,
        default=None,
    )


def dormant_ids(
    events: list[Event],
    history: Iterable[Snapshot],
    coverage_breaks: tuple[datetime, ...] = (),
) -> frozenset[str]:
    result: set[str] = set()
    previous: datetime | None = None
    dormant_from: datetime | None = None
    previous_segment = -1
    snapshots = tuple(history)
    for event in events:
        segment = bisect_right(coverage_breaks, event.time)
        if segment != previous_segment:
            dormant_from = None
            snapshot = state_at(snapshots, event.time)
            if (
                snapshot
                and (segment == 0 or snapshot.taken_at >= coverage_breaks[segment - 1])
                and snapshot.last_used_days is not None
                and snapshot.last_used_days >= 30
            ):
                dormant_from = event.time.astimezone(UTC).replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
        elif previous is not None and event.time - previous >= timedelta(days=30):
            dormant_from = event.time
        if dormant_from is not None and event.time < dormant_from + timedelta(days=1):
            result.add(event.event_id)
        previous = event.time
        previous_segment = segment
    return frozenset(result)


CLOSURE_GRACE = timedelta(minutes=15)


def closed_boundary(now: datetime) -> datetime:
    return hour_start(now - CLOSURE_GRACE)


def evaluate_events(
    events: Iterable[Event],
    snapshots: Mapping[Identity, tuple[Snapshot, ...]],
    now: datetime,
    model: Model = CLOUD,
    *,
    trusted: tuple[Network, ...] = (),
    break_glass: frozenset[Identity] = frozenset(),
    feedback: Mapping[WindowKey, str] | None = None,
    start: datetime | None = None,
    monitoring_starts: Mapping[Identity, datetime] | None = None,
    coverage_breaks: Iterable[datetime] = (),
    adjust: IndicatorAdjuster | None = None,
    capture_evidence: bool = False,
) -> dict[WindowKey, Window]:
    cutoff = closed_boundary(now)
    ordered = sorted(
        {event.event_id: event for event in events if event.hour < cutoff}.values(),
        key=lambda event: (event.time, event.event_id),
    )
    by_identity: dict[Identity, list[Event]] = defaultdict(list)
    by_hour: dict[datetime, dict[Identity, list[Event]]] = defaultdict(
        lambda: defaultdict(list)
    )
    starts = monitoring_starts or {}
    for event in ordered:
        if event.identity is not None:
            by_identity[event.identity].append(event)
            begins = starts.get(event.identity, start)
            if begins is None or event.hour >= begins:
                by_hour[event.hour][event.identity].append(event)
    breaks = tuple(sorted(set(coverage_breaks)))
    inactive = {
        identity: dormant_ids(history, snapshots.get(identity, ()), breaks)
        for identity, history in by_identity.items()
    }
    transitions = defaultdict(list)
    for edge in role_edges(ordered):
        transitions[hour_start(edge.time)].append(edge)

    windows: dict[WindowKey, Window] = {}
    exclusions: dict[Identity, set[datetime]] = defaultdict(set)
    daily_profiles: dict[tuple[Identity, datetime], Profile | None] = {}
    previous_day: datetime | None = None
    for hour, groups in sorted(by_hour.items()):
        day = hour.replace(hour=0)
        if day != previous_day:
            daily_profiles.clear()
            previous_day = day
        current: dict[WindowKey, Window] = {}
        for identity, group in sorted(groups.items()):
            profile_key = identity, day
            if profile_key not in daily_profiles:
                daily_profiles[profile_key] = build_profile(
                    by_identity[identity],
                    day,
                    frozenset(exclusions[identity]),
                )
            current[identity, hour] = score_window(
                group,
                daily_profiles[profile_key],
                state_at(snapshots.get(identity, ()), hour),
                model,
                dormant_events=inactive[identity],
                trusted=trusted,
                break_glass=identity in break_glass,
                adjust=adjust,
                capture_evidence=capture_evidence,
            )
        relevant = {
            (identity, hour - timedelta(hours=offset)): window
            for identity in by_identity
            for offset in range(1, 5)
            if (window := windows.get((identity, hour - timedelta(hours=offset))))
            is not None
        }
        linked = apply_role_risk(
            relevant | current,
            transitions[hour - timedelta(hours=1)] + transitions[hour],
            model,
            break_glass,
        )
        for key in current:
            result = linked[key]
            windows[key] = result
            if result.level != "low" and (feedback or {}).get(key) not in BENIGN:
                exclusions[result.identity].add(hour)
    return windows
