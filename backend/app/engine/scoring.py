from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from math import fsum
from typing import Literal

import polars as pl

from app.engine.events import Event, Identity, Network, outside_networks, source_prefix
from app.engine.model import CLOUD, DECRYPT_OPERATIONS, Model
from app.engine.posture import Snapshot

Level = Literal["low", "medium", "high"]
WindowKey = tuple[Identity, datetime]
IndicatorAdjuster = Callable[[list[Event], pl.DataFrame, Model], pl.DataFrame]
BENIGN = frozenset(("false_positive", "benign_true_positive"))
ASSUME = frozenset(("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"))


@dataclass(frozen=True, slots=True)
class Profile:
    regions: frozenset[str]
    prefixes: frozenset[str]
    ops: frozenset[str]
    hours: frozenset[int]
    mean: float
    std: float
    n_events: int
    n_days: int


@dataclass(frozen=True, slots=True)
class Evidence:
    baseline_events: int
    baseline_days: int
    mean: float | None
    std: float | None
    regions: tuple[str, ...]
    hours: tuple[int, ...]
    operations: tuple[str, ...]
    network_count: int
    snapshot_at: datetime | None
    weights: dict[str, float]
    fact_weights: dict[str, float]
    medium: float
    high: float
    strongest_events: dict[str, str]


@dataclass(frozen=True, slots=True)
class Window:
    identity: Identity
    hour: datetime
    model_version: str
    events: int
    behavior: float
    modifier: float
    risk: float
    level: Level
    indicators: dict[str, float]
    contributions: dict[str, float]
    facts: tuple[str, ...]
    explanation_uk: str
    explanation_en: str
    event_scores: dict[str, float]
    evidence: Evidence | None = None
    override: str | None = None


@dataclass(frozen=True, slots=True)
class RoleEdge:
    source: Identity
    target: Identity
    time: datetime

    @property
    def cross_account(self) -> bool:
        return self.source.account_id != self.target.account_id


LAMBDA_OPERATIONS = {
    "UpdateFunctionCode20150331v2": "UpdateFunctionCode",
    "UpdateFunctionConfiguration20150331v2": "UpdateFunctionConfiguration",
    "PublishLayerVersion20181031": "PublishLayerVersion",
}


def operation_key(event: Event) -> str:
    if event.source == "lambda.amazonaws.com":
        return LAMBDA_OPERATIONS.get(event.name, event.name)
    return event.name


def event_frame(events: Iterable[Event]) -> pl.DataFrame:
    return pl.DataFrame(
        (
            (
                e.event_id,
                e.time,
                e.region,
                source_prefix(e.source_ip),
                operation_key(e),
                e.with_decryption,
                e.mfa_used,
            )
            for e in events
        ),
        schema={
            "event_id": pl.String,
            "time": pl.Datetime("us", "UTC"),
            "region": pl.String,
            "prefix": pl.String,
            "operation": pl.String,
            "decrypt": pl.Boolean,
            "mfa": pl.Boolean,
        },
        orient="row",
    ).with_columns(
        pl.col("time").dt.truncate("1h").alias("window"),
        pl.col("time").dt.hour().alias("hour"),
    )


def build_profile(
    events: Iterable[Event],
    day: datetime,
    excluded_hours: frozenset[datetime] = frozenset(),
) -> Profile | None:
    day = day.replace(hour=0, minute=0, second=0, microsecond=0)
    frame = event_frame(events).filter(
        (pl.col("time") >= day - timedelta(days=14))
        & (pl.col("time") < day)
        & ~pl.col("window").is_in(sorted(excluded_hours))
    )
    if frame.is_empty():
        return None
    hourly = frame.group_by("window").len()
    mean, std = hourly.select(
        pl.col("len").mean().alias("mean"), pl.col("len").std(ddof=0).alias("std")
    ).row(0)
    regions = frozenset(
        frame.group_by("region").len().filter(pl.col("len") >= 2)["region"]
    )
    prefixes = frozenset(
        frame.group_by("prefix").len().filter(pl.col("len") >= 2)["prefix"]
    )
    ops = frozenset(
        frame.group_by("operation").len().filter(pl.col("len") >= 2)["operation"]
    )
    hours = frozenset(frame.group_by("hour").len().filter(pl.col("len") >= 2)["hour"])
    return Profile(
        regions,
        prefixes,
        ops,
        hours,
        float(mean),
        max(1.0, float(std)),
        frame.height,
        frame.select(pl.col("time").dt.date().n_unique()).item(),
    )


def event_indicators(
    events: list[Event],
    profile: Profile | None,
    model: Model,
    snapshot: Snapshot | None,
    dormant_events: frozenset[str],
    trusted: tuple[Network, ...],
) -> pl.DataFrame:
    frame = event_frame(events)
    operation = pl.col("operation")
    if profile is None:
        geo = ip = time = seq = pl.lit(True)
        volume = 0.0
    else:
        geo = ~pl.col("region").is_in(sorted(profile.regions))
        ip = ~pl.col("prefix").is_in(sorted(profile.prefixes))
        time = ~pl.col("hour").is_in(sorted(profile.hours))
        seq = ~operation.is_in(sorted(profile.ops))
        volume = min(
            1.0, max(0.0, ((len(events) - profile.mean) / profile.std - 3) / 5)
        )
    is_priv = operation.is_in(sorted(model.priv))
    priv = pl.when(is_priv).then(pl.when(seq).then(1.0).otherwise(0.5)).otherwise(0.0)
    secret = operation.is_in(sorted(model.secret))
    evasion = operation.is_in(sorted(model.evasion))
    extras: list[pl.Expr | pl.Series] = []
    if "wexfil" in model.weights:
        identity = events[0].identity
        if identity is not None and identity.kind in {"user", "root"}:
            priv = (
                pl.when((operation == "ConsoleLogin") & (pl.col("mfa") == False))
                .then(1.0)
                .otherwise(priv)
            )
        secret = secret | (
            operation.is_in(sorted(DECRYPT_OPERATIONS)) & pl.col("decrypt")
        )
        extras = [
            pl.col("event_id")
            .is_in(sorted(dormant_events))
            .cast(pl.Float64)
            .alias("dormant"),
            pl.Series(
                "wexfil",
                [
                    float(
                        identity is not None
                        and identity.kind == "role"
                        and snapshot is not None
                        and snapshot.workload
                        and not event.vpc_endpoint_id
                        and outside_networks(event.source_ip, trusted)
                    )
                    for event in events
                ],
            ),
        ]
    return frame.with_columns(
        geo.cast(pl.Float64).alias("geo"),
        ip.cast(pl.Float64).alias("ip"),
        time.cast(pl.Float64).alias("time"),
        seq.cast(pl.Float64).alias("seq"),
        pl.lit(volume).alias("vol"),
        priv.alias("priv"),
        evasion.cast(pl.Float64).alias("evasion"),
        (secret & seq).cast(pl.Float64).alias("secret"),
        *extras,
    )


FACT_LABELS = {
    "no_mfa": ("немає MFA", "MFA is disabled"),
    "old_key": ("застарілий ключ", "aging access key"),
    "privileged": ("адміністративні дозволи", "administrative permissions"),
    "escalation": ("можливе підвищення привілеїв", "privilege escalation is possible"),
    "critical": ("доступ до критичних ресурсів", "access to critical resources"),
    "external_trust": ("зовнішня довіра", "external trust"),
    "imds_v1": ("дозволено IMDSv1", "IMDSv1 is allowed"),
    "excessive_perms": ("надлишкові дозволи", "excess permissions"),
    "risky_source": ("ризикове джерело ролі", "risky role source"),
    "thin_baseline": ("недостатня історія", "limited baseline"),
}
INDICATOR_LABELS = dict(
    zip(
        (
            "geo",
            "ip",
            "time",
            "seq",
            "vol",
            "priv",
            "evasion",
            "secret",
            "dormant",
            "wexfil",
        ),
        (
            ("незвичний регіон", "unusual region"),
            ("незвична мережа", "unusual network"),
            ("незвична година", "unusual hour"),
            ("незвична операція", "unusual operation"),
            ("надмірний обсяг", "unusual volume"),
            ("привілейована дія", "privileged action"),
            ("уникнення журналювання", "logging evasion"),
            ("доступ до секретів", "secret access"),
            ("активація сплячої ідентичності", "dormant identity reactivation"),
            (
                "використання облікових даних поза AWS",
                "workload credentials used outside AWS",
            ),
        ),
        strict=True,
    )
)


def risk_value(behavior: float, modifier: float) -> float:
    return 100 * min(1.0, behavior * modifier)


def modifier_for(facts: Iterable[str], model: Model = CLOUD) -> float:
    return 1.0 + fsum(model.facts[fact] for fact in set(facts) & model.facts.keys())


def behavior_terms(indicators: Mapping[str, float], model: Model) -> dict[str, float]:
    return {
        key: weight * indicators.get(key, 0.0) for key, weight in model.weights.items()
    }


def classify(
    risk: float, medium: float, high: float, override: str | None = None
) -> Level:
    return "high" if override or risk >= high else "medium" if risk >= medium else "low"


def explain(
    level: Level,
    risk: float,
    modifier: float,
    contributions: dict[str, float],
    facts: tuple[str, ...],
    override: str | None,
) -> tuple[str, str]:
    top = sorted(contributions, key=lambda key: (-contributions[key], key))[:3]
    reasons_uk = ", ".join(
        f"{INDICATOR_LABELS[k][0]} ({contributions[k]:.0%})" for k in top
    )
    reasons_en = ", ".join(
        f"{INDICATOR_LABELS[k][1]} ({contributions[k]:.0%})" for k in top
    )
    label = {"low": "низький", "medium": "середній", "high": "високий"}[level]
    uk_score = f"{risk:.2f}".replace(".", ",")
    uk_modifier = f"{modifier:.2f}".replace(".", ",")
    uk = f"Рівень ризику {label} ({uk_score} з 100)."
    en = f"Risk level {level} ({risk:.2f} out of 100)."
    if top:
        uk += f" Основні причини — {reasons_uk}."
        en += f" Main drivers are {reasons_en}."
    if facts:
        uk += f" Оцінку підвищено в {uk_modifier} раза через такі факти: "
        uk += ", ".join(FACT_LABELS[k][0] for k in facts) + "."
        en += f" Context multiplies the score by {modifier:.2f} due to "
        en += ", ".join(FACT_LABELS[k][1] for k in facts) + "."
    if override == "root":
        uk += " Правило використання кореневого користувача встановило високий рівень."
        en += " Root usage forced high severity."
    if override == "break-glass":
        uk += " Правило аварійного доступу встановило високий рівень."
        en += " Break-glass usage forced high severity."
    return uk, en


def apply_context(
    window: Window,
    facts: Iterable[str],
    model: Model,
    break_glass: bool = False,
) -> Window:
    selected_facts = set(facts)
    active = tuple(fact for fact in model.facts if fact in selected_facts)
    modifier = modifier_for(active, model)
    risk = risk_value(window.behavior, modifier)
    override = (
        "root"
        if window.identity.kind == "root"
        else "break-glass"
        if break_glass
        else None
    )
    level = classify(risk, model.thr_mid, model.thr_high, override)
    uk, en = explain(level, risk, modifier, window.contributions, active, override)
    return replace(
        window,
        facts=active,
        modifier=modifier,
        risk=risk,
        level=level,
        explanation_uk=uk,
        explanation_en=en,
        override=override,
    )


def score_window(
    events: list[Event],
    profile: Profile | None,
    snapshot: Snapshot | None = None,
    model: Model = CLOUD,
    *,
    dormant_events: frozenset[str] = frozenset(),
    trusted: tuple[Network, ...] = (),
    break_glass: bool = False,
    adjust: IndicatorAdjuster | None = None,
    capture_evidence: bool = False,
) -> Window:
    if not events or events[0].identity is None:
        raise ValueError(
            "A score requires at least one event attributed to an identity"
        )
    first = events[0]
    identity = events[0].identity
    if any(event.identity != identity or event.hour != first.hour for event in events):
        raise ValueError("A score accepts a single identity and UTC hour")
    frame = event_indicators(events, profile, model, snapshot, dormant_events, trusted)
    if adjust is not None:
        frame = adjust(events, frame, model)
    peaks = frame.select(pl.col(list(model.weights)).max()).row(0, named=True)
    terms = behavior_terms(peaks, model)
    behavior = fsum(terms.values())
    contribution = {key: term / behavior for key, term in terms.items() if term > 0}
    event_scores = frame.select(
        "event_id",
        pl.sum_horizontal(
            *(pl.col(key) * weight for key, weight in model.weights.items())
        ),
    )
    facts = set(snapshot.facts(identity) if snapshot else ())
    if profile is None or profile.n_events < 50:
        facts.add("thin_baseline")
    evidence = None
    if capture_evidence:
        winners = frame.select(*(pl.col(key).arg_max() for key in model.weights)).row(
            0, named=True
        )
        evidence = Evidence(
            baseline_events=profile.n_events if profile else 0,
            baseline_days=profile.n_days if profile else 0,
            mean=profile.mean if profile else None,
            std=profile.std if profile else None,
            regions=tuple(sorted(profile.regions)) if profile else (),
            hours=tuple(sorted(profile.hours)) if profile else (),
            operations=tuple(sorted(profile.ops)[:50]) if profile else (),
            network_count=len(profile.prefixes) if profile else 0,
            snapshot_at=snapshot.taken_at if snapshot else None,
            weights=dict(model.weights),
            fact_weights=dict(model.facts),
            medium=model.thr_mid,
            high=model.thr_high,
            strongest_events={
                key: events[index].event_id
                for key, index in winners.items()
                if peaks[key] > 0
            },
        )
    result = Window(
        identity,
        first.hour,
        model.version,
        len(events),
        behavior,
        1,
        0,
        "low",
        peaks,
        contribution,
        (),
        "",
        "",
        dict(event_scores.iter_rows()),
        evidence=evidence,
    )
    return apply_context(result, facts, model, break_glass)


def role_edges(events: Iterable[Event]) -> list[RoleEdge]:
    edges = []
    for event in events:
        if event.name not in ASSUME or event.identity is None or event.error_code:
            continue
        parts = event.target.split(":", 5)
        if (
            len(parts) != 6
            or parts[0] != "arn"
            or parts[2] != "iam"
            or not parts[5].startswith("role/")
        ):
            continue
        target = Identity(parts[4], "role", parts[5].rsplit("/", 1)[-1])
        edges.append(RoleEdge(event.identity, target, event.time))
    return edges


def exposure(facts: Iterable[str], model: Model = CLOUD) -> float:
    return 100 * fsum(
        model.facts[fact] for fact in set(facts) & model.facts.keys() - {"risky_source"}
    )


def active_risk(windows: Iterable[Window], now: datetime) -> float:
    return max(
        (
            w.risk * 2 ** (-(now - w.hour).total_seconds() / 86400)
            for w in windows
            if timedelta() <= now - w.hour <= timedelta(days=7)
        ),
        default=0.0,
    )


def quadrant(risk: float, state: float, model: Model = CLOUD) -> str:
    return {
        (True, True): "act_now",
        (True, False): "investigate",
        (False, True): "harden",
        (False, False): "normal",
    }[risk >= model.thr_mid, state >= 40]


def apply_role_risk(
    windows: Mapping[WindowKey, Window],
    edges: Iterable[RoleEdge],
    model: Model = CLOUD,
    break_glass: frozenset[Identity] = frozenset(),
) -> dict[WindowKey, Window]:
    result = dict(windows)
    if "risky_source" not in model.facts:
        return result
    pending = sorted(edges, key=lambda edge: (edge.time, edge.source, edge.target))
    # Propagation only adds a fact and terminates after at most one change per window.
    changed = True
    while changed:
        changed = False
        for edge in pending:
            start = edge.time.replace(minute=0, second=0, microsecond=0)
            if not any(
                (w := result.get((edge.source, start - timedelta(hours=offset))))
                is not None
                and timedelta() <= edge.time - w.hour <= timedelta(hours=3)
                and w.risk >= model.thr_mid
                for offset in range(4)
            ):
                continue
            for hour in (start, start + timedelta(hours=1)):
                key = edge.target, hour
                target = result.get(key)
                if target and "risky_source" not in target.facts:
                    result[key] = apply_context(
                        target,
                        (*target.facts, "risky_source"),
                        model,
                        edge.target in break_glass,
                    )
                    changed = True
    return result
