"""SLA and model quality from recorded incident outcomes."""

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

import numpy as np
from fastapi import APIRouter, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.repository import Repository

Hours = Annotated[float, Field(gt=0, le=720)]


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    response: Hours
    resolution: Hours

    @model_validator(mode="after")
    def ordered(self) -> "Target":
        if self.response > self.resolution:
            raise ValueError("Resolution time must be at least response time")
        return self


class SLATargets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    high: Target = Field(default_factory=lambda: Target(response=1, resolution=24))
    medium: Target = Field(default_factory=lambda: Target(response=8, resolution=72))


class SLASettings(SLATargets):
    accounts: dict[Annotated[str, Field(pattern=r"^[0-9]{12}$")], SLATargets] = Field(
        default_factory=dict, max_length=200
    )


class Breach(BaseModel):
    case_id: str
    account: str
    level: str
    response_late: bool
    resolution_late: bool


class SLAReport(BaseModel):
    open_cases: int
    awaiting_response: int
    overdue_resolution: int
    mtta_median_hours: float | None
    mtta_p90_hours: float | None
    mttr_median_hours: float | None
    mttr_p90_hours: float | None
    within_resolution_target: float | None
    severity: dict[str, int]
    overdue: list[Breach]


class Week(BaseModel):
    starts: str
    labeled: int
    true_positives: int
    precision: float


class ThresholdPoint(BaseModel):
    threshold: int
    precision: float
    f1: float
    predicted: int


class Quality(BaseModel):
    by_week: list[Week]
    incidents_by_day: dict[str, int]
    mtta_hours: float | None
    false_positive_indicators: dict[str, float]
    false_positive_facts: dict[str, int]
    benign_reasons: dict[str, int]
    curve: list[ThresholdPoint]
    recommended: ThresholdPoint | None


def elapsed(start: datetime, end: datetime) -> float:
    return max(0.0, (end - start).total_seconds() / 3600)


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def sla_report(
    rows: list[dict[str, Any]], settings: SLASettings, now: datetime
) -> SLAReport:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["case_id"]].append(row)
    responses: list[float] = []
    resolutions: list[float] = []
    open_cases = within = no_response = overdue_resolution = 0
    overdue = []
    severity: Counter[str] = Counter()
    for case_id, items in groups.items():
        is_open = any(row["status"] != "closed" for row in items)
        open_cases += int(is_open)
        strongest = min(
            items,
            key=lambda row: (row["level"] != "high", row["detected_at"], row["id"]),
        )
        level = "high" if strongest["level"] == "high" else "medium"
        account = strongest["identity"]["account_id"]
        selected = settings.accounts.get(account, settings)
        target = selected.high if level == "high" else selected.medium
        severity[level] += 1
        start = min(timestamp(row["detected_at"]) for row in items)
        answered = min(
            (
                timestamp(row["first_response_at"])
                for row in items
                if row.get("first_response_at")
            ),
            default=None,
        )
        if answered:
            responses.append(elapsed(start, answered))
        if not is_open and all(row["verdict"] and row["resolved_at"] for row in items):
            resolved = max(timestamp(row["resolved_at"]) for row in items)
            duration = elapsed(start, resolved)
            resolutions.append(duration)
            within += int(duration <= target.resolution)
        response_late = (
            is_open and answered is None and elapsed(start, now) > target.response
        )
        resolution_late = is_open and elapsed(start, now) > target.resolution
        no_response += int(response_late)
        overdue_resolution += int(resolution_late)
        if response_late or resolution_late:
            overdue.append(
                Breach(
                    case_id=case_id,
                    account=account,
                    level=level,
                    response_late=response_late,
                    resolution_late=resolution_late,
                )
            )
    return SLAReport(
        open_cases=open_cases,
        awaiting_response=no_response,
        overdue_resolution=overdue_resolution,
        mtta_median_hours=float(np.median(responses)) if responses else None,
        mtta_p90_hours=float(np.percentile(responses, 90)) if responses else None,
        mttr_median_hours=float(np.median(resolutions)) if resolutions else None,
        mttr_p90_hours=float(np.percentile(resolutions, 90)) if resolutions else None,
        within_resolution_target=within / len(resolutions) if resolutions else None,
        severity=dict(severity),
        overdue=overdue,
    )


def quality_report(rows: list[dict[str, Any]], sla: SLAReport) -> Quality:
    buckets: dict[str, list[bool]] = defaultdict(list)
    per_day: Counter[str] = Counter()
    indicators: dict[str, float] = defaultdict(float)
    facts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    labeled: list[tuple[float, bool]] = []
    for row in rows:
        per_day[row["detected_at"][:10]] += 1
        if row["status"] != "closed" or not row["verdict"] or not row["resolved_at"]:
            continue
        resolved = timestamp(row["resolved_at"])
        label = row["verdict"] == "true_positive"
        key = (
            resolved.date()
            .fromordinal(resolved.date().toordinal() - resolved.weekday())
            .isoformat()
        )
        buckets[key].append(label)
        labeled.append((row["risk"], label))
        if row["verdict"] == "false_positive":
            for indicator, amount in row["contributions"].items():
                indicators[indicator] += amount
            facts.update(row["facts"])
        if row["verdict"] == "benign_true_positive" and row["reason"]:
            reasons[row["reason"]] += 1
    curve = []
    if labeled:
        positives = sum(label for _, label in labeled)
        for threshold in range(20, 81):
            selected = [label for risk, label in labeled if risk >= threshold]
            tp = sum(selected)
            curve.append(
                ThresholdPoint(
                    threshold=threshold,
                    precision=tp / len(selected) if selected else 0.0,
                    f1=2 * tp / (len(selected) + positives)
                    if len(selected) + positives
                    else 0.0,
                    predicted=len(selected),
                )
            )
    return Quality(
        by_week=[
            Week(
                starts=week,
                labeled=len(items),
                true_positives=sum(items),
                precision=sum(items) / len(items),
            )
            for week, items in sorted(buckets.items())
        ],
        incidents_by_day=dict(sorted(per_day.items())),
        mtta_hours=sla.mtta_median_hours,
        false_positive_indicators=dict(indicators),
        false_positive_facts=dict(facts),
        benign_reasons=dict(reasons),
        curve=curve,
        recommended=max(
            (point for point in curve if point.precision >= 0.9),
            key=lambda point: (point.f1, -point.threshold),
            default=None,
        ),
    )


def router_for(repository: Repository) -> APIRouter:
    router = APIRouter()

    @router.get("/sla/settings", operation_id="getSlaSettings")
    def settings() -> SLASettings:
        return SLASettings.model_validate(repository.read_setting("sla") or {})

    @router.put("/sla/settings", operation_id="saveSlaSettings")
    def save(body: SLASettings) -> SLASettings:
        repository.save_setting("sla", body.model_dump(mode="json"), "sla.updated")
        return body

    @router.get("/sla", operation_id="getSlaReport")
    def sla(
        account: Annotated[str | None, Query(pattern=r"^[0-9]{12}$")] = None,
        range_days: Annotated[Literal["7", "30", "all"], Query(alias="range")] = "all",
    ) -> SLAReport:
        now = datetime.now(UTC)
        since = now - timedelta(days=int(range_days)) if range_days != "all" else None
        rows = repository.incidents(since, accounts=(account,) if account else ())
        return sla_report(rows, settings(), now)

    @router.get("/quality", operation_id="getRiskQuality")
    def quality() -> Quality:
        rows = repository.incidents()
        return quality_report(rows, sla_report(rows, settings(), datetime.now(UTC)))

    return router
