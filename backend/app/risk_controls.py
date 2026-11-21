"""Local detection lifecycle, retrospective scoring, suppressions and AHP drafts."""

import os
from datetime import UTC, datetime, timedelta
from math import log
from typing import Annotated, Any, Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engine.adjustments import ExceptionInput, ExceptionRecord
from app.engine.detections import Category, InvalidRule, Rule, event_context, parse_rule
from app.engine.model import (
    CLOUD_MATRIX,
    CORE_MATRIX,
    MODELS,
    Model,
    calculate_ahp,
    normalized,
)
from app.engine.scoring import Window, WindowKey
from app.repository import Repository, identity_id

RuleStatus = Literal["draft", "enabled", "disabled"]
ProfileName = Literal["core-v1", "cloud-v2"]
Matrix = list[list[float]]
SAATY = {
    1.0,
    *(float(value) for value in range(2, 10)),
    *(1 / value for value in range(2, 10)),
}
PROFILE_NAMES: tuple[ProfileName, ...] = ("core-v1", "cloud-v2")
MATRICES = {"core-v1": CORE_MATRIX, "cloud-v2": CLOUD_MATRIX}


class RuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: Annotated[str, Field(min_length=1, max_length=32_768)]
    status: RuleStatus = "draft"


class RuleRevision(RuleInput):
    id: str
    name: str
    category: Category
    revision: int
    created_at: datetime


class BacktestInput(BaseModel):
    yaml: Annotated[str, Field(min_length=1, max_length=32_768)]
    days: Annotated[int, Field(ge=1, le=30)] = 7


class WindowChange(BaseModel):
    identity_id: str
    hour: datetime
    before: str
    after: str
    risk_before: float
    risk_after: float


class Comparison(BaseModel):
    evaluated: int
    changed: int
    new_incidents: int
    new_by_day: dict[str, int]
    examples: list[WindowChange]


class RuleMatch(BaseModel):
    event_id: str
    operation: str
    region: str
    time: datetime


class Backtest(Comparison):
    matches: int
    examples_events: list[RuleMatch]


class Toggle(BaseModel):
    enabled: bool


class MatrixInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: ProfileName
    matrix: Matrix = Field(min_length=8, max_length=10)


class DraftInput(MatrixInput):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, Field(min_length=3, max_length=100)]
    thr_mid: Annotated[float, Field(gt=0, lt=100)] = 25
    thr_high: Annotated[float, Field(gt=0, le=100)] = 50

    @model_validator(mode="after")
    def ordered(self) -> "DraftInput":
        if self.thr_mid >= self.thr_high:
            raise ValueError(
                "The medium threshold must be lower than the high threshold"
            )
        return self


class AHPReport(BaseModel):
    weights: dict[str, float]
    eigenvalue: float
    ci: float
    cr: float
    consistent: bool
    inconsistent_pairs: list[tuple[int, int]]


class Baseline(BaseModel):
    profile: ProfileName
    matrix: Matrix
    weights: dict[str, float]
    fact_weights: dict[str, float]
    thr_mid: float
    thr_high: float


class Version(DraftInput):
    id: str
    created_at: datetime
    report: AHPReport
    rule_versions: list[str]
    shadow: Comparison | None = None


class ShadowInput(BaseModel):
    days: Annotated[int, Field(ge=1, le=30)] = 7


def parse(source: str) -> Rule:
    try:
        return parse_rule(source)
    except InvalidRule as error:
        raise HTTPException(422, str(error)) from None


def compare(
    baseline: dict[WindowKey, Window],
    candidate: dict[WindowKey, Window],
    since: datetime,
) -> Comparison:
    changes = []
    evaluated = 0
    by_day: dict[str, int] = {}
    for key, window in candidate.items():
        if window.hour < since or key not in baseline:
            continue
        evaluated += 1
        previous = baseline[key]
        if previous.level == window.level:
            continue
        changes.append(
            WindowChange(
                identity_id=identity_id(window.identity),
                hour=window.hour,
                before=previous.level,
                after=window.level,
                risk_before=previous.risk,
                risk_after=window.risk,
            )
        )
        if previous.level == "low" and window.level != "low":
            day = window.hour.date().isoformat()
            by_day[day] = by_day.get(day, 0) + 1
    return Comparison(
        evaluated=evaluated,
        changed=len(changes),
        new_incidents=sum(by_day.values()),
        new_by_day=by_day,
        examples=sorted(changes, key=lambda row: row.hour, reverse=True)[:30],
    )


def analyze(body: MatrixInput) -> AHPReport:
    keys = tuple(MODELS[body.profile].weights)
    size = len(keys)
    if len(body.matrix) != size or any(len(row) != size for row in body.matrix):
        raise HTTPException(422, "The matrix must match the selected baseline")
    if any(value not in SAATY for row in body.matrix for value in row):
        raise HTTPException(422, "Use the values in Saaty's comparison scale")
    try:
        result = calculate_ahp(tuple(tuple(row) for row in body.matrix))
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    pairs = sorted(
        ((left, right) for left in range(size) for right in range(left + 1, size)),
        key=lambda pair: abs(
            log(
                body.matrix[pair[0]][pair[1]]
                * result.weights[pair[1]]
                / result.weights[pair[0]]
            )
        ),
        reverse=True,
    )
    return AHPReport(
        weights=dict(zip(keys, result.weights, strict=True)),
        eigenvalue=result.eigenvalue,
        ci=result.consistency_index,
        cr=result.consistency_ratio,
        consistent=result.consistency_ratio < 0.1,
        inconsistent_pairs=pairs[:3],
    )


def router_for(repository: Repository) -> APIRouter:
    router = APIRouter()

    @router.get("/detections", operation_id="listDetectionRevisions")
    def detections() -> list[RuleRevision]:
        return [
            RuleRevision.model_validate(item)
            for item in (repository.read_setting("detections") or {}).get("items", [])
        ][::-1]

    @router.post("/detections", operation_id="saveDetectionRevision")
    def save_rule(body: RuleInput) -> RuleRevision:
        rule = parse(body.yaml)
        definition = rule.definition

        def append(state: dict[str, Any]) -> dict[str, Any]:
            items = state.get("items", [])
            if len(items) >= 250:
                raise HTTPException(409, "The local revision store reached its limit")
            revision = 1 + max(
                (row["revision"] for row in items if row["id"] == definition.id),
                default=0,
            )
            record = RuleRevision(
                **body.model_dump(),
                id=definition.id,
                name=definition.name,
                category=definition.category,
                revision=revision,
                created_at=datetime.now(UTC),
            )
            return {"items": [*items, record.model_dump(mode="json")]}

        result = repository.change_setting(
            "detections", append, "detection.revised", rescore=body.status != "draft"
        )
        return RuleRevision.model_validate(result["items"][-1])

    @router.post("/detections/backtest", operation_id="backtestDetection")
    def backtest(body: BacktestInput) -> Backtest:
        candidate = parse(body.yaml)
        now = datetime.now(UTC)
        since = now - timedelta(days=body.days)
        with repository.connect() as connection:
            connection.execute("BEGIN")
            events, active, _ = repository.score_data(connection, now)
            _, proposed, _ = repository.score_data(
                connection, now, proposed_rule=candidate
            )
        matched = sorted(
            (
                event
                for event in events
                if since <= event.time <= now
                and candidate.matches(event_context(event))
            ),
            key=lambda event: (event.time, event.event_id),
            reverse=True,
        )
        comparison = compare(active, proposed, since)
        return Backtest(
            **comparison.model_dump(),
            matches=len(matched),
            examples_events=[
                RuleMatch(
                    event_id=e.event_id, operation=e.name, region=e.region, time=e.time
                )
                for e in matched[:15]
            ],
        )

    @router.get("/suppressions", operation_id="listSuppressions")
    def suppressions() -> list[ExceptionRecord]:
        return [
            ExceptionRecord.model_validate(item)
            for item in (repository.read_setting("suppressions") or {}).get("items", [])
        ][::-1]

    @router.post("/suppressions", operation_id="saveSuppression")
    def save_suppression(body: ExceptionInput) -> ExceptionRecord:
        if not any(
            f"{item['identity']['account_id']}:{item['identity']['kind']}:{item['identity']['name']}"
            == body.identity_id
            for item in repository.incidents(case_id=body.case_id)
        ):
            raise HTTPException(422, "The identity must belong to the source case")
        now = datetime.now(UTC)
        record = ExceptionRecord(
            **body.model_dump(),
            id=uuid4().hex,
            created_at=now,
            expires_at=now + timedelta(days=body.days),
        )

        def append(state: dict[str, Any]) -> dict[str, Any]:
            items = state.get("items", [])
            if len(items) >= 250:
                raise HTTPException(
                    409, "The local suppression store reached its limit"
                )
            return {"items": [*items, record.model_dump(mode="json")]}

        result = repository.change_setting(
            "suppressions", append, "suppression.created", rescore=True
        )
        return ExceptionRecord.model_validate(result["items"][-1])

    @router.patch("/suppressions/{item_id}", operation_id="toggleSuppression")
    def toggle(item_id: str, body: Toggle) -> ExceptionRecord:
        def update(state: dict[str, Any]) -> dict[str, Any]:
            item = next(
                (row for row in state.get("items", []) if row["id"] == item_id), None
            )
            if item is None:
                raise HTTPException(404, "Suppression not found")
            item["enabled"] = body.enabled
            return state

        result = repository.change_setting(
            "suppressions", update, "suppression.updated", rescore=True
        )
        return ExceptionRecord.model_validate(
            next(row for row in result["items"] if row["id"] == item_id)
        )

    @router.post("/suppressions/rescore", operation_id="rescoreSuppressions")
    async def rescore() -> dict[str, bool]:
        from starlette.concurrency import run_in_threadpool
        from temporalio.client import Client, WorkflowFailureError
        from temporalio.service import RPCError

        from app.workflows import TASK_QUEUE, Rescore

        address = os.getenv("IG_TEMPORAL_ADDRESS")
        if address:
            try:
                client = await Client.connect(address)
                await client.execute_workflow(
                    Rescore.run,
                    id=f"rescore-{uuid4().hex}",
                    task_queue=TASK_QUEUE,
                    execution_timeout=timedelta(minutes=3),
                )
            except (RuntimeError, OSError, WorkflowFailureError, RPCError):
                raise HTTPException(
                    502, "Temporal could not complete the rescore"
                ) from None
        else:
            await run_in_threadpool(repository.rescore)
        return {"rescored": True}

    @router.get("/models/baselines", operation_id="listModelBaselines")
    def baselines() -> list[Baseline]:
        return [
            Baseline(
                profile=key,
                matrix=[list(row) for row in MATRICES[key]],
                weights=dict(MODELS[key].weights),
                fact_weights=dict(MODELS[key].facts),
                thr_mid=MODELS[key].thr_mid,
                thr_high=MODELS[key].thr_high,
            )
            for key in PROFILE_NAMES
        ]

    @router.post("/models/ahp", operation_id="analyzeAhp")
    def ahp(body: MatrixInput) -> AHPReport:
        return analyze(body)

    @router.get("/models/drafts", operation_id="listModelDrafts")
    def drafts() -> list[Version]:
        return [
            Version.model_validate(row["version"])
            for row in (repository.read_setting("models") or {}).get("items", [])
        ][::-1]

    @router.post("/models/drafts", operation_id="saveModelDraft")
    def save_draft(body: DraftInput) -> Version:
        report = analyze(body)
        if not report.consistent:
            raise HTTPException(422, "AHP consistency ratio must be below 0.1")
        with repository.connect() as connection:
            rules = repository.active_rule_config(connection)
        version = Version(
            **body.model_dump(),
            id=uuid4().hex,
            created_at=datetime.now(UTC),
            report=report,
            rule_versions=[f"{item['id']}@{item['revision']}" for item in rules],
        )

        def append(state: dict[str, Any]) -> dict[str, Any]:
            items = state.get("items", [])
            if len(items) >= 100:
                raise HTTPException(
                    409, "The local model draft store reached its limit"
                )
            return {
                "items": [
                    *items,
                    {"version": version.model_dump(mode="json"), "rules": rules},
                ]
            }

        repository.change_setting("models", append, "model.drafted")
        return version

    @router.post("/models/drafts/{model_id}/shadow", operation_id="runModelShadow")
    def run_shadow(model_id: str, body: ShadowInput) -> Version:
        state = repository.read_setting("models") or {}
        row = next(
            (
                item
                for item in state.get("items", [])
                if item["version"]["id"] == model_id
            ),
            None,
        )
        if row is None:
            raise HTTPException(404, "Model draft not found")
        version = Version.model_validate(row["version"])
        base = MODELS[version.profile]
        keys = tuple(base.weights)
        model = Model(
            version.id,
            normalized(keys, tuple(version.report.weights[key] for key in keys)),
            base.facts,
            base.priv,
            base.evasion,
            base.secret,
            version.thr_mid,
            version.thr_high,
        )
        now = datetime.now(UTC)
        with repository.connect() as connection:
            connection.execute("BEGIN")
            _, baseline, _ = repository.score_data(connection, now)
            _, proposal, _ = repository.score_data(
                connection, now, model=model, rule_config=row["rules"]
            )
        report = compare(baseline, proposal, now - timedelta(days=body.days))

        def attach(state: dict[str, Any]) -> dict[str, Any]:
            current = next(
                item for item in state["items"] if item["version"]["id"] == model_id
            )
            current["version"]["shadow"] = report.model_dump(mode="json")
            return state

        repository.change_setting("models", attach, "model.shadow.evaluated")
        return version.model_copy(update={"shadow": report})

    return router
