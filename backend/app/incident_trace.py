"""Evidence for the scored window attached to an incident."""

import json
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.access_control import request_accounts
from app.engine.model import MODELS
from app.engine.scoring import Evidence, classify, risk_value
from app.repository import Repository


class Signal(BaseModel):
    indicator: str
    value: float
    weight: float
    contribution: float
    event_id: str | None


class EventEvidence(BaseModel):
    event_id: str
    time: datetime
    operation: str
    region: str
    category: str
    behavior: float


class IncidentTrace(BaseModel):
    hour: datetime
    model_version: str
    baseline: Evidence | None
    behavior_without_context: float
    without_context_level: Literal["low", "medium", "high"]
    context_uplift: float
    uncapped_risk: float
    medium_threshold: float
    high_threshold: float
    policy_override: str | None
    fact_weights: dict[str, float]
    signals: list[Signal]
    events: list[EventEvidence]


def router_for(repository: Repository) -> APIRouter:
    router = APIRouter()

    @router.get("/incidents/{incident_id}/trace", operation_id="getIncidentTrace")
    def trace(incident_id: str, request: Request) -> IncidentTrace:
        accounts = request_accounts(request)
        scope = json.dumps(accounts)
        with repository.connect() as connection:
            row = connection.execute(
                """
                SELECT w.data FROM windows w JOIN incidents i ON w.id=i.id WHERE i.id=?
                AND (?='[]' OR json_extract(w.data,'$.identity.account_id') IN (SELECT value FROM json_each(?)))
            """,
                (incident_id, scope, scope),
            ).fetchone()
        if not row:
            raise HTTPException(404, "Incident not found")
        item = json.loads(row["data"])
        baseline = item.get("evidence")
        base = MODELS.get(item["model_version"].split("+", 1)[0])
        if base is None:
            raise HTTPException(409, "The recorded model version is unavailable")
        weights = baseline["weights"] if baseline else base.weights
        context = baseline["fact_weights"] if baseline else base.facts
        medium = baseline["medium"] if baseline else base.thr_mid
        high = baseline["high"] if baseline else base.thr_high
        strongest = baseline["strongest_events"] if baseline else {}
        scores = item["event_scores"]
        ids = list(
            dict.fromkeys(
                [
                    *strongest.values(),
                    *sorted(scores, key=lambda key: (-scores[key], key)),
                ]
            )
        )[:16]
        evidence = repository.events_by_id(ids, accounts=accounts)
        behavior_only = risk_value(item["behavior"], 1)
        override = item.get("override") or (
            "root" if item["identity"]["kind"] == "root" else None
        )
        return IncidentTrace(
            hour=item["hour"],
            model_version=item["model_version"],
            baseline=baseline,
            behavior_without_context=behavior_only,
            context_uplift=item["risk"] - behavior_only,
            without_context_level=classify(behavior_only, medium, high, override),
            uncapped_risk=item["behavior"] * item["modifier"] * 100,
            medium_threshold=medium,
            high_threshold=high,
            policy_override=override,
            fact_weights={key: context[key] for key in item["facts"] if key in context},
            signals=sorted(
                [
                    Signal(
                        indicator=key,
                        value=value,
                        weight=weights[key],
                        contribution=weights[key] * value,
                        event_id=strongest.get(key),
                    )
                    for key, value in item["indicators"].items()
                    if key in weights
                ],
                key=lambda signal: (-signal.contribution, signal.indicator),
            ),
            events=[
                EventEvidence(
                    event_id=event["event_id"],
                    time=event["time"],
                    operation=event["name"],
                    region=event["region"],
                    category=event["category"],
                    behavior=scores[event["event_id"]],
                )
                for event in evidence
            ],
        )

    return router
