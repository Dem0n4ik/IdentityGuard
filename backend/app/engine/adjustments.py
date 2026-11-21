"""Rule contributions and event-level suppressions before hourly aggregation."""

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Literal

import polars as pl
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engine.detections import Rule, cidr_test, event_context
from app.engine.events import Event, source_prefix
from app.engine.model import Model

Indicator = Literal[
    "geo", "ip", "time", "seq", "vol", "priv", "secret", "dormant", "wexfil"
]
Match = Literal["region", "ip_prefix", "cidr", "event_name", "user_agent_prefix"]


class ExceptionInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    identity_id: Annotated[str, Field(min_length=5, max_length=350)]
    indicator: Indicator
    field: Match
    value: Annotated[str, Field(min_length=1, max_length=250)]
    reason: Annotated[str, Field(min_length=10, max_length=1000)]
    days: Annotated[int, Field(ge=1, le=90)]
    case_id: Annotated[str, Field(min_length=1, max_length=350)]

    @model_validator(mode="after")
    def valid_condition(self) -> "ExceptionInput":
        if self.field == "cidr":
            from ipaddress import ip_network

            ip_network(self.value, strict=False)
        return self


class ExceptionRecord(ExceptionInput):
    id: str
    created_at: datetime
    expires_at: datetime
    enabled: bool = True
    hits: int = 0


def matches(item: ExceptionRecord, event: Event) -> bool:
    if item.field == "cidr":
        return cidr_test(event.source_ip, item.value)
    if item.field == "user_agent_prefix":
        return event.user_agent.startswith(item.value)
    return {
        "region": event.region,
        "ip_prefix": source_prefix(event.source_ip),
        "event_name": event.name,
    }[item.field] == item.value


class Adjustments:
    def __init__(
        self,
        rules: Iterable[Rule],
        exceptions: Iterable[ExceptionRecord],
        now: datetime,
    ) -> None:
        self.rules = tuple(rules)
        self.exceptions: dict[str, list[ExceptionRecord]] = defaultdict(list)
        for item in exceptions:
            if item.enabled and now < item.expires_at:
                self.exceptions[item.identity_id].append(item)
        self.hits: dict[str, set[str]] = defaultdict(set)

    def __call__(
        self, events: list[Event], frame: pl.DataFrame, model: Model
    ) -> pl.DataFrame:
        identity = events[0].identity
        key = (
            f"{identity.account_id}:{identity.kind}:{identity.name}" if identity else ""
        )
        exceptions = self.exceptions.get(key, ())
        if not self.rules and not exceptions:
            return frame
        changes: dict[str, list[float]] = {}

        def column(name: str) -> list[float]:
            if name not in changes:
                changes[name] = frame[name].to_list()
            return changes[name]

        for index, event in enumerate(events):
            if self.rules:
                context = event_context(event)
                for rule in self.rules:
                    definition = rule.definition
                    if rule.matches(context):
                        values = column(definition.category)
                        values[index] = max(values[index], definition.value)
            suppressed: set[str] = set()
            for item in exceptions:
                if (
                    item.indicator in model.weights
                    and matches(item, event)
                    and column(item.indicator)[index] > 0
                ):
                    self.hits[item.id].add(event.event_id)
                    suppressed.add(item.indicator)
            for name in suppressed:
                column(name)[index] = 0.0
        return frame.with_columns(
            *(pl.Series(name, values) for name, values in changes.items())
        )
