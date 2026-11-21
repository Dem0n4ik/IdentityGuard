import asyncio
import base64
import binascii
import json
import os
import sqlite3
from collections import Counter, defaultdict
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from clickhouse_connect.driver.exceptions import ClickHouseError
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import (
    access_control,
    analytics,
    assistant,
    automatic_scoring,
    cloud_views,
    incident_trace,
    local_settings,
    metrics,
    risk_controls,
    runtime_views,
    webhooks,
)
from app.devdata import CORP
from app.engine.scoring import ASSUME
from app.ingest import MAX_UPLOAD, InvalidCloudTrail, read_cloudtrail
from app.repository import (
    SIMULATION_SETTING,
    Conflict,
    ImportResult,
    Repository,
    Source,
    Status,
)

PREFIX = "/api/v1"
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
)
LOCAL_HOSTS = frozenset(("127.0.0.1", "::1", "localhost", "testserver"))
Level = Literal["low", "medium", "high"]
Verdict = Literal["true_positive", "benign_true_positive", "false_positive"]


class Principal(BaseModel):
    account_id: str
    kind: str
    name: str


class Incident(BaseModel):
    id: str
    identity: Principal
    hour: datetime
    case_id: str
    status: Status
    verdict: Verdict | None
    reason: str | None
    note: str
    detected_at: datetime
    resolved_at: datetime | None
    first_response_at: datetime | None = None
    auto_resolution: str | None
    version: int
    model_version: str
    events: int
    behavior: float
    modifier: float
    risk: float
    level: Level
    indicators: dict[str, float]
    contributions: dict[str, float]
    facts: list[str]
    explanation_uk: str
    explanation_en: str


class IncidentUpdate(BaseModel):
    status: Status
    verdict: Verdict | None = None
    reason: Annotated[str, Field(min_length=1, max_length=250)] | None = None
    note: Annotated[str, Field(max_length=4000)] = ""


class IsolationRequest(BaseModel):
    confirmation: Annotated[str, Field(min_length=1, max_length=64)]


class DryRun(BaseModel):
    id: str
    incident_id: str
    target: str
    at: datetime
    api: Literal["iam:AttachUserPolicy"]
    params: dict[str, str]
    mode: Literal["dry_run"]


class SimulationCase(BaseModel):
    title_uk: str
    title_en: str
    context_uk: str
    context_en: str


class Case(BaseModel):
    id: str
    level: Level
    risk: float
    status: Status
    updated: datetime
    identities: list[Principal]
    incidents: list[Incident]
    simulation: SimulationCase | None = None


class IdentitySummary(Principal):
    id: str
    risk: float
    exposure: float
    quadrant: Literal["act_now", "investigate", "harden", "normal"]
    facts: list[str]


class TrailEvent(BaseModel):
    event_id: str
    time: datetime
    account_id: str
    identity: Principal | None
    name: str
    region: str
    source: str
    category: str
    source_ip: str
    access_key_id: str
    session_name: str
    target: str
    user_agent: str
    mfa_used: bool | None
    error_code: str


class CaseTimelineEntry(BaseModel):
    incident_id: str
    behavior: float
    event: TrailEvent
    role_transition: bool


class CaseTimeline(BaseModel):
    total: int
    items: list[CaseTimelineEntry]


class EventsPage(BaseModel):
    engine: Literal["clickhouse", "local"]
    items: list[TrailEvent]
    next_cursor: str | None


class AuditEntry(BaseModel):
    seq: int
    at: datetime
    action: str
    target: str
    details: dict[str, Any]
    prev_hash: str
    hash: str


class AuditPage(BaseModel):
    valid: bool
    items: list[AuditEntry]


class Overview(BaseModel):
    source: Source
    cases: list[Case]
    identities: list[IdentitySummary]
    open_by_level: dict[str, int]
    timeline: dict[str, int]
    now: datetime


def incident_cases(
    items: list[Incident], simulations: Mapping[str, SimulationCase] | None = None
) -> list[Case]:
    groups: dict[str, list[Incident]] = defaultdict(list)
    for item in items:
        groups[item.case_id].append(item)
    levels = {"low": 0, "medium": 1, "high": 2}
    statuses = {"closed": 0, "new": 1, "investigating": 2, "responded": 3}
    result = []
    for key, group in groups.items():
        by_identity = {
            (
                item.identity.account_id,
                item.identity.kind,
                item.identity.name,
            ): item.identity
            for item in group
        }
        result.append(
            Case(
                id=key,
                level=max(
                    (item.level for item in group), key=lambda level: levels[level]
                ),
                risk=max(item.risk for item in group),
                status=max(
                    (item.status for item in group), key=lambda status: statuses[status]
                ),
                updated=max(item.detected_at for item in group),
                identities=list(by_identity.values()),
                incidents=group,
                simulation=(simulations or {}).get(key),
            )
        )
    return sorted(
        result,
        key=lambda item: (levels[item.level], item.updated, item.id),
        reverse=True,
    )


def make_cursor(event: TrailEvent) -> str:
    return base64.urlsafe_b64encode(
        json.dumps([event.time.isoformat(), event.event_id]).encode()
    ).decode()


def parse_cursor(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    try:
        decoded = json.loads(base64.b64decode(value, altchars=b"-_", validate=True))
        if (
            not isinstance(decoded, list)
            or len(decoded) != 2
            or not all(isinstance(item, str) for item in decoded)
            or datetime.fromisoformat(decoded[0]).tzinfo is None
        ):
            raise ValueError
        return str(decoded[0]), str(decoded[1])
    except (ValueError, UnicodeDecodeError, binascii.Error) as error:
        raise HTTPException(400, "Invalid pagination cursor") from error


def create_app(
    repository: Repository,
    static: Path | None = None,
    token: str | None = None,
    *,
    ai_key: str | None = None,
    ai_model: str | None = None,
    access_key: bytes | None = None,
    console_host: str = "",
) -> FastAPI:
    if console_host and (
        access_key is None
        or not all(
            label
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(
                character.isascii() and (character.isalnum() or character == "-")
                for character in label
            )
            for label in console_host.split(".")
        )
    ):
        raise ValueError(
            "IG_CONSOLE_HOST requires authenticated access and a valid DNS hostname"
        )
    allowed_hosts = LOCAL_HOSTS | ({console_host.lower()} if console_host else set())
    if access_key is not None and (token is not None or repository.source != "demo"):
        raise ValueError("Local user sessions require a standalone workspace")
    access = (
        access_control.AccessControl(repository, access_key)
        if access_key is not None
        else None
    )
    if (
        token is None
        and repository.source == "aws"
        or token is not None
        and len(token) < 32
    ):
        raise ValueError(
            "Use a workspace token of at least 32 characters. AWS history requires a token."
        )

    @asynccontextmanager
    async def lifecycle(_app: FastAPI) -> AsyncIterator[None]:
        if os.getenv("IG_TEMPORAL_ADDRESS"):
            yield
            return
        stop = asyncio.Event()

        async def tick() -> None:
            await asyncio.to_thread(repository.close_due, datetime.now(UTC))

        worker = asyncio.create_task(automatic_scoring.repeat(stop, tick))
        try:
            yield
        finally:
            stop.set()
            await worker

    app = FastAPI(
        title="IdentityGuard",
        version="0.1.0",
        lifespan=lifecycle,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def problem(request: Request, status: int, detail: str) -> JSONResponse:
        from http import HTTPStatus

        request_id = request.state.request_id
        return JSONResponse(
            {
                "type": "about:blank",
                "title": HTTPStatus(status).phrase,
                "status": status,
                "detail": detail,
                "instance": request.url.path,
                "request_id": request_id,
            },
            status_code=status,
            media_type="application/problem+json",
        )

    async def with_access(request: Request, call_next: Any) -> Response:
        from starlette.concurrency import run_in_threadpool

        path = request.url.path.rstrip("/")
        if path == access_control.AUTH_PATH + "/status" or path in {
            access_control.AUTH_PATH + "/login",
            access_control.AUTH_PATH + "/verify",
        }:
            return await call_next(request)  # type: ignore[no-any-return]
        if access is None:
            return problem(request, 404, "Workspace login is disabled")
        cookie = request.cookies.get(access_control.COOKIE, "")
        session = await run_in_threadpool(
            access.session, cookie, int(datetime.now(UTC).timestamp())
        )
        if session is None:
            return problem(request, 401, "Workspace login required")
        if (
            not access_control.permitted(session.role, request.method, path)
            or session.accounts
            and not access_control.scoped_route(request.method, path)
        ):
            return problem(request, 403, "Access denied")
        if request.method not in access_control.SAFE_METHODS and not compare_digest(
            request.headers.get("X-CSRF-Token", "").encode(), session.csrf.encode()
        ):
            return problem(request, 403, "Invalid CSRF token")
        request.state.access_session = session
        return await call_next(request)  # type: ignore[no-any-return]

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Response:
        request.state.request_id = uuid4().hex
        is_api = request.url.path == PREFIX or request.url.path.startswith(PREFIX + "/")
        if request.url.hostname not in allowed_hosts:
            response: Response = problem(
                request, 403, "This hostname is not configured"
            )
        elif request.url.hostname not in LOCAL_HOSTS and request.url.scheme != "https":
            response = problem(
                request, 403, "Authenticated console access requires HTTPS"
            )
        elif (
            is_api
            and request.url.path != access_control.AUTH_PATH + "/status"
            and token is not None
            and not compare_digest(
                request.headers.get("Authorization", "").encode(),
                f"Bearer {token}".encode(),
            )
        ):
            response = problem(request, 401, "Private workspace token required")
        elif request.method not in {"GET", "HEAD", "OPTIONS"} and (
            request.headers.get("Sec-Fetch-Site") == "cross-site"
            or request.headers.get("Origin")
            not in {None, str(request.base_url).rstrip("/")}
            or request.headers.get("X-IdentityGuard-Local") != "1"
        ):
            response = problem(request, 403, "A local same-origin request is required")
        elif (
            request.method not in {"GET", "HEAD", "OPTIONS"}
            and repository.source == "aws"
            and request.url.path
            not in {
                PREFIX + suffix
                for suffix in (
                    "/profile",
                    "/integrations/aws/verify",
                    "/integrations/aws/import",
                    "/cloud/refresh",
                    "/detections/backtest",
                    "/models/ahp",
                )
            }
            and not (
                request.url.path.startswith(PREFIX + "/attack-paths/")
                and request.url.path.endswith("/explain")
            )
            and not (
                request.url.path.startswith(PREFIX + "/cases/")
                and request.url.path.endswith("/analysis")
            )
        ):
            response = problem(request, 403, "The AWS history workspace is read-only")
        elif is_api and (
            access is not None
            or request.url.path.startswith(access_control.AUTH_PATH + "/")
        ):
            response = await with_access(request, call_next)
        else:
            response = await call_next(request)
        response.headers.update(
            {
                "Content-Security-Policy": CSP,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "X-Request-ID": request.state.request_id,
            }
        )
        if is_api:
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, error: HTTPException) -> JSONResponse:
        return problem(request, error.status_code, str(error.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, _error: RequestValidationError
    ) -> JSONResponse:
        return problem(request, 422, "The request did not match the API contract")

    @app.get("/healthz", operation_id="health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", operation_id="readiness")
    def readiness() -> dict[str, str]:
        try:
            with repository.connect() as connection:
                connection.execute("SELECT 1 FROM metadata LIMIT 1")
            if analytics.enabled(repository):
                client = analytics.reader()
                try:
                    client.query("SELECT event_id FROM identityguard.events LIMIT 0")
                finally:
                    client.close()
        except (sqlite3.Error, ClickHouseError, OSError, KeyError):
            raise HTTPException(503, "An event store is not ready") from None
        return {"status": "ready"}

    def list_incidents(accounts: list[str]) -> list[Incident]:
        return [
            Incident.model_validate({**row, "case_id": row["id"]} if accounts else row)
            for row in repository.incidents(accounts=accounts)
        ]

    @app.get(PREFIX + "/overview", operation_id="getOverview")
    def overview(request: Request) -> Overview:
        now = datetime.now(UTC)
        accounts = access_control.request_accounts(request)
        items = list_incidents(accounts)
        exercise = (
            repository.read_setting(SIMULATION_SETTING)
            if repository.source == "demo" and not accounts
            else None
        ) or {}
        cases = incident_cases(
            items,
            {
                key: SimulationCase.model_validate(label)
                for key, label in exercise.get("cases", {}).items()
            },
        )
        timeline = {
            (now - timedelta(days=day)).date().isoformat(): 0
            for day in reversed(range(7))
        }
        for item in items:
            day = item.hour.date().isoformat()
            if day in timeline:
                timeline[day] += 1
        return Overview(
            source=repository.source,
            cases=cases,
            identities=[
                IdentitySummary.model_validate(row)
                for row in repository.identities(now, accounts=accounts)
            ],
            open_by_level=dict(
                Counter(item.level for item in cases if item.status != "closed")
            ),
            timeline=timeline,
            now=now,
        )

    @app.get(PREFIX + "/cases/{case_id}/timeline", operation_id="getCaseTimeline")
    def case_timeline(case_id: str, request: Request) -> CaseTimeline:
        accounts = json.dumps(access_control.request_accounts(request))
        with repository.connect() as connection:
            if not connection.execute(
                """SELECT 1 FROM incidents i JOIN windows w ON w.id=i.id
                   WHERE (CASE WHEN ?='[]' THEN i.case_id ELSE i.id END)=? AND (?='[]' OR
                       json_extract(w.data, '$.identity.account_id') IN (SELECT value FROM json_each(?))) LIMIT 1""",
                (accounts, case_id, accounts, accounts),
            ).fetchone():
                raise HTTPException(404, "Case not found")
            role_operations = json.dumps(sorted(ASSUME))
            rows = connection.execute(
                """
                SELECT i.id AS incident_id, CAST(score.value AS REAL) AS behavior,
                    e.data, e.time, e.id, count(*) OVER () AS total,
                    json_extract(e.data, '$.name') IN (SELECT value FROM json_each(?))
                    AND json_extract(e.data, '$.error_code') = ''
                    AND json_extract(e.data, '$.target') LIKE 'arn:%:iam::%:role/%'
                    AS role_transition
                FROM incidents i JOIN windows w ON w.id=i.id
                    JOIN json_each(w.data, '$.event_scores') score
                    JOIN events e ON e.id=score.key
                WHERE (CASE WHEN ?='[]' THEN i.case_id ELSE i.id END)=? AND (?='[]' OR (
                    json_extract(w.data, '$.identity.account_id') IN (SELECT value FROM json_each(?))
                    AND json_extract(e.data, '$.account_id') IN (SELECT value FROM json_each(?))
                    AND json_extract(e.data, '$.identity.account_id') IN (SELECT value FROM json_each(?))
                ))
                ORDER BY role_transition DESC, behavior DESC, e.time, e.id
                LIMIT 200
                """,
                (
                    role_operations,
                    accounts,
                    case_id,
                    accounts,
                    accounts,
                    accounts,
                    accounts,
                ),
            ).fetchall()
        return CaseTimeline(
            total=rows[0]["total"] if rows else 0,
            items=[
                CaseTimelineEntry(
                    incident_id=row["incident_id"],
                    behavior=row["behavior"],
                    role_transition=bool(row["role_transition"]),
                    event=TrailEvent.model_validate(
                        repository.public_event(row["data"])
                    ),
                )
                for row in sorted(rows, key=lambda row: (row["time"], row["id"]))
            ],
        )

    @app.get(PREFIX + "/incidents", operation_id="listIncidents")
    def incidents(request: Request) -> list[Incident]:
        return list_incidents(access_control.request_accounts(request))

    @app.patch(PREFIX + "/incidents/{incident_id}", operation_id="updateIncident")
    def patch_incident(
        incident_id: str,
        body: IncidentUpdate,
        response: Response,
        request: Request,
        if_match: Annotated[str, Header()],
    ) -> Incident:
        if (
            not if_match.startswith('"')
            or not if_match.endswith('"')
            or not if_match[1:-1].isdigit()
        ):
            raise HTTPException(
                400, "If-Match must contain the quoted incident version"
            )
        try:
            row = repository.patch_incident(
                incident_id,
                int(if_match[1:-1]),
                body.status,
                body.verdict,
                body.reason.strip() if body.reason else None,
                body.note,
                datetime.now(UTC),
                accounts=access_control.request_accounts(request),
            )
        except Conflict as error:
            raise HTTPException(412, str(error)) from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        except KeyError as error:
            raise HTTPException(404, "Incident not found") from error
        response.headers["ETag"] = f'"{row["version"]}"'
        if access_control.request_accounts(request):
            row["case_id"] = row["id"]
        return Incident.model_validate(row)

    @app.post(
        PREFIX + "/incidents/{incident_id}/isolation", operation_id="isolateUserDryRun"
    )
    def isolate_user(
        incident_id: str,
        body: IsolationRequest,
        idempotency_key: Annotated[UUID, Header()],
    ) -> DryRun:
        try:
            result = repository.isolate_user_dry_run(
                incident_id,
                body.confirmation,
                str(idempotency_key),
                datetime.now(UTC),
            )
        except KeyError as error:
            raise HTTPException(404, "Incident not found") from error
        except Conflict as error:
            raise HTTPException(409, str(error)) from error
        except ValueError as error:
            raise HTTPException(422, str(error)) from error
        return DryRun.model_validate(result)

    @app.get(PREFIX + "/events", operation_id="listEvents")
    def events(
        request: Request,
        identity: Annotated[str, Query(max_length=350)] = "",
        operation: Annotated[str, Query(max_length=128)] = "",
        account: Annotated[str, Query(max_length=12)] = "",
        cursor: Annotated[str, Query(max_length=1024)] = "",
        region: Annotated[str, Query(max_length=50)] = "",
        category: Annotated[str, Query(max_length=30)] = "",
        since: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> EventsPage:
        if since is not None and since.tzinfo is None:
            raise HTTPException(400, "The event range must include a timezone")
        accounts = tuple(access_control.request_accounts(request))
        search = analytics.Search(
            identity=identity,
            allowed_accounts=accounts,
            operation=operation,
            account=account,
            region=region,
            category=category,
            before=parse_cursor(cursor),
            since=since.astimezone(UTC) if since else None,
            limit=limit + 1,
        )
        engine: Literal["clickhouse", "local"] = "local"
        if analytics.enabled(repository):
            engine = "clickhouse"
            try:
                rows = analytics.search_index(repository, search)
            except (ClickHouseError, OSError, KeyError):
                raise HTTPException(
                    503,
                    "The ClickHouse search index is unavailable. Retry after the service recovers.",
                ) from None
        else:
            rows = repository.event_page(
                identity=search.identity,
                operation=search.operation,
                account=search.account,
                allowed_accounts=search.allowed_accounts,
                region=search.region,
                category=search.category,
                before=search.before,
                since=search.since,
                limit=search.limit,
            )
        page = [TrailEvent.model_validate(row) for row in rows[:limit]]
        return EventsPage(
            engine=engine,
            items=page,
            next_cursor=make_cursor(page[-1]) if len(rows) > limit else None,
        )

    @app.post(
        PREFIX + "/sources/upload",
        operation_id="uploadCloudTrail",
        response_model=ImportResult,
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/octet-stream": {
                        "schema": {"type": "string", "format": "binary"}
                    },
                },
            }
        },
    )
    async def upload(request: Request) -> ImportResult:
        from starlette.concurrency import run_in_threadpool

        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_UPLOAD:
                raise HTTPException(413, "CloudTrail upload exceeds 20 MiB")
            body.extend(chunk)
        try:
            result: ImportResult = await run_in_threadpool(
                lambda: repository.ingest(
                    read_cloudtrail(bytes(body)), datetime.now(UTC)
                ),
            )
        except InvalidCloudTrail as error:
            raise HTTPException(422, str(error)) from error
        return result

    @app.get(PREFIX + "/audit", operation_id="listAudit")
    def audit() -> AuditPage:
        valid, rows = repository.audit_entries()
        return AuditPage(
            valid=valid, items=[AuditEntry.model_validate(row) for row in rows]
        )

    app.include_router(local_settings.router_for(repository), prefix=PREFIX)
    app.include_router(risk_controls.router_for(repository), prefix=PREFIX)
    app.include_router(incident_trace.router_for(repository), prefix=PREFIX)
    app.include_router(access_control.router_for(access), prefix=PREFIX)
    app.include_router(metrics.router_for(repository), prefix=PREFIX)
    app.include_router(
        cloud_views.router_for(repository, ai_key, ai_model), prefix=PREFIX
    )
    app.include_router(
        assistant.router_for(repository, ai_key, ai_model), prefix=PREFIX
    )

    app.include_router(runtime_views.router_for(repository), prefix=PREFIX)
    app.include_router(
        webhooks.router_for(repository, os.getenv("IG_WEBHOOK_SECRET")), prefix=PREFIX
    )

    if static is not None and (static / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=static / "assets"), name="assets")

        @app.get("/{spa_path:path}", include_in_schema=False)
        def frontend(spa_path: str) -> FileResponse:
            if spa_path.startswith(("api/", "assets/")):
                raise HTTPException(404, "Route not found")
            return FileResponse(static / "index.html")

    return app


def from_env() -> FastAPI:
    access_key = (
        access_control.key_from_environment()
        if os.getenv("IG_ACCESS_KEY") or os.getenv("IG_REQUIRE_ACCESS") == "1"
        else None
    )
    source: Source = "aws" if os.getenv("IG_SOURCE") == "aws" else "demo"
    path = Path(os.getenv("IG_DATABASE", "data/demo.sqlite"))
    if source == "aws":
        if (
            "IG_DATABASE" not in os.environ
            or not path.is_absolute()
            or path.resolve().is_relative_to(Path.cwd())
        ):
            raise ValueError(
                "Use an absolute private database path outside the Git workspace"
            )
        repository = Repository(path, source=source)
    else:
        repository = Repository(path, trusted=CORP)
    return create_app(
        repository,
        Path("frontend/dist"),
        os.getenv("IG_WORKSPACE_TOKEN") or None,
        ai_key=os.getenv("ANTHROPIC_API_KEY"),
        ai_model=os.getenv("IG_AI_MODEL"),
        access_key=access_key,
        console_host=os.getenv("IG_CONSOLE_HOST", ""),
    )
