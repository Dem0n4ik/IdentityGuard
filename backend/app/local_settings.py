"""Local workspace profile and AWS integration."""

import os
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated, Literal

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.aws_history import AccountMismatch, lookup, verified_session
from app.aws_inventory import read_inventory
from app.ingest import InvalidCloudTrail
from app.repository import Conflict, ImportResult, Repository

Language = Literal["uk", "en"]


class Profile(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: Annotated[str, Field(max_length=100)] = ""
    email: Annotated[
        str, Field(max_length=254, pattern=r"^(|[^\s@]+@[^\s@]+\.[^\s@]+)$")
    ] = ""
    position: Annotated[str, Field(max_length=100)] = ""
    language: Language = "uk"
    theme: Literal["dark", "light"] = "dark"
    compact: bool = False
    local_time: bool = False


class AwsSettings(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    account_id: Annotated[str, Field(pattern=r"^[0-9]{12}$")]
    region: Annotated[
        str, Field(pattern=r"^[a-z]{2}(?:-[a-z]+)+-[0-9]$", max_length=30)
    ]
    credential_source: Literal["profile", "environment"] = "profile"
    profile: Annotated[
        str, Field(max_length=100, pattern=r"^[a-zA-Z0-9_.@+=,: -]*$")
    ] = ""


class AwsImport(AwsSettings):
    days: Annotated[int, Field(ge=1, le=90)] = 21
    include_iam: bool = True


class ImportSummary(BaseModel):
    imported_at: datetime
    settings: AwsSettings
    cloudtrail: ImportResult
    iam: Literal["imported", "skipped", "unavailable"]
    iam_identities: int


class AwsWorkspace(BaseModel):
    enabled: bool
    account_id: str | None
    available_profiles: list[str]
    environment_credentials: bool
    last_import: ImportSummary | None


def configured_environment() -> bool:
    return bool(
        (os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))
        or (os.getenv("AWS_WEB_IDENTITY_TOKEN_FILE") and os.getenv("AWS_ROLE_ARN"))
    )


def configured_profiles() -> list[str]:
    try:
        return sorted(boto3.Session().available_profiles)
    except BotoCoreError:
        return []


def aws_error(error: Exception) -> HTTPException:
    if isinstance(error, AccountMismatch):
        return HTTPException(
            422, "The verified AWS account or principal does not match"
        )
    if isinstance(error, InvalidCloudTrail):
        return HTTPException(422, "AWS returned an unsupported CloudTrail record")
    if isinstance(error, ValueError):
        return HTTPException(
            422, "Reduce the requested history range or check the AWS settings"
        )
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            return HTTPException(
                403,
                "The AWS principal lacks permission for the selected read operation",
            )
        if code in {
            "ExpiredToken",
            "ExpiredTokenException",
            "InvalidClientTokenId",
            "UnrecognizedClientException",
        }:
            return HTTPException(422, "The AWS session is expired or invalid")
    return HTTPException(
        502,
        "Could not read AWS. Check the local credential profile and AWS connectivity",
    )


def router_for(repository: Repository) -> APIRouter:
    router = APIRouter()
    import_lock = Lock()

    @router.get("/profile", operation_id="getProfile")
    def profile() -> Profile:
        return Profile.model_validate(repository.read_setting("profile") or {})

    @router.put("/profile", operation_id="saveProfile")
    def save_profile(body: Profile) -> Profile:
        repository.save_setting(
            "profile", body.model_dump(mode="json"), "profile.updated"
        )
        return body

    @router.get("/integrations/aws", operation_id="getAwsWorkspace")
    def aws_workspace() -> AwsWorkspace:
        enabled = repository.source == "aws"
        previous = repository.read_setting("aws_import") if enabled else None
        return AwsWorkspace(
            enabled=enabled,
            account_id=repository.bound_account() if enabled else None,
            available_profiles=configured_profiles() if enabled else [],
            environment_credentials=configured_environment() if enabled else False,
            last_import=ImportSummary.model_validate(previous) if previous else None,
        )

    def check_settings(body: AwsSettings) -> str | None:
        if repository.source != "aws":
            raise HTTPException(
                403, "Open the private AWS workspace to connect an account"
            )
        existing = repository.bound_account()
        if existing is not None and body.account_id != existing:
            raise HTTPException(
                409, "This private workspace already contains another AWS account"
            )
        if body.credential_source == "environment":
            if not configured_environment():
                raise HTTPException(
                    422, "No AWS credentials are configured in this process"
                )
            return None
        if not body.profile or body.profile not in configured_profiles():
            raise HTTPException(
                422, "Select an AWS profile configured on this computer"
            )
        return body.profile

    @router.post("/integrations/aws/verify", operation_id="verifyAwsConnection")
    def verify(body: AwsSettings) -> AwsSettings:
        profile_name = check_settings(body)
        try:
            session, config = verified_session(
                body.account_id, body.region, profile_name
            )
            session.client("cloudtrail", config=config).lookup_events(MaxResults=1)
        except (BotoCoreError, ClientError, ValueError) as error:
            raise aws_error(error) from error
        repository.save_setting(
            "aws_verified", body.model_dump(mode="json"), "aws.connection.verified"
        )
        return body

    @router.post("/integrations/aws/import", operation_id="importAwsAccount")
    def import_account(body: AwsImport) -> ImportSummary:
        if not import_lock.acquire(blocking=False):
            raise HTTPException(409, "An AWS import is already running")
        try:
            profile_name = check_settings(body)
            settings = AwsSettings.model_validate(
                body.model_dump(include=set(AwsSettings.model_fields))
            )
            if repository.read_setting("aws_verified") != settings.model_dump(
                mode="json"
            ):
                raise HTTPException(
                    409, "Verify these AWS connection settings before importing"
                )

            try:
                events = list(
                    lookup(body.account_id, body.region, body.days, 200, profile_name)
                )
            except (BotoCoreError, ClientError, ValueError) as error:
                raise aws_error(error) from error
            now = datetime.now(UTC)
            try:
                repository.pin_account(body.account_id)
                result = repository.ingest(events, now)
            except Conflict as error:
                raise HTTPException(409, str(error)) from error
            iam_state: Literal["imported", "skipped", "unavailable"] = "skipped"
            iam_count = 0
            if body.include_iam:
                try:
                    inventory = read_inventory(
                        body.account_id, body.region, profile_name
                    )
                except (BotoCoreError, ClientError, TypeError, ValueError):
                    iam_state = "unavailable"
                else:
                    repository.save_posture(inventory, datetime.now(UTC))
                    iam_state, iam_count = "imported", len(inventory)
            summary = ImportSummary(
                imported_at=datetime.now(UTC),
                settings=settings,
                cloudtrail=result,
                iam=iam_state,
                iam_identities=iam_count,
            )
            repository.save_setting(
                "aws_import", summary.model_dump(mode="json"), "aws.account.imported"
            )
            return summary
        finally:
            import_lock.release()

    return router
