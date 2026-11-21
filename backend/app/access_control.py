"""Local workspace users, MFA and server-side sessions."""

import argparse
import base64
import hmac
import json
import os
import re
import secrets
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from getpass import getpass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field, model_validator

from app.repository import Repository, audit

Role = Literal["admin", "analyst", "detection_engineer", "viewer"]
ROLES = ("admin", "analyst", "detection_engineer", "viewer")
COOKIE = "ig_session"
AUTH_PATH = "/api/v1/auth"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
WINDOW = 30
SESSION_LENGTH = 8 * 60 * 60
SESSION_IDLE = 30 * 60
CHALLENGE_LENGTH = 5 * 60
MAX_ATTEMPTS = 5
LOCK_TIME = 15 * 60
PASSWORDS = PasswordHasher()

SCHEMA = """
CREATE TABLE IF NOT EXISTS access_users (
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','analyst','detection_engineer','viewer')),
    secret BLOB NOT NULL,
    accounts TEXT NOT NULL DEFAULT '[]',
    last_step INTEGER NOT NULL DEFAULT -1
);
CREATE TABLE IF NOT EXISTS access_recovery (
    email TEXT NOT NULL REFERENCES access_users(email) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    PRIMARY KEY(email,code_hash)
);
CREATE TABLE IF NOT EXISTS access_attempts (
    key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_challenges (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES access_users(email) ON DELETE CASCADE,
    attempt_key TEXT NOT NULL, expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS access_sessions (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL REFERENCES access_users(email) ON DELETE CASCADE,
    expires INTEGER NOT NULL, idle INTEGER NOT NULL
);
"""


class PasswordLogin(BaseModel):
    email: Annotated[str, Field(min_length=1, max_length=254)]
    password: Annotated[str, Field(min_length=1, max_length=512)]


class FactorLogin(BaseModel):
    challenge: Annotated[str, Field(min_length=43, max_length=43)]
    code: Annotated[str, Field(min_length=1, max_length=64)]


class Challenge(BaseModel):
    challenge: str


class SessionInfo(BaseModel):
    email: str
    role: Role
    csrf: str
    accounts: list[str]


class AccessStatus(BaseModel):
    enabled: bool


AccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]


class RoleAssignment(BaseModel):
    role: Role
    accounts: Annotated[list[AccountId], Field(max_length=200)] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def validate_admin(self) -> "RoleAssignment":
        if self.role == "admin" and self.accounts:
            raise ValueError("Workspace administrators require all accounts")
        return self


class WorkspaceUser(RoleAssignment):
    email: str
    mfa_enrolled: bool


@dataclass(frozen=True)
class Enrollment:
    uri: str
    recovery_codes: tuple[str, ...]


def totp(secret: bytes, step: int, digits: int = 6) -> str:
    digest = hmac.digest(secret, struct.pack(">Q", step), "sha1")
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(number % (10**digits)).zfill(digits)


def key_from_environment() -> bytes:
    value = os.getenv("IG_ACCESS_KEY", "")
    try:
        key = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(
            "IG_ACCESS_KEY must contain a 32-byte hexadecimal key"
        ) from error
    if len(key) != 32:
        raise ValueError("IG_ACCESS_KEY must contain a 32-byte hexadecimal key")
    return key


def token_hash(value: str) -> str:
    return sha256(value.encode()).hexdigest()


class AccessControl:
    def __init__(self, repository: Repository, key: bytes) -> None:
        self.repository = repository
        self.cipher = AESGCM(key)
        self.csrf_key = hmac.digest(key, b"identityguard.csrf", "sha256")
        self.dummy_hash = PASSWORDS.hash(secrets.token_urlsafe(32))
        with repository.connect() as connection:
            connection.executescript(SCHEMA)

    def provision(
        self,
        email: str,
        password: str,
        role: Role,
        accounts: tuple[str, ...] = (),
    ) -> Enrollment:
        email = email.strip().lower()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            raise ValueError("Enter a valid email address")
        if not 12 <= len(password) <= 512 or not all(
            re.search(pattern, password) for pattern in ("[a-z]", "[A-Z]", "[0-9]")
        ):
            raise ValueError(
                "Use at least 12 characters, with upper and lower case and a digit"
            )
        if role not in ROLES:
            raise ValueError("Unknown workspace role")
        if role == "admin" and accounts:
            raise ValueError("Workspace administrators require all accounts")
        if any(not re.fullmatch(r"[0-9]{12}", account) for account in accounts):
            raise ValueError("Account scopes must be twelve-digit AWS account IDs")
        secret = secrets.token_bytes(20)
        nonce = secrets.token_bytes(12)
        encrypted = nonce + self.cipher.encrypt(nonce, secret, email.encode())
        codes = tuple(secrets.token_hex(10) for _ in range(10))
        hashed = PASSWORDS.hash(password)
        with self.repository.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT OR IGNORE INTO access_users(email,password,role,secret,accounts) VALUES (?,?,?,?,?)",
                (email, hashed, role, encrypted, json.dumps(sorted(set(accounts)))),
            )
            if not cursor.rowcount:
                raise ValueError("This user already exists")
            connection.executemany(
                "INSERT INTO access_recovery VALUES (?,?)",
                ((email, token_hash(code)) for code in codes),
            )
            audit(
                connection,
                datetime.now(UTC),
                "access.user.created",
                email,
                {"role": role, "accounts": sorted(set(accounts))},
            )
        secret_text = base64.b32encode(secret).decode()
        label = quote(f"IdentityGuard:{email}", safe="")
        return Enrollment(
            f"otpauth://totp/{label}?secret={secret_text}&issuer=IdentityGuard",
            codes,
        )

    def csrf(self, token: str) -> str:
        return hmac.digest(self.csrf_key, token.encode(), "sha256").hex()

    def session_hash(self, token: str) -> str:
        return hmac.digest(self.csrf_key, b"session:" + token.encode(), "sha256").hex()

    def login(self, body: PasswordLogin, address: str, now: int) -> str:
        email = body.email.strip().lower()
        attempt_key = token_hash(f"{email}|{address}")
        with self.repository.connect() as connection:
            row = connection.execute(
                "SELECT password FROM access_users WHERE email=?", (email,)
            ).fetchone()
        password_hash = row["password"] if row else self.dummy_hash
        try:
            verified = (
                PASSWORDS.verify(password_hash, body.password) and row is not None
            )
        except VerifyMismatchError:
            verified = False

        challenge = secrets.token_urlsafe(32)
        with self.repository.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM access_attempts WHERE expires<=?", (now,))
            connection.execute("DELETE FROM access_challenges WHERE expires<=?", (now,))
            attempts = connection.execute(
                "SELECT attempts FROM access_attempts WHERE key=?", (attempt_key,)
            ).fetchone()
            blocked = attempts is not None and attempts["attempts"] >= MAX_ATTEMPTS
            if verified and not blocked:
                connection.execute(
                    "DELETE FROM access_challenges WHERE attempt_key=?", (attempt_key,)
                )
                connection.execute(
                    "INSERT INTO access_challenges(token_hash,email,attempt_key,expires) VALUES (?,?,?,?)",
                    (token_hash(challenge), email, attempt_key, now + CHALLENGE_LENGTH),
                )
                return challenge
            if not blocked:
                connection.execute(
                    """INSERT INTO access_attempts VALUES (?,1,?)
                       ON CONFLICT(key) DO UPDATE SET attempts=attempts+1,
                       expires=CASE WHEN attempts=? THEN excluded.expires ELSE expires END""",
                    (attempt_key, now + LOCK_TIME, MAX_ATTEMPTS - 1),
                )
                if attempts and attempts["attempts"] == MAX_ATTEMPTS - 1:
                    audit(
                        connection, datetime.now(UTC), "access.login.locked", email, {}
                    )
        raise HTTPException(401, "Invalid credentials")

    def finish(self, body: FactorLogin, now: int) -> tuple[str, SessionInfo]:
        key = token_hash(body.challenge)
        code = body.code.strip().lower()
        with self.repository.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT c.email,c.attempts,c.attempt_key,u.role,u.secret,u.last_step,u.accounts,
                    (SELECT attempts FROM access_attempts a WHERE a.key=c.attempt_key AND a.expires>?) AS total_attempts
                FROM access_challenges c JOIN access_users u USING(email)
                WHERE c.token_hash=? AND c.expires>? AND c.attempts<?
                """,
                (now, key, now, MAX_ATTEMPTS),
            ).fetchone()
            if row is not None and (row["total_attempts"] or 0) < MAX_ATTEMPTS:
                email = row["email"]
                encrypted = row["secret"]
                recovery = False
                step = None
                if re.fullmatch(r"[0-9]{6}", code):
                    secret = self.decrypt(encrypted, email)
                    counter = now // WINDOW
                    step = next(
                        (
                            value
                            for value in (counter, counter - 1, counter + 1)
                            if value >= 0
                            and value > row["last_step"]
                            and hmac.compare_digest(totp(secret, value), code)
                        ),
                        None,
                    )
                elif row["last_step"] >= 0 and re.fullmatch(r"[0-9a-f]{20}", code):
                    recovery = (
                        connection.execute(
                            "DELETE FROM access_recovery WHERE email=? AND code_hash=?",
                            (email, token_hash(code)),
                        ).rowcount
                        == 1
                    )

                if recovery or step is not None:
                    connection.execute(
                        "DELETE FROM access_challenges WHERE email=?", (email,)
                    )
                    connection.execute(
                        "DELETE FROM access_attempts WHERE key=?", (row["attempt_key"],)
                    )
                    connection.execute(
                        "DELETE FROM access_sessions WHERE expires<=? OR idle<=?",
                        (now, now),
                    )
                    if step is not None:
                        connection.execute(
                            "UPDATE access_users SET last_step=? WHERE email=?",
                            (step, email),
                        )
                    token = secrets.token_urlsafe(32)
                    connection.execute(
                        "INSERT INTO access_sessions VALUES (?,?,?,?)",
                        (
                            self.session_hash(token),
                            email,
                            now + SESSION_LENGTH,
                            now + SESSION_IDLE,
                        ),
                    )
                    audit(
                        connection,
                        datetime.now(UTC),
                        "access.login",
                        email,
                        {"recovery": recovery},
                    )
                    return token, SessionInfo(
                        email=email,
                        role=row["role"],
                        csrf=self.csrf(token),
                        accounts=json.loads(row["accounts"]),
                    )

                connection.execute(
                    "UPDATE access_challenges SET attempts=attempts+1 WHERE token_hash=?",
                    (key,),
                )
                connection.execute(
                    """INSERT INTO access_attempts VALUES (?,1,?)
                       ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN expires<=? THEN 1 ELSE attempts+1 END,
                       expires=excluded.expires""",
                    (row["attempt_key"], now + LOCK_TIME, now),
                )
                if row["total_attempts"] == MAX_ATTEMPTS - 1:
                    audit(
                        connection, datetime.now(UTC), "access.login.locked", email, {}
                    )
        raise HTTPException(401, "Invalid or expired verification code")

    def decrypt(self, encrypted: bytes, email: str) -> bytes:
        try:
            return self.cipher.decrypt(encrypted[:12], encrypted[12:], email.encode())
        except InvalidTag as error:
            raise HTTPException(
                503, "Workspace MFA key does not match this database"
            ) from error

    def session(self, token: str, now: int) -> SessionInfo | None:
        if len(token) != 43:
            return None
        key = self.session_hash(token)
        with self.repository.connect() as connection:
            row = connection.execute(
                """
                SELECT s.email,u.role,u.accounts FROM access_sessions s JOIN access_users u USING(email)
                WHERE s.token_hash=? AND s.expires>? AND s.idle>?
                """,
                (key, now, now),
            ).fetchone()
            if row is None:
                return None
            if not connection.execute(
                "UPDATE access_sessions SET idle=MAX(idle,?) WHERE token_hash=? AND expires>? AND idle>?",
                (now + SESSION_IDLE, key, now, now),
            ).rowcount:
                return None
            return SessionInfo(
                email=row["email"],
                role=row["role"],
                csrf=self.csrf(token),
                accounts=json.loads(row["accounts"]),
            )

    def users(self) -> list[WorkspaceUser]:
        with self.repository.connect() as connection:
            rows = connection.execute(
                "SELECT email,role,accounts,last_step FROM access_users ORDER BY email"
            ).fetchall()
        return [
            WorkspaceUser(
                email=row["email"],
                role=row["role"],
                accounts=json.loads(row["accounts"]),
                mfa_enrolled=row["last_step"] >= 0,
            )
            for row in rows
        ]

    def update_assignment(
        self, email: str, body: RoleAssignment, actor: str
    ) -> WorkspaceUser:
        accounts = sorted(set(body.accounts))
        with self.repository.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT role,accounts,last_step FROM access_users WHERE email=?",
                (email,),
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Workspace user not found")
            if (
                row["role"] == "admin"
                and body.role != "admin"
                and not connection.execute(
                    "SELECT 1 FROM access_users WHERE role='admin' AND email<>? AND last_step>=0 LIMIT 1",
                    (email,),
                ).fetchone()
            ):
                raise HTTPException(
                    409, "At least one enrolled administrator is required"
                )
            if row["role"] != body.role or json.loads(row["accounts"]) != accounts:
                connection.execute(
                    "UPDATE access_users SET role=?,accounts=? WHERE email=?",
                    (body.role, json.dumps(accounts), email),
                )
                connection.execute(
                    "DELETE FROM access_sessions WHERE email=?", (email,)
                )
                connection.execute(
                    "DELETE FROM access_challenges WHERE email=?", (email,)
                )
                audit(
                    connection,
                    datetime.now(UTC),
                    "access.assignment.updated",
                    email,
                    {"actor": actor, "role": body.role, "accounts": accounts},
                )
            return WorkspaceUser(
                email=email,
                role=body.role,
                accounts=accounts,
                mfa_enrolled=row["last_step"] >= 0,
            )

    def logout(self, token: str, email: str) -> None:
        with self.repository.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM access_sessions WHERE token_hash=? AND email=?",
                (self.session_hash(token), email),
            )
            audit(connection, datetime.now(UTC), "access.logout", email, {})


def request_accounts(request: Request) -> list[str]:
    session = getattr(request.state, "access_session", None)
    return list(session.accounts) if session is not None else []


def scoped_route(method: str, path: str) -> bool:
    if path in {AUTH_PATH + "/session", AUTH_PATH + "/logout"}:
        return True
    if method == "GET":
        return (
            path in {"/api/v1/overview", "/api/v1/incidents", "/api/v1/events"}
            or re.fullmatch(r"/api/v1/incidents/[^/]+/trace", path) is not None
            or re.fullmatch(r"/api/v1/cases/[^/]+/timeline", path) is not None
        )
    return (
        method == "PATCH" and re.fullmatch(r"/api/v1/incidents/[^/]+", path) is not None
    )


def permitted(role: Role, method: str, path: str) -> bool:
    if role == "admin" or path == AUTH_PATH + "/session" and method == "GET":
        return True
    if path == AUTH_PATH + "/logout" and method == "POST":
        return True
    suffix = path.removeprefix("/api/v1")
    if method in SAFE_METHODS:
        if suffix in {"/detections", "/models/baselines", "/models/drafts"}:
            return role == "detection_engineer"
        return (
            suffix
            in {
                "/overview",
                "/incidents",
                "/events",
                "/cloud",
                "/attack-paths",
                "/attack-paths/origins",
                "/role-chains",
                "/quality",
                "/sla",
                "/sla/settings",
                "/assistant",
            }
            or re.fullmatch(
                r"/cases/[^/]+/(?:timeline|analysis)|/incidents/[^/]+/trace", suffix
            )
            is not None
        )
    if role == "detection_engineer":
        return method == "POST" and (
            suffix
            in {"/detections", "/detections/backtest", "/models/ahp", "/models/drafts"}
            or re.fullmatch(r"/models/drafts/[^/]+/shadow", suffix) is not None
        )
    if role == "analyst":
        return (
            method == "PATCH"
            and re.fullmatch(r"/incidents/[^/]+", suffix) is not None
            or method == "POST"
            and re.fullmatch(r"/incidents/[^/]+/isolation", suffix) is not None
        )
    return False


def router_for(access: AccessControl | None) -> APIRouter:
    router = APIRouter()

    def configured() -> AccessControl:
        if access is None:
            raise HTTPException(404, "Workspace login is disabled")
        return access

    @router.get("/auth/status", operation_id="getAccessStatus")
    def status() -> AccessStatus:
        return AccessStatus(enabled=access is not None)

    @router.post("/auth/login", operation_id="beginLogin")
    def login(body: PasswordLogin, request: Request) -> Challenge:
        address = request.client.host if request.client else ""
        return Challenge(
            challenge=configured().login(
                body, address, int(datetime.now(UTC).timestamp())
            )
        )

    @router.post("/auth/verify", operation_id="verifyLogin")
    def verify(body: FactorLogin, response: Response) -> SessionInfo:
        token, session = configured().finish(body, int(datetime.now(UTC).timestamp()))
        response.set_cookie(
            COOKIE,
            token,
            max_age=SESSION_LENGTH,
            httponly=True,
            secure=True,
            samesite="strict",
        )
        return session

    @router.get("/auth/session", operation_id="getAccessSession")
    def session(request: Request) -> SessionInfo:
        result: SessionInfo = request.state.access_session
        return result

    @router.post("/auth/logout", operation_id="endLogin")
    def logout(request: Request, response: Response) -> AccessStatus:
        configured().logout(request.cookies[COOKIE], request.state.access_session.email)
        response.delete_cookie(COOKIE, httponly=True, secure=True, samesite="strict")
        return AccessStatus(enabled=True)

    @router.get("/admin/access", operation_id="listAccessUsers")
    def users() -> list[WorkspaceUser]:
        return configured().users()

    @router.put("/admin/access/{email}", operation_id="updateAccessAssignment")
    def assignment(email: str, body: RoleAssignment, request: Request) -> WorkspaceUser:
        control = configured()
        session: SessionInfo = request.state.access_session
        return control.update_assignment(email, body, session.email)

    return router


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision a user in the local IdentityGuard workspace."
    )
    parser.add_argument("database", type=Path)
    parser.add_argument("email")
    parser.add_argument("role", choices=ROLES)
    parser.add_argument("--account", action="append", default=[])
    options = parser.parse_args()
    if not options.database.is_file():
        parser.error("The workspace database must already exist")
    key = key_from_environment()
    password = getpass("Password: ")
    if password != getpass("Repeat password: "):
        parser.error("Passwords do not match")
    control = AccessControl(Repository(options.database), key)
    enrollment = control.provision(
        options.email, password, options.role, tuple(options.account)
    )
    print(enrollment.uri)
    print("One-time recovery codes:")
    print("\n".join(enrollment.recovery_codes))


if __name__ == "__main__":
    main()
