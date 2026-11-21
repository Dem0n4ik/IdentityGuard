from base64 import b32decode
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_bytes, token_urlsafe
from urllib.parse import parse_qs, urlparse

from app.access_control import COOKIE, AccessControl, totp
from app.analytics import Search, build_query
from app.api import create_app
from app.engine.events import Event, Identity
from app.repository import Repository
from fastapi.testclient import TestClient

PREFIX = "/api/v1"
HEADERS = {"X-IdentityGuard-Local": "1"}
ACCOUNT = "111122223333"
OTHER = "222233334444"


def create_workspace(path: Path) -> tuple[Repository, AccessControl, TestClient]:
    key = token_bytes(32)
    repo = Repository(path)
    return (
        repo,
        AccessControl(repo, key),
        TestClient(create_app(repo, access_key=key), base_url="https://localhost"),
    )


def test_totp_rfc6238_vectors() -> None:
    seed = b"12345678901234567890"
    assert totp(seed, 59 // 30, 8) == "94287082"
    assert totp(seed, 1111111109 // 30, 8) == "07081804"


def test_mfa_login_recovery_replay_and_csrf(tmp_path: Path) -> None:
    _, control, client = create_workspace(tmp_path / "access.sqlite")
    email = "admin@example.test"
    password = "T9" + token_urlsafe(18)
    enrollment = control.provision(email, password, "admin")
    seed = b32decode(parse_qs(urlparse(enrollment.uri).query)["secret"][0])
    cookie_route = PREFIX + "/auth/session"
    login_route = PREFIX + "/auth/login"
    verify_route = PREFIX + "/auth/verify"

    assert client.get(PREFIX + "/overview").status_code == 401
    assert client.get(PREFIX + "/auth/status").json() == {"enabled": True}
    auth = {"email": email, "password": password}

    def challenge() -> str:
        result = client.post(login_route, json=auth, headers=HEADERS)
        assert result.status_code == 200
        return result.json()["challenge"]

    initial = challenge()
    assert client.get(cookie_route).status_code == 401
    now = int(datetime.now(UTC).timestamp())
    code = totp(seed, now // 30)
    invalid_code = next(
        str(n).zfill(6)
        for n in range(5)
        if str(n).zfill(6)
        not in {totp(seed, now // 30 + delta) for delta in (-1, 0, 1, 2)}
    )
    assert (
        client.post(
            verify_route,
            json={"challenge": initial, "code": invalid_code},
            headers=HEADERS,
        ).status_code
        == 401
    )
    verified = client.post(
        verify_route, json={"challenge": initial, "code": code}, headers=HEADERS
    )
    assert verified.status_code == 200
    assert {"secure", "httponly", "samesite=strict"} <= {
        part.strip().lower() for part in verified.headers["set-cookie"].split(";")
    }
    assert client.cookies.get(COOKIE)
    assert client.get(PREFIX + "/overview").status_code == 200
    logout_route = PREFIX + "/auth/logout"
    assert client.post(logout_route, headers=HEADERS).status_code == 403
    csrf = {"X-CSRF-Token": verified.json()["csrf"]}
    assert client.post(logout_route, headers=HEADERS | csrf).status_code == 200
    assert client.get(cookie_route).status_code == 401

    retry = challenge()
    assert (
        client.post(
            verify_route, json={"challenge": retry, "code": code}, headers=HEADERS
        ).status_code
        == 401
    )
    backup = enrollment.recovery_codes[0]
    verified_backup = client.post(
        verify_route, json={"challenge": retry, "code": backup}, headers=HEADERS
    )
    assert verified_backup.status_code == 200
    assert client.post(
        logout_route, headers=HEADERS | {"X-CSRF-Token": verified_backup.json()["csrf"]}
    ).is_success
    assert (
        client.post(
            verify_route,
            json={"challenge": challenge(), "code": backup},
            headers=HEADERS,
        ).status_code
        == 401
    )


def test_api_roles_and_scoped_accounts(tmp_path: Path) -> None:
    repo, control, client = create_workspace(tmp_path / "access.sqlite")
    now = datetime.now(UTC)
    repo.ingest(
        [
            Event(
                event_id=f"event-{index}",
                time=now - timedelta(hours=3),
                account_id=account,
                identity=Identity(account, "user", name),
                name="DeleteTrail",
                region="eu-central-1",
                source_ip="192.0.2.1",
            )
            for index, (account, name) in enumerate(
                ((ACCOUNT, "allowed-user"), (OTHER, "hidden-user"))
            )
        ],
        now,
    )
    sessions = {}
    for role in ("admin", "analyst", "detection_engineer", "viewer"):
        email = role + "@example.test"
        password = "M8" + token_urlsafe(18)
        accounts = (ACCOUNT,) if role == "analyst" else ()
        enrollment = control.provision(email, password, role, accounts)
        claim = client.post(
            PREFIX + "/auth/login",
            json={"email": email, "password": password},
            headers=HEADERS,
        ).json()
        seed = b32decode(parse_qs(urlparse(enrollment.uri).query)["secret"][0])
        code = totp(seed, int(datetime.now(UTC).timestamp()) // 30)
        result = client.post(
            PREFIX + "/auth/verify",
            json={**claim, "code": code},
            headers=HEADERS,
        )
        assert result.status_code == 200
        sessions[role] = (
            client.cookies.get(COOKIE),
            {"X-CSRF-Token": result.json()["csrf"]},
        )

    disabled = next(
        row for row in repo.incidents() if row["identity"]["account_id"] == OTHER
    )
    allowed = next(
        row for row in repo.incidents() if row["identity"]["account_id"] == ACCOUNT
    )
    for role, (cookie, csrf) in sessions.items():
        client.cookies.clear()
        client.cookies.set(COOKIE, cookie)
        assert client.get(PREFIX + "/admin/access").status_code == (
            200 if role == "admin" else 403
        )
        assert client.get(PREFIX + "/audit").status_code == (
            200 if role == "admin" else 403
        )
        assert client.get(PREFIX + "/detections").status_code == (
            200 if role in {"admin", "detection_engineer"} else 403
        )
        overview = client.get(PREFIX + "/overview")
        assert overview.status_code == 200
        if role == "analyst":
            assert OTHER not in overview.text
            assert "hidden-user" not in overview.text
            events = client.get(PREFIX + "/events").json()["items"]
            assert events and {event["account_id"] for event in events} == {ACCOUNT}
            assert not client.get(PREFIX + "/events", params={"account": OTHER}).json()[
                "items"
            ]
            assert (
                client.get(PREFIX + f"/incidents/{disabled['id']}/trace").status_code
                == 404
            )
            assert (
                client.get(PREFIX + f"/cases/{disabled['id']}/timeline").status_code
                == 404
            )
            assert (
                client.get(PREFIX + f"/cases/{allowed['id']}/timeline").status_code
                == 200
            )
            assert not repo.events_by_id(["event-1"], accounts=(ACCOUNT,))
        payload = {"status": "investigating"}
        incident = disabled if role == "analyst" else allowed
        headers = HEADERS | csrf | {"If-Match": f'"{incident["version"]}"'}
        assert (
            client.patch(
                PREFIX + f"/incidents/{incident['id']}", json=payload, headers=headers
            ).status_code
            == {
                "admin": 200,
                "analyst": 404,
                "detection_engineer": 403,
                "viewer": 403,
            }[role]
        )

    client.cookies.clear()
    client.cookies.set(COOKIE, sessions["admin"][0])
    assert (
        client.put(
            PREFIX + "/admin/access/analyst@example.test",
            json={"role": "viewer", "accounts": [ACCOUNT]},
            headers=HEADERS | sessions["admin"][1],
        ).status_code
        == 200
    )
    client.cookies.clear()
    client.cookies.set(COOKIE, sessions["analyst"][0])
    assert client.get(PREFIX + "/overview").status_code == 401


def test_clickhouse_query_always_intersects_requested_account_with_scope() -> None:
    query, params = build_query(Search(account=OTHER, allowed_accounts=(ACCOUNT,)))
    assert "account_id = {account:String}" in query
    assert "account_id IN splitByChar(',', {allowed_accounts:String})" in query
    assert params["account"] == OTHER
    assert params["allowed_accounts"] == ACCOUNT
