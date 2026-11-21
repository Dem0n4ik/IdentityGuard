"""Replay an explicitly synthetic CloudTrail exercise in a demo workspace."""

import argparse
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from app.devdata import CORP
from app.engine.events import Event, Identity
from app.engine.posture import Snapshot
from app.ingest import normalize
from app.pipeline import closed_boundary
from app.repository import SIMULATION_SETTING, Conflict, Repository, Status

PACK = SIMULATION_SETTING
ACCOUNTS = (
    "111000001001",
    "111000001002",
    "111000001003",
    "111000001004",
    "111000001005",
)


@dataclass(frozen=True)
class Scenario:
    key: str
    title_uk: str
    title_en: str
    context_uk: str
    context_en: str
    stages: tuple[tuple[int, str, str], ...]
    verdict: str | None = None
    disposition: str = "attack"


SCENARIOS = (
    Scenario(
        "runner",
        "Компрометація CI-раннера",
        "Compromised CI runner",
        "Викрадена сесія раннера відкрила шлях через доставку артефактів до секретів продакшну, журналів та резервних копій.",
        "A stolen runner session pivoted through artifact delivery to production secrets, audit logs and backups.",
        (
            (0, "BuildRunner", "PutRolePolicy"),
            (1, "ArtifactPublisher", "CreatePolicyVersion"),
            (2, "ReleaseOrchestrator", "UpdateFunctionCode"),
            (3, "ProdSecretReader", "GetSecretValue"),
            (4, "AuditMaintainer", "StopLogging"),
            (3, "BackupExporter", "ModifyDBSnapshotAttribute"),
            (2, "DataExportOperator", "GetObject"),
        ),
    ),
    Scenario(
        "vendor",
        "Захоплення доступу підрядника",
        "Hijacked vendor access",
        "Обліковий запис підтримки перейшов у фінансовий акаунт через виняток у довірі до зовнішньої ролі. Слід веде до секрету білінгу.",
        "A support identity used an external trust exception to enter the finance account and reach a billing secret.",
        (
            (0, "vendor-support", "CreateAccessKey"),
            (1, "PartnerIntake", "UpdateAssumeRolePolicy"),
            (2, "SupportBroker", "AttachRolePolicy"),
            (4, "FinanceReadBridge", "GetParameter"),
            (3, "BillingOps", "GetSecretValue"),
            (4, "FinanceArchive", "PutBucketPolicy"),
        ),
    ),
    Scenario(
        "backup",
        "Витік через резервне відновлення",
        "Backup recovery exfiltration",
        "Сесія відновлення пройшла через резервні копії й тимчасовий акаунт відновлення. Наприкінці змінено доступ до знімка RDS.",
        "A recovery session crossed backup and restore accounts before changing access to an RDS snapshot.",
        (
            (4, "RecoveryConsole", "UpdateTrail"),
            (1, "VaultBroker", "CreatePolicyVersion"),
            (3, "SnapshotRestorer", "GetSecretValue"),
            (2, "RestoreValidation", "PutRolePolicy"),
            (4, "SnapshotShare", "ModifyDBSnapshotAttribute"),
        ),
    ),
    Scenario(
        "oidc",
        "Підміна релізу через федерацію",
        "Federated release tampering",
        "Сесія, отримана через CI-федерацію, змінила код функції й дозволи ролі, а потім звузила збір аудиту.",
        "A CI-federated session modified function code and role permissions, then narrowed audit collection.",
        (
            (0, "OidcRelease", "UpdateFunctionCode"),
            (2, "DeploymentBridge", "PutRolePolicy"),
            (3, "RuntimeUpdater", "GetParameter"),
            (4, "AuditControl", "PutEventSelectors"),
            (1, "PolicyDistribution", "SetDefaultPolicyVersion"),
        ),
    ),
    Scenario(
        "workload",
        "Викрадення сесії з робочого навантаження",
        "Stolen workload session",
        "Облікові дані ролі обробки задач використано за межами її звичного мережевого профілю. Через спільні ролі сесія дісталася секретів клієнтського сервісу.",
        "Job processing credentials were used outside their usual network profile, then crossed shared roles to reach customer-service secrets.",
        (
            (1, "BatchWorker", "GetSecretValue"),
            (0, "WorkloadBridge", "PutRolePolicy"),
            (2, "QueueAdmin", "CreatePolicyVersion"),
            (4, "LogDeliveryControl", "StopLogging"),
            (3, "CustomerSecrets", "GetSecretValue"),
            (2, "ObjectStoreAccess", "PutBucketPolicy"),
        ),
    ),
    Scenario(
        "iam-key",
        "Закріплення через додатковий ключ IAM",
        "Persistence via a new IAM key",
        "Застарілий ключ автоматизації використано для створення другого ключа та зміни політики користувача.",
        "An aging automation key was used to create a second key and change the user's policy.",
        ((1, "pipeline-bot", "CreateAccessKey PutUserPolicy GetSecretValue"),),
        "true_positive",
    ),
    Scenario(
        "trail",
        "Вимкнення журналювання поза вікном змін",
        "Logging disabled outside change window",
        "Сесію адміністрування журналів перехоплено. У реєстрі змін немає дозволу на зупинення трейлу.",
        "A logging administration session was compromised. The change register contains no approved trail shutdown.",
        ((4, "TrailDelivery", "StopLogging PutEventSelectors"),),
    ),
    Scenario(
        "function",
        "Ін’єкція коду у функцію обробки платежів",
        "Code injection into payment processor",
        "Окрема сесія змінила код функції обробки платежів і прочитала секрет застосунку.",
        "A separate session modified a payment processor and retrieved an application secret.",
        ((3, "PaymentFunctionDeploy", "UpdateFunctionCode GetSecretValue"),),
    ),
    Scenario(
        "s3-policy",
        "Зміна політики сховища клієнтських експортів",
        "Customer exports bucket policy change",
        "Роль змінила політику сховища й прочитала тестовий експорт. Власник сервісу підтвердив, що це не його сесія.",
        "A role modified the export bucket policy and read a test export. The owner confirmed the session was unauthorized.",
        ((2, "CustomerExportMaintainer", "PutBucketPolicy GetObject"),),
    ),
    Scenario(
        "rotation",
        "Погоджена аварійна ротація секретів",
        "Approved emergency secret rotation",
        "Власник підтвердив аварійне читання секрету й тимчасове розширення дозволів за заявкою CHG-4102. Поведінка справді нетипова.",
        "The owner confirmed an emergency secret read and a temporary permission change under CHG-4102. The behavior was genuinely unusual.",
        ((3, "EmergencyRotation", "PutRolePolicy GetSecretValue"),),
        "benign_true_positive",
        "approved",
    ),
    Scenario(
        "failover",
        "Планове перемикання CloudTrail",
        "Scheduled CloudTrail failover",
        "Зміна CHG-4170 погоджує коротке зупинення й оновлення трейлу під час переходу на нове сховище.",
        "Change CHG-4170 authorizes a short trail shutdown and update during a storage migration.",
        ((4, "AuditFailover", "StopLogging UpdateTrail StartLogging"),),
        "benign_true_positive",
        "approved",
    ),
    Scenario(
        "bluegreen",
        "Нічний реліз blue-green",
        "Overnight blue-green deployment",
        "Дозволений позаплановий реліз CHG-4207 тимчасово оновив код функції та прочитав секрет перевірки працездатності.",
        "Approved emergency release CHG-4207 temporarily updated function code and read the health-check secret.",
        ((2, "BlueGreenCanary", "UpdateFunctionCode GetSecretValue"),),
        "benign_true_positive",
        "approved",
    ),
    Scenario(
        "collector",
        "Хибне спрацювання через розрив збору",
        "False positive after a collection gap",
        "Резервний трейл підтвердив регулярну перевірку правил збору. Через розрив в основному журналі модель бачила лише неповний профіль.",
        "The secondary trail confirmed a recurring selector check. A gap in the primary feed left the model with an incomplete profile.",
        ((4, "SelectorReconciler", "PutEventSelectors"),),
        "false_positive",
        "gap",
    ),
    Scenario(
        "policy-sync",
        "Хибне спрацювання після онбордингу акаунта",
        "False positive after account onboarding",
        "Перша видима синхронізація політик була штатною. Історія старого акаунта ще не була доступна профілю нової ролі.",
        "The first visible policy sync was routine. The new role's profile had no access to the old account's history.",
        ((1, "PolicySync", "CreatePolicyVersion GetSecretValue"),),
        "false_positive",
        "gap",
    ),
    Scenario(
        "retention",
        "Хибне спрацювання після зміни агента збору",
        "False positive after a collector migration",
        "Власник підтвердив щоденне прибирання тимчасової групи журналів. Новий збирач вперше зафіксував виклик DeleteLogGroup.",
        "The owner confirmed daily cleanup of a temporary log group. The replacement collector observed DeleteLogGroup for the first time.",
        ((2, "LogRetentionReaper", "DeleteLogGroup"),),
        "false_positive",
        "gap",
    ),
    Scenario(
        "quiet-deploy",
        "Контроль: штатний деплой",
        "Control: routine deployment",
        "",
        "",
        ((2, "RoutineDeploy", "ListRoles GetFunction"),),
        disposition="control",
    ),
    Scenario(
        "quiet-audit",
        "Контроль: штатний аудит",
        "Control: routine audit",
        "",
        "",
        ((4, "RoutineAudit", "DescribeTrails GetTrailStatus"),),
        disposition="control",
    ),
)

BASELINES = (
    "ListRoles GetRole ListPolicies",
    "ListBuckets GetBucketLocation ListObjectsV2",
    "GetFunction ListFunctions GetFunctionConfiguration",
    "DescribeDBInstances DescribeDBSnapshots ListSecrets",
    "DescribeTrails GetTrailStatus ListTrails",
)
SERVICES = {
    "iam": "ListRoles GetRole ListPolicies PutRolePolicy CreatePolicyVersion UpdateAssumeRolePolicy AttachRolePolicy SetDefaultPolicyVersion CreateAccessKey PutUserPolicy",
    "sts": "AssumeRole",
    "cloudtrail": "DescribeTrails GetTrailStatus ListTrails StopLogging UpdateTrail StartLogging PutEventSelectors",
    "s3": "ListBuckets GetBucketLocation ListObjectsV2 PutBucketPolicy GetObject",
    "lambda": "GetFunction ListFunctions GetFunctionConfiguration UpdateFunctionCode",
    "rds": "DescribeDBInstances DescribeDBSnapshots ModifyDBSnapshotAttribute",
    "secretsmanager": "ListSecrets GetSecretValue",
    "ssm": "GetParameter",
    "logs": "DeleteLogGroup",
}
OP_SERVICES = {
    operation: service for service, ops in SERVICES.items() for operation in ops.split()
}


def role_arn(account: str, role: str) -> str:
    return f"arn:aws:iam::{account}:role/{role}"


def target_for(operation: str, account: str, actor: str, region: str) -> str:
    service = OP_SERVICES[operation]
    resource = f"ig-{account[-3:]}-{actor.removeprefix('ig-').lower()}"
    if service == "iam":
        if operation in {"CreateAccessKey", "PutUserPolicy"}:
            return f"arn:aws:iam::{account}:user/{actor}"
        if operation in {"CreatePolicyVersion", "SetDefaultPolicyVersion"}:
            return f"arn:aws:iam::{account}:policy/{resource}"
        return role_arn(account, actor)
    if service == "s3":
        bucket = f"arn:aws:s3:::{resource}"
        return (
            f"{bucket}/exports/daily/order-ledger.csv"
            if operation == "GetObject"
            else bucket
        )
    parts = {
        "secretsmanager": f"secret:{resource}-aB1234",
        "ssm": f"parameter/{resource}/database",
        "cloudtrail": f"trail/{resource}",
        "rds": f"snapshot:{resource}",
        "lambda": f"function:{resource}",
        "logs": f"log-group:/aws/lambda/{resource}",
    }
    return f"arn:aws:{service}:{region}:{account}:{parts[service]}"


def make_event(
    identity: Identity,
    time: datetime,
    operation: str,
    region: str,
    ip: str,
    session: str,
    *,
    target: str = "",
    error: str = "",
) -> Event:
    account, actor = identity.account_id, identity.name
    key = uuid5(NAMESPACE_URL, f"identityguard/{PACK}/{identity}/{time}/{operation}")
    credential = uuid5(NAMESPACE_URL, f"identityguard/{PACK}/{identity}/{session}").hex
    request: dict[str, Any] = {}
    if operation == "AssumeRole":
        request = {"roleArn": target, "roleSessionName": session}
    if operation == "GetParameter":
        request["withDecryption"] = True
    if operation in {"GetParameter", "GetSecretValue"}:
        request["name" if operation == "GetParameter" else "secretId"] = (
            target or target_for(operation, account, actor, region)
        )
    principal: dict[str, Any] = {
        "accountId": account,
        "accessKeyId": ("ASIA" if identity.kind == "role" else "AKIA")
        + credential[:16].upper(),
    }
    if identity.kind == "role":
        principal.update(
            type="AssumedRole",
            arn=f"arn:aws:sts::{account}:assumed-role/{actor}/{session}",
        )
    else:
        principal.update(
            type="IAMUser", userName=actor, arn=f"arn:aws:iam::{account}:user/{actor}"
        )
    read_only = operation.startswith(("List", "Get", "Describe"))
    if not target and (
        not read_only or operation in {"GetObject", "GetSecretValue", "GetParameter"}
    ):
        target = target_for(operation, account, actor, region)
    return normalize(
        {
            "eventID": str(key),
            "eventTime": time.isoformat(),
            "eventName": operation,
            "eventSource": OP_SERVICES[operation] + ".amazonaws.com",
            "eventCategory": "Data" if operation == "GetObject" else "Management",
            "recipientAccountId": target.split(":")[4]
            if operation == "AssumeRole"
            else account,
            "awsRegion": region,
            "sourceIPAddress": ip,
            "readOnly": read_only,
            "userIdentity": principal,
            "requestParameters": request,
            "resources": [{"ARN": target}] if target else [],
            "userAgent": "aws-cli/2.17.24" if ":" in ip else "Boto3/1.34.162",
            "errorCode": error,
        }
    )


def actors_for(scenario: Scenario) -> list[Identity]:
    return [
        Identity(
            ACCOUNTS[account], "role" if name[0].isupper() else "user", f"ig-{name}"
        )
        for account, name, _ in scenario.stages
    ]


def exercise_region(index: int) -> str:
    return "eu-central-1" if index % 2 else "us-east-1"


def exercise_hour(anchor: datetime, index: int) -> datetime:
    # Spread activity across shifts and leave time for the closed cases to resolve.
    lookback = (1, 9, 28, 17, 4, 71, 2, 19, 37, 15, 53, 34, 7, 48, 21, 23, 47)
    hour = anchor - timedelta(hours=lookback[index - 1])
    if SCENARIOS[index - 1].disposition == "control":
        return hour.replace(hour=9)
    if SCENARIOS[index - 1].disposition == "attack" and hour.hour in {9, 13}:
        return hour - timedelta(hours=1)
    return hour


def build(anchor: datetime) -> tuple[list[Event], dict[Identity, tuple[Snapshot, ...]]]:
    events: list[Event] = []
    inventory: dict[Identity, tuple[Snapshot, ...]] = {}
    for index, scenario in enumerate(SCENARIOS, 1):
        actors = actors_for(scenario)
        hour = exercise_hour(anchor, index)
        day = hour.replace(hour=0)
        for stage, ((account, _, actions), identity) in enumerate(
            zip(scenario.stages, actors, strict=True)
        ):
            baseline = BASELINES[account].split()
            if scenario.disposition == "control":
                baseline = actions.split()
            start = day - timedelta(days=14)
            inventory[identity] = (
                Snapshot(
                    start,
                    mfa_enabled=False,
                    active_key_age_days=148 if identity.kind == "user" else None,
                    actions=frozenset({"*"})
                    if account in {2, 3, 4} or stage == 0
                    else frozenset({"iam:PutRolePolicy", "sts:AssumeRole"}),
                    critical=account != 0,
                    external_trust=bool(stage),
                    imds_v1=identity.name == "ig-BatchWorker",
                    unused_services_ratio=0.68 if stage % 2 == 0 else 0.35,
                    workload=account in {0, 1, 2, 3},
                ),
            )
            normal_ip = f"203.0.113.{10 + index}"
            days = (13,) if scenario.disposition == "gap" else range(14)
            for baseline_day in days:
                routine_day = start + timedelta(days=baseline_day)
                random = Random(
                    f"{routine_day.date()}:{identity.account_id}:{identity.name}"
                )
                for baseline_hour in (9, 13):
                    count = random.randint(3, 5)
                    for offset, minute in enumerate(
                        sorted(random.sample(range(60), count))
                    ):
                        timestamp = routine_day + timedelta(
                            hours=baseline_hour, minutes=minute
                        )
                        events.append(
                            make_event(
                                identity,
                                timestamp,
                                baseline[offset % len(baseline)],
                                "eu-west-1",
                                normal_ip,
                                f"batch-{timestamp:%Y%m%d}-{baseline_hour:02d}-{stage + 1:02d}",
                            )
                        )

            control = scenario.disposition == "control"
            session = f"pipeline-{hour:%y%m%d%H}-{4100 + index}"
            # The final runner pivot re-enters via a familiar corporate network.
            familiar_network = (
                scenario.disposition != "attack"
                or scenario.key == "runner"
                and stage == len(actors) - 1
            )
            ip = normal_ip if familiar_network else f"2001:db8:{index:x}::4a"
            region = "eu-west-1" if control else exercise_region(index)
            operation_list = actions.split()
            random = Random(f"{hour.isoformat()}:{identity.name}")
            stage_time = hour + timedelta(
                minutes=2 + stage * 8, seconds=random.randint(0, 30)
            )
            if scenario.disposition == "attack":
                events.append(
                    make_event(identity, stage_time, baseline[0], region, ip, session)
                )
            for offset, operation in enumerate(operation_list, 1):
                events.append(
                    make_event(
                        identity,
                        stage_time + timedelta(minutes=offset),
                        operation,
                        region,
                        ip,
                        session,
                    )
                )
            if scenario.key in {"runner", "workload"} and stage == 2:
                events.append(
                    make_event(
                        identity,
                        stage_time + timedelta(minutes=4),
                        "AssumeRole",
                        region,
                        ip,
                        session,
                        target=role_arn(ACCOUNTS[4], "ig-SecurityAdmin"),
                        error="AccessDenied",
                    )
                )
            if stage + 1 < len(actors):
                next_role = actors[stage + 1]
                events.append(
                    make_event(
                        identity,
                        stage_time + timedelta(minutes=6),
                        "AssumeRole",
                        region,
                        ip,
                        session,
                        target=role_arn(next_role.account_id, next_role.name),
                    )
                )
    return events, inventory


def advance_incident(
    repository: Repository, incident: dict[str, Any], scenario: Scenario, now: datetime
) -> None:
    detected = datetime.fromisoformat(incident["detected_at"])
    resolution = {"iam-key": 26 * 60, "failover": 87, "rotation": 43, "bluegreen": 142}
    investigations = {
        "vendor": (
            82,
            "Зіставлено сесію підрядника з журналом підтримки. Очікується підтвердження власника фінансового акаунта.",
        ),
        "backup": (
            38,
            "Зафіксовано зміни доступу до резервного знімка. Команда даних звіряє журнал відновлення.",
        ),
        "oidc": (
            25,
            "Власник релізу підтвердив, що зміни поза заявкою. Перевіряємо час видачі сесії.",
        ),
        "workload": (
            18,
            "Підтверджено нетипове джерело сесії. Розпочато перевірку журналів робочого навантаження.",
        ),
        "s3-policy": (
            112,
            "Власник підтвердив зміну поза заявкою. Перевіряємо, які об’єкти були прочитані.",
        ),
        "function": (26, "Зіставляємо зміни функції з хешем затвердженого артефакту."),
    }

    def patch(
        status: Status, minutes: int, note: str, verdict: str | None = None
    ) -> dict[str, Any]:
        return repository.patch_incident(
            incident["id"],
            incident["version"],
            status,
            verdict,
            scenario.context_uk if verdict else None,
            note,
            min(now, detected + timedelta(minutes=minutes)),
        )

    try:
        if scenario.verdict:
            minutes = resolution.get(scenario.key, 71)
            incident = patch(
                "investigating",
                min(31, minutes // 2),
                "Тріаж завершено. Звірено CloudTrail і реєстр змін.",
            )
            patch("closed", minutes, scenario.context_uk, scenario.verdict)
        elif scenario.key in investigations:
            minutes, note = investigations[scenario.key]
            patch(
                "responded" if scenario.key == "workload" else "investigating",
                minutes,
                note,
            )
    except Conflict:
        # A concurrent operator update has priority over generated demo feedback.
        return


def replay(
    repository: Repository, now: datetime, *, refresh: bool = False
) -> dict[str, Any]:
    if repository.source != "demo":
        raise ValueError("The simulation requires the demo workspace")
    saved = repository.read_setting(PACK) or {}
    target_anchor = closed_boundary(now)
    if "summary" in saved and (
        not refresh
        or target_anchor - datetime.fromisoformat(saved["anchor"]) < timedelta(hours=24)
    ):
        return {**saved["summary"], "already_loaded": True}

    def initial_state(existing: dict[str, Any]) -> dict[str, Any]:
        if existing and (
            "summary" not in existing
            or not refresh
            or target_anchor - datetime.fromisoformat(existing["anchor"])
            < timedelta(hours=24)
        ):
            return existing
        starts = {
            Identity(**row["identity"]): row
            for row in existing.get("monitoring_starts", [])
        }
        for index, scenario in enumerate(SCENARIOS, 1):
            for actor in actors_for(scenario):
                starts.setdefault(
                    actor,
                    {
                        "identity": asdict(actor),
                        "at": exercise_hour(target_anchor, index).isoformat(),
                    },
                )
        return {
            "anchor": target_anchor.isoformat(),
            "monitoring_starts": list(starts.values()),
            "cases": existing.get("cases", {}),
        }

    state = repository.change_setting(PACK, initial_state, "simulation.started")
    if "summary" in state:
        return {**state["summary"], "already_loaded": True}
    anchor = datetime.fromisoformat(state["anchor"])
    events, inventory = build(anchor)
    repository.save_posture(inventory, now)
    imported = repository.ingest(events, now)
    run_windows = {
        (actor, exercise_hour(anchor, index)): scenario
        for index, scenario in enumerate(SCENARIOS, 1)
        for actor in actors_for(scenario)
    }
    case_labels: dict[str, dict[str, str]] = {}
    counts: dict[str, int] = {}
    for incident in repository.incidents():
        scenario = run_windows.get(
            (Identity(**incident["identity"]), datetime.fromisoformat(incident["hour"]))
        )
        if scenario is None:
            continue
        counts[scenario.key] = counts.get(scenario.key, 0) + 1
        case_labels[incident["case_id"]] = {
            "title_uk": scenario.title_uk,
            "title_en": scenario.title_en,
            "context_uk": scenario.context_uk,
            "context_en": scenario.context_en,
        }
        if incident["status"] == "new":
            advance_incident(repository, incident, scenario, now)
    summary = {
        "events": len(events),
        "inserted": imported["inserted"],
        "identities": len(inventory),
        "cases": len(case_labels),
        "incidents": counts,
        "anchor": anchor.isoformat(),
        "latest_cases": sorted(case_labels),
    }
    repository.change_setting(
        PACK,
        lambda current: (
            {
                **current,
                "cases": {**current.get("cases", {}), **case_labels},
                "summary": summary,
            }
            if current.get("anchor") == state["anchor"]
            else current
        ),
        "simulation.loaded",
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Append a fresh exercise at most once every 24 hours.",
    )
    args = parser.parse_args()
    if os.getenv("IG_SOURCE", "demo") != "demo":
        raise SystemExit("Synthetic replay is available only in the demo workspace")
    repository = Repository(
        Path(os.getenv("IG_DATABASE", "data/demo.sqlite")), trusted=CORP
    )
    print(
        json.dumps(
            replay(repository, datetime.now(UTC), refresh=args.refresh),
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
