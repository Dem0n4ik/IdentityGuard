from collections.abc import Mapping
from dataclasses import dataclass
from math import fsum, isfinite
from types import MappingProxyType

import numpy as np

INDICATORS = ("geo", "ip", "time", "seq", "vol", "priv", "evasion", "secret")
CORE_MATRIX = (
    (1, 2, 3, 1 / 2, 4, 1 / 3, 1 / 4, 1 / 2),
    (1 / 2, 1, 2, 1 / 3, 3, 1 / 4, 1 / 5, 1 / 3),
    (1 / 3, 1 / 2, 1, 1 / 4, 2, 1 / 5, 1 / 6, 1 / 4),
    (2, 3, 4, 1, 5, 1 / 2, 1 / 3, 1),
    (1 / 4, 1 / 3, 1 / 2, 1 / 5, 1, 1 / 6, 1 / 7, 1 / 5),
    (3, 4, 5, 2, 6, 1, 1 / 2, 2),
    (4, 5, 6, 3, 7, 2, 1, 3),
    (2, 3, 4, 1, 5, 1 / 2, 1 / 3, 1),
)
DORMANT_ROW = (2, 3, 4, 1, 5, 1 / 2, 1 / 3, 1, 1, 1 / 3)
WEXFIL_ROW = (4, 5, 6, 3, 7, 2, 1, 3, 3, 1)
CLOUD_MATRIX = tuple(
    row + (1 / DORMANT_ROW[index], 1 / WEXFIL_ROW[index])
    for index, row in enumerate(CORE_MATRIX)
) + (DORMANT_ROW, WEXFIL_ROW)

CORE_PRIV = frozenset(
    [
        "CreateAccessKey",
        "AttachUserPolicy",
        "CreateLoginProfile",
        "PutUserPolicy",
        "UpdateAssumeRolePolicy",
        "CreatePolicyVersion",
        "CreateUser",
        "PutBucketPolicy",
        "AttachRolePolicy",
    ]
)
CORE_EVASION = frozenset(("StopLogging", "DeleteTrail", "UpdateTrail"))
CORE_SECRET = frozenset(("GetSecretValue",))
CLOUD_PRIV = CORE_PRIV | frozenset(
    [
        "PutRolePolicy",
        "AttachGroupPolicy",
        "PutGroupPolicy",
        "AddUserToGroup",
        "SetDefaultPolicyVersion",
        "UpdateLoginProfile",
        "CreateRole",
        "UpdateFunctionCode",
        "UpdateFunctionConfiguration",
        "PublishLayerVersion",
        "CreateTrustAnchor",
        "CreateProfile",
        "ModifySnapshotAttribute",
        "ModifyImageAttribute",
        "ModifyDBSnapshotAttribute",
        "AuthorizeSecurityGroupIngress",
        "SendSSHPublicKey",
        "SendSerialConsoleSSHPublicKey",
    ]
)
CLOUD_EVASION = CORE_EVASION | frozenset(
    [
        "PutEventSelectors",
        "DeleteFlowLogs",
        "DeleteResolverQueryLogConfig",
        "DeleteDetector",
        "DisableAWSServiceAccess",
        "LeaveOrganization",
        "DeleteLogGroup",
        "StopConfigurationRecorder",
    ]
)
CLOUD_SECRET = CORE_SECRET | {"BatchGetSecretValue", "GetPasswordData"}
DECRYPT_OPERATIONS = frozenset(("GetParameter", "GetParameters", "GetParametersByPath"))

CORE_FACTS = {
    "no_mfa": 0.25,
    "old_key": 0.20,
    "privileged": 0.25,
    "critical": 0.20,
    "thin_baseline": 0.10,
}
CLOUD_FACTS = {
    "no_mfa": 0.16,
    "old_key": 0.10,
    "privileged": 0.14,
    "escalation": 0.12,
    "critical": 0.10,
    "external_trust": 0.08,
    "imds_v1": 0.08,
    "excessive_perms": 0.06,
    "risky_source": 0.10,
    "thin_baseline": 0.06,
}


@dataclass(frozen=True, slots=True)
class AHPResult:
    weights: tuple[float, ...]
    eigenvalue: float
    consistency_index: float
    consistency_ratio: float


def calculate_ahp(matrix: tuple[tuple[float, ...], ...]) -> AHPResult:
    size = len(matrix)
    if size not in (8, 10) or any(len(row) != size for row in matrix):
        raise ValueError("AHP requires a square 8×8 or 10×10 matrix")
    values = np.asarray(matrix, dtype=np.float64)
    if (
        not np.isfinite(values).all()
        or (values <= 0).any()
        or not np.allclose(np.diag(values), 1, rtol=0, atol=1e-12)
        or not np.allclose(values * values.T, 1, rtol=0, atol=1e-12)
    ):
        raise ValueError(
            "AHP matrix must be positive and reciprocal with a unit diagonal"
        )
    eigenvalues, vectors = np.linalg.eig(values)
    index = int(np.argmax(eigenvalues.real))
    eigenvalue = float(eigenvalues[index].real)
    vector = np.abs(vectors[:, index].real)
    weights = tuple(float(weight) for weight in vector / vector.sum())
    ci = max(0.0, (eigenvalue - size) / (size - 1))
    return AHPResult(weights, eigenvalue, ci, ci / {8: 1.41, 10: 1.49}[size])


def require_consistent_matrix(matrix: tuple[tuple[float, ...], ...]) -> AHPResult:
    result = calculate_ahp(matrix)
    if result.consistency_ratio >= 0.1:
        raise ValueError("AHP consistency ratio must be below 0.1")
    return result


@dataclass(frozen=True, slots=True)
class Model:
    version: str
    weights: Mapping[str, float]
    facts: Mapping[str, float]
    priv: frozenset[str]
    evasion: frozenset[str]
    secret: frozenset[str]
    thr_mid: float = 25
    thr_high: float = 50


def normalized(
    keys: tuple[str, ...], weights: tuple[float, ...]
) -> Mapping[str, float]:
    if not weights or any(not isfinite(weight) or weight <= 0 for weight in weights):
        raise ValueError("Indicator weights must be positive and finite")
    return MappingProxyType(
        dict(zip(keys, (weight / fsum(weights) for weight in weights), strict=True))
    )


def matrix_weights(
    keys: tuple[str, ...], matrix: tuple[tuple[float, ...], ...]
) -> Mapping[str, float]:
    return MappingProxyType(
        dict(zip(keys, require_consistent_matrix(matrix).weights, strict=True))
    )


CORE = Model(
    "core-v1",
    matrix_weights(INDICATORS, CORE_MATRIX),
    MappingProxyType(CORE_FACTS),
    CORE_PRIV,
    CORE_EVASION,
    CORE_SECRET,
)
CLOUD = Model(
    "cloud-v2",
    matrix_weights(INDICATORS + ("dormant", "wexfil"), CLOUD_MATRIX),
    MappingProxyType(CLOUD_FACTS),
    CLOUD_PRIV,
    CLOUD_EVASION,
    CLOUD_SECRET,
)
MODELS = MappingProxyType({CORE.version: CORE, CLOUD.version: CLOUD})
