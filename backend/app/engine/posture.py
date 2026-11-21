from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase

from app.engine.events import Identity

ESCALATION_PATHS = (
    ("iam:CreatePolicyVersion",),
    ("iam:SetDefaultPolicyVersion",),
    ("iam:AttachUserPolicy",),
    ("iam:AttachGroupPolicy",),
    ("iam:AttachRolePolicy", "sts:AssumeRole"),
    ("iam:PutUserPolicy",),
    ("iam:PutGroupPolicy",),
    ("iam:PutRolePolicy", "sts:AssumeRole"),
    ("iam:AddUserToGroup",),
    ("iam:CreateAccessKey",),
    ("iam:CreateLoginProfile",),
    ("iam:UpdateLoginProfile",),
    ("iam:UpdateAssumeRolePolicy", "sts:AssumeRole"),
    ("iam:PassRole", "ec2:RunInstances"),
    ("iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"),
    ("iam:PassRole", "cloudformation:CreateStack"),
    ("iam:PassRole", "glue:CreateDevEndpoint"),
    ("lambda:UpdateFunctionCode",),
)


def escalation_paths(actions: frozenset[str]) -> tuple[int, ...]:
    if actions & {"*", "*:*"}:
        return ()
    patterns = tuple(action.lower() for action in actions)
    return tuple(
        index
        for index, required in enumerate(ESCALATION_PATHS, start=1)
        if all(
            any(fnmatchcase(action.lower(), pattern) for pattern in patterns)
            for action in required
        )
    )


@dataclass(frozen=True, slots=True)
class Snapshot:
    taken_at: datetime
    mfa_enabled: bool | None = None
    active_key_age_days: float | None = None
    actions: frozenset[str] = frozenset()
    critical: bool = False
    external_trust: bool = False
    imds_v1: bool = False
    unused_services_ratio: float | None = None
    last_used_days: float | None = None
    workload: bool = False

    def facts(self, identity: Identity) -> frozenset[str]:
        return frozenset(
            name
            for name, applies in {
                "no_mfa": identity.kind in {"user", "root"}
                and self.mfa_enabled is False,
                "old_key": self.active_key_age_days is not None
                and self.active_key_age_days > 90,
                "privileged": bool(self.actions & {"*", "*:*"}),
                "escalation": bool(escalation_paths(self.actions)),
                "critical": self.critical,
                "external_trust": identity.kind == "role" and self.external_trust,
                "imds_v1": identity.kind == "role" and self.imds_v1,
                "excessive_perms": self.unused_services_ratio is not None
                and self.unused_services_ratio > 0.5,
            }.items()
            if applies
        )
