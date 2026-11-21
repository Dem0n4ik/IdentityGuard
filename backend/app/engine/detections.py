"""Compile bounded declarative detection rules into predicates."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, Literal

import re2  # type: ignore[import-untyped]
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.engine.events import Event

Category = Literal["priv", "evasion", "secret"]
Predicate = Callable[[Mapping[str, Any]], bool]
KINDS = Literal["user", "root", "role", "sso_user", "federated"]
RULE_FIELDS = frozenset(
    (
        "event_id",
        "event_name",
        "event_time",
        "event_source",
        "event_category",
        "read_only",
        "aws_region",
        "source_ip",
        "user_agent",
        "error_code",
        "identity_id",
        "access_key_id",
        "session_name",
        "target",
        "mfa_used",
        "vpc_endpoint_id",
        "identity.name",
        "identity.kind",
        "identity.account_id",
        "account.id",
        "account.account_id",
    )
)


class InvalidRule(ValueError):
    pass


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accounts: list[Annotated[str, Field(pattern=r"^(\*|[0-9]{12})$")]] = Field(
        default_factory=lambda: ["*"], min_length=1, max_length=100
    )
    identity_kinds: list[KINDS] = Field(default_factory=list, max_length=5)


class RuleTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: dict[str, Any]
    expect: Literal["match", "no_match"]


class Definition(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,63}$")]
    name: Annotated[str, Field(min_length=1, max_length=150)]
    description: Annotated[str, Field(max_length=1000)] = ""
    category: Category
    value: Annotated[float, Field(gt=0, le=1)]
    scope: Scope = Field(default_factory=Scope)
    condition: dict[str, Any]
    tests: list[RuleTest] = Field(min_length=1, max_length=100)


def field_value(context: Mapping[str, Any], path: str) -> Any:
    node: Any = context
    for part in path.split("."):
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def test_membership(actual: Any, allowed: list[Any]) -> bool:
    return any(same(actual, value) for value in allowed)


def same(left: Any, right: Any) -> bool:
    return bool(type(left) is type(right) and left == right)


def cidr_test(value: Any, cidr: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ip_address(value) in ip_network(cidr, strict=False)
    except ValueError:
        return False


def compile_condition(node: Any, depth: int = 0) -> Predicate:
    if depth >= 8 or not isinstance(node, dict):
        raise InvalidRule(
            "condition must be an object with at most eight nested levels"
        )
    for operator in ("all", "any", "not"):
        if set(node) == {operator}:
            branch = node[operator]
            if operator == "not":
                inner = compile_condition(branch, depth + 1)
                return lambda context: not inner(context)
            if not isinstance(branch, list) or not 1 <= len(branch) <= 32:
                raise InvalidRule(f"{operator} requires 1 to 32 conditions")
            children = [compile_condition(child, depth + 1) for child in branch]
            aggregate = all if operator == "all" else any
            return lambda context: aggregate(child(context) for child in children)
    if not {"field", "op"}.issubset(node) or not set(node) <= {"field", "op", "value"}:
        raise InvalidRule("a condition requires field, op and value")
    name, operator, value = node["field"], node["op"], node.get("value")
    if not isinstance(name, str) or (
        name not in RULE_FIELDS and not name.startswith("request.")
    ):
        raise InvalidRule("unknown event field")
    if len(name) > 120 or not isinstance(operator, str):
        raise InvalidRule("invalid condition field or operator")
    if operator == "exists":
        if "value" in node and not isinstance(value, bool):
            raise InvalidRule("exists expects a boolean")
        expected = True if "value" not in node else value
        return lambda context: (field_value(context, name) is not None) is expected
    if "value" not in node:
        raise InvalidRule("condition is missing its value")
    if operator in {"eq", "ne"}:
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise InvalidRule("eq and ne require a scalar")
        return lambda context: (
            same(field_value(context, name), value) == (operator == "eq")
        )
    if operator in {"in", "not_in"}:
        if (
            not isinstance(value, list)
            or not value
            or len(value) > 100
            or not all(
                isinstance(item, (str, int, float, bool)) or item is None
                for item in value
            )
        ):
            raise InvalidRule("in and not_in require a list of up to 100 scalars")
        return lambda context: (
            test_membership(field_value(context, name), value) == (operator == "in")
        )
    if operator not in {"prefix", "not_prefix", "suffix", "contains", "regex", "cidr"}:
        raise InvalidRule("unknown operator")
    if not isinstance(value, str) or not value or len(value) > 512:
        raise InvalidRule(
            "text operators require a nonempty string of up to 512 characters"
        )
    if operator == "cidr":
        try:
            ip_network(value, strict=False)
        except ValueError:
            raise InvalidRule("invalid CIDR") from None
        return lambda context: cidr_test(field_value(context, name), value)
    if operator == "regex":
        if len(value) > 200:
            raise InvalidRule("regex cannot exceed 200 characters")
        try:
            options = re2.Options()
            options.log_errors = False
            options.max_mem = 1024 * 1024
            pattern = re2.compile(value, options=options)
        except re2.error:
            raise InvalidRule("invalid RE2 expression") from None
        return lambda context: (
            isinstance(actual := field_value(context, name), str)
            and pattern.search(actual[:4096]) is not None
        )
    return lambda context: (
        isinstance(actual := field_value(context, name), str)
        and {
            "prefix": str.startswith,
            "not_prefix": lambda text, needle: not text.startswith(needle),
            "suffix": str.endswith,
            "contains": str.__contains__,
        }[operator](actual, value)
    )


@dataclass(frozen=True, slots=True)
class Rule:
    definition: Definition
    predicate: Predicate

    def matches(self, context: Mapping[str, Any]) -> bool:
        scope = self.definition.scope
        account = (
            field_value(context, "account.id")
            or field_value(context, "account.account_id")
            or field_value(context, "identity.account_id")
        )
        kind = field_value(context, "identity.kind")
        return (
            ("*" in scope.accounts or account in scope.accounts)
            and (not scope.identity_kinds or kind in scope.identity_kinds)
            and self.predicate(context)
        )


def parse_rule(source: str) -> Rule:
    if not 1 <= len(source.encode("utf-8")) <= 32_768:
        raise InvalidRule("line 1: YAML must be 1 to 32768 bytes")
    try:
        depth = 0
        for token in yaml.scan(source):
            if isinstance(
                token,
                (yaml.tokens.AliasToken, yaml.tokens.AnchorToken, yaml.tokens.TagToken),
            ):
                raise InvalidRule(
                    f"line {token.start_mark.line + 1}: aliases, anchors and tags are unsupported"
                )
            if isinstance(
                token,
                (
                    yaml.tokens.BlockMappingStartToken,
                    yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken,
                    yaml.tokens.FlowSequenceStartToken,
                ),
            ):
                depth += 1
                if depth > 24:
                    raise InvalidRule(
                        f"line {token.start_mark.line + 1}: YAML nesting is too deep"
                    )
            elif isinstance(
                token,
                (
                    yaml.tokens.BlockEndToken,
                    yaml.tokens.FlowMappingEndToken,
                    yaml.tokens.FlowSequenceEndToken,
                ),
            ):
                depth -= 1
        root = yaml.compose(source, Loader=yaml.SafeLoader)
        if not isinstance(root, yaml.MappingNode):
            raise InvalidRule("line 1: expected a YAML object")
        lines: dict[str, int] = {}
        for key, _ in root.value:
            if isinstance(key, yaml.ScalarNode):
                if key.value in lines:
                    raise InvalidRule(
                        f"line {key.start_mark.line + 1}: duplicate field {key.value}"
                    )
                lines[key.value] = key.start_mark.line + 1
        body = Definition.model_validate(yaml.safe_load(source))
    except yaml.MarkedYAMLError as error:
        line = error.problem_mark.line + 1 if error.problem_mark else 1
        raise InvalidRule(f"line {line}: invalid YAML") from None
    except ValidationError as error:
        first = error.errors()[0]
        field = str(first["loc"][0]) if first["loc"] else ""
        raise InvalidRule(
            f"line {lines.get(field, 1)}: {field} — {first['msg']}"
        ) from None
    try:
        predicate = compile_condition(body.condition)
    except InvalidRule as error:
        raise InvalidRule(f"line {lines.get('condition', 1)}: {error}") from None
    rule = Rule(body, predicate)
    for index, test in enumerate(body.tests, 1):
        if rule.matches(test.event) != (test.expect == "match"):
            raise InvalidRule(f"line {lines.get('tests', 1)}: rule test {index} failed")
    return rule


def event_context(event: Event) -> Mapping[str, Any]:
    identity = event.identity
    return {
        "event_id": event.event_id,
        "event_name": event.name,
        "event_time": event.time.isoformat(),
        "event_source": event.source,
        "event_category": event.category,
        "read_only": event.read_only,
        "aws_region": event.region,
        "source_ip": event.source_ip,
        "user_agent": event.user_agent,
        "error_code": event.error_code,
        "identity_id": f"{identity.account_id}:{identity.kind}:{identity.name}"
        if identity
        else None,
        "access_key_id": event.access_key_id,
        "session_name": event.session_name,
        "target": event.target,
        "mfa_used": event.mfa_used,
        "vpc_endpoint_id": event.vpc_endpoint_id,
        "identity": {
            "name": identity.name,
            "kind": identity.kind,
            "account_id": identity.account_id,
        }
        if identity
        else None,
        "account": {"id": event.account_id, "account_id": event.account_id},
        "request": event.raw.get("requestParameters"),
    }
