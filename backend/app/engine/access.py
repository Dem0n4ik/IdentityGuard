"""Conservative access graph with bounded shortest paths and mandatory links."""

from collections import defaultdict, deque
from collections.abc import Iterable
from datetime import datetime
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, Field

NodeKind = Literal[
    "user",
    "role",
    "group",
    "s3",
    "kms",
    "secret",
    "parameter",
    "lambda",
    "ec2",
    "ebs",
    "rds",
]
EdgeKind = Literal["can_assume", "member_of", "has_access", "runs_as", "can_escalate"]


class AccessNode(BaseModel):
    id: str
    name: str
    kind: NodeKind
    account_id: str
    critical: bool = False
    tags: dict[str, str] = Field(default_factory=dict)


class AccessEdge(BaseModel):
    id: str
    source: str
    target: str
    kind: EdgeKind
    actions: list[str] = Field(default_factory=list)


class Check(BaseModel):
    id: str
    level: Literal["critical", "high", "medium"]
    passed: bool | None


class CloudSnapshot(BaseModel):
    account_id: str
    region: str
    taken_at: datetime
    source: Literal["demo", "aws"]
    checks: list[Check]
    nodes: list[AccessNode]
    edges: list[AccessEdge]
    unavailable: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    id: str
    origin: AccessNode
    resource: AccessNode
    hops: int
    routes: list[list[AccessEdge]]
    nodes: list[AccessNode]
    key_links: list[str]


def critical(tags: dict[str, str]) -> bool:
    return tags.get("ig:critical", "").lower() == "true" or tags.get(
        "data-classification", ""
    ).lower() in {"confidential", "restricted"}


def edge(
    source: str, target: str, kind: EdgeKind, actions: Iterable[str] = ()
) -> AccessEdge:
    operations = sorted(set(actions))
    key = "\0".join((source, target, kind, *operations))
    return AccessEdge(
        id=sha256(key.encode()).hexdigest()[:24],
        source=source,
        target=target,
        kind=kind,
        actions=operations,
    )


class Graph:
    def __init__(
        self, nodes: Iterable[AccessNode], edges: Iterable[AccessEdge]
    ) -> None:
        self.nodes = {node.id: node for node in nodes}
        self.outgoing: dict[str, list[AccessEdge]] = defaultdict(list)
        for item in sorted(
            {item.id: item for item in edges}.values(),
            key=lambda item: (item.target, item.kind, item.id),
        ):
            if item.source in self.nodes and item.target in self.nodes:
                self.outgoing[item.source].append(item)

    def search(
        self,
        origin: str,
        excluded: str = "",
    ) -> tuple[dict[str, int], dict[str, list[AccessEdge]]]:
        parents: dict[str, list[AccessEdge]] = defaultdict(list)
        distance = {origin: 0}
        queue = deque((origin,))
        while queue:
            source = queue.popleft()
            if distance[source] >= 4:
                continue
            candidate = distance[source] + 1
            for item in self.outgoing[source]:
                if item.id == excluded:
                    continue
                if item.target not in distance:
                    distance[item.target] = candidate
                    queue.append(item.target)
                if distance[item.target] == candidate:
                    parents[item.target].append(item)
        return distance, parents

    def paths(self, origin: str) -> list[AttackPath]:
        if origin not in self.nodes:
            return []
        distance, parents = self.search(origin)
        resources = sorted(
            key for key in distance if key != origin and self.nodes[key].critical
        )

        def routes_to(key: str) -> Iterable[list[AccessEdge]]:
            if key == origin:
                yield []
                return
            for item in parents[key]:
                for route in routes_to(item.source):
                    yield [*route, item]

        from itertools import islice

        result = []
        for resource in resources:
            routes = list(islice(routes_to(resource), 25))
            mandatory = [
                item.id
                for item in routes[0]
                if resource not in self.search(origin, item.id)[0]
            ]
            keys = {origin, resource}
            keys.update(item.target for route in routes for item in route)
            signature = "\0".join(
                (
                    origin,
                    resource,
                    *sorted(item.id for route in routes for item in route),
                    *mandatory,
                )
            )
            result.append(
                AttackPath(
                    id=sha256(signature.encode()).hexdigest()[:24],
                    origin=self.nodes[origin],
                    resource=self.nodes[resource],
                    hops=distance[resource],
                    routes=routes,
                    nodes=[self.nodes[key] for key in sorted(keys)],
                    key_links=mandatory,
                )
            )
        return sorted(result, key=lambda path: (path.hops, path.resource.name, path.id))
