from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Network,
    collapse_addresses,
    ip_address,
    ip_network,
)
from typing import Any

Network = IPv4Network | IPv6Network

INTERNAL = tuple(
    ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fd00::/8",
        "::1/128",
        "fe80::/10",
    )
)


def aws_public_networks(document: Mapping[str, Any]) -> tuple[Network, ...]:
    networks: list[Network] = []
    for group, prefix_key, version in (
        ("prefixes", "ip_prefix", 4),
        ("ipv6_prefixes", "ipv6_prefix", 6),
    ):
        ranges = document.get(group)
        if not isinstance(ranges, list) or not ranges:
            raise ValueError("Expected both AWS IPv4 and IPv6 ranges")
        for item in ranges:
            if not isinstance(item, dict) or not isinstance(item.get(prefix_key), str):
                raise TypeError("Invalid AWS IP range")
            network = ip_network(item[prefix_key])
            if network.version != version or not network.prefixlen:
                raise ValueError("Invalid AWS IP range")
            networks.append(network)
    return (
        *collapse_addresses(n for n in networks if isinstance(n, IPv4Network)),
        *collapse_addresses(n for n in networks if isinstance(n, IPv6Network)),
    )


def hour_start(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("Event time must have a timezone")
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def source_prefix(value: str) -> str:
    try:
        address = ip_address(value)
    except ValueError:
        return value
    if isinstance(address, IPv4Address):
        return str(address).rsplit(".", 1)[0]
    if address.ipv4_mapped:
        return str(address.ipv4_mapped).rsplit(".", 1)[0]
    return str(ip_network((address, 64), strict=False))


def outside_networks(value: str, trusted: tuple[Network, ...]) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    if not isinstance(address, IPv4Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        not (address.is_unspecified or address.is_multicast or address.is_reserved)
        and not any(address in net for net in INTERNAL)
        and not any(address in net for net in trusted)
    )


@dataclass(frozen=True, order=True, slots=True)
class Identity:
    account_id: str
    kind: str
    name: str


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    time: datetime
    account_id: str
    name: str
    region: str
    source_ip: str
    identity: Identity | None
    source: str = ""
    category: str = "Management"
    read_only: bool | None = None
    user_agent: str = ""
    error_code: str = ""
    access_key_id: str = ""
    session_name: str = ""
    target: str = ""
    mfa_used: bool | None = None
    vpc_endpoint_id: str = ""
    with_decryption: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def hour(self) -> datetime:
        return hour_start(self.time)
