"""Versioned RBAC and retention policy for the regulated operations plane."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


KNOWN_PERMISSIONS = frozenset(
    {
        "status:read",
        "trust:read",
        "sources:read",
        "policy:read",
        "lineage:read",
        "ingestion:create",
        "governance:read",
        "audit:read",
        "retention:preview",
        "retention:execute",
    }
)


@dataclass(frozen=True, slots=True)
class Principal:
    actor_id: str
    display_name: str
    role: str
    key_sha256: str
    enabled: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "actor_id": self.actor_id,
            "display_name": self.display_name,
            "role": self.role,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    accepted_payment_days: int
    quarantine_days: int

    def __post_init__(self) -> None:
        for name, value in (
            ("accepted_payment_days", self.accepted_payment_days),
            ("quarantine_days", self.quarantine_days),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class GovernancePolicy:
    version: str
    roles: Mapping[str, tuple[str, ...]]
    principals: tuple[Principal, ...]
    retention: RetentionPolicy

    @classmethod
    def load(cls, path: str | Path) -> "GovernancePolicy":
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        if not isinstance(payload, Mapping):
            raise ValueError("governance policy root must be an object")
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "GovernancePolicy":
        _require_keys(
            payload,
            {"policy_version", "roles", "principals", "retention"},
            "governance policy",
        )
        version = payload["policy_version"]
        roles_payload = payload["roles"]
        principals_payload = payload["principals"]
        retention_payload = payload["retention"]
        if not isinstance(version, str) or not version.strip():
            raise ValueError("policy_version must be a non-empty string")
        if not isinstance(roles_payload, Mapping) or not roles_payload:
            raise ValueError("roles must be a non-empty object")
        if not isinstance(principals_payload, list) or not principals_payload:
            raise ValueError("principals must be a non-empty array")
        if not isinstance(retention_payload, Mapping):
            raise ValueError("retention must be an object")

        roles: dict[str, tuple[str, ...]] = {}
        for role, permissions in roles_payload.items():
            if not isinstance(role, str) or not role.strip():
                raise ValueError("role names must be non-empty strings")
            if (
                not isinstance(permissions, list)
                or not permissions
                or any(not isinstance(item, str) for item in permissions)
            ):
                raise ValueError(f"role {role!r} must contain permissions")
            permission_tuple = tuple(permissions)
            if len(set(permission_tuple)) != len(permission_tuple):
                raise ValueError(f"role {role!r} contains duplicate permissions")
            unknown = set(permission_tuple) - KNOWN_PERMISSIONS
            if unknown:
                raise ValueError(f"role {role!r} has unknown permissions: {sorted(unknown)!r}")
            roles[role] = permission_tuple

        principals: list[Principal] = []
        for raw in principals_payload:
            if not isinstance(raw, Mapping):
                raise ValueError("each principal must be an object")
            _require_keys(
                raw,
                {"actor_id", "display_name", "role", "key_sha256", "enabled"},
                "principal",
            )
            actor_id = _non_empty_string(raw, "actor_id")
            display_name = _non_empty_string(raw, "display_name")
            role = _non_empty_string(raw, "role")
            key_sha256 = _non_empty_string(raw, "key_sha256").lower()
            enabled = raw["enabled"]
            if role not in roles:
                raise ValueError(f"principal {actor_id!r} references unknown role {role!r}")
            if len(key_sha256) != 64 or any(char not in "0123456789abcdef" for char in key_sha256):
                raise ValueError("key_sha256 must be a 64-character lowercase hex digest")
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be boolean")
            principals.append(
                Principal(actor_id, display_name, role, key_sha256, enabled)
            )

        actor_ids = [item.actor_id for item in principals]
        key_hashes = [item.key_sha256 for item in principals]
        if len(set(actor_ids)) != len(actor_ids):
            raise ValueError("principal actor_id values must be unique")
        if len(set(key_hashes)) != len(key_hashes):
            raise ValueError("principal key_sha256 values must be unique")

        _require_keys(
            retention_payload,
            {"accepted_payment_days", "quarantine_days"},
            "retention",
        )
        retention = RetentionPolicy(
            accepted_payment_days=_positive_integer(
                retention_payload, "accepted_payment_days"
            ),
            quarantine_days=_positive_integer(retention_payload, "quarantine_days"),
        )
        return cls(version, roles, tuple(principals), retention)

    def authenticate(self, supplied_key: str) -> Principal | None:
        candidate = hashlib.sha256(supplied_key.encode("utf-8")).hexdigest()
        matched: Principal | None = None
        for principal in self.principals:
            if secrets.compare_digest(candidate, principal.key_sha256):
                matched = principal
        return matched if matched is not None and matched.enabled else None

    def permissions_for(self, principal: Principal) -> tuple[str, ...]:
        return self.roles.get(principal.role, ())

    def permits(self, principal: Principal, permission: str) -> bool:
        return principal.enabled and permission in self.permissions_for(principal)

    def as_dict(self, *, include_key_hashes: bool = True) -> dict[str, object]:
        principals = []
        for principal in self.principals:
            item = principal.public_dict()
            if include_key_hashes:
                item["key_sha256"] = principal.key_sha256
            principals.append(item)
        return {
            "policy_version": self.version,
            "roles": {name: list(values) for name, values in self.roles.items()},
            "principals": principals,
            "retention": {
                "accepted_payment_days": self.retention.accepted_payment_days,
                "quarantine_days": self.retention.quarantine_days,
            },
        }

    def public_dict(self) -> dict[str, object]:
        return self.as_dict(include_key_hashes=False) | {"fingerprint": self.fingerprint}

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _require_keys(
    mapping: Mapping[str, object], expected: set[str], section: str
) -> None:
    if set(mapping) != expected:
        raise ValueError(
            f"{section} keys mismatch: expected={sorted(expected)!r}, "
            f"actual={sorted(mapping)!r}"
        )


def _non_empty_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{key} must be a trimmed non-empty string")
    return value


def _positive_integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{key} must be a positive integer")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate governance policy key: {key}")
        result[key] = value
    return result
