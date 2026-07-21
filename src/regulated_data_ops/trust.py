"""Versioned operational policy and deterministic SLO evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True, slots=True)
class RulePolicy:
    allowed_currencies: tuple[str, ...]
    allowed_lawful_bases: tuple[str, ...]
    maximum_amount: str
    allowed_source_systems: tuple[str, ...]

    def __post_init__(self) -> None:
        for name, values in (
            ("allowed_currencies", self.allowed_currencies),
            ("allowed_lawful_bases", self.allowed_lawful_bases),
            ("allowed_source_systems", self.allowed_source_systems),
        ):
            if not values or len(set(values)) != len(values):
                raise ValueError(f"{name} must contain unique non-empty values")
            if any(not value or value.strip() != value for value in values):
                raise ValueError(f"{name} contains an invalid value")
        try:
            amount = Decimal(self.maximum_amount)
        except InvalidOperation as exc:
            raise ValueError("maximum_amount must be a decimal") from exc
        if not amount.is_finite() or amount <= 0:
            raise ValueError("maximum_amount must be finite and positive")


@dataclass(frozen=True, slots=True)
class SLOPolicy:
    minimum_valid_rate: float
    maximum_quarantine_rate: float
    maximum_run_duration_ms: int
    minimum_total_rows: int

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_valid_rate <= 1:
            raise ValueError("minimum_valid_rate must be between 0 and 1")
        if not 0 <= self.maximum_quarantine_rate <= 1:
            raise ValueError("maximum_quarantine_rate must be between 0 and 1")
        if self.maximum_run_duration_ms <= 0:
            raise ValueError("maximum_run_duration_ms must be positive")
        if self.minimum_total_rows < 1:
            raise ValueError("minimum_total_rows must be at least 1")


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    version: str
    rules: RulePolicy
    slo: SLOPolicy

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "TrustPolicy":
        expected = {"policy_version", "rules", "slo"}
        if set(payload) != expected:
            raise ValueError(
                f"policy keys mismatch: expected={sorted(expected)!r}, "
                f"actual={sorted(payload)!r}"
            )
        version = payload["policy_version"]
        rules = payload["rules"]
        slo = payload["slo"]
        if not isinstance(version, str) or not version.strip():
            raise ValueError("policy_version must be a non-empty string")
        if not isinstance(rules, Mapping) or not isinstance(slo, Mapping):
            raise ValueError("rules and slo must be objects")
        _require_keys(
            rules,
            {
                "allowed_currencies",
                "allowed_lawful_bases",
                "maximum_amount",
                "allowed_source_systems",
            },
            "rules",
        )
        _require_keys(
            slo,
            {
                "minimum_valid_rate",
                "maximum_quarantine_rate",
                "maximum_run_duration_ms",
                "minimum_total_rows",
            },
            "slo",
        )
        return cls(
            version=version,
            rules=RulePolicy(
                allowed_currencies=_string_tuple(rules, "allowed_currencies"),
                allowed_lawful_bases=_string_tuple(
                    rules, "allowed_lawful_bases"
                ),
                maximum_amount=_string(rules, "maximum_amount"),
                allowed_source_systems=_string_tuple(
                    rules, "allowed_source_systems"
                ),
            ),
            slo=SLOPolicy(
                minimum_valid_rate=_rate(slo, "minimum_valid_rate"),
                maximum_quarantine_rate=_rate(
                    slo, "maximum_quarantine_rate"
                ),
                maximum_run_duration_ms=_integer(
                    slo, "maximum_run_duration_ms"
                ),
                minimum_total_rows=_integer(slo, "minimum_total_rows"),
            ),
        )

    @classmethod
    def load(cls, path: str | Path) -> "TrustPolicy":
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        if not isinstance(payload, Mapping):
            raise ValueError("policy root must be an object")
        return cls.from_mapping(payload)

    def as_dict(self) -> dict[str, object]:
        return {
            "policy_version": self.version,
            "rules": {
                "allowed_currencies": list(self.rules.allowed_currencies),
                "allowed_lawful_bases": list(
                    self.rules.allowed_lawful_bases
                ),
                "maximum_amount": self.rules.maximum_amount,
                "allowed_source_systems": list(
                    self.rules.allowed_source_systems
                ),
            },
            "slo": asdict(self.slo),
        }

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustEvaluation:
    status: str
    valid_rate: float
    quarantine_rate: float
    breaches: tuple[str, ...]


def evaluate_trust(
    policy: TrustPolicy,
    *,
    run_status: str,
    total_rows: int,
    accepted_rows: int,
    quarantined_rows: int,
    duplicate_rows: int,
    duration_ms: int,
) -> TrustEvaluation:
    valid_rows = accepted_rows + duplicate_rows
    valid_rate = valid_rows / total_rows if total_rows else 0.0
    quarantine_rate = quarantined_rows / total_rows if total_rows else 0.0
    breaches: list[str] = []
    if run_status != "succeeded":
        breaches.append("run_failed")
    if total_rows < policy.slo.minimum_total_rows:
        breaches.append("minimum_total_rows")
    if total_rows and valid_rate < policy.slo.minimum_valid_rate:
        breaches.append("minimum_valid_rate")
    if total_rows and quarantine_rate > policy.slo.maximum_quarantine_rate:
        breaches.append("maximum_quarantine_rate")
    if duration_ms > policy.slo.maximum_run_duration_ms:
        breaches.append("maximum_run_duration_ms")
    return TrustEvaluation(
        status="passing" if not breaches else "breached",
        valid_rate=round(valid_rate, 6),
        quarantine_rate=round(quarantine_rate, 6),
        breaches=tuple(breaches),
    )


def _string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _string_tuple(mapping: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = mapping.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{key} must be a string array")
    return tuple(value)


def _rate(mapping: Mapping[str, object], key: str) -> float:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be numeric")
    return float(value)


def _integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _require_keys(
    mapping: Mapping[str, object], expected: set[str], section: str
) -> None:
    if set(mapping) != expected:
        raise ValueError(
            f"{section} keys mismatch: expected={sorted(expected)!r}, "
            f"actual={sorted(mapping)!r}"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate policy key: {key}")
        result[key] = value
    return result


DEFAULT_TRUST_POLICY = TrustPolicy.from_mapping(
    {
        "policy_version": "2.0.0",
        "rules": {
            "allowed_currencies": ["EUR", "USD", "GBP"],
            "allowed_lawful_bases": [
                "contract",
                "consent",
                "legal_obligation",
            ],
            "maximum_amount": "100000.00",
            "allowed_source_systems": [
                "legacy",
                "core-banking",
                "fraud-screening",
            ],
        },
        "slo": {
            "minimum_valid_rate": 0.95,
            "maximum_quarantine_rate": 0.05,
            "maximum_run_duration_ms": 5000,
            "minimum_total_rows": 1,
        },
    }
)
