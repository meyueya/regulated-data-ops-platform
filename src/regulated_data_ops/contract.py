"""Versioned payment-event contract.

Modified work notice: the immutable, ordered-rule structure is adapted from
scripts/data_contract.py in the MIT-licensed
theofanis-tsakanikas/contract-driven-data-pipeline project at commit
5f422adeb31743a73a78f9eab5e58ed5b7f32adf.

Changed by Pedro Castillo in 2026: domain, vocabulary, validation semantics,
sensitivity model, fingerprint and documentation format were replaced.
No source lines were copied verbatim.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum


class Sensitivity(StrEnum):
    OPERATIONAL = "operational"
    DIRECT_IDENTIFIER = "direct_identifier"
    FINANCIAL = "financial"
    QUASI_IDENTIFIER = "quasi_identifier"
    GOVERNANCE = "governance"


class RuleType(StrEnum):
    UUID = "uuid"
    EMAIL = "email"
    MONEY = "money"
    ENUM = "enum"
    TIMESTAMP = "timestamp"
    COUNTRY = "country"


@dataclass(frozen=True, slots=True)
class FieldRule:
    name: str
    rule_type: RuleType
    sensitivity: Sensitivity
    failure_code: str
    description: str
    choices: tuple[str, ...] = ()
    minimum: str | None = None
    maximum: str | None = None


@dataclass(frozen=True, slots=True)
class DataContract:
    name: str
    version: str
    fields: tuple[FieldRule, ...]

    @property
    def required_headers(self) -> tuple[str, ...]:
        return tuple(field.name for field in self.fields)

    @property
    def fingerprint(self) -> str:
        payload = {
            "name": self.name,
            "version": self.version,
            "fields": [asdict(field) for field in self.fields],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def failure_codes(self) -> tuple[str, ...]:
        return tuple(field.failure_code for field in self.fields)

    def render_markdown(self) -> str:
        rows = [
            (
                f"| {field.name} | {field.rule_type.value} | "
                f"{field.sensitivity.value} | {field.failure_code} |"
            )
            for field in self.fields
        ]
        return "\n".join(
            [
                f"# Data contract — {self.name} v{self.version}",
                "",
                f"Contract fingerprint: {self.fingerprint}",
                "",
                "| Field | Rule | Sensitivity | Failure code |",
                "| --- | --- | --- | --- |",
                *rows,
                "",
                "Rows failing a rule are quarantined using the first failure code",
                "in contract order. Direct identifiers are never persisted in clear.",
                "",
            ]
        )


PAYMENT_CONTRACT = DataContract(
    name="regulated-payment-events",
    version="1.0.0",
    fields=(
        FieldRule(
            "event_id",
            RuleType.UUID,
            Sensitivity.OPERATIONAL,
            "invalid_event_id",
            "Stable idempotency identifier.",
        ),
        FieldRule(
            "customer_email",
            RuleType.EMAIL,
            Sensitivity.DIRECT_IDENTIFIER,
            "invalid_customer_email",
            "Synthetic subject address; pseudonymized before persistence.",
        ),
        FieldRule(
            "amount",
            RuleType.MONEY,
            Sensitivity.FINANCIAL,
            "invalid_amount",
            "Positive amount with at most two decimal places.",
            minimum="0.01",
            maximum="100000.00",
        ),
        FieldRule(
            "currency",
            RuleType.ENUM,
            Sensitivity.FINANCIAL,
            "unsupported_currency",
            "Permitted ISO-4217 currency.",
            choices=("EUR", "USD", "GBP"),
        ),
        FieldRule(
            "event_time",
            RuleType.TIMESTAMP,
            Sensitivity.OPERATIONAL,
            "invalid_event_time",
            "ISO-8601 timestamp with explicit timezone.",
        ),
        FieldRule(
            "country",
            RuleType.COUNTRY,
            Sensitivity.QUASI_IDENTIFIER,
            "invalid_country",
            "Uppercase ISO-3166 alpha-2 shape.",
        ),
        FieldRule(
            "lawful_basis",
            RuleType.ENUM,
            Sensitivity.GOVERNANCE,
            "invalid_lawful_basis",
            "Declared processing basis for the synthetic event.",
            choices=("contract", "consent", "legal_obligation"),
        ),
    ),
)
