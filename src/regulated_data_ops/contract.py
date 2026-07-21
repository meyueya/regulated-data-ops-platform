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

from regulated_data_ops.trust import DEFAULT_TRUST_POLICY, TrustPolicy


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
    required: bool = True
    default: str | None = None


@dataclass(frozen=True, slots=True)
class DataContract:
    name: str
    version: str
    fields: tuple[FieldRule, ...]

    @property
    def required_headers(self) -> tuple[str, ...]:
        return tuple(field.name for field in self.fields if field.required)

    @property
    def accepted_headers(self) -> tuple[str, ...]:
        return tuple(field.name for field in self.fields)

    @property
    def fingerprint(self) -> str:
        fields = []
        for field in self.fields:
            serialized = asdict(field)
            # Preserve the V1 canonical representation and therefore its
            # historical fingerprint while allowing V2 optional metadata.
            if field.required:
                serialized.pop("required")
            if field.default is None:
                serialized.pop("default")
            fields.append(serialized)
        payload = {
            "name": self.name,
            "version": self.version,
            "fields": fields,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def failure_codes(self) -> tuple[str, ...]:
        return tuple(field.failure_code for field in self.fields)

    def render_markdown(self) -> str:
        rows = [
            (
                f"| {field.name} | {field.rule_type.value} | "
                f"{field.sensitivity.value} | {str(field.required).lower()} | "
                f"{field.default or '—'} | {field.failure_code} |"
            )
            for field in self.fields
        ]
        return "\n".join(
            [
                f"# Data contract — {self.name} v{self.version}",
                "",
                f"Contract fingerprint: {self.fingerprint}",
                "",
                "| Field | Rule | Sensitivity | Required | Default | Failure code |",
                "| --- | --- | --- | --- | --- | --- |",
                *rows,
                "",
                "Rows failing a rule are quarantined using the first failure code",
                "in contract order. Direct identifiers are never persisted in clear.",
                "",
            ]
        )


PAYMENT_CONTRACT_V1 = DataContract(
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


def payment_contract_for_policy(policy: TrustPolicy) -> DataContract:
    """Build V2 while preserving the complete required V1 header set."""

    fields = list(PAYMENT_CONTRACT_V1.fields)
    for index, field in enumerate(fields):
        if field.name == "amount":
            fields[index] = FieldRule(
                field.name,
                field.rule_type,
                field.sensitivity,
                field.failure_code,
                field.description,
                choices=field.choices,
                minimum=field.minimum,
                maximum=policy.rules.maximum_amount,
            )
        elif field.name == "currency":
            fields[index] = FieldRule(
                field.name,
                field.rule_type,
                field.sensitivity,
                field.failure_code,
                field.description,
                choices=policy.rules.allowed_currencies,
            )
        elif field.name == "lawful_basis":
            fields[index] = FieldRule(
                field.name,
                field.rule_type,
                field.sensitivity,
                field.failure_code,
                field.description,
                choices=policy.rules.allowed_lawful_bases,
            )
    fields.append(
        FieldRule(
            "source_system",
            RuleType.ENUM,
            Sensitivity.OPERATIONAL,
            "unsupported_source_system",
            "Optional producer identity added in V2; legacy is the safe default.",
            choices=policy.rules.allowed_source_systems,
            required=False,
            default="legacy",
        )
    )
    return DataContract(
        name=PAYMENT_CONTRACT_V1.name,
        version="2.0.0",
        fields=tuple(fields),
    )


PAYMENT_CONTRACT_V2 = payment_contract_for_policy(DEFAULT_TRUST_POLICY)

# Public V1 alias retained so existing importers and generated V1 evidence remain valid.
PAYMENT_CONTRACT = PAYMENT_CONTRACT_V1
