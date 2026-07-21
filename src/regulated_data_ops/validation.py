"""Pure contract validation and privacy-preserving normalization."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Mapping
from uuid import UUID

from regulated_data_ops.contract import DataContract, FieldRule, RuleType

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COUNTRY_PATTERN = re.compile(r"^[A-Z]{2}$")


def _valid(rule: FieldRule, value: str) -> bool:
    value = value.strip()
    if rule.rule_type == RuleType.UUID:
        try:
            UUID(value)
            return True
        except (ValueError, AttributeError):
            return False
    if rule.rule_type == RuleType.EMAIL:
        return bool(EMAIL_PATTERN.fullmatch(value))
    if rule.rule_type == RuleType.MONEY:
        try:
            amount = Decimal(value)
            minimum = Decimal(rule.minimum or "0")
            maximum = Decimal(rule.maximum or "Infinity")
            decimals = max(0, -amount.as_tuple().exponent)
            return amount.is_finite() and minimum <= amount <= maximum and decimals <= 2
        except InvalidOperation:
            return False
    if rule.rule_type == RuleType.ENUM:
        return value in rule.choices
    if rule.rule_type == RuleType.TIMESTAMP:
        try:
            return datetime.fromisoformat(value).tzinfo is not None
        except ValueError:
            return False
    if rule.rule_type == RuleType.COUNTRY:
        return bool(COUNTRY_PATTERN.fullmatch(value))
    raise ValueError(f"unsupported rule type: {rule.rule_type}")


def validate_row(contract: DataContract, row: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        rule.failure_code
        for rule in contract.fields
        if not _valid(rule, row.get(rule.name, ""))
    )


def subject_token(email: str, key: bytes) -> str:
    canonical = email.strip().casefold().encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def row_fingerprint(row: Mapping[str, str], key: bytes) -> str:
    canonical = json.dumps(dict(row), sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def normalized_payment(row: Mapping[str, str], key: bytes) -> dict[str, object]:
    return {
        "event_id": str(UUID(row["event_id"].strip())),
        "subject_token": subject_token(row["customer_email"], key),
        "amount_minor": int(Decimal(row["amount"].strip()) * 100),
        "currency": row["currency"].strip(),
        "event_time": datetime.fromisoformat(row["event_time"].strip()).isoformat(),
        "country": row["country"].strip(),
        "lawful_basis": row["lawful_basis"].strip(),
    }
