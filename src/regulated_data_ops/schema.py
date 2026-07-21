"""Fail-closed schema compatibility checks for contract evolution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from regulated_data_ops.contract import DataContract


@dataclass(frozen=True, slots=True)
class SchemaCompatibility:
    compatible: bool
    mode: str
    missing_required: tuple[str, ...]
    missing_optional: tuple[str, ...]
    unexpected: tuple[str, ...]
    duplicates: tuple[str, ...]

    def require_compatible(self) -> None:
        if not self.compatible:
            raise ValueError(
                "schema mismatch: "
                f"missing={self.missing_required!r}, "
                f"unexpected={self.unexpected!r}, duplicates={self.duplicates!r}"
            )


def assess_schema(
    contract: DataContract, headers: Iterable[str]
) -> SchemaCompatibility:
    actual = tuple(headers)
    accepted = contract.accepted_headers
    missing_required = tuple(
        name for name in contract.required_headers if name not in actual
    )
    missing_optional = tuple(
        field.name
        for field in contract.fields
        if not field.required and field.name not in actual
    )
    unexpected = tuple(name for name in actual if name not in accepted)
    duplicates = tuple(
        name for index, name in enumerate(actual) if name in actual[:index]
    )
    compatible = not missing_required and not unexpected and not duplicates
    mode = (
        "incompatible"
        if not compatible
        else "backward-compatible"
        if missing_optional
        else "native"
    )
    return SchemaCompatibility(
        compatible=compatible,
        mode=mode,
        missing_required=missing_required,
        missing_optional=missing_optional,
        unexpected=unexpected,
        duplicates=duplicates,
    )
