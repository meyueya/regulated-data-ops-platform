from __future__ import annotations

import unittest
from pathlib import Path

from regulated_data_ops.contract import PAYMENT_CONTRACT, PAYMENT_CONTRACT_V2


class ContractTests(unittest.TestCase):
    def test_contract_has_stable_ordered_failure_codes(self) -> None:
        self.assertEqual(
            PAYMENT_CONTRACT.failure_codes(),
            (
                "invalid_event_id",
                "invalid_customer_email",
                "invalid_amount",
                "unsupported_currency",
                "invalid_event_time",
                "invalid_country",
                "invalid_lawful_basis",
            ),
        )

    def test_contract_fingerprint_is_stable(self) -> None:
        self.assertEqual(len(PAYMENT_CONTRACT.fingerprint), 64)
        self.assertEqual(PAYMENT_CONTRACT.fingerprint, PAYMENT_CONTRACT.fingerprint)

    def test_generated_contract_documents_governance(self) -> None:
        document = PAYMENT_CONTRACT.render_markdown()
        self.assertIn("direct_identifier", document)
        self.assertIn("Direct identifiers are never persisted", document)

    def test_committed_contract_document_is_current(self) -> None:
        root = Path(__file__).resolve().parents[1]
        committed = (
            root / "docs" / "governance" / "PAYMENT_DATA_CONTRACT.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(committed, PAYMENT_CONTRACT.render_markdown())

    def test_committed_v2_contract_document_is_current(self) -> None:
        root = Path(__file__).resolve().parents[1]
        committed = (
            root / "docs" / "governance" / "PAYMENT_DATA_CONTRACT_V2.md"
        ).read_text(encoding="utf-8")
        self.assertEqual(committed, PAYMENT_CONTRACT_V2.render_markdown())


if __name__ == "__main__":
    unittest.main()
