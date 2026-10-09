"""Public interface for Regulated Data Ops Platform V4."""

__version__ = "4.0.0"

from regulated_data_ops.contract import (
    PAYMENT_CONTRACT,
    PAYMENT_CONTRACT_V1,
    PAYMENT_CONTRACT_V2,
    DataContract,
)
from regulated_data_ops.pipeline import IngestionPipeline, RunReport
from regulated_data_ops.governance import GovernancePolicy, Principal
from regulated_data_ops.trust import TrustPolicy

__all__ = [
    "DataContract",
    "IngestionPipeline",
    "GovernancePolicy",
    "PAYMENT_CONTRACT",
    "PAYMENT_CONTRACT_V1",
    "PAYMENT_CONTRACT_V2",
    "RunReport",
    "Principal",
    "TrustPolicy",
    "__version__",
]
