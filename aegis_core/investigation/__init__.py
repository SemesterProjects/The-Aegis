"""Investigation Agent sub-package for Aegis Core.

Sits on top of the existing Monitoring -> Evidence -> Detection/Triage pipeline.
Read-only.  Never executes remediation.
"""
from .agent import InvestigationAgent
from .result import (
    InvestigationResult,
    InvestigationStatus,
    Classification,
    InvestigationCoverage,
    ActivityChainStep,
    AttackTechnique,
    EvidenceRelationship,
    IOC,
)
from .state import (
    InvestigationState,
    Hypothesis,
    InvestigationBudget,
    InvestigationAction,
    StopReason,
    EvidenceCoverage,
)
from .tools import InvestigationTools

__all__ = [
    "InvestigationAgent",
    "InvestigationResult",
    "InvestigationStatus",
    "Classification",
    "InvestigationCoverage",
    "ActivityChainStep",
    "AttackTechnique",
    "EvidenceRelationship",
    "IOC",
    "InvestigationState",
    "Hypothesis",
    "InvestigationBudget",
    "InvestigationAction",
    "StopReason",
    "EvidenceCoverage",
    "InvestigationTools",
]
