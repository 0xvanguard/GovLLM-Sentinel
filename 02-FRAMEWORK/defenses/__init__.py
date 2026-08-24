"""
Defenses Module - GovLLM-Sentinel

Módulos de defensa para proteger modelos LLM en entornos gubernamentales.

Componentes:
- PII Guard: Filtrado de datos de identificación personal
- Compliance Filter: Detección de secretos de Estado y manipulación geopolítica
- Alignment Module: Alineación estricta de marca e institución
"""

from .pii_guard import PIIGuard, PIIType, PIIScanResult
from .compliance_filter import ComplianceFilter, ComplianceViolation, ComplianceType
from .alignment_module import AlignmentModule, AlignmentViolation, AlignmentSeverity

__all__ = [
    "PIIGuard",
    "PIIType",
    "PIIScanResult",
    "ComplianceFilter",
    "ComplianceViolation",
    "ComplianceType",
    "AlignmentModule",
    "AlignmentViolation",
    "AlignmentSeverity",
]
