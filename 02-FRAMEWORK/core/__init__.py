"""
GovLLM-Sentinel Core Module
Framework de evaluación y hardening de LLMs para sector público.

Este módulo proporciona las herramientas principales para:
- Evaluación autorizada de modelos LLM
- Red teaming defensivo
- Generación de reportes ejecutivos
- Integración con dashboards gubernamentales

⚠️ REQUIERE CONTRATO DE AUTORIZACIÓN VÁLIDO
"""

__version__ = "1.0.0"
__author__ = "GovLLM-Sentinel Team"

try:
    from .evaluator import GovLLMEvaluator
except ImportError:
    GovLLMEvaluator = None

try:
    from .red_team import GovLLMRedTeam
except ImportError:
    GovLLMRedTeam = None

try:
    from .defense_engine import DefenseEngine
except ImportError:
    DefenseEngine = None

try:
    from .authorization import AuthorizationManager
except ImportError:
    AuthorizationManager = None

from .llm_connector import LLMConnector
from .report_generator import ReportGenerator
from .realtime_monitor import RealtimeMonitor
from .adversarial_trainer import AdversarialTrainer

__all__ = [
    "LLMConnector",
    "ReportGenerator",
    "RealtimeMonitor",
    "AdversarialTrainer",
    "GovLLMEvaluator",
    "GovLLMRedTeam",
    "DefenseEngine",
    "AuthorizationManager",
]
