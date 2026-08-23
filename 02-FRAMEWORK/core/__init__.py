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

from .evaluator import GovLLMEvaluator
from .red_team import GovLLMRedTeam
from .defense_engine import DefenseEngine
from .authorization import AuthorizationManager

__all__ = [
    "GovLLMEvaluator",
    "GovLLMRedTeam", 
    "DefenseEngine",
    "AuthorizationManager"
]
