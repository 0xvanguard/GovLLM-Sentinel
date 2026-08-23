"""
GovLLM-Sentinel - Módulo de Ataques Autorizados

Este paquete contiene técnicas de ataque autorizadas para evaluar
la seguridad de modelos de lenguaje.

⚠️ REQUIERE CONTRATO DE AUTORIZACIÓN VÁLIDO
⚠️ Solo para uso defensivo y educativo
"""

from .jailbreaks import JailbreakTester
from .prompt_injection import InjectionTester
from .data_exfiltration import ExfiltrationTester
from .content_filter_bypass import FilterBypassTester

__all__ = [
    "JailbreakTester",
    "InjectionTester", 
    "ExfiltrationTester",
    "FilterBypassTester"
]
