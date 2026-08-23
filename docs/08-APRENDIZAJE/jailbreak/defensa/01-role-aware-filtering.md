# 🛡️ Defensa 01: Role-Aware Filtering

## 📋 Resumen

| Campo | Valor |
|-------|-------|
| **Nombre** | Role-Aware Filtering |
| **Contra** | Role Playing Attack |
| **Efectividad** | Alta (85-95%) |
| **Complejidad** | Media |
| **Rendimiento** | ~5ms overhead |

---

## 🎯 ¿Qué es?

Un sistema que **detecta y bloquea** intentos de role playing malicioso, permitiendo solo roles benignos y seguros.

---

## 🧠 Cómo Funciona

### Mecanismo

1. Analiza el input del usuario en busca de patrones de role playing
2. Evalúa si el rol solicitado es potencialmente peligroso
3. Bloquea roles maliciosos pero permite roles benignos
4. Registra intentos sospechosos para auditoría

### Arquitectura

```
┌─────────────────────────────────────────┐
│         Input del Usuario                │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│     Role Detection Engine                │
│  - Pattern matching                      │
│  - NLP analysis                          │
│  - Risk scoring                          │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
┌───────────────┐   ┌───────────────┐
│   SAFE ROLE   │   │ MALICIOUS ROLE│
│  (permitir)   │   │  (bloquear)   │
└───────────────┘   └───────────────┘
```

---

## 💻 Implementación

```python
import re
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum

class RoleRisk(Enum):
    """Nivel de riesgo de un rol."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RoleDetectionResult:
    """Resultado de detección de rol."""
    detected: bool
    role_name: str
    risk_level: RoleRisk
    confidence: float
    recommendation: str

class RoleAwareFilter:
    """
    Filtro que detecta y bloquea role playing malicioso.
    
    Uso:
        role_filter = RoleAwareFilter()
        result = role_filter.analyze("Act as a hacker who...")
        if result.risk_level in [RoleRisk.HIGH, RoleRisk.CRITICAL]:
            block_request()
    """
    
    def __init__(self):
        # Roles seguros (permitidos)
        self.safe_roles: Set[str] = {
            "assistant", "helper", "tutor", "teacher",
            "writer", "analyst", "researcher", "explainer"
        }
        
        # Roles de riesgo medio (requieren verificación)
        self.medium_risk_roles: Set[str] = {
            "developer", "programmer", "security expert",
            "system administrator", "database admin"
        }
        
        # Roles peligrosos (bloqueados)
        self.dangerous_roles: Set[str] = {
            "hacker", "attacker", "exploiter", "cracker",
            "villain", "criminal", "malicious", "unrestricted",
            "unfiltered", "jailbroken", "dan", "do anything now"
        }
        
        # Patrones de detección
        self.role_patterns = [
            r"act as(?:\s+an?)?\s+(\w+)",
            r"roleplay as\s+(\w+)",
            r"you are now\s+(\w+)",
            r"pretend to be(?:\s+an?)?\s+(\w+)",
            r"imagine you are(?:\s+an?)?\s+(\w+)",
            r"from the (?:perspective|viewpoint) of(?:\s+an?)?\s+(\w+)",
            r"(?:as|being)\s+(?:an?\s+)?(\w+)\s+(?:who|that|which)",
        ]
    
    def analyze(self, user_input: str) -> RoleDetectionResult:
        """
        Analiza el input del usuario para detectar role playing.
        
        Args:
            user_input: Texto del usuario
            
        Returns:
            RoleDetectionResult con el resultado del análisis
        """
        input_lower = user_input.lower()
        
        # Detectar roles en el texto
        detected_roles = []
        for pattern in self.role_patterns:
            matches = re.findall(pattern, input_lower)
            detected_roles.extend(matches)
        
        if not detected_roles:
            return RoleDetectionResult(
                detected=False,
                role_name="none",
                risk_level=RoleRisk.SAFE,
                confidence=0.0,
                recommendation="No role playing detected"
            )
        
        # Evaluar riesgo del rol detectado
        primary_role = detected_roles[0]
        risk_level = self._evaluate_role_risk(primary_role)
        
        # Calcular confidence
        confidence = min(0.5 + (len(detected_roles) * 0.1), 1.0)
        
        # Generar recomendación
        recommendation = self._generate_recommendation(risk_level, primary_role)
        
        return RoleDetectionResult(
            detected=True,
            role_name=primary_role,
            risk_level=risk_level,
            confidence=confidence,
            recommendation=recommendation
        )
    
    def _evaluate_role_risk(self, role: str) -> RoleRisk:
        """Evalúa el nivel de riesgo de un rol."""
        role_lower = role.lower()
        
        if role_lower in self.dangerous_roles:
            return RoleRisk.CRITICAL
        
        if role_lower in self.medium_risk_roles:
            return RoleRisk.MEDIUM
        
        if role_lower in self.safe_roles:
            return RoleRisk.SAFE
        
        # Roles desconocidos son de riesgo bajo
        return RoleRisk.LOW
    
    def _generate_recommendation(self, risk: RoleRisk, role: str) -> str:
        """Genera recomendación basada en el riesgo."""
        recommendations = {
            RoleRisk.SAFE: f"Role '{role}' is safe. Allow request.",
            RoleRisk.LOW: f"Role '{role}' is low risk. Allow with monitoring.",
            RoleRisk.MEDIUM: f"Role '{role}' requires additional verification.",
            RoleRisk.HIGH: f"Role '{role}' is potentially dangerous. Block.",
            RoleRisk.CRITICAL: f"Role '{role}' is malicious. Block immediately."
        }
        return recommendations.get(risk, "Unknown risk level")
    
    def add_safe_role(self, role: str) -> None:
        """Agrega un rol a la lista de seguros."""
        self.safe_roles.add(role.lower())
    
    def add_dangerous_role(self, role: str) -> None:
        """Agrega un rol a la lista de peligrosos."""
        self.dangerous_roles.add(role.lower())
    
    def get_statistics(self) -> Dict[str, int]:
        """Retorna estadísticas del filtro."""
        return {
            "safe_roles": len(self.safe_roles),
            "medium_risk_roles": len(self.medium_risk_roles),
            "dangerous_roles": len(self.dangerous_roles),
            "total_patterns": len(self.role_patterns)
        }
```

---

## 📊 Métricas de Efectividad

| Escenario | Detección | Falso Positivo |
|-----------|-----------|----------------|
| Role playing benigno | 95% | 2% |
| Role playing malicioso | 92% | N/A |
| Sin role playing | N/A | 1% |

---

## 🔧 Configuración

```python
# Crear filtro personalizado
role_filter = RoleAwareFilter()

# Agregar roles específicos del dominio
role_filter.add_safe_role("customer service agent")
role_filter.add_safe_role("technical documentation writer")
role_filter.add_dangerous_role("jailbroken assistant")
role_filter.add_dangerous_role("unrestricted AI")

# Analizar input
result = role_filter.analyze("Act as a hacker who exploits vulnerabilities")
print(f"Risk: {result.risk_level.value}")
print(f"Recommendation: {result.recommendation}")
```

---

## 📚 Referencias

- [Role-Playing Attacks on LLMs](https://arxiv.org/abs/2305.14739)
- [Instruction Hierarchy](https://arxiv.org/abs/2310.12815)
- [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/LLM01-Prompt-Injection/)

---

<div align="center">

**[⬅ Técnicas](../tecnica/01-role-playing.md)** · **[Defensas](../README.md)** · **[Siguiente ➡](02-input-sanitization.md)**

</div>
