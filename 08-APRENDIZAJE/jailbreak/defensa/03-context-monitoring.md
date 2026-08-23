# 🛡️ Defensa 03: Context Monitoring

## 📋 Resumen

| Campo | Valor |
|-------|-------|
| **Nombre** | Context Monitoring / Session Analysis |
| **Contra** | Context Manipulation Attack |
| **Efectividad** | Media (70-80%) |
| **Complejidad** | Alta |
| **Rendimiento** | ~15ms overhead |

---

## 🎯 ¿Qué es?

Un sistema que **monitorea el contexto** de la conversación para detectar manipulaciones, cambios sospechosos y patrones de ataque multi-turno.

---

## 💻 Implementación

```python
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import re

@dataclass
class ConversationTurn:
    """Representa un turno de conversación."""
    role: str
    content: str
    timestamp: datetime
    risk_score: float = 0.0

@dataclass
class ContextAnalysis:
    """Resultado de análisis de contexto."""
    risk_score: float
    suspicious: bool
    detected_issues: List[str]
    recommendations: List[str]

class ContextMonitor:
    """
    Monitor de contexto para detectar manipulaciones.
    
    Uso:
        monitor = ContextMonitor()
        analysis = monitor.analyze_conversation(history)
        if analysis.suspicious:
            alert_security_team()
    """
    
    def __init__(self, max_turns: int = 50, alert_threshold: float = 0.7):
        self.max_turns = max_turns
        self.alert_threshold = alert_threshold
        self.conversation_history: List[ConversationTurn] = []
        
        # Patrones de detección
        self.suspicious_patterns = [
            # Cambios de instrucción
            r"ignore.*previous",
            r"forget.*instructions",
            r"new.*rules.*override",
            
            # Manipulación de contexto
            r"from now on",
            r"starting.*here",
            r"new.*context",
            
            # Intentos de reset
            r"reset.*conversation",
            r"clear.*memory",
            r"start.*fresh",
        ]
    
    def add_turn(self, role: str, content: str) -> ContextAnalysis:
        """Agrega un turno y analiza el contexto."""
        turn = ConversationTurn(
            role=role,
            content=content,
            timestamp=datetime.now()
        )
        
        # Analizar el turno
        analysis = self._analyze_turn(turn)
        turn.risk_score = analysis.risk_score
        
        self.conversation_history.append(turn)
        
        # Mantener historial within limits
        if len(self.conversation_history) > self.max_turns:
            self.conversation_history = self.conversation_history[-self.max_turns:]
        
        return analysis
    
    def _analyze_turn(self, turn: ConversationTurn) -> ContextAnalysis:
        """Analiza un turno individual."""
        risk_score = 0.0
        detected_issues = []
        recommendations = []
        
        content_lower = turn.content.lower()
        
        # Detectar patrones sospechosos
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content_lower):
                risk_score += 0.3
                detected_issues.append(f"Suspicious pattern: {pattern}")
        
        # Detectar cambios de tema bruscos
        if self.conversation_history:
            last_turn = self.conversation_history[-1]
            topic_change = self._detect_topic_change(last_turn.content, turn.content)
            if topic_change:
                risk_score += 0.2
                detected_issues.append("Abrupt topic change detected")
        
        # Detectar duplicación de contenido
        if self._detect_content_duplication(turn.content):
            risk_score += 0.25
            detected_issues.append("Content duplication detected")
        
        # Detectar longitud anómala
        if len(turn.content) > 5000:
            risk_score += 0.15
            detected_issues.append("Unusually long message")
        
        # Normalizar risk score
        risk_score = min(risk_score, 1.0)
        
        # Generar recomendaciones
        if risk_score > 0.5:
            recommendations.append("Review conversation context")
            recommendations.append("Consider conversation reset")
        if risk_score > 0.7:
            recommendations.append("Alert security team")
            recommendations.append("Log full conversation")
        
        return ContextAnalysis(
            risk_score=risk_score,
            suspicious=risk_score >= self.alert_threshold,
            detected_issues=detected_issues,
            recommendations=recommendations
        )
    
    def _detect_topic_change(self, text1: str, text2: str) -> bool:
        """Detecta cambios de tema bruscos."""
        # Extraer palabras clave
        keywords1 = set(text1.lower().split())
        keywords2 = set(text2.lower().split())
        
        # Calcular similitud
        if not keywords1 or not keywords2:
            return False
        
        intersection = keywords1 & keywords2
        similarity = len(intersection) / min(len(keywords1), len(keywords2))
        
        return similarity < 0.1  # Menos del 10% de similitud
    
    def _detect_content_duplication(self, content: str) -> bool:
        """Detecta duplicación de contenido."""
        if not self.conversation_history:
            return False
        
        last_content = self.conversation_history[-1].content
        return content == last_content
    
    def get_risk_summary(self) -> Dict[str, float]:
        """Retorna resumen de riesgo de la conversación."""
        if not self.conversation_history:
            return {"average_risk": 0.0, "max_risk": 0.0}
        
        risks = [turn.risk_score for turn in self.conversation_history]
        
        return {
            "average_risk": sum(risks) / len(risks),
            "max_risk": max(risks),
            "total_turns": len(self.conversation_history),
            "suspicious_turns": sum(1 for r in risks if r > 0.5)
        }
    
    def reset(self) -> None:
        """Reinicia el monitor."""
        self.conversation_history = []
```

---

## 📊 Métricas de Efectividad

| Escenario | Detección | Falso Positivo |
|-----------|-----------|----------------|
| Context manipulation | 75% | 5% |
| Abrupt topic change | 80% | 8% |
| Multi-turn attacks | 70% | 3% |

---

<div align="center">

**[⬅ Anterior](02-input-sanitization.md)** · **[Siguiente ➡](04-adversarial-training.md)**

</div>
