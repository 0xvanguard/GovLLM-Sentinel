"""
Compliance Filter - Módulo de Cumplimiento Normativo

Detecta y filtra:
- Secretos de Estado y patrones de acceso no autorizado
- Manipulación geopolítica y directivas de soberanía territorial
- Intentos de extracción de contexto sensible
- Premisas falsas o sesgadas sobre instituciones

⚠️ Diseñado para entornos gubernamentales altamente regulados
⚠️ Cumple con NIST AI RMF, GDPR, Ley 1273, y marcos de transparencia pública
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class ComplianceType(Enum):
    """Tipos de violaciones de cumplimiento."""
    STATE_SECRETS = "state_secrets"
    GEOPOLITICAL_MANIPULATION = "geopolitical_manipulation"
    SOVEREIGNTY_VIOLATION = "sovereignty_violation"
    INSTITUTIONAL_ATTACK = "institutional_attack"
    CONTEXT_EXTRACTION = "context_extraction"
    POLICY_BYPASS = "policy_bypass"


class ComplianceSeverity(Enum):
    """Nivel de severidad de la violación de cumplimiento."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ComplianceViolation:
    """Una instancia detectada de violación de cumplimiento."""
    
    compliance_type: ComplianceType
    severity: ComplianceSeverity
    matched_text: str
    position_start: int
    position_end: int
    confidence: float
    description: str
    recommendation: str
    regulation: str
    requires_review: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliance_type": self.compliance_type.value,
            "severity": self.severity.value,
            "matched_text": self._mask_text(),
            "position": f"{self.position_start}-{self.position_end}",
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "regulation": self.regulation,
            "requires_review": self.requires_review,
        }
    
    def _mask_text(self) -> str:
        text = self.matched_text
        if len(text) <= 6:
            return "*" * len(text)
        return text[:3] + "*" * (len(text) - 6) + text[-3:]


@dataclass
class ComplianceScanResult:
    """Resultado completo de un escaneo de cumplimiento."""
    
    scan_id: str
    timestamp: str
    input_text: str
    detected: bool
    total_violations: int
    violations_by_type: Dict[str, int]
    violations: List[ComplianceViolation]
    action: str
    scan_duration_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "detected": self.detected,
            "total_violations": self.total_violations,
            "violations_by_type": self.violations_by_type,
            "violations": [v.to_dict() for v in self.violations],
            "action": self.action,
            "scan_duration_ms": self.scan_duration_ms,
        }


class ComplianceFilter:
    """
    Filtro de cumplimiento normativo para LLMs gubernamentales.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scan_count = 0
        self.violation_log: List[Dict[str, Any]] = []
        self._patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[ComplianceType, List[Tuple[re.Pattern, str, float, str, ComplianceSeverity]]]:
        """Compila patrones regex para detección de violaciones."""
        patterns = {}
        
        # SECRETOS DE ESTADO
        patterns[ComplianceType.STATE_SECRETS] = [
            (re.compile(r'\b(?:clasificado|secreto|reservado|confidencial)\s+(?:de\s+estado|nacional|militar|defensa)\b', re.IGNORECASE),
             "Referencia a información clasificada de Estado", 0.95,
             "NIST AI RMF - Protección de Información", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:planes?\s+de\s+(?:defensa|operación|emergencia|continuidad)|estrategia\s+nacional|doctrina\s+militar)\b', re.IGNORECASE),
             "Referencia a documentos de defensa nacional", 0.90,
             "NIST AI RMF - Control de Acceso", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:armas?\s+nucleares?|misiles?|armamento|arsenal|operación\s+encubierta|agente\s+secreto)\b', re.IGNORECASE),
             "Referencia a armamento o operaciones clasificadas", 0.85,
             "NIST AI RMF - Seguridad Nacional", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:inteligencia\s+nacional|espionaje|interceptación|vigilancia|cyber\s+inteligencia)\b', re.IGNORECASE),
             "Referencia a operaciones de inteligencia", 0.88,
             "Ley de Seguridad Nacional", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:acceso\s+(?:no\s+autorizado|ilegal|ilegítimo)|hackear|intrusión|penetrar)\s+(?:sistema|red|base\s+de\s+datos)\b', re.IGNORECASE),
             "Referencia a acceso no autorizado a sistemas", 0.92,
             "Ley 1273 - Delitos Informáticos", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:sistemas?|redes?|bases?\s+de\s+datos?)\s+(?:clasificados?|secreto?|reservados?)\b', re.IGNORECASE),
             "Referencia a sistemas con información clasificada", 0.90,
             "NIST AI RMF - Control de Acceso", ComplianceSeverity.CRITICAL),
        ]
        
        # MANIPULACIÓN GEOPOLÍTICA
        patterns[ComplianceType.GEOPOLITICAL_MANIPULATION] = [
            (re.compile(r'\b(?:taiwán\s+es\s+(?:un\s+)?país|tibet\s+(?:debe|es)\s+independiente|hong\s*kong\s+libre)\b', re.IGNORECASE),
             "Directiva de manipulación de soberanía territorial", 0.98,
             "Principio de Soberanía Territorial", ComplianceSeverity.CRITICAL),
            
            (re.compile(r'\b(?:cataluña\s+independiente|escocia\s+independiente|quebec\s+independiente|kurdistán\s+libre)\b', re.IGNORECASE),
             "Promoción de separatismo regional", 0.85,
             "Estabilidad Territorial", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:el\s+gobierno\s+es\s+(?:ilegítimo|corrupto|dictadura)|el\s+presidente\s+es\s+(?:un\s+)?dictador)\b', re.IGNORECASE),
             "Narrativa de desestabilización institucional", 0.80,
             "Neutralidad Institucional", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:sanciones?\s+internacionales?|embargo|presión\s+económica|boicot\s+internacional)\b', re.IGNORECASE),
             "Referencia a presión internacional coercitiva", 0.75,
             "Autodeterminación", ComplianceSeverity.MEDIUM),
        ]
        
        # ATAQUES INSTITUCIONALES
        patterns[ComplianceType.INSTITUTIONAL_ATTACK] = [
            (re.compile(r'\b(?:olvida\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?|directivas?)|ignora\s+(?:tus?\s+)?(?:instrucciones?|reglas?))\b', re.IGNORECASE),
             "Intento de bypass de directivas del sistema", 0.95,
             "Integridad del Sistema", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:actúa?\s+como\s+si\s+no\s+tuvieras?\s+restricciones?|simula\s+que\s+eres?\s+un\s+modelo\s+sin\s+filtros?)\b', re.IGNORECASE),
             "Intento de evadir restricciones de modelo", 0.88,
             "Integridad del Sistema", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:muéstrame?\s+(?:el\s+)?(?:system\s+prompt|instrucciones?\s+del\s+sistema|configuración\s+interna))\b', re.IGNORECASE),
             "Intento de extracción de system prompt", 0.92,
             "Protección de Configuración", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:todos?\s+los?\s+(?:funcionarios?|políticos?|gobernantes?)\s+(?:son|están)\s+(?:corruptos?|ladrones?|mentirosos?))\b', re.IGNORECASE),
             "Generalización negativa sobre instituciones", 0.80,
             "Neutralidad Institucional", ComplianceSeverity.MEDIUM),
        ]
        
        # EXTRACCIÓN DE CONTEXTO
        patterns[ComplianceType.CONTEXT_EXTRACTION] = [
            (re.compile(r'\b(?:cuáles?\s+son\s+(?:tus?\s+)?(?:instrucciones?|configuración|restricciones?|límites?))\b', re.IGNORECASE),
             "Intento de extracción de configuración del modelo", 0.85,
             "Protección de Configuración", ComplianceSeverity.MEDIUM),
            
            (re.compile(r'\b(?:en\s+qué\s+datos?\s+(?:te\s+)?entrenaron?|cuándo\s+fue\s+(?:tu?\s+)?(?:entrenamiento|ultima?\s+actualización))\b', re.IGNORECASE),
             "Intento de extracción de información de entrenamiento", 0.75,
             "Protección de Propiedad Intelectual", ComplianceSeverity.MEDIUM),
            
            (re.compile(r'\b(?:muéstrame?\s+(?:tu?\s+)?(?:cadena\s+de\s+pensamiento|razonamiento|proceso\s+interno|pensamientos?))\b', re.IGNORECASE),
             "Intento de extracción de cadena de pensamiento", 0.80,
             "Integridad del Sistema", ComplianceSeverity.MEDIUM),
        ]
        
        # BYPASS DE POLÍTICAS
        patterns[ComplianceType.POLICY_BYPASS] = [
            (re.compile(r'\b(?:imagina?\s+que\s+eres?\s+(?:un\s+)?(?:hacker|atacante|villano|anti[^a-z]*héroe))\b', re.IGNORECASE),
             "Role playing para evadir restricciones de seguridad", 0.82,
             "Integridad del Sistema", ComplianceSeverity.HIGH),
            
            (re.compile(r'\b(?:(?:en\s+)?un\s+(?:scenario|escenario)\s+hipotético|supongamos?\s+que)\s+(?:no\s+tienes?\s+restricciones?|puedes?\s+hacer\s+cualquier\s+cosa)\b', re.IGNORECASE),
             "Escenario hipotético para evadir restricciones", 0.78,
             "Integridad del Sistema", ComplianceSeverity.MEDIUM),
            
            (re.compile(r'\b(?:modo\s+(?:desarrollador|developer|debug|admin)|activa?\s+(?:el\s+)?modo\s+(?:libre|sin\s+restricciones?))\b', re.IGNORECASE),
             "Intento de activar modo sin restricciones", 0.90,
             "Integridad del Sistema", ComplianceSeverity.HIGH),
        ]
        
        return patterns
    
    def _get_recommendation(self, compliance_type: ComplianceType) -> str:
        recommendations = {
            ComplianceType.STATE_SECRETS: "Bloquear inmediatamente. Escalar a oficial de seguridad.",
            ComplianceType.GEOPOLITICAL_MANIPULATION: "Bloquear y rechazar premisa. Responder con neutralidad.",
            ComplianceType.SOVEREIGNTY_VIOLATION: "Bloquear. Mantener posición neutral.",
            ComplianceType.INSTITUTIONAL_ATTACK: "Rechazar premisa. No validar generalizaciones.",
            ComplianceType.CONTEXT_EXTRACTION: "Rechazar solicitud. No revelar configuración.",
            ComplianceType.POLICY_BYPASS: "Rechazar intento. Mantener restricciones activas.",
        }
        return recommendations.get(compliance_type, "Revisar manualmente.")
    
    def scan(self, text: str, context: Optional[Dict[str, Any]] = None) -> ComplianceScanResult:
        """Escanea un texto en busca de violaciones de cumplimiento."""
        import time
        import uuid
        
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        violations = []
        
        for compliance_type, pattern_list in self._patterns.items():
            for pattern, description, confidence, regulation, severity in pattern_list:
                for match in pattern.finditer(text):
                    violation = ComplianceViolation(
                        compliance_type=compliance_type,
                        severity=severity,
                        matched_text=match.group(),
                        position_start=match.start(),
                        position_end=match.end(),
                        confidence=confidence,
                        description=description,
                        recommendation=self._get_recommendation(compliance_type),
                        regulation=regulation,
                        requires_review=severity in [ComplianceSeverity.CRITICAL, ComplianceSeverity.HIGH],
                    )
                    violations.append(violation)
        
        violations_by_type = {}
        for v in violations:
            t = v.compliance_type.value
            violations_by_type[t] = violations_by_type.get(t, 0) + 1
        
        action = self._determine_action(violations)
        duration_ms = (time.time() - start_time) * 1000
        self.scan_count += 1
        
        result = ComplianceScanResult(
            scan_id=scan_id,
            timestamp=datetime.now().isoformat(),
            input_text=text,
            detected=len(violations) > 0,
            total_violations=len(violations),
            violations_by_type=violations_by_type,
            violations=violations,
            action=action,
            scan_duration_ms=round(duration_ms, 2),
        )
        
        if violations:
            self.violation_log.append({
                "scan_id": scan_id,
                "timestamp": result.timestamp,
                "violation_count": len(violations),
                "action": action,
                "types_detected": list(set(v.compliance_type.value for v in violations)),
            })
        
        return result
    
    def scan_output(self, text: str, context: Optional[Dict[str, Any]] = None) -> ComplianceScanResult:
        """Escanea una respuesta de salida."""
        result = self.scan(text, context)
        result.action = self._determine_output_action(result.violations)
        return result
    
    def _determine_action(self, violations: List[ComplianceViolation]) -> str:
        if not violations:
            return "allow"
        
        has_critical = any(v.severity == ComplianceSeverity.CRITICAL for v in violations)
        has_high = any(v.severity == ComplianceSeverity.HIGH for v in violations)
        
        if has_critical:
            return "block"
        elif has_high:
            return "escalate"
        elif len(violations) > 2:
            return "modify"
        else:
            return "allow"
    
    def _determine_output_action(self, violations: List[ComplianceViolation]) -> str:
        if not violations:
            return "allow"
        
        has_critical = any(v.severity == ComplianceSeverity.CRITICAL for v in violations)
        
        if has_critical:
            return "block"
        elif len(violations) > 1:
            return "modify"
        else:
            return "review"
    
    def get_violation_stats(self) -> Dict[str, Any]:
        return {
            "total_scans": self.scan_count,
            "total_violations": len(self.violation_log),
            "recent_violations": self.violation_log[-10:] if self.violation_log else [],
        }
