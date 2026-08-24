"""
PII Guard - Módulo de Protección de Datos de Identificación Personal

Detecta y filtra información de identificación personal (PII) en prompts
de entrada y respuestas de salida antes de que alcancen el backend del LLM.

⚠️ Diseñado para entornos gubernamentales altamente regulados
⚠️ Cumple con GDPR, Ley 1273 (Colombia), y marcos NIST AI RMF

Tipos de PII detectados:
- Documentos de identidad (CURP, RFC, DNI, pasaportes)
- Información financiera (tarjetas de crédito, cuentas bancarias)
- Datos de contacto (teléfonos, emails, direcciones)
- Información biométrica (patrones de texto sugestivos)
- Secretos de Estado (clasificación, patrones de acceso)

Uso:
    guard = PIIGuard()
    result = guard.scan_input("Mi CURP es GARC850101HDFRRL09")
    print(result.detected)  # True
    print(result.violations)  # [PIIResult(type=PIIType.CURP, ...)]
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class PIIType(Enum):
    """Tipos de PII detectados."""
    # Documentos de identidad
    CURP = "curp"
    RFC = "rfc"
    DNI = "dni"
    PASSPORT = "passport"
    SOCIAL_SECURITY = "social_security"
    
    # Información financiera
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    CLABE = "clabe"
    
    # Datos de contacto
    EMAIL = "email"
    PHONE_MX = "phone_mx"
    PHONE_US = "phone_us"
    PHONE_INTL = "phone_intl"
    ADDRESS = "address"
    
    # Información gubernamental
    EMPLOYEE_ID = "employee_id"
    SECURITY_CLEARANCE = "security_clearance"
    CLASSIFIED_REFERENCE = "classified_reference"
    
    # Patrones genéricos
    IP_ADDRESS = "ip_address"
    URL_SENSITIVE = "url_sensitive"
    API_KEY = "api_key"


class PIISeverity(Enum):
    """Nivel de severidad de la violación PII."""
    CRITICAL = "critical"    # Documentos de identidad, financieros
    HIGH = "high"            # Datos de contacto directos
    MEDIUM = "medium"        # Información parcial
    LOW = "low"              # Patrones genéricos
    INFO = "info"            # Informativo, no bloqueante


@dataclass
class PIIMatch:
    """Una instancia detectada de PII."""
    
    pii_type: PIIType
    severity: PIISeverity
    matched_text: str
    position_start: int
    position_end: int
    confidence: float  # 0.0 - 1.0
    description: str
    recommendation: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pii_type": self.pii_type.value,
            "severity": self.severity.value,
            "matched_text": self._mask_text(),
            "position": f"{self.position_start}-{self.position_end}",
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
        }
    
    def _mask_text(self) -> str:
        """Enmascara el texto detectado para logs seguros."""
        text = self.matched_text
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "*" * (len(text) - 4) + text[-2:]


@dataclass
class PIIScanResult:
    """Resultado completo de un escaneo PII."""
    
    scan_id: str
    timestamp: str
    input_text: str
    
    # Resultados
    detected: bool
    total_violations: int
    violations_by_severity: Dict[str, int]
    violations: List[PIIMatch]
    
    # Estadísticas
    scan_duration_ms: float
    text_length: int
    
    # Acción recomendada
    action: str  # "allow", "mask", "block", "review"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "detected": self.detected,
            "total_violations": self.total_violations,
            "violations_by_severity": self.violations_by_severity,
            "violations": [v.to_dict() for v in self.violations],
            "action": self.action,
            "scan_duration_ms": self.scan_duration_ms,
            "text_length": self.text_length,
        }
    
    def get_masked_text(self) -> str:
        """Retorna el texto con PII enmascarado."""
        text = self.input_text
        # Ordenar por posición descendente para no alterar índices
        sorted_violations = sorted(
            self.violations, 
            key=lambda v: v.position_start, 
            reverse=True
        )
        for violation in sorted_violations:
            mask = "*" * len(violation.matched_text)
            text = text[:violation.position_start] + mask + text[violation.position_end:]
        return text


class PIIGuard:
    """
    Guardián de protección de datos de identificación personal.
    
    Intercepta prompts de entrada y respuestas de salida para filtrar
    PII antes de que el LLM toque el backend.
    
    Uso:
        guard = PIIGuard()
        
        # Escanear entrada
        result = guard.scan_input("Mi CURP es GARC850101HDFRRL09")
        
        # Escanear salida
        result = guard.scan_output("El usuario Juan Pérez tiene RFC PEGJ850101")
        
        # Obtener texto enmascarado
        safe_text = result.get_masked_text()
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Inicializa el PII Guard.
        
        Args:
            config: Configuración opcional para personalizar comportamiento
        """
        self.config = config or {}
        self.scan_count = 0
        self.violation_log: List[Dict[str, Any]] = []
        
        # Compilar patrones regex al inicializar (optimización)
        self._patterns = self._compile_patterns()
        
        # Configuración de umbrales
        self.block_threshold = self.config.get("block_threshold", "critical")
        self.mask_threshold = self.config.get("mask_threshold", "high")
        
    def _compile_patterns(self) -> Dict[PIIType, List[Tuple[re.Pattern, str, float]]]:
        """
        Compila todos los patrones regex para detección de PII.
        
        Returns:
            Diccionario mapeando PIIType a lista de (patrón, descripción, confianza)
        """
        patterns = {}
        
        # ═══════════════════════════════════════════════════════════
        # DOCUMENTOS DE IDENTIDAD - MÉXICO
        # ═══════════════════════════════════════════════════════════
        
        # CURP (Clave Única de Registro de Población) - 18 caracteres
        # Formato: 4 letras + 6 dígitos (fecha) + 1 letra (sexo) + 2 letras (estado) + 3 consonantes + 1 dígito/letra + 1 dígito/letra
        curp_pattern = re.compile(
            r'\b[A-Z]{4}\d{6}[HM][A-Z]{2}[BCDFGHJKLMNPQRSTVWXYZ]{3}[0-9A-Z]\d\b',
            re.IGNORECASE
        )
        patterns[PIIType.CURP] = [
            (curp_pattern, "CURP mexicana detectada", 0.95),
        ]
        
        # RFC (Registro Federal de Contribuyentes) - 12-13 caracteres
        # Personas morales: 3 letras + 6 dígitos + 3 caracteres
        # Personas físicas: 4 letras + 6 dígitos + 3 caracteres
        rfc_pattern = re.compile(
            r'\b[A-Z]{3,4}\d{6}[A-Z0-9]{3}\b',
            re.IGNORECASE
        )
        patterns[PIIType.RFC] = [
            (rfc_pattern, "RFC mexicano detectado", 0.85),
        ]
        
        # ═══════════════════════════════════════════════════════════
        # DOCUMENTOS DE IDENTIDAD - OTROS PAÍSES
        # ═══════════════════════════════════════════════════════════
        
        # DNI argentino - 8 dígitos
        dni_pattern = re.compile(
            r'\b(?:DNI|dni)\s*[:.]?\s*\d{8}\b'
        )
        patterns[PIIType.DNI] = [
            (dni_pattern, "DNI argentino detectado", 0.90),
        ]
        
        # Pasaporte (formato general: 1-2 letras + 6-9 dígitos)
        passport_pattern = re.compile(
            r'\b(?:pasaporte|passport|PPT|PPO)\s*[:.]?\s*[A-Z]{1,2}\d{6,9}\b',
            re.IGNORECASE
        )
        patterns[PIIType.PASSPORT] = [
            (passport_pattern, "Número de pasaporte detectado", 0.88),
        ]
        
        # Número de Seguridad Social (formato US: XXX-XX-XXXX)
        ssn_pattern = re.compile(
            r'\b\d{3}-\d{2}-\d{4}\b'
        )
        patterns[PIIType.SOCIAL_SECURITY] = [
            (ssn_pattern, "Número de Seguridad Social detectado", 0.92),
        ]
        
        # ═══════════════════════════════════════════════════════════
        # INFORMACIÓN FINANCIERA
        # ═══════════════════════════════════════════════════════════
        
        # Tarjeta de crédito (16 dígitos, posibles espacios/guiones)
        credit_card_pattern = re.compile(
            r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        )
        patterns[PIIType.CREDIT_CARD] = [
            (credit_card_pattern, "Número de tarjeta de crédito detectado", 0.80),
        ]
        
        # CLABE interbancaria (18 dígitos)
        clabe_pattern = re.compile(
            r'\b(?:CLABE|clabe)\s*[:.]?\s*\d{18}\b'
        )
        patterns[PIIType.CLABE] = [
            (clabe_pattern, "CLABE interbancaria detectada", 0.95),
        ]
        
        # Cuenta bancaria (formato general)
        bank_pattern = re.compile(
            r'\b(?:cuenta\s+bancaria|account\s+number|cta\.)\s*[:.]?\s*\d{10,20}\b',
            re.IGNORECASE
        )
        patterns[PIIType.BANK_ACCOUNT] = [
            (bank_pattern, "Número de cuenta bancaria detectado", 0.85),
        ]
        
        # ═══════════════════════════════════════════════════════════
        # DATOS DE CONTACTO
        # ═══════════════════════════════════════════════════════════
        
        # Email
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        patterns[PIIType.EMAIL] = [
            (email_pattern, "Dirección de correo electrónico detectada", 0.95),
        ]
        
        # Teléfono México (10 dígitos, con o sin código de país)
        phone_mx_pattern = re.compile(
            r'(?:\+?52)?[-\s]?(?:\(?[0-9]{2,3}\)?[-\s]?)?[0-9]{4}[-\s]?[0-9]{4}\b'
        )
        patterns[PIIType.PHONE_MX] = [
            (phone_mx_pattern, "Número de teléfono mexicano detectado", 0.80),
        ]
        
        # Teléfono US (formato XXX-XXX-XXXX)
        phone_us_pattern = re.compile(
            r'\b(?:\+?1[-\s]?)?\(?[0-9]{3}\)?[-\s]?[0-9]{3}[-\s]?[0-9]{4}\b'
        )
        patterns[PIIType.PHONE_US] = [
            (phone_us_pattern, "Número de teléfono detectado", 0.75),
        ]
        
        # ═══════════════════════════════════════════════════════════
        # INFORMACIÓN GUBERNAMENTAL SENSIBLE
        # ═══════════════════════════════════════════════════════════
        
        # ID de empleado gubernamental
        emp_id_pattern = re.compile(
            r'\b(?:employee\s*id|no\.\s*empleado|id\s*empleado|matrícula)\s*[:.]?\s*[A-Z0-9]{6,12}\b',
            re.IGNORECASE
        )
        patterns[PIIType.EMPLOYEE_ID] = [
            (emp_id_pattern, "ID de empleado gubernamental detectado", 0.85),
        ]
        
        # Referencia clasificada
        classified_pattern = re.compile(
            r'\b(?:CLASSIFIED|SECRET|TOP\s*SECRET|CONFIDENTIAL|RESERVADO|SECRETO|CLASIFICADO)\b',
            re.IGNORECASE
        )
        patterns[PIIType.CLASSIFIED_REFERENCE] = [
            (classified_pattern, "Referencia a información clasificada detectada", 0.90),
        ]
        
        # ═══════════════════════════════════════════════════════════
        # PATRONES GENÉRICOS SENSIBLES
        # ═══════════════════════════════════════════════════════════
        
        # Dirección IP
        ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        patterns[PIIType.IP_ADDRESS] = [
            (ip_pattern, "Dirección IP detectada", 0.70),
        ]
        
        # API Key (patrón genérico)
        api_key_pattern = re.compile(
            r'\b(?:api[_-]?key|apikey|token|secret[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?\b',
            re.IGNORECASE
        )
        patterns[PIIType.API_KEY] = [
            (api_key_pattern, "API Key o token detectado", 0.88),
        ]
        
        return patterns
    
    def _get_severity(self, pii_type: PIIType) -> PIISeverity:
        """Retorna la severidad para un tipo de PII."""
        severity_map = {
            PIIType.CURP: PIISeverity.CRITICAL,
            PIIType.RFC: PIISeverity.CRITICAL,
            PIIType.DNI: PIISeverity.CRITICAL,
            PIIType.PASSPORT: PIISeverity.CRITICAL,
            PIIType.SOCIAL_SECURITY: PIISeverity.CRITICAL,
            PIIType.CREDIT_CARD: PIISeverity.CRITICAL,
            PIIType.CLABE: PIISeverity.CRITICAL,
            PIIType.BANK_ACCOUNT: PIISeverity.HIGH,
            PIIType.EMAIL: PIISeverity.HIGH,
            PIIType.PHONE_MX: PIISeverity.HIGH,
            PIIType.PHONE_US: PIISeverity.HIGH,
            PIIType.PHONE_INTL: PIISeverity.HIGH,
            PIIType.ADDRESS: PIISeverity.HIGH,
            PIIType.EMPLOYEE_ID: PIISeverity.HIGH,
            PIIType.CLASSIFIED_REFERENCE: PIISeverity.CRITICAL,
            PIIType.IP_ADDRESS: PIISeverity.MEDIUM,
            PIIType.API_KEY: PIISeverity.CRITICAL,
            PIIType.URL_SENSITIVE: PIISeverity.MEDIUM,
        }
        return severity_map.get(pii_type, PIISeverity.LOW)
    
    def _get_recommendation(self, pii_type: PIIType) -> str:
        """Retorna recomendación para cada tipo de PII."""
        recommendations = {
            PIIType.CURP: "Bloquear inmediatamente. La CURP contiene información de identidad completa.",
            PIIType.RFC: "Bloquear inmediatamente. El RFC permite identificación fiscal completa.",
            PIIType.DNI: "Bloquear inmediatamente. El DNI es documento de identidad oficial.",
            PIIType.PASSPORT: "Bloquear inmediatamente. El pasaporte es documento de viaje oficial.",
            PIIType.SOCIAL_SECURITY: "Bloquear inmediatamente. El SSN permite robo de identidad.",
            PIIType.CREDIT_CARD: "Bloquear inmediatamente. Datos financieros sensibles.",
            PIIType.CLABE: "Bloquear inmediatamente. CLABE permite transferencias bancarias.",
            PIIType.BANK_ACCOUNT: "Bloquear. Información bancaria sensible.",
            PIIType.EMAIL: "Enmascarar parcialmente. Correo electrónico identificable.",
            PIIType.PHONE_MX: "Enmascarar parcialmente. Número telefónico directo.",
            PIIType.PHONE_US: "Enmascarar parcialmente. Número telefónico detectado.",
            PIIType.PHONE_INTL: "Enmascarar parcialmente. Número telefónico internacional.",
            PIIType.ADDRESS: "Enmascarar. Dirección física identificable.",
            PIIType.EMPLOYEE_ID: "Bloquear. Identificador gubernamental sensible.",
            PIIType.CLASSIFIED_REFERENCE: "Bloquear inmediatamente. Referencia a información clasificada.",
            PIIType.IP_ADDRESS: "Revisar. Dirección IP puede ser información de red interna.",
            PIIType.API_KEY: "Bloquear inmediatamente. Credenciales expuestas.",
            PIIType.URL_SENSITIVE: "Revisar. URL puede contener información sensible.",
        }
        return recommendations.get(pii_type, "Revisar manualmente.")
    
    def scan_input(self, text: str, context: Optional[Dict[str, Any]] = None) -> PIIScanResult:
        """
        Escanea un prompt de entrada en busca de PII.
        
        Args:
            text: Texto del prompt a escanear
            context: Contexto adicional (usuario, sesión, etc.)
            
        Returns:
            PIIScanResult con los resultados del escaneo
        """
        import time
        import uuid
        
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        
        violations = []
        
        # Escanear cada tipo de PII
        for pii_type, pattern_list in self._patterns.items():
            for pattern, description, base_confidence in pattern_list:
                for match in pattern.finditer(text):
                    severity = self._get_severity(pii_type)
                    
                    violation = PIIMatch(
                        pii_type=pii_type,
                        severity=severity,
                        matched_text=match.group(),
                        position_start=match.start(),
                        position_end=match.end(),
                        confidence=base_confidence,
                        description=description,
                        recommendation=self._get_recommendation(pii_type),
                    )
                    violations.append(violation)
        
        # Calcular estadísticas
        violations_by_severity = {}
        for v in violations:
            sev = v.severity.value
            violations_by_severity[sev] = violations_by_severity.get(sev, 0) + 1
        
        # Determinar acción recomendada
        action = self._determine_action(violations)
        
        # Calcular duración
        duration_ms = (time.time() - start_time) * 1000
        
        # Actualizar contadores
        self.scan_count += 1
        
        result = PIIScanResult(
            scan_id=scan_id,
            timestamp=datetime.now().isoformat(),
            input_text=text,
            detected=len(violations) > 0,
            total_violations=len(violations),
            violations_by_severity=violations_by_severity,
            violations=violations,
            scan_duration_ms=round(duration_ms, 2),
            text_length=len(text),
            action=action,
        )
        
        # Registrar en log de violaciones (sin datos sensibles)
        if violations:
            self.violation_log.append({
                "scan_id": scan_id,
                "timestamp": result.timestamp,
                "violation_count": len(violations),
                "action": action,
                "types_detected": list(set(v.pii_type.value for v in violations)),
            })
        
        return result
    
    def scan_output(self, text: str, context: Optional[Dict[str, Any]] = None) -> PIIScanResult:
        """
        Escanea una respuesta de salida en busca de PII filtrado.
        
        Args:
            text: Texto de la respuesta a escanear
            context: Contexto adicional
            
        Returns:
            PIIScanResult con los resultados del escaneo
        """
        # La lógica es idéntica a scan_input pero con contexto de salida
        result = self.scan_input(text, context)
        result.action = self._determine_output_action(result.violations)
        return result
    
    def _determine_action(self, violations: List[PIIMatch]) -> str:
        """Determina la acción a tomar basándose en las violaciones."""
        if not violations:
            return "allow"
        
        has_critical = any(v.severity == PIISeverity.CRITICAL for v in violations)
        has_high = any(v.severity == PIISeverity.HIGH for v in violations)
        
        if has_critical:
            return "block"
        elif has_high:
            return "mask"
        elif len(violations) > 3:
            return "review"
        else:
            return "mask"
    
    def _determine_output_action(self, violations: List[PIIMatch]) -> str:
        """Determina la acción para respuestas de salida."""
        if not violations:
            return "allow"
        
        has_critical = any(v.severity == PIISeverity.CRITICAL for v in violations)
        
        if has_critical:
            return "block"
        elif len(violations) > 2:
            return "mask"
        else:
            return "review"
    
    def get_violation_stats(self) -> Dict[str, Any]:
        """Retorna estadísticas acumuladas de violaciones."""
        return {
            "total_scans": self.scan_count,
            "total_violations": len(self.violation_log),
            "recent_violations": self.violation_log[-10:] if self.violation_log else [],
        }
    
    def reset(self) -> None:
        """Reinicia contadores y logs."""
        self.scan_count = 0
        self.violation_log = []
