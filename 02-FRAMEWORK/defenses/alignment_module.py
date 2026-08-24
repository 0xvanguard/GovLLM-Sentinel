"""
Alignment Module - Módulo de Alineación Estricta de Marca e Institución

Implementa restricciones de neutralidad institucional y rechazo estructurado
ante premisas falsas o sesgadas, adaptando la lógica del modelo a normativas
de transparencia pública sin caer en discursos burocráticos vacíos.

Componentes:
1. PRE-FILTRO: Valida prompts antes de que lleguen al modelo
2. POST-ANÁLISIS: Analiza respuestas para detectar desviaciones
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class AlignmentSeverity(Enum):
    """Nivel de severidad de violación de alineación."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlignmentCategory(Enum):
    """Categorías de violaciones de alineación."""
    NEUTRALITY_BREACH = "neutrality_breach"
    FALSE_PREMISE = "false_premise"
    BIAS_DETECTED = "bias_detected"
    TONE_VIOLATION = "tone_violation"
    INSTITUTIONAL_DISRESPECT = "institutional_disrespect"
    PROPAGANDA_DETECTED = "propaganda_detected"
    FACTUAL_ERROR = "factual_error"


@dataclass
class AlignmentViolation:
    """Una instancia detectada de violación de alineación."""
    
    category: AlignmentCategory
    severity: AlignmentSeverity
    matched_text: str
    position_start: int
    position_end: int
    confidence: float
    description: str
    recommendation: str
    phase: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "matched_text": self._mask_text(),
            "position": f"{self.position_start}-{self.position_end}",
            "confidence": self.confidence,
            "description": self.description,
            "recommendation": self.recommendation,
            "phase": self.phase,
        }
    
    def _mask_text(self) -> str:
        text = self.matched_text
        if len(text) <= 6:
            return "*" * len(text)
        return text[:3] + "*" * (len(text) - 6) + text[-3:]


@dataclass
class AlignmentResult:
    """Resultado de un análisis de alineación."""
    
    scan_id: str
    timestamp: str
    pre_filter_violations: List[AlignmentViolation]
    pre_filter_action: str
    post_analysis_violations: List[AlignmentViolation]
    post_analysis_action: str
    overall_compliant: bool
    overall_score: float
    recommended_response_strategy: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "pre_filter": {
                "violations": [v.to_dict() for v in self.pre_filter_violations],
                "action": self.pre_filter_action,
            },
            "post_analysis": {
                "violations": [v.to_dict() for v in self.post_analysis_violations],
                "action": self.post_analysis_action,
            },
            "overall_compliant": self.overall_compliant,
            "overall_score": self.overall_score,
            "recommended_response_strategy": self.recommended_response_strategy,
        }


class AlignmentModule:
    """
    Módulo de Alineación Estricta de Marca e Institución.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scan_count = 0
        self._pre_patterns = self._compile_pre_filter_patterns()
        self._post_patterns = self._compile_post_analysis_patterns()
    
    def _compile_pre_filter_patterns(self) -> Dict[AlignmentCategory, List[Tuple[re.Pattern, str, float, AlignmentSeverity]]]:
        """Compila patrones para pre-filtro de prompts."""
        patterns = {}
        
        # PREMISAS FALSAS
        patterns[AlignmentCategory.FALSE_PREMISE] = [
            (re.compile(r'\b(?:todos?|todas?|cada\s+uno|siempre|nunca)\s+(?:los?\s+|las?\s+)?(?:políticos?|funcionarios?|gobernantes?|empresarios?|ricos?)\s+(?:son|están|han|son)\s+(?:corruptos?|ladrones?|mentirosos?|ineptos?|incompetentes?)\b', re.IGNORECASE),
             "Generalización negativa sobre grupo profesional", 0.90,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:confirma?|acepta?|reconoce?)\s+(?:que\s+)?(?:el\s+presidente|el\s+gobierno|la\s+institución)\s+(?:es\s+(?:corrupto|culpable|responsable)|robó|mintió|engañó)\b', re.IGNORECASE),
             "Presunción de culpabilidad sin evidencia", 0.88,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:por\s+qué\s+(?:el\s+presidente|el\s+gobierno)\s+(?:miente|engaña|roba|es\s+corrupto|es\s+un\s+dictador))\b', re.IGNORECASE),
             "Pregunta cargada con premisa sesgada", 0.92,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:comparar?|es\s+(?:igual|peor)\s+(?:que|a))\s+(?:Hitler|Mussolini|dictadura|nazismo|fascismo)\b', re.IGNORECASE),
             "Comparación despectiva con regímenes autoritarios", 0.85,
             AlignmentSeverity.CRITICAL),
        ]
        
        # SESGO DETECTADO
        patterns[AlignmentCategory.BIAS_DETECTED] = [
            (re.compile(r'\b(?:izquierda|derecha|liberal|conservador|socialista|comunista|fascista)\s+(?:es\s+(?:mejor|peor|superior|inferior)|siempre\s+(?:tiene\s+razón|está\s+equivocado))\b', re.IGNORECASE),
             "Sesgo político explícito", 0.80,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:las?\s+mujeres?|los?\s+hombres?|los?\s+viejos?|los?\s+jóvenes?|los?\s+extranjeros?)\s+(?:siempre|nunca|todos?|nadie)\s+(?:son|están|hacen|deben)\b', re.IGNORECASE),
             "Sesgo discriminatorio por grupo", 0.85,
             AlignmentSeverity.CRITICAL),
            
            (re.compile(r'\b(?:nuestra\s+cultura|nuestra\s+raza|nuestro\s+pueblo)\s+(?:es\s+(?:superior|mejor|la\s+única\s+verdadera)|siempre\s+tiene\s+razón)\b', re.IGNORECASE),
             "Supremacía cultural", 0.88,
             AlignmentSeverity.CRITICAL),
        ]
        
        # DESRESPETO INSTITUCIONAL
        patterns[AlignmentCategory.INSTITUTIONAL_DISRESPECT] = [
            (re.compile(r'\b(?:el\s+gobierno|la\s+institución|el\s+presidente)\s+(?:es\s+)?(?:una\s+(?:mierda|basura|vergüenza)|no\s+(?:vale|sirve|funciona)|es\s+una\s+broma)\b', re.IGNORECASE),
             "Insulto directo a institución", 0.90,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:payasos?|ineptos?|ladrones?|corruptos?|sinvergüenzas?|caraduras?)\s+(?:del\s+gobierno|gubernamental|oficial)\b', re.IGNORECASE),
             "Lenguaje despectivo hacia funcionarios", 0.85,
             AlignmentSeverity.MEDIUM),
        ]
        
        return patterns
    
    def _compile_post_analysis_patterns(self) -> Dict[AlignmentCategory, List[Tuple[re.Pattern, str, float, AlignmentSeverity]]]:
        """Compila patrones para post-análisis de respuestas."""
        patterns = {}
        
        # DESVIACIONES DE NEUTRALIDAD
        patterns[AlignmentCategory.NEUTRALITY_BREACH] = [
            (re.compile(r'\b(?:yo\s+opino|en\s+mi\s+opinión|personalmente\s+creo|yo\s+pienso|me\s+parece\s+(?:que\s+)?)\s+(?:que\s+)?(?:el\s+gobierno|el\s+presidente|la\s+institución)\s+(?:es|está|debería|tiene)\b', re.IGNORECASE),
             "Expresión de opinión personal del modelo sobre institución", 0.75,
             AlignmentSeverity.HIGH),
            
            (re.compile(r'\b(?:es\s+(?:increíble|escandaloso|vergonzoso|patético|desastrozo|desastroso|aterrador|horrible))\b', re.IGNORECASE),
             "Lenguaje emocional o exagerado en respuesta", 0.70,
             AlignmentSeverity.MEDIUM),
            
            (re.compile(r'\b(?:hay\s+que\s+(?:apoyar|defender|luchar\s+por|proteger)\s+(?:al\s+gobierno|al\s+presidente|la\s+revolución|el\s+movimiento))\b', re.IGNORECASE),
             "Tono propagandístico detectado", 0.80,
             AlignmentSeverity.HIGH),
        ]
        
        # ERROR FACTUAL
        patterns[AlignmentCategory.FACTUAL_ERROR] = [
            (re.compile(r'\b(?:en\s+(?:el\s+año\s+)?\d{4}\s+(?:se\s+inventó|se\s+creó|se\s+descubrió|ocurrió))\b', re.IGNORECASE),
             "Posible error factual (verificar fecha/evento)", 0.60,
             AlignmentSeverity.MEDIUM),
            
            (re.compile(r'\b(?:siempre\s+(?:ha\s+sido|se\s+ha\s+hecho|funcionó)|nunca\s+(?:ha\s+habido|se\s+ha\s+intentado))\b', re.IGNORECASE),
             "Afirmación absoluta sin verificación de fuente", 0.65,
             AlignmentSeverity.MEDIUM),
        ]
        
        return patterns
    
    def _get_pre_recommendation(self, category: AlignmentCategory) -> str:
        recommendations = {
            AlignmentCategory.FALSE_PREMISE: "Rechazar premisa. Responder con neutralidad y hechos.",
            AlignmentCategory.BIAS_DETECTED: "Neutralizar sesgo. No validar generalizaciones.",
            AlignmentCategory.INSTITUTIONAL_DISRESPECT: "Mantener respeto institucional.",
        }
        return recommendations.get(category, "Aplicar neutralidad institucional.")
    
    def _get_post_recommendation(self, category: AlignmentCategory) -> str:
        recommendations = {
            AlignmentCategory.NEUTRALITY_BREACH: "Regenerar respuesta con tono neutral.",
            AlignmentCategory.FACTUAL_ERROR: "Verificar hechos. Corregir información errónea.",
            AlignmentCategory.PROPAGANDA_DETECTED: "Eliminar tono propagandístico.",
        }
        return recommendations.get(category, "Revisar y corregir tono.")
    
    def pre_filter(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Pre-filtro: Analiza el prompt antes de que llegue al modelo."""
        import time
        import uuid
        
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        violations = []
        
        for category, pattern_list in self._pre_patterns.items():
            for pattern, description, confidence, severity in pattern_list:
                for match in pattern.finditer(prompt):
                    violation = AlignmentViolation(
                        category=category,
                        severity=severity,
                        matched_text=match.group(),
                        position_start=match.start(),
                        position_end=match.end(),
                        confidence=confidence,
                        description=description,
                        recommendation=self._get_pre_recommendation(category),
                        phase="pre_filter",
                    )
                    violations.append(violation)
        
        action = self._determine_pre_action(violations)
        duration_ms = (time.time() - start_time) * 1000
        self.scan_count += 1
        
        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "phase": "pre_filter",
            "detected": len(violations) > 0,
            "violations": [v.to_dict() for v in violations],
            "action": action,
            "scan_duration_ms": round(duration_ms, 2),
        }
    
    def post_analyze(self, response: str, original_prompt: str = "", 
                     context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Post-análisis: Valida la respuesta generada."""
        import time
        import uuid
        
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]
        violations = []
        
        for category, pattern_list in self._post_patterns.items():
            for pattern, description, confidence, severity in pattern_list:
                for match in pattern.finditer(response):
                    violation = AlignmentViolation(
                        category=category,
                        severity=severity,
                        matched_text=match.group(),
                        position_start=match.start(),
                        position_end=match.end(),
                        confidence=confidence,
                        description=description,
                        recommendation=self._get_post_recommendation(category),
                        phase="post_analysis",
                    )
                    violations.append(violation)
        
        action = self._determine_post_action(violations)
        duration_ms = (time.time() - start_time) * 1000
        self.scan_count += 1
        
        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "phase": "post_analysis",
            "detected": len(violations) > 0,
            "violations": [v.to_dict() for v in violations],
            "action": action,
            "scan_duration_ms": round(duration_ms, 2),
        }
    
    def analyze(self, prompt: str, response: str, 
                context: Optional[Dict[str, Any]] = None) -> AlignmentResult:
        """Pipeline completo: pre-filtro + post-análisis."""
        import uuid
        
        scan_id = str(uuid.uuid4())[:8]
        
        pre_result = self.pre_filter(prompt, context)
        pre_violations = []
        for v_dict in pre_result["violations"]:
            pre_violations.append(AlignmentViolation(
                category=AlignmentCategory(v_dict["category"]),
                severity=AlignmentSeverity(v_dict["severity"]),
                matched_text=v_dict["matched_text"],
                position_start=0,
                position_end=0,
                confidence=v_dict["confidence"],
                description=v_dict["description"],
                recommendation=v_dict["recommendation"],
                phase="pre_filter",
            ))
        
        post_result = self.post_analyze(response, prompt, context)
        post_violations = []
        for v_dict in post_result["violations"]:
            post_violations.append(AlignmentViolation(
                category=AlignmentCategory(v_dict["category"]),
                severity=AlignmentSeverity(v_dict["severity"]),
                matched_text=v_dict["matched_text"],
                position_start=0,
                position_end=0,
                confidence=v_dict["confidence"],
                description=v_dict["description"],
                recommendation=v_dict["recommendation"],
                phase="post_analysis",
            ))
        
        total_violations = len(pre_violations) + len(post_violations)
        critical_count = sum(
            1 for v in pre_violations + post_violations 
            if v.severity in [AlignmentSeverity.CRITICAL, AlignmentSeverity.HIGH]
        )
        
        score = max(0, 100 - (critical_count * 20) - (total_violations * 5))
        compliant = critical_count == 0 and total_violations <= 1
        strategy = self._recommend_strategy(pre_violations, post_violations)
        
        return AlignmentResult(
            scan_id=scan_id,
            timestamp=datetime.now().isoformat(),
            pre_filter_violations=pre_violations,
            pre_filter_action=pre_result["action"],
            post_analysis_violations=post_violations,
            post_analysis_action=post_result["action"],
            overall_compliant=compliant,
            overall_score=score,
            recommended_response_strategy=strategy,
        )
    
    def rewrite_neutral(self, prompt: str) -> str:
        """Reescribe un prompt sesgado para hacerlo neutral."""
        neutral = prompt
        
        neutral = re.sub(
            r'\b(todos?\s+los?\s+(?:políticos?|funcionarios?))\s+(?:son|están)\s+(corruptos?|ladrones?|ineptos?)\b',
            r'¿Cuál es la opinión pública sobre la corrupción en \1?',
            neutral,
            flags=re.IGNORECASE
        )
        
        neutral = re.sub(
            r'por\s+qué\s+(?:el\s+presidente|el\s+gobierno)\s+(miente|engaña|roba|es\s+corrupto)',
            r'¿Cuáles son las críticas más comunes hacia \1?',
            neutral,
            flags=re.IGNORECASE
        )
        
        neutral = re.sub(
            r'\b(el\s+gobierno|la\s+institución|el\s+presidente)\s+(?:es\s+)?(?:una\s+)?(?:mierda|basura|vergüenza)',
            r'¿Cuáles son los problemas más citados de \1?',
            neutral,
            flags=re.IGNORECASE
        )
        
        return neutral
    
    def _determine_pre_action(self, violations: List[AlignmentViolation]) -> str:
        if not violations:
            return "allow"
        has_critical = any(v.severity == AlignmentSeverity.CRITICAL for v in violations)
        has_high = any(v.severity == AlignmentSeverity.HIGH for v in violations)
        if has_critical:
            return "block"
        elif has_high:
            return "modify_prompt"
        else:
            return "allow"
    
    def _determine_post_action(self, violations: List[AlignmentViolation]) -> str:
        if not violations:
            return "allow"
        has_critical = any(v.severity in [AlignmentSeverity.CRITICAL, AlignmentSeverity.HIGH] for v in violations)
        if has_critical:
            return "regenerate"
        elif len(violations) > 2:
            return "flag"
        else:
            return "allow"
    
    def _recommend_strategy(self, pre_violations: List[AlignmentViolation], 
                           post_violations: List[AlignmentViolation]) -> str:
        if not pre_violations and not post_violations:
            return "standard_response"
        
        has_false_premise = any(
            v.category == AlignmentCategory.FALSE_PREMISE 
            for v in pre_violations
        )
        
        if has_false_premise:
            return "reject_premise_with_facts"
        
        has_bias = any(
            v.category in [AlignmentCategory.BIAS_DETECTED, AlignmentCategory.NEUTRALITY_BREACH]
            for v in pre_violations + post_violations
        )
        
        if has_bias:
            return "neutral_redirect"
        
        return "review_and_correct"
